//! Lifetime and deadline protection for optional native analysis tools.
//!
//! String extraction never starts a process. CLI integrations and consumers
//! such as filefacts explicitly arm this guard when launching their tools.

#![cfg(unix)]

use std::ffi::CString;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::Duration;

/// A lifeline held by the scanner until its contained child is cleaned up.
///
/// Before exec, a watchdog forks into the tool's private process group. It
/// kills that group on deadline or when this lifeline closes, including when
/// the scanner aborts or is killed. Remaining in the group also pins its ID:
/// even after the scanner dies and the tool is reaped, the watchdog cannot
/// accidentally signal a recycled group. The watchdog closes every inherited
/// descriptor except its lifeline and uses only async-signal-safe operations.
#[derive(Debug)]
pub struct Watchdog {
    _lifeline: UnixStream,
    killed: bool,
}

impl Watchdog {
    /// Kill a spawned tool's pinned private group. Call before reaping its
    /// leader; subsequent calls are harmless even after the ID is recycled.
    pub fn kill_group(&mut self, pid: u32) {
        if !self.killed {
            self.killed = true;
            // SAFETY: caller supplies its own spawned child's group. The
            // unreaped leader or this guard's watchdog still pins that group.
            unsafe {
                libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
            }
        }
    }

    /// Put `command` in a private group and arm an independent wall deadline.
    ///
    /// Keep the returned guard until the tool's group has been killed. Failure
    /// to fork the watchdog refuses the tool launch. No watchdog is started
    /// until `Command::spawn` runs the hook.
    pub fn arm(command: &mut Command, timeout: Duration) -> io::Result<Self> {
        let (lifeline, child_line) = UnixStream::pair()?;
        let parent_fd = lifeline.as_raw_fd();
        // Read the descriptor bound before fork; the watchdog must not retain
        // another concurrent launch's lifeline, sockets, or stdout pipes.
        // SAFETY: getdtablesize has no memory effects.
        let max_fd = unsafe { libc::getdtablesize() };
        if max_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let seconds = CString::new(format!(
            "{}.{:09}",
            timeout.as_secs(),
            timeout.subsec_nanos()
        ))
        .map_err(io::Error::other)?;
        command.process_group(0);
        // SAFETY: the hook and forked watchdog allocate nothing and take no
        // Rust locks. All child operations are syscall wrappers; _exit skips
        // inherited destructors and allocator state.
        unsafe {
            command.pre_exec(move || {
                let fd = child_line.as_raw_fd();
                // Close the scanner's writer in both descendants before fork.
                libc::close(parent_fd);
                // Pin the private group before creating its watchdog member.
                if libc::setpgid(0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                match libc::fork() {
                    -1 => Err(io::Error::last_os_error()),
                    0 => watchdog(fd, max_fd, seconds.as_ptr()),
                    _ => Ok(()),
                }
            });
        }
        Ok(Self {
            _lifeline: lifeline,
            killed: false,
        })
    }
}

// SAFETY: called only after fork; exec releases the inherited scanner heap.
// The POSIX shell races a bounded sleep against EOF on stdin. Both branches
// kill their own pinned group, including the watchdog, timer and tool. No
// platform-specific Python/Perl installation or separate shipped binary is used.
unsafe fn watchdog(fd: libc::c_int, max_fd: libc::c_int, seconds: *const libc::c_char) -> ! {
    // The watchdog execs with a deliberately minimal descriptor table. Close
    // other launches' lifelines and output pipes before starting the shell.
    for other in 0..max_fd {
        if other != fd {
            unsafe {
                libc::close(other);
            }
        }
    }
    // stdin is the scanner lifeline. Clear CLOEXEC even when fd already was 0.
    if unsafe { libc::dup2(fd, 0) } < 0 || unsafe { libc::fcntl(0, libc::F_SETFD, 0) } < 0 {
        unsafe {
            libc::kill(0, libc::SIGKILL);
            libc::_exit(1);
        }
    }
    if fd != 0 {
        unsafe {
            libc::close(fd);
        }
    }
    let mut digits = [0u8; 24];
    let mut pos = digits.len() - 1;
    let mut group = unsafe { libc::getpgrp() } as u32;
    loop {
        pos -= 1;
        digits[pos] = b'0' + (group % 10) as u8;
        group /= 10;
        if group == 0 {
            break;
        }
    }
    let argv = [
        c"sh".as_ptr(),
        c"-c".as_ptr(),
        c"(/bin/sleep \"$1\"; kill -KILL -- \"-$2\") & IFS= read -r ignored; kill -KILL -- \"-$2\""
            .as_ptr(),
        c"analysis-watchdog".as_ptr(),
        seconds,
        unsafe { digits.as_ptr().add(pos).cast() },
        std::ptr::null(),
    ];
    let env = [std::ptr::null()];
    unsafe {
        libc::execve(c"/bin/sh".as_ptr(), argv.as_ptr(), env.as_ptr());
        // A missing shell must fail closed, never leave an unguarded tool.
        libc::kill(0, libc::SIGKILL);
        libc::_exit(1);
    }
}

/// Observe a tool's exit without reaping its group leader. The leader keeps
/// the group ID reserved until cleanup, including after the watchdog expires.
pub fn exited_unreaped(pid: u32) -> io::Result<bool> {
    // SAFETY: siginfo_t is plain storage initialized before the syscall.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: pid names the caller's own child and info is writable storage.
    let rc = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &raw mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: waitid succeeded; a zero pid means no exit event yet.
    Ok(unsafe { info.si_pid() } != 0)
}
