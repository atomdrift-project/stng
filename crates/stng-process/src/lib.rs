//! Lifetime and deadline protection for optional native analysis tools.
//!
//! String extraction never starts a process. Callers that launch a tool, such
//! as the `stng` command running rizin, arm this guard explicitly.

#![cfg(unix)]

use std::ffi::CString;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command};
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
    /// Kill the private group led by `child`, the command this guard armed.
    /// Call before reaping `child`; later calls do nothing, so a recycled
    /// group ID is never signalled.
    pub fn kill_group(&mut self, child: &Child) {
        if self.killed {
            return;
        }
        self.killed = true;
        let Ok(pid) = libc::pid_t::try_from(child.id()) else {
            return;
        };
        // SAFETY: `child` is unreaped, so its group ID is still reserved, and
        // a spawned child's pid is never 0 or 1, so `-pid` names only that group.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }

    /// Put `command` in a private group and arm an independent wall deadline.
    ///
    /// Keep the returned guard until the tool's group has been killed. Failure
    /// to fork the watchdog refuses the tool launch. No watchdog is started
    /// until `Command::spawn` runs the hook.
    pub fn arm(command: &mut Command, timeout: Duration) -> io::Result<Self> {
        let sleep = sleep_path()?;
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
                // std applies process_group before pre_exec hooks, but does not
                // document that order, and the watchdog is only safe inside it.
                if libc::setpgid(0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                match libc::fork() {
                    -1 => Err(io::Error::last_os_error()),
                    0 => watchdog(fd, max_fd, seconds.as_ptr(), sleep.as_ptr()),
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

/// Locate `sleep(1)` before forking: the watchdog execs with an empty
/// environment, and a missing timer would make the deadline kill the tool at
/// once. Searches `PATH`, then `/bin` and `/usr/bin`.
fn sleep_path() -> io::Result<CString> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .chain([PathBuf::from("/bin"), PathBuf::from("/usr/bin")])
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join("sleep"))
        .find(|p| {
            p.metadata()
                .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        })
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "watchdog: sleep(1) not found"))
        .and_then(|p| CString::new(p.as_os_str().as_bytes()).map_err(io::Error::other))
}

/// Become the watchdog: a POSIX shell that races a bounded sleep against EOF
/// on stdin (the lifeline). Both branches kill the pinned group, including
/// the watchdog, timer and tool. Needs no interpreter or shipped helper.
///
/// # Safety
/// Call only in a freshly forked child of the `pre_exec` hook. It performs
/// only async-signal-safe syscalls, and exec releases the inherited heap.
/// `seconds` and `sleep` must point to NUL-terminated strings.
unsafe fn watchdog(
    fd: libc::c_int,
    max_fd: libc::c_int,
    seconds: *const libc::c_char,
    sleep: *const libc::c_char,
) -> ! {
    // stdin is the scanner lifeline. Clear CLOEXEC even when fd already was 0.
    // SAFETY: dup2 and fcntl take plain descriptors.
    let lifeline = unsafe { libc::dup2(fd, 0) >= 0 && libc::fcntl(0, libc::F_SETFD, 0) >= 0 };
    if !lifeline {
        fail_closed();
    }
    // Exec with only the lifeline: close other launches' lifelines and
    // output pipes, and the original lifeline descriptor.
    // SAFETY: this process owns its descriptor table and keeps only stdin.
    unsafe { close_from(1, max_fd) };
    // SAFETY: getpgrp cannot fail.
    let mut group = unsafe { libc::getpgrp() }.unsigned_abs();
    let mut digits = [0u8; 24];
    let mut pos = digits.len() - 1;
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
        c"(\"$3\" \"$1\"; kill -KILL -- \"-$2\") & IFS= read -r ignored; kill -KILL -- \"-$2\""
            .as_ptr(),
        c"analysis-watchdog".as_ptr(),
        seconds,
        digits[pos..].as_ptr().cast(),
        sleep,
        std::ptr::null(),
    ];
    let env = [std::ptr::null()];
    // SAFETY: argv and env are NULL-terminated arrays of C strings that
    // outlive the call; execve returns only on failure.
    unsafe { libc::execve(c"/bin/sh".as_ptr(), argv.as_ptr(), env.as_ptr()) };
    // A missing shell must fail closed, never leave an unguarded tool.
    fail_closed()
}

/// Kill this process's group, which includes the tool, and exit.
fn fail_closed() -> ! {
    // SAFETY: kill and _exit take plain integers; _exit skips destructors
    // and allocator state inherited across fork.
    unsafe {
        libc::kill(0, libc::SIGKILL);
        libc::_exit(1)
    }
}

/// Close every descriptor from `low` up. One syscall where the platform has
/// one; a container's descriptor limit can be over a million.
///
/// # Safety
/// Only for the forked watchdog, which owns its whole descriptor table.
unsafe fn close_from(low: libc::c_int, max_fd: libc::c_int) {
    #[cfg(any(
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    {
        let _ = max_fd;
        // SAFETY: closefrom takes a plain integer.
        unsafe { libc::closefrom(low) };
    }
    #[cfg(not(any(
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "netbsd",
        target_os = "openbsd"
    )))]
    {
        // SAFETY: close_range takes plain integers. Kernels before 5.9 return
        // ENOSYS and fall back to the loop.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if unsafe { libc::syscall(libc::SYS_close_range, low, libc::c_uint::MAX, 0) } == 0 {
            return;
        }
        for other in low..max_fd {
            // SAFETY: closing an unopened descriptor only returns EBADF.
            unsafe {
                libc::close(other);
            }
        }
    }
}

/// Observe `child`'s exit without reaping it. As the group leader it keeps
/// the group ID reserved until cleanup, including after the watchdog expires.
pub fn exited_unreaped(child: &Child) -> io::Result<bool> {
    // SAFETY: siginfo_t is plain storage initialized before the syscall.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: `child` is the caller's own child and info is writable storage.
    let rc = unsafe {
        libc::waitid(
            libc::P_PID,
            child.id() as libc::id_t,
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
