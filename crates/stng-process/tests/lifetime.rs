//! The watchdog kills its tool on deadline and whenever the scanner goes away.
#![cfg(unix)]

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use stng_process::{Watchdog, exited_unreaped};

fn running(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    if let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        return stat
            .split_once(") ")
            .is_some_and(|(_, rest)| !rest.starts_with('Z'));
    }
    // SAFETY: signal zero only probes process existence.
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

fn wait_until(mut done: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(5);
    while !done() {
        assert!(
            Instant::now() < end,
            "child survived its lifetime/deadline bound"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn tool(timeout: Duration) -> (std::process::Child, Watchdog) {
    let mut cmd = Command::new("/bin/sleep");
    cmd.arg("30")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let watchdog = Watchdog::arm(&mut cmd, timeout).unwrap();
    let child = cmd.spawn().unwrap();
    (child, watchdog)
}

#[test]
fn deadline_needs_no_scanner_polling() {
    let (mut child, _guard) = tool(Duration::from_millis(200));
    wait_until(|| exited_unreaped(&child).unwrap());
    assert!(!child.wait().unwrap().success());
}

#[test]
fn another_watchdog_cannot_retain_the_first_lifeline() {
    let (mut first, first_guard) = tool(Duration::from_secs(10));
    let (mut second, mut second_guard) = tool(Duration::from_secs(10));
    drop(first_guard);
    wait_until(|| exited_unreaped(&first).unwrap());
    assert!(!first.wait().unwrap().success());
    assert!(running(second.id()));
    second_guard.kill_group(&second);
    second.wait().unwrap();
}

// This runs in its own subprocess for the death and SIGSTOP cases below.
#[test]
fn scanner_probe() {
    let Ok(pidfile) = std::env::var("WATCHDOG_PROBE_PIDFILE") else {
        return;
    };
    let timeout = if std::env::var_os("WATCHDOG_PROBE_STOP").is_some() {
        Duration::from_millis(500)
    } else {
        Duration::from_secs(10)
    };
    let (mut child, _guard) = tool(timeout);
    std::fs::write(pidfile, child.id().to_string()).unwrap();
    child.wait().unwrap();
}

fn scanner_case(stop: bool) {
    let dir = std::env::temp_dir().join(format!("watchdog-test-{}-{stop}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let pidfile = dir.join("tool.pid");
    let _ = std::fs::remove_file(&pidfile);
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args(["--exact", "scanner_probe", "--nocapture"])
        .env("WATCHDOG_PROBE_PIDFILE", &pidfile)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if stop {
        cmd.env("WATCHDOG_PROBE_STOP", "1");
    }
    let mut scanner = cmd.spawn().unwrap();
    wait_until(|| Path::new(&pidfile).exists());
    let pid = std::fs::read_to_string(&pidfile).unwrap().parse().unwrap();
    if stop {
        // SAFETY: this is our own scanner subprocess, not its tool's group.
        unsafe {
            libc::kill(scanner.id() as i32, libc::SIGSTOP);
        }
    } else {
        scanner.kill().unwrap();
    }
    // Always clean up the scanner, even when an assertion fails.
    let result = std::panic::catch_unwind(|| wait_until(|| !running(pid)));
    if stop {
        scanner.kill().unwrap();
    }
    scanner.wait().unwrap();
    let _ = std::fs::remove_dir_all(dir);
    result.unwrap();
}

#[test]
fn killed_scanner_cannot_leave_a_live_tool() {
    scanner_case(false);
}

#[test]
fn stopped_scanner_cannot_suspend_the_tools_deadline() {
    scanner_case(true);
}
