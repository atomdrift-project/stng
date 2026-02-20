//! Test that /etc/passwd entries are not misclassified

use std::fs;
use std::process::Command;

#[test]
fn test_passwd_entries_not_misclassified() {
    // Create a test file with passwd-style entries
    let test_file = "/tmp/stng_test_passwd.txt";
    let content = r#"_assetcache:*:235:235:Asset Cache Service:/var/empty:/usr/bin/false
_mobileasset:*:253:253:MobileAsset User:/var/ma:/usr/bin/false
_datadetectors:*:257:257:DataDetectors:/var/db/datadetectors:/usr/bin/false
_mmaintenanced:*:283:283:mmaintenanced:/var/db/mmaintenanced:/usr/bin/false
_biome:*:289:289:Biome:/var/db/biome:/usr/bin/false
_terminusd:*:295:295:Terminus:/var/db/terminus:/usr/bin/false
_nsurlsessiond:*:242:242:NSURLSession Daemon:/var/db/nsurlsessiond:/usr/bin/false
"#;
    fs::write(test_file, content).expect("failed to write test file");

    // Run stng on the file
    let output = Command::new("cargo")
        .args(["run", "--release", "--bin", "stng", "--"])
        .arg(test_file)
        .output()
        .expect("failed to execute stng");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify NO lines are classified as "applescript" or "base85"
    let has_applescript = stdout.lines().any(|line| {
        let parts: Vec<&str> = line.split_whitespace().collect();
        parts.len() >= 3 && parts[1] == "applescript"
    });

    let has_base85 = stdout.lines().any(|line| {
        let parts: Vec<&str> = line.split_whitespace().collect();
        parts.len() >= 3 && parts[1] == "base85"
    });

    assert!(
        !has_applescript,
        "Passwd entries should not be classified as applescript:\n{}",
        stdout
    );
    assert!(
        !has_base85,
        "Passwd entries should not be classified as base85:\n{}",
        stdout
    );

    // Clean up
    fs::remove_file(test_file).ok();
}

#[test]
fn test_real_applescript_still_detected() {
    // Create a test file with real AppleScript
    let test_file = "/tmp/stng_test_applescript.txt";
    let content = r#"tell application "Finder"
set myVar to 10
do shell script "ls -la"
path to desktop folder
"#;
    fs::write(test_file, content).expect("failed to write test file");

    // Run stng on the file
    let output = Command::new("cargo")
        .args(["run", "--release", "--bin", "stng", "--"])
        .arg(test_file)
        .output()
        .expect("failed to execute stng");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify at least some lines are classified as applescript
    let has_applescript = stdout.lines().any(|line| {
        let parts: Vec<&str> = line.split_whitespace().collect();
        parts.len() >= 3 && parts[1] == "applescript"
    });

    assert!(
        has_applescript,
        "Real AppleScript should still be detected:\n{}",
        stdout
    );

    // Clean up
    fs::remove_file(test_file).ok();
}
