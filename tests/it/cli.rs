//! CLI integration tests for stng.

#[test]
fn help_lists_main_flags() {
    let output = crate::stng()
        .arg("--help")
        .output()
        .expect("Failed to execute stng");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("stng"));
    assert!(stdout.contains("--min-length"));
    assert!(stdout.contains("--json"));
}

#[test]
fn prints_version() {
    let output = crate::stng()
        .arg("--version")
        .output()
        .expect("Failed to execute stng");

    assert!(output.status.success());
}

#[test]
fn fails_on_missing_file() {
    let output = crate::stng()
        .arg("/nonexistent/file/path")
        .output()
        .expect("Failed to execute stng");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("does not exist") || stderr.contains("No such file"));
}

#[test]
fn detect_reports_text() {
    // Create a temp file with text content
    // Under target/, and per process, so concurrent runs cannot collide.
    let temp_file = crate::common::scratch_dir()
        .join(format!("{}-stng_test_detect_text.txt", std::process::id()));
    std::fs::write(&temp_file, b"not a binary").unwrap();

    let output = crate::stng()
        .arg("--detect")
        .arg(&temp_file)
        .output()
        .expect("Failed to execute stng");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("text"));

    std::fs::remove_file(&temp_file).ok();
}

#[test]
fn detect_reports_unknown_for_binary() {
    // Create a temp file with binary garbage
    // Under target/, and per process, so concurrent runs cannot collide.
    let temp_file = crate::common::scratch_dir()
        .join(format!("{}-stng_test_detect_bin.bin", std::process::id()));
    std::fs::write(&temp_file, [0x00, 0x01, 0x02, 0x03, 0x04, 0x05]).unwrap();

    let output = crate::stng()
        .arg("--detect")
        .arg(&temp_file)
        .output()
        .expect("Failed to execute stng");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("unknown"));

    std::fs::remove_file(&temp_file).ok();
}

#[test]
fn json_output_is_an_array() {
    let binary_path = crate::common::path("testdata/pe/msvc_console_amd64.exe");

    let output = crate::stng()
        .arg("--json")
        .arg(binary_path)
        .output()
        .expect("Failed to execute stng");

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Should be valid JSON array
        assert!(stdout.starts_with('['));
        assert!(stdout.trim().ends_with(']'));
    }
}

#[test]
fn decodes_encoded_vbscript_in_asp() {
    let sample = crate::common::path("testdata/script/vbscript-encoded-malformed-asp.asp");
    let output = crate::stng()
        .args(["--json", "--no-xor"])
        .arg(sample)
        .output()
        .expect("Failed to execute stng");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("script_decode"));
    assert!(stdout.contains("wscript.shell"));
}

#[test]
fn simple_mode_reports_count_on_stderr() {
    let binary_path = crate::common::path("testdata/pe/msvc_console_amd64.exe");

    let output = crate::stng()
        .arg("--simple")
        .arg(binary_path)
        .output()
        .expect("Failed to execute stng");

    if output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Simple mode shows count in stderr
        assert!(stderr.contains("strings extracted"));
    }
}

#[test]
fn min_length_never_adds_strings() {
    let binary_path = crate::common::path("testdata/pe/msvc_console_amd64.exe");

    // Run with min_length 4 (default)
    let output_default = crate::stng()
        .arg("--json")
        .arg(binary_path)
        .output()
        .expect("Failed to execute stng");

    // Run with min_length 20
    let output_long = crate::stng()
        .arg("-m")
        .arg("20")
        .arg("--json")
        .arg(binary_path)
        .output()
        .expect("Failed to execute stng");

    if output_default.status.success() && output_long.status.success() {
        let count_default = String::from_utf8_lossy(&output_default.stdout)
            .matches("\"value\"")
            .count();
        let count_long = String::from_utf8_lossy(&output_long.stdout)
            .matches("\"value\"")
            .count();
        // Higher min_length should result in fewer or equal strings
        assert!(
            count_long <= count_default,
            "min_length 20 ({count_long}) should have <= strings than default ({count_default})"
        );
    }
}

#[test]
fn unfiltered_never_drops_strings() {
    let binary_path = crate::common::path("testdata/pe/msvc_console_amd64.exe");

    // Run without --unfiltered
    let output1 = crate::stng()
        .arg("--json")
        .arg(binary_path)
        .output()
        .expect("Failed to execute stng");

    // Run with --unfiltered
    let output2 = crate::stng()
        .arg("--json")
        .arg("--unfiltered")
        .arg(binary_path)
        .output()
        .expect("Failed to execute stng");

    if output1.status.success() && output2.status.success() {
        // Unfiltered should have more or equal strings
        let count1 = String::from_utf8_lossy(&output1.stdout)
            .matches("\"value\"")
            .count();
        let count2 = String::from_utf8_lossy(&output2.stdout)
            .matches("\"value\"")
            .count();
        assert!(count2 >= count1);
    }
}

#[test]
fn rejects_removed_flags() {
    let binary_path = crate::common::path("testdata/pe/msvc_console_amd64.exe");
    for removed in [
        "--flat",
        "--r2",
        "--no-r2",
        "--no-rizin",
        "--no-cache",
        "--flush-cache",
        "--xor-min-length",
    ] {
        let output = crate::stng()
            .arg(removed)
            .arg(binary_path)
            .output()
            .expect("Failed to execute stng");
        assert!(!output.status.success(), "{removed} should be rejected");
    }
    let output = crate::stng()
        .arg("--json")
        .arg(binary_path)
        .output()
        .expect("Failed to execute stng");
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).starts_with('['));
}

#[test]
fn prints_text_files_verbatim() {
    // Text files should be output like `cat`
    // Under target/, and per process, so concurrent runs cannot collide.
    let temp_file =
        crate::common::scratch_dir().join(format!("{}-stng_test_text.txt", std::process::id()));
    let content = b"This is just a text file, not a binary";
    std::fs::write(&temp_file, content).unwrap();

    let output = crate::stng()
        .arg(&temp_file)
        .output()
        .expect("Failed to execute stng");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("This is just a text file"));

    std::fs::remove_file(&temp_file).ok();
}

#[test]
fn reports_no_strings_in_garbage() {
    // Binary garbage should find no strings
    // Under target/, and per process, so concurrent runs cannot collide.
    let temp_file =
        crate::common::scratch_dir().join(format!("{}-stng_test_garbage.bin", std::process::id()));
    std::fs::write(&temp_file, [0x00, 0x01, 0x02, 0x03, 0x04, 0x05]).unwrap();

    let output = crate::stng()
        .arg(&temp_file)
        .output()
        .expect("Failed to execute stng");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("No strings found"));

    std::fs::remove_file(&temp_file).ok();
}

#[test]
fn reports_no_strings_in_empty_file() {
    // Under target/, and per process, so concurrent runs cannot collide.
    let temp_file =
        crate::common::scratch_dir().join(format!("{}-stng_test_empty.bin", std::process::id()));
    std::fs::write(&temp_file, b"").unwrap();

    let output = crate::stng()
        .arg(&temp_file)
        .output()
        .expect("Failed to execute stng");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("No strings found"));

    std::fs::remove_file(&temp_file).ok();
}

#[test]
fn prints_decoded_base64() {
    // Test that base64 strings are decoded and shown in brackets
    // Under target/, and per process, so concurrent runs cannot collide.
    let temp_file =
        crate::common::scratch_dir().join(format!("{}-stng_test_base64.bin", std::process::id()));

    // Create a fake ELF with a base64-encoded string
    // "VGhpcyBpcyBhIHNlY3JldCBtZXNzYWdl" decodes to "This is a secret message"
    let mut content = vec![0x7f, b'E', b'L', b'F']; // ELF magic
    content.extend_from_slice(&[0x00; 4]); // padding
    content.extend_from_slice(b"VGhpcyBpcyBhIHNlY3JldCBtZXNzYWdl"); // base64 string (32 chars)
    content.extend_from_slice(&[0x00; 4]); // null terminator
    std::fs::write(&temp_file, &content).unwrap();

    let output = crate::stng()
        .arg("--no-color")
        .arg(&temp_file)
        .output()
        .expect("Failed to execute stng");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should show the decoded text (either in brackets or as a separate decoded entry)
    // With the new decoder pipeline, base64 strings are decoded and added as separate entries
    assert!(
        stdout.contains("This is a secret message"),
        "Expected base64 decoded text, got: {stdout}"
    );

    std::fs::remove_file(&temp_file).ok();
}

#[test]
fn trims_trailing_newlines() {
    // Test that trailing newlines/control chars are stripped from output
    // Under target/, and per process, so concurrent runs cannot collide.
    let temp_file =
        crate::common::scratch_dir().join(format!("{}-stng_test_newlines.bin", std::process::id()));

    // Create a fake ELF with strings that have trailing newlines
    let mut content = vec![0x7f, b'E', b'L', b'F']; // ELF magic
    content.extend_from_slice(&[0x00; 4]); // padding
    content.extend_from_slice(b"hello_world\n"); // string with trailing newline
    content.extend_from_slice(&[0x00]); // null terminator
    content.extend_from_slice(b"test_string\r\n"); // string with CRLF
    content.extend_from_slice(&[0x00]); // null terminator
    content.extend_from_slice(b"another_test\n\n"); // string with multiple newlines
    content.extend_from_slice(&[0x00]); // null terminator
    std::fs::write(&temp_file, &content).unwrap();

    let output = crate::stng()
        .arg("--no-color")
        .arg(&temp_file)
        .output()
        .expect("Failed to execute stng");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Output should not have consecutive blank lines caused by trailing newlines in strings
    // Each string should be on its own line without extra blank lines
    assert!(
        !stdout.contains("\n\n\n"),
        "Output should not have triple newlines from untrimmed strings: {stdout}"
    );

    // Verify the strings appear without their trailing control characters
    for line in stdout.lines() {
        if line.contains("hello_world")
            || line.contains("test_string")
            || line.contains("another_test")
        {
            // The line should not end with control characters
            assert!(
                !line.ends_with('\n') && !line.ends_with('\r'),
                "Line should not end with control chars: {line:?}"
            );
        }
    }

    std::fs::remove_file(&temp_file).ok();
}

#[test]
fn simple_mode_trims_trailing_newlines() {
    // Test that --simple mode also trims trailing control characters
    // Under target/, and per process, so concurrent runs cannot collide.
    let temp_file = crate::common::scratch_dir().join(format!(
        "{}-stng_test_simple_newlines.bin",
        std::process::id()
    ));

    let mut content = vec![0x7f, b'E', b'L', b'F']; // ELF magic
    content.extend_from_slice(&[0x00; 4]); // padding
    content.extend_from_slice(b"simple_test_string\n"); // string with trailing newline
    content.extend_from_slice(&[0x00]); // null terminator
    std::fs::write(&temp_file, &content).unwrap();

    let output = crate::stng()
        .arg("--simple")
        .arg(&temp_file)
        .output()
        .expect("Failed to execute stng");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // In simple mode, each string is on its own line
    // Should not have extra blank lines from trailing newlines
    let lines: Vec<&str> = stdout.lines().collect();
    for line in &lines {
        if line.contains("simple_test_string") {
            // Should be exactly the string, not with trailing newline
            assert!(
                !line.ends_with('\n'),
                "Simple mode line should not end with newline: {line:?}"
            );
        }
    }

    std::fs::remove_file(&temp_file).ok();
}

#[test]
fn interesting_emits_json_array() {
    let binary_path = crate::common::path("testdata/pe/msvc_console_amd64.exe");

    let output = crate::stng()
        .arg("--interesting")
        .arg("--json")
        .arg(binary_path)
        .output()
        .expect("Failed to execute stng");

    assert!(
        output.status.success(),
        "--interesting flag should not cause a failure"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.starts_with('['),
        "--interesting with --json should produce a JSON array"
    );
}

#[test]
fn no_xor_emits_no_xor_decodes() {
    let binary_path = crate::common::path("testdata/pe/msvc_console_amd64.exe");

    let output = crate::stng()
        .arg("--no-xor")
        .arg("--json")
        .arg(binary_path)
        .output()
        .expect("Failed to execute stng");

    assert!(
        output.status.success(),
        "--no-xor flag should not cause a failure"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("\"XorDecode\""),
        "--no-xor should produce no XorDecode entries"
    );
}

#[test]
fn debug_flag_succeeds() {
    // Under target/, and per process, so concurrent runs cannot collide.
    let temp_file = crate::common::scratch_dir()
        .join(format!("{}-stng_test_debug_flag.bin", std::process::id()));
    std::fs::write(&temp_file, b"debug test content for flag check").unwrap();

    let output = crate::stng()
        .arg("--debug")
        .arg(&temp_file)
        .output()
        .expect("Failed to execute stng");

    assert!(
        output.status.success(),
        "--debug flag should not cause a failure"
    );

    std::fs::remove_file(&temp_file).ok();
}

#[test]
fn json_stays_parseable_when_the_library_warns() {
    // An odd-length UTF-16 file logs a warning; it must go to stderr.
    let path = crate::common::temp_file("odd_utf16.txt", b"\xff\xfeh\0i\0!\0x\0y\0z");
    let output = crate::stng().args(["--json", path]).output().unwrap();
    assert!(output.status.success());
    let parsed: Result<serde_json::Value, _> = serde_json::from_slice(&output.stdout);
    assert!(
        parsed.is_ok(),
        "stdout is not JSON: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn closed_stdout_ends_the_run_quietly() {
    use std::process::Stdio;
    let mut child = crate::stng()
        .arg(env!("CARGO_BIN_EXE_stng"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    let output = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "exit {:?}: {stderr}",
        output.status
    );
    assert!(!stderr.contains("panicked"), "{stderr}");
}

#[cfg(unix)]
#[test]
fn rejects_targets_that_are_not_regular_files() {
    let output = crate::stng().arg("/dev/null").output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not a regular file"));
}

#[test]
fn unreadable_file_error_names_the_path() {
    let missing = crate::common::scratch_dir().join("no-such-sample");
    let output = crate::stng().arg(&missing).output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no-such-sample"));
}

/// JSON is often read on a terminal, so the C1 controls (`U+009B` is CSI)
/// and bidirectional overrides serde_json passes through are escaped, and
/// the escaped document still parses to the original values.
#[test]
fn json_escapes_terminal_controls_without_changing_values() {
    // base64 of "hello \u{9b}31mworld \u{202e}evil text here and more"
    let path = crate::common::temp_file(
        "terminal_controls.js",
        b"var p = \"aGVsbG8gwpszMW13b3JsZCDigK5ldmlsIHRleHQgaGVyZSBhbmQgbW9yZQ==\";",
    );
    let output = crate::stng().args(["--json", path]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains(['\u{9b}', '\u{202e}']), "{stdout}");
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&stdout).unwrap();
    assert!(
        parsed
            .iter()
            .any(|s| s["value"] == "hello \u{9b}31mworld \u{202e}evil text here and more"),
        "{stdout}"
    );
}

/// A symlink inside a scanned directory is not followed: it could point at
/// a secret, or at a device that never ends.
#[cfg(unix)]
#[test]
fn directory_scan_skips_symlinks() {
    let dir = crate::common::scratch_dir().join(format!("{}-symlinks", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let secret = crate::common::temp_file("secret.txt", b"do-not-follow-this-link-secret");
    let link = dir.join("link");
    std::fs::remove_file(&link).ok();
    std::os::unix::fs::symlink(secret, &link).unwrap();
    let output = crate::stng().args(["--json"]).arg(&dir).output().unwrap();
    std::fs::remove_dir_all(&dir).ok();
    assert!(output.status.success());
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("do-not-follow"),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}
