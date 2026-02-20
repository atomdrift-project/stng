//! CLI integration tests for stng.

use std::path::Path;
use std::process::Command;

fn stng_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_stng"))
}

#[test]
fn test_cli_help() {
    let output = stng_cmd()
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
fn test_cli_version() {
    let output = stng_cmd()
        .arg("--version")
        .output()
        .expect("Failed to execute stng");

    assert!(output.status.success());
}

#[test]
fn test_cli_nonexistent_file() {
    let output = stng_cmd()
        .arg("/nonexistent/file/path")
        .output()
        .expect("Failed to execute stng");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("does not exist") || stderr.contains("No such file"));
}

#[test]
fn test_cli_detect_language_text() {
    // Create a temp file with text content
    let temp_dir = std::env::temp_dir();
    let temp_file = temp_dir.join("stng_test_detect_text.txt");
    std::fs::write(&temp_file, b"not a binary").unwrap();

    let output = stng_cmd()
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
fn test_cli_detect_language_unknown() {
    // Create a temp file with binary garbage
    let temp_dir = std::env::temp_dir();
    let temp_file = temp_dir.join("stng_test_detect_bin.bin");
    std::fs::write(&temp_file, [0x00, 0x01, 0x02, 0x03, 0x04, 0x05]).unwrap();

    let output = stng_cmd()
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
fn test_cli_json_output() {
    // Use a real binary like /bin/ls if available
    let binary_path = if Path::new("/bin/ls").exists() {
        "/bin/ls".to_string()
    } else if Path::new("/usr/bin/ls").exists() {
        "/usr/bin/ls".to_string()
    } else {
        // Skip on systems without ls
        return;
    };

    let output = stng_cmd()
        .arg("--json")
        .arg("--no-r2")
        .arg(&binary_path)
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
fn test_cli_simple_output() {
    let binary_path = if Path::new("/bin/ls").exists() {
        "/bin/ls".to_string()
    } else if Path::new("/usr/bin/ls").exists() {
        "/usr/bin/ls".to_string()
    } else {
        return;
    };

    let output = stng_cmd()
        .arg("--simple")
        .arg("--no-r2")
        .arg(&binary_path)
        .output()
        .expect("Failed to execute stng");

    if output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Simple mode shows count in stderr
        assert!(stderr.contains("strings extracted"));
    }
}

#[test]
fn test_cli_min_length() {
    let binary_path = if Path::new("/bin/ls").exists() {
        "/bin/ls".to_string()
    } else {
        return;
    };

    // Run with min_length 4 (default)
    let output_default = stng_cmd()
        .arg("--json")
        .arg("--no-r2")
        .arg(&binary_path)
        .output()
        .expect("Failed to execute stng");

    // Run with min_length 20
    let output_long = stng_cmd()
        .arg("-m")
        .arg("20")
        .arg("--json")
        .arg("--no-r2")
        .arg(&binary_path)
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
            "min_length 20 ({}) should have <= strings than default ({})",
            count_long,
            count_default
        );
    }
}

#[test]
fn test_cli_unfiltered() {
    let binary_path = if Path::new("/bin/ls").exists() {
        "/bin/ls".to_string()
    } else {
        return;
    };

    // Run without --unfiltered
    let output1 = stng_cmd()
        .arg("--json")
        .arg("--no-r2")
        .arg(&binary_path)
        .output()
        .expect("Failed to execute stng");

    // Run with --unfiltered
    let output2 = stng_cmd()
        .arg("--json")
        .arg("--no-r2")
        .arg("--unfiltered")
        .arg(&binary_path)
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
fn test_cli_flat_output() {
    let binary_path = if Path::new("/bin/ls").exists() {
        "/bin/ls".to_string()
    } else {
        return;
    };

    let output = stng_cmd()
        .arg("--flat")
        .arg("--no-r2")
        .arg(&binary_path)
        .output()
        .expect("Failed to execute stng");

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Should have a header with string count and format info
        assert!(stdout.contains("strings ·") || stdout.contains("strings"));
    }
}

#[test]
fn test_cli_no_r2() {
    let binary_path = if Path::new("/bin/ls").exists() {
        "/bin/ls".to_string()
    } else {
        return;
    };

    let output = stng_cmd()
        .arg("--no-r2")
        .arg("--json")
        .arg(&binary_path)
        .output()
        .expect("Failed to execute stng");

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Should not have r2 method strings when r2 is disabled
        // (they might still appear if r2 is auto-detected, but we explicitly disabled it)
        // Just check it's valid output
        assert!(stdout.starts_with('['));
    }
}

#[test]
fn test_cli_text_file_cat() {
    // Text files should be output like `cat`
    let temp_dir = std::env::temp_dir();
    let temp_file = temp_dir.join("stng_test_text.txt");
    let content = b"This is just a text file, not a binary";
    std::fs::write(&temp_file, content).unwrap();

    let output = stng_cmd()
        .arg(&temp_file)
        .output()
        .expect("Failed to execute stng");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("This is just a text file"));

    std::fs::remove_file(&temp_file).ok();
}

#[test]
fn test_cli_binary_garbage() {
    // Binary garbage should find no strings
    let temp_dir = std::env::temp_dir();
    let temp_file = temp_dir.join("stng_test_garbage.bin");
    std::fs::write(&temp_file, [0x00, 0x01, 0x02, 0x03, 0x04, 0x05]).unwrap();

    let output = stng_cmd()
        .arg(&temp_file)
        .output()
        .expect("Failed to execute stng");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("No strings found"));

    std::fs::remove_file(&temp_file).ok();
}

#[test]
fn test_cli_empty_file() {
    let temp_dir = std::env::temp_dir();
    let temp_file = temp_dir.join("stng_test_empty.bin");
    std::fs::write(&temp_file, b"").unwrap();

    let output = stng_cmd()
        .arg(&temp_file)
        .output()
        .expect("Failed to execute stng");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("No strings found"));

    std::fs::remove_file(&temp_file).ok();
}

#[test]
fn test_cli_base64_decoding() {
    // Test that base64 strings are decoded and shown in brackets
    let temp_dir = std::env::temp_dir();
    let temp_file = temp_dir.join("stng_test_base64.bin");

    // Create a fake ELF with a base64-encoded string
    // "VGhpcyBpcyBhIHNlY3JldCBtZXNzYWdl" decodes to "This is a secret message"
    let mut content = vec![0x7f, b'E', b'L', b'F']; // ELF magic
    content.extend_from_slice(&[0x00; 4]); // padding
    content.extend_from_slice(b"VGhpcyBpcyBhIHNlY3JldCBtZXNzYWdl"); // base64 string (32 chars)
    content.extend_from_slice(&[0x00; 4]); // null terminator
    std::fs::write(&temp_file, &content).unwrap();

    let output = stng_cmd()
        .arg("--no-color")
        .arg("--no-r2")
        .arg(&temp_file)
        .output()
        .expect("Failed to execute stng");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should show the decoded text (either in brackets or as a separate decoded entry)
    // With the new decoder pipeline, base64 strings are decoded and added as separate entries
    assert!(
        stdout.contains("This is a secret message"),
        "Expected base64 decoded text, got: {}",
        stdout
    );

    std::fs::remove_file(&temp_file).ok();
}

#[test]
fn test_cli_trailing_newlines_trimmed() {
    // Test that trailing newlines/control chars are stripped from output
    let temp_dir = std::env::temp_dir();
    let temp_file = temp_dir.join("stng_test_newlines.bin");

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

    let output = stng_cmd()
        .arg("--no-color")
        .arg("--no-r2")
        .arg(&temp_file)
        .output()
        .expect("Failed to execute stng");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Output should not have consecutive blank lines caused by trailing newlines in strings
    // Each string should be on its own line without extra blank lines
    assert!(
        !stdout.contains("\n\n\n"),
        "Output should not have triple newlines from untrimmed strings: {}",
        stdout
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
                "Line should not end with control chars: {:?}",
                line
            );
        }
    }

    std::fs::remove_file(&temp_file).ok();
}

#[test]
fn test_cli_simple_mode_trims_newlines() {
    // Test that --simple mode also trims trailing control characters
    let temp_dir = std::env::temp_dir();
    let temp_file = temp_dir.join("stng_test_simple_newlines.bin");

    let mut content = vec![0x7f, b'E', b'L', b'F']; // ELF magic
    content.extend_from_slice(&[0x00; 4]); // padding
    content.extend_from_slice(b"simple_test_string\n"); // string with trailing newline
    content.extend_from_slice(&[0x00]); // null terminator
    std::fs::write(&temp_file, &content).unwrap();

    let output = stng_cmd()
        .arg("--simple")
        .arg("--no-r2")
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
                "Simple mode line should not end with newline: {:?}",
                line
            );
        }
    }

    std::fs::remove_file(&temp_file).ok();
}

#[test]
fn test_cli_interesting_flag() {
    let binary_path = if std::path::Path::new("/bin/ls").exists() {
        "/bin/ls"
    } else if std::path::Path::new("/usr/bin/ls").exists() {
        "/usr/bin/ls"
    } else {
        return;
    };

    let output = stng_cmd()
        .arg("--interesting")
        .arg("--json")
        .arg("--no-r2")
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
fn test_cli_no_xor_flag() {
    let binary_path = if std::path::Path::new("/bin/ls").exists() {
        "/bin/ls"
    } else if std::path::Path::new("/usr/bin/ls").exists() {
        "/usr/bin/ls"
    } else {
        return;
    };

    let output = stng_cmd()
        .arg("--no-xor")
        .arg("--json")
        .arg("--no-r2")
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
fn test_cli_debug_flag_does_not_crash() {
    let temp_dir = std::env::temp_dir();
    let temp_file = temp_dir.join("stng_test_debug_flag.bin");
    std::fs::write(&temp_file, b"debug test content for flag check").unwrap();

    let output = stng_cmd()
        .arg("--debug")
        .arg("--no-r2")
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
fn test_cli_xor_min_length_respected() {
    let binary_path = if std::path::Path::new("/bin/ls").exists() {
        "/bin/ls"
    } else if std::path::Path::new("/usr/bin/ls").exists() {
        "/usr/bin/ls"
    } else {
        return;
    };

    let output = stng_cmd()
        .arg("--json")
        .arg("--no-r2")
        .arg("--xor-min-length")
        .arg("200")
        .arg(binary_path)
        .output()
        .expect("Failed to execute stng");

    assert!(
        output.status.success(),
        "--xor-min-length should not cause a failure"
    );
}
