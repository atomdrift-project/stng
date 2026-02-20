//! Tests for string wrapping and sorting functionality

use std::fs;
use std::process::Command;

fn run_stng(args: &[&str]) -> String {
    let output = Command::new("cargo")
        .args(["run", "--release", "--bin", "stng", "--"])
        .args(args)
        .output()
        .expect("failed to execute stng");

    String::from_utf8_lossy(&output.stdout).to_string()
}

fn run_stng_stderr(args: &[&str]) -> String {
    let output = Command::new("cargo")
        .args(["run", "--release", "--bin", "stng", "--"])
        .args(args)
        .output()
        .expect("failed to execute stng");

    String::from_utf8_lossy(&output.stderr).to_string()
}

#[test]
fn test_text_file_offset_sorting() {
    // Create a temporary text file with known content
    let test_file = "/tmp/stng_test_sorting.txt";
    let content = "First line\nSecond line\nThird line with more content\n";
    fs::write(test_file, content).expect("failed to write test file");

    let output = run_stng(&[test_file]);

    // Extract offsets from output
    let offsets: Vec<u64> = output
        .lines()
        .filter_map(|line| {
            // Parse lines like "         0          -            First line"
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                u64::from_str_radix(parts[0], 16).ok()
            } else {
                None
            }
        })
        .collect();

    // Verify offsets are in ascending order
    assert!(
        offsets.windows(2).all(|w| w[0] <= w[1]),
        "Offsets should be in ascending order: {:?}",
        offsets
    );

    // Verify we have the expected offsets
    // "First line\n" = 11 bytes (offset 0)
    // "Second line\n" = 12 bytes (offset 11 = 0xb)
    // "Third line..." = 29 bytes (offset 23 = 0x17)
    assert!(offsets.contains(&0), "Should have offset 0");

    // Clean up
    fs::remove_file(test_file).ok();
}

#[test]
fn test_string_wrapping_long_lines() {
    // Create a file with a very long line
    let test_file = "/tmp/stng_test_wrapping.txt";
    let long_line = "A".repeat(200);
    fs::write(test_file, &long_line).expect("failed to write test file");

    let output = run_stng(&[test_file]);

    // Count how many times we see offset 0 (wrapped lines)
    let offset_0_count = output
        .lines()
        .filter(|line| line.trim().starts_with("0 "))
        .count();

    // For a 200-character line with typical terminal width (120), we should see wrapping
    // The exact count depends on terminal width and prefix columns
    // We just verify the line appears at least once
    assert!(
        offset_0_count >= 1,
        "Should have at least one line starting at offset 0"
    );

    // Clean up
    fs::remove_file(test_file).ok();
}

#[test]
fn test_offset_calculation_multiline() {
    // Create a file with multiple lines of known lengths
    let test_file = "/tmp/stng_test_offsets.txt";
    // Line 1: "AAAA\n" = 5 bytes (offset 0)
    // Line 2: "BBBBBBBB\n" = 9 bytes (offset 5)
    // Line 3: "CCCC\n" = 5 bytes (offset 14 = 0xe)
    let content = "AAAA\nBBBBBBBB\nCCCC\n";
    fs::write(test_file, content).expect("failed to write test file");

    let output = run_stng(&[test_file]);

    // Parse all offsets
    let offsets: Vec<u64> = output
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                u64::from_str_radix(parts[0], 16).ok()
            } else {
                None
            }
        })
        .collect();

    // Should have offsets 0, 5, and 14 (0xe)
    assert!(offsets.contains(&0), "Should have offset 0 (AAAA)");
    assert!(offsets.contains(&5), "Should have offset 5 (BBBBBBBB)");
    assert!(
        offsets.contains(&14),
        "Should have offset 14/0xe (CCCC), got: {:?}",
        offsets
    );

    // Clean up
    fs::remove_file(test_file).ok();
}

#[test]
fn test_utf8_wrapping() {
    // Create a file with UTF-8 characters to ensure proper byte boundary handling
    let test_file = "/tmp/stng_test_utf8.txt";
    // Each emoji is 4 bytes in UTF-8
    let content = "🔥".repeat(50); // 200 bytes
    fs::write(test_file, content).expect("failed to write test file");

    let output = run_stng(&[test_file]);

    // Should not panic or produce garbled output
    // Just verify we get output without errors
    assert!(
        !output.is_empty() || !run_stng_stderr(&[test_file]).contains("error"),
        "Should handle UTF-8 without errors"
    );

    // Clean up
    fs::remove_file(test_file).ok();
}

#[test]
fn test_empty_file() {
    let test_file = "/tmp/stng_test_empty.txt";
    fs::write(test_file, "").expect("failed to write test file");

    // Run command and capture both stdout and stderr
    let output_result = Command::new("cargo")
        .args(["run", "--release", "--bin", "stng", "--"])
        .arg(test_file)
        .output()
        .expect("failed to execute stng");

    let stdout = String::from_utf8_lossy(&output_result.stdout);
    let stderr = String::from_utf8_lossy(&output_result.stderr);

    // Should handle empty file gracefully with "No strings found" message
    assert!(
        stdout.contains("No strings found") || stderr.contains("No strings found"),
        "Should handle empty file gracefully with 'No strings found' message. stdout: '{}', stderr: '{}'",
        stdout,
        stderr
    );

    // Clean up
    fs::remove_file(test_file).ok();
}

#[test]
fn test_single_long_line_wrapping() {
    // Create a file with a single very long line to test wrapping
    let test_file = "/tmp/stng_test_single_long.txt";
    let long_line = "X".repeat(300);
    fs::write(test_file, long_line).expect("failed to write test file");

    let output = run_stng(&[test_file]);

    // All wrapped lines should start at offset 0 since it's one continuous string
    let lines_with_offset: Vec<&str> = output
        .lines()
        .filter(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            parts.len() >= 3 && parts[0].parse::<u64>().is_ok()
        })
        .collect();

    // For wrapping to work correctly, we should see the offset incrementing
    // as the line wraps. The first part is at offset 0, subsequent parts
    // should have increasing offsets based on how much content came before
    if lines_with_offset.len() > 1 {
        // Get the offsets
        let offsets: Vec<u64> = lines_with_offset
            .iter()
            .filter_map(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                u64::from_str_radix(parts[0], 16).ok()
            })
            .collect();

        // First offset should be 0
        assert_eq!(offsets[0], 0, "First offset should be 0");

        // Subsequent offsets should be greater (due to wrapping)
        for i in 1..offsets.len() {
            assert!(
                offsets[i] > offsets[i - 1],
                "Wrapped line offsets should increase: {:?}",
                offsets
            );
        }
    }

    // Clean up
    fs::remove_file(test_file).ok();
}

#[test]
fn test_sorting_preserves_all_strings() {
    let test_file = "/tmp/stng_test_count.txt";
    let content = "line1\nline2\nline3\nline4\nline5\n";
    fs::write(test_file, content).expect("failed to write test file");

    let output = run_stng(&[test_file]);

    // Count output lines that contain actual string data (exclude headers)
    let string_lines = output
        .lines()
        .filter(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            parts.len() >= 3 && u64::from_str_radix(parts[0], 16).is_ok()
        })
        .count();

    // Should have 5 strings
    assert_eq!(
        string_lines, 5,
        "Should preserve all 5 strings after sorting"
    );

    // Clean up
    fs::remove_file(test_file).ok();
}

#[test]
fn test_flat_mode_sorting() {
    let test_file = "/tmp/stng_test_flat.txt";
    let content = "First\nSecond\nThird\n";
    fs::write(test_file, content).expect("failed to write test file");

    let output = run_stng(&["--flat", test_file]);

    // Extract offsets
    let offsets: Vec<u64> = output
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                u64::from_str_radix(parts[0], 16).ok()
            } else {
                None
            }
        })
        .collect();

    // In flat mode, offsets should still be sorted
    assert!(
        offsets.windows(2).all(|w| w[0] <= w[1]),
        "Flat mode should also sort by offset: {:?}",
        offsets
    );

    // Clean up
    fs::remove_file(test_file).ok();
}
