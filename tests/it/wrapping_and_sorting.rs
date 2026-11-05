//! Tests for string wrapping and sorting functionality

use std::fs;

fn run_stng(args: &[&str]) -> String {
    let output = crate::stng()
        .args(args)
        .output()
        .expect("failed to execute stng");

    String::from_utf8_lossy(&output.stdout).to_string()
}

#[test]
fn sorts_text_lines_by_offset() {
    // Create a temporary text file with known content
    let content = "First line\nSecond line\nThird line with more content\n";
    let test_file = crate::common::temp_file("sorting.txt", content);

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
        "Offsets should be in ascending order: {offsets:?}"
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
fn shows_long_line_at_offset_zero() {
    // Create a file with a very long line
    let long_line = "A".repeat(200);
    let test_file = crate::common::temp_file("wrapping.txt", &long_line);

    // A run of one letter is noise to the garbage filter; this tests layout.
    let output = run_stng(&["--unfiltered", test_file]);

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
fn reports_each_line_offset() {
    // Create a file with multiple lines of known lengths
    // Line 1: "AAAA\n" = 5 bytes (offset 0)
    // Line 2: "BBBBBBBB\n" = 9 bytes (offset 5)
    // Line 3: "CCCC\n" = 5 bytes (offset 14 = 0xe)
    let content = "AAAA\nBBBBBBBB\nCCCC\n";
    let test_file = crate::common::temp_file("offsets.txt", content);

    // Runs of one letter are noise to the garbage filter; this tests offsets.
    let output = run_stng(&["--unfiltered", test_file]);

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
        "Should have offset 14/0xe (CCCC), got: {offsets:?}"
    );

    // Clean up
    fs::remove_file(test_file).ok();
}

#[test]
fn exits_cleanly_on_emoji_only_text() {
    // Create a file with UTF-8 characters to ensure proper byte boundary handling
    // Each emoji is 4 bytes in UTF-8
    let content = "🔥".repeat(50); // 200 bytes
    let test_file = crate::common::temp_file("utf8.txt", content);

    let output = crate::stng()
        .arg(test_file)
        .output()
        .expect("failed to execute stng");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // The raw scan reads printable ASCII runs, and this file has none: it must
    // say so and exit cleanly, not panic on a split character.
    assert!(output.status.success(), "stderr: {stderr}");
    assert!(
        stdout.contains("No strings found"),
        "stdout: {stdout}, stderr: {stderr}"
    );

    // Clean up
    fs::remove_file(test_file).ok();
}

#[test]
fn reports_no_strings_for_empty_file() {
    let test_file = crate::common::temp_file("empty.txt", "");

    // Run command and capture both stdout and stderr
    let output_result = crate::stng()
        .arg(test_file)
        .output()
        .expect("failed to execute stng");

    let stdout = String::from_utf8_lossy(&output_result.stdout);
    let stderr = String::from_utf8_lossy(&output_result.stderr);

    // Should handle empty file gracefully with "No strings found" message
    assert!(
        stdout.contains("No strings found") || stderr.contains("No strings found"),
        "Should handle empty file gracefully with 'No strings found' message. stdout: '{stdout}', stderr: '{stderr}'"
    );

    // Clean up
    fs::remove_file(test_file).ok();
}

#[test]
fn keeps_long_string_unwrapped_when_piped() {
    // Values wrap only on a terminal; piped output keeps each string on one
    // row so it can be grepped. (Wrapped offsets are unit-tested in cli::output.)
    let long_line = "X".repeat(300);
    let test_file = crate::common::temp_file("single_long.txt", &long_line);

    // A one-character run is garbage, so only --unfiltered shows it.
    assert!(run_stng(&[test_file]).starts_with("No strings found"));

    let output = run_stng(&["--unfiltered", test_file]);
    let rows: Vec<Vec<&str>> = output
        .lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        .filter(|parts| parts.len() >= 3 && u64::from_str_radix(parts[0], 16).is_ok())
        .collect();
    assert_eq!(rows, [vec!["0", "-", long_line.as_str()]], "{output}");

    // Clean up
    fs::remove_file(test_file).ok();
}

#[test]
fn keeps_every_line_when_sorting() {
    let content = "line1\nline2\nline3\nline4\nline5\n";
    let test_file = crate::common::temp_file("count.txt", content);

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
fn sorts_unfiltered_listing_by_offset() {
    let content = "First\nSecond\nThird\n";
    let test_file = crate::common::temp_file("flat.txt", content);

    let output = run_stng(&["--unfiltered", test_file]);

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
        "Flat mode should also sort by offset: {offsets:?}"
    );

    // Clean up
    fs::remove_file(test_file).ok();
}
