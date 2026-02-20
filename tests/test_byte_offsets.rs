//! Tests for byte offset accuracy in text files and binaries

use stng::{ExtractOptions, StringMethod};

#[test]
fn test_text_file_byte_offsets_not_line_numbers() {
    // Create test content with known structure
    let content = b"AAAA\nBBBBBBBB\nCCCCCCCCCCCC\n";
    //              ^0   ^5       ^14

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(content, &opts);

    // Find the raw scan strings
    let raw_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.method == StringMethod::RawScan)
        .collect();

    assert_eq!(raw_strings.len(), 3, "Should find 3 strings");

    // Check offsets are BYTES not line numbers
    let aaaa = raw_strings.iter().find(|s| s.value == "AAAA").unwrap();
    assert_eq!(aaaa.data_offset, 0, "AAAA should be at byte 0");

    let bbbb = raw_strings.iter().find(|s| s.value == "BBBBBBBB").unwrap();
    assert_eq!(
        bbbb.data_offset, 5,
        "BBBBBBBB should be at byte 5 (not line 1)"
    );

    let cccc = raw_strings
        .iter()
        .find(|s| s.value == "CCCCCCCCCCCC")
        .unwrap();
    assert_eq!(
        cccc.data_offset, 14,
        "CCCCCCCCCCCC should be at byte 14 (not line 2)"
    );
}

#[test]
fn test_decoded_string_inherits_correct_offset() {
    // Base64 on its own line
    let content = b"SGVsbG8gV29ybGQh\n"; // "Hello World!"
                                         //              ^0

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(content, &opts);

    // Find the decoded base64
    let decoded = strings
        .iter()
        .find(|s| s.method == StringMethod::Base64Decode);

    assert!(decoded.is_some(), "Should decode base64");
    let decoded = decoded.unwrap();

    assert_eq!(decoded.value, "Hello World!");
    assert_eq!(
        decoded.data_offset, 0,
        "Decoded string should inherit offset from original"
    );
}

#[test]
fn test_multiple_lines_correct_offsets() {
    // Use a longer base64 string (MIN_BASE64_LENGTH is 16)
    // "line1\n" = 6 bytes, base64 = 40 bytes, "\n" = 1, "line3" starts at 47
    let content = b"line1\nVGhpcyBpcyBhIGxvbmdlciB0ZXN0IHN0cmluZw==\nline3\n";
    //              ^0    ^6                                    ^47

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(content, &opts);

    // Find all raw strings
    let line1 = strings.iter().find(|s| s.value == "line1");
    let line3 = strings.iter().find(|s| s.value == "line3");

    assert!(line1.is_some());
    assert!(line3.is_some());

    assert_eq!(line1.unwrap().data_offset, 0, "line1 at byte 0");
    assert_eq!(line3.unwrap().data_offset, 47, "line3 at byte 47");

    // Find decoded base64 (could be Base64Decode or Base64ObfuscatedDecode)
    let decoded = strings.iter().find(|s| {
        matches!(
            s.method,
            StringMethod::Base64Decode | StringMethod::Base64ObfuscatedDecode
        )
    });
    assert!(decoded.is_some(), "Should decode base64");
    assert_eq!(
        decoded.unwrap().data_offset,
        6,
        "Base64 line starts at byte 6"
    );
    assert_eq!(decoded.unwrap().value, "This is a longer test string");
}

#[test]
fn test_empty_lines_dont_affect_offsets() {
    let content = b"AAAA\n\nBBBB\n";
    //              ^0   ^5 ^6

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(content, &opts);

    let aaaa = strings.iter().find(|s| s.value == "AAAA").unwrap();
    let bbbb = strings.iter().find(|s| s.value == "BBBB").unwrap();

    assert_eq!(aaaa.data_offset, 0);
    assert_eq!(bbbb.data_offset, 6, "BBBB after empty line");
}
