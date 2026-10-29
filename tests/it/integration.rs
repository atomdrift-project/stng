//! Integration tests for stng library.

use crate::common::minimal_elf_header;
use stng::{
    ExtractOptions, ExtractedString, StringKind, StringMethod, detect_language, extract_strings,
    extract_strings_with_options, is_garbage, is_go_binary, is_rust_binary,
};

// Test data: minimal Mach-O header for 64-bit
fn minimal_macho_header() -> Vec<u8> {
    let mut data = vec![0u8; 512];
    // Mach-O 64-bit magic
    data[0..4].copy_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]);
    // CPU type: x86_64 (0x01000007)
    data[4..8].copy_from_slice(&[0x07, 0x00, 0x00, 0x01]);
    // CPU subtype
    data[8..12].copy_from_slice(&[0x03, 0x00, 0x00, 0x00]);
    // File type: executable (2)
    data[12..16].copy_from_slice(&[0x02, 0x00, 0x00, 0x00]);
    // Number of load commands
    data[16..20].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    // Size of load commands
    data[20..24].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    data
}

#[test]
fn test_extract_strings_empty_data() {
    let strings = extract_strings(&[], 4);
    assert!(strings.is_empty());
}

#[test]
fn test_extract_strings_from_printable_data() {
    // Printable data should be extracted (like traditional `strings`)
    let data = b"not a valid binary format at all";
    let strings = extract_strings(data, 4);
    // Should find the printable string
    assert!(!strings.is_empty());
}

#[test]
fn test_extract_strings_pure_binary() {
    // Pure binary data with no printable runs should return empty
    let data = &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let strings = extract_strings(data, 4);
    assert!(strings.is_empty());
}

#[test]
fn test_extract_strings_minimal_elf() {
    let data = minimal_elf_header();
    let strings = extract_strings(&data, 4);
    // Minimal ELF with no sections should return empty
    assert!(strings.is_empty());
}

#[test]
fn test_extract_strings_minimal_macho() {
    let data = minimal_macho_header();
    let strings = extract_strings(&data, 4);
    // Minimal Mach-O with no segments should return empty
    assert!(strings.is_empty());
}

#[test]
fn test_detect_language_empty() {
    assert_eq!(detect_language(&[]), "unknown");
}

#[test]
fn test_detect_language_text() {
    // Plain text should be detected as "text"
    assert_eq!(detect_language(b"not a binary"), "text");
}

#[test]
fn test_detect_language_binary_garbage() {
    // Binary garbage should be "unknown"
    assert_eq!(detect_language(&[0x00, 0x01, 0x02, 0x03, 0x04]), "unknown");
}

#[test]
fn test_detect_language_elf() {
    let data = minimal_elf_header();
    assert_eq!(detect_language(&data), "unknown"); // No Go/Rust sections
}

#[test]
fn test_is_go_binary_empty() {
    assert!(!is_go_binary(&[]));
}

#[test]
fn test_is_go_binary_invalid() {
    assert!(!is_go_binary(b"not a binary"));
}

#[test]
fn test_is_rust_binary_empty() {
    assert!(!is_rust_binary(&[]));
}

#[test]
fn test_is_rust_binary_invalid() {
    assert!(!is_rust_binary(b"not a binary"));
}

#[test]
fn test_extract_options_new() {
    let opts = ExtractOptions::new(4);
    assert_eq!(opts.min_length, 4);
    assert!(opts.r2_strings.is_none());
}

#[test]
fn test_extract_strings_with_options_empty() {
    let opts = ExtractOptions::new(4);
    let strings = extract_strings_with_options(&[], &opts);
    assert!(strings.is_empty());
}

// Garbage detection tests
#[test]
fn test_is_garbage_valid_strings() {
    assert!(!is_garbage("Hello World"));
    assert!(!is_garbage("go1.22.0"));
    assert!(!is_garbage("/usr/lib/go"));
    assert!(!is_garbage("runtime.memequal"));
    assert!(!is_garbage("SIGFPE: floating-point exception"));
    assert!(!is_garbage("Bool"));
    assert!(!is_garbage("Time"));
    assert!(!is_garbage("linux"));
    assert!(!is_garbage("amd64"));
    assert!(!is_garbage("https://example.com"));
    assert!(!is_garbage("ERROR_CODE_123"));
}

#[test]
fn test_is_garbage_empty_and_short() {
    assert!(is_garbage(""));
    assert!(is_garbage(" "));
    assert!(is_garbage("a")); // Single char
}

#[test]
fn test_is_garbage_control_chars() {
    assert!(is_garbage("ab\x00cd"));
    assert!(is_garbage("\x01\x02\x03"));
    assert!(is_garbage("hello\x00world"));
}

#[test]
fn test_is_garbage_misaligned_patterns() {
    assert!(is_garbage("asL "));
    assert!(is_garbage("``L "));
    assert!(is_garbage("dL "));
    assert!(is_garbage("`L "));
}

#[test]
fn test_is_garbage_short_mixed_case() {
    assert!(is_garbage("P9O"));
    assert!(is_garbage("8ZAj"));
    assert!(is_garbage("pIo2"));
}

#[test]
fn test_is_garbage_all_caps_short_ok() {
    // All caps short strings are OK
    assert!(!is_garbage("API"));
    assert!(!is_garbage("HTTP"));
    assert!(!is_garbage("GET"));
}

#[test]
fn test_is_garbage_all_lowercase_short_ok() {
    assert!(!is_garbage("foo"));
    assert!(!is_garbage("bar"));
    assert!(!is_garbage("test"));
}

#[test]
fn test_is_garbage_all_digits_short_ok() {
    assert!(!is_garbage("1234"));
    assert!(!is_garbage("2024"));
}

#[test]
fn test_is_garbage_repeated_chars() {
    assert!(is_garbage("aaaa"));
    assert!(is_garbage("...."));
    assert!(is_garbage("----"));
}

#[test]
fn test_is_garbage_excessive_whitespace() {
    assert!(is_garbage("   a   ")); // Single char after trim
    // "ab cd" after trim has proper content, may not be garbage
}

#[test]
fn test_is_garbage_unicode_endings() {
    assert!(is_garbage("333333ӿ"));
    assert!(is_garbage("abcӿ"));
}

#[test]
fn test_is_garbage_noise_punctuation() {
    assert!(is_garbage("@#$%"));
    assert!(is_garbage("@E?"));
    assert!(is_garbage("P$O"));
}

#[test]
fn test_is_garbage_hex_patterns() {
    // Pure-hex runs ≥8 chars are kept — could be hash fragments,
    // short build IDs, or other hex identifiers.
    assert!(!is_garbage("deadbeef"));
    assert!(!is_garbage("0a1b2c3d"));
}

// Test StringKind variants
#[test]
fn test_string_kind_default() {
    let kind: Option<StringKind> = None;
    assert_eq!(kind, None);
}

// Test ExtractedString
#[test]
fn test_extracted_string_serialization() {
    let s = ExtractedString {
        value: "test".to_string(),
        data_offset: 0x1000,
        method: StringMethod::Structure,
        kind: None,
        ..Default::default()
    };

    let json = serde_json::to_string(&s).unwrap();
    assert!(json.contains("\"value\":\"test\""));
    assert!(json.contains("\"data_offset\":4096"));
}

/// Tests for UTF-16LE wide string extraction (Windows binaries)
/// Tests for IP detection improvements (filtering version numbers)
/// Tests for shell command detection improvements (filtering .NET generics)
/// XOR detection tests for compiled binaries
#[cfg(test)]
#[cfg(test)]
/// The npm install-hook packer decodes through charcodes and a recovered Caesar
/// shift, exposing the AES staging call underneath.
///
/// Regression for a real miss: the payload was invisible end to end because the
/// charcode recipe was written as an array `.map(...)` rather than a direct
/// `eval(String.fromCharCode(...))`, and because the shift was 6 rather than the
/// ROT13 everyone tries. Both had to be fixed for a single string of the
/// payload to reach a rule.
#[test]
fn npm_charcode_rot_packer_exposes_aes_staging() {
    let src = crate::common::bytes("testdata/script/npm-charcode-rot-packer.js").leak();
    let results = stng::script::deobfuscate_script(src);
    let decoded: String = results.iter().map(|r| r.decoded.as_str()).collect();

    assert!(
        !results.is_empty(),
        "packer produced no deobfuscation results"
    );
    assert!(
        decoded.contains("createDecipheriv"),
        "AES staging call not recovered: {}",
        &decoded[..decoded.len().min(200)]
    );
    assert!(
        decoded.contains("aes-128-gcm"),
        "cipher name not recovered from the decoded payload"
    );
    assert!(
        results
            .iter()
            .any(|r| r.chain_description.contains("charcode-array")),
        "expected the charcode-array chain, got: {:?}",
        results
            .iter()
            .map(|r| r.chain_description.as_str())
            .collect::<Vec<_>>()
    );
}

mod api;
mod cross_compiled;
mod edge_cases;
mod extract_from;
mod extraction_scenarios;
mod fat_binary;
mod filter;
mod garbage_edge_cases;
mod go_binary;
mod ip_detection;
mod real_binary;
mod rust_binary;
mod severity;
mod shell_detection;
mod sockaddr_extraction;
mod string_deduplication;
mod string_kinds;
mod testdata_binaries;
mod wide_strings;
mod xor_detection;
