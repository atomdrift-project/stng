//! Integration tests for clean system binaries that should have minimal false positives.
//!
//! These tests verify that legitimate binaries without obfuscation don't trigger
//! false positive detections for XOR, base85, URL encoding, etc.

use std::fs;
use stng::{ExtractOptions, StringKind, extract_strings_with_options};

/// A clean Go hello-world ELF has no obfuscated content: no XOR or
/// encoding detections.
#[test]
fn clean_elf_has_no_obfuscated_strings() {
    let data = crate::common::bytes("testdata/elf/hello_linux_amd64");

    let opts = ExtractOptions::new(10)
        .with_xor(stng::XorMode::Auto)
        .with_xor_min_length(10);

    let strings = extract_strings_with_options(&data, &opts);

    // Count detection types
    let xor_count = strings
        .iter()
        .filter(|s| s.method == stng::StringMethod::XorDecode)
        .count();

    let base85_count = strings
        .iter()
        .filter(|s| s.kind == Some(StringKind::Base85))
        .count();

    let urlenc_count = strings
        .iter()
        .filter(|s| s.kind == Some(StringKind::UrlEncoded))
        .count();

    let base32_count = strings
        .iter()
        .filter(|s| s.kind == Some(StringKind::Base32))
        .count();

    let base64_count = strings
        .iter()
        .filter(|s| s.kind == Some(StringKind::Base64))
        .count();

    assert_eq!(
        xor_count, 0,
        "Clean binary should have NO XOR strings, found {xor_count}"
    );

    // Base85 should not trigger on normal strings
    assert_eq!(
        base85_count, 0,
        "Clean binary should have no base85 false positives, found {base85_count}"
    );

    // URL encoding should not trigger on printf format strings
    assert_eq!(
        urlenc_count, 0,
        "Clean binary should have no urlenc false positives, found {urlenc_count}"
    );

    // Base32 should not trigger on clean binaries (certificates are not base32)
    assert_eq!(
        base32_count, 0,
        "Clean binary should have no base32 detections, found {base32_count}"
    );

    // Verify no XOR key was detected
    let xor_key_count = strings
        .iter()
        .filter(|s| s.kind == Some(StringKind::XorKey))
        .count();

    assert_eq!(
        xor_key_count, 0,
        "Clean binary should have no detected XOR keys, found {xor_key_count}"
    );

    // Base64: /bin/ls contains legitimate base64 in code signature (CD hashes)
    // These are SHA-1 hashes in <data> tags inside the code signature blob
    // They should be categorized as CodeSignature method, not generic base64
    let codesig_base64_count = strings
        .iter()
        .filter(|s| {
            s.kind == Some(StringKind::Base64) && s.method == stng::StringMethod::CodeSignature
        })
        .count();

    // All base64 should be code signature hashes (in __LINKEDIT)
    assert_eq!(
        base64_count, codesig_base64_count,
        "All base64 should be CodeSignature method, found {base64_count} base64 but only {codesig_base64_count} with CodeSignature method"
    );

    assert!(
        base64_count <= 2,
        "Clean binary should have minimal base64 (code sig hashes), found {base64_count}"
    );
}

/// A clean MSVC console PE has no obfuscated content.
#[test]
fn clean_pe_has_no_obfuscated_strings() {
    let data = crate::common::bytes("testdata/pe/msvc_console_amd64.exe");

    let opts = ExtractOptions::new(10)
        .with_xor(stng::XorMode::Auto)
        .with_xor_min_length(10);

    let strings = extract_strings_with_options(&data, &opts);

    let xor_count = strings
        .iter()
        .filter(|s| s.method == stng::StringMethod::XorDecode)
        .count();

    // /bin/cat should have no XOR-encoded strings
    assert_eq!(
        xor_count, 0,
        "Clean binary /bin/cat should have no XOR strings, found {xor_count}"
    );
}

/// Test that vget_sample (Rust binary) has no false base85 detections.
/// File paths like "library/alloc/src/raw_vec/mod.rs" are not base85 encoded.
#[test]
fn finds_at_most_one_base85_in_rust_binary() {
    let sample_path = crate::common::path("testdata/malware/vget_sample");

    let data = fs::read(sample_path).expect("Failed to read vget_sample");

    let opts = ExtractOptions::new(10);
    let strings = extract_strings_with_options(&data, &opts);

    let base85_count = strings
        .iter()
        .filter(|s| s.kind == Some(StringKind::Base85))
        .count();

    // Rust binaries have lots of paths/strings with base85-valid chars,
    // but they're not actually base85 encoded. Decoding them produces garbage.
    // Quality heuristic filters most, but allow up to 1 false positive
    assert!(
        base85_count <= 1,
        "Rust binary should have minimal base85 false positives, found {base85_count}"
    );
}
