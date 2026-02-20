//! Integration tests for clean system binaries that should have minimal false positives.
//!
//! These tests verify that legitimate binaries without obfuscation don't trigger
//! false positive detections for XOR, base85, URL encoding, etc.

use std::fs;
use std::path::Path;
use stng::{extract_strings_with_options, ExtractOptions, StringKind};

/// Test that /bin/ls has no obfuscated content.
/// This is a clean system binary that should not trigger XOR or encoding detections.
#[test]
fn test_bin_ls_clean() {
    let bin_path = "/bin/ls";

    // Skip test if /bin/ls doesn't exist on this system
    if !Path::new(bin_path).exists() {
        eprintln!("Skipping test: {} not found", bin_path);
        return;
    }

    let data = fs::read(bin_path).expect("Failed to read /bin/ls");

    let opts = ExtractOptions::new(10).with_xor(Some(10));

    let strings = extract_strings_with_options(&data, &opts);

    // Count detection types
    let xor_count = strings
        .iter()
        .filter(|s| s.method == stng::StringMethod::XorDecode)
        .count();

    let base85_count = strings
        .iter()
        .filter(|s| s.kind == StringKind::Base85)
        .count();

    let urlenc_count = strings
        .iter()
        .filter(|s| s.kind == StringKind::UrlEncoded)
        .count();

    let base32_count = strings
        .iter()
        .filter(|s| s.kind == StringKind::Base32)
        .count();

    let base64_count = strings
        .iter()
        .filter(|s| s.kind == StringKind::Base64)
        .count();

    // /bin/ls should have ZERO XOR false positives
    if xor_count > 0 {
        eprintln!("Found {} XOR strings in /bin/ls:", xor_count);
        for s in strings
            .iter()
            .filter(|s| s.method == stng::StringMethod::XorDecode)
        {
            eprintln!(
                "  offset={} kind={:?} value={:?}",
                s.data_offset, s.kind, s.value
            );
        }
    }
    assert_eq!(
        xor_count, 0,
        "Clean binary should have NO XOR strings, found {}",
        xor_count
    );

    // Base85 should not trigger on normal strings
    assert_eq!(
        base85_count, 0,
        "Clean binary should have no base85 false positives, found {}",
        base85_count
    );

    // URL encoding should not trigger on printf format strings
    assert_eq!(
        urlenc_count, 0,
        "Clean binary should have no urlenc false positives, found {}",
        urlenc_count
    );

    // Base32 should not trigger on clean binaries (certificates are not base32)
    assert_eq!(
        base32_count, 0,
        "Clean binary should have no base32 detections, found {}",
        base32_count
    );

    // Verify no XOR key was detected
    let xor_key_count = strings
        .iter()
        .filter(|s| s.kind == StringKind::XorKey)
        .count();

    assert_eq!(
        xor_key_count, 0,
        "Clean binary should have no detected XOR keys, found {}",
        xor_key_count
    );

    // Base64: /bin/ls contains legitimate base64 in code signature (CD hashes)
    // These are SHA-1 hashes in <data> tags inside the code signature blob
    // They should be categorized as CodeSignature method, not generic base64
    let codesig_base64_count = strings
        .iter()
        .filter(|s| s.kind == StringKind::Base64 && s.method == stng::StringMethod::CodeSignature)
        .count();

    if base64_count > 0 {
        eprintln!("Found {} base64 strings in /bin/ls:", base64_count);
        for s in strings.iter().filter(|s| s.kind == StringKind::Base64) {
            eprintln!(
                "  offset=0x{:x} method={:?} section={:?} value={:?}",
                s.data_offset, s.method, s.section, s.value
            );
        }
    }

    // All base64 should be code signature hashes (in __LINKEDIT)
    assert_eq!(
        base64_count, codesig_base64_count,
        "All base64 should be CodeSignature method, found {} base64 but only {} with CodeSignature method",
        base64_count, codesig_base64_count
    );

    assert!(
        base64_count <= 2,
        "Clean binary should have minimal base64 (code sig hashes), found {}",
        base64_count
    );
}

/// Test that /bin/cat has no obfuscated content.
#[test]
fn test_bin_cat_clean() {
    let bin_path = "/bin/cat";

    if !Path::new(bin_path).exists() {
        eprintln!("Skipping test: {} not found", bin_path);
        return;
    }

    let data = fs::read(bin_path).expect("Failed to read /bin/cat");

    let opts = ExtractOptions::new(10).with_xor(Some(10));

    let strings = extract_strings_with_options(&data, &opts);

    let xor_count = strings
        .iter()
        .filter(|s| s.method == stng::StringMethod::XorDecode)
        .count();

    // /bin/cat should have no XOR-encoded strings
    assert_eq!(
        xor_count, 0,
        "Clean binary /bin/cat should have no XOR strings, found {}",
        xor_count
    );
}

/// Test that vget_sample (Rust binary) has no false base85 detections.
/// File paths like "library/alloc/src/raw_vec/mod.rs" are not base85 encoded.
#[test]
fn test_vget_sample_no_base85() {
    let sample_path = "testdata/malware/vget_sample";

    if !Path::new(sample_path).exists() {
        eprintln!("Skipping test: {} not found", sample_path);
        return;
    }

    let data = fs::read(sample_path).expect("Failed to read vget_sample");

    let opts = ExtractOptions::new(10);
    let strings = extract_strings_with_options(&data, &opts);

    let base85_count = strings
        .iter()
        .filter(|s| s.kind == StringKind::Base85)
        .count();

    // Rust binaries have lots of paths/strings with base85-valid chars,
    // but they're not actually base85 encoded. Decoding them produces garbage.
    // Quality heuristic filters most, but allow up to 1 false positive
    assert!(
        base85_count <= 1,
        "Rust binary should have minimal base85 false positives, found {}",
        base85_count
    );
}
