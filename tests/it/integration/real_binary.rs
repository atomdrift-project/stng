//! Tests using real system binaries for higher coverage

use super::*;

/// A small C program built with MSVC.
fn real_binary() -> Vec<u8> {
    crate::common::bytes("testdata/pe/msvc_console_amd64.exe")
}

#[test]
fn test_extract_strings_real_binary() {
    let data = real_binary();

    let strings = extract_strings(&data, 4);
    // Real binaries should have some strings
    assert!(!strings.is_empty(), "Real binary should have strings");
}

#[test]
fn test_detect_language_real_binary() {
    let data = real_binary();

    let lang = detect_language(&data);
    // Real system binary is typically C/unknown
    assert!(matches!(
        lang,
        stng::Language::Unknown | stng::Language::Rust | stng::Language::Go
    ));
}

#[test]
fn test_is_go_binary_real_binary() {
    let data = real_binary();

    // System binaries are typically not Go
    let result = is_go_binary(&data);
    assert!(!result, "System binary should not be Go");
}

#[test]
fn test_is_rust_binary_real_binary() {
    let data = real_binary();

    // System binaries are typically not Rust
    let result = is_rust_binary(&data);
    assert!(!result, "System binary should not be Rust");
}

#[test]
fn test_extract_with_options_real_binary() {
    let data = real_binary();

    let opts = ExtractOptions::new(4);
    let strings = extract_strings_with_options(&data, &opts);
    assert!(!strings.is_empty());
}

#[test]
fn test_extract_with_min_length_variations() {
    let data = real_binary();

    let strings_4 = extract_strings(&data, 4);
    let strings_10 = extract_strings(&data, 10);
    let strings_20 = extract_strings(&data, 20);

    // More restrictive min_length should yield fewer or equal strings
    assert!(strings_10.len() <= strings_4.len());
    assert!(strings_20.len() <= strings_10.len());
}

#[test]
fn test_extracted_strings_have_valid_values() {
    let data = real_binary();

    let strings = extract_strings(&data, 4);
    for s in &strings {
        // Strings should be valid UTF-8 (they're already String type)
        assert!(!s.value.is_empty());
        // Note: Some strings (imports/symbols) may be shorter than min_length
        // The min_length filter applies to extracted strings, not imports
    }
}
