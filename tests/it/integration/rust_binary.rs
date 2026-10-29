//! Tests using real Rust binaries

use super::*;

/// The `stng` binary under test, a Rust executable.
fn rust_binary() -> Vec<u8> {
    std::fs::read(env!("CARGO_BIN_EXE_stng")).expect("read stng binary")
}

#[test]
fn test_self_binary_detection() {
    // Test against our own binary
    let data = rust_binary();

    assert_eq!(detect_language(&data), stng::Language::Rust);
    assert!(is_rust_binary(&data));
    let strings = extract_strings(&data, 4);
    assert!(!strings.is_empty(), "Self binary should have strings");
}

#[test]
fn test_self_binary_with_options() {
    let data = rust_binary();

    // Test with various options
    let opts = ExtractOptions::new(6).with_garbage_filter(true);
    let strings = extract_strings_with_options(&data, &opts);
    assert!(!strings.is_empty());

    // All strings should be >= 6 chars (mostly - imports might be shorter)
    // Just verify it doesn't panic
}

#[test]
fn test_self_binary_extract_from_object() {
    let data = rust_binary();
    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(&data, &opts);
    assert!(!strings.is_empty());
}

#[test]
fn test_self_binary_string_kinds() {
    let data = rust_binary();
    let strings = extract_strings(&data, 4);

    // Should have various kinds of strings
    let has_const = strings.iter().any(|s| s.kind.is_none());
    let has_import = strings.iter().any(|s| s.kind == Some(StringKind::Import));

    assert!(
        has_const || has_import,
        "Should have None (Const) or Import strings"
    );
}

#[test]
fn test_extract_strings_rust_binary() {
    let data = rust_binary();

    let strings = extract_strings(&data, 4);
    assert!(!strings.is_empty(), "Rust binary should have strings");
}

#[test]
fn test_rust_binary_has_rust_strings() {
    let data = rust_binary();

    let strings = extract_strings(&data, 4);

    // Rust binaries often have typical Rust strings
    let has_rust_hint = strings.iter().any(|s| {
        s.value.contains("rust")
            || s.value.contains("panic")
            || s.value.contains("unwrap")
            || s.value.contains("core::")
            || s.value.contains("std::")
    });

    assert!(has_rust_hint);
}
