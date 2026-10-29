//! Tests for fat Mach-O binaries

use super::*;

/// A universal (x86_64 + arm64) C program that links libSystem.
fn fat_binary() -> Vec<u8> {
    crate::common::bytes("testdata/macho/charge0x_installer_universal.macho")
}

#[test]
fn test_fat_binary_extract_strings() {
    let data = fat_binary();

    let strings = extract_strings(&data, 4);
    assert!(!strings.is_empty(), "Fat binary should have strings");
}

#[test]
fn test_fat_binary_detect_language() {
    let data = fat_binary();

    let lang = detect_language(&data);
    // System binaries are typically C/unknown
    assert_eq!(lang, "unknown");
}

#[test]
fn test_fat_binary_not_go() {
    let data = fat_binary();

    assert!(!is_go_binary(&data), "Fat system binary should not be Go");
}

#[test]
fn test_fat_binary_not_rust() {
    let data = fat_binary();

    assert!(
        !is_rust_binary(&data),
        "Fat system binary should not be Rust"
    );
}

#[test]
fn test_fat_binary_with_options() {
    let data = fat_binary();

    let opts = ExtractOptions::new(8);
    let strings = extract_strings_with_options(&data, &opts);
    assert!(!strings.is_empty());
}

#[test]
fn test_fat_binary_has_imports() {
    let data = fat_binary();

    let strings = extract_strings(&data, 4);

    // System binaries should have imports
    let has_imports = strings.iter().any(|s| s.kind == Some(StringKind::Import));
    assert!(has_imports, "Fat binary should have imports");
}
