//! Tests for fat Mach-O binaries

use super::*;

/// A universal (x86_64 + arm64) C program that links libSystem.
fn fat_binary() -> Vec<u8> {
    crate::common::bytes("testdata/macho/charge0x_installer_universal.macho")
}

#[test]
fn finds_libsystem_load_command() {
    let data = fat_binary();

    let strings = extract_strings(&data, 4);
    // The x86_64 slice's LC_LOAD_DYLIB for libSystem, at its fat-file offset.
    assert!(
        strings
            .iter()
            .any(|s| s.value == "/usr/lib/libSystem.B.dylib"
                && s.data_offset == 0x45b0
                && s.kind == Some(StringKind::Path)),
        "libSystem load command not found"
    );
}

#[test]
fn detects_unknown_language() {
    let data = fat_binary();

    let lang = detect_language(&data);
    // System binaries are typically C/unknown
    assert_eq!(lang, stng::Language::Unknown);
}

#[test]
fn is_not_go() {
    let data = fat_binary();

    assert!(!is_go_binary(&data), "Fat system binary should not be Go");
}

#[test]
fn is_not_rust() {
    let data = fat_binary();

    assert!(
        !is_rust_binary(&data),
        "Fat system binary should not be Rust"
    );
}

#[test]
fn min_length_drops_short_imports() {
    let data = fat_binary();

    let opts = ExtractOptions::new(8);
    let strings = extract_strings_with_options(&data, &opts);
    // A 17-byte import clears the bar; the 7-byte `_system` does not.
    assert!(
        strings
            .iter()
            .any(|s| s.value == "___stack_chk_fail" && s.kind == Some(StringKind::Import))
    );
    assert!(!strings.iter().any(|s| s.value == "_system"));
}

#[test]
fn finds_imports() {
    let data = fat_binary();

    let strings = extract_strings(&data, 4);

    // System binaries should have imports
    let has_imports = strings.iter().any(|s| s.kind == Some(StringKind::Import));
    assert!(has_imports, "Fat binary should have imports");
}
