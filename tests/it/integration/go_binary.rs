//! Tests using real Go binaries

use super::*;

fn go_binary() -> Vec<u8> {
    crate::common::bytes("testdata/elf/hello_linux_amd64")
}

#[test]
fn detects_go() {
    let data = go_binary();

    let is_go = is_go_binary(&data);
    assert!(is_go, "Go binary should be detected as Go");
}

#[test]
fn detects_go_language() {
    let data = go_binary();

    let lang = detect_language(&data);
    assert_eq!(
        lang,
        stng::Language::Go,
        "Go binary should be detected as 'go'"
    );
}

#[test]
fn finds_many_strings() {
    let data = go_binary();

    let strings = extract_strings(&data, 4);
    assert!(!strings.is_empty(), "Go binary should have many strings");

    // Go binaries typically have thousands of strings
    assert!(
        strings.len() > 100,
        "Expected many strings from Go binary, got {}",
        strings.len()
    );
}

#[test]
fn finds_runtime_or_version_strings() {
    let data = go_binary();

    let strings = extract_strings(&data, 4);

    // Go binaries should have typical Go runtime strings
    let has_runtime = strings.iter().any(|s| s.value.contains("runtime"));
    let has_go_version = strings.iter().any(|s| s.value.contains("go1."));

    // At least one should be true
    assert!(
        has_runtime || has_go_version,
        "Go binary should have runtime or version strings"
    );
}

#[test]
fn finds_main_main_in_pclntab() {
    let data = go_binary();

    let strings = extract_strings(&data, 4);

    // Go function names come from the pclntab function-name table, where
    // `main.main` sits NUL-terminated at file offset 0xfa8a8.
    assert!(
        strings.iter().any(|s| s.value == "main.main"
            && s.data_offset == 0xfa8a8
            && s.method == StringMethod::PclntabSymbol),
        "main.main not found in the pclntab"
    );
}
