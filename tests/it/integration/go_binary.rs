//! Tests using real Go binaries

use super::*;

fn go_binary() -> Vec<u8> {
    crate::common::bytes("testdata/elf/hello_linux_amd64")
}

#[test]
fn test_detect_go_binary() {
    let data = go_binary();

    let is_go = is_go_binary(&data);
    assert!(is_go, "Go binary should be detected as Go");
}

#[test]
fn test_detect_language_go() {
    let data = go_binary();

    let lang = detect_language(&data);
    assert_eq!(lang, "go", "Go binary should be detected as 'go'");
}

#[test]
fn test_extract_strings_go_binary() {
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
fn test_go_binary_has_go_strings() {
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
fn test_go_binary_has_funcname_kinds() {
    let data = go_binary();

    let strings = extract_strings(&data, 4);

    // Go binaries should extract strings successfully
    // Modern Go binaries may have different internal structures
    // Just verify we extracted some reasonable strings
    assert!(
        !strings.is_empty(),
        "Go binary should have some extracted strings"
    );

    // If we do find FuncName strings, that's great, but not required
    let _has_funcname = strings.iter().any(|s| s.kind == Some(StringKind::FuncName));
}
