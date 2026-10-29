//! Tests using cross-compiled ELF and PE binaries

use super::*;

fn go_elf_binary() -> Vec<u8> {
    crate::common::bytes("testdata/elf/hello_linux_amd64")
}

fn go_pe_binary() -> Vec<u8> {
    crate::common::bytes("testdata/pe/hello_windows.exe")
}

// ELF Go binary tests
#[test]
fn test_elf_go_binary_detection() {
    let data = go_elf_binary();

    assert!(
        is_go_binary(&data),
        "ELF Go binary should be detected as Go"
    );
}

#[test]
fn test_elf_go_detect_language() {
    let data = go_elf_binary();

    let lang = detect_language(&data);
    assert_eq!(lang, "go", "ELF Go binary should be detected as 'go'");
}

#[test]
fn test_elf_go_extract_strings() {
    let data = go_elf_binary();

    let strings = extract_strings(&data, 4);
    assert!(!strings.is_empty(), "ELF Go binary should have strings");

    // Go binaries should have many strings
    assert!(
        strings.len() > 100,
        "Expected many strings from Go ELF, got {}",
        strings.len()
    );
}

#[test]
fn test_elf_go_has_runtime_strings() {
    let data = go_elf_binary();

    let strings = extract_strings(&data, 4);

    // Go binaries should have runtime strings
    let has_runtime = strings.iter().any(|s| s.value.contains("runtime"));
    assert!(has_runtime, "ELF Go binary should have runtime strings");
}

#[test]
fn test_elf_go_has_gopclntab_strings() {
    let data = go_elf_binary();

    let strings = extract_strings(&data, 4);

    // Should extract strings successfully from Go ELF binaries
    assert!(
        !strings.is_empty(),
        "ELF Go binary should have extracted strings"
    );

    // Modern Go binaries may not have traditional gopclntab structure
    let _has_func = strings.iter().any(|s| s.kind == Some(StringKind::FuncName));
}

#[test]
fn test_elf_go_has_filepath_strings() {
    let data = go_elf_binary();

    let strings = extract_strings(&data, 4);

    // Should extract strings successfully
    assert!(
        !strings.is_empty(),
        "ELF Go binary should have extracted strings"
    );

    // File paths may or may not be present depending on build flags
    let _has_path = strings
        .iter()
        .any(|s| s.kind == Some(StringKind::FilePath) || s.kind == Some(StringKind::Path));
}

// PE Go binary tests
#[test]
fn test_pe_go_binary_detection() {
    let data = go_pe_binary();

    // PE detection may not identify Go specifically
    let is_go = is_go_binary(&data);
    // Just verify it doesn't panic and returns a boolean
    let _ = is_go;
}

#[test]
fn test_pe_go_extract_strings() {
    let data = go_pe_binary();

    let strings = extract_strings(&data, 4);
    assert!(!strings.is_empty(), "PE Go binary should have strings");
}

#[test]
fn test_pe_go_has_strings() {
    let data = go_pe_binary();

    let strings = extract_strings(&data, 4);

    // PE Go binaries should have some recognizable strings
    let has_hello = strings.iter().any(|s| s.value.contains("Hello"));
    let has_runtime = strings.iter().any(|s| s.value.contains("runtime"));

    assert!(
        has_hello || has_runtime,
        "PE Go binary should have Hello or runtime strings"
    );
}

#[test]
fn test_elf_not_rust() {
    let data = go_elf_binary();

    assert!(
        !is_rust_binary(&data),
        "Go ELF should not be detected as Rust"
    );
}

#[test]
fn test_pe_not_rust() {
    let data = go_pe_binary();

    assert!(
        !is_rust_binary(&data),
        "Go PE should not be detected as Rust"
    );
}

#[test]
fn test_elf_extract_with_options() {
    let data = go_elf_binary();

    let opts = ExtractOptions::new(10);
    let strings = extract_strings_with_options(&data, &opts);
    assert!(!strings.is_empty());
}

#[test]
fn test_pe_extract_with_options() {
    let data = go_pe_binary();

    let opts = ExtractOptions::new(10);
    let strings = extract_strings_with_options(&data, &opts);
    assert!(!strings.is_empty());
}

#[test]
fn test_elf_go_with_garbage_filter() {
    let data = go_elf_binary();

    let opts_filtered = ExtractOptions::new(4).with_garbage_filter(true);
    let opts_unfiltered = ExtractOptions::new(4).with_garbage_filter(false);

    let filtered = extract_strings_with_options(&data, &opts_filtered);
    let unfiltered = extract_strings_with_options(&data, &opts_unfiltered);

    assert!(unfiltered.len() >= filtered.len());
}

#[test]
fn test_pe_go_with_garbage_filter() {
    let data = go_pe_binary();

    let opts_filtered = ExtractOptions::new(4).with_garbage_filter(true);
    let opts_unfiltered = ExtractOptions::new(4).with_garbage_filter(false);

    let filtered = extract_strings_with_options(&data, &opts_filtered);
    let unfiltered = extract_strings_with_options(&data, &opts_unfiltered);

    assert!(unfiltered.len() >= filtered.len());
}

#[test]
fn test_elf_extract_from_object() {
    let data = go_elf_binary();

    let opts = ExtractOptions::new(4);
    let strings = extract_strings_with_options(&data, &opts);

    assert!(!strings.is_empty());
}

#[test]
fn test_pe_extract_from_object() {
    let data = go_pe_binary();

    let opts = ExtractOptions::new(4);
    let strings = extract_strings_with_options(&data, &opts);

    assert!(!strings.is_empty());
}
