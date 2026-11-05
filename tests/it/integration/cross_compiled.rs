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
fn detects_go_elf() {
    let data = go_elf_binary();

    assert!(
        is_go_binary(&data),
        "ELF Go binary should be detected as Go"
    );
}

#[test]
fn detects_go_language_in_elf() {
    let data = go_elf_binary();

    let lang = detect_language(&data);
    assert_eq!(
        lang,
        stng::Language::Go,
        "ELF Go binary should be detected as 'go'"
    );
}

#[test]
fn finds_many_strings_in_go_elf() {
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
fn finds_runtime_strings_in_go_elf() {
    let data = go_elf_binary();

    let strings = extract_strings(&data, 4);

    // Go binaries should have runtime strings
    let has_runtime = strings.iter().any(|s| s.value.contains("runtime"));
    assert!(has_runtime, "ELF Go binary should have runtime strings");
}

#[test]
fn finds_runtime_main_in_elf_pclntab() {
    let data = go_elf_binary();

    let strings = extract_strings(&data, 4);

    assert!(
        strings.iter().any(|s| s.value == "runtime.main"
            && s.data_offset == 0xef99d
            && s.method == StringMethod::PclntabSymbol),
        "runtime.main not found in the pclntab"
    );
}

#[test]
fn finds_go_source_path_in_elf_pclntab() {
    let data = go_elf_binary();

    let strings = extract_strings(&data, 4);

    // The pclntab file table names every compiled source file.
    let proc_go = "/opt/homebrew/Cellar/go/1.25.6/libexec/src/runtime/proc.go";
    assert!(
        strings.iter().any(|s| s.value == proc_go
            && s.data_offset == 0xfc151
            && s.method == StringMethod::PclntabSymbol
            && s.kind == Some(StringKind::Path)),
        "{proc_go} not found in the pclntab"
    );
}

// PE Go binary tests
#[test]
fn detects_go_pe() {
    let data = go_pe_binary();

    assert!(is_go_binary(&data), "PE Go binary should be detected as Go");
}

#[test]
fn finds_hello_literal_in_go_pe() {
    let data = go_pe_binary();

    let strings = extract_strings(&data, 4);
    // The program's one literal, recovered as a length-delimited Go string.
    assert!(
        strings.iter().any(|s| s.value == "Hello, World!"
            && s.data_offset == 0xc4959
            && s.method == StringMethod::Structure),
        "Hello, World! not found"
    );
}

#[test]
fn finds_hello_or_runtime_in_go_pe() {
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
fn go_elf_is_not_rust() {
    let data = go_elf_binary();

    assert!(
        !is_rust_binary(&data),
        "Go ELF should not be detected as Rust"
    );
}

#[test]
fn go_pe_is_not_rust() {
    let data = go_pe_binary();

    assert!(
        !is_rust_binary(&data),
        "Go PE should not be detected as Rust"
    );
}

#[test]
fn min_length_drops_short_symbols_in_go_elf() {
    let data = go_elf_binary();

    let opts = ExtractOptions::new(10);
    let strings = extract_strings_with_options(&data, &opts);
    // 13 bytes clears the bar; the 9-byte `main.main` symbol does not.
    assert!(strings.iter().any(|s| s.value == "Hello, World!"));
    assert!(!strings.iter().any(|s| s.value == "main.main"));
}

#[test]
fn min_length_drops_short_symbols_in_go_pe() {
    let data = go_pe_binary();

    let opts = ExtractOptions::new(10);
    let strings = extract_strings_with_options(&data, &opts);
    // 13 bytes clears the bar; the 9-byte `main.main` symbol does not.
    assert!(strings.iter().any(|s| s.value == "Hello, World!"));
    assert!(!strings.iter().any(|s| s.value == "main.main"));
}

#[test]
fn garbage_filter_never_grows_go_elf_output() {
    let data = go_elf_binary();

    let opts_filtered = ExtractOptions::new(4).with_garbage_filter(true);
    let opts_unfiltered = ExtractOptions::new(4).with_garbage_filter(false);

    let filtered = extract_strings_with_options(&data, &opts_filtered);
    let unfiltered = extract_strings_with_options(&data, &opts_unfiltered);

    assert!(unfiltered.len() >= filtered.len());
}

#[test]
fn garbage_filter_never_grows_go_pe_output() {
    let data = go_pe_binary();

    let opts_filtered = ExtractOptions::new(4).with_garbage_filter(true);
    let opts_unfiltered = ExtractOptions::new(4).with_garbage_filter(false);

    let filtered = extract_strings_with_options(&data, &opts_filtered);
    let unfiltered = extract_strings_with_options(&data, &opts_unfiltered);

    assert!(unfiltered.len() >= filtered.len());
}

#[test]
fn finds_go_version_in_elf() {
    let data = go_elf_binary();

    let opts = ExtractOptions::new(4);
    let strings = extract_strings_with_options(&data, &opts);

    // The toolchain version recorded in the build info.
    assert!(
        strings.iter().any(|s| s.value == "go1.25.6"
            && s.data_offset == 0xe3e58
            && s.method == StringMethod::Structure),
        "go1.25.6 not found"
    );
}

#[test]
fn finds_go_version_in_pe() {
    let data = go_pe_binary();

    let opts = ExtractOptions::new(4);
    let strings = extract_strings_with_options(&data, &opts);

    // The toolchain version recorded in the build info.
    assert!(
        strings.iter().any(|s| s.value == "go1.25.6"
            && s.data_offset == 0xec120
            && s.method == StringMethod::Structure),
        "go1.25.6 not found"
    );
}
