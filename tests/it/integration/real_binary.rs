//! Tests using real system binaries for higher coverage

use super::*;

/// A small C program built with MSVC.
fn real_binary() -> Vec<u8> {
    crate::common::bytes("testdata/pe/msvc_console_amd64.exe")
}

#[test]
fn finds_powershell_exclusion_command() {
    let data = real_binary();

    let strings = extract_strings(&data, 4);
    // The program's payload: a Defender exclusion for the whole C: drive.
    assert!(
        strings.iter().any(|s| s.value
            == r#"powershell -Command "Add-MpPreference -ExclusionPath 'C:\'""#
            && s.data_offset == 0x1450),
        "powershell command not found"
    );
}

#[test]
fn detects_compiled_language() {
    let data = real_binary();

    let lang = detect_language(&data);
    // Real system binary is typically C/unknown
    assert!(matches!(
        lang,
        stng::Language::Unknown | stng::Language::Rust | stng::Language::Go
    ));
}

#[test]
fn is_not_go() {
    let data = real_binary();

    // System binaries are typically not Go
    let result = is_go_binary(&data);
    assert!(!result, "System binary should not be Go");
}

#[test]
fn is_not_rust() {
    let data = real_binary();

    // System binaries are typically not Rust
    let result = is_rust_binary(&data);
    assert!(!result, "System binary should not be Rust");
}

#[test]
fn finds_system_import() {
    let data = real_binary();

    let opts = ExtractOptions::new(4);
    let strings = extract_strings_with_options(&data, &opts);
    // The CRT `system` the payload runs through, at its import-by-name entry.
    assert!(
        strings.iter().any(|s| s.value == "system"
            && s.data_offset == 0x1d5a
            && s.kind == Some(StringKind::Import)),
        "system import not found"
    );
}

#[test]
fn higher_min_length_finds_fewer() {
    let data = real_binary();

    let strings_4 = extract_strings(&data, 4);
    let strings_10 = extract_strings(&data, 10);
    let strings_20 = extract_strings(&data, 20);

    // More restrictive min_length should yield fewer or equal strings
    assert!(strings_10.len() <= strings_4.len());
    assert!(strings_20.len() <= strings_10.len());
}

#[test]
fn raw_scan_values_match_file_bytes() {
    let data = real_binary();

    let strings = extract_strings(&data, 4);
    let raw: Vec<_> = strings
        .iter()
        .filter(|s| s.method == StringMethod::RawScan)
        .collect();
    assert!(!raw.is_empty(), "no raw-scan strings");
    // A raw-scan string is a byte-identical copy of the file at its offset.
    for s in raw {
        let start = usize::try_from(s.data_offset).unwrap();
        assert_eq!(
            data.get(start..start + s.value.len()),
            Some(s.value.as_bytes()),
            "{:?} at 0x{start:x}",
            s.value
        );
    }
}
