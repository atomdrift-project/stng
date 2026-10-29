//! Tests for the new API features

use super::*;

#[test]
fn test_extract_from_object_api() {
    let data = crate::common::bytes("testdata/macho/charge0x_installer_universal.macho");
    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(&data, &opts);
    assert!(!strings.is_empty());
}

#[test]
fn test_extract_from_object_with_preextracted_r2() {
    let data = crate::common::bytes("testdata/macho/charge0x_installer_universal.macho");

    // Create fake pre-extracted r2 strings
    let fake_r2 = vec![ExtractedString {
        value: "fake_r2_string".to_string(),
        data_offset: 0x1000,
        method: StringMethod::R2String,
        kind: None,
        ..Default::default()
    }];

    let opts = ExtractOptions::new(4).with_r2_strings(fake_r2);
    let strings = stng::extract_strings_with_options(&data, &opts);

    // Should include our fake r2 string
    assert!(strings.iter().any(|s| s.value == "fake_r2_string"));
}

#[test]
fn test_goblin_reexport() {
    // Verify goblin is properly re-exported
    let data = crate::common::bytes("testdata/macho/charge0x_installer_universal.macho");
    assert!(matches!(
        stng::goblin::Object::parse(&data),
        Ok(stng::goblin::Object::Mach(_))
    ));
}

#[test]
fn test_extract_options_builder_chain() {
    let fake_strings = vec![ExtractedString {
        value: "test".to_string(),
        data_offset: 0,
        method: StringMethod::R2String,
        kind: None,
        ..Default::default()
    }];

    let opts = ExtractOptions::new(8).with_r2_strings(fake_strings);

    assert_eq!(opts.min_length, 8);
    assert!(opts.r2_strings.is_some());
}

#[test]
fn test_extract_from_elf_object() {
    let path = crate::common::path("testdata/elf/hello_linux_amd64");

    let data = std::fs::read(path).unwrap();
    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(&data, &opts);

    assert!(!strings.is_empty());
}

#[test]
fn test_extract_from_pe_object() {
    let path = crate::common::path("testdata/pe/hello_windows.exe");

    let data = std::fs::read(path).unwrap();
    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(&data, &opts);

    assert!(!strings.is_empty());
}
