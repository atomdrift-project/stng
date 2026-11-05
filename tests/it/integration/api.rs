//! Tests for the new API features

use super::*;

#[test]
fn finds_system_import_in_fat_macho() {
    let data = crate::common::bytes("testdata/macho/charge0x_installer_universal.macho");
    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(&data, &opts);
    // The installer shells out through libc's `system`, bound by name in
    // the x86_64 slice's string table.
    assert!(
        strings.iter().any(|s| s.value == "_system"
            && s.data_offset == 0xf4bc
            && s.kind == Some(StringKind::Import)),
        "_system import not found"
    );
}

#[test]
fn reexports_goblin() {
    // Verify goblin is properly re-exported
    let data = crate::common::bytes("testdata/macho/charge0x_installer_universal.macho");
    assert!(matches!(
        stng::goblin::Object::parse(&data),
        Ok(stng::goblin::Object::Mach(_))
    ));
}

#[test]
fn builder_sets_min_length_and_xor() {
    let opts = ExtractOptions::new(8).with_xor(stng::XorMode::Auto);

    assert_eq!(opts.min_length(), 8);
    assert_eq!(*opts.xor(), stng::XorMode::Auto);
}

#[test]
fn finds_hello_literal_in_go_elf() {
    let path = crate::common::path("testdata/elf/hello_linux_amd64");

    let data = std::fs::read(path).unwrap();
    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(&data, &opts);

    assert!(
        strings.iter().any(|s| s.value == "Hello, World!"
            && s.data_offset == 0xbd6d0
            && s.method == StringMethod::Structure),
        "Hello, World! not found"
    );
}

#[test]
fn finds_main_main_in_go_pe() {
    let path = crate::common::path("testdata/pe/hello_windows.exe");

    let data = std::fs::read(path).unwrap();
    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(&data, &opts);

    assert!(
        strings.iter().any(|s| s.value == "main.main"
            && s.data_offset == 0x102fc0
            && s.method == StringMethod::PclntabSymbol),
        "main.main not found in the pclntab"
    );
}
