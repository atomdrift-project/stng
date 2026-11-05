//! Tests for edge cases and corner cases
//! Additional tests for specific extraction scenarios

use super::*;

#[test]
fn finds_whole_run_in_unknown_format() {
    // Random data that isn't ELF, Mach-O, or PE
    let data = b"RANDOMDATANOTABINARYFORMAT123456789";
    let strings = extract_strings(data, 4);
    assert!(
        strings
            .iter()
            .any(|s| s.value == "RANDOMDATANOTABINARYFORMAT123456789")
    );
}

#[test]
fn corrupted_elf_does_not_panic() {
    let mut data = minimal_elf_header();
    // Corrupt the header
    data[16] = 0xFF;
    data[17] = 0xFF;
    // Must not panic.
    let _ = extract_strings(&data, 4);
}

#[test]
fn corrupted_macho_does_not_panic() {
    let mut data = minimal_macho_header();
    // Set invalid CPU type
    data[4..8].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
    // Must not panic.
    let _ = extract_strings(&data, 4);
}

#[test]
fn finds_nothing_in_elf_magic_alone() {
    // Just the magic bytes for ELF
    let data = vec![0x7f, b'E', b'L', b'F'];
    let strings = extract_strings(&data, 4);
    assert!(strings.is_empty());
}

#[test]
fn finds_nothing_in_macho_magic_alone() {
    // Just the magic bytes for Mach-O
    let data = vec![0xCF, 0xFA, 0xED, 0xFE];
    let strings = extract_strings(&data, 4);
    assert!(strings.is_empty());
}
