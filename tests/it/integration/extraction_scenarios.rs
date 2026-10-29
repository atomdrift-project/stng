//! Tests for edge cases and corner cases
//! Additional tests for specific extraction scenarios

use super::*;

#[test]
fn test_extract_unknown_binary_format() {
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
fn test_extract_corrupted_elf() {
    let mut data = minimal_elf_header();
    // Corrupt the header
    data[16] = 0xFF;
    data[17] = 0xFF;
    // Must not panic.
    let _ = extract_strings(&data, 4);
}

#[test]
fn test_extract_corrupted_macho() {
    let mut data = minimal_macho_header();
    // Set invalid CPU type
    data[4..8].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
    // Must not panic.
    let _ = extract_strings(&data, 4);
}

#[test]
fn test_extract_very_small_binary() {
    // Just the magic bytes for ELF
    let data = vec![0x7f, b'E', b'L', b'F'];
    let strings = extract_strings(&data, 4);
    assert!(strings.is_empty());
}

#[test]
fn test_extract_very_small_macho() {
    // Just the magic bytes for Mach-O
    let data = vec![0xCF, 0xFA, 0xED, 0xFE];
    let strings = extract_strings(&data, 4);
    assert!(strings.is_empty());
}
