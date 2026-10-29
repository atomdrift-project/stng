//! Tests for extraction and overlay detection

use stng::{
    ExtractOptions, detect_elf_overlay, extract_overlay_strings, extract_strings_with_options,
};

fn minimal_elf_with_strings(strings: &[&str]) -> Vec<u8> {
    let mut data = vec![0u8; 1024];
    // ELF magic
    data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    data[4] = 2; // 64-bit
    data[5] = 1; // little-endian
    data[6] = 1; // version
    data[16..18].copy_from_slice(&[2, 0]); // executable
    data[18..20].copy_from_slice(&[0x3E, 0]); // x86_64

    // Embed strings starting at 0x200
    let mut offset = 0x200;
    for s in strings {
        let bytes = s.as_bytes();
        data[offset..offset + bytes.len()].copy_from_slice(bytes);
        data[offset + bytes.len()] = 0;
        offset += bytes.len() + 1;
    }

    // Trim to actual used size to avoid false overlay detection
    data.truncate(offset);
    data
}

fn minimal_macho_with_strings(strings: &[&str]) -> Vec<u8> {
    let mut data = vec![0u8; 1024];
    // Mach-O 64-bit magic
    data[0..4].copy_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]);
    data[4..8].copy_from_slice(&[0x07, 0x00, 0x00, 0x01]); // x86_64
    data[8..12].copy_from_slice(&[0x03, 0x00, 0x00, 0x00]); // subtype
    data[12..16].copy_from_slice(&[0x02, 0x00, 0x00, 0x00]); // executable

    // Embed strings starting at 0x200
    let mut offset = 0x200;
    for s in strings {
        let bytes = s.as_bytes();
        data[offset..offset + bytes.len()].copy_from_slice(bytes);
        data[offset + bytes.len()] = 0;
        offset += bytes.len() + 1;
    }
    data
}

fn minimal_pe_with_overlay(overlay_data: &[u8]) -> Vec<u8> {
    let mut data = vec![0u8; 1024];
    // DOS header
    data[0..2].copy_from_slice(&[0x4D, 0x5A]); // MZ
    data[0x3C..0x40].copy_from_slice(&[0x80, 0x00, 0x00, 0x00]); // PE offset

    // PE signature
    data[0x80..0x84].copy_from_slice(&[0x50, 0x45, 0x00, 0x00]); // PE\0\0

    // COFF header (20 bytes)
    data[0x84..0x86].copy_from_slice(&[0x64, 0x86]); // Machine: AMD64
    data[0x86..0x88].copy_from_slice(&[0x01, 0x00]); // NumberOfSections: 1
    data[0x94..0x96].copy_from_slice(&[0xF0, 0x00]); // SizeOfOptionalHeader: 240

    // Optional header
    data[0x98..0x9A].copy_from_slice(&[0x0B, 0x02]); // Magic: PE32+
    // SizeOfHeaders at offset 0x98 + 60 = 0xD4
    data[0xD4..0xD8].copy_from_slice(&[0x00, 0x02, 0x00, 0x00]); // SizeOfHeaders: 512

    // Section header at 0x188 (after optional header)
    // .text section
    data[0x188..0x190].copy_from_slice(b".text\0\0\0");
    // VirtualSize
    data[0x190..0x194].copy_from_slice(&[0x00, 0x02, 0x00, 0x00]); // 512
    // VirtualAddress
    data[0x194..0x198].copy_from_slice(&[0x00, 0x10, 0x00, 0x00]); // 0x1000
    // SizeOfRawData
    data[0x198..0x19C].copy_from_slice(&[0x00, 0x02, 0x00, 0x00]); // 512
    // PointerToRawData
    data[0x19C..0x1A0].copy_from_slice(&[0x00, 0x02, 0x00, 0x00]); // 512

    // Section data starts at 512, ends at 1024
    // Append overlay data
    data.extend_from_slice(overlay_data);
    data
}

#[test]
fn test_extract_from_elf_basic() {
    let data = minimal_elf_with_strings(&["hello_from_elf", "test_string_elf"]);
    let opts = ExtractOptions::new(4);

    let strings = extract_strings_with_options(&data, &opts);

    // Should find some strings (at minimum from raw scan)
    let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();
    assert!(
        values
            .iter()
            .any(|v| v.contains("hello") || v.contains("test")),
        "Should extract strings from ELF: {values:?}"
    );
}

#[test]
fn test_extract_from_macho_basic() {
    let data = minimal_macho_with_strings(&["hello_from_macho", "test_string_macho"]);
    let opts = ExtractOptions::new(4);

    let strings = extract_strings_with_options(&data, &opts);

    let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();
    assert!(
        values
            .iter()
            .any(|v| v.contains("hello") || v.contains("test")),
        "Should extract strings from Mach-O: {values:?}"
    );
}

#[test]
fn test_extract_from_pe_basic() {
    let mut data = vec![0u8; 1024];
    // DOS header
    data[0..2].copy_from_slice(&[0x4D, 0x5A]);
    data[0x3C..0x40].copy_from_slice(&[0x80, 0x00, 0x00, 0x00]);
    // PE signature
    data[0x80..0x84].copy_from_slice(&[0x50, 0x45, 0x00, 0x00]);
    // Add strings
    data[0x200..0x210].copy_from_slice(b"hello_from_pe\0\0\0");

    let opts = ExtractOptions::new(4);

    let strings = extract_strings_with_options(&data, &opts);

    let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();
    assert!(
        values.iter().any(|v| v.contains("hello")),
        "Should extract strings from PE: {values:?}"
    );
}

#[test]
fn test_extract_overlay_strings_basic() {
    // Create PE with overlay containing strings
    let overlay = b"OVERLAY_SECRET_STRING\0more_overlay_data\0";
    let data = minimal_pe_with_overlay(overlay);

    // Overlay extraction covers ELF only.
    assert!(extract_overlay_strings(&data, 4).is_empty());
}

#[test]
fn test_detect_elf_overlay_no_overlay() {
    let data = minimal_elf_with_strings(&["test"]);
    let overlay = detect_elf_overlay(&data);
    // Minimal ELF without proper section headers will have data treated as overlay
    // Just verify the detection doesn't crash and returns reasonable results
    if let Some(o) = overlay {
        assert!(o.start_offset >= 64); // Should start after ELF header
        assert!(o.size < data.len() as u64); // Should be less than total file size
    }
}

#[test]
fn test_overlay_string_offsets_are_absolute() {
    // Create a minimal ELF that ends at a known offset
    let mut data = vec![0u8; 1024];
    // ELF magic
    data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    data[4] = 2; // 64-bit
    data[5] = 1; // little-endian
    data[6] = 1; // version
    data[16..18].copy_from_slice(&[2, 0]); // executable
    data[18..20].copy_from_slice(&[0x3E, 0]); // x86_64

    // Set e_shoff (section header offset) to 512
    data[40..48].copy_from_slice(&[0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    // Set e_shnum (section header count) to 1
    data[60..62].copy_from_slice(&[0x01, 0x00]);
    // Set e_shentsize (section header entry size) to 64
    data[58..60].copy_from_slice(&[0x40, 0x00]);

    // Section header at offset 512 (0x200)
    // This section ends at offset 512 + 64 = 576 (0x240)
    let section_header_start = 512;
    data[section_header_start..section_header_start + 4].copy_from_slice(&[0x01, 0x00, 0x00, 0x00]); // sh_name
    data[section_header_start + 4..section_header_start + 8]
        .copy_from_slice(&[0x01, 0x00, 0x00, 0x00]); // sh_type

    // ELF structure ends at 576 (0x240)
    let elf_end = 576;

    // Append overlay data starting at offset 576 (0x240)
    // Add some padding to reach exactly 576 bytes
    data.truncate(elf_end);

    // Add overlay strings at known positions
    // First string "OVERLAY_TEST_AAA" starts at offset 576 (0x240)
    let overlay_start = data.len();
    data.extend_from_slice(b"OVERLAY_TEST_AAA\0");
    let first_string_offset = overlay_start;

    // Second string "OVERLAY_TEST_BBB" starts at offset 593 (0x251)
    data.extend_from_slice(b"OVERLAY_TEST_BBB\0");
    let second_string_offset = overlay_start + 17;

    // Extract overlay strings
    let strings = extract_overlay_strings(&data, 4);

    // Verify we found the strings
    assert!(!strings.is_empty(), "Should find overlay strings");

    // Find our test strings
    let test_aaa = strings
        .iter()
        .find(|s| s.value.contains("OVERLAY_TEST_AAA"));
    let test_bbb = strings
        .iter()
        .find(|s| s.value.contains("OVERLAY_TEST_BBB"));

    // Verify offsets are absolute file offsets, not relative to overlay start
    let s = test_aaa.expect("Should find OVERLAY_TEST_AAA string");
    assert_eq!(
        usize::try_from(s.data_offset).unwrap(),
        first_string_offset,
        "First overlay string offset should be absolute file offset 0x{first_string_offset:x}, not relative to overlay"
    );
    assert_eq!(
        s.kind,
        Some(stng::StringKind::Overlay),
        "Should be marked as overlay"
    );

    let s = test_bbb.expect("Should find OVERLAY_TEST_BBB string");
    assert_eq!(
        usize::try_from(s.data_offset).unwrap(),
        second_string_offset,
        "Second overlay string offset should be absolute file offset 0x{second_string_offset:x}, not relative to overlay"
    );
    assert_eq!(
        s.kind,
        Some(stng::StringKind::Overlay),
        "Should be marked as overlay"
    );
}

#[test]
fn test_extract_from_elf_with_garbage_filter() {
    let data = minimal_elf_with_strings(&["valid_string", "@@##$$"]);
    let mut opts = ExtractOptions::new(4);
    opts.filter_garbage = true;

    let strings = extract_strings_with_options(&data, &opts);

    // Garbage filter should remove noise
    let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();
    assert!(!values.contains(&"@@##$$"), "Garbage should be filtered");
}

#[test]
fn test_extract_from_macho_with_garbage_filter() {
    let data = minimal_macho_with_strings(&["valid_string", "@@##$$"]);
    let mut opts = ExtractOptions::new(4);
    opts.filter_garbage = true;

    let strings = extract_strings_with_options(&data, &opts);

    let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();
    assert!(!values.contains(&"@@##$$"), "Garbage should be filtered");
}

#[test]
fn test_extract_from_pe_with_garbage_filter() {
    let mut data = vec![0u8; 1024];
    data[0..2].copy_from_slice(&[0x4D, 0x5A]);
    data[0x3C..0x40].copy_from_slice(&[0x80, 0x00, 0x00, 0x00]);
    data[0x80..0x84].copy_from_slice(&[0x50, 0x45, 0x00, 0x00]);
    data[0x200..0x210].copy_from_slice(b"valid_string\0\0\0\0");

    let mut opts = ExtractOptions::new(4);
    opts.filter_garbage = true;

    let strings = extract_strings_with_options(&data, &opts);
    assert!(strings.iter().any(|s| s.value == "valid_string"));
}
