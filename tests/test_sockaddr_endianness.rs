//! End-to-end coverage for the endianness-aware `sockaddr_in` scan and the
//! extended Windows-registry classifier (see `binary_net::scan_sockaddr_in` and
//! `classifier::is_registry_path`).
//!
//! These tests build a minimal-but-real PE32 image so that goblin parses it as
//! a PE, which is what triggers the LE-only AF_INET branch. The image embeds
//! both a plausible-looking big-endian sockaddr_in (which must be ignored on
//! Windows/PE) and a true little-endian one (which must still be reported), as
//! well as several registry strings.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use stng::{ExtractOptions, StringKind, classify_string, extract_strings_with_options};

/// Builds a minimal PE32 image (i386, single `.data` section) with `data_bytes`
/// placed at the start of `.data`. The image is just complete enough for
/// goblin's PE parser to succeed — we only need that, not a runnable program.
fn build_minimal_pe32(data_bytes: &[u8]) -> Vec<u8> {
    const PE_OFFSET: usize = 0x80;
    const COFF_OFFSET: usize = PE_OFFSET + 4;
    const OPTIONAL_HEADER_OFFSET: usize = COFF_OFFSET + 20;
    const SIZE_OF_OPTIONAL_HEADER: u16 = 224; // standard PE32 optional header
    const SECTION_HEADER_OFFSET: usize = OPTIONAL_HEADER_OFFSET + SIZE_OF_OPTIONAL_HEADER as usize;
    const SECTION_ALIGNMENT: u32 = 0x1000;
    const FILE_ALIGNMENT: u32 = 0x200;
    const SECTION_RAW_OFFSET: u32 = 0x400;
    const SECTION_VIRTUAL_ADDR: u32 = 0x1000;

    let raw_size = (data_bytes.len() as u32)
        .next_multiple_of(FILE_ALIGNMENT)
        .max(FILE_ALIGNMENT);
    let total_size = SECTION_RAW_OFFSET + raw_size;

    let mut img = vec![0u8; total_size as usize];

    // ── DOS header ──
    img[0..2].copy_from_slice(b"MZ");
    img[0x3C..0x40].copy_from_slice(&(PE_OFFSET as u32).to_le_bytes());

    // ── PE signature ──
    img[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");

    // ── COFF file header ──
    img[COFF_OFFSET..COFF_OFFSET + 2].copy_from_slice(&0x014Cu16.to_le_bytes()); // Machine: IMAGE_FILE_MACHINE_I386
    img[COFF_OFFSET + 2..COFF_OFFSET + 4].copy_from_slice(&1u16.to_le_bytes()); // 1 section
    img[COFF_OFFSET + 4..COFF_OFFSET + 8].copy_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
    img[COFF_OFFSET + 8..COFF_OFFSET + 12].copy_from_slice(&0u32.to_le_bytes()); // SymTab ptr
    img[COFF_OFFSET + 12..COFF_OFFSET + 16].copy_from_slice(&0u32.to_le_bytes()); // NumSyms
    img[COFF_OFFSET + 16..COFF_OFFSET + 18].copy_from_slice(&SIZE_OF_OPTIONAL_HEADER.to_le_bytes());
    img[COFF_OFFSET + 18..COFF_OFFSET + 20].copy_from_slice(&0x0102u16.to_le_bytes()); // EXECUTABLE_IMAGE | 32BIT

    // ── Optional header (PE32) ──
    let oh = OPTIONAL_HEADER_OFFSET;
    img[oh..oh + 2].copy_from_slice(&0x010Bu16.to_le_bytes()); // Magic: PE32
    img[oh + 2] = 1; // MajorLinkerVersion
    img[oh + 3] = 0; // MinorLinkerVersion
    img[oh + 4..oh + 8].copy_from_slice(&raw_size.to_le_bytes()); // SizeOfCode
    img[oh + 8..oh + 12].copy_from_slice(&raw_size.to_le_bytes()); // SizeOfInitializedData
    img[oh + 12..oh + 16].copy_from_slice(&0u32.to_le_bytes()); // SizeOfUninitializedData
    img[oh + 16..oh + 20].copy_from_slice(&0u32.to_le_bytes()); // AddressOfEntryPoint
    img[oh + 20..oh + 24].copy_from_slice(&SECTION_VIRTUAL_ADDR.to_le_bytes()); // BaseOfCode
    img[oh + 24..oh + 28].copy_from_slice(&SECTION_VIRTUAL_ADDR.to_le_bytes()); // BaseOfData
    img[oh + 28..oh + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes()); // ImageBase
    img[oh + 32..oh + 36].copy_from_slice(&SECTION_ALIGNMENT.to_le_bytes());
    img[oh + 36..oh + 40].copy_from_slice(&FILE_ALIGNMENT.to_le_bytes());
    img[oh + 40..oh + 42].copy_from_slice(&4u16.to_le_bytes()); // MajorOSVersion
    img[oh + 48..oh + 50].copy_from_slice(&4u16.to_le_bytes()); // MajorSubsystemVersion
    img[oh + 56..oh + 60]
        .copy_from_slice(&(SECTION_VIRTUAL_ADDR + SECTION_ALIGNMENT).to_le_bytes()); // SizeOfImage
    img[oh + 60..oh + 64].copy_from_slice(&SECTION_RAW_OFFSET.to_le_bytes()); // SizeOfHeaders
    img[oh + 68..oh + 70].copy_from_slice(&3u16.to_le_bytes()); // Subsystem: CONSOLE
    img[oh + 92..oh + 96].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes

    // ── Section header (.data) ──
    let sh = SECTION_HEADER_OFFSET;
    img[sh..sh + 5].copy_from_slice(b".data");
    img[sh + 8..sh + 12].copy_from_slice(&raw_size.to_le_bytes()); // VirtualSize
    img[sh + 12..sh + 16].copy_from_slice(&SECTION_VIRTUAL_ADDR.to_le_bytes());
    img[sh + 16..sh + 20].copy_from_slice(&raw_size.to_le_bytes()); // SizeOfRawData
    img[sh + 20..sh + 24].copy_from_slice(&SECTION_RAW_OFFSET.to_le_bytes());
    img[sh + 36..sh + 40].copy_from_slice(&0xC000_0040u32.to_le_bytes()); // R/W initialized data

    // ── Section payload ──
    let start = SECTION_RAW_OFFSET as usize;
    img[start..start + data_bytes.len()].copy_from_slice(data_bytes);

    img
}

#[test]
fn pe_le_rejects_big_endian_sockaddr_in_false_positives() {
    // Pre-flight: a known-real LE sockaddr_in we WANT extracted, plus the two
    // BE-marker patterns from the 185291 sample that were previously surfaced
    // as fake IPs.
    let mut payload = vec![0u8; 0x600];
    // Real LE sockaddr_in: 192.168.1.50:8080 at offset 0x10 within .data
    payload[0x10] = 0x02;
    payload[0x11] = 0x00;
    payload[0x12..0x14].copy_from_slice(&[0x1F, 0x90]);
    payload[0x14..0x18].copy_from_slice(&[0xC0, 0xA8, 0x01, 0x32]);

    // Fake "BE sockaddr_in" from the 185291 sample at offset 0x100:
    //   00 02 BC FB 9B F1 EF 1A  → would decode to 155.241.239.26:48379
    payload[0x100] = 0x00;
    payload[0x101] = 0x02;
    payload[0x102..0x104].copy_from_slice(&[0xBC, 0xFB]);
    payload[0x104..0x108].copy_from_slice(&[0x9B, 0xF1, 0xEF, 0x1A]);

    // Second fake from a small-int lookup table at offset 0x200:
    //   00 02 0A 15 16 1A 1C 1E  → would decode to 22.26.28.30:2581
    payload[0x200] = 0x00;
    payload[0x201] = 0x02;
    payload[0x202..0x204].copy_from_slice(&[0x0A, 0x15]);
    payload[0x204..0x208].copy_from_slice(&[0x16, 0x1A, 0x1C, 0x1E]);

    let pe = build_minimal_pe32(&payload);
    let strings = extract_strings_with_options(&pe, &ExtractOptions::new(4));

    let ip_ports: Vec<&str> = strings
        .iter()
        .filter(|s| matches!(s.kind, Some(StringKind::IPPort)))
        .map(|s| s.value.as_str())
        .collect();

    assert!(
        !ip_ports.iter().any(|v| v.contains("155.241.239.26")),
        "BE-marker GUID-like sequence must not be classified as a sockaddr_in IP on an LE PE; got: {ip_ports:?}"
    );
    assert!(
        !ip_ports.iter().any(|v| v.contains("22.26.28.30")),
        "BE-marker lookup-table bytes must not be classified as a sockaddr_in IP on an LE PE; got: {ip_ports:?}"
    );

    // Regression guard: the genuine LE sockaddr_in is still extracted.
    assert!(
        ip_ports.contains(&"192.168.1.50:8080"),
        "Real LE sockaddr_in must still be reported on an LE PE; got: {ip_ports:?}"
    );
}

#[test]
fn registry_subkey_paths_are_classified() {
    // Strings that appear in the wild as `lpSubKey` arguments to RegOpenKeyExA
    // (the hKey is passed separately, so the embedded literal has no HKEY_ prefix).
    let cases = &[
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\Launch.exe",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
        "Software\\JavaSoft\\Java Runtime Environment",
        "Software\\Classes\\CLSID",
        "Software\\Wow6432Node\\Microsoft\\Office",
        "SOFTWARE\\Microsoft\\Cryptography",
        "System\\CurrentControlSet\\Services\\Tcpip\\Parameters",
        // Pre-existing forms must still classify.
        "HKEY_LOCAL_MACHINE\\SOFTWARE",
        "HKLM\\Software\\Foo",
        "HKCU\\Software\\Bar",
        "HKCR\\.exe",
        "HKU\\S-1-5-21-1\\Software",
        "HKCC\\System\\CurrentControlSet",
    ];

    for case in cases {
        assert_eq!(
            classify_string(case),
            Some(StringKind::Registry),
            "expected {case:?} to be classified as Registry"
        );
    }
}

#[test]
fn non_registry_software_paths_are_not_misclassified() {
    // Generic strings starting with "Software" / "System" but not following the
    // hive-subkey convention must NOT be classified as Registry.
    let cases = &[
        "Software",
        "System",
        "Systems",
        "Software is great",
        // Single-component hive-relative form is too ambiguous (could be a
        // filesystem directory in an installer manifest) — we deliberately
        // leave it unclassified rather than flagging it as Registry.
        "Software\\MyAppName",
    ];

    for case in cases {
        assert_ne!(
            classify_string(case),
            Some(StringKind::Registry),
            "{case:?} must not be classified as Registry"
        );
    }
}

#[test]
fn registry_subkey_in_pe_data_is_extracted_and_classified() {
    // End-to-end: same path through extract_strings_with_options. The string
    // must be extracted from .data AND tagged as Registry.
    let mut payload = vec![0u8; 0x400];
    let s = b"Software\\Microsoft\\Windows\\CurrentVersion\\Run\0";
    payload[..s.len()].copy_from_slice(s);

    let pe = build_minimal_pe32(&payload);
    let strings = extract_strings_with_options(&pe, &ExtractOptions::new(4));

    let hit = strings
        .iter()
        .find(|s| s.value == "Software\\Microsoft\\Windows\\CurrentVersion\\Run")
        .expect("registry subkey string should be extracted from .data");

    assert_eq!(
        hit.kind,
        Some(StringKind::Registry),
        "embedded registry subkey should classify as Registry, got {:?}",
        hit.kind
    );
}
