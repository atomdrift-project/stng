//! Tests for ELF overlay/appended data detection (overlay.rs).

use stng::{StringKind, detect_elf_overlay, extract_overlay_strings};

fn read_hello_linux() -> Vec<u8> {
    crate::common::bytes("testdata/elf/hello_linux_amd64")
}

// ── detect_elf_overlay ──────────────────────────────────────────────────────

#[test]
fn finds_no_overlay_in_clean_elf() {
    let data = read_hello_linux();
    assert!(
        detect_elf_overlay(&data).is_none(),
        "Unmodified ELF binary should have no overlay"
    );
}

#[test]
fn detects_appended_data() {
    let mut data = read_hello_linux();
    // 200 bytes of payload — well above the 16-byte minimum threshold
    let payload = b"AppendedPayloadData: injected content 1234567890.".repeat(4);
    data.extend_from_slice(&payload);

    let overlay = detect_elf_overlay(&data);
    assert!(
        overlay.is_some(),
        "Overlay should be detected after appending data to ELF"
    );
}

#[test]
fn reports_overlay_size_and_start() {
    let mut data = read_hello_linux();
    let original_size = data.len();

    let payload = b"OverlaySizeCheckPayload0123456789"; // 32 bytes, well above threshold
    let payload_len = payload.len();
    data.extend_from_slice(payload);

    let info = detect_elf_overlay(&data).expect("Overlay should be detected");

    assert_eq!(
        usize::try_from(info.size).unwrap(),
        payload_len,
        "Reported overlay size should exactly match the appended payload length"
    );
    assert_eq!(
        usize::try_from(info.start_offset).unwrap(),
        original_size,
        "Overlay start offset should be at the original file boundary"
    );
}

#[test]
fn ignores_overlay_under_16_bytes() {
    let mut data = read_hello_linux();
    // 10 bytes — below the minimum of 16 (avoids false positives from alignment padding)
    data.extend_from_slice(b"ShortData1");

    assert!(
        detect_elf_overlay(&data).is_none(),
        "Overlay smaller than 16 bytes should not be reported"
    );
}

#[test]
fn detects_16_byte_overlay() {
    let mut data = read_hello_linux();
    data.extend_from_slice(b"Exactly16BytesOK"); // exactly 16 bytes

    assert!(
        detect_elf_overlay(&data).is_some(),
        "Overlay of exactly 16 bytes should be at the detection threshold"
    );
}

#[test]
fn finds_no_overlay_in_macho() {
    // Mach-O magic — overlay detection is ELF-only
    let mut data = vec![0u8; 200];
    data[0..4].copy_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]);
    assert!(
        detect_elf_overlay(&data).is_none(),
        "Non-ELF (Mach-O) data should return None"
    );
}

#[test]
fn finds_no_overlay_in_empty_input() {
    assert!(
        detect_elf_overlay(&[]).is_none(),
        "Empty input should return None"
    );
}

// ── extract_overlay_strings ─────────────────────────────────────────────────

#[test]
fn extracts_nothing_from_clean_elf() {
    let data = read_hello_linux();
    let strings = extract_overlay_strings(&data, 4);
    assert!(
        strings.is_empty(),
        "Clean ELF without appended data should produce no overlay strings"
    );
}

#[test]
fn extracts_appended_payload_at_its_offset() {
    let mut data = read_hello_linux();
    let start = data.len() as u64;
    // Long enough printable content to produce extractable strings
    let payload =
        b"OverlayPayloadContent: injected_string_value_for_test_extraction_here".repeat(3);
    data.extend_from_slice(&payload);

    let strings = extract_overlay_strings(&data, 4);
    // The payload is one printable run, so it is one string at the boundary.
    assert!(
        strings
            .iter()
            .any(|s| s.data_offset == start && s.value.as_bytes() == payload),
        "the appended payload should be one string at {start:#x}: {strings:?}"
    );
}

#[test]
fn places_overlay_strings_past_elf_end() {
    let mut data = read_hello_linux();
    let original_size = data.len() as u64;

    let payload =
        b"OverlayOffsetCheckContent: string_at_known_position_for_offset_validation".repeat(3);
    data.extend_from_slice(&payload);

    let strings = extract_overlay_strings(&data, 4);
    assert!(
        !strings.is_empty(),
        "Should extract strings from overlay region"
    );

    for s in &strings {
        assert!(
            s.data_offset >= original_size,
            "Overlay string at offset {} must be >= original file boundary {}",
            s.data_offset,
            original_size
        );
    }
}

#[test]
fn tags_appended_text_as_overlay() {
    let mut data = read_hello_linux();
    let payload =
        b"GenericOverlayText: this content should be classified as generic overlay kind".repeat(3);
    data.extend_from_slice(&payload);

    let strings = extract_overlay_strings(&data, 4);
    let text = strings
        .iter()
        .find(|s| s.value.as_bytes() == payload)
        .unwrap_or_else(|| panic!("the appended text is not extracted: {strings:?}"));

    assert_eq!(
        text.kind,
        Some(StringKind::Overlay),
        "Generic text in overlay should be classified as StringKind::Overlay"
    );
}

#[test]
fn keeps_url_kind_in_overlay() {
    let mut data = read_hello_linux();
    // A URL embedded in overlay data should be classified as Url, not generic Overlay
    let padding = b"\x00".repeat(20); // ensure some separation
    let url = b"http://malware.example.com/payload/download";
    data.extend_from_slice(&padding);
    data.extend_from_slice(url);
    data.extend_from_slice(b" extra padding to exceed the 16-byte threshold here"); // pad to >= 16

    let strings = extract_overlay_strings(&data, 4);

    // If a URL was extracted, it should not be downgraded to generic Overlay kind
    let url_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.value.contains("malware.example.com"))
        .collect();

    for s in &url_strings {
        assert_ne!(
            s.kind,
            Some(StringKind::Overlay),
            "URL '{}' in overlay should preserve specific classification, not be demoted to Overlay",
            s.value
        );
    }
}

#[test]
fn extracts_no_elf_overlay_from_pe() {
    // PE data — no ELF overlay possible
    let path = crate::common::path("testdata/pe/hello_windows.exe");
    let data = std::fs::read(path).expect("Failed to read hello_windows.exe");
    let strings = extract_overlay_strings(&data, 4);
    assert!(
        strings.is_empty(),
        "PE binary should produce no ELF overlay strings"
    );
}

#[test]
fn pe_overlay_strings_are_found_and_typed() {
    let mut data = crate::common::bytes("testdata/pe/msvc_console_amd64.exe");
    let start = data.len() as u64;
    data.extend_from_slice(
        b"\0\0\0\0config=http://overlay.example/beacon\0\0\0\0padding padding\0",
    );
    let strings = stng::extract_strings(&data, 4);
    let url = strings
        .iter()
        .find(|s| s.value.contains("http://overlay.example/beacon"))
        .expect("the appended URL is found");
    assert!(url.data_offset >= start, "{url:?}");
    assert!(
        strings
            .iter()
            .any(|s| s.data_offset >= start && s.kind == Some(StringKind::Overlay)),
        "{strings:?}"
    );
}

#[test]
fn a_pe_without_appended_data_has_no_overlay() {
    let data = crate::common::bytes("testdata/pe/msvc_console_amd64.exe");
    assert!(
        stng::extract_strings(&data, 4)
            .iter()
            .all(|s| !matches!(s.kind, Some(StringKind::Overlay | StringKind::OverlayWide))),
    );
}

#[test]
fn an_authenticode_table_is_not_overlay() {
    // Append an 8-byte-aligned certificate table and point data directory 4
    // at it, as signing does.
    let mut data = crate::common::bytes("testdata/pe/msvc_console_amd64.exe");
    while !data.len().is_multiple_of(8) {
        data.push(0);
    }
    let cert_at = data.len();
    let mut cert = vec![0u8; 0x200];
    cert[..4].copy_from_slice(&0x200u32.to_le_bytes()); // dwLength
    cert[4..6].copy_from_slice(&0x0200u16.to_le_bytes()); // WIN_CERT_REVISION_2_0
    cert[6..8].copy_from_slice(&0x0002u16.to_le_bytes()); // PKCS_SIGNED_DATA
    cert[8..48].copy_from_slice(b"Not overlay: certificate bytes........!!");
    data.extend_from_slice(&cert);
    let pe_at = u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap()) as usize;
    let optional = pe_at + 24;
    assert_eq!(
        &data[optional..optional + 2],
        &0x20bu16.to_le_bytes(),
        "PE32+"
    );
    let dir4 = optional + 112 + 4 * 8;
    data[dir4..dir4 + 4].copy_from_slice(&u32::try_from(cert_at).unwrap().to_le_bytes());
    data[dir4 + 4..dir4 + 8].copy_from_slice(&0x200u32.to_le_bytes());

    assert!(matches!(
        stng::goblin::Object::parse(&data),
        Ok(stng::goblin::Object::PE(_))
    ));
    let strings = stng::extract_strings(&data, 4);
    assert!(
        strings
            .iter()
            .any(|s| s.value.contains("certificate bytes"))
    );
    assert!(
        strings
            .iter()
            .all(|s| !matches!(s.kind, Some(StringKind::Overlay | StringKind::OverlayWide))),
    );
}
