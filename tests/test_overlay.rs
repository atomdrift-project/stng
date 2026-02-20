//! Tests for ELF overlay/appended data detection (overlay.rs).

use std::path::Path;
use stng::{detect_elf_overlay, extract_overlay_strings, StringKind};

fn read_hello_linux() -> Option<Vec<u8>> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/testdata/hello_linux_amd64"
    );
    if Path::new(path).exists() {
        Some(std::fs::read(path).expect("Failed to read hello_linux_amd64"))
    } else {
        None
    }
}

// ── detect_elf_overlay ──────────────────────────────────────────────────────

#[test]
fn test_no_overlay_on_clean_elf() {
    let Some(data) = read_hello_linux() else {
        return;
    };
    assert!(
        detect_elf_overlay(&data).is_none(),
        "Unmodified ELF binary should have no overlay"
    );
}

#[test]
fn test_overlay_detected_when_data_appended() {
    let Some(mut data) = read_hello_linux() else {
        return;
    };
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
fn test_overlay_size_and_start_offset_accurate() {
    let Some(mut data) = read_hello_linux() else {
        return;
    };
    let original_size = data.len();

    let payload = b"OverlaySizeCheckPayload0123456789"; // 32 bytes, well above threshold
    let payload_len = payload.len();
    data.extend_from_slice(payload);

    let info = detect_elf_overlay(&data).expect("Overlay should be detected");

    assert_eq!(
        info.size as usize, payload_len,
        "Reported overlay size should exactly match the appended payload length"
    );
    assert_eq!(
        info.start_offset as usize, original_size,
        "Overlay start offset should be at the original file boundary"
    );
}

#[test]
fn test_overlay_below_16_byte_threshold_not_reported() {
    let Some(mut data) = read_hello_linux() else {
        return;
    };
    // 10 bytes — below the minimum of 16 (avoids false positives from alignment padding)
    data.extend_from_slice(b"ShortData1");

    assert!(
        detect_elf_overlay(&data).is_none(),
        "Overlay smaller than 16 bytes should not be reported"
    );
}

#[test]
fn test_overlay_exactly_16_bytes_is_detected() {
    let Some(mut data) = read_hello_linux() else {
        return;
    };
    data.extend_from_slice(b"Exactly16BytesOK"); // exactly 16 bytes

    assert!(
        detect_elf_overlay(&data).is_some(),
        "Overlay of exactly 16 bytes should be at the detection threshold"
    );
}

#[test]
fn test_detect_overlay_returns_none_for_non_elf() {
    // Mach-O magic — overlay detection is ELF-only
    let mut data = vec![0u8; 200];
    data[0..4].copy_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]);
    assert!(
        detect_elf_overlay(&data).is_none(),
        "Non-ELF (Mach-O) data should return None"
    );
}

#[test]
fn test_detect_overlay_returns_none_for_empty() {
    assert!(
        detect_elf_overlay(&[]).is_none(),
        "Empty input should return None"
    );
}

// ── extract_overlay_strings ─────────────────────────────────────────────────

#[test]
fn test_extract_overlay_strings_clean_elf_is_empty() {
    let Some(data) = read_hello_linux() else {
        return;
    };
    let strings = extract_overlay_strings(&data, 4);
    assert!(
        strings.is_empty(),
        "Clean ELF without appended data should produce no overlay strings"
    );
}

#[test]
fn test_extract_overlay_strings_with_appended_payload() {
    let Some(mut data) = read_hello_linux() else {
        return;
    };
    // Long enough printable content to produce extractable strings
    let payload =
        b"OverlayPayloadContent: injected_string_value_for_test_extraction_here".repeat(3);
    data.extend_from_slice(&payload);

    let strings = extract_overlay_strings(&data, 4);
    assert!(
        !strings.is_empty(),
        "Appended printable payload should produce overlay strings"
    );
}

#[test]
fn test_overlay_string_offsets_are_in_overlay_region() {
    let Some(mut data) = read_hello_linux() else {
        return;
    };
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
fn test_overlay_generic_strings_have_overlay_kind() {
    let Some(mut data) = read_hello_linux() else {
        return;
    };
    let payload =
        b"GenericOverlayText: this content should be classified as generic overlay kind".repeat(3);
    data.extend_from_slice(&payload);

    let strings = extract_overlay_strings(&data, 4);
    let overlay_kind: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == StringKind::Overlay)
        .collect();

    assert!(
        !overlay_kind.is_empty(),
        "Generic text in overlay should be classified as StringKind::Overlay"
    );
}

#[test]
fn test_overlay_url_ioc_preserves_classification() {
    let Some(mut data) = read_hello_linux() else {
        return;
    };
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
            StringKind::Overlay,
            "URL '{}' in overlay should preserve specific classification, not be demoted to Overlay",
            s.value
        );
    }
}

#[test]
fn test_extract_overlay_strings_non_elf_returns_empty() {
    // PE data — no ELF overlay possible
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/testdata/hello_windows.exe"
    );
    if !Path::new(path).exists() {
        return;
    }
    let data = std::fs::read(path).expect("Failed to read hello_windows.exe");
    let strings = extract_overlay_strings(&data, 4);
    assert!(
        strings.is_empty(),
        "PE binary should produce no ELF overlay strings"
    );
}
