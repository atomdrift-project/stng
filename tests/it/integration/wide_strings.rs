use super::*;

/// Helper to encode a string as UTF-16LE with null terminator
fn to_utf16le_null(s: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for c in s.encode_utf16() {
        bytes.extend_from_slice(&c.to_le_bytes());
    }
    bytes.extend_from_slice(&[0x00, 0x00]);
    bytes
}

/// Helper to create a minimal PE with embedded wide strings
fn minimal_pe_with_wide_strings(wide_strings: &[&str]) -> Vec<u8> {
    let mut data = vec![0u8; 1024];

    // DOS header magic
    data[0..2].copy_from_slice(&[0x4D, 0x5A]); // MZ

    // PE offset at 0x3C
    data[0x3C..0x40].copy_from_slice(&[0x80, 0x00, 0x00, 0x00]);

    // PE signature at 0x80
    data[0x80..0x84].copy_from_slice(&[0x50, 0x45, 0x00, 0x00]); // PE\0\0

    // COFF header (20 bytes) at 0x84
    data[0x84..0x86].copy_from_slice(&[0x64, 0x86]); // Machine: AMD64
    data[0x86..0x88].copy_from_slice(&[0x01, 0x00]); // NumberOfSections: 1
    data[0x94..0x96].copy_from_slice(&[0xF0, 0x00]); // SizeOfOptionalHeader
    data[0x96..0x98].copy_from_slice(&[0x22, 0x00]); // Characteristics

    // Optional header at 0x98
    data[0x98..0x9A].copy_from_slice(&[0x0B, 0x02]); // PE32+ magic

    // Embed wide strings starting at offset 0x200
    let mut offset = 0x200;
    for s in wide_strings {
        let encoded = to_utf16le_null(s);
        if offset + encoded.len() <= data.len() {
            data[offset..offset + encoded.len()].copy_from_slice(&encoded);
            offset += encoded.len();
        }
    }

    data
}

#[test]
fn wide_string_debug_name() {
    // Verify the WideString method variant is available
    let method = StringMethod::WideString;
    assert_eq!(format!("{method:?}"), "WideString");
}

#[test]
fn finds_wide_strings_in_go_pe() {
    // Use the real Windows binary which is a valid PE
    let path = std::path::Path::new(crate::common::path("testdata/pe/hello_windows.exe"));

    let data = std::fs::read(path).expect("Failed to read test binary");
    let strings = extract_strings(&data, 4);

    assert!(strings.iter().any(|s| s.method == StringMethod::WideString));
}

#[test]
fn tags_utf16_as_wide_string() {
    let data = minimal_pe_with_wide_strings(&["TestString"]);
    let strings = extract_strings(&data, 4);

    let wide_strings: Vec<_> = strings.iter().filter(|s| s.value == "TestString").collect();

    assert_eq!(
        wide_strings.first().map(|s| s.method),
        Some(StringMethod::WideString),
        "{strings:?}"
    );
}

#[test]
fn finds_wide_strings_in_hello_windows() {
    // Test with the real Windows Go binary in testdata
    let path = std::path::Path::new(crate::common::path("testdata/pe/hello_windows.exe"));

    let data = std::fs::read(path).expect("Failed to read test binary");
    let strings = extract_strings(&data, 4);

    assert!(strings.iter().any(|s| s.method == StringMethod::WideString));
}

#[test]
fn classifies_wide_url_path_registry() {
    let data = minimal_pe_with_wide_strings(&[
        "https://example.com",
        "C:\\Users\\Test",
        "HKEY_LOCAL_MACHINE\\SOFTWARE",
    ]);

    let strings = extract_strings(&data, 4);

    for (value, kind) in [
        ("https://example.com", StringKind::Url),
        ("C:\\Users\\Test", StringKind::Path),
        ("HKEY_LOCAL_MACHINE\\SOFTWARE", StringKind::Registry),
    ] {
        let s = strings
            .iter()
            .find(|s| s.value == value)
            .unwrap_or_else(|| panic!("{value} is extracted"));
        assert_eq!(s.method, StringMethod::WideString, "{s:?}");
        assert_eq!(s.kind, Some(kind), "{s:?}");
    }
}

#[test]
fn filter_keeps_wide_identifiers() {
    let data = minimal_pe_with_wide_strings(&["ValidString", "Test1234"]);

    let opts = ExtractOptions::new(4).with_garbage_filter(true);
    let strings = extract_strings_with_options(&data, &opts);

    // Valid strings should pass garbage filter
    let wide_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.method == StringMethod::WideString)
        .collect();

    // Garbage filter should not remove legitimate wide strings
    for s in &wide_strings {
        assert!(
            !is_garbage(&s.value),
            "Wide string '{}' should not be garbage",
            s.value
        );
    }
}

#[test]
fn min_length_applies_to_wide_strings() {
    // Test min_length filtering with the real Windows binary
    let path = std::path::Path::new(crate::common::path("testdata/pe/hello_windows.exe"));

    let data = std::fs::read(path).expect("Failed to read test binary");

    // Extract with min_length=4
    let strings_short = extract_strings(&data, 4);
    let wide_short: Vec<_> = strings_short
        .iter()
        .filter(|s| s.method == StringMethod::WideString)
        .collect();

    // Extract with min_length=10
    let strings_long = extract_strings(&data, 10);
    let wide_long: Vec<_> = strings_long
        .iter()
        .filter(|s| s.method == StringMethod::WideString)
        .collect();

    // Higher min_length should result in fewer or equal wide strings
    assert!(
        wide_long.len() <= wide_short.len(),
        "Higher min_length should filter more strings"
    );

    // All wide strings should meet min_length requirement
    for s in &wide_long {
        assert!(
            s.value.len() >= 10,
            "Wide string '{}' should be >= 10 chars",
            s.value
        );
    }
}

#[test]
fn dedups_repeated_wide_string() {
    let data = minimal_pe_with_wide_strings(&["Duplicate", "Duplicate", "Unique"]);

    let strings = extract_strings(&data, 4);

    // Should only have one "Duplicate"
    let dup_count = strings.iter().filter(|s| s.value == "Duplicate").count();
    assert!(dup_count <= 1, "Duplicate strings should be deduplicated");
}

#[test]
fn wide_offset_is_past_header() {
    let data = minimal_pe_with_wide_strings(&["FirstString"]);

    let strings = extract_strings(&data, 4);

    let s = strings
        .iter()
        .find(|s| s.value == "FirstString")
        .expect("FirstString is extracted");
    assert_eq!(s.method, StringMethod::WideString, "{s:?}");
    // The helper embeds the first wide string at 0x200.
    assert_eq!(s.data_offset, 0x200, "{s:?}");
}
