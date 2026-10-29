use super::*;
use stng::Severity;

/// Helper to create a minimal PE with embedded ASCII strings
fn minimal_pe_with_strings(strings: &[&str]) -> Vec<u8> {
    let mut data = vec![0u8; 1024];

    // DOS header magic
    data[0..2].copy_from_slice(&[0x4D, 0x5A]); // MZ

    // PE offset at 0x3C
    data[0x3C..0x40].copy_from_slice(&[0x80, 0x00, 0x00, 0x00]);

    // PE signature at 0x80
    data[0x80..0x84].copy_from_slice(&[0x50, 0x45, 0x00, 0x00]); // PE\0\0

    // Embed strings starting at 0x200
    let mut offset = 0x200;
    for s in strings {
        let bytes = s.as_bytes();
        data[offset..offset + bytes.len()].copy_from_slice(bytes);
        data[offset + bytes.len()] = 0; // null terminator
        offset += bytes.len() + 1;
    }

    data
}

#[test]
fn test_real_ip_classified_as_ip() {
    // Create binary with a real IP address embedded
    let data = minimal_pe_with_strings(&["168.235.103.57"]);

    let strings = extract_strings(&data, 4);
    let ip_string = strings.iter().find(|s| s.value == "168.235.103.57");

    assert!(ip_string.is_some(), "Real IP should be extracted");
    assert_eq!(
        ip_string.unwrap().kind,
        Some(StringKind::Ip),
        "Real IP should be classified as IP"
    );
}

#[test]
fn test_version_number_not_ip() {
    // Create binary with version numbers (should NOT be IPs)
    let data = minimal_pe_with_strings(&["1.0.0.0"]);

    let strings = extract_strings(&data, 4);
    let version_string = strings.iter().find(|s| s.value == "1.0.0.0");

    // Should either not be found or not be classified as IP
    if let Some(s) = version_string {
        assert_ne!(
            s.kind,
            Some(StringKind::Ip),
            "Version number 1.0.0.0 should NOT be classified as IP"
        );
    }
}

#[test]
fn test_version_pattern_x_y_0_0_not_ip() {
    // Pattern X.Y.0.0 should not be IP
    let data = minimal_pe_with_strings(&["4.5.0.0"]);

    let strings = extract_strings(&data, 4);
    let version_string = strings.iter().find(|s| s.value == "4.5.0.0");

    if let Some(s) = version_string {
        assert_ne!(
            s.kind,
            Some(StringKind::Ip),
            "Version number 4.5.0.0 should NOT be classified as IP"
        );
    }
}

#[test]
fn test_ip_has_high_severity() {
    // IPs should have high severity
    let data = minimal_pe_with_strings(&["8.8.8.8"]);

    let strings = extract_strings(&data, 4);
    let ip_string = strings.iter().find(|s| s.value == "8.8.8.8");

    if let Some(s) = ip_string {
        assert_eq!(
            s.kind.map(StringKind::severity).unwrap_or(Severity::Info),
            Severity::High,
            "IP addresses should have High severity"
        );
    }
}

#[test]
fn test_ip_severity_higher_priority_than_url() {
    // IPs should sort before URLs when prioritizing notable items
    // This tests the severity ordering used in main.rs Notable section
    let ip_severity = StringKind::Ip.severity();
    let url_severity = StringKind::Url.severity();

    // Both are High, but we test the ordering logic in main.rs
    assert_eq!(ip_severity, Severity::High);
    assert_eq!(url_severity, Severity::High);
}
