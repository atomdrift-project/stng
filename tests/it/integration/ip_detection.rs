use super::*;
use stng::Severity;

#[test]
fn classifies_ipv4_as_ip() {
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
fn does_not_classify_1_0_0_0_as_ip() {
    // Create binary with version numbers (should NOT be IPs)
    let data = minimal_pe_with_strings(&["1.0.0.0"]);

    let strings = extract_strings(&data, 4);
    let version = strings
        .iter()
        .find(|s| s.value == "1.0.0.0")
        .expect("1.0.0.0 is extracted");
    assert_ne!(
        version.kind,
        Some(StringKind::Ip),
        "Version number 1.0.0.0 should NOT be classified as IP"
    );
}

#[test]
fn does_not_classify_x_y_0_0_as_ip() {
    // Pattern X.Y.0.0 should not be IP
    let data = minimal_pe_with_strings(&["4.5.0.0"]);

    let strings = extract_strings(&data, 4);
    let version = strings
        .iter()
        .find(|s| s.value == "4.5.0.0")
        .expect("4.5.0.0 is extracted");
    assert_ne!(
        version.kind,
        Some(StringKind::Ip),
        "Version number 4.5.0.0 should NOT be classified as IP"
    );
}

#[test]
fn rates_ip_high() {
    // IPs should have high severity
    let data = minimal_pe_with_strings(&["8.8.8.8"]);

    let strings = extract_strings(&data, 4);
    let ip = strings
        .iter()
        .find(|s| s.value == "8.8.8.8")
        .expect("8.8.8.8 is extracted");
    assert_eq!(ip.kind, Some(StringKind::Ip), "{ip:?}");
    assert_eq!(StringKind::Ip.severity(), Severity::High);
}

#[test]
fn rates_ip_and_url_high() {
    // IPs should sort before URLs when prioritizing notable items
    // This tests the severity ordering used in main.rs Notable section
    let ip_severity = StringKind::Ip.severity();
    let url_severity = StringKind::Url.severity();

    // Both are High, but we test the ordering logic in main.rs
    assert_eq!(ip_severity, Severity::High);
    assert_eq!(url_severity, Severity::High);
}
