#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Integration test for ThreadRacer CPU benchmarking tool (PE x64, Bitsum LLC).
//!
//! Validates that stng does not produce false positives from VS_VERSION_INFO:
//! - ProductVersion "18.0.0.23" must not be classified as an IP address

mod common;

use stng::{ExtractOptions, StringKind};

#[test]
fn test_no_version_info_ip_false_positive() {
    let data = common::bytes("tests/testdata/malware/threadracer.exe");

    let opts = ExtractOptions::new(4);
    let extracted = stng::extract_strings_with_options(&data, &opts);

    let ip_values: Vec<&str> = extracted
        .iter()
        .filter(|s| matches!(s.kind, Some(StringKind::IP) | Some(StringKind::IPPort)))
        .map(|s| s.value.as_str())
        .collect();

    assert!(
        !ip_values.contains(&"18.0.0.23"),
        "ProductVersion '18.0.0.23' from VS_VERSION_INFO should not be classified as an IP. IPs found: {ip_values:?}",
    );
}
