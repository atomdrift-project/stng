//! Integration test for WizardNet Downloader.dll (PE x86).
//!
//! Validates that stng does not produce false positives on this sample:
//! - No XOR IP false positives from XAML Margin comma-separated values
//! - No base64 false positives from ASN.1 certificate timestamps or x86 code
//! - No PHP false positives from .reloc section random data

use stng::{ExtractOptions, StringKind, StringMethod};

const SAMPLE_PATH: &str = "testdata/malware/wizardnet_downloader.dll";

fn load_sample() -> Option<Vec<u8>> {
    let path = std::path::Path::new(SAMPLE_PATH);
    if !path.exists() {
        eprintln!("Skipping - sample not found at {SAMPLE_PATH}");
        return None;
    }
    Some(std::fs::read(path).expect("Failed to read sample"))
}

#[test]
fn test_no_xor_ip_false_positives_from_xaml_margins() {
    let Some(data) = load_sample() else {
        return;
    };

    let opts = ExtractOptions::new(4).with_xor(Some(8));
    let extracted = stng::extract_strings_with_options(&data, &opts);

    // These "IPs" are XAML Margin values (e.g. "30,10,30,0") where comma XOR 0x02 = period.
    let false_positive_ips = ["12.32.12.2", "74.33.2.2", "12.2.12.2"];

    let xor_ips: Vec<&str> = extracted
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode && s.kind == StringKind::IP)
        .map(|s| s.value.as_str())
        .collect();

    for fp in false_positive_ips {
        assert!(
            !xor_ips.contains(&fp),
            "False positive XOR IP {fp:?} from XAML margin should not be detected. XOR IPs found: {xor_ips:?}",
        );
    }
}

#[test]
fn test_no_base64_false_positives_from_cert_timestamps() {
    let Some(data) = load_sample() else {
        return;
    };

    let opts = ExtractOptions::new(4);
    let extracted = stng::extract_strings_with_options(&data, &opts);

    // ASN.1 certificate validity timestamps that happen to have base64-valid chars
    let false_positives = ["201229235959Z0b1", "310111235959Z0w1"];

    let base64_strings: Vec<&str> = extracted
        .iter()
        .filter(|s| s.kind == StringKind::Base64)
        .map(|s| s.value.as_str())
        .collect();

    for fp in false_positives {
        assert!(
            !base64_strings.contains(&fp),
            "False positive base64 {fp:?} (cert timestamp) should not be detected. Base64 found: {base64_strings:?}",
        );
    }
}

#[test]
fn test_no_base64_false_positives_from_x86_code() {
    let Some(data) = load_sample() else {
        return;
    };

    let opts = ExtractOptions::new(4);
    let extracted = stng::extract_strings_with_options(&data, &opts);

    // x86 conditional jump instruction bytes that look like base64
    let base64_strings: Vec<&str> = extracted
        .iter()
        .filter(|s| s.kind == StringKind::Base64)
        .map(|s| s.value.as_str())
        .collect();

    assert!(
        !base64_strings.contains(&"rtVHHtRHt2HtLHHu"),
        "x86 instruction pattern should not be classified as base64. Base64 found: {base64_strings:?}",
    );
}

#[test]
fn test_no_php_false_positives_from_reloc_section() {
    let Some(data) = load_sample() else {
        return;
    };

    let opts = ExtractOptions::new(4);
    let extracted = stng::extract_strings_with_options(&data, &opts);

    let php_strings: Vec<&str> = extracted
        .iter()
        .filter(|s| s.kind == StringKind::PhpCode)
        .map(|s| s.value.as_str())
        .collect();

    // .reloc section data containing <?= followed by random punctuation
    for s in &php_strings {
        assert!(
            !s.starts_with("<?=\""),
            "Random .reloc data {s:?} should not be classified as PHP. PHP strings found: {php_strings:?}",
        );
    }
}

#[test]
fn test_legitimate_strings_still_extracted() {
    let Some(data) = load_sample() else {
        return;
    };

    let opts = ExtractOptions::new(4);
    let extracted = stng::extract_strings_with_options(&data, &opts);

    let values: Vec<&str> = extracted.iter().map(|s| s.value.as_str()).collect();

    // Key strings that must be present (legitimate content from this QQBrowser downloader)
    let required = [
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT %d.%d) QQBrowser/6.0",
        "Software\\Tencent\\QQBrowser",
        "URLDownloadToFileW",
        "explorer.exe",
    ];

    for needle in required {
        assert!(
            values.iter().any(|v| v.contains(needle)),
            "Missing expected string containing {needle:?}",
        );
    }
}
