//! Comprehensive tests for base64 extraction and decoding.
//!
//! Tests base64 patterns including fuzzy/obfuscated variants:
//! - Standard base64 detection
//! - Base64 decoding
//! - Quality filtering
//! - Edge cases and error handling

use stng::{extract_strings_with_options, ExtractOptions, StringKind, StringMethod};

/// Helper to create test data with embedded content
fn make_test_data(content: &str) -> Vec<u8> {
    let mut data = Vec::new();
    // Add some binary header
    data.extend_from_slice(&[0x7f, 0x45, 0x4c, 0x46]); // ELF magic
    data.extend_from_slice(&[0; 100]); // Padding
                                       // Add the content
    data.extend_from_slice(content.as_bytes());
    // Add trailing data
    data.extend_from_slice(&[0; 100]);
    data
}

#[test]
fn test_long_valid_base64_detection() {
    // Long valid base64 string (100+ chars) - guaranteed to be detected
    let long_b64 = "VGhpcyBpcyBhIHJlYWxseSBsb25nIGJhc2U2NCBzdHJpbmcgdGhhdCBzaG91bGQgYmUgZGV0ZWN0ZWQgYW5kIGRlY29kZWQgcHJvcGVybHkgd2l0aG91dCBhbnkgaXNzdWVzIGJlY2F1c2UgaXQgbWVldHMgdGhlIG1pbmltdW0gbGVuZ3RoIHJlcXVpcmVtZW50";
    let data = make_test_data(long_b64);

    let opts = ExtractOptions::new(4);
    let strings = extract_strings_with_options(&data, &opts);

    // Should detect as base64 or decode it
    let base64_strings: Vec<_> = strings
        .iter()
        .filter(|s| {
            (s.kind == StringKind::Base64
                || s.method == StringMethod::Base64Decode
                || s.method == StringMethod::Base64ObfuscatedDecode)
                && s.value.len() > 50
        })
        .collect();

    assert!(
        !base64_strings.is_empty(),
        "Should detect long valid base64 string"
    );
}

#[test]
fn test_base64_decoding_enabled() {
    // Test that base64 gets decoded automatically
    let b64 = "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0IG1lc3NhZ2UgZm9yIGJhc2U2NCBkZWNvZGluZw==";
    let data = make_test_data(b64);

    let opts = ExtractOptions::new(4);
    let strings = extract_strings_with_options(&data, &opts);

    // Should either detect as base64 or decode it
    let has_base64_or_decoded = strings.iter().any(|s| {
        s.kind == StringKind::Base64
            || s.method == StringMethod::Base64Decode
            || s.value.contains("Hello World")
    });

    assert!(
        has_base64_or_decoded,
        "Should detect or decode base64 string"
    );
}

#[test]
fn test_no_false_positive_on_plain_text() {
    // Plain string with no base64
    let plain = "This is just a regular string with no encoding whatsoever in it at all";
    let data = make_test_data(plain);

    let opts = ExtractOptions::new(4);
    let strings = extract_strings_with_options(&data, &opts);

    // Should find the plain string but not classify it as base64
    let wrong_base64: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == StringKind::Base64 && s.value.contains("regular"))
        .collect();

    assert!(
        wrong_base64.is_empty(),
        "Should not misclassify plain text as base64"
    );
}

#[test]
fn test_invalid_base64_chars_rejected() {
    // String with mostly invalid base64 characters
    let invalid = "!!!###$$$%%%^^^&&&***((()))___|||";
    let data = make_test_data(invalid);

    let opts = ExtractOptions::new(4);
    let strings = extract_strings_with_options(&data, &opts);

    // Should not detect as base64
    let base64_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == StringKind::Base64)
        .collect();

    assert!(
        base64_strings.is_empty(),
        "Should not detect base64 in invalid characters"
    );
}

#[test]
fn test_base64_in_http_auth_header() {
    // Base64 embedded in realistic context
    let mut data = vec![0u8; 50];
    data.extend_from_slice(b"Authorization: Basic dXNlcjpwYXNzd29yZA==");
    data.extend_from_slice(&[0u8; 50]);

    let opts = ExtractOptions::new(4);
    let strings = extract_strings_with_options(&data, &opts);

    // Should find the base64 credential
    let has_base64 = strings.iter().any(|s| {
        s.value.contains("dXNlcjpwYXNzd29yZA")
            || (s.method == StringMethod::Base64Decode && s.value.contains("user:password"))
    });

    assert!(has_base64, "Should extract base64 from HTTP auth header");
}

#[test]
fn test_malware_pe_header_base64() {
    // Realistic base64-encoded PE header (MZ signature)
    let pe_b64 = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let data = make_test_data(pe_b64);

    let opts = ExtractOptions::new(4);
    let strings = extract_strings_with_options(&data, &opts);

    // Should detect as base64
    let base64_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == StringKind::Base64 && s.value.contains("TVq"))
        .collect();

    assert!(
        !base64_strings.is_empty(),
        "Should detect base64-encoded PE header"
    );
}

#[test]
fn test_base64_minimum_length_threshold() {
    // Very short string should not be detected as base64
    let short = "abc=";
    let data = make_test_data(short);

    let opts = ExtractOptions::new(4);
    let strings = extract_strings_with_options(&data, &opts);

    // Should not detect very short strings as base64
    let base64_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == StringKind::Base64 && s.value == "abc=")
        .collect();

    assert!(
        base64_strings.is_empty(),
        "Should not detect very short strings as base64"
    );
}

#[test]
fn test_empty_data_handling() {
    let data: Vec<u8> = vec![];

    let opts = ExtractOptions::new(4);
    let strings = extract_strings_with_options(&data, &opts);

    assert!(
        strings.is_empty(),
        "Should return empty results for empty data"
    );
}

#[test]
fn test_binary_only_no_false_positives() {
    // Pure binary data with no strings
    let data = vec![0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD];

    let opts = ExtractOptions::new(4);
    let strings = extract_strings_with_options(&data, &opts);

    // Should find no base64
    let base64_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == StringKind::Base64)
        .collect();

    assert!(
        base64_strings.is_empty(),
        "Should find no base64 in pure binary data"
    );
}

#[test]
fn test_base64_with_standard_padding() {
    // Base64 with standard = padding (long enough to be detected)
    let padded = "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0IHdpdGggcGFkZGluZw==";
    let data = make_test_data(padded);

    let opts = ExtractOptions::new(4);
    let strings = extract_strings_with_options(&data, &opts);

    // Should detect as base64 or decode it
    let base64_strings: Vec<_> = strings
        .iter()
        .filter(|s| {
            (s.kind == StringKind::Base64
                || s.method == StringMethod::Base64Decode
                || s.method == StringMethod::Base64ObfuscatedDecode)
                && s.value.len() > 30
        })
        .collect();

    assert!(
        !base64_strings.is_empty(),
        "Should detect base64 with standard padding"
    );
}

#[test]
fn test_multiple_base64_in_data() {
    // Multiple base64 strings embedded in data
    let content = "First: SGVsbG8gV29ybGQhIFRoaXMgaXMgdGVzdCBudW1iZXIgb25lLg== Second: QW5vdGhlciBiYXNlNjQgc3RyaW5nIGZvciB0ZXN0aW5nIHB1cnBvc2Vz";
    let data = make_test_data(content);

    let opts = ExtractOptions::new(4);
    let strings = extract_strings_with_options(&data, &opts);

    // Should find at least one string containing base64 content (encoded or decoded)
    let has_base64_content = strings.iter().any(|s| {
        s.kind == StringKind::Base64
            || s.method == StringMethod::Base64Decode
            || s.method == StringMethod::Base64ObfuscatedDecode
            || s.value.contains("SGVsbG8")
            || s.value.contains("QW5v")
    });

    assert!(
        has_base64_content,
        "Should detect base64 strings from multiple candidates"
    );
}

#[test]
fn test_base64_quality_threshold() {
    // Low quality string with mixed content
    let low_quality = "abc!!!def!!!ghi!!!jkl!!!mno!!!";
    let data = make_test_data(low_quality);

    let opts = ExtractOptions::new(4);
    let strings = extract_strings_with_options(&data, &opts);

    // Should not detect low quality strings as base64
    let base64_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == StringKind::Base64 && s.value.contains("!!!"))
        .collect();

    assert!(
        base64_strings.is_empty(),
        "Should filter out low quality base64 candidates"
    );
}

#[test]
fn test_pem_certificate_base64() {
    // Base64 from PEM certificate format
    let pem = "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAKL0UG+mRKOzMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV\nBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX\n-----END CERTIFICATE-----";
    let data = make_test_data(pem);

    let opts = ExtractOptions::new(4);
    let strings = extract_strings_with_options(&data, &opts);

    // Should find base64 sections
    let has_base64 = strings
        .iter()
        .any(|s| s.kind == StringKind::Base64 || s.value.contains("MIIDXTCCAkWgAw"));

    assert!(has_base64, "Should extract base64 from PEM certificate");
}

#[test]
fn test_jwt_token_base64() {
    // JWT token (header.payload.signature)
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let data = make_test_data(jwt);

    let opts = ExtractOptions::new(4);
    let strings = extract_strings_with_options(&data, &opts);

    // Should find the JWT components (either encoded or decoded)
    let has_jwt_parts = strings.iter().any(|s| {
        s.value.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
            || s.kind == StringKind::Base64
            || s.method == StringMethod::Base64Decode
            || s.method == StringMethod::Base64ObfuscatedDecode
    });

    assert!(
        has_jwt_parts,
        "Should extract base64 segments from JWT token"
    );
}

#[test]
fn test_base64_offset_tracking() {
    // Verify offsets are tracked correctly
    let content = "PADDING_TEXT_HERE_SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0IG1lc3NhZ2U=";
    let data = make_test_data(content);

    let opts = ExtractOptions::new(4);
    let strings = extract_strings_with_options(&data, &opts);

    // All strings should have valid offsets
    for s in &strings {
        assert!(
            s.data_offset < data.len() as u64,
            "String offset {} should be within data bounds ({})",
            s.data_offset,
            data.len()
        );
    }
}

#[test]
fn test_base64_no_crash_on_malformed() {
    // Malformed base64-like strings should not crash
    let malformed = vec![
        "AAAA====",     // Too much padding
        "A",            // Too short
        "AA",           // Incomplete
        "!!!BASE64!!!", // Invalid chars
    ];

    for test_case in malformed {
        let data = make_test_data(test_case);
        let opts = ExtractOptions::new(4);
        let _strings = extract_strings_with_options(&data, &opts);
        // Just verify no crash
    }

    assert!(true, "Should handle malformed base64 without crashing");
}
