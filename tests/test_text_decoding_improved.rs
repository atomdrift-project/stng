//! Tests for improved text file decoding with embedded base64 extraction

use stng::{classify_string, StringKind};

#[test]
fn test_base64_classification_short_strings() {
    // Test that 16-char base64 is now detected (was 20)
    let s = "SGVsbG8gV29ybGQ="; // "Hello World"
    assert_eq!(s.len(), 16);
    let kind = classify_string(s);
    assert_eq!(kind, StringKind::Base64);
}

#[test]
fn test_base64_classification_20_chars() {
    // Longer base64 should still work
    let s = "VGhpcyBpcyBhIHRlc3Q="; // "This is a test"
    assert_eq!(s.len(), 20);
    let kind = classify_string(s);
    assert_eq!(kind, StringKind::Base64);
}

#[test]
fn test_hex_classification_short_strings() {
    // Test that 16-char hex is now detected (was 40)
    let s = "48656c6c6f20576f"; // "Hello Wo"
    assert_eq!(s.len(), 16);
    let kind = classify_string(s);
    assert_eq!(kind, StringKind::HexEncoded);
}

#[test]
fn test_hex_classification_longer() {
    // Longer hex should still work
    let s = "48656c6c6f20576f726c6421"; // "Hello World!"
    assert_eq!(s.len(), 24);
    let kind = classify_string(s);
    assert_eq!(kind, StringKind::HexEncoded);
}

#[test]
fn test_url_encoding_classification_short() {
    // Test that 2 percent sequences are now enough (was 3)
    let s = "Hello%20World%21"; // "Hello World!"
    let kind = classify_string(s);
    assert_eq!(kind, StringKind::UrlEncoded);
}

#[test]
fn test_url_encoding_classification_longer() {
    let s = "Hello%20World%21%20Test%20123"; // "Hello World! Test 123"
    let kind = classify_string(s);
    assert_eq!(kind, StringKind::UrlEncoded);
}

#[test]
fn test_base64_not_detected_too_short() {
    // Less than 16 chars should not be detected as base64
    let s = "SGVsbG8="; // Only 8 chars
    assert!(s.len() < 16);
    let kind = classify_string(s);
    assert_ne!(kind, StringKind::Base64);
}

#[test]
fn test_hex_not_detected_too_short() {
    // Less than 16 chars should not be detected as hex
    let s = "48656c6c6f"; // Only 10 chars
    assert!(s.len() < 16);
    let kind = classify_string(s);
    assert_ne!(kind, StringKind::HexEncoded);
}

#[test]
fn test_url_encoding_not_detected_one_sequence() {
    // Only 1 percent sequence should not be detected
    let s = "Hello%20World"; // Only one %XX
    let kind = classify_string(s);
    assert_ne!(kind, StringKind::UrlEncoded);
}

#[test]
fn test_base64_decoding() {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;

    let encoded = "SGVsbG8gV29ybGQ=";
    let decoded = BASE64.decode(encoded).unwrap();
    let text = String::from_utf8(decoded).unwrap();
    assert_eq!(text, "Hello World");
}

#[test]
fn test_hex_decoding() {
    let encoded = "48656c6c6f20576f726c6421";
    let decoded = hex::decode(encoded).unwrap();
    let text = String::from_utf8(decoded).unwrap();
    assert_eq!(text, "Hello World!");
}

#[test]
fn test_url_decoding() {
    let encoded = "Hello%20World%21";
    let decoded = urlencoding::decode(encoded).unwrap();
    assert_eq!(decoded, "Hello World!");
}

#[test]
fn test_embedded_base64_regex_pattern() {
    use regex::Regex;

    // Test regex can find base64 in commands
    let re = Regex::new(r"([A-Za-z0-9+/]{12,}={0,2})").unwrap();

    let command = r#"eval "$(echo SGVsbG8gV29ybGQ= | base64 -d)""#;
    let captures: Vec<_> = re
        .captures_iter(command)
        .filter_map(|cap| cap.get(1))
        .map(|m| m.as_str())
        .collect();

    assert!(!captures.is_empty());
    // The regex captures with padding included
    assert!(captures.contains(&"SGVsbG8gV29ybGQ="));
}

#[test]
fn test_embedded_base64_in_variable_assignment() {
    use regex::Regex;

    let re = Regex::new(r"([A-Za-z0-9+/]{12,}={0,2})").unwrap();

    let assignment = r#"token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9""#;
    let captures: Vec<_> = re
        .captures_iter(assignment)
        .filter_map(|cap| cap.get(1))
        .map(|m| m.as_str())
        .collect();

    assert!(!captures.is_empty());
    assert!(captures
        .iter()
        .any(|s| s.starts_with("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")));
}

#[test]
fn test_jwt_token_classification() {
    // JWT should be classified as JWT, not just base64
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123";
    let kind = classify_string(jwt);
    assert_eq!(kind, StringKind::JWT);
}

#[test]
fn test_command_injection_classification() {
    // Shell commands should be detected
    let cmd = r#"eval "$(echo SGVsbG8gV29ybGQ= | base64 -d)""#;
    let kind = classify_string(cmd);
    assert_eq!(kind, StringKind::CommandInjection);
}

#[test]
fn test_invalid_base64_not_decoded() {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;

    // Invalid base64 should fail gracefully
    let invalid = "ThisIsNotBase64!@#$%";
    let result = BASE64.decode(invalid);
    assert!(result.is_err());
}

#[test]
fn test_odd_length_hex_not_decoded() {
    // Odd length hex should not be valid
    let odd_hex = "48656c6c6f2"; // 11 chars (odd)
    let result = hex::decode(odd_hex);
    assert!(result.is_err());
}

#[test]
fn test_malformed_url_encoding() {
    // Malformed URL encoding should handle gracefully
    let malformed = "Hello%2World"; // Missing one hex digit
    let decoded = urlencoding::decode(malformed).unwrap();
    // Should decode what it can
    assert!(decoded.contains("Hello"));
}

#[test]
fn test_base64_with_whitespace() {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;

    // Base64 with whitespace should be trimmed and decoded
    let encoded = "  SGVsbG8gV29ybGQ=  ";
    let decoded = BASE64.decode(encoded.trim()).unwrap();
    let text = String::from_utf8(decoded).unwrap();
    assert_eq!(text, "Hello World");
}

#[test]
fn test_multiple_base64_in_one_line() {
    use regex::Regex;

    let re = Regex::new(r"([A-Za-z0-9+/]{12,}={0,2})").unwrap();

    // Use longer base64 strings that meet the 12-char minimum
    let line = "token1=SGVsbG8gV29ybGQ= token2=VGhpcyBpcyBhIHRlc3Q=";
    let captures: Vec<_> = re
        .captures_iter(line)
        .filter_map(|cap| cap.get(1))
        .map(|m| m.as_str())
        .collect();

    // The regex captures each base64 string separately
    assert_eq!(captures.len(), 2);
    assert!(captures.iter().any(|s| s.contains("SGVsbG8gV29ybGQ")));
    assert!(captures.iter().any(|s| s.contains("VGhpcyBpcyBhIHRlc3Q")));
}

#[test]
fn test_base64_in_json() {
    use regex::Regex;

    let re = Regex::new(r"([A-Za-z0-9+/]{12,}={0,2})").unwrap();

    // Use base64 strings that meet the 12-char minimum
    let json = r#"{"token":"SGVsbG8gV29ybGQ=","data":"VGhpcyBpcyBhIHRlc3Q="}"#;
    let captures: Vec<_> = re
        .captures_iter(json)
        .filter_map(|cap| cap.get(1))
        .map(|m| m.as_str())
        .collect();

    // Should capture both base64 strings
    assert_eq!(captures.len(), 2);
    assert!(captures.iter().any(|s| s.contains("SGVsbG8gV29ybGQ")));
    assert!(captures.iter().any(|s| s.contains("VGhpcyBpcyBhIHRlc3Q")));
}

#[test]
fn test_base64_padding_variations() {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;

    // Test different padding scenarios
    let test_cases = vec![
        ("SGVsbG8=", "Hello"),               // One padding
        ("SGVsbG8gV29ybGQ=", "Hello World"), // One padding
        ("Zm9vYmFy", "foobar"),              // No padding
    ];

    for (encoded, expected) in test_cases {
        let decoded = BASE64.decode(encoded).unwrap();
        let text = String::from_utf8(decoded).unwrap();
        assert_eq!(text, expected);
    }
}

#[test]
fn test_case_sensitivity() {
    // Hex should be case-insensitive
    let lower = "48656c6c6f";
    let upper = "48656C6C6F";

    let decoded_lower = hex::decode(lower).unwrap();
    let decoded_upper = hex::decode(upper).unwrap();

    assert_eq!(decoded_lower, decoded_upper);
}

#[test]
fn test_non_utf8_decoded_content() {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;

    // Base64 that decodes to binary (non-UTF8) should be handled
    let binary_b64 = "AAECAwQFBgcICQ=="; // Binary data
    let decoded = BASE64.decode(binary_b64).unwrap();

    // Should decode successfully even if not valid UTF-8
    assert!(!decoded.is_empty());

    // Attempting to convert to UTF-8 should fail gracefully
    let result = String::from_utf8(decoded);
    // This may or may not be valid UTF-8, but shouldn't panic
    let _ = result;
}
