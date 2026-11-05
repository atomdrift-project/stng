//! Tests for improved text file decoding with embedded base64 extraction

use stng::{ExtractedString, StringKind, StringMethod, classify_string};

/// What stng's decoders make of `value` with `method`.
fn decoded(value: &str, method: StringMethod) -> Vec<String> {
    let input = ExtractedString::new(value, 0, stng::StringMethod::RawScan);
    stng::decode_encoded_strings(&[input])
        .into_iter()
        .filter(|s| s.method == method)
        .map(|s| s.value)
        .collect()
}

#[test]
fn classifies_16_char_base64() {
    // Test that 16-char base64 is now detected (was 20)
    let s = "SGVsbG8gV29ybGQ="; // "Hello World"
    assert_eq!(s.len(), 16);
    let kind = classify_string(s);
    assert_eq!(kind, Some(StringKind::Base64));
}

#[test]
fn classifies_20_char_base64() {
    // Longer base64 should still work
    let s = "VGhpcyBpcyBhIHRlc3Q="; // "This is a test"
    assert_eq!(s.len(), 20);
    let kind = classify_string(s);
    assert_eq!(kind, Some(StringKind::Base64));
}

#[test]
fn classifies_16_char_hex() {
    // Test that 16-char hex is now detected (was 40)
    let s = "48656c6c6f20576f"; // "Hello Wo"
    assert_eq!(s.len(), 16);
    let kind = classify_string(s);
    assert_eq!(kind, Some(StringKind::HexEncoded));
}

#[test]
fn classifies_24_char_hex() {
    // Longer hex should still work
    let s = "48656c6c6f20576f726c6421"; // "Hello World!"
    assert_eq!(s.len(), 24);
    let kind = classify_string(s);
    assert_eq!(kind, Some(StringKind::HexEncoded));
}

#[test]
fn classifies_two_percent_escapes_as_url_encoded() {
    // Test that 2 percent sequences are now enough (was 3)
    let s = "Hello%20World%21"; // "Hello World!"
    let kind = classify_string(s);
    assert_eq!(kind, Some(StringKind::UrlEncoded));
}

#[test]
fn classifies_many_percent_escapes_as_url_encoded() {
    let s = "Hello%20World%21%20Test%20123"; // "Hello World! Test 123"
    let kind = classify_string(s);
    assert_eq!(kind, Some(StringKind::UrlEncoded));
}

#[test]
fn rejects_8_char_base64() {
    // Less than 16 chars should not be detected as base64
    let s = "SGVsbG8="; // Only 8 chars
    assert!(s.len() < 16);
    let kind = classify_string(s);
    assert_ne!(kind, Some(StringKind::Base64));
}

#[test]
fn rejects_10_char_hex() {
    // Less than 16 chars should not be detected as hex
    let s = "48656c6c6f"; // Only 10 chars
    assert!(s.len() < 16);
    let kind = classify_string(s);
    assert_ne!(kind, Some(StringKind::HexEncoded));
}

#[test]
fn rejects_one_percent_escape_as_url_encoded() {
    // Only 1 percent sequence should not be detected
    let s = "Hello%20World"; // Only one %XX
    let kind = classify_string(s);
    assert_ne!(kind, Some(StringKind::UrlEncoded));
}

#[test]
fn decodes_hex() {
    let encoded = "48656c6c6f20576f726c6421";
    assert_eq!(decoded(encoded, StringMethod::HexDecode), ["Hello World!"]);
}

#[test]
fn decodes_percent_escapes() {
    let encoded = "Hello%20World%21%3F";
    assert_eq!(decoded(encoded, StringMethod::UrlDecode), ["Hello World!?"]);
}

#[test]
fn decodes_base64_in_assignment() {
    let assignment = r#"token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9""#;
    assert_eq!(
        decoded(assignment, StringMethod::Base64Decode),
        [r#"{"alg":"HS256","typ":"JWT"}"#]
    );
}

#[test]
fn classifies_jwt_over_base64() {
    // JWT should be classified as JWT, not just base64
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123";
    let kind = classify_string(jwt);
    assert_eq!(kind, Some(StringKind::Jwt));
}

#[test]
fn classifies_eval_base64_pipe_as_command_injection() {
    // Shell commands should be detected
    let cmd = r#"eval "$(echo SGVsbG8gV29ybGQ= | base64 -d)""#;
    let kind = classify_string(cmd);
    assert_eq!(kind, Some(StringKind::CommandInjection));
}

#[test]
fn decodes_nothing_from_punctuated_text() {
    let input = ExtractedString::new("ThisIsNotBase64!@#$%", 0, StringMethod::RawScan);
    let out = stng::decode_encoded_strings(&[input]);
    assert!(out.is_empty(), "{out:?}");
}

#[test]
fn rejects_odd_length_hex() {
    // Odd length hex should not be valid
    let odd_hex = "48656c6c6f20576f726c642"; // 23 chars (odd)
    assert!(decoded(odd_hex, StringMethod::HexDecode).is_empty());
}

#[test]
fn keeps_incomplete_percent_escape() {
    // A `%` without two hex digits after it stays as it is; the rest decodes.
    let malformed = "Hello%2World%20%21%3F";
    assert_eq!(
        decoded(malformed, StringMethod::UrlDecode),
        ["Hello%2World !?"]
    );
}

#[test]
fn decodes_each_base64_on_a_line() {
    let line = "token1=SGVsbG8gV29ybGQ= token2=VGhpcyBpcyBhIHRlc3Q=";
    assert_eq!(
        decoded(line, StringMethod::Base64Decode),
        ["Hello World", "This is a test"]
    );
}

#[test]
fn decodes_base64_in_json_values() {
    let json = r#"{"token":"SGVsbG8gV29ybGQ=","data":"VGhpcyBpcyBhIHRlc3Q="}"#;
    assert_eq!(
        decoded(json, StringMethod::Base64Decode),
        ["Hello World", "This is a test"]
    );
}

#[test]
fn decodes_hex_case_insensitively() {
    // Hex should be case-insensitive
    let lower = "48656c6c6f20576f726c6421";
    let upper = "48656C6C6F20576F726C6421";

    let decoded_lower = decoded(lower, StringMethod::HexDecode);
    let decoded_upper = decoded(upper, StringMethod::HexDecode);

    assert_eq!(decoded_lower, ["Hello World!"]);
    assert_eq!(decoded_lower, decoded_upper);
}
