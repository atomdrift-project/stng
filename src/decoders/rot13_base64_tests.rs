use super::*;

fn s(v: &str) -> ExtractedString {
    ExtractedString {
        value: v.to_string(),
        ..Default::default()
    }
}

/// The shape this decoder exists for: a payload base64-encoded and then
/// rotated, so a reader who tries base64 first gets nothing.
#[test]
fn recovers_rot13_wrapped_base64_payload() {
    let payload = "import os\nhook = \"https://discord.com/api/webhooks/1088/abc\"\n";
    let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, payload);
    let rotated: String = b64
        .chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a' + 13) % 26) + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A' + 13) % 26) + b'A') as char,
            other => other,
        })
        .collect();
    let out = decode_rot13_base64_strings(&[s(&rotated)]);
    assert_eq!(out.len(), 1, "rotated base64 should decode");
    assert!(out[0].value.contains("discord.com/api/webhooks"));
    assert_eq!(out[0].method, StringMethod::Rot13Base64Decode);
}

/// A string that is already base64 belongs to the plain decoder; rotating
/// it would only produce a second, wrong reading of the same bytes.
#[test]
fn leaves_plain_base64_to_the_base64_decoder() {
    let b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        "import os\nhook = \"https://example.com/a\"\n",
    );
    assert!(decode_rot13_base64_strings(&[s(&b64)]).is_empty());
}

/// Every alphabetic string is valid rot13 input, so the guard against
/// doubling the string table with noise is that the *result* has to look
/// like base64. Ordinary text does not.
#[test]
fn ignores_ordinary_text_and_identifiers() {
    for v in [
        "the quick brown fox jumps over the lazy dog",
        "getUserProfileFromDatabaseConnection",
        "/usr/local/lib/python3.11/site-packages",
        "Copyright (c) 2024 Example Corporation",
    ] {
        assert!(
            decode_rot13_base64_strings(&[s(v)]).is_empty(),
            "should not decode: {v}"
        );
    }
}
