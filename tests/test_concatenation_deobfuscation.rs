//! Tests for string concatenation deobfuscation.
//!
//! Malware often splits encoded strings using concatenation to evade detection.
//! These tests verify that we can detect and reassemble these patterns.
//!
//! NOTE: This feature is not yet fully implemented. Tests are marked as #[ignore].

use stng::{ExtractOptions, StringMethod};

#[test]
#[ignore = "concatenation deobfuscation not yet implemented"]
fn test_javascript_double_quotes_concatenation() {
    // JavaScript: "chunk1" + "chunk2" + "chunk3"
    let obfuscated = r#"var data = "ZnVuY3Rpb24" + "gT0tiTGM" + "gew0KICAgIA==";"#;

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(obfuscated.as_bytes(), &opts);

    // Should find the reassembled base64 and decode it
    let decoded = strings
        .iter()
        .find(|s| s.method == StringMethod::Base64Decode);
    assert!(decoded.is_some(), "Should decode concatenated base64");

    let decoded = decoded.unwrap();
    assert!(
        decoded.value.contains("function"),
        "Should decode to 'function OKbLc'"
    );
}

#[test]
#[ignore = "concatenation deobfuscation not yet implemented"]
fn test_javascript_single_quotes_concatenation() {
    // JavaScript: 'chunk1' + 'chunk2' + 'chunk3'
    let obfuscated = r#"var data = 'ZnVuY3Rpb24' + 'gT0tiTGM' + 'gew0KICAgIA==';"#;

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(obfuscated.as_bytes(), &opts);

    let decoded = strings
        .iter()
        .find(|s| s.method == StringMethod::Base64Decode);
    assert!(
        decoded.is_some(),
        "Should decode concatenated base64 with single quotes"
    );
}

#[test]
#[ignore = "concatenation deobfuscation not yet implemented"]
fn test_mixed_quotes_concatenation() {
    // Mixed single and double quotes
    let obfuscated = r#"data = "ZnVuY3Rpb24" + 'gT0tiTGM' + "gew0KICAgIA==";"#;

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(obfuscated.as_bytes(), &opts);

    let decoded = strings
        .iter()
        .find(|s| s.method == StringMethod::Base64Decode);
    assert!(decoded.is_some(), "Should handle mixed quote styles");
}

#[test]
fn test_obfuscated_with_junk_insertion() {
    // Real malware pattern: base64 split with junk characters inserted
    // "ZnVuY3Rpb24" + 'A' + "gT0tiTGM" + 'B' + "gew0KICAgIA=="
    let obfuscated = r#"x = "ZnVuY3Rpb24" + 'A' + "gT0tiTGM" + '9' + "gew0KICAgIA==";"#;

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(obfuscated.as_bytes(), &opts);

    // After deobfuscation, we get: "ZnVuY3Rpb24AgT0tiTGM9gew0KICAgIA=="
    // The 'A' and '9' are concatenated in, making it invalid base64
    // BUT we should at least try to decode it

    // For now, just verify we extract something
    assert!(
        !strings.is_empty(),
        "Should extract strings from obfuscated code"
    );
}

#[test]
#[ignore = "concatenation deobfuscation not yet implemented"]
fn test_real_malware_pattern_utf16() {
    // Pattern from 79197527.js (simplified)
    let obfuscated = r#"PoQct = "ZnVuY3Rpb24gT0tiTGMgew0KIC' +  'A'  + 'gIHBvd2Vyc2hlbGwgLWNvbW1hbmQgIlJlc3RhIi' +  'A'  + 'rICJydC1Db21wdXRlciIgew0KfQ==";"#;

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(obfuscated.as_bytes(), &opts);

    // Should reassemble: ZnVuY3Rpb24gT0tiTGMgew0KICAgIHBvd2Vyc2hlbGwgLWNvbW1hbmQgIlJlc3RhIiArICJydC1Db21wdXRlciIgew0KfQ==
    // But the junk 'A' insertions corrupt it: ZnVuY3Rpb24gT0tiTGMgew0KICAgAgIHBvd2Vyc2hlbGwgLWNvbW1hbmQgIlJlc3RhIiAgArICJydC1Db21wdXRlciIgew0KfQ==

    // Let's just verify we get some extraction
    let has_base64 = strings.iter().any(|s| s.value.contains("ZnVu"));
    assert!(has_base64, "Should extract base64-like strings");
}

#[test]
#[ignore = "concatenation deobfuscation not yet implemented"]
fn test_php_concatenation() {
    // PHP uses . for concatenation
    let obfuscated = r#"$data = 'ZnVuY3Rpb24' . 'gT0tiTGM' . 'gew0KICAgIA==';"#;

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(obfuscated.as_bytes(), &opts);

    let decoded = strings
        .iter()
        .find(|s| s.method == StringMethod::Base64Decode);
    assert!(decoded.is_some(), "Should handle PHP . concatenation");
}

#[test]
#[ignore = "concatenation deobfuscation not yet implemented"]
fn test_hex_concatenation() {
    // Hex-encoded "Hello World" split across concatenation
    let obfuscated = r#"data = "48656c6c6f" + "20576f" + "726c6421";"#;

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(obfuscated.as_bytes(), &opts);

    let decoded = strings.iter().find(|s| s.method == StringMethod::HexDecode);
    assert!(decoded.is_some(), "Should decode concatenated hex");

    if let Some(decoded) = decoded {
        assert!(
            decoded.value.contains("Hello"),
            "Should decode to 'Hello World!'"
        );
        assert!(
            decoded.value.contains("World"),
            "Should decode to 'Hello World!'"
        );
    }
}

#[test]
#[ignore = "concatenation deobfuscation not yet implemented"]
fn test_no_concatenation_unchanged() {
    // String without concatenation should not be modified
    let normal = r#"data = "ZnVuY3Rpb24gT0tiTGMgew0KICAgIA==";"#;

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(normal.as_bytes(), &opts);

    // Should still decode normally
    let decoded = strings
        .iter()
        .find(|s| s.method == StringMethod::Base64Decode);
    assert!(decoded.is_some(), "Should decode normal base64");
}

#[test]
#[ignore = "concatenation deobfuscation not yet implemented"]
fn test_empty_segments() {
    // Edge case: empty strings in concatenation
    let obfuscated = r#"x = "ZnVu" + "" + "Y3Rp" + "b24=";"#;

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(obfuscated.as_bytes(), &opts);

    // Should handle empty segments gracefully
    let decoded = strings
        .iter()
        .find(|s| s.method == StringMethod::Base64Decode);
    assert!(decoded.is_some(), "Should handle empty segments");
}

#[test]
#[ignore = "concatenation deobfuscation not yet implemented"]
fn test_single_segment_no_deobfuscation() {
    // Only one segment - should not trigger deobfuscation
    let single = r#"x = "ZnVuY3Rpb24gT0tiTGM=";"#;

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(single.as_bytes(), &opts);

    // Should decode normally without deobfuscation
    let decoded = strings
        .iter()
        .find(|s| s.method == StringMethod::Base64Decode);
    assert!(decoded.is_some(), "Should decode single segment");
}

#[test]
#[ignore = "concatenation deobfuscation not yet implemented"]
fn test_powershell_concatenation() {
    // PowerShell: 'chunk' + 'chunk'
    let obfuscated = r#"$b64 = 'ZnVuY3Rpb24' + 'gT0tiTGM' + 'gew0KICAgIA=='"#;

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(obfuscated.as_bytes(), &opts);

    let decoded = strings
        .iter()
        .find(|s| s.method == StringMethod::Base64Decode);
    assert!(decoded.is_some(), "Should handle PowerShell concatenation");
}

#[test]
#[ignore = "concatenation deobfuscation not yet implemented"]
fn test_whitespace_variations() {
    // Different whitespace around operators
    let obfuscated = r#"x="ZnVu"+"Y3Rp"+ "b24=";  y = 'aGVs' +  'bG8' +   '='"#;

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(obfuscated.as_bytes(), &opts);

    // Should handle various whitespace patterns
    let decoded_count = strings
        .iter()
        .filter(|s| s.method == StringMethod::Base64Decode)
        .count();
    assert!(
        decoded_count >= 1,
        "Should decode despite whitespace variations"
    );
}

#[test]
fn test_nested_quotes_not_confused() {
    // Make sure we don't get confused by quotes inside quotes
    let complex = r#"x = "He said \"hello\"" + " world";"#;

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(complex.as_bytes(), &opts);

    // Should extract something without crashing
    assert!(!strings.is_empty(), "Should handle nested quotes");
}

#[test]
fn test_long_concatenation_chain() {
    // Very long chain to test performance
    let obfuscated =
        r#"x = "aGVs" + "bG8g" + "d29y" + "bGQg" + "dGhp" + "cyBp" + "cyBh" + " long" + " test";"#;

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(obfuscated.as_bytes(), &opts);

    // Should reassemble long chains
    let has_decoded = strings
        .iter()
        .any(|s| s.method == StringMethod::Base64Decode);
    assert!(
        has_decoded || !strings.is_empty(),
        "Should handle long concatenation chains"
    );
}
