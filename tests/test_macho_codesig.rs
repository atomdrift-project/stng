//! Tests for macOS code signature and entitlements extraction.
//!
//! These tests verify that we correctly extract and categorize:
//! - Entitlements XML from Mach-O binaries
//! - Code signature hashes (CD hashes) in __LINKEDIT section
//! - Application identifiers and individual entitlement keys

use std::fs;
use std::path::Path;
use stng::{extract_strings_with_options, ExtractOptions, StringKind, StringMethod};

#[test]
fn test_codesig_base64_categorization() {
    let bin_path = "/bin/ls";

    if !Path::new(bin_path).exists() {
        eprintln!("Skipping test: {} not found", bin_path);
        return;
    }

    let data = fs::read(bin_path).expect("Failed to read /bin/ls");
    let opts = ExtractOptions::new(10);
    let strings = extract_strings_with_options(&data, &opts);

    // Find all code signature hash strings
    let codesig_hashes: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == StringKind::CodeSignatureHash)
        .collect();

    // /bin/ls should have exactly 2 CD hashes
    assert!(
        codesig_hashes.len() >= 2,
        "Expected at least 2 CD hashes in /bin/ls, found {}",
        codesig_hashes.len()
    );

    // All CD hashes should be in __LINKEDIT section
    for s in &codesig_hashes {
        assert_eq!(
            s.section.as_deref(),
            Some("__LINKEDIT"),
            "CD hash at offset 0x{:x} should be in __LINKEDIT section, got {:?}",
            s.data_offset,
            s.section
        );
    }

    // All CD hashes should have CodeSignature method
    for s in &codesig_hashes {
        assert_eq!(
            s.method,
            StringMethod::CodeSignature,
            "CD hash at offset 0x{:x} should have CodeSignature method, got {:?}",
            s.data_offset,
            s.method
        );
    }

    // Verify the hashes decode to valid SHA-1 hashes (20 bytes)
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;

    for s in &codesig_hashes {
        let decoded = BASE64.decode(s.value.trim()).expect(&format!(
            "Failed to decode CD hash at 0x{:x}",
            s.data_offset
        ));

        assert_eq!(
            decoded.len(),
            20,
            "CD hash at 0x{:x} should be 20 bytes (SHA-1), got {}",
            s.data_offset,
            decoded.len()
        );
    }
}

#[test]
fn test_entitlements_extraction_brew_agent() {
    let sample_path = "testdata/malware/brew_agent";

    if !Path::new(sample_path).exists() {
        eprintln!("Skipping test: {} not found", sample_path);
        return;
    }

    let data = fs::read(sample_path).expect("Failed to read brew_agent");
    let opts = ExtractOptions::new(10);
    let strings = extract_strings_with_options(&data, &opts);

    // Find entitlements XML
    let entitlements: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == StringKind::EntitlementsXml)
        .collect();

    assert_eq!(
        entitlements.len(),
        1,
        "brew_agent should have exactly 1 entitlements XML block, found {}",
        entitlements.len()
    );

    let ent = entitlements[0];

    // Verify it's valid XML
    assert!(
        ent.value.starts_with("<?xml"),
        "Entitlements should start with XML declaration"
    );
    assert!(
        ent.value.contains("<!DOCTYPE plist"),
        "Entitlements should have plist DOCTYPE"
    );
    assert!(
        ent.value.contains("<plist version=\"1.0\">"),
        "Entitlements should have plist root element"
    );
    assert!(
        ent.value.contains("<dict/>") || ent.value.contains("<dict>"),
        "Entitlements should have dict element"
    );
    assert!(
        ent.value.ends_with("</plist>"),
        "Entitlements should end with closing plist tag"
    );

    // Verify it's multi-line
    assert!(
        ent.value.contains('\n'),
        "Entitlements XML should be multi-line"
    );

    // Verify StringMethod is CodeSignature (part of code signature blob)
    assert_eq!(
        ent.method,
        StringMethod::CodeSignature,
        "Entitlements should be extracted via CodeSignature method"
    );
}

#[test]
fn test_entitlements_extraction_securityd() {
    let bin_path = "/usr/libexec/securityd_system";

    if !Path::new(bin_path).exists() {
        eprintln!("Skipping test: {} not found", bin_path);
        return;
    }

    let data = fs::read(bin_path).expect("Failed to read securityd_system");
    let opts = ExtractOptions::new(10);
    let strings = extract_strings_with_options(&data, &opts);

    // Find entitlements XML
    let entitlements: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == StringKind::EntitlementsXml)
        .collect();

    assert_eq!(
        entitlements.len(),
        1,
        "securityd_system should have exactly 1 entitlements XML block, found {}",
        entitlements.len()
    );

    let ent = entitlements[0];

    // Verify expected entitlement keys are present
    let expected_keys = [
        "application-identifier",
        "com.apple.application-identifier",
        "com.apple.keystore.access-keychain-keys",
        "com.apple.keystore.lockassertion",
        "com.apple.private.security.storage.Keychains",
    ];

    for key in &expected_keys {
        assert!(
            ent.value.contains(key),
            "Entitlements should contain key '{}', but it's missing.\nEntitlements:\n{}",
            key,
            ent.value
        );
    }

    // Verify application identifier value
    assert!(
        ent.value.contains("com.apple.securityd.system"),
        "Entitlements should contain 'com.apple.securityd.system' identifier"
    );

    // Verify boolean entitlements have <true/> tags
    assert!(
        ent.value.contains("<true/>"),
        "Entitlements should have boolean <true/> values"
    );

    // Verify it's valid XML structure
    assert!(
        ent.value.starts_with("<?xml"),
        "Should start with XML declaration"
    );
    assert!(
        ent.value.contains("<!DOCTYPE plist"),
        "Should have plist DOCTYPE"
    );
    assert!(
        ent.value.contains("<plist version=\"1.0\">"),
        "Should have plist root"
    );
    assert!(ent.value.contains("<dict>"), "Should have dict element");
    assert!(
        ent.value.ends_with("</plist>"),
        "Should end with closing plist"
    );
}

#[test]
fn test_linkedit_section_enrichment() {
    let bin_path = "/bin/ls";

    if !Path::new(bin_path).exists() {
        eprintln!("Skipping test: {} not found", bin_path);
        return;
    }

    let data = fs::read(bin_path).expect("Failed to read /bin/ls");
    let opts = ExtractOptions::new(10);
    let strings = extract_strings_with_options(&data, &opts);

    // Find all CodeSignatureHash strings in __LINKEDIT section
    let linkedit_hashes: Vec<_> = strings
        .iter()
        .filter(|s| {
            s.section.as_deref() == Some("__LINKEDIT") && s.kind == StringKind::CodeSignatureHash
        })
        .collect();

    assert!(
        !linkedit_hashes.is_empty(),
        "Should find CodeSignatureHash strings in __LINKEDIT section"
    );

    // All CodeSignatureHash strings in __LINKEDIT should have CodeSignature method
    for s in &linkedit_hashes {
        assert_eq!(
            s.method,
            StringMethod::CodeSignature,
            "CodeSignatureHash at 0x{:x} in __LINKEDIT should have CodeSignature method, got {:?}",
            s.data_offset,
            s.method
        );
    }
}

#[test]
fn test_codesig_hash_format() {
    let bin_path = "/bin/ls";

    if !Path::new(bin_path).exists() {
        eprintln!("Skipping test: {} not found", bin_path);
        return;
    }

    let data = fs::read(bin_path).expect("Failed to read /bin/ls");
    let opts = ExtractOptions::new(10);
    let strings = extract_strings_with_options(&data, &opts);

    // Only check CodeSignatureHash kind (not all CodeSignature method strings)
    let codesig_hashes: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == StringKind::CodeSignatureHash)
        .collect();

    assert!(
        codesig_hashes.len() >= 2,
        "Should have at least 2 code signature hashes"
    );

    for hash in &codesig_hashes {
        // Verify base64 format (no whitespace)
        assert!(
            !hash.value.contains(' '),
            "Code signature hash should not contain spaces"
        );
        assert!(
            !hash.value.contains('\n'),
            "Code signature hash should not contain newlines"
        );

        // Verify it's valid base64 (alphanumeric plus +, /, =)
        // Note: The value might have hex preview appended in brackets
        let base64_part = if hash.value.contains('[') {
            hash.value.split('[').next().unwrap().trim()
        } else {
            hash.value.as_str()
        };

        assert!(
            base64_part
                .chars()
                .all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '='),
            "Code signature hash should contain only valid base64 characters, got: {}",
            base64_part
        );
    }
}

#[test]
fn test_entitlements_vs_codesign_count() {
    let bin_path = "/usr/libexec/securityd_system";

    if !Path::new(bin_path).exists() {
        eprintln!("Skipping test: {} not found", bin_path);
        return;
    }

    let data = fs::read(bin_path).expect("Failed to read securityd_system");
    let opts = ExtractOptions::new(10);
    let strings = extract_strings_with_options(&data, &opts);

    // Count entitlement keys in our extraction
    let entitlements: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == StringKind::EntitlementsXml)
        .collect();

    assert_eq!(
        entitlements.len(),
        1,
        "Should have one entitlements XML block"
    );

    let ent_xml = &entitlements[0].value;

    // Count <key> tags in the XML
    let key_count = ent_xml.matches("<key>").count();

    // securityd_system has many entitlement keys (11+)
    assert!(
        key_count >= 11,
        "securityd_system should have at least 11 entitlement keys, found {}",
        key_count
    );

    // Verify we're getting the full XML, not truncated
    let lines = ent_xml.lines().count();
    assert!(
        lines >= 20,
        "Entitlements XML should have at least 20 lines, found {}",
        lines
    );
}

#[test]
fn test_no_entitlements_in_clean_binaries() {
    // Some system binaries like /bin/ls don't have entitlements
    let bin_path = "/bin/ls";

    if !Path::new(bin_path).exists() {
        eprintln!("Skipping test: {} not found", bin_path);
        return;
    }

    let data = fs::read(bin_path).expect("Failed to read /bin/ls");
    let opts = ExtractOptions::new(10);
    let strings = extract_strings_with_options(&data, &opts);

    let entitlements: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == StringKind::EntitlementsXml)
        .collect();

    assert_eq!(
        entitlements.len(),
        0,
        "/bin/ls should have no entitlements, found {}",
        entitlements.len()
    );
}

#[test]
fn test_entitlements_offset_accuracy() {
    let sample_path = "testdata/malware/brew_agent";

    if !Path::new(sample_path).exists() {
        eprintln!("Skipping test: {} not found", sample_path);
        return;
    }

    let data = fs::read(sample_path).expect("Failed to read brew_agent");
    let opts = ExtractOptions::new(10);
    let strings = extract_strings_with_options(&data, &opts);

    let entitlements: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == StringKind::EntitlementsXml)
        .collect();

    assert_eq!(
        entitlements.len(),
        1,
        "Should have exactly one entitlements block"
    );

    let ent = entitlements[0];

    // Verify the offset points to actual XML content
    let offset = ent.data_offset as usize;
    assert!(
        offset < data.len(),
        "Offset 0x{:x} should be within file bounds ({})",
        offset,
        data.len()
    );

    // Verify the data at that offset starts with XML declaration
    let xml_start = String::from_utf8_lossy(&data[offset..std::cmp::min(offset + 5, data.len())]);
    assert!(
        xml_start.starts_with("<?xml"),
        "Data at offset 0x{:x} should start with '<?xml', got '{}'",
        offset,
        xml_start
    );
}

#[test]
fn test_codesig_hashes_are_sha1() {
    let bin_path = "/bin/cat";

    if !Path::new(bin_path).exists() {
        eprintln!("Skipping test: {} not found", bin_path);
        return;
    }

    let data = fs::read(bin_path).expect("Failed to read /bin/cat");
    let opts = ExtractOptions::new(10);
    let strings = extract_strings_with_options(&data, &opts);

    let codesig_hashes: Vec<_> = strings
        .iter()
        .filter(|s| {
            s.method == StringMethod::CodeSignature && s.kind == StringKind::CodeSignatureHash
        })
        .collect();

    if codesig_hashes.is_empty() {
        eprintln!("Skipping hash verification: no code signature hashes found in /bin/cat");
        return;
    }

    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;

    for hash in &codesig_hashes {
        // Extract just the base64 part (before any hex preview)
        let base64_part = if hash.value.contains('[') {
            hash.value.split('[').next().unwrap().trim()
        } else {
            hash.value.as_str()
        };

        let decoded = BASE64.decode(base64_part).expect(&format!(
            "Failed to decode hash at 0x{:x}",
            hash.data_offset
        ));

        // CD hashes are SHA-1 (20 bytes) or SHA-256 (32 bytes)
        assert!(
            decoded.len() == 20 || decoded.len() == 32,
            "Code directory hash at 0x{:x} should be 20 (SHA-1) or 32 (SHA-256) bytes, got {}",
            hash.data_offset,
            decoded.len()
        );
    }
}
