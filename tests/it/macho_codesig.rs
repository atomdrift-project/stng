//! Tests for macOS code signature and entitlements extraction.
//!
//! These tests verify that we correctly extract and categorize:
//! - Entitlements XML from Mach-O binaries
//! - Code signature hashes (CD hashes) in __LINKEDIT section
//! - Application identifiers and individual entitlement keys

use std::fs;
use stng::{ExtractOptions, StringKind, StringMethod, extract_strings_with_options};

#[cfg(target_os = "macos")]
fn macho_arch_count(data: &[u8]) -> usize {
    match goblin::Object::parse(data) {
        Ok(goblin::Object::Mach(goblin::mach::Mach::Fat(fat))) => fat.narches,
        Ok(goblin::Object::Mach(goblin::mach::Mach::Binary(_))) => 1,
        _ => 0,
    }
}

#[test]
#[cfg(target_os = "macos")] // reads an Apple-signed system binary
fn tags_ls_cd_hashes_as_sha1_code_signature() {
    let bin_path = "/bin/ls";

    let data = fs::read(bin_path).expect("Failed to read /bin/ls");

    let opts = ExtractOptions::new(10);
    let strings = extract_strings_with_options(&data, &opts);

    // Find all code signature hash strings
    let codesig_hashes: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == Some(StringKind::CodeSignatureHash))
        .collect();

    let arch_count = macho_arch_count(&data);

    assert!(
        !codesig_hashes.is_empty(),
        "Expected at least 1 CD hash in /bin/ls, found {}",
        codesig_hashes.len()
    );
    assert!(
        arch_count == 0 || codesig_hashes.len() <= arch_count,
        "Expected CD hash count to be <= architecture count (hashes={}, arches={})",
        codesig_hashes.len(),
        arch_count
    );

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
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;

    for s in &codesig_hashes {
        let decoded = BASE64
            .decode(s.value.trim())
            .unwrap_or_else(|_| panic!("Failed to decode CD hash at 0x{:x}", s.data_offset));

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
fn extracts_one_entitlements_plist_per_slice() {
    let sample_path = crate::common::path("testdata/malware/brew_agent");

    let data = fs::read(sample_path).expect("Failed to read brew_agent");
    let opts = ExtractOptions::new(10);
    let strings = extract_strings_with_options(&data, &opts);

    // Find entitlements XML
    let entitlements: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == Some(StringKind::EntitlementsXml))
        .collect();

    // A universal binary: each slice is signed with its own entitlements
    // (`codesign -d --entitlements - --arch …` shows one per slice).
    assert_eq!(
        entitlements.len(),
        2,
        "brew_agent should have one entitlements XML block per slice, found {}",
        entitlements.len()
    );

    for ent in entitlements {
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
}

#[test]
#[cfg(target_os = "macos")] // reads an Apple-signed system binary
fn extracts_securityd_entitlement_keys() {
    let bin_path = "/usr/libexec/securityd_system";

    let data = fs::read(bin_path).expect("Failed to read securityd_system");
    let opts = ExtractOptions::new(10);
    let strings = extract_strings_with_options(&data, &opts);

    // Find entitlements XML
    let entitlements: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == Some(StringKind::EntitlementsXml))
        .collect();

    assert_eq!(
        entitlements.len(),
        slice_count(&data),
        "securityd_system should have one entitlements XML block per slice"
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
#[cfg(target_os = "macos")] // reads an Apple-signed system binary
fn tags_linkedit_cd_hashes_code_signature() {
    let bin_path = "/bin/ls";

    let data = fs::read(bin_path).expect("Failed to read /bin/ls");

    let opts = ExtractOptions::new(10);
    let strings = extract_strings_with_options(&data, &opts);

    // Find all CodeSignatureHash strings in __LINKEDIT section
    let linkedit_hashes: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == Some(StringKind::CodeSignatureHash))
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
#[cfg(target_os = "macos")] // reads an Apple-signed system binary
fn formats_cd_hashes_as_bare_base64() {
    let bin_path = "/bin/ls";

    let data = fs::read(bin_path).expect("Failed to read /bin/ls");

    let opts = ExtractOptions::new(10);
    let strings = extract_strings_with_options(&data, &opts);

    // Only check CodeSignatureHash kind (not all CodeSignature method strings)
    let codesig_hashes: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == Some(StringKind::CodeSignatureHash))
        .collect();

    let arch_count = macho_arch_count(&data);

    assert!(
        !codesig_hashes.is_empty(),
        "Should have at least 1 code signature hash"
    );
    assert!(
        arch_count == 0 || codesig_hashes.len() <= arch_count,
        "Should not have more code signature hashes than architectures (hashes={}, arches={})",
        codesig_hashes.len(),
        arch_count
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
            "Code signature hash should contain only valid base64 characters, got: {base64_part}"
        );
    }
}

#[test]
#[cfg(target_os = "macos")] // reads an Apple-signed system binary
fn extracts_untruncated_securityd_entitlements() {
    let bin_path = "/usr/libexec/securityd_system";

    let data = fs::read(bin_path).expect("Failed to read securityd_system");
    let opts = ExtractOptions::new(10);
    let strings = extract_strings_with_options(&data, &opts);

    // Count entitlement keys in our extraction
    let entitlements: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == Some(StringKind::EntitlementsXml))
        .collect();

    assert_eq!(
        entitlements.len(),
        slice_count(&data),
        "one entitlements XML block per slice"
    );

    let ent_xml = &entitlements[0].value;

    // Count <key> tags in the XML
    let key_count = ent_xml.matches("<key>").count();

    // securityd_system has many entitlement keys (11+)
    assert!(
        key_count >= 11,
        "securityd_system should have at least 11 entitlement keys, found {key_count}"
    );

    // Verify we're getting the full XML, not truncated
    let lines = ent_xml.lines().count();
    assert!(
        lines >= 20,
        "Entitlements XML should have at least 20 lines, found {lines}"
    );
}

#[test]
#[cfg(target_os = "macos")] // reads an Apple-signed system binary
fn finds_no_entitlements_in_ls() {
    // Some system binaries like /bin/ls don't have entitlements
    let bin_path = "/bin/ls";

    let data = fs::read(bin_path).expect("Failed to read /bin/ls");

    let opts = ExtractOptions::new(10);
    let strings = extract_strings_with_options(&data, &opts);

    let entitlements: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == Some(StringKind::EntitlementsXml))
        .collect();

    assert_eq!(
        entitlements.len(),
        0,
        "/bin/ls should have no entitlements, found {}",
        entitlements.len()
    );
}

#[test]
fn points_entitlements_offset_at_xml_declaration() {
    let sample_path = crate::common::path("testdata/malware/brew_agent");

    let data = fs::read(sample_path).expect("Failed to read brew_agent");
    let opts = ExtractOptions::new(10);
    let strings = extract_strings_with_options(&data, &opts);

    let entitlements: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == Some(StringKind::EntitlementsXml))
        .collect();

    assert_eq!(entitlements.len(), 2, "one entitlements block per slice");

    for ent in entitlements {
        // Verify the offset points to actual XML content
        let offset = usize::try_from(ent.data_offset).unwrap();
        assert!(
            offset < data.len(),
            "Offset 0x{:x} should be within file bounds ({})",
            offset,
            data.len()
        );

        // Verify the data at that offset starts with XML declaration
        let xml_start =
            String::from_utf8_lossy(&data[offset..std::cmp::min(offset + 5, data.len())]);
        assert!(
            xml_start.starts_with("<?xml"),
            "Data at offset 0x{offset:x} should start with '<?xml', got '{xml_start}'"
        );
    }
}

#[test]
#[cfg(target_os = "macos")] // reads an Apple-signed system binary
fn decodes_cat_cd_hashes_to_sha_digests() {
    let bin_path = "/bin/cat";

    let data = fs::read(bin_path).expect("Failed to read /bin/cat");
    let opts = ExtractOptions::new(10);
    let strings = extract_strings_with_options(&data, &opts);

    let codesig_hashes: Vec<_> = strings
        .iter()
        .filter(|s| {
            s.method == StringMethod::CodeSignature && s.kind == Some(StringKind::CodeSignatureHash)
        })
        .collect();

    assert!(
        !codesig_hashes.is_empty(),
        "/bin/cat's code directories carry hashes"
    );

    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;

    for hash in &codesig_hashes {
        // Extract just the base64 part (before any hex preview)
        let base64_part = if hash.value.contains('[') {
            hash.value.split('[').next().unwrap().trim()
        } else {
            hash.value.as_str()
        };

        let decoded = BASE64
            .decode(base64_part)
            .unwrap_or_else(|_| panic!("Failed to decode hash at 0x{:x}", hash.data_offset));

        // CD hashes are SHA-1 (20 bytes) or SHA-256 (32 bytes)
        assert!(
            decoded.len() == 20 || decoded.len() == 32,
            "Code directory hash at 0x{:x} should be 20 (SHA-1) or 32 (SHA-256) bytes, got {}",
            hash.data_offset,
            decoded.len()
        );
    }
}

#[test]
fn fat_slice_entitlements_are_read_from_their_slice() {
    // The second-architecture code signature: its load command's offset is
    // relative to the slice, not the file.
    let data = crate::common::bytes("testdata/malware/dynamichub/DynamicHub");
    let strings = stng::extract_strings(&data, 4);
    let xml = strings
        .iter()
        .find(|s| s.kind == Some(stng::StringKind::EntitlementsXml))
        .expect("entitlements are found");
    assert_eq!(xml.data_offset, 328_314);
    assert!(xml.value.starts_with("<?xml") && xml.value.ends_with("</plist>"));
    assert_eq!(&data[328_314..328_319], b"<?xml");
}

#[test]
fn signature_plists_other_than_entitlements_are_not_entitlements() {
    // A signed binary with no entitlements still embeds a CMS `cdhashes`
    // plist in its signature; only the entitlements slot counts.
    let data = crate::common::bytes("testdata/macho/charge0x_installer_universal.macho");
    let strings = stng::extract_strings(&data, 4);
    assert!(
        strings
            .iter()
            .filter(|s| s.kind == Some(StringKind::EntitlementsXml))
            .all(|s| !s.value.contains("<key>cdhashes</key>")),
    );
}

/// Architectures in a Mach-O: a universal binary signs each one.
#[cfg(target_os = "macos")]
fn slice_count(data: &[u8]) -> usize {
    match stng::goblin::Object::parse(data) {
        Ok(stng::goblin::Object::Mach(stng::goblin::mach::Mach::Fat(fat))) => fat.narches,
        _ => 1,
    }
}
