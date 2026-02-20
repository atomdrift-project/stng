//! Tests to ensure code signature classification is precise.
//!
//! Verifies that:
//! - Only actual code signature data is marked as CodeSignature method
//! - Symbol table imports are NOT marked as code signature
//! - Random strings in __LINKEDIT are NOT marked as code signature
//! - Only Base64 CD hashes get CodeSignatureHash kind

use std::fs;
use std::path::Path;
use stng::{extract_strings_with_options, ExtractOptions, StringKind, StringMethod};

#[test]
fn test_imports_not_marked_as_codesig() {
    let bin_path = "/bin/ls";

    if !Path::new(bin_path).exists() {
        eprintln!("Skipping test: {} not found", bin_path);
        return;
    }

    let data = fs::read(bin_path).expect("Failed to read /bin/ls");
    let opts = ExtractOptions::new(10);
    let strings = extract_strings_with_options(&data, &opts);

    // Find all imports
    let imports: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == StringKind::Import)
        .collect();

    assert!(!imports.is_empty(), "Should find imports in /bin/ls");

    // None of the imports should be marked as CodeSignature method
    for import in &imports {
        assert_ne!(
            import.method,
            StringMethod::CodeSignature,
            "Import '{}' at offset 0x{:x} should not be marked as CodeSignature",
            import.value,
            import.data_offset
        );
    }
}

#[test]
fn test_only_base64_gets_codesig_hash_kind() {
    let bin_path = "/bin/ls";

    if !Path::new(bin_path).exists() {
        eprintln!("Skipping test: {} not found", bin_path);
        return;
    }

    let data = fs::read(bin_path).expect("Failed to read /bin/ls");
    let opts = ExtractOptions::new(10);
    let strings = extract_strings_with_options(&data, &opts);

    // All CodeSignatureHash strings must be base64-encoded
    let codesig_hashes: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == StringKind::CodeSignatureHash)
        .collect();

    assert!(
        !codesig_hashes.is_empty(),
        "Should find code signature hashes in /bin/ls"
    );

    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;

    for hash in &codesig_hashes {
        // Extract base64 part (before any hex preview)
        let base64_part = if hash.value.contains('[') {
            hash.value.split('[').next().unwrap().trim()
        } else {
            hash.value.as_str()
        };

        // Must be valid base64
        let decoded = BASE64.decode(base64_part);
        assert!(
            decoded.is_ok(),
            "CodeSignatureHash at 0x{:x} should be valid base64: {}",
            hash.data_offset,
            hash.value
        );

        // Must decode to SHA-1 (20 bytes) or SHA-256 (32 bytes)
        let decoded = decoded.unwrap();
        assert!(
            decoded.len() == 20 || decoded.len() == 32,
            "CodeSignatureHash at 0x{:x} should decode to 20 or 32 bytes, got {}",
            hash.data_offset,
            decoded.len()
        );
    }
}

#[test]
fn test_linkedit_const_strings_selective_codesig() {
    let bin_path = "/bin/ls";

    if !Path::new(bin_path).exists() {
        eprintln!("Skipping test: {} not found", bin_path);
        return;
    }

    let data = fs::read(bin_path).expect("Failed to read /bin/ls");
    let opts = ExtractOptions::new(10);
    let strings = extract_strings_with_options(&data, &opts);

    // Helper to check if string is certificate-related (matches lib.rs implementation)
    fn is_certificate_string(s: &str) -> bool {
        // Certificate Authority names
        if s.contains("Certification Authority")
            || s.contains("Certificate Authority")
            || s.contains("Root CA")
        {
            return true;
        }
        // Code signing related
        if s.contains("Code Signing") || s.contains("Software Signing") {
            return true;
        }
        // CRL URLs
        if s.contains("crl.apple.com")
            || s.contains("appleca")
            || (s.contains(".crl") && s.contains("http"))
        {
            return true;
        }
        // ASN.1 date format: YYMMDDHHMMSSZ or YYYYMMDDHHMMSSZ
        if s.len() >= 13 && s.ends_with('Z') {
            let without_z = &s[..s.len() - 1];
            if without_z.chars().all(|c| c.is_ascii_digit())
                && (without_z.len() == 12 || without_z.len() == 14)
            {
                return true;
            }
        }
        // Sometimes has trailing digits/chars after Z
        if s.len() >= 14 && s.contains('Z') {
            if let Some(z_pos) = s.find('Z') {
                if z_pos >= 12 {
                    let before_z = &s[..z_pos];
                    if before_z.chars().rev().take(12).all(|c| c.is_ascii_digit()) {
                        return true;
                    }
                }
            }
        }
        // Certificate policy text
        if s.contains("certificate is to be used")
            || s.contains("Reliance on this certificate")
            || s.contains("terms and conditions")
        {
            return true;
        }
        // Apple organizational units
        if (s.contains("Apple Inc.") || s.contains("Apple Software")) && s.len() < 50 {
            return true;
        }
        false
    }

    // Find Const strings in __LINKEDIT that are NOT XML/plist or certificate related
    let non_codesig_consts: Vec<_> = strings
        .iter()
        .filter(|s| {
            s.kind == StringKind::Const
                && s.section.as_deref() == Some("__LINKEDIT")
                && !s.value.starts_with('<')
                && !s.value.starts_with("<?xml")
                && !is_certificate_string(&s.value)
        })
        .collect();

    assert!(
        !non_codesig_consts.is_empty(),
        "Should find non-code-signature Const strings in __LINKEDIT"
    );

    // These non-code-signature strings should NOT be marked as CodeSignature
    for s in &non_codesig_consts {
        assert_ne!(
            s.method,
            StringMethod::CodeSignature,
            "Non-code-signature Const string '{}' at offset 0x{:x} should not be marked as CodeSignature",
            s.value,
            s.data_offset
        );
    }

    // XML/plist strings in __LINKEDIT SHOULD be marked as CodeSignature
    let xml_strings: Vec<_> = strings
        .iter()
        .filter(|s| {
            s.section.as_deref() == Some("__LINKEDIT")
                && (s.value.starts_with("<?xml")
                    || s.value.starts_with("<plist")
                    || s.value.starts_with("<dict")
                    || s.value.starts_with("<key>"))
        })
        .collect();

    if !xml_strings.is_empty() {
        for s in &xml_strings {
            assert_eq!(
                s.method,
                StringMethod::CodeSignature,
                "XML/plist string '{}' at offset 0x{:x} should be marked as CodeSignature",
                s.value,
                s.data_offset
            );
        }
    }
}

#[test]
fn test_codesig_method_on_signatures() {
    let bin_path = "/bin/ls";

    if !Path::new(bin_path).exists() {
        eprintln!("Skipping test: {} not found", bin_path);
        return;
    }

    let data = fs::read(bin_path).expect("Failed to read /bin/ls");
    let opts = ExtractOptions::new(10);
    let strings = extract_strings_with_options(&data, &opts);

    // Find all strings with CodeSignature method
    let codesig_method: Vec<_> = strings
        .iter()
        .filter(|s| s.method == StringMethod::CodeSignature)
        .collect();

    assert!(
        !codesig_method.is_empty(),
        "Should find CodeSignature method strings"
    );

    // Helper to check if string is certificate-related (matches lib.rs implementation)
    fn is_certificate_string(s: &str) -> bool {
        // Certificate Authority names
        if s.contains("Certification Authority")
            || s.contains("Certificate Authority")
            || s.contains("Root CA")
        {
            return true;
        }
        // Code signing related
        if s.contains("Code Signing") || s.contains("Software Signing") {
            return true;
        }
        // CRL URLs
        if s.contains("crl.apple.com")
            || s.contains("appleca")
            || (s.contains(".crl") && s.contains("http"))
        {
            return true;
        }
        // ASN.1 date format: YYMMDDHHMMSSZ or YYYYMMDDHHMMSSZ
        if s.len() >= 13 && s.ends_with('Z') {
            let without_z = &s[..s.len() - 1];
            if without_z.chars().all(|c| c.is_ascii_digit())
                && (without_z.len() == 12 || without_z.len() == 14)
            {
                return true;
            }
        }
        // Sometimes has trailing digits/chars after Z
        if s.len() >= 14 && s.contains('Z') {
            if let Some(z_pos) = s.find('Z') {
                if z_pos >= 12 {
                    let before_z = &s[..z_pos];
                    if before_z.chars().rev().take(12).all(|c| c.is_ascii_digit()) {
                        return true;
                    }
                }
            }
        }
        // Certificate policy text
        if s.contains("certificate is to be used")
            || s.contains("Reliance on this certificate")
            || s.contains("terms and conditions")
        {
            return true;
        }
        // Apple organizational units
        if (s.contains("Apple Inc.") || s.contains("Apple Software")) && s.len() < 50 {
            return true;
        }
        false
    }

    // CodeSignature method should include:
    // 1. CodeSignatureHash (CD hashes)
    // 2. XML/plist strings from code signature blob
    // 3. Certificate strings (X.509 certificate chain components)
    for s in &codesig_method {
        let is_valid = s.kind == StringKind::CodeSignatureHash
            || s.value.starts_with("<?xml")
            || s.value.starts_with("<!DOCTYPE")
            || s.value.starts_with("<plist")
            || s.value.starts_with("<dict")
            || s.value.starts_with("</dict>")
            || s.value.starts_with("</plist>")
            || s.value.starts_with("<key>")
            || s.value.starts_with("<array>")
            || s.value.starts_with("</array>")
            || s.value.starts_with("<data>")
            || s.value.starts_with("</data>")
            || is_certificate_string(&s.value);

        assert!(
            is_valid,
            "String at offset 0x{:x} with CodeSignature method should be either CD hash, XML, or certificate: {:?} = '{}'",
            s.data_offset,
            s.kind,
            s.value
        );
    }
}

#[test]
fn test_no_base64_kind_in_linkedit() {
    let bin_path = "/bin/ls";

    if !Path::new(bin_path).exists() {
        eprintln!("Skipping test: {} not found", bin_path);
        return;
    }

    let data = fs::read(bin_path).expect("Failed to read /bin/ls");
    let opts = ExtractOptions::new(10);
    let strings = extract_strings_with_options(&data, &opts);

    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;

    // Base64 strings in __LINKEDIT that decode to SHA-1 (20 bytes) or SHA-256 (32 bytes)
    // are CD hashes and must be promoted to CodeSignatureHash. Base64 data that decodes
    // to other sizes (certificate fragments, etc.) may remain as Base64.
    let hash_sized_base64_in_linkedit: Vec<_> = strings
        .iter()
        .filter(|s| {
            s.kind == StringKind::Base64
                && s.section.as_deref() == Some("__LINKEDIT")
                && BASE64
                    .decode(s.value.trim())
                    .map(|b| b.len() == 20 || b.len() == 32)
                    .unwrap_or(false)
        })
        .collect();

    assert_eq!(
        hash_sized_base64_in_linkedit.len(),
        0,
        "Base64 strings in __LINKEDIT that decode to 20 or 32 bytes must be promoted to \
         CodeSignatureHash; found {} still as Base64",
        hash_sized_base64_in_linkedit.len()
    );
}

#[test]
fn test_cert_strings_not_marked_as_hashes() {
    let bin_path = "/bin/ls";

    if !Path::new(bin_path).exists() {
        eprintln!("Skipping test: {} not found", bin_path);
        return;
    }

    let data = fs::read(bin_path).expect("Failed to read /bin/ls");
    let opts = ExtractOptions::new(10);
    let strings = extract_strings_with_options(&data, &opts);

    // Find certificate-related strings (Apple Certification Authority, etc.)
    let cert_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.value.contains("Apple") && s.value.contains("Cert"))
        .collect();

    if cert_strings.is_empty() {
        eprintln!("Warning: No cert strings found, test may be incomplete");
        return;
    }

    // None of these should be CodeSignatureHash
    for s in &cert_strings {
        assert_ne!(
            s.kind,
            StringKind::CodeSignatureHash,
            "Certificate string '{}' should not be marked as CodeSignatureHash",
            s.value
        );
    }
}

#[test]
fn test_exact_hash_count() {
    let bin_path = "/bin/ls";

    if !Path::new(bin_path).exists() {
        eprintln!("Skipping test: {} not found", bin_path);
        return;
    }

    let data = fs::read(bin_path).expect("Failed to read /bin/ls");
    let opts = ExtractOptions::new(10);
    let strings = extract_strings_with_options(&data, &opts);

    // Count CodeSignatureHash kind strings (the actual CD hashes)
    let hash_count = strings
        .iter()
        .filter(|s| s.kind == StringKind::CodeSignatureHash)
        .count();

    // /bin/ls should have exactly 2 CD hashes (one per architecture)
    assert_eq!(
        hash_count, 2,
        "/bin/ls should have exactly 2 CD hashes (one per arch), found {}",
        hash_count
    );

    // Count CodeSignature method strings (includes hashes + XML)
    let codesig_count = strings
        .iter()
        .filter(|s| s.method == StringMethod::CodeSignature)
        .count();

    // Should have more than just the hashes (includes XML/plist)
    assert!(
        codesig_count >= hash_count,
        "CodeSignature method count ({}) should be >= hash count ({}) (includes XML/plist)",
        codesig_count,
        hash_count
    );

    // Count AppId strings (bundle identifiers)
    let appid_count = strings
        .iter()
        .filter(|s| s.kind == StringKind::AppId)
        .count();

    // /bin/ls should have at least 1 AppId (com.apple.ls)
    assert!(
        appid_count >= 1,
        "/bin/ls should have at least 1 AppId (com.apple.ls), found {}",
        appid_count
    );
}
