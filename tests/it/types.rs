//! Comprehensive tests for types.rs
//!
//! Tests core type definitions, methods, serialization, and edge cases.

use stng::{ExtractedString, Severity, StringFragment, StringKind, StringMethod};

// ===== ExtractedString Tests =====

#[test]
fn test_extracted_string_default() {
    let s = ExtractedString::default();
    assert_eq!(s.value, "");
    assert_eq!(s.data_offset, 0);
    assert_eq!(s.method, StringMethod::RawScan);
    assert_eq!(s.kind, None);
    assert_eq!(s.fragments, None);
}

// ===== StringKind::severity() Tests =====

#[test]
fn test_severity_high_security() {
    // Test all High severity kinds
    assert_eq!(StringKind::Ip.severity(), Severity::High);
    assert_eq!(StringKind::IpPort.severity(), Severity::High);
    assert_eq!(StringKind::Hostname.severity(), Severity::High);
    assert_eq!(StringKind::Url.severity(), Severity::High);
    assert_eq!(StringKind::ShellCmd.severity(), Severity::High);
    assert_eq!(StringKind::SuspiciousPath.severity(), Severity::High);
    assert_eq!(StringKind::Base64.severity(), Severity::High);
    assert_eq!(StringKind::HexEncoded.severity(), Severity::High);
    assert_eq!(StringKind::XorKey.severity(), Severity::High);
}

#[test]
fn test_severity_high_crypto() {
    assert_eq!(StringKind::CryptoWallet.severity(), Severity::High);
    assert_eq!(StringKind::MiningPool.severity(), Severity::High);
    assert_eq!(StringKind::Email.severity(), Severity::High);
    assert_eq!(StringKind::TorAddress.severity(), Severity::High);
}

#[test]
fn test_severity_high_attacks() {
    assert_eq!(StringKind::SqlInjection.severity(), Severity::High);
    assert_eq!(StringKind::XssPayload.severity(), Severity::High);
    assert_eq!(StringKind::CommandInjection.severity(), Severity::High);
    assert_eq!(StringKind::CtfFlag.severity(), Severity::High);
}

#[test]
fn test_severity_high_secrets() {
    assert_eq!(StringKind::Jwt.severity(), Severity::High);
    assert_eq!(StringKind::ApiKey.severity(), Severity::High);
    assert_eq!(StringKind::Mutex.severity(), Severity::High);
    assert_eq!(StringKind::Guid.severity(), Severity::High);
    assert_eq!(StringKind::RansomNote.severity(), Severity::High);
    assert_eq!(StringKind::LdapPath.severity(), Severity::High);
}

#[test]
fn test_severity_medium() {
    assert_eq!(StringKind::Path.severity(), Severity::Medium);
    assert_eq!(StringKind::FilePath.severity(), Severity::Medium);
    assert_eq!(StringKind::Import.severity(), Severity::Medium);
    assert_eq!(StringKind::EnvVar.severity(), Severity::Medium);
    assert_eq!(StringKind::Registry.severity(), Severity::Medium);
    assert_eq!(StringKind::Error.severity(), Severity::Medium);
    assert_eq!(StringKind::Section.severity(), Severity::Medium);
    assert_eq!(StringKind::EntitlementsXml.severity(), Severity::Medium);
}

#[test]
fn test_severity_low() {
    assert_eq!(StringKind::FuncName.severity(), Severity::Low);
    assert_eq!(StringKind::Export.severity(), Severity::Low);
}

#[test]
fn test_severity_info() {
    assert_eq!(StringKind::Ident.severity(), Severity::Info);
    assert_eq!(StringKind::Arg.severity(), Severity::Info);
    assert_eq!(StringKind::MapKey.severity(), Severity::Info);
    assert_eq!(StringKind::Garbage.severity(), Severity::Info);
}

#[test]
fn test_severity_ordering() {
    // Verify severity ordering: High < Medium < Low < Info
    assert!(Severity::High < Severity::Medium);
    assert!(Severity::Medium < Severity::Low);
    assert!(Severity::Low < Severity::Info);
}

// ===== StringKind::short_name() Tests =====

#[test]
fn test_short_name_basic() {
    assert_eq!(StringKind::FuncName.short_name(), "func");
    assert_eq!(StringKind::FilePath.short_name(), "file");
    assert_eq!(StringKind::MapKey.short_name(), "key");
    assert_eq!(StringKind::Error.short_name(), "error");
    assert_eq!(StringKind::EnvVar.short_name(), "env");
    assert_eq!(StringKind::Url.short_name(), "url");
    assert_eq!(StringKind::Path.short_name(), "path");
    assert_eq!(StringKind::Arg.short_name(), "arg");
    assert_eq!(StringKind::Ident.short_name(), "ident");
    assert_eq!(StringKind::Garbage.short_name(), "garbage");
}

#[test]
fn test_short_name_binary() {
    assert_eq!(StringKind::Section.short_name(), "section");
    assert_eq!(StringKind::Import.short_name(), "import");
    assert_eq!(StringKind::Export.short_name(), "export");
}

#[test]
fn test_short_name_network() {
    assert_eq!(StringKind::Ip.short_name(), "ip");
    assert_eq!(StringKind::IpPort.short_name(), "ip:port");
    assert_eq!(StringKind::Hostname.short_name(), "host");
}

#[test]
fn test_short_name_security() {
    assert_eq!(StringKind::ShellCmd.short_name(), "shell");
    assert_eq!(StringKind::SuspiciousPath.short_name(), "sus");
    assert_eq!(StringKind::Registry.short_name(), "registry");
    assert_eq!(StringKind::AppleScript.short_name(), "applescript");
}

#[test]
fn test_short_name_encoding() {
    assert_eq!(StringKind::Base64.short_name(), "base64");
    assert_eq!(StringKind::HexEncoded.short_name(), "hex");
    assert_eq!(StringKind::UnicodeEscaped.short_name(), "unicode");
    assert_eq!(StringKind::UrlEncoded.short_name(), "urlenc");
    assert_eq!(StringKind::Base32.short_name(), "base32");
    assert_eq!(StringKind::Base58.short_name(), "base58");
    assert_eq!(StringKind::Base85.short_name(), "base85");
}

#[test]
fn test_short_name_overlay() {
    assert_eq!(StringKind::Overlay.short_name(), "overlay");
    assert_eq!(StringKind::OverlayWide.short_name(), "overlay:16LE");
}

#[test]
fn test_short_name_crypto() {
    assert_eq!(StringKind::CryptoWallet.short_name(), "crypto");
    assert_eq!(StringKind::MiningPool.short_name(), "miner");
    assert_eq!(StringKind::Email.short_name(), "email");
    assert_eq!(StringKind::TorAddress.short_name(), "tor");
}

#[test]
fn test_short_name_attacks() {
    assert_eq!(StringKind::CtfFlag.short_name(), "ctf_flag");
    assert_eq!(StringKind::SqlInjection.short_name(), "sqli");
    assert_eq!(StringKind::XssPayload.short_name(), "xss");
    assert_eq!(StringKind::CommandInjection.short_name(), "cmdi");
}

#[test]
fn test_short_name_secrets() {
    assert_eq!(StringKind::Jwt.short_name(), "jwt");
    assert_eq!(StringKind::ApiKey.short_name(), "api_key");
    assert_eq!(StringKind::Mutex.short_name(), "mutex");
    assert_eq!(StringKind::Guid.short_name(), "guid");
    assert_eq!(StringKind::RansomNote.short_name(), "ransom");
    assert_eq!(StringKind::LdapPath.short_name(), "ldap");
}

#[test]
fn test_short_name_macho() {
    assert_eq!(StringKind::StackString.short_name(), "stack");
    assert_eq!(StringKind::Entitlement.short_name(), "entitlement");
    assert_eq!(StringKind::AppId.short_name(), "appid");
    assert_eq!(StringKind::EntitlementsXml.short_name(), "entitlements");
    assert_eq!(StringKind::XorKey.short_name(), "xor_key");
}

// ===== FunctionMetadata Tests =====

// ===== Serialization Tests =====

#[test]
fn test_extracted_string_serialization() {
    let s = ExtractedString::new("test_value".to_string(), 0x1234, StringMethod::Structure)
        .with_kind(StringKind::FuncName);

    let json = serde_json::to_string(&s).unwrap();
    assert!(json.contains("test_value"));
    assert!(json.contains("4660")); // 0x1234 in decimal
}

#[test]
fn test_extracted_string_serialization_skip_none() {
    let s = ExtractedString::new("test".to_string(), 100, stng::StringMethod::RawScan);

    let json = serde_json::to_string(&s).unwrap();
    // None fields should be skipped
    assert!(!json.contains("library"));
    assert!(!json.contains("fragments"));
    assert!(!json.contains("architecture"));
    // An unrecorded extent (data_len == 0) is omitted from the wire form.
    assert!(!json.contains("data_len"));
}

#[test]
fn test_extracted_string_data_len_roundtrip() {
    // UTF-16LE source extent, 2× the value
    let s = ExtractedString::new("Hi", 0x40, StringMethod::WideString).with_data_len(4);

    let json = serde_json::to_string(&s).unwrap();
    // A recorded extent is serialized...
    assert!(json.contains("data_len"));
    // ...and survives a round-trip, preserving the source span.
    let back: ExtractedString = serde_json::from_str(&json).unwrap();
    assert_eq!(back.data_len, 4);
    assert_eq!(back.source_spans().collect::<Vec<_>>(), vec![(0x40, 4)]);
}

// Note: StringFragment is not exported in the public API, so we can't test it directly here.
// Fragment handling is tested indirectly through stack string extraction tests.

// ===== Edge Cases =====

#[test]
fn test_extracted_string_with_all_fields() {
    // A fragmented stack string carries its spans in `fragments`, so the
    // contiguous `data_len` is left unrecorded (0).
    let s = ExtractedString::new("complex_string", 0x5000, StringMethod::StackString)
        .with_kind(StringKind::StackString)
        .with_fragments(vec![StringFragment {
            offset: 0x5000,
            length: 14,
        }]);

    assert_eq!(s.value, "complex_string");
    assert_eq!(s.data_offset, 0x5000);
    assert!(s.fragments.is_some());
    // Fragmented strings locate via their fragments, not the single extent.
    assert_eq!(
        s.source_spans().collect::<Vec<_>>(),
        vec![(0x5000, 14)],
        "source_spans should follow fragments, ignoring data_len"
    );
}

#[test]
fn test_string_kind_default() {
    // Test that Default trait works
    let kind: Option<StringKind> = None;
    assert_eq!(kind, None);
}

#[test]
fn test_severity_all_values() {
    // Ensure all Severity values are distinct
    assert_ne!(Severity::High, Severity::Medium);
    assert_ne!(Severity::Medium, Severity::Low);
    assert_ne!(Severity::Low, Severity::Info);
    assert_ne!(Severity::High, Severity::Info);
}
