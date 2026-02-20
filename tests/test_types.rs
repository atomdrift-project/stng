//! Comprehensive tests for types.rs
//!
//! Tests core type definitions, methods, serialization, and edge cases.

use serde_json;
use stng::{
    ExtractedString, FunctionMetadata, OverlayInfo, Severity, StringKind, StringMethod,
    StringStruct,
};

// ===== ExtractedString Tests =====

#[test]
fn test_extracted_string_default() {
    let s = ExtractedString::default();
    assert_eq!(s.value, "");
    assert_eq!(s.data_offset, 0);
    assert_eq!(s.section, None);
    assert_eq!(s.method, StringMethod::RawScan);
    assert_eq!(s.kind, StringKind::Const);
    assert_eq!(s.library, None);
    assert_eq!(s.fragments, None);
    assert_eq!(s.section_size, None);
    assert_eq!(s.section_executable, None);
    assert_eq!(s.section_writable, None);
    assert_eq!(s.architecture, None);
    assert_eq!(s.function_meta, None);
}

#[test]
fn test_section_metadata_str_not_section_kind() {
    let s = ExtractedString {
        value: "test".to_string(),
        kind: StringKind::Const,
        section_size: Some(1024),
        section_executable: Some(true),
        section_writable: Some(false),
        ..Default::default()
    };

    // Should return None if not a Section kind
    assert_eq!(s.section_metadata_str(), None);
}

#[test]
fn test_section_metadata_str_missing_size() {
    let s = ExtractedString {
        value: ".text".to_string(),
        kind: StringKind::Section,
        section_size: None,
        ..Default::default()
    };

    // Should return None if size is missing
    assert_eq!(s.section_metadata_str(), None);
}

#[test]
fn test_section_metadata_str_bytes() {
    let s = ExtractedString {
        value: ".text".to_string(),
        kind: StringKind::Section,
        section_size: Some(512), // < 1024
        section_executable: Some(true),
        section_writable: Some(false),
        ..Default::default()
    };

    let meta = s.section_metadata_str().unwrap();
    assert_eq!(meta, "(512b, TEXT)");
}

#[test]
fn test_section_metadata_str_kilobytes() {
    let s = ExtractedString {
        value: ".data".to_string(),
        kind: StringKind::Section,
        section_size: Some(2048), // 2kb
        section_executable: Some(false),
        section_writable: Some(true),
        ..Default::default()
    };

    let meta = s.section_metadata_str().unwrap();
    assert_eq!(meta, "(2.0kb, DATA)");
}

#[test]
fn test_section_metadata_str_megabytes() {
    let s = ExtractedString {
        value: ".rodata".to_string(),
        kind: StringKind::Section,
        section_size: Some(5 * 1024 * 1024), // 5mb
        section_executable: Some(false),
        section_writable: Some(false),
        ..Default::default()
    };

    let meta = s.section_metadata_str().unwrap();
    assert_eq!(meta, "(5.0mb, DATA)");
}

#[test]
fn test_section_metadata_str_text_exec_only() {
    let s = ExtractedString {
        value: ".text".to_string(),
        kind: StringKind::Section,
        section_size: Some(1024),
        section_executable: Some(true),
        section_writable: Some(false),
        ..Default::default()
    };

    let meta = s.section_metadata_str().unwrap();
    assert!(meta.contains("TEXT"));
    assert!(!meta.contains("DATA"));
}

#[test]
fn test_section_metadata_str_data_write_only() {
    let s = ExtractedString {
        value: ".data".to_string(),
        kind: StringKind::Section,
        section_size: Some(1024),
        section_executable: Some(false),
        section_writable: Some(true),
        ..Default::default()
    };

    let meta = s.section_metadata_str().unwrap();
    assert!(meta.contains("DATA"));
    assert!(!meta.contains("TEXT+DATA"));
}

#[test]
fn test_section_metadata_str_text_plus_data() {
    let s = ExtractedString {
        value: ".weird".to_string(),
        kind: StringKind::Section,
        section_size: Some(1024),
        section_executable: Some(true),
        section_writable: Some(true),
        ..Default::default()
    };

    let meta = s.section_metadata_str().unwrap();
    assert!(meta.contains("TEXT+DATA"));
}

#[test]
fn test_section_metadata_str_default_permissions() {
    let s = ExtractedString {
        value: ".bss".to_string(),
        kind: StringKind::Section,
        section_size: Some(1024),
        section_executable: None,
        section_writable: None,
        ..Default::default()
    };

    // Should default to (false, false) -> DATA
    let meta = s.section_metadata_str().unwrap();
    assert!(meta.contains("DATA"));
}

// ===== StringKind::severity() Tests =====

#[test]
fn test_severity_high_security() {
    // Test all High severity kinds
    assert_eq!(StringKind::IP.severity(), Severity::High);
    assert_eq!(StringKind::IPPort.severity(), Severity::High);
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
    assert_eq!(StringKind::SQLInjection.severity(), Severity::High);
    assert_eq!(StringKind::XSSPayload.severity(), Severity::High);
    assert_eq!(StringKind::CommandInjection.severity(), Severity::High);
    assert_eq!(StringKind::CTFFlag.severity(), Severity::High);
}

#[test]
fn test_severity_high_secrets() {
    assert_eq!(StringKind::JWT.severity(), Severity::High);
    assert_eq!(StringKind::APIKey.severity(), Severity::High);
    assert_eq!(StringKind::Mutex.severity(), Severity::High);
    assert_eq!(StringKind::GUID.severity(), Severity::High);
    assert_eq!(StringKind::RansomNote.severity(), Severity::High);
    assert_eq!(StringKind::LDAPPath.severity(), Severity::High);
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
    assert_eq!(StringKind::Const.severity(), Severity::Info);
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
    assert_eq!(StringKind::Const.short_name(), "-");
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
    assert_eq!(StringKind::IP.short_name(), "ip");
    assert_eq!(StringKind::IPPort.short_name(), "ip:port");
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
    assert_eq!(StringKind::CTFFlag.short_name(), "ctf_flag");
    assert_eq!(StringKind::SQLInjection.short_name(), "sqli");
    assert_eq!(StringKind::XSSPayload.short_name(), "xss");
    assert_eq!(StringKind::CommandInjection.short_name(), "cmdi");
}

#[test]
fn test_short_name_secrets() {
    assert_eq!(StringKind::JWT.short_name(), "jwt");
    assert_eq!(StringKind::APIKey.short_name(), "api_key");
    assert_eq!(StringKind::Mutex.short_name(), "mutex");
    assert_eq!(StringKind::GUID.short_name(), "guid");
    assert_eq!(StringKind::RansomNote.short_name(), "ransom");
    assert_eq!(StringKind::LDAPPath.short_name(), "ldap");
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

#[test]
fn test_function_metadata_construction() {
    let meta = FunctionMetadata {
        size: 1024,
        basic_blocks: 10,
        branches: 15,
        instructions: 200,
        signature: Some("int foo(char*, int)".to_string()),
        noreturn: Some(false),
    };

    assert_eq!(meta.size, 1024);
    assert_eq!(meta.basic_blocks, 10);
    assert_eq!(meta.branches, 15);
    assert_eq!(meta.instructions, 200);
    assert_eq!(meta.signature, Some("int foo(char*, int)".to_string()));
    assert_eq!(meta.noreturn, Some(false));
}

#[test]
fn test_function_metadata_clone() {
    let meta = FunctionMetadata {
        size: 512,
        basic_blocks: 5,
        branches: 8,
        instructions: 100,
        signature: None,
        noreturn: Some(true),
    };

    let cloned = meta.clone();
    assert_eq!(meta.size, cloned.size);
    assert_eq!(meta.basic_blocks, cloned.basic_blocks);
    assert_eq!(meta.branches, cloned.branches);
    assert_eq!(meta.instructions, cloned.instructions);
    assert_eq!(meta.signature, cloned.signature);
    assert_eq!(meta.noreturn, cloned.noreturn);
}

#[test]
fn test_function_metadata_equality() {
    let meta1 = FunctionMetadata {
        size: 100,
        basic_blocks: 2,
        branches: 3,
        instructions: 50,
        signature: Some("test".to_string()),
        noreturn: None,
    };

    let meta2 = FunctionMetadata {
        size: 100,
        basic_blocks: 2,
        branches: 3,
        instructions: 50,
        signature: Some("test".to_string()),
        noreturn: None,
    };

    assert_eq!(meta1, meta2);
}

// ===== OverlayInfo Tests =====

#[test]
fn test_overlay_info_construction() {
    let overlay = OverlayInfo {
        start_offset: 0x10000,
        size: 0x5000,
    };

    assert_eq!(overlay.start_offset, 0x10000);
    assert_eq!(overlay.size, 0x5000);
}

#[test]
fn test_overlay_info_clone() {
    let overlay = OverlayInfo {
        start_offset: 0x20000,
        size: 0x8000,
    };

    let cloned = overlay.clone();
    assert_eq!(overlay.start_offset, cloned.start_offset);
    assert_eq!(overlay.size, cloned.size);
}

#[test]
fn test_overlay_info_equality() {
    let overlay1 = OverlayInfo {
        start_offset: 1000,
        size: 500,
    };

    let overlay2 = OverlayInfo {
        start_offset: 1000,
        size: 500,
    };

    assert_eq!(overlay1, overlay2);
}

// ===== Serialization Tests =====

#[test]
fn test_extracted_string_serialization() {
    let s = ExtractedString {
        value: "test_value".to_string(),
        data_offset: 0x1234,
        section: Some(".text".to_string()),
        method: StringMethod::Structure,
        kind: StringKind::FuncName,
        library: Some("libc.so".to_string()),
        fragments: None,
        section_size: None,
        section_executable: None,
        section_writable: None,
        architecture: Some("x86_64".to_string()),
        function_meta: None,
    };

    let json = serde_json::to_string(&s).unwrap();
    assert!(json.contains("test_value"));
    assert!(json.contains("4660")); // 0x1234 in decimal
    assert!(json.contains(".text"));
    assert!(json.contains("libc.so"));
    assert!(json.contains("x86_64"));
}

#[test]
fn test_extracted_string_serialization_skip_none() {
    let s = ExtractedString {
        value: "test".to_string(),
        data_offset: 100,
        section: None,
        method: StringMethod::RawScan,
        kind: StringKind::Const,
        library: None,
        fragments: None,
        section_size: None,
        section_executable: None,
        section_writable: None,
        architecture: None,
        function_meta: None,
    };

    let json = serde_json::to_string(&s).unwrap();
    // None fields should be skipped
    assert!(!json.contains("library"));
    assert!(!json.contains("fragments"));
    assert!(!json.contains("architecture"));
}

#[test]
fn test_function_metadata_serialization() {
    let meta = FunctionMetadata {
        size: 1024,
        basic_blocks: 10,
        branches: 15,
        instructions: 200,
        signature: Some("test_func".to_string()),
        noreturn: Some(false),
    };

    let json = serde_json::to_string(&meta).unwrap();
    assert!(json.contains("1024"));
    assert!(json.contains("10"));
    assert!(json.contains("15"));
    assert!(json.contains("200"));
    assert!(json.contains("test_func"));
    assert!(json.contains("false"));
}

// ===== StringStruct Tests =====

#[test]
fn test_string_struct_construction() {
    let s = StringStruct {
        struct_offset: 0x1000,
        ptr: 0x2000,
        len: 42,
    };

    assert_eq!(s.struct_offset, 0x1000);
    assert_eq!(s.ptr, 0x2000);
    assert_eq!(s.len, 42);
}

#[test]
fn test_string_struct_equality() {
    let s1 = StringStruct {
        struct_offset: 100,
        ptr: 200,
        len: 10,
    };

    let s2 = StringStruct {
        struct_offset: 100,
        ptr: 200,
        len: 10,
    };

    assert_eq!(s1, s2);
}

#[test]
fn test_string_struct_hash() {
    use std::collections::HashSet;

    let s1 = StringStruct {
        struct_offset: 100,
        ptr: 200,
        len: 10,
    };

    let s2 = StringStruct {
        struct_offset: 100,
        ptr: 200,
        len: 10,
    };

    let mut set = HashSet::new();
    set.insert(s1);
    assert!(set.contains(&s2)); // Should find duplicate
}

// ===== ExtractedString with Fragments Tests =====
// Note: StringFragment is not exported in the public API, so we can't test it directly here.
// Fragment handling is tested indirectly through stack string extraction tests.

// ===== Edge Cases =====

#[test]
fn test_section_metadata_str_boundary_sizes() {
    // Test exactly at 1kb boundary
    let s1kb = ExtractedString {
        value: "test".to_string(),
        kind: StringKind::Section,
        section_size: Some(1024),
        ..Default::default()
    };
    assert_eq!(s1kb.section_metadata_str().unwrap(), "(1.0kb, DATA)");

    // Test exactly at 1mb boundary
    let s1mb = ExtractedString {
        value: "test".to_string(),
        kind: StringKind::Section,
        section_size: Some(1024 * 1024),
        ..Default::default()
    };
    assert_eq!(s1mb.section_metadata_str().unwrap(), "(1.0mb, DATA)");
}

#[test]
fn test_extracted_string_with_all_fields() {
    let s = ExtractedString {
        value: "complex_string".to_string(),
        data_offset: 0x5000,
        section: Some(".data".to_string()),
        method: StringMethod::StackString,
        kind: StringKind::StackString,
        library: Some("lib.so".to_string()),
        fragments: None, // Cannot construct StringFragment directly (not exported)
        section_size: Some(4096),
        section_executable: Some(false),
        section_writable: Some(true),
        architecture: Some("arm64".to_string()),
        function_meta: Some(FunctionMetadata {
            size: 256,
            basic_blocks: 4,
            branches: 6,
            instructions: 50,
            signature: Some("void func()".to_string()),
            noreturn: Some(false),
        }),
    };

    assert_eq!(s.value, "complex_string");
    assert_eq!(s.data_offset, 0x5000);
    assert!(s.section.is_some());
    assert!(s.library.is_some());
    assert!(s.section_size.is_some());
    assert!(s.architecture.is_some());
    assert!(s.function_meta.is_some());
}

#[test]
fn test_string_kind_default() {
    // Test that Default trait works
    let kind: StringKind = Default::default();
    assert_eq!(kind, StringKind::Const);
}

#[test]
fn test_severity_all_values() {
    // Ensure all Severity values are distinct
    assert_ne!(Severity::High, Severity::Medium);
    assert_ne!(Severity::Medium, Severity::Low);
    assert_ne!(Severity::Low, Severity::Info);
    assert_ne!(Severity::High, Severity::Info);
}
