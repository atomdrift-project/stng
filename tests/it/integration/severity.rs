//! Tests for severity levels

use stng::{Severity, StringKind};

#[test]
fn test_all_kinds_have_severity() {
    // Ensure all StringKind variants return a valid severity
    let kinds = vec![
        None,
        Some(StringKind::FuncName),
        Some(StringKind::Ident),
        Some(StringKind::Import),
        Some(StringKind::Export),
        Some(StringKind::Url),
        Some(StringKind::IP),
        Some(StringKind::IPPort),
        Some(StringKind::EnvVar),
        Some(StringKind::Path),
        Some(StringKind::SuspiciousPath),
        Some(StringKind::ShellCmd),
        Some(StringKind::Base64),
        Some(StringKind::HexEncoded),
        Some(StringKind::UnicodeEscaped),
        Some(StringKind::UrlEncoded),
        Some(StringKind::Base32),
        Some(StringKind::Base58),
        Some(StringKind::Overlay),
        Some(StringKind::OverlayWide),
    ];

    for kind in kinds {
        let severity = kind.map(StringKind::severity).unwrap_or(Severity::Info);
        assert!(
            matches!(
                severity,
                Severity::Info | Severity::Low | Severity::Medium | Severity::High
            ),
            "{kind:?} should have a valid severity"
        );
    }
}

#[test]
fn test_high_severity_kinds() {
    assert_eq!(StringKind::ShellCmd.severity(), Severity::High);
    assert_eq!(StringKind::SuspiciousPath.severity(), Severity::High);
    assert_eq!(StringKind::IP.severity(), Severity::High);
    assert_eq!(StringKind::IPPort.severity(), Severity::High);
    assert_eq!(StringKind::Base64.severity(), Severity::High);
    assert_eq!(StringKind::HexEncoded.severity(), Severity::High);
    assert_eq!(StringKind::UnicodeEscaped.severity(), Severity::High);
    assert_eq!(StringKind::UrlEncoded.severity(), Severity::High);
    assert_eq!(StringKind::Base32.severity(), Severity::High);
    assert_eq!(StringKind::Base58.severity(), Severity::High);
    assert_eq!(StringKind::Overlay.severity(), Severity::High);
    assert_eq!(StringKind::OverlayWide.severity(), Severity::High);
}

#[test]
fn test_medium_severity_kinds() {
    assert_eq!(StringKind::EnvVar.severity(), Severity::Medium);
    assert_eq!(StringKind::Path.severity(), Severity::Medium);
    assert_eq!(StringKind::Import.severity(), Severity::Medium);
}

#[test]
fn test_low_severity_kinds() {
    assert_eq!(StringKind::FuncName.severity(), Severity::Low);
    assert_eq!(StringKind::Export.severity(), Severity::Low);
}

#[test]
fn test_info_severity_kinds() {
    // Test None instead of Const
    assert_eq!(
        None::<StringKind>
            .map(StringKind::severity)
            .unwrap_or(Severity::Info),
        Severity::Info
    );
    assert_eq!(StringKind::Ident.severity(), Severity::Info);
}
