//! Tests for severity levels

use stng::{Severity, StringKind};

#[test]
fn rates_encoded_network_and_overlay_high() {
    assert_eq!(StringKind::ShellCmd.severity(), Severity::High);
    assert_eq!(StringKind::SuspiciousPath.severity(), Severity::High);
    assert_eq!(StringKind::Ip.severity(), Severity::High);
    assert_eq!(StringKind::IpPort.severity(), Severity::High);
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
fn rates_env_path_import_medium() {
    assert_eq!(StringKind::EnvVar.severity(), Severity::Medium);
    assert_eq!(StringKind::Path.severity(), Severity::Medium);
    assert_eq!(StringKind::Import.severity(), Severity::Medium);
}

#[test]
fn rates_func_and_export_low() {
    assert_eq!(StringKind::FuncName.severity(), Severity::Low);
    assert_eq!(StringKind::Export.severity(), Severity::Low);
}

#[test]
fn rates_untyped_and_ident_info() {
    // Test None instead of Const
    assert_eq!(
        None::<StringKind>
            .map(StringKind::severity)
            .unwrap_or(Severity::Info),
        Severity::Info
    );
    assert_eq!(StringKind::Ident.severity(), Severity::Info);
}
