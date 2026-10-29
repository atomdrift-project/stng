//! Integration test for a clean Go Windows PE that should trigger zero IOC detections.
//!
//! `does-nothing-windows-amd64.exe` is a Go PE x64 built against klog/logr that
//! contains no network, crypto, or obfuscation behavior. stng previously produced
//! a number of false positives against it:
//!
//! - XOR/IP: `23.22.21.3` from a single-byte XOR 0x03 on an unrelated region.
//! - XOR/incremental: ~20 garbage-looking strings decoded from `.text` using the
//!   incremental scanner (seed 0x28) — bytes happened to match the XOR plaintext
//!   anchors (`://`, `/bin`, etc.) by coincidence.
//! - email: Go module paths like `k8s.io/klog/v2@v2.130.1/klog.go` whose
//!   `package@version` form matched the email regex.
//! - jwt: `internal/runtime/maps.ctrlGroup.matchEmptyOrDeleted` — a Go symbol
//!   with two dots and a slash matching the JWT three-segment heuristic.
//!
//! A hex false positive (`4444444444444444` → `DDDDDDDD`, a Go runtime memory-
//! poison pattern) is surfaced by the CLI via radare2's string extraction; it
//! doesn't currently reach the library-level classifier in a way this test can
//! observe, so it's covered here via the CLI integration test.

use stng::{ExtractOptions, StringKind, StringMethod, extract_strings_with_options};

static SAMPLE_PATH: std::sync::LazyLock<&str> =
    std::sync::LazyLock::new(|| crate::common::path("testdata/pe/does-nothing-windows-amd64.exe"));

fn load_sample() -> Vec<u8> {
    std::fs::read(*SAMPLE_PATH).expect("Failed to read does-nothing-windows-amd64.exe")
}

#[test]
fn test_no_xor_ip_false_positive() {
    let data = load_sample();

    let opts = ExtractOptions::new(4)
        .with_xor(stng::XorMode::Auto)
        .with_xor_min_length(8);
    let extracted = extract_strings_with_options(&data, &opts);

    let xor_ips: Vec<&str> = extracted
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode && s.kind == Some(StringKind::Ip))
        .map(|s| s.value.as_str())
        .collect();

    assert!(
        xor_ips.is_empty(),
        "Clean Go PE should produce no XOR-decoded IPs; found: {xor_ips:?}",
    );
}

#[test]
fn test_no_incremental_xor_false_positives() {
    let data = load_sample();

    let opts = ExtractOptions::new(4)
        .with_xor(stng::XorMode::Auto)
        .with_xor_min_length(8);
    let extracted = extract_strings_with_options(&data, &opts);

    let xor_decoded: Vec<&str> = extracted
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .map(|s| s.value.as_str())
        .collect();

    assert!(
        xor_decoded.is_empty(),
        "Clean Go PE should not trigger the XOR scanner; found {} strings: {:?}",
        xor_decoded.len(),
        xor_decoded,
    );
}

#[test]
fn test_no_email_false_positives_from_go_module_paths() {
    let data = load_sample();

    let opts = ExtractOptions::new(4);
    let extracted = extract_strings_with_options(&data, &opts);

    let emails: Vec<&str> = extracted
        .iter()
        .filter(|s| s.kind == Some(StringKind::Email))
        .map(|s| s.value.as_str())
        .collect();

    // Go module paths of the form "pkg/path@vX.Y.Z/file.go" must not be
    // classified as emails — the `@` here separates module and version.
    for value in &emails {
        assert!(
            !value.contains("@v") || !value.ends_with(".go"),
            "Go module path {value:?} must not be classified as Email",
        );
    }

    // The concrete offenders seen on this sample.
    let known_false_positives = [
        "github.com/go-logr/logr@v1.4.1/logr.go",
        "k8s.io/klog/v2@v2.130.1/klog.go",
    ];
    for fp in known_false_positives {
        assert!(
            !emails.contains(&fp),
            "Known false-positive email {fp:?} should not be detected; emails: {emails:?}",
        );
    }
}

#[test]
fn rizin_no_hex_false_positive_from_runtime_poison_pattern() {
    if !crate::rizin_installed() {
        return;
    }
    // The hex false positive is produced by radare2's string extraction path,
    // which the CLI wires up end-to-end. Invoke the built binary and scan its
    // JSON output.
    let output = crate::stng()
        .arg("--json")
        .arg(*SAMPLE_PATH)
        .output()
        .expect("Failed to run stng CLI");
    assert!(
        output.status.success(),
        "stng CLI failed: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = std::str::from_utf8(&output.stdout).expect("stng output is not UTF-8");
    let strings: Vec<serde_json::Value> =
        serde_json::from_str(stdout).expect("stng --json did not produce a JSON array");

    // "4444444444444444" decodes to "DDDDDDDD" — a Go runtime memory-poison
    // pattern — and must not be classified as HexEncoded.
    let has_hex_poison = strings.iter().any(|s| {
        s.get("value").and_then(|v| v.as_str()) == Some("4444444444444444")
            && s.get("kind").and_then(|v| v.as_str()) == Some("HexEncoded")
    });

    assert!(
        !has_hex_poison,
        "Runtime poison pattern 4444... should not be classified as HexEncoded",
    );
}

#[test]
fn test_no_jwt_false_positive_from_go_symbol() {
    let data = load_sample();

    let opts = ExtractOptions::new(4);
    let extracted = extract_strings_with_options(&data, &opts);

    let jwts: Vec<&str> = extracted
        .iter()
        .filter(|s| s.kind == Some(StringKind::Jwt))
        .map(|s| s.value.as_str())
        .collect();

    // Go symbol names with `pkg/sub.Type.method` shape must not match JWT.
    for value in &jwts {
        assert!(
            !value.starts_with("internal/") && !value.starts_with("runtime/"),
            "Go symbol {value:?} must not be classified as JWT",
        );
    }

    assert!(
        !jwts.contains(&"internal/runtime/maps.ctrlGroup.matchEmptyOrDeleted"),
        "Known false-positive JWT should not be detected; JWTs: {jwts:?}",
    );
}
