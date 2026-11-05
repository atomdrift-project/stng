//! Tests for real binaries in testdata

use std::path::Path;
use stng::{ExtractOptions, StringKind, extract_strings_with_options};

#[test]
fn static_go_elf_has_no_imports() {
    let path = Path::new(crate::common::path("testdata/elf/hello_linux_amd64"));

    let data = std::fs::read(path).unwrap();
    let opts = ExtractOptions::new(4);

    let strings = extract_strings_with_options(&data, &opts);

    // A statically linked Go binary imports nothing.
    let imports: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == Some(StringKind::Import))
        .map(|s| &s.value)
        .collect();
    assert!(imports.is_empty(), "{imports:?}");
}

#[test]
fn finds_runtime_strings_in_go_pe() {
    let path = Path::new(crate::common::path("testdata/pe/hello_windows.exe"));

    let data = std::fs::read(path).unwrap();
    let opts = ExtractOptions::new(4);

    let strings = extract_strings_with_options(&data, &opts);

    assert!(!strings.is_empty(), "Should extract strings from PE");

    // Check for common Go runtime strings
    let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();
    let has_runtime = values
        .iter()
        .any(|v| v.contains("runtime") || v.contains("go"));
    assert!(has_runtime, "Go PE should have runtime strings");
}

#[test]
fn higher_min_length_finds_fewer_in_go_elf() {
    let path = Path::new(crate::common::path("testdata/elf/hello_linux_amd64"));

    let data = std::fs::read(path).unwrap();

    let opts_short = ExtractOptions::new(4);
    let opts_long = ExtractOptions::new(20);

    let strings_short = extract_strings_with_options(&data, &opts_short);
    let strings_long = extract_strings_with_options(&data, &opts_long);

    assert!(
        strings_long.len() <= strings_short.len(),
        "Longer min_length should produce fewer strings"
    );
}

/// End-to-end test against the BrickStorm/garble-obfuscated ELF malware sample.
///
/// Verifies that XOR-pair extraction recovers known strings from the binary,
/// including environment variable lookups, the C2 hostname, and multi-chunk
/// merged results longer than a single 8-byte encoding chunk.
#[test]
fn recovers_brickstorm_xor_pairs() {
    use stng::StringMethod;

    let path = Path::new(crate::common::path(
        "testdata/malware/brickstorm_linux_amd64",
    ));

    let data = std::fs::read(path).unwrap();
    let opts = ExtractOptions::new(4);

    let strings = extract_strings_with_options(&data, &opts);
    let xor: Vec<_> = strings
        .iter()
        .filter(|s| s.method == StringMethod::XorStackPair)
        .collect();

    assert!(
        !xor.is_empty(),
        "expected XorStackPair results from BrickStorm binary"
    );

    let values: Vec<&str> = xor.iter().map(|s| s.value.as_str()).collect();

    // Environment variable lookups observed in the wild.
    for expected in &["PATH", "HOME", "TERM"] {
        assert!(
            values.contains(expected),
            "expected env var {expected:?} in XOR-pair results"
        );
    }

    // C2 hostname fragment — characteristic of this sample.
    assert!(
        values.iter().any(|v| v.contains("systemsvcs")),
        "expected C2 hostname fragment containing 'systemsvcs'"
    );

    // Multi-chunk merging: at least one result longer than one 8-byte chunk.
    let max_len = xor.iter().map(|s| s.value.len()).max().unwrap_or(0);
    assert!(
        max_len > 8,
        "expected at least one merged multi-chunk result (got max len {max_len})"
    );
}
