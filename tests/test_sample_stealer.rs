#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Integration test for Go credential stealer sample.
//!
//! Validates that structure-based and instruction-pattern extraction finds
//! short strings like "gh", "auth", "token" that are passed as arguments
//! to exec.Command calls in Go binaries, including stack-based patterns
//! used for variadic arguments and interface conversions.

use stng::ExtractOptions;

#[test]
fn test_sample_stealer_short_strings() {
    let sample_path = "testdata/malware/sample-stealer";
    if !std::path::Path::new(sample_path).exists() {
        eprintln!("Skipping - sample not found at {sample_path}");
        return;
    }

    let data = std::fs::read(sample_path).expect("Failed to read sample");

    // Use default min_length=4 — short strings from high-confidence extraction
    // (structure-based and instruction pattern) should still appear.
    let opts = ExtractOptions::new(4);
    let extracted = stng::extract_strings_with_options(&data, &opts);

    let values: Vec<&str> = extracted.iter().map(|s| s.value.as_str()).collect();

    // Short strings from exec.Command arguments — Go stores these as
    // inline literals loaded via LEA+MOV instruction patterns, including
    // stack-based patterns for variadic/interface arguments.
    let required_short = ["gh", "auth", "token"];
    for needle in required_short {
        assert!(
            values.contains(&needle),
            "Missing short string {:?} — high-confidence extraction should find it",
            needle,
        );
    }

    // Other exec.Command arguments, string literals, and path components.
    // These test both register-based and stack-based instruction patterns.
    let required_exact = [
        "git",
        "credential",
        "gcloud",
        "kubectl",
        "password=",
        "no oauth token",
        "application/json",
        ".npmrc",
        ".pypirc",
        ".docker",
        "config.json",
        ".cursor",
        ".kiro",
        "mcp.json",
    ];
    for needle in required_exact {
        assert!(
            values.iter().any(|v| v.contains(needle)),
            "Missing expected string containing {:?}",
            needle,
        );
    }
}
