#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Real-world test for the 3CX supply-chain implant (`libffmpeg.dylib`).
//!
//! The macOS payload hides its command-and-control configuration behind a
//! single-byte XOR (key `0x7a`). Each C2 URL is stored in a fixed-size record,
//! preceded by NUL padding. Under the key, NUL decodes to the printable byte
//! `'z'`, so a naive printable-run scan sees each URL buried inside a long run
//! of padding and either trims it away or rejects the whole run as null-heavy.
//!
//! This sample is the x86_64 slice of the fat binary, which carries the config.

use stng::{ExtractOptions, StringMethod};

/// The ten fake-CDN C2 domains embedded in the macOS 3CX config block.
const C2_DOMAINS: &[&str] = &[
    "msstorageazure.com",
    "officestoragebox.com",
    "visualstudiofactory.com",
    "azuredeploystore.com",
    "msstorageboxes.com",
    "officeaddons.com",
    "sourceslabs.com",
    "acharryblogs.com", // stored as "zacharryblogs.com"; leading 'z' == key byte 0x7a == NUL padding
    "pbxcloudeservices.com",
    "pbxphonenetwork.com",
];

#[test]
fn test_3cx_libffmpeg_xor_config() {
    let sample_path = "testdata/xor/libffmpeg_3cx_x64_xor";

    // Skip if sample doesn't exist (large real-world binary may be omitted).
    if !std::path::Path::new(sample_path).exists() {
        eprintln!("Skipping - 3CX sample not found at {sample_path}");
        return;
    }

    let data = std::fs::read(sample_path).expect("Failed to read 3CX sample");

    // Analyst workflow: supply the known single-byte key.
    let opts = ExtractOptions::new(6).with_xor_key(vec![0x7a]);
    let extracted = stng::extract_strings_with_options(&data, &opts);

    let xor_strings: Vec<&str> = extracted
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .map(|s| s.value.as_str())
        .collect();

    println!("Recovered {} XOR-decoded strings", xor_strings.len());

    // The regression this guards against: NUL-padded C2 records were dropped
    // wholesale (0/10 recovered) before padding-aware run segmentation.
    let missing: Vec<&str> = C2_DOMAINS
        .iter()
        .copied()
        .filter(|dom| !xor_strings.iter().any(|s| s.contains(dom)))
        .collect();
    assert!(
        missing.is_empty(),
        "Failed to recover XOR-hidden C2 domains: {missing:?}"
    );

    // The cookie-based auth format string reveals the C2 protocol.
    assert!(
        xor_strings.iter().any(|s| s.contains("3cx_auth_id=")),
        "Should recover the 3cx_auth_id cookie auth format string"
    );

    // The local staging path under the 3CX app support directory.
    assert!(
        xor_strings
            .iter()
            .any(|s| s.contains("Library/Application Support/3CX Desktop App")),
        "Should recover the 3CX Desktop App staging path"
    );
}
