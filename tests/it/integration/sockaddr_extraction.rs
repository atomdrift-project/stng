use std::fs;
use stng::{ExtractOptions, extract_strings_with_options};

// The C2 address comes from rizin's connect() scan, which the CLI runs:
// see `rizin_recovers_kimwolf_connect_address` in cli.rs.

#[test]
fn test_kimwolf_installer_string_deduplication() {
    // Test that overlapping strings at same offset only keep the longest
    let path = crate::common::path("testdata/malware/kimwolf_installer");
    let data = fs::read(path).expect("Failed to read kimwolf_installer test sample");

    let opts = ExtractOptions::new(4).with_garbage_filter(true);

    let strings = extract_strings_with_options(&data, &opts);

    // Check strings at offset 0x1d4
    let strings_at_1d4: Vec<_> = strings.iter().filter(|s| s.data_offset == 0x1d4).collect();

    // Should only have ONE string at this offset (the longest one)
    assert_eq!(
        strings_at_1d4.len(),
        1,
        "Should only have one string at offset 0x1d4 (the longest). Found: {:?}",
        strings_at_1d4.iter().map(|s| &s.value).collect::<Vec<_>>()
    );

    // The kept string should be the longest one
    let kept_string = strings_at_1d4[0];
    assert!(
        kept_string.value.len() >= "krebsforeheadindustrie".len(),
        "Kept string should be at least as long as the shorter variant"
    );
}
