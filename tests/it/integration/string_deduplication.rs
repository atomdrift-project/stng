use std::fs;
use stng::{ExtractOptions, extract_strings_with_options};

#[test]
fn test_overlapping_strings_keep_longest() {
    // Create binary with overlapping strings at same offset
    let data = b"\x00\x00\x00\x00HelloWorld\x00Extra\x00";

    let opts = ExtractOptions::new(4);
    let strings = extract_strings_with_options(data, &opts);

    // Group strings by offset
    let mut by_offset = std::collections::HashMap::new();
    for s in &strings {
        by_offset
            .entry(s.data_offset)
            .or_insert_with(Vec::new)
            .push(s);
    }

    // At each offset, should only have one string
    for (offset, strings_at_offset) in by_offset {
        assert_eq!(
            strings_at_offset.len(),
            1,
            "Offset 0x{:x} should only have one string (the longest). Found: {:?}",
            offset,
            strings_at_offset
                .iter()
                .map(|s| &s.value)
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn test_kimwolf_installer_section_names() {
    // Test that we extract all section names that GNU strings finds
    let path = crate::common::path("testdata/malware/kimwolf_installer");
    let data = fs::read(path).expect("Failed to read kimwolf_installer test sample");

    let opts = ExtractOptions::new(4);
    let strings = extract_strings_with_options(&data, &opts);

    let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();

    // Print strings around offset 520-560

    // Section names that GNU strings finds
    assert!(
        values.contains(&".shstrtab"),
        "Should find .shstrtab section name. Found: {values:?}"
    );
    assert!(
        values.contains(&".text"),
        "Should find .text section name. Found: {values:?}"
    );
    assert!(
        values.contains(&".data"),
        "Should find .data section name. Found: {values:?}"
    );
    assert!(
        values.contains(&".ARM.attributes"),
        "Should find .ARM.attributes section name. Found: {values:?}"
    );
}
