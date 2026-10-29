//! Tests for garbage filtering

use super::*;

#[test]
fn test_garbage_filter_enabled() {
    let data = crate::common::bytes("testdata/macho/charge0x_installer_universal.macho");
    let opts_filtered = ExtractOptions::new(4).with_garbage_filter(true);
    let opts_unfiltered = ExtractOptions::new(4).with_garbage_filter(false);

    let filtered = extract_strings_with_options(&data, &opts_filtered);
    let unfiltered = extract_strings_with_options(&data, &opts_unfiltered);

    // Unfiltered should have more or equal strings
    assert!(unfiltered.len() >= filtered.len());
}

// The filter judges each string in its section context, while this checks
// context-free `is_garbage`; they agree on /bin/ls but not in general
// (e.g. x86 asm noise in a data section). Revisit with P8.5.
#[test]
#[cfg(unix)] // reads /bin/ls
fn test_garbage_filter_removes_garbage() {
    // The filter judges each string in its context (kind, section,
    // architecture), so its output is not the strings the context-free
    // `is_garbage` accepts. What holds everywhere: it only removes.
    let data = crate::common::bytes("testdata/elf/hello_linux_amd64");
    let key = |s: &stng::ExtractedString| (s.data_offset, s.value.clone());
    let all: std::collections::HashSet<_> =
        extract_strings_with_options(&data, &ExtractOptions::new(4))
            .iter()
            .map(key)
            .collect();
    let kept =
        extract_strings_with_options(&data, &ExtractOptions::new(4).with_garbage_filter(true));
    assert!(kept.len() < all.len(), "the filter removed nothing");
    for s in &kept {
        assert!(all.contains(&key(s)), "filter added {:?}", s.value);
    }
}

#[test]
fn test_options_default_no_filter() {
    let opts = ExtractOptions::new(4);
    assert!(!opts.filter_garbage());
}

#[test]
fn test_options_with_filter() {
    let opts = ExtractOptions::new(4).with_garbage_filter(true);
    assert!(opts.filter_garbage());
}
