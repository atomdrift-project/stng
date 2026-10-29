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
#[cfg_attr(windows, ignore = "reads /bin/ls")]
fn test_garbage_filter_removes_garbage() {
    let data = std::fs::read("/bin/ls").expect("read /bin/ls");
    let opts = ExtractOptions::new(4).with_garbage_filter(true);
    let strings = extract_strings_with_options(&data, &opts);

    // All strings should pass is_garbage check, except for special kinds
    // that are exempt from garbage filtering (Section, EntitlementsXml)
    for s in &strings {
        if s.kind != Some(StringKind::Section) && s.kind != Some(StringKind::EntitlementsXml) {
            assert!(
                !is_garbage(&s.value),
                "Found garbage string: {} (kind: {:?})",
                s.value,
                s.kind
            );
        }
    }
}

#[test]
fn test_options_default_no_filter() {
    let opts = ExtractOptions::new(4);
    assert!(!opts.filter_garbage);
}

#[test]
fn test_options_with_filter() {
    let opts = ExtractOptions::new(4).with_garbage_filter(true);
    assert!(opts.filter_garbage);
}
