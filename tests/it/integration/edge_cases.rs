use super::*;

#[test]
fn zero_min_length_does_not_panic() {
    let data = minimal_elf_header();
    // Must not panic.
    let _ = extract_strings(&data, 0);
}

#[test]
fn huge_min_length_finds_nothing() {
    let data = minimal_elf_header();
    let strings = extract_strings(&data, 1000);
    assert!(strings.is_empty());
}

#[test]
fn builder_chains_all_setters() {
    let opts = ExtractOptions::new(5)
        .with_garbage_filter(true)
        .with_xor(stng::XorMode::Auto)
        .with_xor_min_length(12);
    assert_eq!(opts.min_length(), 5);
    assert_eq!(*opts.xor(), stng::XorMode::Auto);
}

#[test]
fn clone_keeps_value() {
    let s1 = ExtractedString::new("test".to_string(), 0x1000, StringMethod::Structure);
    let s2 = ExtractedString::new("test".to_string(), 0x1000, StringMethod::Structure);
    // Clone check
    let s3 = s1.clone();
    assert_eq!(s1.value, s2.value);
    assert_eq!(s1.value, s3.value);
}

#[test]
fn rejects_tabs_newlines_and_non_ascii() {
    // Null bytes
    assert!(is_garbage("ab\0cd"));
    // Tabs are treated as garbage
    assert!(is_garbage("hello\tworld"));
    // Newlines are also garbage
    assert!(is_garbage("hello\nworld"));
    // Non-ASCII unicode is treated as garbage (binary artifacts)
    assert!(is_garbage("héllo wörld"));
    // ASCII strings are fine
    assert!(!is_garbage("hello world"));
    // Very long string (all same char is garbage)
    let long = "a".repeat(10000);
    assert!(is_garbage(&long));
    // Long varied string is not garbage
    let varied = "hello world this is a longer test string";
    assert!(!is_garbage(varied));
}

#[test]
fn finds_nothing_in_bare_pe_header() {
    // Create minimal PE header
    let mut data = vec![0u8; 512];
    // DOS header magic
    data[0..2].copy_from_slice(&[0x4D, 0x5A]); // MZ
    // PE offset at 0x3C
    data[0x3C..0x40].copy_from_slice(&[0x80, 0x00, 0x00, 0x00]);
    // PE signature at 0x80
    data[0x80..0x84].copy_from_slice(&[0x50, 0x45, 0x00, 0x00]); // PE\0\0

    // This is a minimal/invalid PE, should return empty
    let strings = extract_strings(&data, 4);
    assert!(strings.is_empty());
}
