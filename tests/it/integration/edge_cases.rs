use super::*;

#[test]
fn test_extract_with_zero_min_length() {
    let data = minimal_elf_header();
    // Must not panic.
    let _ = extract_strings(&data, 0);
}

#[test]
fn test_extract_with_large_min_length() {
    let data = minimal_elf_header();
    let strings = extract_strings(&data, 1000);
    assert!(strings.is_empty());
}

#[test]
fn test_string_kind_debug() {
    let kinds = vec![
        None,
        Some(StringKind::FuncName),
        Some(StringKind::FilePath),
        Some(StringKind::EnvVar),
        Some(StringKind::Error),
        Some(StringKind::Url),
        Some(StringKind::Path),
        Some(StringKind::Section),
        Some(StringKind::Ident),
        Some(StringKind::Arg),
        Some(StringKind::MapKey),
        Some(StringKind::Import),
        Some(StringKind::Export),
    ];
    for kind in kinds {
        let s = format!("{kind:?}");
        assert!(!s.is_empty());
    }
}

#[test]
fn test_string_method_debug() {
    let methods = vec![
        StringMethod::Structure,
        StringMethod::InstructionPattern,
        StringMethod::RawScan,
        StringMethod::Heuristic,
        StringMethod::RizinString,
        StringMethod::RizinSymbol,
    ];
    for method in methods {
        let s = format!("{method:?}");
        assert!(!s.is_empty());
    }
}

#[test]
fn test_extract_options_builder_pattern() {
    let opts = ExtractOptions::new(5)
        .with_garbage_filter(true)
        .with_xor(stng::XorMode::Auto)
        .with_xor_min_length(12);
    assert_eq!(opts.min_length(), 5);
    assert_eq!(*opts.xor(), stng::XorMode::Auto);
}

#[test]
fn test_extracted_string_equality() {
    let s1 = ExtractedString::new("test".to_string(), 0x1000, StringMethod::Structure);
    let s2 = ExtractedString::new("test".to_string(), 0x1000, StringMethod::Structure);
    // Clone check
    let s3 = s1.clone();
    assert_eq!(s1.value, s2.value);
    assert_eq!(s1.value, s3.value);
}

#[test]
fn test_is_garbage_edge_cases() {
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
fn test_minimal_pe_header() {
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
