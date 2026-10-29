use super::*;
use crate::StringKind;
use goblin::mach::MachO;

#[test]
fn test_rust_extractor_creation() {
    let extractor = RustStringExtractor::new(4);
    assert_eq!(extractor.min_length, 4);
}

#[test]
fn test_rust_extractor_different_min_lengths() {
    let extractor1 = RustStringExtractor::new(0);
    assert_eq!(extractor1.min_length, 0);
    let extractor2 = RustStringExtractor::new(100);
    assert_eq!(extractor2.min_length, 100);
}

#[test]
fn test_raw_string_extraction() {
    let extractor = RustStringExtractor::new(4);
    let data = b"Hello\0World\0foo\0";

    let strings = extractor.extract_raw_strings(data);

    assert_eq!(strings.len(), 2); // "Hello" and "World", "foo" is < 4 chars
    assert!(strings.iter().any(|s| s.value == "Hello"));
    assert!(strings.iter().any(|s| s.value == "World"));
}

#[test]
fn test_raw_string_deduplication() {
    let extractor = RustStringExtractor::new(4);
    let data = b"Hello\0Hello\0World\0";

    let strings = extractor.extract_raw_strings(data);

    // Should deduplicate
    assert_eq!(strings.iter().filter(|s| s.value == "Hello").count(), 1);
}

#[test]
fn test_raw_string_min_length() {
    let extractor = RustStringExtractor::new(6);
    let data = b"Hello\0World\0";

    let strings = extractor.extract_raw_strings(data);

    // "Hello" is 5 chars, "World" is 5 chars - both < 6
    assert!(strings.is_empty());
}

#[test]
fn test_raw_string_whitespace_trimming() {
    let extractor = RustStringExtractor::new(4);
    let data = b"  Hello  \0  World  \0";

    let strings = extractor.extract_raw_strings(data);

    assert!(strings.iter().any(|s| s.value == "Hello"));
    assert!(strings.iter().any(|s| s.value == "World"));
}

#[test]
fn test_raw_string_non_printable_breaks() {
    let extractor = RustStringExtractor::new(4);
    // Non-printable byte should break the string
    let data = b"Hello\x01World\0";

    let strings = extractor.extract_raw_strings(data);

    // Should have World (5 chars), Hello was broken
    assert!(strings.iter().any(|s| s.value == "World"));
}

#[test]
fn test_extract_packed_strings_urls() {
    let extractor = RustStringExtractor::new(4);
    let data = b"https://example.com/path?query=value";

    let strings = extractor.extract_packed_strings(data);

    assert!(strings.iter().any(|s| s.value.contains("example.com")));
}

#[test]
fn test_extract_packed_strings_paths() {
    let extractor = RustStringExtractor::new(4);
    let data = b"/usr/local/bin/rustc";

    let strings = extractor.extract_packed_strings(data);

    assert!(strings.iter().any(|s| s.value.contains("/usr")));
}

#[test]
fn test_extract_packed_strings_env_vars() {
    let extractor = RustStringExtractor::new(4);
    let data = b"RUST_BACKTRACE=full HOME_DIR=/home";

    let strings = extractor.extract_packed_strings(data);

    assert!(strings.iter().any(|s| s.value.contains("RUST_BACKTRACE")));
}

#[test]
fn test_extract_packed_strings_snake_case() {
    let extractor = RustStringExtractor::new(4);
    let data = b"my_function_name some_other_var";

    let strings = extractor.extract_packed_strings(data);

    assert!(strings.iter().any(|s| s.value.contains("my_function_name")));
}

#[test]
fn test_extract_packed_strings_domain_names() {
    let extractor = RustStringExtractor::new(4);
    let data = b"example.com api.github.com";

    let strings = extractor.extract_packed_strings(data);

    assert!(strings.iter().any(|s| s.value.contains("example.com")));
}

#[test]
fn test_extract_packed_strings_null_separated() {
    let extractor = RustStringExtractor::new(4);
    let data = b"hello\0world\0test";

    let strings = extractor.extract_packed_strings(data);

    // Should split on nulls
    assert!(strings.iter().any(|s| s.value == "hello"));
    assert!(strings.iter().any(|s| s.value == "world"));
}

#[test]
fn test_extract_packed_strings_newline_separated() {
    let extractor = RustStringExtractor::new(4);
    let data = b"line1\nline2\nline3";

    let strings = extractor.extract_packed_strings(data);

    // Should process newlines
    assert!(!strings.is_empty());
}

#[test]
fn test_add_if_valid_too_short() {
    let extractor = RustStringExtractor::new(10);
    let mut strings = Vec::new();
    let mut seen = HashSet::new();

    extractor.add_if_valid("short", 0, &mut strings, &mut seen);

    assert!(strings.is_empty());
}

#[test]
fn test_add_if_valid_duplicate() {
    let extractor = RustStringExtractor::new(4);
    let mut strings = Vec::new();
    let mut seen = HashSet::new();

    seen.insert("hello".to_string());
    extractor.add_if_valid("hello", 0, &mut strings, &mut seen);

    assert!(strings.is_empty());
}

#[test]
fn test_add_if_valid_mostly_digits() {
    let extractor = RustStringExtractor::new(4);
    let mut strings = Vec::new();
    let mut seen = HashSet::new();

    // More than 70% digits should be rejected
    extractor.add_if_valid("12345678ab", 0, &mut strings, &mut seen);

    assert!(strings.is_empty());
}

#[test]
fn test_add_if_valid_hex_pattern() {
    let extractor = RustStringExtractor::new(4);
    let mut strings = Vec::new();
    let mut seen = HashSet::new();

    // Short hex patterns should be rejected
    extractor.add_if_valid("deadbeef", 0, &mut strings, &mut seen);

    assert!(strings.is_empty());
}

#[test]
fn test_add_if_valid_success() {
    let extractor = RustStringExtractor::new(4);
    let mut strings = Vec::new();
    let mut seen = HashSet::new();

    extractor.add_if_valid("hello_world", 0, &mut strings, &mut seen);

    assert_eq!(strings.len(), 1);
    assert_eq!(strings[0].value, "hello_world");
    assert_eq!(strings[0].method, StringMethod::Heuristic);
}

#[test]
fn test_extract_patterns_from_segment_complex() {
    let extractor = RustStringExtractor::new(4);
    let segment = "https://example.com/path /usr/bin/test MY_ENV_VAR=value snake_case_ident";
    let mut strings = Vec::new();
    let mut seen = HashSet::new();

    extractor.extract_patterns_from_segment(segment, 0, &mut strings, &mut seen);

    // Should extract URLs, paths, env vars, and identifiers
    assert!(!strings.is_empty());
}

#[test]
fn test_extract_patterns_case_transition_split() {
    let extractor = RustStringExtractor::new(4);
    // lowercaseUPPERCASEFOLLOWS - should split on case transition
    let segment = "helloWORLDNOW";
    let mut strings = Vec::new();
    let mut seen = HashSet::new();

    extractor.extract_patterns_from_segment(segment, 0, &mut strings, &mut seen);

    // Should handle case transitions
    assert!(!strings.is_empty());
}

#[test]
fn test_find_section_not_found() {
    // Create minimal ELF-like data
    let mut data = vec![0u8; 512];
    data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    data[4] = 2; // 64-bit
    data[5] = 1; // little endian

    // Parse as ELF and try to find a non-existent section
    if let Ok(goblin::Object::Elf(elf)) = goblin::Object::parse(&data) {
        let result = crate::binary::elf_section(&elf, &data, ".nonexistent");
        assert!(result.is_none());
    }
}

#[test]
fn test_raw_string_classification() {
    let extractor = RustStringExtractor::new(4);
    let data = b"https://example.com\0/usr/bin\0ERROR_CODE\0";

    let strings = extractor.extract_raw_strings(data);

    // Check classification
    let url = strings
        .iter()
        .find(|s| s.value.contains("example"))
        .unwrap();
    assert_eq!(url.kind, Some(StringKind::Url));

    let path = strings.iter().find(|s| s.value.contains("/usr")).unwrap();
    assert_eq!(path.kind, Some(StringKind::Path));
}

#[test]
fn test_elf_extraction_empty_data() {
    let extractor = RustStringExtractor::new(4);
    let mut elf_data = vec![0u8; 64];
    elf_data[0..4].copy_from_slice(b"\x7fELF");
    elf_data[4] = 2;
    elf_data[5] = 1;
    elf_data[6] = 1;
    if let Ok(elf) = goblin::elf::Elf::parse(&elf_data) {
        let strings = extractor.extract_elf(&elf, &elf_data);
        assert!(strings.len() < 10);
    }
}

#[test]
fn test_elf_extraction_with_rodata() {
    let extractor = RustStringExtractor::new(4);
    let mut elf_data = vec![0u8; 1024];
    elf_data[0..4].copy_from_slice(b"\x7fELF");
    elf_data[4] = 2;
    elf_data[5] = 1;
    elf_data[6] = 1;
    elf_data[16] = 3;
    elf_data[18] = 0x3e;
    let test_strings = b"test_string\0another_test\0hello_world\0";
    elf_data[512..512 + test_strings.len()].copy_from_slice(test_strings);
    if let Ok(elf) = goblin::elf::Elf::parse(&elf_data) {
        let strings = extractor.extract_elf(&elf, &elf_data);
        assert!(strings.len() < 100);
    }
}

#[test]
fn test_macho_extraction_minimal() {
    let extractor = RustStringExtractor::new(4);
    let mut macho_data = vec![0u8; 4096];
    macho_data[0..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
    if let Ok(macho) = MachO::parse(&macho_data, 0) {
        let strings = extractor.extract_macho(&macho, 0);
        assert!(strings.len() < 10);
    }
}

/// A small Rust program built for linux/amd64 (see testdata/rust_elf).
fn rust_elf() -> (&'static [u8], goblin::elf::Elf<'static>) {
    let data = crate::test_fixture("testdata/rust_elf/linux_amd64");
    (data, goblin::elf::Elf::parse(data).unwrap())
}

#[test]
fn test_elf_multiple_sections() {
    let (data, elf) = rust_elf();
    let strings = RustStringExtractor::new(4).extract_elf(&elf, data);
    assert!(!strings.is_empty());
    assert!(
        strings
            .iter()
            .any(|s| s.method == crate::StringMethod::Structure)
    );
}

#[test]
fn test_min_length_filtering_elf() {
    let (data, elf) = rust_elf();
    let strings_short = RustStringExtractor::new(4).extract_elf(&elf, data);
    let strings_long = RustStringExtractor::new(20).extract_elf(&elf, data);
    assert!(strings_long.len() <= strings_short.len());
    // Structure-based strings can be shorter than min_length (down to 2).
    for s in strings_long.iter().chain(&strings_short) {
        assert!(s.value.len() >= 2, "String too short: '{}'", s.value);
    }
}

#[test]
fn test_elf_string_deduplication() {
    let (data, elf) = rust_elf();
    let strings = RustStringExtractor::new(4).extract_elf(&elf, data);
    let mut seen = std::collections::HashSet::new();
    let duplicates = strings.iter().filter(|s| !seen.insert(&s.value)).count();
    assert!(
        duplicates * 10 <= strings.len(),
        "Too many duplicates: {duplicates} out of {}",
        strings.len()
    );
}

#[test]
fn test_macho_text_const() {
    let data = crate::test_fixture("testdata/macho/rust_heap_xor_installer_universal.macho");
    let goblin::mach::Mach::Fat(fat) = goblin::mach::Mach::parse(data).unwrap() else {
        panic!("universal binary")
    };
    let arch = fat.arches().unwrap()[0];
    let slice = &data[arch.offset as usize..][..arch.size as usize];
    let macho = MachO::parse(slice, 0).unwrap();
    let strings = RustStringExtractor::new(4).extract_macho(&macho, 0);
    assert!(!strings.is_empty());
    for s in &strings {
        assert!(s.value.len() >= STRUCTURE_MIN_LENGTH, "{:?}", s.value);
    }
}

#[test]
fn test_corrupted_binary_handling() {
    let extractor = RustStringExtractor::new(4);
    let garbage_data = vec![0xAA; 1024];
    if let Ok(elf) = goblin::elf::Elf::parse(&garbage_data) {
        let strings = extractor.extract_elf(&elf, &garbage_data);
        assert!(strings.len() < 500);
    }
}

#[test]
fn test_very_large_min_length() {
    let (data, elf) = rust_elf();
    let strings = RustStringExtractor::new(1000).extract_elf(&elf, data);
    // Even with min_length 1000, structure-based strings can be as short as 2.
    for s in &strings {
        assert!(
            s.value.len() >= 2,
            "String shorter than STRUCTURE_MIN_LENGTH"
        );
    }
    assert!(strings.len() < 50);
}

#[test]
fn test_offset_validity() {
    let (data, elf) = rust_elf();
    let file_size = data.len() as u64;
    for s in RustStringExtractor::new(4).extract_elf(&elf, data) {
        assert!(
            s.data_offset < file_size,
            "Offset {} exceeds file size {file_size}",
            s.data_offset
        );
    }
}
