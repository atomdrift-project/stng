use super::*;
use crate::StringKind;
use goblin::mach::MachO;

#[test]
fn new_sets_min_length() {
    let extractor = RustStringExtractor::new(4);
    assert_eq!(extractor.min_length, 4);
}

#[test]
fn new_keeps_extreme_min_lengths() {
    let extractor1 = RustStringExtractor::new(0);
    assert_eq!(extractor1.min_length, 0);
    let extractor2 = RustStringExtractor::new(100);
    assert_eq!(extractor2.min_length, 100);
}

#[test]
fn raw_scan_splits_on_nul_and_drops_short() {
    let extractor = RustStringExtractor::new(4);
    let data = b"Hello\0World\0foo\0";

    let strings = extractor.extract_raw_strings(data);

    assert_eq!(strings.len(), 2); // "Hello" and "World", "foo" is < 4 chars
    assert!(strings.iter().any(|s| s.value == "Hello"));
    assert!(strings.iter().any(|s| s.value == "World"));
}

#[test]
fn raw_scan_deduplicates() {
    let extractor = RustStringExtractor::new(4);
    let data = b"Hello\0Hello\0World\0";

    let strings = extractor.extract_raw_strings(data);

    // Should deduplicate
    assert_eq!(strings.iter().filter(|s| s.value == "Hello").count(), 1);
}

#[test]
fn raw_scan_respects_min_length() {
    let extractor = RustStringExtractor::new(6);
    let data = b"Hello\0World\0";

    let strings = extractor.extract_raw_strings(data);

    // "Hello" is 5 chars, "World" is 5 chars - both < 6
    assert!(strings.is_empty());
}

#[test]
fn raw_scan_trims_whitespace() {
    let extractor = RustStringExtractor::new(4);
    let data = b"  Hello  \0  World  \0";

    let strings = extractor.extract_raw_strings(data);

    assert!(strings.iter().any(|s| s.value == "Hello"));
    assert!(strings.iter().any(|s| s.value == "World"));
}

#[test]
fn raw_scan_breaks_on_non_printable() {
    let extractor = RustStringExtractor::new(4);
    // Non-printable byte should break the string
    let data = b"Hello\x01World\0";

    let strings = extractor.extract_raw_strings(data);

    // Should have World (5 chars), Hello was broken
    assert!(strings.iter().any(|s| s.value == "World"));
}

#[test]
fn packed_scan_finds_urls() {
    let extractor = RustStringExtractor::new(4);
    let data = b"https://example.com/path?query=value";

    let strings = extractor.extract_packed_strings(data);

    assert!(strings.iter().any(|s| s.value.contains("example.com")));
}

#[test]
fn packed_scan_finds_paths() {
    let extractor = RustStringExtractor::new(4);
    let data = b"/usr/local/bin/rustc";

    let strings = extractor.extract_packed_strings(data);

    assert!(strings.iter().any(|s| s.value.contains("/usr")));
}

#[test]
fn packed_scan_finds_env_vars() {
    let extractor = RustStringExtractor::new(4);
    let data = b"RUST_BACKTRACE=full HOME_DIR=/home";

    let strings = extractor.extract_packed_strings(data);

    assert!(strings.iter().any(|s| s.value.contains("RUST_BACKTRACE")));
}

#[test]
fn packed_scan_finds_snake_case_identifiers() {
    let extractor = RustStringExtractor::new(4);
    let data = b"my_function_name some_other_var";

    let strings = extractor.extract_packed_strings(data);

    assert!(strings.iter().any(|s| s.value.contains("my_function_name")));
}

#[test]
fn packed_scan_finds_domains() {
    let extractor = RustStringExtractor::new(4);
    let data = b"example.com api.github.com";

    let strings = extractor.extract_packed_strings(data);

    assert!(strings.iter().any(|s| s.value.contains("example.com")));
}

#[test]
fn packed_scan_splits_on_nul() {
    let extractor = RustStringExtractor::new(4);
    let data = b"hello\0world\0test";

    let strings = extractor.extract_packed_strings(data);

    // Should split on nulls
    assert!(strings.iter().any(|s| s.value == "hello"));
    assert!(strings.iter().any(|s| s.value == "world"));
}

#[test]
fn packed_scan_splits_on_newline() {
    let extractor = RustStringExtractor::new(4);
    let data = b"line1\nline2\nline3";

    let strings = extractor.extract_packed_strings(data);
    // Should split on newlines
    let found: Vec<_> = strings
        .iter()
        .map(|s| (s.value.as_str(), s.data_offset))
        .collect();
    assert_eq!(found, [("line1", 0), ("line2", 6), ("line3", 12)]);
}

#[test]
fn add_if_valid_rejects_short() {
    let extractor = RustStringExtractor::new(10);
    let mut strings = Vec::new();
    let mut seen = HashSet::new();

    extractor.add_if_valid("short", 0, &mut strings, &mut seen);

    assert!(strings.is_empty());
}

#[test]
fn add_if_valid_rejects_seen() {
    let extractor = RustStringExtractor::new(4);
    let mut strings = Vec::new();
    let mut seen = HashSet::new();

    seen.insert("hello".to_string());
    extractor.add_if_valid("hello", 0, &mut strings, &mut seen);

    assert!(strings.is_empty());
}

#[test]
fn add_if_valid_rejects_mostly_digits() {
    let extractor = RustStringExtractor::new(4);
    let mut strings = Vec::new();
    let mut seen = HashSet::new();

    // More than 70% digits should be rejected
    extractor.add_if_valid("12345678ab", 0, &mut strings, &mut seen);

    assert!(strings.is_empty());
}

#[test]
fn add_if_valid_rejects_short_hex() {
    let extractor = RustStringExtractor::new(4);
    let mut strings = Vec::new();
    let mut seen = HashSet::new();

    // Short hex patterns should be rejected
    extractor.add_if_valid("deadbeef", 0, &mut strings, &mut seen);

    assert!(strings.is_empty());
}

#[test]
fn add_if_valid_keeps_identifier() {
    let extractor = RustStringExtractor::new(4);
    let mut strings = Vec::new();
    let mut seen = HashSet::new();

    extractor.add_if_valid("hello_world", 0, &mut strings, &mut seen);

    assert_eq!(strings.len(), 1);
    assert_eq!(strings[0].value, "hello_world");
    assert_eq!(strings[0].method, StringMethod::Heuristic);
}

#[test]
fn segment_scan_finds_url_path_env_and_ident() {
    let extractor = RustStringExtractor::new(4);
    let segment = "https://example.com/path /usr/bin/test MY_ENV_VAR=value snake_case_ident";
    let mut strings = Vec::new();
    let mut seen = HashSet::new();

    extractor.extract_patterns_from_segment(segment, 0, &mut strings, &mut seen);
    // Should extract URLs, paths, env vars, and identifiers
    let has = |value: &str, offset: u64, kind: Option<StringKind>| {
        strings
            .iter()
            .any(|s| s.value == value && s.data_offset == offset && s.kind == kind)
    };
    assert!(has("https://example.com/path", 0, Some(StringKind::Url)));
    assert!(has("/usr/bin/test", 25, Some(StringKind::Path)));
    assert!(has("MY_ENV_VAR", 39, Some(StringKind::EnvVar)));
    assert!(has("snake_case_ident", 56, None));
}

#[test]
fn segment_scan_splits_on_case_transition() {
    let extractor = RustStringExtractor::new(4);
    // lowercaseUPPERCASEFOLLOWS - should split on case transition
    let segment = "helloWORLDNOW";
    let mut strings = Vec::new();
    let mut seen = HashSet::new();

    extractor.extract_patterns_from_segment(segment, 0, &mut strings, &mut seen);
    // Should split where lowercase turns to uppercase
    let found: Vec<_> = strings
        .iter()
        .map(|s| (s.value.as_str(), s.data_offset))
        .collect();
    assert_eq!(found, [("hello", 0), ("WORLDNOW", 5)]);
}

#[test]
fn elf_section_missing_is_none() {
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
fn raw_scan_classifies_urls_and_paths() {
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
fn extracts_little_from_empty_elf() {
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
fn bounds_strings_from_sectionless_elf() {
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
fn extracts_little_from_empty_macho() {
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
fn finds_structure_strings_in_rust_elf() {
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
fn longer_min_length_yields_fewer_strings() {
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
fn elf_scan_has_few_duplicates() {
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
fn macho_strings_meet_structure_min_length() {
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
fn bounds_strings_from_garbage_elf() {
    let extractor = RustStringExtractor::new(4);
    let garbage_data = vec![0xAA; 1024];
    if let Ok(elf) = goblin::elf::Elf::parse(&garbage_data) {
        let strings = extractor.extract_elf(&elf, &garbage_data);
        assert!(strings.len() < 500);
    }
}

#[test]
fn huge_min_length_keeps_only_structure_strings() {
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
fn offsets_stay_within_file() {
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
