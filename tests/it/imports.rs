//! Tests for import/export symbol extraction (imports.rs).
//!
//! ELF import extraction is exercised via `extract_from_elf` which calls
//! `extract_elf_imports` internally. Mach-O import extraction is tested
//! on a universal fixture. Deduplication correctness is verified through
//! the full `extract_strings` pipeline.

use std::collections::BTreeSet;
use stng::{
    ExtractOptions, StringKind, StringMethod, extract_strings, extract_strings_with_options, goblin,
};

/// A universal C program that links libSystem dynamically.
fn macho_binary_path() -> &'static str {
    crate::common::path("testdata/macho/charge0x_installer_universal.macho")
}

// ── Mach-O imports ──────────────────────────────────────────────────────────

#[test]
fn finds_macho_libsystem_imports() {
    let data = std::fs::read(macho_binary_path()).expect("read Mach-O fixture");

    let strings = extract_strings(&data, 4);
    for name in ["_system", "_strlen", "_memcpy", "dyld_stub_binder"] {
        assert!(
            strings
                .iter()
                .any(|s| s.value == name && s.kind == Some(StringKind::Import)),
            "{name} should be an Import; found {} total strings",
            strings.len()
        );
    }
}

#[test]
fn tags_exactly_the_undefined_symbols_as_imports() {
    let data = std::fs::read(macho_binary_path()).expect("read Mach-O fixture");

    let strings = extract_strings(&data, 4);
    let imports: BTreeSet<&str> = strings
        .iter()
        .filter(|s| s.kind == Some(StringKind::Import))
        .map(|s| s.value.as_str())
        .collect();

    // `nm -u` of both slices: only arm64 imports `___chkstk_darwin` and
    // `_bzero`, only x86_64 imports `_memset`.
    let undefined = BTreeSet::from([
        "__Unwind_Resume",
        "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6__initEPKcm",
        "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED1Ev",
        "___chkstk_darwin",
        "___gxx_personality_v0",
        "___stack_chk_fail",
        "___stack_chk_guard",
        "_bzero",
        "_memcpy",
        "_memset",
        "_strlen",
        "_system",
        "dyld_stub_binder",
    ]);
    assert_eq!(imports, undefined);
}

#[test]
fn keeps_raw_scan_hit_when_retagging_import() {
    // An import the raw scan already found in the string table gets its kind
    // upgraded to Import but keeps its method and its offset.
    let data = std::fs::read(macho_binary_path()).expect("read Mach-O fixture");

    let strings = extract_strings(&data, 4);
    let system = strings
        .iter()
        .find(|s| s.value == "_system")
        .expect("_system is found");
    assert_eq!(system.kind, Some(StringKind::Import), "{system:?}");
    assert_eq!(system.method, StringMethod::RawScan, "{system:?}");
    let at = usize::try_from(system.data_offset).unwrap();
    assert_eq!(&data[at..at + 8], b"_system\0", "{system:?}");
}

#[test]
fn tags_defined_externals_as_exports() {
    let data = std::fs::read(macho_binary_path()).expect("read Mach-O fixture");

    let strings = extract_strings(&data, 4);
    let exports: BTreeSet<&str> = strings
        .iter()
        .filter(|s| s.kind == Some(StringKind::Export))
        .map(|s| s.value.as_str())
        .collect();

    // `nm -gU`, the same in both slices.
    assert_eq!(
        exports,
        BTreeSet::from([
            "__Z5cryptILm37077EEDaRAT__Kcj",
            "__ZN4mlcg4prngEj",
            "__mh_execute_header",
        ])
    );
}

// ── ELF imports ─────────────────────────────────────────────────────────────

#[test]
fn finds_literals_but_no_imports_in_static_go_elf() {
    // A statically linked Go binary has no dynamic imports, but the pipeline
    // still finds its literals.
    let path = crate::common::path("testdata/elf/hello_linux_amd64");
    let data = std::fs::read(path).expect("Failed to read hello_linux_amd64");
    let Ok(goblin::Object::Elf(_)) = goblin::Object::parse(&data) else {
        return;
    };

    let strings = extract_strings_with_options(&data, &ExtractOptions::new(4));
    let imports: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == Some(StringKind::Import))
        .collect();
    assert!(imports.is_empty(), "{imports:?}");
    let hello = strings
        .iter()
        .find(|s| s.value == "Hello, World!")
        .expect("the program's literal is found");
    let at = usize::try_from(hello.data_offset).unwrap();
    assert_eq!(&data[at..at + 13], b"Hello, World!", "{hello:?}");
}

#[test]
fn locates_elf_dynamic_imports_at_their_names() {
    // A dynamically linked Rust ELF. Its dynamic-symbol names are raw-scan
    // hits in .dynstr that merge_imports retags as imports, keeping the
    // offset of the name itself.
    let path = crate::common::path("testdata/rust_elf/linux_amd64");
    let data = std::fs::read(path).expect("Failed to read rust_elf/linux_amd64");

    let strings = extract_strings_with_options(&data, &ExtractOptions::new(4));
    let imports: BTreeSet<&str> = strings
        .iter()
        .filter(|s| s.kind == Some(StringKind::Import))
        .map(|s| s.value.as_str())
        .collect();
    for name in [
        "__libc_start_main",
        "malloc",
        "pthread_self",
        "_Unwind_Resume",
    ] {
        assert!(
            imports.contains(name),
            "{name} should be an Import: {imports:?}"
        );
    }
    for s in strings
        .iter()
        .filter(|s| s.kind == Some(StringKind::Import) || s.kind == Some(StringKind::Export))
    {
        let at = usize::try_from(s.data_offset).unwrap();
        assert_eq!(
            data.get(at..at + s.value.len()),
            Some(s.value.as_bytes()),
            "{s:?} is not at its name"
        );
    }
}

// ── Deduplication (full pipeline) ───────────────────────────────────────────

#[test]
fn emits_one_elf_string_per_offset() {
    // The full extract_strings pipeline applies deduplicate_by_offset at the end.
    // No two strings in the output should share the same data_offset.
    let path = crate::common::path("testdata/elf/hello_linux_amd64");
    let data = std::fs::read(path).expect("Failed to read hello_linux_amd64");

    let strings = extract_strings(&data, 4);

    let mut seen_offsets = std::collections::HashMap::new();
    for s in &strings {
        assert!(
            seen_offsets.insert(s.data_offset, &s.value).is_none(),
            "Duplicate offset {} found for '{}' — deduplication failed",
            s.data_offset,
            s.value
        );
    }
}

#[test]
fn emits_one_pe_string_per_offset() {
    let path = crate::common::path("testdata/pe/hello_windows.exe");
    let data = std::fs::read(path).expect("Failed to read hello_windows.exe");

    let strings = extract_strings(&data, 4);

    let mut seen_offsets = std::collections::HashMap::new();
    for s in &strings {
        assert!(
            seen_offsets.insert(s.data_offset, &s.value).is_none(),
            "Duplicate offset {} found for '{}' — deduplication failed",
            s.data_offset,
            s.value
        );
    }
}
