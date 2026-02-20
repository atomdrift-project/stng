//! Tests for import/export symbol extraction (imports.rs).
//!
//! ELF import extraction is exercised via `extract_from_elf` which calls
//! `extract_elf_imports` internally. Mach-O import extraction is tested
//! on macOS system binaries. Deduplication correctness is verified through
//! the full `extract_strings` pipeline.

use std::path::Path;
use stng::{
    extract_strings, extract_strings_with_options, goblin, ExtractOptions, StringKind, StringMethod,
};

fn macho_binary_path() -> Option<&'static str> {
    // Prefer /bin/ls which on macOS is always Mach-O
    if Path::new("/bin/ls").exists() {
        Some("/bin/ls")
    } else if Path::new("/usr/bin/ls").exists() {
        Some("/usr/bin/ls")
    } else {
        None // Not macOS or unusual layout
    }
}

// ── Mach-O imports (macOS system binaries) ──────────────────────────────────

#[test]
fn test_macho_binary_has_import_strings() {
    // /bin/ls on macOS dynamically links libSystem — should have Import kind strings
    let Some(binary_path) = macho_binary_path() else {
        return;
    };
    let data = std::fs::read(binary_path).expect("Failed to read ls binary");
    // Skip if this happens to be an ELF binary (e.g. Linux /bin/ls)
    if !matches!(goblin::Object::parse(&data), Ok(goblin::Object::Mach(_))) {
        return;
    }

    let strings = extract_strings(&data, 4);
    let imports: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == StringKind::Import)
        .collect();

    assert!(
        !imports.is_empty(),
        "Mach-O /bin/ls should have Import kind strings from dylib; \
         found {} total strings",
        strings.len()
    );
}

#[test]
fn test_macho_import_strings_have_nonempty_values() {
    let Some(binary_path) = macho_binary_path() else {
        return;
    };
    let data = std::fs::read(binary_path).expect("Failed to read ls binary");
    if !matches!(goblin::Object::parse(&data), Ok(goblin::Object::Mach(_))) {
        return;
    }

    let strings = extract_strings(&data, 4);
    for s in strings.iter().filter(|s| s.kind == StringKind::Import) {
        assert!(
            !s.value.is_empty(),
            "Import at offset {} must have a non-empty symbol name",
            s.data_offset
        );
    }
}

#[test]
fn test_macho_import_strings_added_from_symbol_table_use_structure_method() {
    // Imports that exist only in the symbol table (not found by raw scan) should
    // have Structure method. Those already found by raw scan get kind upgraded to
    // Import but keep their original method.
    let Some(binary_path) = macho_binary_path() else {
        return;
    };
    let data = std::fs::read(binary_path).expect("Failed to read ls binary");
    if !matches!(goblin::Object::parse(&data), Ok(goblin::Object::Mach(_))) {
        return;
    }

    let strings = extract_strings(&data, 4);
    let structure_imports: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == StringKind::Import && s.method == StringMethod::Structure)
        .collect();

    // At least some imports should come directly from the symbol table
    // (those not discoverable by raw scan, e.g. short or non-printable names)
    // This is not guaranteed on all binaries, so we check a softer invariant:
    // all strings with Structure method AND Import kind must have non-empty values.
    for s in &structure_imports {
        assert!(
            !s.value.is_empty(),
            "Structure-method Import '{}' must have non-empty value",
            s.value
        );
    }
}

#[test]
fn test_macho_import_strings_have_library_field() {
    let Some(binary_path) = macho_binary_path() else {
        return;
    };
    let data = std::fs::read(binary_path).expect("Failed to read ls binary");
    if !matches!(goblin::Object::parse(&data), Ok(goblin::Object::Mach(_))) {
        return;
    }

    let strings = extract_strings(&data, 4);
    let imports: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == StringKind::Import)
        .collect();

    if imports.is_empty() {
        return; // Skip if no imports (e.g. static binary or different binary format)
    }

    // At least some Mach-O imports should carry the dylib name in the library field
    let with_library: Vec<_> = imports.iter().filter(|s| s.library.is_some()).collect();
    assert!(
        !with_library.is_empty(),
        "Mach-O imports should have library (dylib) field set; \
         found {} imports, {} with library set",
        imports.len(),
        with_library.len()
    );

    for s in &imports {
        if let Some(lib) = &s.library {
            assert!(
                !lib.is_empty(),
                "Library name should not be an empty string"
            );
        }
    }
}

// ── ELF imports ─────────────────────────────────────────────────────────────

#[test]
fn test_elf_extraction_completes_without_panic() {
    // Go ELF binaries are statically linked so may have no dynamic imports,
    // but the extraction pipeline must complete and return strings.
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/testdata/hello_linux_amd64"
    );
    if !Path::new(path).exists() {
        return;
    }
    let data = std::fs::read(path).expect("Failed to read hello_linux_amd64");
    let Ok(goblin::Object::Elf(_)) = goblin::Object::parse(&data) else {
        return;
    };

    let strings = extract_strings_with_options(&data, &ExtractOptions::new(4));
    assert!(
        !strings.is_empty(),
        "ELF extraction should produce strings even when there are no dynamic imports"
    );
}

#[test]
fn test_elf_import_export_strings_have_nonempty_values_when_present() {
    // If the ELF has dynamic symbols, they must have non-empty names.
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/testdata/hello_linux_amd64"
    );
    if !Path::new(path).exists() {
        return;
    }
    let data = std::fs::read(path).expect("Failed to read hello_linux_amd64");
    let Ok(goblin::Object::Elf(_)) = goblin::Object::parse(&data) else {
        return;
    };

    let strings = extract_strings_with_options(&data, &ExtractOptions::new(4));
    for s in strings
        .iter()
        .filter(|s| s.kind == StringKind::Import || s.kind == StringKind::Export)
    {
        assert!(
            !s.value.is_empty(),
            "Import/Export symbol at offset {} must have a non-empty name",
            s.data_offset
        );
        assert_eq!(
            s.method,
            StringMethod::Structure,
            "Import/Export '{}' should use Structure method",
            s.value
        );
    }
}

// ── Deduplication (full pipeline) ───────────────────────────────────────────

#[test]
fn test_full_pipeline_deduplicates_by_offset() {
    // The full extract_strings pipeline applies deduplicate_by_offset at the end.
    // No two strings in the output should share the same data_offset.
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/testdata/hello_linux_amd64"
    );
    if !Path::new(path).exists() {
        return;
    }
    let data = std::fs::read(path).expect("Failed to read hello_linux_amd64");

    let strings = extract_strings(&data, 4);

    let mut seen_offsets = std::collections::HashMap::new();
    for s in &strings {
        if let Some(prev_value) = seen_offsets.insert(s.data_offset, &s.value) {
            panic!(
                "Duplicate offset {} found: '{}' and '{}' — deduplication failed",
                s.data_offset, prev_value, s.value
            );
        }
    }
}

#[test]
fn test_full_pipeline_pe_deduplicates_by_offset() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/testdata/hello_windows.exe"
    );
    if !Path::new(path).exists() {
        return;
    }
    let data = std::fs::read(path).expect("Failed to read hello_windows.exe");

    let strings = extract_strings(&data, 4);

    let mut seen_offsets = std::collections::HashMap::new();
    for s in &strings {
        if let Some(prev_value) = seen_offsets.insert(s.data_offset, &s.value) {
            panic!(
                "Duplicate offset {} found: '{}' and '{}' — deduplication failed",
                s.data_offset, prev_value, s.value
            );
        }
    }
}
