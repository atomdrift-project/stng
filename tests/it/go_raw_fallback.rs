#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Tests for Go binary raw scan fallback.
//!
//! Go shared libraries (cgo) often lack .gopclntab and store strings in
//! .noptrdata, .strtab, .symtab etc. The structure-based Go extractor only
//! targets .rodata, so a raw scan fallback is needed to catch the rest.
//! These tests verify:
//! 1. Strings in .noptrdata are found via raw fallback
//! 2. Structure-extracted strings are not duplicated by the raw scan
//! 3. Structure-extracted strings keep their higher-priority method tag

use crate::common::build_elf_with_sections;
use stng::{ExtractOptions, StringMethod, extract_strings_with_options};

/// Build a Go ELF shared library with .rodata containing structure-referenced
/// strings, .go.buildinfo as the Go marker, and .noptrdata containing
/// null-terminated strings only reachable by raw scan.
fn build_go_elf_with_noptrdata(rodata_strings: &[&str], noptrdata_strings: &[&str]) -> Vec<u8> {
    // --- Build .rodata blob ---
    // Pack strings contiguously (no null terminators — Go style)
    let mut rodata_blob = Vec::new();
    let mut rodata_positions: Vec<(usize, usize)> = Vec::new(); // (offset_in_blob, len)
    for s in rodata_strings {
        let start = rodata_blob.len();
        rodata_blob.extend_from_slice(s.as_bytes());
        rodata_positions.push((start, s.len()));
    }
    // Pad to at least 256 bytes so the section looks realistic
    while rodata_blob.len() < 256 {
        rodata_blob.push(0);
    }

    let rodata_file_offset: u64 = 0x1000;
    let rodata_vaddr: u64 = 0x400000;

    // --- Build a data section containing {ptr, len} structures ---
    // Each structure is 16 bytes: 8-byte pointer + 8-byte length
    let mut structs_data = Vec::new();
    for (offset_in_blob, len) in &rodata_positions {
        let ptr = rodata_vaddr + *offset_in_blob as u64;
        structs_data.extend_from_slice(&ptr.to_le_bytes());
        structs_data.extend_from_slice(&(*len as u64).to_le_bytes());
    }
    // Pad
    while structs_data.len() < 256 {
        structs_data.push(0);
    }

    let structs_file_offset: u64 = 0x2000;
    let structs_vaddr: u64 = 0x500000;

    // --- Build .go.buildinfo section (just needs to exist) ---
    let buildinfo_data = vec![0u8; 32];
    let buildinfo_file_offset: u64 = 0x3000;
    let buildinfo_vaddr: u64 = 0x600000;

    // --- Build .noptrdata with null-terminated strings ---
    let mut noptrdata_blob = Vec::new();
    for s in noptrdata_strings {
        noptrdata_blob.extend_from_slice(s.as_bytes());
        noptrdata_blob.push(0); // null-terminated
    }
    while noptrdata_blob.len() < 256 {
        noptrdata_blob.push(0);
    }

    let noptrdata_file_offset: u64 = 0x4000;
    let noptrdata_vaddr: u64 = 0x700000;

    // SHF_ALLOC = 2, SHF_WRITE = 1, SHF_EXECINSTR = 4
    let shf_alloc: u32 = 2;
    let shf_write_alloc: u32 = 3;

    build_elf_with_sections(&[
        (
            ".rodata",
            rodata_file_offset,
            rodata_vaddr,
            &rodata_blob,
            shf_alloc,
        ),
        (
            ".data",
            structs_file_offset,
            structs_vaddr,
            &structs_data,
            shf_write_alloc,
        ),
        (
            ".go.buildinfo",
            buildinfo_file_offset,
            buildinfo_vaddr,
            &buildinfo_data,
            shf_alloc,
        ),
        (
            ".noptrdata",
            noptrdata_file_offset,
            noptrdata_vaddr,
            &noptrdata_blob,
            shf_write_alloc,
        ),
    ])
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Verify the synthetic ELF is detected as Go by goblin + stng.
#[test]
fn test_go_elf_detected_as_go() {
    let elf = build_go_elf_with_noptrdata(&["runtime.main"], &["github.com/shirou/gopsutil/v3"]);
    assert!(
        stng::is_go_binary(&elf),
        "Synthetic Go ELF should be detected as Go (has .go.buildinfo)"
    );
}

/// Core test: strings in .noptrdata must be found via raw scan fallback.
#[test]
fn test_noptrdata_strings_found() {
    let elf = build_go_elf_with_noptrdata(
        &["runtime.main"],
        &[
            "github.com/shirou/gopsutil/v3",
            "github.com/shirou/gopsutil/v3/cpu",
            "/go/pkg/mod/github.com/shirou/gopsutil/v3@v3.21.3/cpu/cpu.go",
        ],
    );

    let opts = ExtractOptions::new(4);
    let strings = extract_strings_with_options(&elf, &opts);
    let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();

    assert!(
        values.iter().any(|v| v.contains("gopsutil")),
        "Should find gopsutil strings from .noptrdata via raw scan fallback. Found: {values:?}"
    );
    assert!(
        values.iter().any(|v| v.contains("gopsutil/v3/cpu")),
        "Should find subpackage path. Found: {values:?}"
    );
}

/// Structure-extracted strings (from .rodata) must still be present.
#[test]
fn test_rodata_structure_strings_still_found() {
    let elf = build_go_elf_with_noptrdata(
        &["runtime.main", "crypto/tls", "net/http"],
        &["github.com/example/extra"],
    );

    let opts = ExtractOptions::new(4);
    let strings = extract_strings_with_options(&elf, &opts);
    let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();

    assert!(
        values.contains(&"runtime.main"),
        "Structure-extracted string 'runtime.main' must be present. Found: {values:?}"
    );
    assert!(
        values.contains(&"crypto/tls"),
        "Structure-extracted string 'crypto/tls' must be present. Found: {values:?}"
    );
    assert!(
        values.contains(&"net/http"),
        "Structure-extracted string 'net/http' must be present. Found: {values:?}"
    );
}

/// No duplicate values: a string found by both structure and raw scan
/// should appear only once, and the structure version (higher priority) wins.
#[test]
fn test_no_duplicate_values() {
    // "runtime.main" is in .rodata (structure-extracted) AND will also appear
    // in the raw scan of the full binary. It must not be duplicated.
    let elf = build_go_elf_with_noptrdata(&["runtime.main"], &["github.com/extra/pkg"]);

    let opts = ExtractOptions::new(4);
    let strings = extract_strings_with_options(&elf, &opts);

    let count = strings.iter().filter(|s| s.value == "runtime.main").count();
    assert_eq!(
        count, 1,
        "String 'runtime.main' should appear exactly once (no duplicates). Found {count} times."
    );
}

/// When a string exists in both .rodata (structure) and raw scan, the
/// structure-extracted version (higher method priority) should be kept.
#[test]
fn test_structure_method_preferred_over_raw() {
    let elf = build_go_elf_with_noptrdata(&["runtime.main"], &["github.com/extra/pkg"]);

    let opts = ExtractOptions::new(4);
    let strings = extract_strings_with_options(&elf, &opts);

    let runtime_main = strings
        .iter()
        .find(|s| s.value == "runtime.main")
        .expect("runtime.main must be found");

    assert_eq!(
        runtime_main.method,
        StringMethod::Structure,
        "runtime.main should keep Structure method (not be downgraded to RawScan)"
    );
}

/// Raw-scan-only strings should be tagged as RawScan.
#[test]
fn test_raw_fallback_strings_tagged_as_raw_scan() {
    let elf = build_go_elf_with_noptrdata(&["runtime.main"], &["github.com/shirou/gopsutil/v3"]);

    let opts = ExtractOptions::new(4);
    let strings = extract_strings_with_options(&elf, &opts);

    if let Some(gopsutil) = strings.iter().find(|s| s.value.contains("gopsutil")) {
        assert_eq!(
            gopsutil.method,
            StringMethod::RawScan,
            "gopsutil string from .noptrdata should be tagged RawScan, got {:?}",
            gopsutil.method
        );
    }
}

/// Both structure and raw strings present together without loss.
#[test]
fn test_combined_extraction_completeness() {
    let rodata = &["runtime.main", "sync.Mutex", "fmt.Println"];
    let noptrdata = &[
        "github.com/shirou/gopsutil/v3",
        "github.com/shirou/gopsutil/v3/cpu",
        "github.com/shirou/gopsutil/v3/net",
    ];

    let elf = build_go_elf_with_noptrdata(rodata, noptrdata);
    let opts = ExtractOptions::new(4);
    let strings = extract_strings_with_options(&elf, &opts);
    let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();

    // All rodata strings should be present
    for expected in rodata {
        assert!(
            values.iter().any(|v| v == expected),
            "Missing rodata string '{expected}'. Found: {values:?}"
        );
    }

    // All noptrdata strings should be present
    for expected in noptrdata {
        assert!(
            values.iter().any(|v| v == expected),
            "Missing noptrdata string '{expected}'. Found: {values:?}"
        );
    }
}

/// Go ELF with no .noptrdata at all should still work (no panic, no regression).
#[test]
fn test_go_elf_without_noptrdata() {
    // Build an ELF with only .rodata and .go.buildinfo (no .noptrdata)
    let mut rodata_blob = Vec::new();
    let s = "runtime.main";
    rodata_blob.extend_from_slice(s.as_bytes());
    while rodata_blob.len() < 256 {
        rodata_blob.push(0);
    }

    let rodata_vaddr: u64 = 0x400000;

    // Build {ptr, len} structure
    let mut structs_data = Vec::new();
    structs_data.extend_from_slice(&rodata_vaddr.to_le_bytes());
    structs_data.extend_from_slice(&(s.len() as u64).to_le_bytes());
    while structs_data.len() < 256 {
        structs_data.push(0);
    }

    let shf_alloc: u32 = 2;
    let shf_write_alloc: u32 = 3;

    let elf = build_elf_with_sections(&[
        (".rodata", 0x1000, rodata_vaddr, &rodata_blob, shf_alloc),
        (".data", 0x2000, 0x500000, &structs_data, shf_write_alloc),
        (".go.buildinfo", 0x3000, 0x600000, &[0u8; 32], shf_alloc),
    ]);

    let opts = ExtractOptions::new(4);
    let strings = extract_strings_with_options(&elf, &opts);
    let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();

    assert!(
        values.contains(&"runtime.main"),
        "runtime.main should still be found without .noptrdata. Found: {values:?}"
    );
}

/// Verify no value appears more than once across all extraction methods.
#[test]
fn test_no_value_duplicates_across_methods() {
    let rodata = &["runtime.main", "sync.Mutex", "fmt.Println"];
    let noptrdata = &[
        "github.com/shirou/gopsutil/v3",
        "github.com/shirou/gopsutil/v3/cpu",
    ];

    let elf = build_go_elf_with_noptrdata(rodata, noptrdata);
    let opts = ExtractOptions::new(4);
    let strings = extract_strings_with_options(&elf, &opts);

    // Check that no value appears more than once
    let mut seen = std::collections::HashSet::new();
    for s in &strings {
        assert!(
            seen.insert(&s.value),
            "Duplicate string value '{}' found (methods: {:?})",
            s.value,
            strings
                .iter()
                .filter(|x| x.value == s.value)
                .map(|x| x.method)
                .collect::<Vec<_>>()
        );
    }
}

/// Regression: Go's compiler packs `.rodata` strings back-to-back without null
/// terminators. The raw printable-run scanner used to emit the entire blob as
/// one merged garbage string (e.g.
/// `"getrandom statessigaction failed0123456789ABCDEFinvalid host: %w..."`).
/// The structure-based extractor already covers `.rodata` with correct
/// boundaries, so the raw scan must skip that section for Go binaries.
#[test]
fn test_rodata_blob_not_emitted_as_merged_string() {
    // Pack adjacent strings without nulls — this is exactly how Go lays out
    // its string blob.
    let parts = [
        "getrandom states",
        "sigaction failed",
        "0123456789ABCDEF",
        "invalid host: %w",
    ];
    let merged: String = parts.concat();

    let elf = build_go_elf_with_noptrdata(&parts, &[]);

    // Sanity: the merged byte sequence is actually present in the file.
    assert!(
        elf.windows(merged.len()).any(|w| w == merged.as_bytes()),
        "test setup: packed rodata should contain the merged byte sequence"
    );

    let opts = ExtractOptions::new(4);
    let strings = extract_strings_with_options(&elf, &opts);
    let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();

    // Each individually-referenced string survives via structure extraction.
    for s in &parts {
        assert!(
            values.contains(s),
            "structure-referenced string {s:?} must still be extracted"
        );
    }

    // The merged form must NOT appear: this is the bug we're guarding against.
    assert!(
        !values.contains(&merged.as_str()),
        "raw scan must not emit the merged rodata blob as a single string"
    );

    // No emitted string should contain a strict superstring of two adjacent
    // parts joined together — that would indicate the raw scanner is still
    // walking past structure boundaries inside the blob.
    let pairs = [
        format!("{}{}", parts[0], parts[1]),
        format!("{}{}", parts[1], parts[2]),
        format!("{}{}", parts[2], parts[3]),
    ];
    for pair in &pairs {
        assert!(
            !values.iter().any(|v| v.contains(pair.as_str())),
            "no extracted string should contain two adjacent rodata strings concatenated ({pair:?})"
        );
    }
}
