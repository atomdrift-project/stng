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

use stng::{ExtractOptions, StringMethod, extract_strings_with_options};

/// Build a minimal but valid 64-bit little-endian ELF with custom sections.
///
/// Each entry in `sections` is (name, file_offset, vaddr, data, flags).
/// The builder places section headers at a fixed offset and creates a proper
/// .shstrtab so goblin can resolve section names.
fn build_elf_with_sections(sections: &[(&str, u64, u64, &[u8], u32)]) -> Vec<u8> {
    // Layout:
    //   0x0000 - ELF header (64 bytes)
    //   0x0040 - Program header (56 bytes) — single PT_LOAD covering everything
    //   0x1000..  Section data (placed at specified offsets)
    //   shstrtab_offset - .shstrtab section data
    //   shdr_offset - section headers (null + sections + .shstrtab)
    //
    // We allocate a large enough buffer and fill it in.

    let shstrtab_offset: usize = 0x8000;
    // Build .shstrtab content: "\0" + each section name + "\0" + ".shstrtab\0"
    let mut shstrtab = vec![0u8]; // null entry
    let mut name_offsets: Vec<usize> = Vec::new();
    for (name, _, _, _, _) in sections {
        name_offsets.push(shstrtab.len());
        shstrtab.extend_from_slice(name.as_bytes());
        shstrtab.push(0);
    }
    let shstrtab_name_offset = shstrtab.len();
    shstrtab.extend_from_slice(b".shstrtab\0");

    let shstrtab_size = shstrtab.len();
    let shdr_offset = shstrtab_offset + shstrtab_size;
    // Align to 8 bytes
    let shdr_offset = (shdr_offset + 7) & !7;

    // Section header count: null + user sections + .shstrtab
    let num_sections = 1 + sections.len() + 1;
    let shdr_entry_size: usize = 64; // sizeof(Elf64_Shdr)
    let total_size = shdr_offset + num_sections * shdr_entry_size;

    let mut data = vec![0u8; total_size];

    // --- ELF header (64 bytes) ---
    data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    data[4] = 2; // ELFCLASS64
    data[5] = 1; // ELFDATA2LSB
    data[6] = 1; // EV_CURRENT
    data[7] = 0; // ELFOSABI_NONE
    // e_type = ET_DYN (shared object, like .so)
    data[16..18].copy_from_slice(&3u16.to_le_bytes());
    // e_machine = EM_X86_64
    data[18..20].copy_from_slice(&0x3Eu16.to_le_bytes());
    // e_version
    data[20..24].copy_from_slice(&1u32.to_le_bytes());
    // e_entry = 0
    data[24..32].copy_from_slice(&0u64.to_le_bytes());
    // e_phoff = 0x40 (right after ELF header)
    data[32..40].copy_from_slice(&0x40u64.to_le_bytes());
    // e_shoff
    data[40..48].copy_from_slice(&(shdr_offset as u64).to_le_bytes());
    // e_flags = 0
    data[48..52].copy_from_slice(&0u32.to_le_bytes());
    // e_ehsize = 64
    data[52..54].copy_from_slice(&64u16.to_le_bytes());
    // e_phentsize = 56
    data[54..56].copy_from_slice(&56u16.to_le_bytes());
    // e_phnum = 1
    data[56..58].copy_from_slice(&1u16.to_le_bytes());
    // e_shentsize = 64
    data[58..60].copy_from_slice(&u16::try_from(shdr_entry_size).unwrap().to_le_bytes());
    // e_shnum
    data[60..62].copy_from_slice(&u16::try_from(num_sections).unwrap().to_le_bytes());
    // e_shstrndx = last section index
    data[62..64].copy_from_slice(&u16::try_from(num_sections - 1).unwrap().to_le_bytes());

    // --- Program header (single PT_LOAD at offset 0x40) ---
    let phdr_off = 0x40usize;
    // p_type = PT_LOAD (1)
    data[phdr_off..phdr_off + 4].copy_from_slice(&1u32.to_le_bytes());
    // p_flags = PF_R | PF_X (5)
    data[phdr_off + 4..phdr_off + 8].copy_from_slice(&5u32.to_le_bytes());
    // p_offset = 0
    data[phdr_off + 8..phdr_off + 16].copy_from_slice(&0u64.to_le_bytes());
    // p_vaddr = 0
    data[phdr_off + 16..phdr_off + 24].copy_from_slice(&0u64.to_le_bytes());
    // p_paddr = 0
    data[phdr_off + 24..phdr_off + 32].copy_from_slice(&0u64.to_le_bytes());
    // p_filesz = total_size
    data[phdr_off + 32..phdr_off + 40].copy_from_slice(&(total_size as u64).to_le_bytes());
    // p_memsz = total_size
    data[phdr_off + 40..phdr_off + 48].copy_from_slice(&(total_size as u64).to_le_bytes());
    // p_align = 0x1000
    data[phdr_off + 48..phdr_off + 56].copy_from_slice(&0x1000u64.to_le_bytes());

    // --- Place section data ---
    for (_, file_offset, _, section_data, _) in sections {
        let off = usize::try_from(*file_offset).unwrap();
        let end = off + section_data.len();
        assert!(
            end <= shstrtab_offset,
            "section data at {off:#x} overlaps shstrtab at {shstrtab_offset:#x}"
        );
        data[off..end].copy_from_slice(section_data);
    }

    // Place .shstrtab data
    data[shstrtab_offset..shstrtab_offset + shstrtab_size].copy_from_slice(&shstrtab);

    // --- Section headers ---
    // Entry 0: null (already zeroed)
    // Entries 1..N: user sections
    for (i, (_, file_offset, vaddr, section_data, flags)) in sections.iter().enumerate() {
        let off = shdr_offset + (i + 1) * shdr_entry_size;
        // sh_name
        data[off..off + 4].copy_from_slice(&u32::try_from(name_offsets[i]).unwrap().to_le_bytes());
        // sh_type = SHT_PROGBITS (1)
        data[off + 4..off + 8].copy_from_slice(&1u32.to_le_bytes());
        // sh_flags
        data[off + 8..off + 16].copy_from_slice(&u64::from(*flags).to_le_bytes());
        // sh_addr (virtual address)
        data[off + 16..off + 24].copy_from_slice(&vaddr.to_le_bytes());
        // sh_offset (file offset)
        data[off + 24..off + 32].copy_from_slice(&file_offset.to_le_bytes());
        // sh_size
        data[off + 32..off + 40].copy_from_slice(&(section_data.len() as u64).to_le_bytes());
        // sh_link, sh_info = 0
        // sh_addralign = 1
        data[off + 48..off + 56].copy_from_slice(&1u64.to_le_bytes());
        // sh_entsize = 0
    }

    // .shstrtab section header (last entry)
    {
        let idx = num_sections - 1;
        let off = shdr_offset + idx * shdr_entry_size;
        // sh_name
        data[off..off + 4]
            .copy_from_slice(&u32::try_from(shstrtab_name_offset).unwrap().to_le_bytes());
        // sh_type = SHT_STRTAB (3)
        data[off + 4..off + 8].copy_from_slice(&3u32.to_le_bytes());
        // sh_flags = 0
        // sh_addr = 0
        // sh_offset
        data[off + 24..off + 32].copy_from_slice(&(shstrtab_offset as u64).to_le_bytes());
        // sh_size
        data[off + 32..off + 40].copy_from_slice(&(shstrtab_size as u64).to_le_bytes());
        // sh_addralign = 1
        data[off + 48..off + 56].copy_from_slice(&1u64.to_le_bytes());
    }

    data
}

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

/// Test with the real libnpc.so if available.
#[test]
fn test_real_go_shared_library() {
    let path = "/tmp/libnpc.so";
    if !std::path::Path::new(path).exists() {
        eprintln!("Skipping test_real_go_shared_library: {path} not found");
        return;
    }

    let data = std::fs::read(path).expect("Failed to read libnpc.so");
    assert!(
        stng::is_go_binary(&data),
        "libnpc.so should be detected as Go"
    );

    let opts = ExtractOptions::new(4);
    let strings = extract_strings_with_options(&data, &opts);
    let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();

    assert!(
        values.iter().any(|v| v.contains("gopsutil")),
        "Should find gopsutil strings in libnpc.so. Total strings: {}",
        strings.len()
    );

    // Verify no value appears as both Structure AND RawScan — that would mean
    // the raw scan fallback failed to skip a structure-extracted string.
    let structure_values: std::collections::HashSet<&str> = strings
        .iter()
        .filter(|s| s.method == StringMethod::Structure)
        .map(|s| s.value.as_str())
        .collect();

    let raw_dupes: Vec<&str> = strings
        .iter()
        .filter(|s| s.method == StringMethod::RawScan)
        .filter(|s| structure_values.contains(s.value.as_str()))
        .map(|s| s.value.as_str())
        .collect();

    assert!(
        raw_dupes.is_empty(),
        "Found {} strings duplicated between Structure and RawScan (first 10: {:?})",
        raw_dupes.len(),
        &raw_dupes[..raw_dupes.len().min(10)]
    );
}
