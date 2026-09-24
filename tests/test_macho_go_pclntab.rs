#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Go function names from Mach-O `__gopclntab`.
//!
//! ELF and PE Go binaries have always yielded their `pkg.Function` names from
//! the pclntab. Mach-O did not: the raw scan skips `__gopclntab` and the
//! structure-based Go extractor recovers string literals, not function names,
//! so a macOS build of a Go implant exposed none of the names its Linux build
//! did — and every rule keyed on them missed the macOS build alone. The sckit
//! worm (npm @memtensor/memos-cloud-openclaw-plugin, PyPI MemoryOS) shipped
//! six builds of one implant; the four Linux and Windows ones were convicted
//! on their function names and the two macOS ones were not.
//!
//! The fixtures under `testdata/go_pclntab/` are one small program, built
//! stripped (`-s -w -trimpath`) the way that implant was, for darwin/amd64,
//! darwin/arm64 and linux/amd64. `src/` holds the source and the build line.

use std::path::Path;

use stng::{ExtractedString, StringMethod, extract_strings};

/// The fixture's own functions. Distinctive enough that nothing else in a Go
/// binary could produce them.
const FUNCTIONS: [&str; 3] = [
    "main.stngFixturePublishRecursively",
    "main.stngFixtureReadCredentialFile",
    "main.stngFixturePrepareRemoteTarget",
];

fn fixture(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/testdata/go_pclntab")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// Every copy of `value` stng reported, as pclntab symbols.
fn pclntab_hits<'a>(strings: &'a [ExtractedString], value: &str) -> Vec<&'a ExtractedString> {
    strings
        .iter()
        .filter(|s| s.value == value && s.method == StringMethod::PclntabSymbol)
        .collect()
}

/// A reported string must sit where it says it does. This is what catches a
/// slice-relative offset reported as a file offset in a fat binary: the value
/// is still found, but at bytes belonging to another slice or the fat header.
fn assert_located(data: &[u8], s: &ExtractedString) {
    let start = usize::try_from(s.data_offset).unwrap();
    let got = data.get(start..start + s.value.len());
    assert_eq!(
        got,
        Some(s.value.as_bytes()),
        "{:?} reported at {:#x}, but those bytes differ",
        s.value,
        s.data_offset
    );
}

fn assert_functions_recovered(name: &str, data: &[u8]) {
    let strings = extract_strings(data, 4);
    for function in FUNCTIONS {
        let hits = pclntab_hits(&strings, function);
        assert!(
            !hits.is_empty(),
            "{name}: {function} not recovered from the pclntab"
        );
        for hit in hits {
            assert_located(data, hit);
        }
    }
}

#[test]
fn thin_darwin_amd64_yields_function_names() {
    assert_functions_recovered("darwin_amd64", &fixture("darwin_amd64"));
}

#[test]
fn thin_darwin_arm64_yields_function_names() {
    assert_functions_recovered("darwin_arm64", &fixture("darwin_arm64"));
}

/// The control: the same program as ELF. If this fails too, the fixture or
/// the shared pclntab scanner broke, not the Mach-O path.
#[test]
fn linux_amd64_yields_function_names() {
    assert_functions_recovered("linux_amd64", &fixture("linux_amd64"));
}

/// Build a universal binary from thin slices: a big-endian fat header, then
/// each slice at a 2^14-aligned offset, the first no earlier than
/// `first_offset`. `lipo -create` would place it at 16 KiB; any aligned offset
/// is equally valid, and a larger one is what lets a test tell a rebased
/// offset from an unrebased one (see the fat test).
fn fat_binary(slices: &[(&[u8], u32, u32)], first_offset: usize) -> (Vec<u8>, Vec<usize>) {
    const ALIGN_LOG2: u32 = 14;
    const ALIGN: usize = 1 << ALIGN_LOG2;
    let header_len = 8 + 20 * slices.len();

    let mut offsets = Vec::new();
    let mut next = header_len.max(first_offset).next_multiple_of(ALIGN);
    for (bytes, _, _) in slices {
        offsets.push(next);
        next = (next + bytes.len()).next_multiple_of(ALIGN);
    }

    let mut out = vec![0u8; next];
    out[0..4].copy_from_slice(&0xcafe_babe_u32.to_be_bytes());
    out[4..8].copy_from_slice(&u32::try_from(slices.len()).unwrap().to_be_bytes());
    for (i, ((bytes, cputype, cpusubtype), offset)) in slices.iter().zip(&offsets).enumerate() {
        let entry = 8 + 20 * i;
        out[entry..entry + 4].copy_from_slice(&cputype.to_be_bytes());
        out[entry + 4..entry + 8].copy_from_slice(&cpusubtype.to_be_bytes());
        out[entry + 8..entry + 12].copy_from_slice(&u32::try_from(*offset).unwrap().to_be_bytes());
        out[entry + 12..entry + 16]
            .copy_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
        out[entry + 16..entry + 20].copy_from_slice(&ALIGN_LOG2.to_be_bytes());
        out[*offset..*offset + bytes.len()].copy_from_slice(bytes);
    }
    (out, offsets)
}

const CPU_TYPE_X86_64: u32 = 0x0100_0007;
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
const CPU_SUBTYPE_X86_64_ALL: u32 = 3;
const CPU_SUBTYPE_ARM64_ALL: u32 = 0;

/// File-offset ranges of `__gopclntab` in each slice of a fat binary.
fn fat_pclntab_ranges(fat: &[u8]) -> Vec<std::ops::Range<u64>> {
    use stng::goblin::mach::{Mach, SingleArch};
    let Ok(Mach::Fat(multi)) = Mach::parse(fat) else {
        panic!("not a fat Mach-O");
    };
    let arches = multi.arches().unwrap();
    let mut ranges = Vec::new();
    for (idx, arch) in arches.iter().enumerate() {
        let Ok(SingleArch::MachO(macho)) = multi.get(idx) else {
            continue;
        };
        for seg in &macho.segments {
            for (sec, _) in seg.sections().unwrap() {
                if sec.name().unwrap() == "__gopclntab" {
                    let start = u64::from(arch.offset) + u64::from(sec.offset);
                    ranges.push(start..start + sec.size);
                }
            }
        }
    }
    ranges
}

/// In a universal binary each slice's section offsets are relative to the
/// slice and must be rebased onto the file. The first slice is placed at
/// 2 MiB — past the end of the fixture's pclntab — so a section read at its
/// slice-relative offset cannot overlap the real one: without the rebase the
/// names are simply not found. At lipo's usual 16 KiB the misplaced window
/// still overlaps most of the section, finds the names, and reports offsets
/// that agree with the wrong window, which is why checking offsets alone
/// passed with the rebase deleted.
#[test]
fn fat_darwin_yields_function_names_at_file_offsets() {
    let amd64 = fixture("darwin_amd64");
    let arm64 = fixture("darwin_arm64");
    let (fat, _) = fat_binary(
        &[
            (&amd64, CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL),
            (&arm64, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL),
        ],
        2 << 20,
    );

    assert_functions_recovered("fat", &fat);

    // And each name comes from a slice's pclntab, not some other bytes that
    // happen to spell it.
    let ranges = fat_pclntab_ranges(&fat);
    assert!(!ranges.is_empty(), "the fat fixture has no __gopclntab");
    let strings = extract_strings(&fat, 4);
    for function in FUNCTIONS {
        for hit in pclntab_hits(&strings, function) {
            assert!(
                ranges.iter().any(|r| r.contains(&hit.data_offset)),
                "{function} at {:#x} lies outside every slice's __gopclntab {ranges:x?}",
                hit.data_offset
            );
        }
    }
}

/// Parity with ELF is the property that matters downstream: a rule written
/// against the Linux build of a Go program must see the same function names
/// in its macOS build.
#[test]
fn darwin_function_names_match_linux() {
    let names = |data: &[u8]| -> std::collections::BTreeSet<String> {
        extract_strings(data, 4)
            .into_iter()
            .filter(|s| s.method == StringMethod::PclntabSymbol && s.value.starts_with("main."))
            .map(|s| s.value)
            .collect()
    };
    let linux = names(&fixture("linux_amd64"));
    assert!(!linux.is_empty(), "the ELF control yielded no main.* names");
    for darwin in ["darwin_amd64", "darwin_arm64"] {
        let got = names(&fixture(darwin));
        let missing: Vec<_> = linux.difference(&got).collect();
        assert!(missing.is_empty(), "{darwin} lacks {missing:?}");
    }
}
