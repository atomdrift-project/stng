#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Go string literals stored as `{ptr, len}` pairs rather than passed to a call.
//!
//! A non-escaping `[]string` of constants is built on the stack: on arm64 each
//! element is `ADRP`+`ADD` (pointer), `MOV` (length), `STP` (store the pair),
//! and no call follows. The arm64 scan only looked behind `BL` call sites, so
//! every such literal went missing from arm64 builds while the amd64 builds of
//! the same source kept them. That is how the sckit implant's credential-file
//! table (`/.git-credentials`, `/.vault-token`, `/id_ed25519`, ...) was
//! invisible in its darwin-arm64, linux-arm64 and windows-arm64 builds.
//!
//! The fixture's `stngFixturePathTable` is that shape; see
//! `testdata/go_pclntab/README.md` for the build.

use std::path::Path;

use stng::{ExtractedString, StringMethod, extract_strings};

const TABLE: [&str; 4] = [
    "/.stng-fixture-table-alpha",
    "/.stng-fixture-table-bravo",
    "/.stng-fixture-table-charlie",
    "/.stng-fixture-table-delta1",
];

fn fixture(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/testdata/go_pclntab")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// Each table entry, recovered as itself — not merely contained in some
/// longer string, which is what a stale length over Go's packed rodata yields.
fn recovered<'a>(name: &str, strings: &'a [ExtractedString]) -> Vec<&'a ExtractedString> {
    TABLE
        .iter()
        .map(|entry| {
            strings
                .iter()
                .find(|s| s.value == *entry && s.method == StringMethod::InstructionPattern)
                .unwrap_or_else(|| panic!("{name}: {entry} not recovered"))
        })
        .collect()
}

#[test]
fn darwin_arm64_recovers_stack_built_string_table() {
    let data = fixture("darwin_arm64");
    let strings = extract_strings(&data, 4);
    for s in recovered("darwin_arm64", &strings) {
        let start = usize::try_from(s.data_offset).unwrap();
        assert_eq!(
            data.get(start..start + s.value.len()),
            Some(s.value.as_bytes()),
            "{} reported at {:#x}, but those bytes differ",
            s.value,
            s.data_offset
        );
    }
}

#[test]
fn linux_arm64_recovers_stack_built_string_table() {
    recovered("linux_arm64", &extract_strings(&fixture("linux_arm64"), 4));
}

#[test]
fn windows_arm64_recovers_stack_built_string_table() {
    recovered(
        "windows_arm64",
        &extract_strings(&fixture("windows_arm64"), 4),
    );
}

/// Every string the Go structure and instruction passes report must sit at
/// the file offset it names. These passes decode pointers, which are virtual
/// addresses; the ELF path once reported them unconverted, placing every Go
/// literal in an ELF build 0x400000 (amd64) or 0x10000 (arm64) away from its
/// bytes — past the end of the file, or on unrelated data.
#[test]
fn go_decoded_strings_report_file_offsets() {
    for name in [
        "darwin_amd64",
        "darwin_arm64",
        "linux_amd64",
        "linux_arm64",
        "windows_amd64",
        "windows_arm64",
    ] {
        let data = fixture(name);
        let decoded: Vec<_> = extract_strings(&data, 4)
            .into_iter()
            .filter(|s| {
                matches!(
                    s.method,
                    StringMethod::Structure | StringMethod::InstructionPattern
                )
            })
            .collect();
        assert!(
            decoded.len() > 100,
            "{name}: only {} decoded strings",
            decoded.len()
        );
        let misplaced: Vec<_> = decoded
            .iter()
            .filter(|s| {
                let start = usize::try_from(s.data_offset).unwrap();
                data.get(start..start + s.value.len()) != Some(s.value.as_bytes())
            })
            .map(|s| format!("{:?}@{:#x}", s.value, s.data_offset))
            .take(5)
            .collect();
        assert!(misplaced.is_empty(), "{name}: misplaced {misplaced:?}");
    }
}

/// The amd64 builds always recovered the table; they are the control that
/// says the fixture really contains it.
#[test]
fn amd64_control_recovers_the_same_table() {
    for name in ["darwin_amd64", "linux_amd64", "windows_amd64"] {
        recovered(name, &extract_strings(&fixture(name), 4));
    }
}
