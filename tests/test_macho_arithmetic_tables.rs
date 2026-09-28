#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Regression coverage for a reverse-engineered AMOS table decoder.
//! Digests were obtained by independently decoding the three tables identified
//! in the entrypoint disassembly, before adding automatic extraction.

use goblin::{Object, mach::Mach};
use sha2::{Digest, Sha256};
use stng::{
    ExtractOptions, ExtractedString, StringMethod, extract_macho_arithmetic_strings,
    extract_strings_with_options,
};

fn fixture() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/macho/amos_arithmetic_tables_universal.macho"
    ))
    .unwrap()
}

fn thin(data: &[u8]) -> (&[u8], usize) {
    let Object::Mach(Mach::Fat(fat)) = Object::parse(data).unwrap() else {
        panic!("universal fixture")
    };
    let arch = fat
        .arches()
        .unwrap()
        .into_iter()
        .find(|a| a.cputype == goblin::mach::constants::cputype::CPU_TYPE_X86_64)
        .unwrap();
    let start = arch.offset as usize;
    (&data[start..start + arch.size as usize], start)
}

fn direct(data: &[u8], base: u64) -> Vec<ExtractedString> {
    let Object::Mach(Mach::Binary(macho)) = Object::parse(data).unwrap() else {
        panic!("thin Mach-O")
    };
    extract_macho_arithmetic_strings(&macho, base, 4)
}

fn assert_stages(strings: &[ExtractedString]) {
    let expected = [
        "22422ea28dc3168fca0f6633341402f35ad168770ad51960e030a9f94946e080",
        "8b787769d8b5108fdb5dcc7af11f9396e78d7b14a865349c8d5b6c3467dd3423",
        "20a60a29c697e89aeab8cc741327f19f84b599e628d175aab132f1551f1da29c",
    ];
    for digest in expected {
        assert!(
            strings
                .iter()
                .any(|s| s.method == StringMethod::Base64ObfuscatedDecode
                    && hex::encode(Sha256::digest(s.value.as_bytes())) == digest),
            "missing independently decoded stage {digest}"
        );
    }
}

#[test]
fn universal_pipeline_recovers_all_three_stages_without_rizin() {
    let data = fixture();
    let opts = ExtractOptions {
        use_cache: false,
        caller_provides_symbols: true,
        ..Default::default()
    };
    let strings = extract_strings_with_options(&data, &opts);
    assert_stages(&strings);
    // Provenance must be rebased onto the universal file, not its first slice.
    let (slice, base) = thin(&data);
    for s in direct(slice, 0) {
        assert!(strings.iter().any(|fat| fat.value == s.value
            && fat.data_offset == s.data_offset + base as u64
            && fat.data_len == s.data_len));
    }
}

#[test]
fn thin_binary_preserves_decode_and_source_ranges() {
    let data = fixture();
    let (slice, _) = thin(&data);
    let strings = direct(slice, 0);
    assert_eq!(strings.len(), 3);
    assert_stages(&strings);
    for s in strings {
        assert!(s.data_offset + u64::from(s.data_len) <= slice.len() as u64);
    }
}

#[test]
fn changed_arithmetic_instruction_does_not_decode_the_old_tables() {
    let data = fixture();
    let (slice, _) = thin(&data);
    let mut changed = slice.to_vec();
    // First alphabet loop: change SUB eax,[r14+r12] to ADD. Ciphertext and
    // metadata remain identical, but this binary no longer uses our formula.
    assert_eq!(&changed[0xed4..0xed8], &[0x43, 0x2b, 0x04, 0x26]);
    changed[0xed5] = 0x03;
    assert!(direct(&changed, 0).is_empty());
}

#[test]
fn out_of_section_table_reference_is_rejected() {
    let data = fixture();
    let (slice, _) = thin(&data);
    let mut changed = slice.to_vec();
    // Alphabet table's RIP-relative LEA: a valid instruction whose new target
    // is far outside __const must never become a source range.
    assert_eq!(&changed[0xeb4..0xeb7], &[0x4c, 0x8d, 0x3d]);
    changed[0xeb7..0xebb].copy_from_slice(&i32::MAX.to_le_bytes());
    assert!(direct(&changed, 0).is_empty());
}
