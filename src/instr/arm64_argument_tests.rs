#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use goblin::{Object, mach::Mach};
const SAMPLE: &[u8] =
    include_bytes!("../../testdata/macho/rust_heap_xor_installer_universal.macho");
fn arm() -> (&'static [u8], u64) {
    let Object::Mach(Mach::Fat(fat)) = Object::parse(SAMPLE).unwrap() else {
        panic!("fat")
    };
    let arch = fat
        .iter_arches()
        .map(Result::unwrap)
        .find(|a| a.cputype == goblin::mach::constants::cputype::CPU_TYPE_ARM64)
        .unwrap();
    (
        &SAMPLE[arch.offset as usize..(arch.offset + arch.size) as usize],
        arch.offset.into(),
    )
}
fn extract(words: &[u32]) -> Vec<ExtractedString> {
    let bytes: Vec<_> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    extract_inline_strings_arm64(&bytes, 0x1000, b"helloworld", 0x2000, 4)
}
fn final_call(words: &[u32]) -> Vec<ExtractedString> {
    let bytes: Vec<_> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    extract_arm64_inline_string(
        bytes.len() - 4,
        &bytes,
        0x1000,
        b"helloworld",
        0x2000,
        0x200a,
        4,
        &mut out,
        &mut seen,
    );
    out
}
#[test]
fn word_lengths_and_stack_result_arguments() {
    for length in [0x528000a3, 0xd28000a3] {
        assert_eq!(
            extract(&[0xb0000002, 0x91000042, length, 0x94000000])[0].value,
            "hello"
        );
        assert_eq!(
            extract(&[0xb0000002, 0x91000042, 0x9101c3e0, length, 0x94000000])[0].value,
            "hello"
        );
        assert_eq!(
            extract(&[0xb0000002, 0x91000042, length, 0x52800001, 0x94000000])[0].value,
            "hello"
        );
    }
}
#[test]
fn constant_length_decoder_checks_width_and_source() {
    assert_eq!(decode_arm_mov_immediate(0x528000a3), Some(5));
    assert_eq!(decode_arm_mov_immediate(0x52a00023), Some(1 << 16));
    assert_eq!(decode_arm_mov_immediate(0xd2e00023), Some(1 << 48));
    assert_eq!(decode_arm_mov_immediate(0x320003e3), Some(1));
    for w in [
        0x52c00023, 0x52e00023, 0x728000a3, 0xf28000a3, 0x32000003, 0xb2000003,
    ] {
        assert_eq!(decode_arm_mov_immediate(w), None, "{w:x}");
    }
}
#[test]
fn branches_clobbers_unknown_gaps_and_bad_add_modes_reject() {
    for gap in [
        0x94000000, 0x14000000, 0x54000040, 0xd2800022, 0x52800203, 0xf94003e0,
    ] {
        assert!(
            final_call(&[0xb0000002, 0x91000042, 0x528000a3, gap, 0x94000000]).is_empty(),
            "{gap:x}"
        );
    }
    for gap in [0x9101c3e2, 0xd503201f, 0xf94003e0] {
        assert!(extract(&[0xb0000002, 0x91000042, gap, 0x528000a3, 0x94000000]).is_empty());
    }
    assert!(extract(&[0xb0000002, 0x91400042, 0x528000a3, 0x94000000]).is_empty());
    assert!(extract(&[0xb0000002, 0x91000042, 0x528000a2, 0x94000000]).is_empty());
}
#[test]
fn original_arm_sql_boundaries_and_public_pipeline() {
    let (bytes, base) = arm();
    let Object::Mach(Mach::Binary(m)) = Object::parse(bytes).unwrap() else {
        panic!("arm")
    };
    let plain = crate::rust::RustStringExtractor::new(4).extract_macho(&m, 0);
    let fat = crate::rust::RustStringExtractor::new(4).extract_macho(&m, base);
    let options = crate::ExtractOptions {
        use_cache: false,
        caller_provides_symbols: true,
        filter_garbage: true,
        ..Default::default()
    };
    let public = crate::extract_strings_with_options(bytes, &options);
    for (at, len, value) in [
        (
            0x2aaaf6,
            62,
            "SELECT origin_url, username_value, password_value FROM logins;",
        ),
        (
            0x2aac6a,
            96,
            "SELECT name_on_card, card_number_encrypted, expiration_month, expiration_year FROM credit_cards;",
        ),
    ] {
        assert_eq!(&bytes[at..at + len], value.as_bytes());
        for (out, offset) in [
            (&plain, at as u64),
            (&fat, base + at as u64),
            (&public, at as u64),
        ] {
            let found = out
                .iter()
                .find(|s| s.value == value && s.method == StringMethod::InstructionPattern)
                .unwrap_or_else(|| panic!("{value}"));
            assert_eq!(
                found.source_spans().collect::<Vec<_>>(),
                [(offset, len as u64)]
            );
        }
    }
}
#[test]
fn word_length_stored_as_a_full_string_header() {
    let out = extract(&[0xb0000002, 0x91000042, 0x528000a3, 0xa9000fe2]);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].value, "hello");
    assert!(extract(&[0xb0000002, 0x91000042, 0x52c000a3, 0xa9000fe2]).is_empty());
}
#[test]
fn truncation_and_out_of_range_lengths_reject() {
    let words = [
        0xb0000002u32,
        0x91000042,
        0x9101c3e0,
        0x528000a3,
        0x94000000,
    ];
    let bytes: Vec<_> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    for len in 0..bytes.len() {
        assert!(
            extract_inline_strings_arm64(&bytes[..len], 0x1000, b"helloworld", 0x2000, 4)
                .is_empty()
        );
    }
    for length in [0x52800003, 0x52800163, 0x52a00023] {
        assert!(extract(&[0xb0000002, 0x91000042, length, 0x94000000]).is_empty());
    }
}
