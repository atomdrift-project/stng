#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Exact values come from independent ARM table reconstruction in the review.
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
fn arm(data: &[u8]) -> &[u8] {
    &data[819200..819200 + 844232]
}
fn direct(data: &[u8], base: u64, min: usize) -> Vec<ExtractedString> {
    let Object::Mach(Mach::Binary(m)) = Object::parse(data).unwrap() else {
        panic!("thin Mach-O")
    };
    extract_macho_arithmetic_strings(&m, base, min)
}
fn digest(s: &[u8]) -> String {
    hex::encode(Sha256::digest(s))
}
const EXPECTED: [(&str, u64, u32, usize); 3] = [
    (
        "22422ea28dc3168fca0f6633341402f35ad168770ad51960e030a9f94946e080",
        0xbc9b0,
        5720,
        536,
    ),
    (
        "8b787769d8b5108fdb5dcc7af11f9396e78d7b14a865349c8d5b6c3467dd3423",
        0x1a20,
        254528,
        23862,
    ),
    (
        "20a60a29c697e89aeab8cc741327f19f84b599e628d175aab132f1551f1da29c",
        0xbc6e0,
        240,
        22,
    ),
];
fn check(strings: &[ExtractedString], base: u64) {
    for (hash, offset, span, len) in EXPECTED {
        let s = strings
            .iter()
            .find(|s| digest(s.value.as_bytes()) == hash && s.data_offset == offset + base)
            .expect("independently reconstructed stage and exact provenance");
        assert_eq!(s.value.len(), len);
        assert_eq!(s.data_len, span);
        assert_eq!(s.method, StringMethod::Base64ObfuscatedDecode);
    }
}
fn put(data: &mut [u8], offset: usize, w: u32) {
    data[offset..offset + 4].copy_from_slice(&w.to_le_bytes());
}
fn get(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}
fn section(data: &[u8], name: &[u8]) -> usize {
    let mut p = 32;
    for _ in 0..get(data, 16) {
        if get(data, p) == 0x19 {
            for i in 0..get(data, p + 64) as usize {
                let q = p + 72 + i * 80;
                if &data[q..q + name.len()] == name {
                    return q;
                }
            }
        }
        p += get(data, p + 4) as usize;
    }
    panic!("section absent")
}
#[test]
fn original_specimen_and_both_provenance_bases() {
    let data = fixture();
    assert_eq!(
        digest(&data),
        "eb784deb84a4aa892ef26901619688f124b51ec460e60076a7c24aa08da2f98c"
    );
    for base in [0, 819200] {
        let out = direct(arm(&data), base, 4);
        assert_eq!(out.len(), 3);
        check(&out, base);
    }
}
#[test]
fn public_thin_and_universal_pipeline_with_x86_decoder_disabled() {
    let mut data = fixture();
    let opts = ExtractOptions {
        use_cache: false,
        caller_provides_symbols: true,
        ..Default::default()
    };
    check(&extract_strings_with_options(arm(&data), &opts), 0);
    // Remove the complete x86 alphabet loop, leaving ARM as the only source.
    data[4096 + 0xed4] = 0x90;
    check(&extract_strings_with_options(&data, &opts), 819200);
}
#[test]
fn every_setup_and_loop_instruction_is_required() {
    let data = fixture();
    let original = arm(&data);
    for (start, end, remaining) in [
        (0xc98, 0xcf4, 0),
        (0xd24, 0xd80, 2),
        (0xe04, 0xe5c, 2),
        (0xed0, 0xf2c, 2),
    ] {
        for pos in (start..end).step_by(4) {
            let mut changed = original.to_vec();
            put(&mut changed, pos, 0xd503201f); // NOP
            assert_eq!(
                direct(&changed, 0, 4).len(),
                remaining,
                "instruction at {pos:x}"
            );
        }
    }
}
#[test]
fn rejects_mismatched_registers_slots_index_steps_and_loop_edges() {
    let data = fixture();
    let original = arm(&data);
    for (pos, bit) in [
        (0xc9c, 0),
        (0xca0, 5),
        (0xcb4, 5),
        (0xcb8, 16),
        (0xccc, 12),
        (0xcd8, 12),
        (0xce4, 31),
        (0xce8, 10),
        (0xcf0, 5),
        (0xd40, 12),
        (0xd78, 22),
        (0xe20, 12),
        (0xe24, 12),
        (0xe54, 10),
        (0xe58, 5),
    ] {
        let mut changed = original.to_vec();
        put(&mut changed, pos, get(original, pos) ^ (1 << bit));
        assert!(
            direct(&changed, 0, 4).len() < 3,
            "mutated operand at {pos:x}"
        );
    }
}
#[test]
fn rejects_zero_odd_counts_out_of_section_tables_and_bad_hex() {
    let data = fixture();
    let original = arm(&data);
    for (pos, word) in [
        (0xe14, 0x52800015),
        (0xe14, 0x52800035),
        (0xcec, 0xf100067f),
        (0xc9c, 0x90000014),
    ] {
        let mut changed = original.to_vec();
        put(&mut changed, pos, word);
        assert!(direct(&changed, 0, 4).len() < 3);
    }
    let mut changed = original.to_vec();
    changed[0xbc0e0] ^= 0x80;
    assert!(direct(&changed, 0, 4).is_empty());
}
#[test]
fn min_length_overflow_unsupported_cpu_and_section_limits() {
    let data = fixture();
    let original = arm(&data);
    assert_eq!(direct(original, 0, 23).len(), 2);
    assert_eq!(direct(original, 0, 537).len(), 1);
    assert!(direct(original, 0, 23863).is_empty());
    assert!(direct(original, u64::MAX, 4).is_empty());
    let mut changed = original.to_vec();
    put(&mut changed, 4, 12);
    assert!(direct(&changed, 0, 4).is_empty());
    // This specimen has no __cstring: repurpose an existing metadata section.
    let mut changed = original.to_vec();
    let q = section(&changed, b"__gcc_except_tab");
    changed[q..q + 16].fill(0);
    changed[q..q + 9].copy_from_slice(b"__cstring");
    changed[q + 40..q + 48].copy_from_slice(&65u64.to_le_bytes());
    assert!(direct(&changed, 0, 4).is_empty());
    for (name, size) in [
        (b"__text".as_slice(), 32769u64),
        (b"__const".as_slice(), 65535),
    ] {
        let mut changed = original.to_vec();
        let q = section(&changed, name);
        changed[q + 40..q + 48].copy_from_slice(&size.to_le_bytes());
        assert!(direct(&changed, 0, 4).is_empty());
    }
}
#[test]
fn all_loop_prefix_truncations_are_safe_and_incomplete_stages_are_rejected() {
    let data = fixture();
    let original = arm(&data);
    let q = section(original, b"__text");
    let start = 0x6e0;
    for end in 0xc98..0xcf4 {
        let mut changed = original.to_vec();
        changed[q + 40..q + 48].copy_from_slice(&((end - start) as u64).to_le_bytes());
        assert!(direct(&changed, 0, 4).is_empty(), "end {end:x}");
    }
}

#[test]
fn decoded_invalid_utf8_and_control_characters_are_rejected() {
    use base64::Engine;
    let data = fixture();
    let original = arm(&data);
    let alphabet_hex: Vec<u8> = (0..128)
        .map(|i| {
            (original[0xbc0e0 + 4 * i].wrapping_sub(original[0xbc4e0 + 4 * i])
                ^ original[0xbc2e0 + 4 * i])
                .wrapping_sub(original[0xbc2e0 + 4 * i])
        })
        .collect();
    let alphabet = hex::decode(alphabet_hex).unwrap();
    let standard = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for byte in [0, 0xff] {
        let mut value = vec![b'A'; 22];
        value[0] = byte;
        let encoded = base64::engine::general_purpose::STANDARD_NO_PAD.encode(value);
        let custom: Vec<u8> = encoded
            .bytes()
            .map(|c| alphabet[standard.iter().position(|&a| a == c).unwrap()])
            .collect();
        let h = hex::encode(custom);
        assert_eq!(h.len(), 60);
        let mut changed = original.to_vec();
        for (i, c) in h.bytes().enumerate() {
            let mask = original[0xbc7d0 + 4 * i];
            changed[0xbc6e0 + 4 * i] =
                (c.wrapping_add(mask) ^ mask).wrapping_add(original[0xbc8c0 + 4 * i]);
        }
        assert_eq!(direct(&changed, 0, 4).len(), 2);
    }
}

#[test]
fn benign_swift_application_has_no_arithmetic_decodes() {
    let data = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/macho/swift_small_strings_webview.macho"
    ))
    .unwrap();
    assert!(direct(&data, 0, 4).is_empty());
}

#[test]
#[ignore = "manual timing; no hardware-dependent pass threshold"]
fn arithmetic_extractor_timing() {
    let data = fixture();
    let benign = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/macho/swift_small_strings_webview.macho"
    ))
    .unwrap();
    for (label, bytes, runs) in [
        ("eligible ARM", arm(&data), 1000),
        ("benign ARM", benign.as_slice(), 10000),
    ] {
        let Object::Mach(Mach::Binary(m)) = Object::parse(bytes).unwrap() else {
            panic!("thin")
        };
        let start = std::time::Instant::now();
        for _ in 0..runs {
            std::hint::black_box(extract_macho_arithmetic_strings(
                std::hint::black_box(&m),
                0,
                4,
            ));
        }
        println!(
            "{label}: {:.3} microseconds/call over {runs} calls, parsed input",
            start.elapsed().as_secs_f64() * 1e6 / f64::from(runs)
        );
    }
}
