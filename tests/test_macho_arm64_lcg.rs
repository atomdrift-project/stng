#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Original a4c3 specimen; expected digest from independent native decoding.
use goblin::{
    Object,
    mach::{
        Mach,
        constants::cputype::{CPU_TYPE_ARM64, CPU_TYPE_X86_64},
    },
};
use sha2::{Digest, Sha256};
use stng::{
    ExtractOptions, ExtractedString, StringMethod, extract_macho_lcg_xor,
    extract_strings_with_options,
};
const FILE: &[u8] = include_bytes!("../testdata/macho/arm64_lcg_xor_universal.macho");
const HASH: &str = "57abe0467d4f5dbed3063f0682715ddf3adc7e684f2df89d15fdf89a408020b8";
fn thin(cpu: u32) -> (&'static [u8], u64) {
    let Object::Mach(Mach::Fat(fat)) = Object::parse(FILE).unwrap() else {
        panic!("fat")
    };
    let a = fat
        .arches()
        .unwrap()
        .into_iter()
        .find(|a| a.cputype == cpu)
        .unwrap();
    (
        &FILE[a.offset as usize..(a.offset + a.size) as usize],
        u64::from(a.offset),
    )
}
fn direct(data: &[u8], base: u64, min: usize) -> Vec<ExtractedString> {
    let Object::Mach(Mach::Binary(m)) = Object::parse(data).unwrap() else {
        panic!("thin")
    };
    extract_macho_lcg_xor(&m, data, base, min)
}
fn word(b: &[u8], p: usize) -> u32 {
    u32::from_le_bytes(b[p..p + 4].try_into().unwrap())
}
fn set(b: &mut [u8], p: usize, w: u32) {
    b[p..p + 4].copy_from_slice(&w.to_le_bytes());
}
fn section(b: &[u8], name: &str) -> usize {
    let mut p = 32;
    for _ in 0..word(b, 16) {
        if word(b, p) == 0x19 {
            for i in 0..word(b, p + 64) as usize {
                let s = p + 72 + i * 80;
                if b[s..s + 16].split(|c| *c == 0).next().unwrap() == name.as_bytes() {
                    return s;
                }
            }
        }
        p += word(b, p + 4) as usize;
    }
    panic!("section")
}
fn check(s: &ExtractedString, offset: u64) {
    assert_eq!(hex::encode(Sha256::digest(s.value.as_bytes())), HASH);
    assert_eq!(s.value.len(), 19775);
    assert_eq!(s.data_offset, offset);
    assert_eq!(s.data_len, 19776);
    assert_eq!(s.method, StringMethod::XorDecode);
}
#[test]
fn original_specimen_and_both_architecture_outputs_match_independent_reconstruction() {
    assert_eq!(
        hex::encode(Sha256::digest(FILE)),
        "a4c3c55d1ca3e406fa8db67d6b8ec395ebb2d8ba76f835bae987733d71ee8fb1"
    );
    for (cpu, offset) in [(CPU_TYPE_X86_64, 0x1238), (CPU_TYPE_ARM64, 0x3238)] {
        let s = direct(thin(cpu).0, 0, 4);
        assert_eq!(s.len(), 1);
        check(&s[0], offset);
    }
}
#[test]
fn filtered_universal_pipeline_preserves_each_architectures_provenance() {
    let opts = ExtractOptions {
        use_cache: false,
        caller_provides_symbols: true,
        filter_garbage: true,
        ..Default::default()
    };
    let all = extract_strings_with_options(FILE, &opts);
    for offset in [0x5238, 0x13238] {
        let found: Vec<_> = all
            .iter()
            .filter(|s| s.data_offset == offset && s.method == StringMethod::XorDecode)
            .collect();
        assert_eq!(found.len(), 1);
        check(found[0], offset);
    }
}
#[test]
fn full_arm_loop_and_register_setup_are_required() {
    for p in (0x2e44..0x2ea4).step_by(4) {
        let mut b = thin(CPU_TYPE_ARM64).0.to_vec();
        let w = word(&b, p) ^ 1;
        set(&mut b, p, w);
        assert!(direct(&b, 0, 4).is_empty(), "changed instruction {p:x}");
    }
}
#[test]
fn seed_source_address_length_and_zero_modulus_are_checked() {
    for (p, w) in [
        (0x3234, 0),
        (0x2e54, 0x9100014a),
        (0x2e38, 0x52800014),
        (0x2e3c, 0x52800001),
        (0x2e6c, 0x5280000e),
        (0x2e58, 0x5280200b),
    ] {
        let mut b = thin(CPU_TYPE_ARM64).0.to_vec();
        set(&mut b, p, w);
        assert!(direct(&b, 0, 4).is_empty(), "changed {p:x}");
    }
}
#[test]
fn invalid_preview_and_late_utf8_or_control_bytes_are_rejected() {
    for (offset, old_plain, new_plain) in [(0, b'o', 0), (100, b'e', 0), (100, b'e', 0xff)] {
        let mut b = thin(CPU_TYPE_ARM64).0.to_vec();
        b[0x3238 + offset] ^= old_plain ^ new_plain;
        assert!(direct(&b, 0, 4).is_empty());
    }
}
#[test]
fn source_section_bounds_and_code_prefix_truncation_are_checked() {
    let original = thin(CPU_TYPE_ARM64).0;
    let mut b = original.to_vec();
    let h = section(&b, "__const");
    b[h + 40..h + 48].copy_from_slice(&19779u64.to_le_bytes());
    assert!(direct(&b, 0, 4).is_empty());
    for end in 0x2e70..0x2ea4 {
        let mut b = original.to_vec();
        let h = section(&b, "__text");
        let addr = u64::from_le_bytes(b[h + 32..h + 40].try_into().unwrap()) - 0x100000000;
        b[h + 40..h + 48].copy_from_slice(&(end - addr).to_le_bytes());
        assert!(direct(&b, 0, 4).is_empty(), "prefix {end:x}");
    }
}
#[test]
fn decoded_minimum_length_and_offset_overflow_are_checked() {
    let b = thin(CPU_TYPE_ARM64).0;
    assert!(direct(b, 0, 19776).is_empty());
    check(&direct(b, 0x10000, 19775)[0], 0x13238);
    assert!(direct(b, u64::MAX, 4).is_empty());
}
#[test]
fn unrelated_native_fixture_is_rejected() {
    let b = include_bytes!("../testdata/macho/swift_small_strings_webview.macho");
    assert!(direct(b, 0, 4).is_empty());
}
