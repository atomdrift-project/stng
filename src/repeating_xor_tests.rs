//! Expected literals come from independent native reconstruction of both samples.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use crate::{ExtractOptions, ExtractedString, StringMethod};
use goblin::{
    Object,
    mach::{
        Mach,
        constants::cputype::{CPU_TYPE_ARM64, CPU_TYPE_X86_64},
    },
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
const UNIVERSAL: &[u8] = include_bytes!("../testdata/macho/repeating_xor_uploader_universal.macho");
const GAPI: &[u8] = include_bytes!("../testdata/macho/repeating_xor_gapi_universal.macho");
const X86: &[u8] = include_bytes!("../testdata/macho/x86_repeating_xor_uploader.macho");
const ARM: &[u8] = include_bytes!("../testdata/macho/arm64_repeating_xor_uploader.macho");
fn direct(b: &[u8], base: u64, min: usize) -> Vec<ExtractedString> {
    let Object::Mach(Mach::Binary(m)) = Object::parse(b).unwrap() else {
        panic!("thin")
    };
    if m.header.cputype == CPU_TYPE_ARM64 {
        crate::arm64_repeating_xor::extract_macho(&m, base, min)
    } else {
        crate::x86_repeating_xor::extract_macho(&m, base, min)
    }
}
fn slices(b: &[u8]) -> Vec<(&[u8], u64)> {
    let Object::Mach(Mach::Fat(f)) = Object::parse(b).unwrap() else {
        panic!("fat")
    };
    f.arches()
        .unwrap()
        .into_iter()
        .map(|a| {
            (
                &b[a.offset as usize..(a.offset + a.size) as usize],
                u64::from(a.offset),
            )
        })
        .collect()
}
fn values(out: &[ExtractedString]) -> BTreeSet<String> {
    out.iter().map(|s| s.value.clone()).collect()
}
fn expected(gapi: bool, min: usize) -> BTreeSet<String> {
    let json = if gapi {
        include_str!("../testdata/macho/repeating_xor_gapi_expected.json")
    } else {
        include_str!("../testdata/macho/repeating_xor_expected.json")
    };
    let data: Vec<serde_json::Value> = serde_json::from_str(json).unwrap();
    data.iter()
        .map(|row| {
            let key =
                u32::from_str_radix(row["key"].as_str().unwrap().trim_start_matches("0x"), 16)
                    .unwrap()
                    .to_le_bytes();
            let cipher = hex::decode(row["ciphertext_hex"].as_str().unwrap()).unwrap();
            let decoded: Vec<_> = cipher
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ key[i % 4])
                .collect();
            let text = row["plaintext"].as_str().unwrap();
            assert_eq!(decoded.strip_suffix(&[0]).unwrap(), text.as_bytes());
            text.to_string()
        })
        .filter(|s| s.len() >= min)
        .collect()
}
fn section(b: &[u8], name: &str) -> usize {
    let word = |p| u32::from_le_bytes(b[p..p + 4].try_into().unwrap()) as usize;
    let mut p = 32;
    for _ in 0..word(16) {
        if word(p) == 0x19 {
            for i in 0..word(p + 64) {
                let s = p + 72 + i * 80;
                if b[s..s + 16].split(|c| *c == 0).next().unwrap() == name.as_bytes() {
                    return s;
                }
            }
        }
        p += word(p + 4);
    }
    panic!("section")
}
#[test]
fn specimens_and_all_independently_reconstructed_literals_match() {
    for (file, hash) in [
        (
            UNIVERSAL,
            "4a6250d7dab7d82255cc526f6b857af8f53378c186700dd8682408180b92cb6a",
        ),
        (
            GAPI,
            "d29ae5317de4d11481e1fde1961dd85b56c364cb8467f9771ec97bfdb792e486",
        ),
        (
            X86,
            "09cae9413387356f4a1f138be252b8a2ffe8f61990cc353738776bfaeeee761d",
        ),
        (
            ARM,
            "4a187d1d3dcc1e684a3a9e7bade340d032d6b77a7a232067eb55f85685c971ca",
        ),
    ] {
        assert_eq!(hex::encode(Sha256::digest(file)), hash);
    }
    assert_eq!(slices(UNIVERSAL)[0].0, X86);
    assert_eq!(slices(UNIVERSAL)[1].0, ARM);
    for (file, gapi) in [(UNIVERSAL, false), (GAPI, true)] {
        for (thin, base) in slices(file) {
            for min in [1, 4, 20, 4097] {
                let out = direct(thin, 0, min);
                assert_eq!(values(&out), expected(gapi, min));
                assert_eq!(out.len(), expected(gapi, min).len());
                for s in &out {
                    assert_eq!(s.method, StringMethod::XorDecode);
                    assert!(s.data_len > 0);
                    assert!((s.data_offset + s.data_len as u64) <= thin.len() as u64);
                }
                let rebased = direct(thin, base, min);
                for (a, b) in out.iter().zip(rebased) {
                    assert_eq!(a.value, b.value);
                    assert_eq!(a.data_offset + base, b.data_offset);
                    assert_eq!(a.data_len, b.data_len);
                }
            }
        }
    }
}
#[test]
fn public_fat_pipeline_reaches_second_slice_when_first_helper_is_absent() {
    let mut bytes = UNIVERSAL.to_vec();
    bytes[0x4000 + 0x1270] ^= 1;
    let opts = ExtractOptions {
        use_cache: false,
        caller_provides_symbols: true,
        filter_garbage: true,
        ..Default::default()
    };
    let all = crate::extract_strings_with_options(&bytes, &opts);
    for wanted in direct(ARM, 0xc000, 4) {
        assert!(
            all.iter().any(|s| s.value == wanted.value
                && s.method == wanted.method
                && s.data_offset == wanted.data_offset
                && s.data_len == wanted.data_len),
            "{}",
            wanted.value
        );
    }
}
#[test]
fn every_byte_of_complete_helpers_is_required() {
    for (file, start, len) in [(X86, 0x1270, 69), (ARM, 0x10f8, 68)] {
        for p in start..start + len {
            let mut b = file.to_vec();
            b[p] ^= 1;
            assert!(direct(&b, 0, 1).is_empty(), "helper mutation {p:x}");
        }
    }
}
#[test]
fn complete_helper_without_calls_and_truncated_helpers_do_not_decode() {
    for (file, start, len) in [(X86, 0x1270, 69), (ARM, 0x10f8, 68)] {
        let h = section(file, "__text");
        let off = u32::from_le_bytes(file[h + 48..h + 52].try_into().unwrap()) as usize;
        for end in start..start + len {
            let mut b = file.to_vec();
            b[h + 40..h + 48].copy_from_slice(&((end - off) as u64).to_le_bytes());
            assert!(direct(&b, 0, 1).is_empty(), "end {end:x}");
        }
    }
}
#[test]
fn cpu_section_bounds_and_offset_overflow_gate_decoding() {
    for file in [X86, ARM] {
        assert!(direct(file, u64::MAX, 1).is_empty());
        let mut b = file.to_vec();
        b[4..8].copy_from_slice(&7u32.to_le_bytes());
        assert!(direct(&b, 0, 1).is_empty());
        let mut b = file.to_vec();
        let h = section(&b, "__text");
        b[h..h + 16].fill(0);
        assert!(direct(&b, 0, 1).is_empty());
        let mut b = file.to_vec();
        let off = u32::from_le_bytes(b[h + 48..h + 52].try_into().unwrap()) as usize;
        b.resize(off + 1024 * 1024 + 1, 0);
        b[h + 40..h + 48].copy_from_slice(&(1024 * 1024 + 1u64).to_le_bytes());
        assert!(direct(&b, 0, 1).is_empty());
    }
}
#[test]
fn mismatched_architectures_and_unrelated_native_code_are_rejected() {
    for file in [
        X86,
        ARM,
        include_bytes!("../testdata/macho/swift_small_strings_webview.macho").as_slice(),
    ] {
        let Object::Mach(Mach::Binary(m)) = Object::parse(file).unwrap() else {
            panic!("thin")
        };
        if m.header.cputype != CPU_TYPE_ARM64 {
            assert!(crate::arm64_repeating_xor::extract_macho(&m, 0, 1).is_empty());
        }
        if m.header.cputype != CPU_TYPE_X86_64 {
            assert!(crate::x86_repeating_xor::extract_macho(&m, 0, 1).is_empty());
        }
        if file.len() != X86.len() && file.len() != ARM.len() {
            assert!(direct(file, 0, 1).is_empty());
        }
    }
}

fn with_code(file: &[u8], code: &[u8]) -> Vec<u8> {
    let mut b = file.to_vec();
    let h = section(&b, "__text");
    let offset = u32::from_le_bytes(b[h + 48..h + 52].try_into().unwrap()) as usize;
    b.resize(b.len().max(offset + code.len()), 0);
    b[h + 40..h + 48].copy_from_slice(&(code.len() as u64).to_le_bytes());
    b[offset..offset + code.len()].copy_from_slice(code);
    b
}
// Native instruction encodings construct a five-byte ciphertext and a four-byte
// key in disjoint stack slots. Each call reconstructs its inputs from scratch.
fn synthetic(
    arm: bool,
    len: u32,
    key_len: u32,
    overlap: bool,
    barrier: bool,
    count: usize,
) -> Vec<u8> {
    let file = if arm { ARM } else { X86 };
    let helper = if arm {
        &ARM[0x10f8..0x113c]
    } else {
        &X86[0x1270..0x12b5]
    };
    let mut code = Vec::new();
    let mut calls = Vec::new();
    for _ in 0..count {
        if arm {
            let mov = |r: u32, imm: u32, shift: u32, keep: bool| -> u32 {
                (if keep { 0xf2800000u32 } else { 0xd2800000u32 })
                    | (shift / 16) << 21
                    | imm << 5
                    | r
            };
            let words = [
                mov(8, 0x6775, 0, false),
                mov(8, 0x7070, 16, true),
                mov(8, 1, 32, true), // test\0 XOR 01020304 LE
                0xf9000be8,          // STR x8,[sp,#16]
                mov(8, 0x0201, 0, false),
                mov(8, 0x0403, 16, true),
                0xb90023e8, // STR w8,[sp,#32]
                0x910043e0, // ADD x0,sp,#16
                if overlap { 0x910043e1 } else { 0x910083e1 },
                mov(2, len, 0, false),
                mov(3, key_len, 0, false),
            ];
            for w in words {
                code.extend_from_slice(&w.to_le_bytes());
            }
            if barrier {
                code.extend_from_slice(&0xd503201fu32.to_le_bytes());
            }
            calls.push(code.len());
            code.extend_from_slice(&[0; 4]);
        } else {
            code.extend_from_slice(&[0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x40]);
            code.extend_from_slice(&[0x48, 0xb8]);
            code.extend_from_slice(&0x0000000170706775u64.to_le_bytes());
            code.extend_from_slice(&[0x48, 0x89, 0x45, 0xf0, 0xc7, 0x45, 0xe8]);
            code.extend_from_slice(&0x04030201u32.to_le_bytes());
            code.extend_from_slice(&[
                0x48,
                0x8d,
                0x7d,
                0xf0,
                0x48,
                0x8d,
                0x75,
                if overlap { 0xf0 } else { 0xe8 },
                0xba,
            ]);
            code.extend_from_slice(&len.to_le_bytes());
            code.push(0xb9);
            code.extend_from_slice(&key_len.to_le_bytes());
            if barrier {
                code.extend_from_slice(&[0x0f, 0x0b]);
            } // UD2 invalidates tracked state.
            calls.push(code.len());
            code.extend_from_slice(&[0xe8, 0, 0, 0, 0]);
        }
    }
    let target = code.len();
    code.extend_from_slice(helper);
    for p in calls {
        if arm {
            let w = 0x94000000 | ((target - p) / 4) as u32;
            code[p..p + 4].copy_from_slice(&w.to_le_bytes());
        } else {
            let rel = (target - p - 5) as i32;
            code[p + 1..p + 5].copy_from_slice(&rel.to_le_bytes());
        }
    }
    with_code(file, &code)
}
#[test]
fn synthetic_calls_require_known_disjoint_buffers_and_valid_lengths() {
    for arm in [false, true] {
        assert_eq!(
            values(&direct(&synthetic(arm, 5, 4, false, false, 1), 0, 1)),
            BTreeSet::from(["test".to_string()])
        );
        for (len, key_len, overlap, barrier) in [
            (0, 4, false, false),
            (4097, 4, false, false),
            (5, 0, false, false),
            (5, 33, false, false),
            (5, 4, true, false),
            (5, 4, false, true),
            (9, 4, false, false),
        ] {
            assert!(
                direct(&synthetic(arm, len, key_len, overlap, barrier, 1), 0, 1).is_empty(),
                "arm={arm} len={len} key={key_len} overlap={overlap} barrier={barrier}"
            );
        }
    }
}
#[test]
fn helper_alone_and_call_count_limit() {
    for arm in [false, true] {
        assert!(direct(&synthetic(arm, 5, 4, false, false, 0), 0, 1).is_empty());
        assert_eq!(
            direct(&synthetic(arm, 5, 4, false, false, 513), 0, 1).len(),
            512
        );
    }
}
