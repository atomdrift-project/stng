#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]
use super::*;
use goblin::{Object, mach::Mach};
use sha2::{Digest, Sha256};
static FILE: std::sync::LazyLock<&[u8]> = std::sync::LazyLock::new(|| {
    crate::test_fixture("testdata/macho/rust_heap_xor_installer_universal.macho")
});
const HASH: &str = "23627563d528164b23449ca26ef9a8202bafd87d2d64454165107b76a0a2987f";
fn thin() -> &'static [u8] {
    &FILE[8192..8192 + 4143304]
}
fn macho(b: &[u8]) -> MachO<'_> {
    let Object::Mach(Mach::Binary(m)) = Object::parse(b).unwrap() else {
        panic!("thin")
    };
    m
}
fn code() -> (u64, &'static [u8], usize) {
    let m = macho(thin());
    for seg in &m.segments {
        for (s, b) in seg.sections().unwrap() {
            if s.name().ok() == Some("__text") {
                return (s.addr, b, (0x10003bb50 - s.addr) as usize);
            }
        }
    }
    panic!("code")
}
fn check(value: &str) {
    assert_eq!(value.len(), 302);
    assert_eq!(hex::encode(Sha256::digest(value.as_bytes())), HASH);
}
#[test]
fn original_specimen_prompt_and_provenance_match_independent_reconstruction() {
    assert_eq!(
        hex::encode(Sha256::digest(*FILE)),
        "78371a85a51dee581823243272525e119ce88255e2ad75bc5980870681999970"
    );
    let (addr, bytes, start) = code();
    let (text, span) = decode_pair(bytes, addr, start, 4).unwrap();
    check(&text);
    assert_eq!(span, 1300);
    for base in [0, 8192] {
        let out = extract_macho(&macho(thin()), base, 4);
        assert_eq!(out.len(), 1);
        check(&out[0].value);
        assert_eq!(out[0].data_offset, 0x3bb50 + base);
        assert_eq!(out[0].data_len, 1300);
        assert_eq!(out[0].method, StringMethod::XorDecode);
    }
    assert!(extract_macho(&macho(thin()), u64::MAX, 4).is_empty());
    assert!(decode_pair(bytes, addr, start, 303).is_none());
    assert!(decode_pair(bytes, u64::MAX, start, 4).is_none());
}
#[test]
fn all_loop_instructions_and_checked_index_helper_are_required() {
    let (addr, bytes, start) = code();
    for (from, count) in [(0x10003c022u64, 18usize), (0x100060ea0, 5)] {
        let offset = (from - addr) as usize;
        let mut d = Decoder::with_ip(64, &bytes[offset..], from, DecoderOptions::NONE);
        for _ in 0..count {
            let i = d.decode();
            let p = (i.ip() - addr) as usize;
            let mut b = bytes.to_vec();
            b[p] = 0xcc;
            assert!(
                decode_pair(&b, addr, start, 4).is_none(),
                "instruction {:x}",
                i.ip()
            );
        }
    }
}
#[test]
fn array_lengths_allocation_identity_and_full_initialization_are_required() {
    let (addr, bytes, start) = code();
    for pos in [0x10003bb50u64, 0x10003bdb9] {
        let p = (pos - addr) as usize;
        for len in [0u32, 7, 301, 303, 4097, u32::MAX] {
            let mut b = bytes.to_vec();
            b[p + 4..p + 8].copy_from_slice(&len.to_le_bytes());
            assert!(decode_pair(&b, addr, start, 4).is_none());
        }
        let mut b = bytes.to_vec();
        b[p + 9] ^= 1;
        assert!(decode_pair(&b, addr, start, 4).is_none()); // allocator target mismatch
        let mut d = Decoder::with_ip(64, &bytes[p..], pos, DecoderOptions::NONE);
        let array = read_array(&mut d, 4).unwrap();
        assert_eq!(array.bytes.len(), 302);
        let consumed = d.position();
        for length in 0..consumed {
            let mut d = Decoder::with_ip(64, &bytes[p..p + length], pos, DecoderOptions::NONE);
            assert!(read_array(&mut d, 4).is_none(), "prefix {length}");
        }
    }
}
#[test]
fn invalid_decoded_utf8_and_controls_are_rejected() {
    let (addr, bytes, start) = code();
    let mut d = Decoder::with_ip(
        64,
        &bytes[start..],
        addr + start as u64,
        DecoderOptions::NONE,
    );
    for _ in 0..5 {
        let _ = d.decode();
    }
    let first = d.decode();
    assert_eq!(first.op1_kind(), OpKind::Immediate64);
    let p = (first.ip() - addr) as usize + 2;
    for target in [0, 1, 0xff] {
        let mut b = bytes.to_vec();
        b[p] ^= b'd' ^ target;
        assert!(decode_pair(&b, addr, start, 4).is_none());
    }
}
#[test]
fn output_truncation_and_unsupported_cpu_are_rejected() {
    let (addr, bytes, start) = code();
    for end in [0, start, start + 1, start + 1299] {
        assert!(decode_pair(&bytes[..end], addr, start, 4).is_none());
    }
    assert!(decode_pair(bytes, addr, usize::MAX, 4).is_none());
    let mut b = thin().to_vec();
    b[4..8].copy_from_slice(&0x0100000cu32.to_le_bytes());
    assert!(extract_macho(&macho(&b), 0, 4).is_empty());
}
#[test]
fn public_pipeline_preserves_full_prompt_in_universal_specimen() {
    let opts = crate::ExtractOptions {
        caller_provides_symbols: true,
        filter_garbage: true,
        ..Default::default()
    };
    let out = crate::extract_strings_with_options(*FILE, &opts);
    let s = out
        .iter()
        .find(|s| {
            s.data_offset == 252752 && s.method == StringMethod::XorDecode && s.value.len() == 302
        })
        .unwrap();
    check(&s.value);
    assert_eq!(s.data_len, 1300);
}

fn replace_text(code: &[u8]) -> Vec<u8> {
    let mut bytes = thin().to_vec();
    let word = |b: &[u8], p| u32::from_le_bytes(b[p..p + 4].try_into().unwrap()) as usize;
    let mut command = 32;
    let mut header = None;
    for _ in 0..word(&bytes, 16) {
        if word(&bytes, command) == 0x19 {
            for i in 0..word(&bytes, command + 64) {
                let p = command + 72 + i * 80;
                if bytes[p..p + 16].split(|b| *b == 0).next().unwrap() == b"__text" {
                    header = Some(p);
                }
            }
        }
        command += word(&bytes, command + 4);
    }
    let p = header.unwrap();
    let offset = bytes.len() as u32;
    bytes[p + 40..p + 48].copy_from_slice(&(code.len() as u64).to_le_bytes());
    bytes[p + 48..p + 52].copy_from_slice(&offset.to_le_bytes());
    bytes.extend_from_slice(code);
    bytes
}
#[test]
fn code_and_candidate_budgets_prevent_late_decode() {
    let (addr, original, start) = code();
    let mut oversized = original.to_vec();
    oversized.resize(MAX_CODE + 1, 0);
    // A valid candidate remains inside the oversized section.
    check(&decode_pair(&oversized, addr, start, 4).unwrap().0);
    assert!(extract_macho(&macho(&replace_text(&oversized)), 0, 4).is_empty());
    let mut crowded = b"\x6a\x01\x5e\xbf\0\0\0\0".repeat(MAX_CANDIDATES);
    let prefix = crowded.len();
    crowded.extend_from_slice(original);
    check(&decode_pair(&crowded, addr, start + prefix, 4).unwrap().0);
    assert!(extract_macho(&macho(&replace_text(&crowded)), 0, 4).is_empty());
}
