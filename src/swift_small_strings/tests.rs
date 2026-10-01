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
    crate::test_fixture("testdata/macho/swift_small_strings_webview.macho")
});
fn extract(bytes: &[u8], base: u64, min: usize) -> Vec<ExtractedString> {
    let Object::Mach(Mach::Binary(m)) = Object::parse(bytes).unwrap() else {
        panic!("thin Mach-O")
    };
    extract_macho(&m, base, min)
}
fn section(b: &[u8], name: &str) -> usize {
    let word = |p| u32::from_le_bytes(b[p..p + 4].try_into().unwrap()) as usize;
    let mut p = 32;
    for _ in 0..word(16) {
        if word(p) == 0x19 {
            for i in 0..word(p + 64) {
                let s = p + 72 + i * 80;
                if b[s..s + 16].split(|v| *v == 0).next().unwrap() == name.as_bytes() {
                    return s;
                }
            }
        }
        p += word(p + 4);
    }
    panic!("section {name}")
}
fn specimen_code(code: &[u32]) -> Vec<u8> {
    let mut b = FILE.to_vec();
    let h = section(&b, "__text");
    let offset = u32::from_le_bytes(b[h + 48..h + 52].try_into().unwrap()) as usize;
    b.resize(b.len().max(offset + code.len() * 4), 0);
    b[h + 40..h + 48].copy_from_slice(&((code.len() * 4) as u64).to_le_bytes());
    for (i, w) in code.iter().enumerate() {
        b[offset + i * 4..offset + (i + 1) * 4].copy_from_slice(&w.to_le_bytes());
    }
    b
}
fn mov(rd: u32, imm: u16, shift: u32, keep: bool, wide: bool) -> u32 {
    (if keep { 0x72800000 } else { 0x52800000 })
        | if wide { 1 << 31 } else { 0 }
        | (shift / 16) << 21
        | u32::from(imm) << 5
        | rd
}
fn pair(text: &[u8], first: u32) -> Vec<u32> {
    assert!(text.len() <= 15);
    let mut raw = [0u8; 16];
    raw[..text.len()].copy_from_slice(text);
    raw[15] = 0xe0 | text.len() as u8;
    let mut out = Vec::new();
    for reg in 0..2 {
        for half in 0..4 {
            let i = reg * 8 + half * 2;
            out.push(mov(
                first + reg as u32,
                u16::from_le_bytes([raw[i], raw[i + 1]]),
                half as u32 * 16,
                half != 0,
                true,
            ));
        }
    }
    out
}
#[test]
fn original_specimen_has_exact_independently_reviewed_values_and_spans() {
    assert_eq!(
        hex::encode(Sha256::digest(*FILE)),
        "e804a52fe033d7e99f4e51c5b7f70bd5101e61de1478f5c619219fea8ef8a957"
    );
    let out = extract(*FILE, 0, 4);
    for (value, start, end) in [
        ("index", 0x1ee8, 0x1ef8),
        ("html", 0x1ef8, 0x1f04),
        ("username", 0x1fd4, 0x1fec),
        (".private", 0x21ec, 0x2204),
        (" but found ", 0x3680, 0x369c),
    ] {
        let found: Vec<_> = out
            .iter()
            .filter(|s| s.value == value && s.data_offset == start)
            .collect();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].data_len, u32::try_from(end - start).unwrap());
        assert_eq!(found[0].method, StringMethod::Structure);
    }
    assert!(!out.iter().any(|s| s.value == "standart"));
    let rebased = extract(*FILE, 0x10000, 4);
    assert_eq!(out.len(), rebased.len());
    for (a, b) in out.iter().zip(rebased) {
        assert_eq!(a.value, b.value);
        assert_eq!(a.data_offset + 0x10000, b.data_offset);
    }
    assert!(extract(*FILE, u64::MAX, 4).is_empty());
    assert!(extract(*FILE, 0, 16).is_empty());
}
#[test]
fn canonical_lengths_and_register_edges() {
    for len in 1..=15 {
        for reg in [0, 14, 29] {
            let text = vec![b'A'; len];
            let b = specimen_code(&pair(&text, reg));
            let out = extract(&b, 0, len);
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].value.as_bytes(), text);
            assert!(extract(&b, 0, len + 1).is_empty());
        }
    }
    assert!(extract(&specimen_code(&pair(b"abc", 30)), 0, 1).is_empty());
    assert!(extract(&specimen_code(&pair(b"", 0)), 0, 0).is_empty());
}
#[test]
fn invalid_payload_tag_padding_and_movk_without_seed_reject() {
    for text in [b"ab\0d".as_slice(), b"ab\x01d", b"ab\xffd", b"ab\nd"] {
        assert!(extract(&specimen_code(&pair(text, 0)), 0, 1).is_empty());
    }
    let mut code = pair(b"test", 0);
    code[7] = mov(1, 0xd400, 48, true, true);
    assert!(extract(&specimen_code(&code), 0, 1).is_empty());
    let mut code = pair(b"test", 0);
    code[2] = mov(0, 1, 32, true, true);
    assert!(extract(&specimen_code(&code), 0, 1).is_empty());
    let mut code = pair(b"test", 0);
    code[0] |= 0x20000000;
    assert!(extract(&specimen_code(&code), 0, 1).is_empty());
}
#[test]
fn barriers_clobbers_and_lifetime_prevent_stale_pairing() {
    for instruction in [
        0x94000000, 0x14000000, 0xf9400002, 0xf9000002, 0xd503201f, 0xaa0303e0, 0x91000400,
    ] {
        let mut code = pair(b"abcdefghijk", 0);
        code.insert(4, instruction);
        assert!(
            extract(&specimen_code(&code), 0, 1).is_empty(),
            "{instruction:x}"
        );
    }
    let mut code = pair(b"abcdefghijk", 0);
    code.splice(4..4, [0x91000402; 8]);
    assert_eq!(extract(&specimen_code(&code), 0, 1).len(), 1); // 16 instructions: last index 15.
    code.insert(4, 0x91000402);
    assert!(extract(&specimen_code(&code), 0, 1).is_empty());
}
#[test]
fn metadata_cpu_and_code_budgets_are_required() {
    let mut b = FILE.to_vec();
    let s = section(&b, "__swift5_types");
    b[s..s + 16].fill(0);
    assert!(extract(&b, 0, 1).is_empty());
    let mut b = FILE.to_vec();
    b[4..8].copy_from_slice(&0x01000007u32.to_le_bytes());
    assert!(extract(&b, 0, 1).is_empty());
    let mut code = pair(b"test", 0);
    code.resize(MAX_CODE / 4 + 1, 0);
    assert!(extract(&specimen_code(&code), 0, 1).is_empty());
}
#[test]
fn output_cap_is_exact_and_instruction_prefixes_do_not_panic() {
    let pair = pair(b"longer than 8", 0);
    for n in 0..pair.len() {
        assert!(extract(&specimen_code(&pair[..n]), 0, 1).is_empty());
    }
    let code = pair.repeat(MAX_STRINGS + 1);
    assert_eq!(extract(&specimen_code(&code), 0, 1).len(), MAX_STRINGS);
}

#[test]
fn public_filtered_pipeline_preserves_specimen_small_strings() {
    let opts = crate::ExtractOptions {
        caller_provides_symbols: true,
        filter_garbage: true,
        ..Default::default()
    };
    let out = crate::extract_strings_with_options(*FILE, &opts);
    for (value, start, length) in [
        ("index", 0x1ee8, 16),
        ("html", 0x1ef8, 12),
        ("username", 0x1fd4, 24),
        (".private", 0x21ec, 24),
    ] {
        assert!(
            out.iter().any(|s| s.value == value
                && s.data_offset == start
                && s.data_len == length
                && s.method == StringMethod::Structure),
            "{value}"
        );
    }
}

#[test]
fn w_register_writes_zero_extend_and_reserved_shifts_invalidate_state() {
    let code = [
        mov(0, 0xffff, 32, false, true),
        mov(0, 0x6574, 0, true, false),
        mov(0, 0x7473, 16, true, false),
        mov(1, 0xe400, 48, false, true),
    ];
    let out = extract(&specimen_code(&code), 0, 4);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].value, "test");
    for shift in [32, 48] {
        let mut invalid = code.to_vec();
        invalid.insert(3, mov(2, 0, shift, false, false));
        assert!(extract(&specimen_code(&invalid), 0, 1).is_empty());
    }
}
