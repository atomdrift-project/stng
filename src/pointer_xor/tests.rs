#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]
use super::*;
use goblin::{Object, mach::Mach};
static FILE: std::sync::LazyLock<&[u8]> = std::sync::LazyLock::new(|| {
    crate::test_fixture("testdata/macho/rust_heap_xor_installer_universal.macho")
});
fn thin() -> &'static [u8] {
    &FILE[8192..8192 + 4143304]
}
fn macho(bytes: &[u8]) -> MachO<'_> {
    let Object::Mach(Mach::Binary(m)) = Object::parse(bytes).unwrap() else {
        panic!("thin")
    };
    m
}
fn code() -> Region<'static> {
    let m = macho(thin());
    for seg in &m.segments {
        for (s, b) in seg.sections().unwrap() {
            if s.name().ok() == Some("__text") {
                return Region {
                    addr: s.addr,
                    offset: s.offset.into(),
                    bytes: b,
                };
            }
        }
    }
    panic!("code")
}
fn num(row: &serde_json::Value, key: &str) -> u64 {
    u64::from_str_radix(row[key].as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}
#[test]
fn every_reviewed_extension_id_and_key_helper_matches_independent_reconstruction() {
    let rows: Vec<serde_json::Value> = serde_json::from_slice(crate::test_fixture(
        "testdata/macho/rust_pointer_xor_expected.json",
    ))
    .unwrap();
    assert_eq!(rows.len(), 298);
    let code = code();
    let out = extract_macho(&macho(thin()), 8192, 4);
    for row in rows {
        assert_eq!(
            fold_helper(
                &code,
                num(&row, "helper"),
                num(&row, "base"),
                num(&row, "seed")
            ),
            Some(num(&row, "key"))
        );
        let offset = num(&row, "ciphertext") - 0x100000000 + 8192;
        assert!(
            out.iter().any(|s| s.value == row["text"].as_str().unwrap()
                && s.data_offset == offset
                && s.data_len == 32
                && s.method == StringMethod::XorDecode),
            "missing {row}"
        );
    }
}
#[test]
fn all_three_padded_endpoints_and_fat_offsets_are_preserved() {
    let m = macho(thin());
    let out = extract_macho(&m, 8192, 4);
    for (value, offset) in [
        ("https://cloudproxy.link/m/opened", 2853402),
        ("https://cloudproxy.link/m/decode", 2853509),
        ("https://cloudproxy.link/db/debug", 2853589),
    ] {
        assert!(
            out.iter().any(|s| s.value.trim_end() == value
                && s.data_offset == offset
                && s.data_len == 32)
        );
    }
    let plain = extract_macho(&m, 0, 4);
    assert_eq!(plain.len(), out.len());
    for (a, b) in plain.iter().zip(out) {
        assert_eq!(a.value, b.value);
        assert_eq!(a.data_offset + 8192, b.data_offset);
    }
    assert!(extract_macho(&m, u64::MAX, 4).is_empty());
    assert!(extract_macho(&m, 0, 513).is_empty());
}
fn setups(code: &Region<'_>) -> Vec<(u64, Setup)> {
    memchr::memmem::find_iter(code.bytes, SETUP)
        .filter_map(|hit| {
            [11, 12, 14, 15].into_iter().find_map(|back| {
                let addr = code.addr + hit.checked_sub(back)? as u64;
                read_setup(code, addr).map(|s| (addr, s))
            })
        })
        .collect()
}
#[test]
fn required_setup_and_loop_instructions_reject_mutation_and_truncation() {
    let original = code();
    for (_, setup) in setups(&original)
        .into_iter()
        .filter(|(_, s)| read_loop(&original, s).is_some())
        .take(3)
    {
        let begin = setup.after as usize - original.addr as usize;
        let mut d = original.decoder(setup.after, 192).unwrap();
        loop {
            let i = d.decode();
            if i.mnemonic() == Mnemonic::Call {
                break;
            }
            let p = (i.ip() - original.addr) as usize;
            let mut b = original.bytes.to_vec();
            b[p] = 0xcc;
            let code = Region {
                bytes: &b,
                addr: original.addr,
                offset: original.offset,
            };
            assert!(read_loop(&code, &setup).is_none(), "loop {:x}", i.ip());
            if d.position() >= 192 {
                panic!("expected consumer call")
            }
        }
        for end in begin..begin + 4 {
            let truncated = Region {
                bytes: &original.bytes[..end],
                addr: original.addr,
                offset: original.offset,
            };
            assert!(read_loop(&truncated, &setup).is_none());
        }
    }
    let (addr, _) = setups(&original).remove(0);
    let mut d = original.decoder(addr, 64).unwrap();
    for _ in 0..8 {
        let i = d.decode();
        let p = (i.ip() - original.addr) as usize;
        let mut b = original.bytes.to_vec();
        b[p] = 0xcc;
        let code = Region {
            bytes: &b,
            addr: original.addr,
            offset: original.offset,
        };
        assert!(read_setup(&code, addr).is_none());
    }
}
#[test]
fn helper_grammar_rejects_memory_unknown_calls_truncation_and_work_overflow() {
    let prefix = [0x55, 0x48, 0x89, 0xe5];
    for middle in [
        vec![0x48, 0x8b, 0x07],
        vec![0xe8, 0, 0, 0, 0],
        vec![0x0f, 0x0b],
        [0x48, 0x89, 0xf8].repeat(25),
    ] {
        let mut b = prefix.to_vec();
        b.extend(middle);
        b.extend([0x5d, 0xc3]);
        let code = Region {
            addr: 0,
            offset: 0,
            bytes: &b,
        };
        assert!(fold_helper(&code, 0, 0x1000, 1).is_none());
    }
    let good = [
        0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0xf8, 0x48, 0x83, 0xc0, 0x10, 0x5d, 0xc3,
    ];
    let code = Region {
        addr: 0,
        offset: 0,
        bytes: &good,
    };
    assert_eq!(fold_helper(&code, 0, 0x1000, 1), Some(0x1010));
    for end in 0..good.len() {
        let code = Region {
            addr: 0,
            offset: 0,
            bytes: &good[..end],
        };
        assert!(fold_helper(&code, 0, 0x1000, 1).is_none());
    }
}
#[test]
fn matching_consumer_length_requires_exact_argument_and_no_intervening_branch() {
    for (b, want) in [
        (&[0x6a, 0x20, 0x5a, 0xe8, 0, 0, 0, 0][..], true),
        (&[0x6a, 0x1f, 0x5a, 0xe8, 0, 0, 0, 0], false),
        (&[0x6a, 0x20, 0x58, 0xe8, 0, 0, 0, 0], false),
        (&[0x6a, 0x20, 0x5a, 0xeb, 0, 0xe8, 0, 0, 0, 0], false),
    ] {
        let code = Region {
            addr: 0,
            offset: 0,
            bytes: b,
        };
        assert_eq!(matching_call_length(&code, 0, 32), want);
    }
}
#[test]
fn region_bounds_and_unsupported_cpu_reject() {
    let region = Region {
        addr: 100,
        offset: 0,
        bytes: &[1, 2, 3, 4],
    };
    assert_eq!(region.at(100, 4), Some(&[1, 2, 3, 4][..]));
    assert!(region.at(99, 1).is_none());
    assert!(region.at(103, 2).is_none());
    assert!(region.at(100, usize::MAX).is_none());
    assert!(region.decoder(99, 4).is_none());
    let mut b = thin().to_vec();
    b[4..8].copy_from_slice(&0x0100000cu32.to_le_bytes());
    assert!(extract_macho(&macho(&b), 0, 4).is_empty());
}

fn replace_code(new_code: &[u8], addr: u64) -> Vec<u8> {
    let mut b = thin().to_vec();
    let word = |b: &[u8], p| u32::from_le_bytes(b[p..p + 4].try_into().unwrap()) as usize;
    let mut command = 32;
    for _ in 0..word(&b, 16) {
        if word(&b, command) == 0x19 {
            for i in 0..word(&b, command + 64) {
                let p = command + 72 + i * 80;
                if b[p..p + 16].split(|c| *c == 0).next().unwrap() == b"__text" {
                    let offset = b.len() as u32;
                    b[p + 32..p + 40].copy_from_slice(&addr.to_le_bytes());
                    b[p + 40..p + 48].copy_from_slice(&(new_code.len() as u64).to_le_bytes());
                    b[p + 48..p + 52].copy_from_slice(&offset.to_le_bytes());
                    b.extend_from_slice(new_code);
                    return b;
                }
            }
        }
        command += word(&b, command + 4);
    }
    panic!("text section")
}
#[test]
fn code_and_candidate_limits_are_enforced_with_valid_later_candidates() {
    let original = code();
    assert!(!extract_macho(&macho(&replace_code(original.bytes, original.addr)), 0, 4).is_empty());
    let mut oversized = original.bytes.to_vec();
    oversized.resize(MAX_CODE + 1, 0);
    assert!(extract_macho(&macho(&replace_code(&oversized, original.addr)), 0, 4).is_empty());
    let mut crowded = SETUP.repeat(MAX_CANDIDATES);
    let prefix = crowded.len();
    crowded.extend_from_slice(original.bytes);
    let addr = original.addr - prefix as u64;
    let relocated = Region {
        addr,
        offset: 0,
        bytes: &crowded,
    };
    // Existing instruction VAs remain unchanged; an original candidate is still valid.
    let (at, old) = setups(&original)
        .into_iter()
        .find(|(_, s)| read_loop(&original, s).is_some())
        .unwrap();
    let new = read_setup(&relocated, at).unwrap();
    assert_eq!(read_loop(&original, &old), read_loop(&relocated, &new));
    assert!(fold_helper(&relocated, new.helper, new.base, new.seed).is_some());
    assert!(extract_macho(&macho(&replace_code(&crowded, addr)), 0, 4).is_empty());
}
#[test]
fn invalid_endpoint_bytes_do_not_suppress_other_valid_literals() {
    let original = extract_macho(&macho(thin()), 0, 4);
    let offset = 2853509 - 8192;
    for new_plain in [0, 1, 0xff] {
        let mut b = thin().to_vec();
        b[offset] ^= b'h' ^ new_plain;
        let out = extract_macho(&macho(&b), 0, 4);
        assert!(!out.iter().any(|s| s.data_offset == offset as u64));
        assert_eq!(out.len() + 1, original.len());
    }
}
