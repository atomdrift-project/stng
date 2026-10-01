#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]
//! Static specimen and malformed-table regressions; never execute the payload.

use sha2::{Digest, Sha256};
use stng::{
    ExtractOptions, StringKind, StringMethod, decode_xor_fat_macho, extract_strings_with_options,
};

static FILE: std::sync::LazyLock<&[u8]> = std::sync::LazyLock::new(|| {
    crate::common::bytes("testdata/macho/xor_fat_dropper.macho").leak()
});
const START: usize = 0x6210;
const LEN: usize = 153824;
fn plain() -> Vec<u8> {
    FILE[START..START + LEN].iter().map(|b| b ^ 0x9c).collect()
}
fn encode(b: &[u8], key: u8) -> Vec<u8> {
    b.iter().map(|v| v ^ key).collect()
}
fn reject(b: &[u8]) {
    assert!(decode_xor_fat_macho(&encode(b, 0x9c), 0x9c).is_none());
}
#[test]
fn specimen_and_full_payload_match_independent_native_reconstruction() {
    assert_eq!(
        crate::common::hex(&Sha256::digest(*FILE)),
        "30c99015f9c432604d8a8206ce8dcb4fba7866b062e5bd1a8f0adb88fba8807c"
    );
    let got = decode_xor_fat_macho(&FILE[START..], 0x9c).unwrap();
    assert_eq!(got.len(), LEN);
    assert_eq!(got, plain());
    assert_eq!(
        crate::common::hex(&Sha256::digest(&got)),
        "5f522222dd8c3237058f7b7b00e717d1365f14aea6f45e41c9f982dd866cb8c0"
    );
}
#[test]
fn public_string_pipeline_locates_key_with_exact_offset() {
    let opts = ExtractOptions {
        caller_provides_symbols: true,
        filter_garbage: true,
        ..Default::default()
    };
    let strings = extract_strings_with_options(*FILE, &opts);
    let keys: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == Some(StringKind::XorKey) && s.data_offset == START as u64)
        .collect();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].value, "0x9c");
    assert_eq!(keys[0].method, StringMethod::XorDecode);
    assert_eq!(decode_xor_fat_macho(&FILE[START..], 0x9c).unwrap(), plain());
}
#[test]
fn arbitrary_nonzero_keys_and_trailing_bytes_preserve_exact_extent() {
    let p = plain();
    for key in [1, 0x23, 0x80, 0xff] {
        let mut b = encode(&p, key);
        b.extend_from_slice(&[0x42; 128]);
        assert_eq!(decode_xor_fat_macho(&b, key).unwrap(), p);
    }
    assert!(decode_xor_fat_macho(&p, 0).is_none());
    assert!(decode_xor_fat_macho(&FILE[START..], 0x9d).is_none());
}
#[test]
fn truncated_headers_tables_and_slices_are_rejected() {
    for len in (0..49).chain([4095, 16384, 71927, 81920, LEN - 1]) {
        assert!(
            decode_xor_fat_macho(&FILE[START..START + len], 0x9c).is_none(),
            "len {len}"
        );
    }
}
#[test]
fn invalid_architecture_counts_offsets_sizes_and_slice_headers_are_rejected() {
    let p = plain();
    for n in [0u32, 33, u32::MAX] {
        let mut b = p.clone();
        b[4..8].copy_from_slice(&n.to_be_bytes());
        reject(&b);
    }
    for start in [8usize, 28] {
        for (field, value) in [(8, 0u32), (12, 0), (8, u32::MAX), (12, u32::MAX), (12, 1)] {
            let mut b = p.clone();
            b[start + field..start + field + 4].copy_from_slice(&value.to_be_bytes());
            reject(&b);
        }
    }
    for offset in [16384usize, 81920] {
        let mut b = p.clone();
        b[offset..offset + 4].fill(0);
        reject(&b);
    }
}
#[test]
fn size_limits_reject_before_full_image_decode() {
    fn assert_valid_slices(bytes: &[u8]) {
        let goblin::Object::Mach(goblin::mach::Mach::Fat(fat)) =
            goblin::Object::parse(bytes).unwrap()
        else {
            panic!("fat");
        };
        for arch in fat.into_iter() {
            assert!(matches!(arch, Ok(goblin::mach::SingleArch::MachO(_))));
        }
    }
    let mut b = plain();
    let mut header = b[16384..16416].to_vec();
    header[16..24].fill(0); // Valid minimal Mach-O with no load commands.
    b[48..80].copy_from_slice(&header);
    b[4..8].copy_from_slice(&1u32.to_be_bytes());
    b[16..20].copy_from_slice(&48u32.to_be_bytes());
    b[20..24].copy_from_slice(&32u32.to_be_bytes());
    b.truncate(80);
    assert_valid_slices(&b);
    reject(&b); // Extent below 4096.
    let mut b = plain();
    b.resize(32 * 1024 * 1024 + 1, 0);
    let size = (b.len() - 81920) as u32;
    b[40..44].copy_from_slice(&size.to_be_bytes());
    assert_valid_slices(&b);
    reject(&b);
}
#[test]
fn fat64_arithmetic_overflow_and_truncated_tables_are_rejected() {
    for swapped in [false, true] {
        let mut b = vec![0u8; 4096];
        b[..4].copy_from_slice(if swapped {
            &[0xbf, 0xba, 0xfe, 0xca]
        } else {
            &[0xca, 0xfe, 0xba, 0xbf]
        });
        b[4..8].copy_from_slice(&if swapped {
            1u32.to_le_bytes()
        } else {
            1u32.to_be_bytes()
        });
        b[16..24].copy_from_slice(&u64::MAX.to_be_bytes());
        b[24..32].copy_from_slice(&if swapped {
            2u64.to_le_bytes()
        } else {
            2u64.to_be_bytes()
        });
        reject(&b);
        for end in 8..40 {
            reject(&b[..end]);
        }
    }
}
