#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use goblin::{
    Object,
    mach::{Mach, SingleArch},
};
use std::collections::BTreeSet;

fn fixture(name: &str) -> &'static [u8] {
    crate::test_fixture(&format!("testdata/macho/{name}"))
}

/// Each slice of a universal Mach-O with its file offset.
fn slices(data: &[u8]) -> Vec<(MachO<'_>, u64)> {
    let Object::Mach(Mach::Fat(fat)) = Object::parse(data).unwrap() else {
        panic!("universal Mach-O")
    };
    let offsets: Vec<u64> = fat
        .arches()
        .unwrap()
        .iter()
        .map(|a| u64::from(a.offset))
        .collect();
    fat.into_iter()
        .zip(offsets)
        .map(|(arch, base)| match arch.unwrap() {
            SingleArch::MachO(m) => (m, base),
            SingleArch::Archive(_) => panic!("slice is an archive"),
        })
        .collect()
}

fn values(out: &[ExtractedString]) -> BTreeSet<&str> {
    out.iter().map(|s| s.value.as_str()).collect()
}

/// Mirror of the sample's encoder: the inverse of [`record`].
fn seal(seed: u32, plain: &[u8]) -> Vec<u8> {
    let mut out = seed.to_le_bytes().to_vec();
    let (mut prev, mut state) = (seed.to_le_bytes()[0], seed);
    for &p in plain.iter().chain(&[0]) {
        let c = p ^ keystream(prev, state);
        out.push(c);
        prev = c;
        state = state.wrapping_add(GOLDEN);
    }
    out.resize(out.len().next_multiple_of(4), 0);
    out
}

#[test]
fn decrypts_sample_record() {
    // Known-answer vector: one 40-byte record from the sample named in the
    // module docs (a Chrome wallet-extension ID).
    let bytes = hex::decode(
        "8bcd0f676348d3192887db21d206cf3b088ba6452f181d5ae1349f14dafd2eae5335fac000000000",
    )
    .unwrap();
    assert_eq!(
        record(&bytes, 0),
        Some(("ldinpeekobnhjjdofggfgjlcehhmanlj".to_owned(), 40))
    );
}

#[test]
fn round_trips_every_length_and_alignment() {
    for len in 1u8..=13 {
        let plain: Vec<u8> = (0..len).map(|i| b'a' + (i % 26)).collect();
        let sealed = seal(0x1234_5678 ^ u32::from(len), &plain);
        assert_eq!(sealed.len() % 4, 0);
        let (value, used) = record(&sealed, 0).unwrap();
        assert_eq!((value.as_bytes(), used), (plain.as_slice(), sealed.len()));
    }
}

#[test]
fn rejects_malformed_records() {
    let good = seal(0xdead_beef, b"hello");
    // Non-zero padding after the terminator.
    let mut bad = good.clone();
    *bad.last_mut().unwrap() = 1;
    assert_eq!(record(&bad, 0), None);
    // A flipped ciphertext byte breaks the terminator or printability.
    let mut bad = good.clone();
    bad[5] ^= 0x80;
    assert_eq!(record(&bad, 0), None);
    // Truncated before the terminator.
    assert_eq!(record(&good[..8], 0), None);
    // An empty plaintext is not a string.
    assert_eq!(record(&seal(7, b""), 0), None);
}

#[test]
fn gates_on_all_three_constants() {
    let x86: Vec<u8> = CONSTANTS.iter().flat_map(|k| k.to_le_bytes()).collect();
    assert!(materializes_constants(&x86));
    assert!(!materializes_constants(&x86[..8]));

    // MOVZ Wd,#lo ; MOVK Wd,#hi,LSL #16 for each constant into a distinct register.
    let arm: Vec<u8> = CONSTANTS
        .iter()
        .zip([25_u32, 26, 27])
        .flat_map(|(k, rd)| {
            let movz = 0x5280_0000 | (k & 0xffff) << 5 | rd;
            let movk = 0x72a0_0000 | (k >> 16) << 5 | rd;
            [movz, movk]
        })
        .flat_map(u32::to_le_bytes)
        .collect();
    assert!(materializes_constants(&arm));
    // The MOVK must complete the same register's MOVZ.
    let mut crossed = arm.clone();
    crossed[4] ^= 1;
    assert!(!materializes_constants(&crossed));
}

#[test]
fn extracts_both_slices_of_the_sample() {
    let data = fixture("fmix_xor_stealer_universal.macho");
    let out: Vec<_> = slices(data)
        .iter()
        .map(|(m, base)| (m.header.cputype, extract_macho(m, *base, 4)))
        .collect();
    let arch = |cpu| {
        values(&out.iter().find(|(c, _)| *c == cpu).unwrap().1)
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>()
    };
    let arm = arch(goblin::mach::constants::cputype::CPU_TYPE_ARM64);
    let x86 = arch(goblin::mach::constants::cputype::CPU_TYPE_X86_64);
    for want in [
        "http://109.238.87.111/log",
        "http://109.238.87.110",
        "Enter an administrator's username and password to allow this.",
        "Keychains/login.keychain-db",
        "Telegram Desktop/tdata/",
        "ldinpeekobnhjjdofggfgjlcehhmanlj",
    ] {
        assert!(arm.contains(want) && x86.contains(want), "{want}");
    }
    // Intel stores the short strings ARM64 builds from immediates as records,
    // so it recovers a superset.
    assert!(arm.is_subset(&x86), "{:?}", arm.difference(&x86));
    // Decoding each of the ARM64 slice's 391 inlined loops from its own
    // instructions yields 387 data-backed strings (the rest are stack
    // immediates of at most 3 characters); the record scan must find exactly
    // those.
    let records = |cpu| out.iter().find(|(c, _)| *c == cpu).unwrap().1.len();
    assert_eq!(
        records(goblin::mach::constants::cputype::CPU_TYPE_ARM64),
        387
    );
    for (_, strings) in &out {
        for s in strings {
            assert_eq!(s.method, StringMethod::XorDecode);
            assert!(s.data_offset < data.len() as u64);
        }
    }
}

#[test]
fn ignores_binaries_without_the_mixer() {
    let data = fixture("arm64_lcg_xor_universal.macho");
    for (m, base) in slices(data) {
        assert!(extract_macho(&m, base, 4).is_empty());
    }
}
