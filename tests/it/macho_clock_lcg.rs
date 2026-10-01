#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Regression for a Mach-O LCG-XOR command whose modulus comes from HH:MM:SS.
//! The specimen is inspected as inert data; no command or script is run.
use goblin::{
    Object,
    mach::{
        Mach,
        constants::cputype::{CPU_TYPE_ARM64, CPU_TYPE_X86_64},
    },
};
use sha2::{Digest, Sha256};
use stng::{ExtractOptions, StringMethod, extract_macho_lcg_xor, extract_strings_with_options};

const FILE: &[u8] = include_bytes!("../../testdata/macho/charge0x_installer_universal.macho");
const HASH: &str = "a2499abd63ef02c20ef6f558e2699bab2beeb5bdbef9677726b83fa4b21c0acc";

fn thin(bytes: &[u8], cpu: u32) -> (Vec<u8>, usize) {
    let Object::Mach(Mach::Fat(fat)) = Object::parse(bytes).unwrap() else {
        panic!("expected universal Mach-O")
    };
    let arch = fat
        .arches()
        .unwrap()
        .into_iter()
        .find(|arch| arch.cputype == cpu)
        .unwrap();
    let start = arch.offset as usize;
    let end = (arch.offset + arch.size) as usize;
    (bytes[start..end].to_vec(), start)
}

fn direct(bytes: &[u8], cpu: u32) -> Vec<stng::ExtractedString> {
    let (slice, base) = thin(bytes, cpu);
    let Object::Mach(Mach::Binary(macho)) = Object::parse(&slice).unwrap() else {
        panic!("expected thin Mach-O slice")
    };
    extract_macho_lcg_xor(&macho, bytes, base as u64, 4)
}

#[test]
fn both_slices_decode_the_same_command_and_keep_file_offsets() {
    assert_eq!(
        hex::encode(Sha256::digest(FILE)),
        "8202c3887b75b107f76385fe36e7949860b7931cebd2c65899649556c37e30bc"
    );
    for (cpu, offset) in [(CPU_TYPE_X86_64, 0x4c90), (CPU_TYPE_ARM64, 0x14de0)] {
        let found = direct(FILE, cpu);
        assert_eq!(found.len(), 1);
        assert_eq!(hex::encode(Sha256::digest(found[0].value.as_bytes())), HASH);
        assert_eq!(found[0].value.len(), 37_076);
        assert!(found[0].value.starts_with("osascript -e 'run script"));
        assert!(found[0].value.contains("charge0x.at"));
        assert!(found[0].value.contains("/log"));
        assert_eq!(found[0].data_offset, offset);
        assert_eq!(found[0].data_len, 37_077);
        assert_eq!(found[0].method, StringMethod::XorDecode);
    }

    let options = ExtractOptions {
        caller_provides_symbols: true,
        filter_garbage: true,
        ..Default::default()
    };
    let all = extract_strings_with_options(FILE, &options);
    for offset in [0x4c90, 0x14de0] {
        let found: Vec<_> = all
            .iter()
            .filter(|string| {
                string.data_offset == offset
                    && string.method == StringMethod::XorDecode
                    && string.value.starts_with("osascript")
            })
            .collect();
        assert_eq!(found.len(), 1);
        assert_eq!(hex::encode(Sha256::digest(found[0].value.as_bytes())), HASH);
    }
}

#[test]
fn rejects_mutated_seed_clock_and_encoded_command_prefix() {
    for cpu in [CPU_TYPE_X86_64, CPU_TYPE_ARM64] {
        let (_, base) = thin(FILE, cpu);
        let const_offset = if cpu == CPU_TYPE_X86_64 {
            0x0c8c
        } else {
            0x0ddc
        };
        let clock_offset = if cpu == CPU_TYPE_X86_64 {
            0x9d68
        } else {
            0x9eb8
        };

        let mut changed = FILE.to_vec();
        changed[base + const_offset] ^= 1;
        assert!(direct(&changed, cpu).is_empty(), "seed mismatch accepted");

        let mut changed = FILE.to_vec();
        changed[base + clock_offset] ^= 1;
        assert!(direct(&changed, cpu).is_empty(), "changed clock accepted");

        let multiplier_offset = if cpu == CPU_TYPE_X86_64 {
            let slice = &FILE[base..];
            let immediate = 0x3785u32.to_le_bytes();
            base + slice
                .windows(4)
                .position(|word| word == immediate)
                .expect("x86 multiplier immediate")
        } else {
            base + 0x924 // MOVZ W9, #0x3785 in the verified ARM64 slice.
        };
        let mut changed = FILE.to_vec();
        changed[multiplier_offset] ^= 1 << 5;
        assert!(
            direct(&changed, cpu).is_empty(),
            "changed multiplier accepted"
        );

        let mut changed = FILE.to_vec();
        changed[base + const_offset + 4] ^= 0x80;
        assert!(
            direct(&changed, cpu).is_empty(),
            "changed command prefix accepted"
        );
    }
}
