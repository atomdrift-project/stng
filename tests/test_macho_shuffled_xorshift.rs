#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Expected digests/addresses come from independent native reconstruction,
//! not from stng's output. Specimens are only parsed, never executed.
use goblin::{
    Object,
    mach::{
        Mach,
        constants::cputype::{CPU_TYPE_ARM64, CPU_TYPE_X86_64},
    },
};
use sha2::{Digest, Sha256};
use stng::{
    ExtractOptions, ExtractedString, StringMethod, extract_macho_shuffled_xorshift_strings,
    extract_strings_with_options,
};

const ORIGINAL: &[u8] = include_bytes!("../testdata/macho/arm64_shuffled_xorshift_universal.macho");
const USTRING: &[u8] =
    include_bytes!("../testdata/macho/arm64_shuffled_xorshift_ustring_universal.macho");
const GATE: &str = "22422ea28dc3168fca0f6633341402f35ad168770ad51960e030a9f94946e080";
const CLEANUP: &str = "20a60a29c697e89aeab8cc741327f19f84b599e628d175aab132f1551f1da29c";
const PAYLOAD: &str = "5195a3d0dac1c124be1ae3396d1f17444c3accd141fd81769c57cdea4c1f2af4";
const ORIGINAL_PAYLOAD: &str = "873d8880d494887ec33291cc88063de732054450a368f176fe8d84d495bb162c";
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn thin(data: &[u8], cpu: u32) -> (&[u8], usize) {
    let Object::Mach(Mach::Fat(fat)) = Object::parse(data).unwrap() else {
        panic!("fat fixture")
    };
    let arch = fat
        .arches()
        .unwrap()
        .into_iter()
        .find(|a| a.cputype == cpu)
        .unwrap();
    let start = arch.offset as usize;
    (&data[start..start + arch.size as usize], start)
}
fn direct(data: &[u8], base: u64, min: usize) -> Vec<ExtractedString> {
    let Object::Mach(Mach::Binary(macho)) = Object::parse(data).unwrap() else {
        panic!("thin fixture")
    };
    extract_macho_shuffled_xorshift_strings(&macho, data, base, min)
}
fn stages(strings: &[ExtractedString], payload: &str, offsets: [u64; 3]) {
    for (hash, len, offset) in [
        (GATE, 536, offsets[0]),
        (payload, 23874, offsets[1]),
        (CLEANUP, 22, offsets[2]),
    ] {
        let matches: Vec<_> = strings
            .iter()
            .filter(|s| digest(s.value.as_bytes()) == hash)
            .collect();
        assert_eq!(matches.len(), 1, "stage {hash}");
        let s = matches[0];
        assert_eq!(s.value.len(), len);
        assert_eq!(s.method, StringMethod::Base64ObfuscatedDecode);
        assert_eq!(s.data_offset, offset);
    }
}
fn arm() -> Vec<u8> {
    thin(USTRING, CPU_TYPE_ARM64).0.to_vec()
}
fn set_word(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn word(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}
fn section_header(data: &[u8], name: &str) -> usize {
    let mut pos = 32;
    for _ in 0..word(data, 16) {
        if word(data, pos) == 0x19 {
            for i in 0..word(data, pos + 64) as usize {
                let h = pos + 72 + i * 80;
                if data[h..h + 16].split(|b| *b == 0).next().unwrap() == name.as_bytes() {
                    return h;
                }
            }
        }
        pos += word(data, pos + 4) as usize;
    }
    panic!("missing section {name}")
}

#[test]
fn fixtures_are_the_original_specimens() {
    assert_eq!(
        digest(ORIGINAL),
        "1d24320db02da6a181abbfe2dfee898231d3cc95af6067fbe97a298b87c2eb8a"
    );
    assert_eq!(
        digest(USTRING),
        "ad79962c1152ec553c885f545f42c7b0672ca186399a0089401dca4952bd1f5e"
    );
}
#[test]
fn both_architectures_and_section_layouts_recover_exact_stages() {
    for (file, hash, x86_offsets, arm_offsets) in [
        (
            ORIGINAL,
            ORIGINAL_PAYLOAD,
            [0x412b0, 0x2cf0, 0x411b0],
            [0x40e50, 0x28a0, 0x40d60],
        ),
        (
            USTRING,
            PAYLOAD,
            [0x41200, 0x2d40, 0x41100],
            [0x40da0, 0x28f0, 0x40cb0],
        ),
    ] {
        for (cpu, offsets) in [
            (CPU_TYPE_X86_64, x86_offsets),
            (CPU_TYPE_ARM64, arm_offsets),
        ] {
            let data = thin(file, cpu).0;
            let strings = direct(data, 0, 4);
            assert_eq!(strings.len(), 3);
            stages(&strings, hash, offsets);
            for s in strings {
                assert!(s.data_offset + u64::from(s.data_len) <= data.len() as u64);
            }
        }
    }
}
#[test]
fn universal_pipeline_decodes_without_rizin_and_rebases_offsets() {
    let opts = ExtractOptions {
        use_cache: false,
        caller_provides_symbols: true,
        filter_garbage: true,
        ..Default::default()
    };
    for (data, hash) in [(ORIGINAL, ORIGINAL_PAYLOAD), (USTRING, PAYLOAD)] {
        let strings = extract_strings_with_options(data, &opts);
        // The library preserves both architecture occurrences. CLI presentation
        // may deduplicate values; both source offsets must be correct here.
        for expected in [GATE, hash, CLEANUP] {
            assert_eq!(
                strings
                    .iter()
                    .filter(|s| digest(s.value.as_bytes()) == expected)
                    .count(),
                2
            );
        }
        for cpu in [CPU_TYPE_X86_64, CPU_TYPE_ARM64] {
            let (slice, base) = thin(data, cpu);
            for s in direct(slice, 0, 4) {
                assert_eq!(
                    strings
                        .iter()
                        .filter(|fat| fat.value == s.value
                            && fat.method == StringMethod::Base64ObfuscatedDecode
                            && fat.data_offset == s.data_offset + base as u64
                            && fat.data_len == s.data_len)
                        .count(),
                    1
                );
            }
        }
    }
}
#[test]
fn arm_rebases_offsets_and_rejects_offset_overflow() {
    let data = arm();
    let base = 0x48000;
    stages(
        &direct(&data, base, 4),
        PAYLOAD,
        [base + 0x40da0, base + 0x28f0, base + 0x40cb0],
    );
    assert!(direct(&data, u64::MAX, 4).is_empty());
}
#[test]
fn minimum_length_is_applied_to_decoded_text() {
    let data = arm();
    let strings = direct(&data, 0, 537);
    assert_eq!(strings.len(), 1);
    assert_eq!(digest(strings[0].value.as_bytes()), PAYLOAD);
    assert!(direct(&data, 0, 23875).is_empty());
}
#[test]
fn duplicate_or_out_of_range_alphabet_indexes_are_rejected() {
    for value in [
        u16::from_le_bytes(arm()[0x4242c..0x4242e].try_into().unwrap()),
        u16::MAX,
    ] {
        let mut data = arm();
        data[0x4242e..0x42430].copy_from_slice(&value.to_le_bytes());
        assert!(direct(&data, 0, 4).is_empty());
    }
}
#[test]
fn truncated_or_unrecognized_index_section_is_rejected() {
    let mut data = arm();
    let h = section_header(&data, "__ustring");
    data[h + 40..h + 48].copy_from_slice(&254u64.to_le_bytes());
    assert!(direct(&data, 0, 4).is_empty());
    let mut data = arm();
    data[h..h + 16].fill(0);
    data[h..h + 7].copy_from_slice(b"__other");
    assert!(direct(&data, 0, 4).is_empty());
}
#[test]
fn invalid_source_and_index_addresses_are_rejected() {
    let mut data = arm();
    // Alphabet ADRP X11: move source to an unmapped page, retaining the opcode/register.
    assert_eq!(word(&data, 0x11f8) & 0x9f00001f, 0x9000000b);
    let changed = (word(&data, 0x11f8) & 0x9f00001f) | 0x00ffffe0;
    set_word(&mut data, 0x11f8, changed);
    assert!(direct(&data, 0, 4).is_empty());
    let mut data = arm();
    // ADD X13,X13,#4095 points past the end of __ustring.
    assert_eq!(word(&data, 0x1208) & 0xffc003ff, 0x910001ad);
    let changed = (word(&data, 0x1208) & !0x003ffc00) | 0x003ffc00;
    set_word(&mut data, 0x1208, changed);
    assert!(direct(&data, 0, 4).is_empty());
}
#[test]
fn all_alphabet_loop_instructions_and_warmup_are_required() {
    for offset in (0x120c..0x1258)
        .step_by(4)
        .chain([0x11e0, 0x11e4, 0x11e8, 0x11ec, 0x11f0])
    {
        let mut data = arm();
        let changed = word(&data, offset) ^ 1;
        set_word(&mut data, offset, changed);
        assert!(
            direct(&data, 0, 4).is_empty(),
            "accepted changed instruction {offset:x}"
        );
    }
}
#[test]
fn invalid_payload_permutation_does_not_hide_other_valid_stages() {
    let mut data = arm();
    data[0x21a50..0x21a52].copy_from_slice(&u16::MAX.to_le_bytes());
    let strings = direct(&data, 0, 4);
    assert_eq!(strings.len(), 2);
    assert!(strings.iter().any(|s| digest(s.value.as_bytes()) == GATE));
    assert!(
        strings
            .iter()
            .any(|s| digest(s.value.as_bytes()) == CLEANUP)
    );
    assert!(
        !strings
            .iter()
            .any(|s| digest(s.value.as_bytes()) == PAYLOAD)
    );
}
#[test]
fn oversized_code_is_rejected_before_decoding() {
    let mut data = arm();
    let h = section_header(&data, "__text");
    data[h + 40..h + 48].copy_from_slice(&32769u64.to_le_bytes());
    assert!(direct(&data, 0, 4).is_empty());
}
#[test]
fn benign_native_fixture_does_not_match_this_decoder() {
    let data = include_bytes!("../testdata/macho/swift_small_strings_webview.macho");
    assert!(direct(data, 0, 4).is_empty());
}

#[test]
fn combined_constant_section_budget_is_enforced() {
    let mut data = arm();
    let h = section_header(&data, "__ustring");
    let size = 512 * 1024u64;
    data[h + 40..h + 48].copy_from_slice(&size.to_le_bytes());
    data.resize(0x4242c + size as usize, 0);
    let Object::Mach(Mach::Binary(macho)) = Object::parse(&data).unwrap() else {
        panic!("thin fixture")
    };
    // Prove this exercises the decoder's budget, rather than a parse failure.
    let section = macho
        .segments
        .iter()
        .flat_map(|s| s.sections().unwrap())
        .find(|(s, _)| s.name().unwrap() == "__ustring")
        .unwrap();
    assert_eq!(section.1.len(), size as usize);
    assert!(extract_macho_shuffled_xorshift_strings(&macho, &data, 0, 4).is_empty());
}

#[test]
fn every_truncated_alphabet_instruction_prefix_is_rejected() {
    // Keep the whole file valid, but end __text at each byte inside the only
    // alphabet loop. Later payload/cleanup loops are outside the declared code.
    for end in 0x120c..0x1258 {
        let mut data = arm();
        let h = section_header(&data, "__text");
        data[h + 40..h + 48].copy_from_slice(&((end - 0x780) as u64).to_le_bytes());
        assert!(
            direct(&data, 0, 4).is_empty(),
            "accepted prefix ending {end:x}"
        );
    }
}
