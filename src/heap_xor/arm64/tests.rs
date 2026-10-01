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
fn code() -> (Code<'static>, u64, u64) {
    let Object::Mach(Mach::Fat(fat)) = Object::parse(*FILE).unwrap() else {
        panic!("fat")
    };
    let arch = fat
        .iter_arches()
        .map(Result::unwrap)
        .find(|a| a.cputype == goblin::mach::constants::cputype::CPU_TYPE_ARM64)
        .unwrap();
    let Object::Mach(Mach::Binary(m)) =
        Object::parse(&FILE[arch.offset as usize..(arch.offset + arch.size) as usize]).unwrap()
    else {
        panic!("arm")
    };
    for seg in &m.segments {
        for (s, b) in seg.sections().unwrap() {
            if s.name().ok() == Some("__text") {
                return (
                    Code {
                        bytes: b,
                        addr: s.addr,
                    },
                    s.offset.into(),
                    arch.offset.into(),
                );
            }
        }
    }
    panic!("text")
}
const PROMPT: &str = "display dialog \"The current version of the app is not fully compatible with your version of MacOS.\n\nFor the app to work correctly please, enter password of your system.\" with title \"Application Error\" default answer \"\" with icon caution buttons {\"Continue\"} default button \"Continue\" with hidden answer";
#[test]
fn independently_reconstructed_prompt_and_spans_match() {
    let (code, offset, slice) = code();
    let start = code.at(0x100028fa0).unwrap();
    let (value, len) = decode(&code, start, 4).unwrap();
    assert_eq!(value, PROMPT);
    assert_eq!(value.len(), 302);
    assert_eq!(len, 1468);
    let out = extract(code.bytes, code.addr, offset, slice, 4);
    let found = out.iter().find(|s| s.value == PROMPT).unwrap();
    assert_eq!(found.data_offset, slice + 0x28fa0);
    assert_eq!(found.data_len, 1468);
}
#[test]
fn required_main_and_helper_instructions_reject_mutation() {
    let (original, _, _) = code();
    let start = original.at(0x100028fa0).unwrap();
    let mut bytes = original.bytes.to_vec();
    let mut positions: Vec<_> = (start..start + 1468).step_by(4).collect();
    for (addr, n) in [
        (0x1001aceb4, 2),
        (0x1001ba72c, 3),
        (0x1001ae540, 3),
        (0x100012220, 4),
        (0x1001b8a58, 4),
    ] {
        let at = original.at(addr).unwrap();
        positions.extend((at..at + n * 4).step_by(4));
    }
    for pos in positions {
        let saved = original.word(pos).unwrap();
        bytes[pos..pos + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(
            decode(
                &Code {
                    bytes: &bytes,
                    addr: original.addr
                },
                start,
                4
            )
            .is_none(),
            "mutation {:x}",
            original.addr + pos as u64
        );
        bytes[pos..pos + 4].copy_from_slice(&saved.to_le_bytes());
    }
}
#[test]
fn array_loop_and_helper_semantic_mismatches_reject() {
    let (original, _, _) = code();
    let start = original.at(0x100028fa0).unwrap();
    let mut bytes = original.bytes.to_vec();
    for (addr, w) in [
        (0x100028fa0, 0x528025e0u32), // first length 303
        (0x10002925c, 0x528025a0),    // second length 301
        (0x100028fcc, 0xa9012408),    // first store leaves a gap
        (0x100028ff0, 0xa9002408),    // overlapping second store
        (0x100029248, 0x5280000a),    // clobber unsupported initialization register
        (0x1001ba72c, 0xaa0003f4),    // second array aliases first preserved register
        (0x1001ba730, 0xd2800036),    // nonzero starting index
        (0x100029524, 0xf104b6df),    // wrong loop bound
        (0x100029554, 0x91000ad6),    // index increments by two
        (0x100029558, 0x17fffff4),    // wrong back edge
        (0x100012220, 0xeb02003f),    // reversed index comparison
        (0x1001b8a5c, 0x2a190108),    // ORR in place of XOR
    ] {
        let pos = original.at(addr).unwrap();
        let saved = original.word(pos).unwrap();
        bytes[pos..pos + 4].copy_from_slice(&w.to_le_bytes());
        assert!(
            decode(
                &Code {
                    bytes: &bytes,
                    addr: original.addr
                },
                start,
                4
            )
            .is_none(),
            "{addr:x}"
        );
        bytes[pos..pos + 4].copy_from_slice(&saved.to_le_bytes());
    }
}
#[test]
fn malformed_text_truncation_alignment_and_limits_reject() {
    let (original, offset, slice) = code();
    let start = original.at(0x100028fa0).unwrap();
    let mut bytes = original.bytes.to_vec();
    let at = original.at(0x100029268).unwrap();
    let old = original.word(at).unwrap();
    for invalid in [0u32, 255] {
        // First key byte is 0xd8 from the independently decoded MOV X8,#0xa9d8.
        let word = (old & !(0xff << 5)) | ((0xd8 ^ invalid) << 5);
        bytes[at..at + 4].copy_from_slice(&word.to_le_bytes());
        assert!(
            decode(
                &Code {
                    bytes: &bytes,
                    addr: original.addr
                },
                start,
                4
            )
            .is_none()
        );
    }
    for end in 0..1468 {
        assert!(
            decode(
                &Code {
                    bytes: &original.bytes[..start + end],
                    addr: original.addr
                },
                start,
                4
            )
            .is_none()
        );
    }
    for bad in [start + 1, start + 2, start + 3, usize::MAX] {
        assert!(decode(&original, bad, 4).is_none());
    }
    assert!(extract(original.bytes, original.addr, offset, slice, 303).is_empty());
    assert!(extract(original.bytes, original.addr, offset, u64::MAX, 4).is_empty());
    assert!(extract(original.bytes, original.addr, u64::MAX, 0, 4).is_empty());
    assert!(extract(original.bytes, u64::MAX - 3, 0, 0, 4).is_empty());
    assert!(extract(&vec![0; MAX_CODE + 1], 0, 0, 0, 4).is_empty());
    assert!(extract(original.bytes, original.addr, 0, 0, MAX_ARRAY + 1).is_empty());
}
#[test]
fn allocation_prefix_attempt_budget_includes_invalid_candidates() {
    let (original, offset, slice) = code();
    let mut bytes = original.bytes.to_vec();
    for i in 0..MAX_CANDIDATES {
        let pos = i * 12;
        for (j, word) in [0x528025c0u32, 0x94000000, 0xaa0003f4]
            .into_iter()
            .enumerate()
        {
            bytes[pos + j * 4..pos + j * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
    }
    assert!(extract(&bytes, original.addr, offset, slice, 4).is_empty());
}
#[test]
fn public_arm_only_pipeline_recovers_prompt_and_benign_control_stays_clean() {
    let Object::Mach(Mach::Fat(fat)) = Object::parse(*FILE).unwrap() else {
        panic!("fat")
    };
    let arch = fat
        .iter_arches()
        .map(Result::unwrap)
        .find(|a| a.cputype == goblin::mach::constants::cputype::CPU_TYPE_ARM64)
        .unwrap();
    let bytes = &FILE[arch.offset as usize..(arch.offset + arch.size) as usize];
    let opts = crate::ExtractOptions {
        caller_provides_symbols: true,
        filter_garbage: true,
        ..Default::default()
    };
    let out = crate::extract_strings_with_options(bytes, &opts);
    let found = out
        .iter()
        .find(|s| s.value == PROMPT && s.method == crate::StringMethod::XorDecode)
        .unwrap();
    assert_eq!((found.data_offset, found.data_len), (0x28fa0, 1468));
    let benign = crate::test_fixture("testdata/macho/swift_small_strings_webview.macho");
    let Object::Mach(Mach::Binary(m)) = Object::parse(benign).unwrap() else {
        panic!("benign")
    };
    assert!(super::super::extract_macho(&m, 0, 4).is_empty());
}
#[test]
fn changed_key_bytes_and_preserved_register_assignments_still_decode() {
    let (original, _, _) = code();
    let start = original.at(0x100028fa0).unwrap();
    let mut bytes = original.bytes.to_vec();
    let mut edit = |addr: u64, mask: u32, value: u32| {
        let at = original.at(addr).unwrap();
        let w = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        bytes[at..at + 4].copy_from_slice(&((w & !mask) | value).to_le_bytes());
    };
    // Renumber both heap pointers, loop counter, descriptor and byte temporary.
    for (addr, mask, value) in [
        (0x100028fa8, 31, 26),
        (0x1001ba72c, 31, 27),
        (0x1001ba730, 31, 28),
        (0x10002951c, 31, 19),
        (0x100029520, 0x3ff, (19 << 5) | 19),
        (0x100029524, 0x3e0, 28 << 5),
        (0x10002952c, 0x1f0000, 26 << 16),
        (0x1001ae540, 0x1f0000, 28 << 16),
        (0x1001ae544, 0x1f0000, 19 << 16),
        (0x10002953c, 31, 24),
        (0x100029540, 0x1f0000, 27 << 16),
        (0x1001b8a5c, 0x1f0000, 24 << 16),
        (0x100029554, 0x3ff, (28 << 5) | 28),
    ] {
        edit(addr, mask, value);
    }
    for addr in [0x100028fac, 0x100029268] {
        let at = original.at(addr).unwrap();
        let w = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) ^ (0x5a << 5);
        bytes[at..at + 4].copy_from_slice(&w.to_le_bytes());
    }
    assert_eq!(
        decode(
            &Code {
                bytes: &bytes,
                addr: original.addr
            },
            start,
            4
        )
        .unwrap()
        .0,
        PROMPT
    );
}
fn synthetic_array(len: usize, initializers: &[u32]) -> Vec<u8> {
    let helper = 3 + initializers.len();
    let mut words = vec![
        0x52800000 | ((len as u32) << 5),
        0x94000000 | (helper as u32 - 1),
        0xaa0003f4,
    ];
    words.extend_from_slice(initializers);
    words.extend([0x52800021, 0x14000001, 0xd65f03c0]);
    words.into_iter().flat_map(u32::to_le_bytes).collect()
}
#[test]
fn exact_array_and_initialization_work_limits_are_supported() {
    let mut init = vec![0xd2882828, 0xf2a82828, 0xf2c82828, 0xf2e82828]; // X8 = repeated 0x4141 halves
    for i in 0..MAX_ARRAY / 8 {
        init.push(0xf9000008 | ((i as u32) << 10));
    }
    let bytes = synthetic_array(MAX_ARRAY, &init);
    let a = array(
        &Code {
            bytes: &bytes,
            addr: 0x1000,
        },
        &mut 0,
        4,
        None,
    )
    .unwrap();
    assert_eq!(a.bytes, vec![0x41; MAX_ARRAY]);
    let bytes = synthetic_array(MAX_ARRAY + 1, &init);
    assert!(
        array(
            &Code {
                bytes: &bytes,
                addr: 0x1000
            },
            &mut 0,
            4,
            None
        )
        .is_none()
    );
    let mut init = vec![0x52882828; 15];
    init.push(0xb9000008);
    let bytes = synthetic_array(4, &init);
    assert!(
        array(
            &Code {
                bytes: &bytes,
                addr: 0x1000
            },
            &mut 0,
            4,
            None
        )
        .is_some()
    );
    init.insert(0, 0x52882828);
    let bytes = synthetic_array(4, &init);
    assert!(
        array(
            &Code {
                bytes: &bytes,
                addr: 0x1000
            },
            &mut 0,
            4,
            None
        )
        .is_none()
    );
}
#[test]
fn byte_registers_must_survive_argument_setup_calls_and_return() {
    let (original, _, _) = code();
    let start = original.at(0x100028fa0).unwrap();
    for bad in [0u32, 1, 2, 3, 30, 31] {
        let mut bytes = original.bytes.to_vec();
        for (addr, mask, value) in [(0x10002953c, 31, bad), (0x1001b8a5c, 0x1f0000, bad << 16)] {
            let p = original.at(addr).unwrap();
            let w = original.word(p).unwrap();
            bytes[p..p + 4].copy_from_slice(&((w & !mask) | value).to_le_bytes());
        }
        assert!(
            decode(
                &Code {
                    bytes: &bytes,
                    addr: original.addr
                },
                start,
                4
            )
            .is_none(),
            "key byte register {bad}"
        );
    }
    for bad in [0u32, 30, 31] {
        let mut bytes = original.bytes.to_vec();
        for (addr, mask, value) in [
            (0x1001b8a58, 31, bad),
            (0x1001b8a5c, 0x3ff, (bad << 5) | bad),
            (0x1001b8a60, 31, bad),
        ] {
            let p = original.at(addr).unwrap();
            let w = original.word(p).unwrap();
            bytes[p..p + 4].copy_from_slice(&((w & !mask) | value).to_le_bytes());
        }
        assert!(
            decode(
                &Code {
                    bytes: &bytes,
                    addr: original.addr
                },
                start,
                4
            )
            .is_none(),
            "xor temporary {bad}"
        );
    }
}
