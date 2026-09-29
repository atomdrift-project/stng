#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::super::tests::{arm_slice, code, num, rows};
use super::*;
use goblin::{Object, mach::Mach};
fn constants() -> Vec<Region<'static>> {
    let (bytes, _) = arm_slice();
    let Object::Mach(Mach::Binary(m)) = Object::parse(bytes).unwrap() else {
        panic!("arm")
    };
    m.segments
        .iter()
        .flat_map(|s| s.sections().unwrap())
        .filter_map(|(s, b)| {
            matches!(s.name().ok(), Some("__const" | "__cstring")).then_some(Region {
                addr: s.addr,
                offset: s.offset.into(),
                bytes: b,
            })
        })
        .collect()
}
#[test]
fn original_names_and_thin_fat_instruction_spans() {
    let code = code();
    let constants = constants();
    let (_, base) = arm_slice();
    let mut count = 0;
    for row in rows().iter().filter(|r| r["length"] == 8) {
        let setup = super::super::setup(&code, num(row, "call")).unwrap();
        let thin = extract(&code, &constants, &setup, 0, 4).unwrap();
        let fat = extract(&code, &constants, &setup, base, 4).unwrap();
        assert_eq!(thin.value, row["text"].as_str().unwrap());
        assert_eq!(
            thin.data_offset,
            num(row, "call") + 4 - code.addr + code.offset
        );
        assert_eq!(thin.data_len, 48);
        assert_eq!(fat.data_offset, thin.data_offset + base);
        assert_eq!(thin.method, crate::StringMethod::XorDecode);
        count += 1;
    }
    assert_eq!(count, 9);
}
#[test]
fn every_main_and_helper_instruction_is_required() {
    let original = code();
    let constants = constants();
    let row = &rows()[0];
    let start = num(row, "call") + 4;
    let mut addresses: Vec<_> = (start..start + 48).step_by(4).collect();
    for (at, n) in [(start, 4), (start + 32, 7), (start + 44, 4)] {
        let target = branch_target(&original, at).unwrap();
        addresses.extend((target..target + n * 4).step_by(4));
    }
    let mut bytes = original.bytes.to_vec();
    for pc in addresses {
        let at = (pc - original.addr) as usize;
        bytes[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        let changed = Region {
            bytes: &bytes,
            ..original
        };
        assert!(read(&changed, &constants, start).is_none(), "{pc:x}");
        bytes[at..at + 4].copy_from_slice(&original.bytes[at..at + 4]);
    }
}
#[test]
fn rejects_wrong_loop_flags_offsets_lengths_and_widths() {
    let original = code();
    let constants = constants();
    let start = num(&rows()[0], "call") + 4;
    let init = branch_target(&original, start).unwrap();
    let body = branch_target(&original, start + 32).unwrap();
    let consumer = branch_target(&original, start + 44).unwrap();
    for (pc, w) in [
        (init + 8, 0x52800009u32),
        (body, 0x52800029),
        (body + 4, 0xf86d6808),
        (body + 12, 0xaa09018c),
        (body + 16, 0xaa080188),
        (start + 4, 0x5280000a),
        (start + 8, 0xf2c0000a),
        (start + 28, 0x36000089),
        (start + 36, 0x3707ffc9),
        (start + 40, 0xf9003fe8),
        (consumer + 4, 0x9101e3e1),
        (consumer + 8, 0x52800122),
    ] {
        let mut bytes = original.bytes.to_vec();
        let at = (pc - original.addr) as usize;
        bytes[at..at + 4].copy_from_slice(&w.to_le_bytes());
        assert!(
            read(
                &Region {
                    bytes: &bytes,
                    ..original
                },
                &constants,
                start
            )
            .is_none(),
            "{pc:x}"
        );
    }
}
#[test]
fn missing_regions_bad_text_truncation_and_overflow_reject() {
    let original = code();
    let constants = constants();
    let row = &rows()[0];
    let setup = super::super::setup(&original, num(row, "call")).unwrap();
    let start = setup.after;
    assert!(read(&original, &[], start).is_none());
    assert!(extract(&original, &constants, &setup, 0, 9).is_none());
    assert!(extract(&original, &constants, &setup, u64::MAX, 4).is_none());
    for pc in [0, start + 1, start + 2, start + 3, u64::MAX, u64::MAX - 3] {
        assert!(read(&original, &constants, pc).is_none());
    }
    for len in (start - original.addr) as usize..(start - original.addr) as usize + 48 {
        assert!(
            read(
                &Region {
                    bytes: &original.bytes[..len],
                    ..original
                },
                &constants,
                start
            )
            .is_none()
        );
    }
    let encoded = read(&original, &constants, start).unwrap();
    let key = num(row, "key");
    for bad in [0, 0xff] {
        let (bytes, _) = arm_slice();
        let mut altered = bytes.to_vec();
        altered[(key - 0x100000000) as usize] = encoded[0] ^ bad;
        let regions: Vec<_> = constants
            .iter()
            .map(|r| Region {
                bytes: &altered[r.offset as usize..r.offset as usize + r.bytes.len()],
                ..*r
            })
            .collect();
        assert!(extract(&original, &regions, &setup, 0, 4).is_none());
    }
}
#[test]
fn changed_immediates_and_key_bytes_are_decoded_without_plaintext_assumptions() {
    let original = code();
    let constants = constants();
    let row = &rows()[0];
    let setup = super::super::setup(&original, num(row, "call")).unwrap();
    let mut bytes = original.bytes.to_vec();
    let at = (setup.after + 4 - original.addr) as usize;
    let w = word(&original, setup.after + 4).unwrap() ^ (1 << 13); // ciphertext byte one
    bytes[at..at + 4].copy_from_slice(&w.to_le_bytes());
    let changed = Region {
        bytes: &bytes,
        ..original
    };
    assert_eq!(
        extract(&changed, &constants, &setup, 0, 4).unwrap().value,
        "Tsonlink"
    );
    let (thin, _) = arm_slice();
    let mut data = thin.to_vec();
    data[(num(row, "key") - 0x100000000) as usize + 1] ^= 1;
    let regions: Vec<_> = constants
        .iter()
        .map(|r| Region {
            bytes: &data[r.offset as usize..r.offset as usize + r.bytes.len()],
            ..*r
        })
        .collect();
    assert_eq!(
        extract(&changed, &regions, &setup, 0, 4).unwrap().value,
        "Tronlink"
    );
}
#[test]
fn public_arm_only_pipeline_recovers_all_reviewed_qword_names() {
    let (bytes, _) = arm_slice();
    let options = crate::ExtractOptions {
        use_cache: false,
        caller_provides_symbols: true,
        filter_garbage: true,
        ..Default::default()
    };
    let output = crate::extract_strings_with_options(bytes, &options);
    for row in rows().iter().filter(|r| r["length"] == 8) {
        assert!(
            output
                .iter()
                .any(|s| s.value == row["text"].as_str().unwrap()
                    && s.method == crate::StringMethod::XorDecode
                    && s.data_offset == num(row, "call") + 4 - 0x100000000)
        );
    }
}
