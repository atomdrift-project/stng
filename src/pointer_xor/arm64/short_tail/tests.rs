#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]
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
fn original_68_names_match_independent_oracle() {
    let code = code();
    let constants = constants();
    let (_, base) = arm_slice();
    let mut count = 0;
    for row in rows()
        .iter()
        .filter(|r| (9..=11).contains(&r["length"].as_u64().unwrap()))
    {
        let setup = super::super::setup(&code, num(row, "call")).unwrap();
        let out =
            extract(&code, &constants, &setup, 0, 4).unwrap_or_else(|| panic!("missing {row}"));
        assert_eq!(out.value, row["text"].as_str().unwrap());
        assert_eq!(
            out.data_offset,
            num(row, "call") + 4 - code.addr + code.offset
        );
        assert!((48..=128).contains(&out.data_len));
        let fat = extract(&code, &constants, &setup, base, 4).unwrap();
        assert_eq!(fat.data_offset, out.data_offset + base);
        assert_eq!(fat.data_len, out.data_len);
        count += 1;
    }
    assert_eq!(count, 68);
}
fn traces() -> Vec<serde_json::Value> {
    serde_json::from_slice::<serde_json::Value>(crate::test_fixture(
        "testdata/macho/rust_arm64_short_tail_expected.json",
    ))
    .unwrap()["rows"]
        .as_array()
        .unwrap()
        .clone()
}
#[test]
fn exact_independent_main_spans_and_all_executed_instructions() {
    let original = code();
    let constants = constants();
    let rows = rows();
    let mut bytes = original.bytes.to_vec();
    for trace in traces() {
        let row = &rows[trace["ordinal"].as_u64().unwrap() as usize];
        let setup = super::super::setup(&original, num(row, "call")).unwrap();
        assert_eq!(
            extract(&original, &constants, &setup, 0, 4)
                .unwrap()
                .data_len,
            u32::try_from(trace["span"].as_u64().unwrap()).unwrap()
        );
        for pc in trace["instructions"].as_array().unwrap() {
            let pc =
                u64::from_str_radix(pc.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
            let at = (pc - original.addr) as usize;
            bytes[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            assert!(
                extract(
                    &Region {
                        bytes: &bytes,
                        ..original
                    },
                    &constants,
                    &setup,
                    0,
                    4
                )
                .is_none(),
                "ordinal {} pc {pc:x}",
                row["ordinal"]
            );
            bytes[at..at + 4].copy_from_slice(&original.bytes[at..at + 4]);
        }
    }
}
#[test]
fn rejects_incomplete_keys_bad_text_and_bad_addresses() {
    let code = code();
    let constants = constants();
    let rows = rows();
    let row = &rows[8];
    let setup = super::super::setup(&code, num(row, "call")).unwrap();
    assert!(extract(&code, &[], &setup, 0, 4).is_none());
    assert!(extract(&code, &constants, &setup, u64::MAX, 4).is_none());
    assert!(extract(&code, &constants, &setup, 0, 11).is_none());
    for start in [
        setup.after + 1,
        setup.after + 2,
        setup.after + 3,
        u64::MAX,
        u64::MAX - 3,
    ] {
        assert!(prefix(&code, &constants, start).is_none());
    }
    let key = num(row, "key");
    let (bytes, _) = arm_slice();
    for bad in [0, 255] {
        let mut changed = bytes.to_vec();
        let at = (key - 0x100000000 + 9) as usize;
        changed[at] ^= row["text"].as_str().unwrap().as_bytes()[9] ^ bad;
        let regions: Vec<_> = constants
            .iter()
            .map(|r| Region {
                bytes: &changed[r.offset as usize..r.offset as usize + r.bytes.len()],
                ..*r
            })
            .collect();
        assert!(extract(&code, &regions, &setup, 0, 4).is_none());
    }
    let key_bytes = constants.iter().find_map(|r| r.at(key, 10)).unwrap();
    let encoded_byte = num(&row["binary_reads"][1], "address");
    let byte = constants
        .iter()
        .find_map(|r| r.at(encoded_byte, 1))
        .unwrap();
    let regions = [
        Region {
            addr: key,
            offset: 0,
            bytes: &key_bytes[..9],
        },
        Region {
            addr: encoded_byte,
            offset: 0,
            bytes: byte,
        },
    ];
    assert!(extract(&code, &regions, &setup, 0, 4).is_none());
}
fn synthetic(padding: usize, change: Option<(usize, u32)>) -> Option<(Vec<u8>, u32)> {
    let mut words = vec![0u32; 256];
    words[0] = 0x94000040;
    for word in &mut words[64..64 + padding] {
        *word = 0x52800009;
    }
    let body = [
        0xf9405be8, 0xf9003be8, 0x52800728, 0x3901e3e8, 0x910243e0, 0x9101c3e1, 0x52800122,
        0x94000001,
    ];
    words[64 + padding..72 + padding].copy_from_slice(&body);
    if let Some((at, w)) = change {
        words[at] = w;
    }
    let bytes: Vec<_> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    tail(
        &Region {
            addr: 0x1000,
            offset: 0,
            bytes: &bytes,
        },
        &[],
        0x1000,
        0x1000,
        0,
        u64::from_le_bytes(*b"12345678"),
        8,
    )
}
#[test]
fn exact_instruction_budget_and_nested_call_limit() {
    assert_eq!(synthetic(55, None).unwrap().0, b"123456789");
    assert!(synthetic(56, None).is_none());
    assert!(synthetic(0, Some((64, 0x94000000))).is_none()); // recursive helper
    assert!(synthetic(0, Some((64, 0xd65f03c0))).is_none()); // premature return
}
#[test]
fn rejects_unknown_registers_wrong_merges_and_incomplete_output() {
    for (at, w) in [
        (64, 0xf9405bec),
        (65, 0xf9003be9),
        (65, 0xf9005be8), // Output overlaps the source qword.
        (69, 0x910243e1), // Consumer points to a different output buffer.
        (67, 0x3901e7e8),
        (70, 0x52800142),
        (68, 0x91024000),
    ] {
        assert!(synthetic(0, Some((at, w))).is_none(), "{at}");
    }
    assert!(synthetic(0, Some((64, 0x14000000))).is_none());
    assert_eq!(
        synthetic(0, Some((68, 0x910083e0))).unwrap().0,
        b"123456789"
    );
    let original = code();
    let constants = constants();
    let row = &rows()[8];
    let setup = super::super::setup(&original, num(row, "call")).unwrap();
    let mut bytes = original.bytes.to_vec();
    // A nonzero BFXIL rotate must not be folded as the low-byte merge.
    let pc = 0x1001a70a0;
    let at = (pc - original.addr) as usize;
    let w = word(&original, pc).unwrap() | (1 << 16);
    bytes[at..at + 4].copy_from_slice(&w.to_le_bytes());
    assert!(
        extract(
            &Region {
                bytes: &bytes,
                ..original
            },
            &constants,
            &setup,
            0,
            4
        )
        .is_none()
    );
}
#[test]
fn public_arm_only_pipeline_and_changed_key_bytes() {
    let (bytes, _) = arm_slice();
    let options = crate::ExtractOptions {
        caller_provides_symbols: true,
        filter_garbage: true,
        ..Default::default()
    };
    let out = crate::extract_strings_with_options(bytes, &options);
    for row in rows()
        .iter()
        .filter(|r| (9..=11).contains(&r["length"].as_u64().unwrap()))
    {
        assert!(out.iter().any(|s| s.value == row["text"].as_str().unwrap()
            && s.method == crate::StringMethod::XorDecode));
    }
    let original = code();
    let constants = constants();
    let row = &rows()[8];
    let setup = super::super::setup(&original, num(row, "call")).unwrap();
    let mut changed = bytes.to_vec();
    changed[(num(row, "key") - 0x100000000 + 9) as usize] ^= 1;
    let regions: Vec<_> = constants
        .iter()
        .map(|r| Region {
            bytes: &changed[r.offset as usize..r.offset as usize + r.bytes.len()],
            ..*r
        })
        .collect();
    assert_eq!(
        extract(&original, &regions, &setup, 0, 4).unwrap().value,
        "MathWalleu"
    );
}
#[test]
fn original_nine_small_names_and_public_pipeline() {
    let code = code();
    let constants = constants();
    let (bytes, base) = arm_slice();
    let options = crate::ExtractOptions {
        caller_provides_symbols: true,
        filter_garbage: true,
        ..Default::default()
    };
    let public = crate::extract_strings_with_options(bytes, &options);
    let mut count = 0;
    for row in rows()
        .iter()
        .filter(|r| (5..=7).contains(&r["length"].as_u64().unwrap()))
    {
        let setup = super::super::setup(&code, num(row, "call")).unwrap();
        let a = extract(&code, &constants, &setup, 0, 4).unwrap_or_else(|| panic!("{row}"));
        let b = extract(&code, &constants, &setup, base, 4).unwrap();
        assert_eq!(a.value, row["text"].as_str().unwrap());
        assert_eq!(
            a.data_offset,
            num(row, "call") + 4 - code.addr + code.offset
        );
        assert_eq!(a.data_offset + base, b.data_offset);
        assert!(
            public
                .iter()
                .any(|s| s.value == a.value && s.method == crate::StringMethod::XorDecode)
        );
        assert!(extract(&code, &constants, &setup, 0, a.value.len() + 1).is_none());
        count += 1;
    }
    assert_eq!(count, 9);
}
#[test]
fn small_names_reject_bad_key_bytes_and_instruction_width_changes() {
    let original = code();
    let constants = constants();
    let (bytes, _) = arm_slice();
    for row in rows()
        .iter()
        .filter(|r| (5..=7).contains(&r["length"].as_u64().unwrap()))
    {
        let setup = super::super::setup(&original, num(row, "call")).unwrap();
        let n = row["length"].as_u64().unwrap() as usize;
        for bad in [0, 255] {
            let mut data = bytes.to_vec();
            let at = (num(row, "key") - 0x100000000) as usize + n - 1;
            data[at] ^= row["text"].as_str().unwrap().as_bytes()[n - 1] ^ bad;
            let regions: Vec<_> = constants
                .iter()
                .map(|r| Region {
                    bytes: &data[r.offset as usize..r.offset as usize + r.bytes.len()],
                    ..*r
                })
                .collect();
            assert!(extract(&original, &regions, &setup, 0, 4).is_none());
        }
    }
    let setup = super::super::setup(&original, num(&rows()[26], "call")).unwrap();
    for (pc, w) in [
        (0x1001a6fd4, 0xf869680du32),
        (0x100019b6c, 0x53103d08 | (1 << 22)),
        (0x1001b5658, 0x4a484168 | (1 << 23)),
        (0x1001b565c, 0x39008fe8),
    ] {
        let mut data = original.bytes.to_vec();
        let at = (pc - original.addr) as usize;
        data[at..at + 4].copy_from_slice(&w.to_le_bytes());
        assert!(
            extract(
                &Region {
                    bytes: &data,
                    ..original
                },
                &constants,
                &setup,
                0,
                4
            )
            .is_none()
        );
    }
    let setup = super::super::setup(&original, num(&rows()[12], "call")).unwrap();
    let mut data = original.bytes.to_vec();
    let at = (0x1001adf48 - original.addr) as usize;
    data[at..at + 4].copy_from_slice(&0xf9405beau32.to_le_bytes());
    assert!(
        extract(
            &Region {
                bytes: &data,
                ..original
            },
            &constants,
            &setup,
            0,
            4
        )
        .is_none()
    );
}
#[test]
fn shifted_tail_arithmetic_obeys_32_bit_width() {
    let words = [
        0xf9405be8u32,
        0xf9003be8,
        0x52800728,
        0x72b00008,
        0x531f7908,
        0x4a4807e8,
        0x3901e3e8,
        0x910243e0,
        0x9101c3e1,
        0x52800122,
        0x94000001,
        0xd503201f,
    ];
    let bytes: Vec<_> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let code = Region {
        addr: 0x1000,
        offset: 0,
        bytes: &bytes,
    };
    assert_eq!(
        tail(
            &code,
            &[],
            0x1000,
            0x1000,
            0,
            u64::from_le_bytes(*b"12345678"),
            8
        )
        .unwrap()
        .0,
        b"123456789"
    );
    for (at, word) in [
        (4, 0x533f7908u32),
        (5, 0x4a4807e8 | (1 << 15)),
        (5, 0x4a4807e8 | (1 << 23)),
    ] {
        let mut changed = bytes.clone();
        changed[at * 4..at * 4 + 4].copy_from_slice(&word.to_le_bytes());
        assert!(
            tail(
                &Region {
                    bytes: &changed,
                    ..code
                },
                &[],
                0x1000,
                0x1000,
                0,
                u64::from_le_bytes(*b"12345678"),
                8
            )
            .is_none()
        );
    }
}
