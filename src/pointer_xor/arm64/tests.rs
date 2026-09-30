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
pub(super) fn code() -> Region<'static> {
    let Object::Mach(Mach::Fat(fat)) = Object::parse(*FILE).unwrap() else {
        panic!("fat")
    };
    for arch in fat.iter_arches() {
        let arch = arch.unwrap();
        if arch.cputype != goblin::mach::constants::cputype::CPU_TYPE_ARM64 {
            continue;
        }
        let bytes = &FILE[arch.offset as usize..(arch.offset + arch.size) as usize];
        let Object::Mach(Mach::Binary(m)) = Object::parse(bytes).unwrap() else {
            panic!("thin")
        };
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
    }
    panic!("arm text")
}
pub(super) fn rows() -> Vec<serde_json::Value> {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../testdata/macho/rust_pointer_xor_arm64_expected.json"
    ))
    .unwrap();
    fixture["rows"].as_array().unwrap().clone()
}
pub(super) fn num(row: &serde_json::Value, key: &str) -> u64 {
    u64::from_str_radix(row[key].as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}
#[test]
fn all_596_independently_reconstructed_arm_keys() {
    let code = code();
    let rows = rows();
    assert_eq!(rows.len(), 596);
    for row in rows {
        assert_eq!(
            fold(
                &code,
                num(&row, "helper"),
                num(&row, "base"),
                num(&row, "seed") as u32
            ),
            Some(num(&row, "key")),
            "{row}"
        );
    }
}

fn synthetic(words: &[u32], base: u64, seed: u32) -> Option<u64> {
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    fold(
        &Region {
            addr: 0x1000,
            offset: 0,
            bytes: &bytes,
        },
        0x1000,
        base,
        seed,
    )
}
#[test]
fn every_executed_specimen_instruction_is_required() {
    let original = code();
    let mut bytes = original.bytes.to_vec();
    let mut checked = 0;
    for row in rows() {
        let start = num(&row, "helper");
        let mut pc = start;
        for _ in 0..MAX_STEPS {
            let inst = word(&original, pc).unwrap();
            let at = (pc - original.addr) as usize;
            bytes[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            let modified = Region {
                addr: original.addr,
                offset: original.offset,
                bytes: &bytes,
            };
            assert_eq!(
                fold(
                    &modified,
                    start,
                    num(&row, "base"),
                    num(&row, "seed") as u32
                ),
                None,
                "mutation {pc:x}"
            );
            bytes[at..at + 4].copy_from_slice(&inst.to_le_bytes());
            checked += 1;
            if inst == 0xd65f03c0 {
                break;
            }
            pc = if inst & 0xfc000000 == 0x14000000 {
                pc.checked_add_signed(i64::from(inst & 0x03ffffff) << 38 >> 36)
                    .unwrap()
            } else {
                pc + 4
            };
        }
    }
    assert!(checked > 4000);
}
#[test]
fn wrapping_zero_extension_and_checked_pointer_addition() {
    // MOV W8,#-1; ADD W8,W8,#2; ADD X0,X0,X8; RET.
    let code = [0x12800008, 0x11000908, 0x8b080000, 0xd65f03c0];
    assert_eq!(synthetic(&code, 0x100000000, 0), Some(0x100000001));
    assert_eq!(synthetic(&code, u64::MAX, 0), None);
    // Offset must fit the helpers' final 16-bit domain.
    assert_eq!(synthetic(&[0x12a00008, 0x8b080000, 0xd65f03c0], 0, 0), None);
}
#[test]
fn uninitialized_registers_memory_calls_flags_and_early_returns_rejected() {
    for inst in [
        0x8b080000, 0x72800008, 0x4a090108, 0xf9400008, 0x94000000, 0x31000428, 0xd65f03c0,
        0xd503201f,
    ] {
        assert_eq!(
            synthetic(&[inst, 0x8b080000, 0xd65f03c0], 0x1000, 123),
            None,
            "{inst:x}"
        );
    }
    // Pure arithmetic cannot overwrite the pointer or immutable seed.
    for inst in [0x52800000, 0x52800001, 0x5280001f] {
        assert_eq!(synthetic(&[inst, 0x8b080000, 0xd65f03c0], 0, 0), None);
    }
}
#[test]
fn tails_and_instruction_work_are_bounded() {
    assert_eq!(synthetic(&[0x14000000], 0, 0), None);
    assert_eq!(
        synthetic(
            &[
                0x14000001, 0x14000001, 0x14000001, 0x52800008, 0x8b080000, 0xd65f03c0
            ],
            0,
            0
        ),
        None
    );
    assert_eq!(
        synthetic(
            &[0x14000001, 0x14000001, 0x52800008, 0x8b080000, 0xd65f03c0],
            0,
            0
        ),
        Some(0)
    );
    let mut code = vec![0x52800008; MAX_STEPS - 2];
    code.extend([0x8b080000, 0xd65f03c0]);
    assert_eq!(synthetic(&code, 0, 0), Some(0));
    code.insert(0, 0x52800008);
    assert_eq!(synthetic(&code, 0, 0), None);
}
#[test]
fn truncation_alignment_outside_code_and_address_overflow_rejected() {
    let bytes: Vec<_> = [0x52800028u32, 0x8b080000, 0xd65f03c0]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    for len in 0..bytes.len() {
        assert_eq!(
            fold(
                &Region {
                    addr: 0x1000,
                    offset: 0,
                    bytes: &bytes[..len]
                },
                0x1000,
                0,
                0
            ),
            None
        );
    }
    let region = Region {
        addr: 0x1000,
        offset: 0,
        bytes: &bytes,
    };
    for start in [0, 0xffc, 0x1001, 0x1002, 0x1003, 0x100c, u64::MAX] {
        assert_eq!(fold(&region, start, 0, 0), None);
    }
    assert_eq!(
        fold(
            &Region {
                addr: u64::MAX - 3,
                offset: 0,
                bytes: &bytes
            },
            u64::MAX - 3,
            0,
            0
        ),
        None
    );
}
#[test]
fn logical_immediates_cover_element_sizes_and_reject_reserved_encodings() {
    for (s, want) in [
        (0b111100, 0x55555555),
        (0b111000, 0x11111111),
        (0b110000, 0x01010101),
        (0b100000, 0x00010001),
        (0, 1),
    ] {
        assert_eq!(bitmask(0x12000000 | (s << 10)), Some(want));
    }
    assert_eq!(
        bitmask(0x12000000 | (0b111100 << 10) | (1 << 16)),
        Some(0xaaaaaaaa)
    );
    for s in [31, 47, 55, 59, 61, 62, 63] {
        assert_eq!(bitmask(0x12000000 | (s << 10)), None);
    }
    assert_eq!(bitmask(0x12400000), None);
    // MOV W8,#1 followed by unsupported 32-bit encodings: high shifts,
    // extended ADD, ROR ADD, ANDS, malformed bitfields and EXTR.
    for inst in [
        0x52c00008, 0x0b088108, 0x0bc80108, 0x0b280108, 0x6a080108, 0x4a088108, 0x13407d08,
        0x531f0108, 0x13888008,
    ] {
        assert_eq!(
            synthetic(&[0x52800028, inst, 0x8b080000, 0xd65f03c0], 0, 0),
            None,
            "{inst:x}"
        );
    }
}

#[test]
fn all_596_setups_match_independent_base_helper_and_seed_expressions() {
    let code = code();
    let mut saved = 0;
    for row in rows() {
        let call = num(&row, "call");
        let found = setup(&code, call).unwrap_or_else(|| panic!("setup {call:x}"));
        assert_eq!(found.helper, num(&row, "helper"));
        assert_eq!(found.base, num(&row, "base"));
        assert_eq!(found.after, call + 4);
        match found.seed {
            Seed::Immediate(seed) => assert_eq!(seed, num(&row, "seed") as u32),
            Seed::Saved { register, add } => {
                saved += 1;
                assert_eq!(register, 22);
                // Independent disassembly: MOV W22,#0x76d5; MOVK W22,#0x455b,LSL#16.
                // This test does not claim the setup parser proves register preservation.
                assert_eq!(0x455b76d5u32.wrapping_add(add), num(&row, "seed") as u32);
            }
        }
    }
    assert_eq!(saved, 2);
}

#[test]
fn every_required_setup_and_outlined_store_instruction_rejects_mutation() {
    let original = code();
    let mut bytes = original.bytes.to_vec();
    let mut checked = 0;
    for row in rows() {
        let call = num(&row, "call");
        let found = setup(&original, call).unwrap();
        let back = if matches!(found.seed, Seed::Immediate(_)) {
            36
        } else {
            32
        };
        let mut addresses: Vec<_> = (call - back..=call).step_by(4).collect();
        for pc in addresses.clone() {
            if pc == call {
                continue;
            }
            if let Some(target) = branch_target(&original, pc) {
                for i in 0..4 {
                    let addr = target + i * 4;
                    addresses.push(addr);
                    if word(&original, addr) == Some(0xd65f03c0) {
                        break;
                    }
                }
            }
        }
        for pc in addresses {
            let at = (pc - original.addr) as usize;
            let old = word(&original, pc).unwrap();
            bytes[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            let modified = Region {
                addr: original.addr,
                offset: original.offset,
                bytes: &bytes,
            };
            assert!(
                setup(&modified, call).is_none(),
                "call {call:x}, mutated {pc:x}"
            );
            bytes[at..at + 4].copy_from_slice(&old.to_le_bytes());
            checked += 1;
        }
    }
    assert!(checked > 9000);
}
#[test]
fn setup_truncation_unmapped_helpers_and_unaligned_sites_rejected() {
    let code = code();
    let row = &rows()[0];
    let call = num(row, "call");
    let at = (call - code.addr) as usize;
    for len in at - 36..at + 4 {
        assert!(
            setup(
                &Region {
                    addr: code.addr,
                    offset: 0,
                    bytes: &code.bytes[..len]
                },
                call
            )
            .is_none()
        );
    }
    for site in [0, code.addr, call + 1, call + 2, call + 3, u64::MAX] {
        assert!(setup(&code, site).is_none());
    }
    let mut bytes = code.bytes.to_vec();
    // Maximum forward BL displacement escapes the text region.
    bytes[at..at + 4].copy_from_slice(&0x95ffffffu32.to_le_bytes());
    assert!(
        setup(
            &Region {
                addr: code.addr,
                offset: 0,
                bytes: &bytes
            },
            call
        )
        .is_none()
    );
}
#[test]
fn setup_requires_matching_argument_slots_registers_and_complete_store_helpers() {
    let code = code();
    let call = num(&rows()[0], "call");
    let mut bytes = code.bytes.to_vec();
    for (pc, new) in [
        (call - 4, 0xb940b7e1u32), // seed read from a different slot
        (call - 4, 0xb940b3e2),    // wrong argument register
        (call - 20, 0xf9405fe0),   // base read from a different slot
        (call - 20, 0xf9405be1),   // wrong base argument register
        (call - 32, 0x91000109),   // mismatched ADRP/ADD destination
        (call - 28, 0x9280000a),   // bias in the wrong register
        (call - 16, 0x52800009),   // seed low bits in wrong register
        (call - 12, 0x72800008),   // seed high bits overwrite low half
    ] {
        let at = (pc - code.addr) as usize;
        let old = word(&code, pc).unwrap();
        bytes[at..at + 4].copy_from_slice(&new.to_le_bytes());
        assert!(
            setup(
                &Region {
                    addr: code.addr,
                    offset: 0,
                    bytes: &bytes
                },
                call
            )
            .is_none(),
            "{pc:x}"
        );
        bytes[at..at + 4].copy_from_slice(&old.to_le_bytes());
    }
}

#[test]
fn bounded_signature_scan_finds_all_reviewed_setups() {
    let code = code();
    let found: std::collections::HashSet<_> = setups(&code).map(|s| s.after - 4).collect();
    for row in rows() {
        assert!(found.contains(&num(&row, "call")));
    }
    assert!(found.len() <= super::super::MAX_CANDIDATES);
}
#[test]
fn signature_scan_rejects_noise_and_enforces_code_and_attempt_budgets() {
    for bytes in [
        b"ordinary text without ARM code".as_slice(),
        b"\xe1\xb3\x40\xb9".as_slice(),
        &[],
    ] {
        assert_eq!(
            setups(&Region {
                addr: 0x1000,
                offset: 0,
                bytes
            })
            .count(),
            0
        );
    }
    let oversized = vec![0u8; super::super::MAX_CODE + 1];
    assert_eq!(
        setups(&Region {
            addr: 0,
            offset: 0,
            bytes: &oversized
        })
        .count(),
        0
    );
    let original = code();
    let mut bytes = original.bytes.to_vec();
    // Invalid candidates exhaust the budget too; later valid setups are skipped.
    for i in 0..super::super::MAX_CANDIDATES {
        bytes[i * 4..i * 4 + 4].copy_from_slice(b"\xe1\xb3\x40\xb9");
    }
    assert_eq!(
        setups(&Region {
            addr: original.addr,
            offset: 0,
            bytes: &bytes
        })
        .count(),
        0
    );
    assert_eq!(
        setups(&Region {
            addr: u64::MAX - 3,
            offset: 0,
            bytes: original.bytes
        })
        .count(),
        0
    );
}

#[test]
fn local_saved_seed_requires_adjacent_constant_pair_and_preserved_register() {
    let original = code();
    let rows = rows();
    let mut resolved = 0;
    for row in &rows {
        let found = setup(&original, num(row, "call")).unwrap();
        if let Some(seed) = local_seed(&original, &found) {
            assert_eq!(seed, num(row, "seed") as u32);
            resolved += 1;
        } else {
            assert_eq!(num(row, "call"), 0x10001b610);
        }
    }
    assert_eq!(resolved, 595);
    let found = setup(&original, num(&rows[57], "call")).unwrap();
    let mut bytes = original.bytes.to_vec();
    let call = found.after - 4;
    for (pc, inst) in [
        (call - 40, 0x52800015u32),
        (call - 36, 0x72a00015),
        (call - 36, 0x72800016),
        (call - 40, 0xb9400016),
    ] {
        let at = (pc - original.addr) as usize;
        let old = word(&original, pc).unwrap();
        bytes[at..at + 4].copy_from_slice(&inst.to_le_bytes());
        assert_eq!(
            local_seed(
                &Region {
                    addr: original.addr,
                    offset: 0,
                    bytes: &bytes
                },
                &found
            ),
            None
        );
        bytes[at..at + 4].copy_from_slice(&old.to_le_bytes());
    }
    let ambiguous = Setup {
        seed: Seed::Saved {
            register: 19,
            add: 0,
        },
        ..found
    };
    assert_eq!(local_seed(&original, &ambiguous), None);
}

#[test]
fn all_298_complete_id_loops_match_independent_cipher_reads_and_lengths() {
    let code = code();
    let rows = rows();
    let mut copied = 0;
    let mut frame = 0;
    for i in (1..596).step_by(2) {
        let row = &rows[i];
        let found = loops::read(&code, num(row, "call") + 4).unwrap_or_else(|| panic!("loop {i}"));
        assert_eq!(found.length, 32);
        let reads = row["binary_reads"].as_array().unwrap();
        assert!(
            reads
                .iter()
                .any(|r| num(r, "address") == found.cipher && r["length"] == 8)
        );
        match found.link {
            loops::OutputLink::Copied {
                write_register,
                copy_register,
                delta,
            } => {
                copied += 1;
                assert_eq!((write_register, copy_register, delta), (19, 20, 32));
            }
            loops::OutputLink::Frame => frame += 1,
        }
    }
    assert_eq!((copied, frame), (296, 2));
}

fn constant_bytes(addr: u64, len: usize) -> Vec<u8> {
    let Object::Mach(Mach::Fat(fat)) = Object::parse(*FILE).unwrap() else {
        panic!("fat")
    };
    for arch in fat.iter_arches() {
        let arch = arch.unwrap();
        if arch.cputype != goblin::mach::constants::cputype::CPU_TYPE_ARM64 {
            continue;
        }
        let slice = &FILE[arch.offset as usize..(arch.offset + arch.size) as usize];
        let Object::Mach(Mach::Binary(m)) = Object::parse(slice).unwrap() else {
            panic!("thin")
        };
        for segment in &m.segments {
            for (section, bytes) in segment.sections().unwrap() {
                if !matches!(section.name().ok(), Some("__const" | "__cstring")) {
                    continue;
                }
                if let Some(off) = addr
                    .checked_sub(section.addr)
                    .and_then(|n| usize::try_from(n).ok())
                    && let Some(value) = bytes.get(off..off + len)
                {
                    return value.to_vec();
                }
            }
        }
    }
    panic!("unmapped constant {addr:x}")
}
#[test]
fn recognized_loops_and_native_key_folding_reproduce_all_298_ids() {
    let code = code();
    let rows = rows();
    for i in (1..596).step_by(2) {
        let row = &rows[i];
        let setup = setup(&code, num(row, "call")).unwrap();
        let literal = loops::read(&code, setup.after).unwrap();
        // One seed still requires caller preservation proof. This test separates
        // arithmetic and loop decoding from that explicitly pending integration.
        let seed = local_seed(&code, &setup).unwrap_or_else(|| {
            assert_eq!(i, 91);
            num(row, "seed") as u32
        });
        let key = fold(&code, setup.helper, setup.base, seed).unwrap();
        let decoded: Vec<_> = constant_bytes(literal.cipher, literal.length)
            .into_iter()
            .zip(constant_bytes(key, literal.length))
            .map(|(a, b)| a ^ b)
            .collect();
        assert_eq!(decoded, row["text"].as_str().unwrap().as_bytes(), "row {i}");
    }
}
#[test]
fn every_required_loop_and_outline_instruction_rejects_mutation() {
    let original = code();
    let mut bytes = original.bytes.to_vec();
    let mut checked = 0;
    for i in (1..596).step_by(2) {
        let rows = rows();
        let start = num(&rows[i], "call") + 4;
        let inline = word(&original, start) == Some(0x6f00e400);
        let length = if inline { 72 } else { 40 };
        let mut addresses: Vec<_> = (start..start + length).step_by(4).collect();
        for pc in addresses.clone() {
            // Final inline BL is the consumer, not an outlined decoder helper.
            if inline && pc == start + 68 {
                continue;
            }
            if let Some(target) = branch_target(&original, pc) {
                for j in 0..8 {
                    let addr = target + j * 4;
                    addresses.push(addr);
                    let inst = word(&original, addr).unwrap();
                    if inst == 0xd65f03c0 || inst & 0xfc000000 == 0x14000000 {
                        break;
                    }
                }
            }
        }
        for pc in addresses {
            let at = (pc - original.addr) as usize;
            let old = word(&original, pc).unwrap();
            bytes[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            assert!(
                loops::read(
                    &Region {
                        addr: original.addr,
                        offset: 0,
                        bytes: &bytes
                    },
                    start
                )
                .is_none(),
                "loop {i}, mutation {pc:x}"
            );
            bytes[at..at + 4].copy_from_slice(&old.to_le_bytes());
            checked += 1;
        }
    }
    assert!(checked > 9000);
}

#[test]
fn loops_reject_wrong_xor_bounds_branches_copy_slots_and_consumer_lengths() {
    let original = code();
    let rows = rows();
    let start = num(&rows[1], "call") + 4;
    let body = branch_target(&original, start + 24).unwrap();
    let compare = branch_target(&original, start + 16).unwrap();
    let copy = branch_target(&original, start + 32).unwrap();
    let consumer = branch_target(&original, start + 36).unwrap();
    let mut bytes = original.bytes.to_vec();
    for (pc, replacement) in [
        (body + 8, 0xaa0a016au32),  // ORR instead of EOR
        (body + 20, 0x91001129),    // advance output by four, not eight
        (body + 24, 0x91001108),    // advance ciphertext by four
        (compare + 4, 0xf1009d5f),  // extra qword beyond the 32-byte output
        (compare + 4, 0xf1005d5f),  // incomplete 24-byte decode
        (start + 20, 0x54000069),   // wrong unsigned condition
        (start + 28, 0x17fffffe),   // wrong back edge
        (consumer + 8, 0x52800302), // 24-byte consumer
        (consumer + 8, 0x52800802), // 64-byte consumer
        (consumer + 4, 0x9100c3e1), // consumer reads another stack slot
        (copy + 4, 0xad0187e0),     // copy writes another stack slot
        (copy, 0xad418680),         // copy reads another source slot
    ] {
        let at = (pc - original.addr) as usize;
        let old = word(&original, pc).unwrap();
        bytes[at..at + 4].copy_from_slice(&replacement.to_le_bytes());
        assert!(
            loops::read(
                &Region {
                    addr: original.addr,
                    offset: 0,
                    bytes: &bytes
                },
                start
            )
            .is_none(),
            "{pc:x}"
        );
        bytes[at..at + 4].copy_from_slice(&old.to_le_bytes());
    }
}
#[test]
fn inline_loops_require_same_frame_buffer_and_exact_consumer_length() {
    let original = code();
    let start = num(&rows()[593], "call") + 4;
    let mut bytes = original.bytes.to_vec();
    for (pc, replacement) in [
        (start + 60, 0xd10283a1u32),
        (start + 40, 0xaa0b018b),
        (start + 64, 0x528003e2),
        (start + 52, 0x17fffffa),
        (start + 28, 0x540000c8),
    ] {
        let at = (pc - original.addr) as usize;
        let old = word(&original, pc).unwrap();
        bytes[at..at + 4].copy_from_slice(&replacement.to_le_bytes());
        assert!(
            loops::read(
                &Region {
                    addr: original.addr,
                    offset: 0,
                    bytes: &bytes
                },
                start
            )
            .is_none(),
            "{pc:x}"
        );
        bytes[at..at + 4].copy_from_slice(&old.to_le_bytes());
    }
}
#[test]
fn loops_fail_closed_on_truncation_alignment_and_address_overflow() {
    let original = code();
    let rows = rows();
    for ordinal in [1, 593, 595] {
        let start = num(&rows[ordinal], "call") + 4;
        let at = (start - original.addr) as usize;
        let length = if ordinal == 1 { 40 } else { 72 };
        for len in at..at + length {
            assert!(
                loops::read(
                    &Region {
                        addr: original.addr,
                        offset: 0,
                        bytes: &original.bytes[..len]
                    },
                    start
                )
                .is_none()
            );
        }
        for bad in [start + 1, start + 2, start + 3, u64::MAX, u64::MAX - 3, 0] {
            assert!(loops::read(&original, bad).is_none());
        }
    }
}

pub(super) fn arm_slice() -> (&'static [u8], u64) {
    let Object::Mach(Mach::Fat(fat)) = Object::parse(*FILE).unwrap() else {
        panic!("fat")
    };
    let arch = fat
        .iter_arches()
        .map(Result::unwrap)
        .find(|a| a.cputype == goblin::mach::constants::cputype::CPU_TYPE_ARM64)
        .unwrap();
    (
        &FILE[arch.offset as usize..(arch.offset + arch.size) as usize],
        arch.offset.into(),
    )
}
#[test]
fn runtime_arm_extraction_preserves_exact_thin_and_fat_spans() {
    let (bytes, slice_base) = arm_slice();
    let Object::Mach(Mach::Binary(m)) = Object::parse(bytes).unwrap() else {
        panic!("arm")
    };
    let plain = super::super::extract_macho(&m, 0, 4);
    let fat = super::super::extract_macho(&m, slice_base, 4);
    assert_eq!(plain.len(), 383); // 297 IDs and 86 immediate/short-tail names.
    assert_eq!(fat.len(), 383);
    let rows = rows();
    for (a, b) in plain.iter().zip(&fat) {
        assert_eq!(a.value, b.value);
        assert_eq!(a.data_offset + slice_base, b.data_offset);
    }
    for i in (1..596).step_by(2).filter(|i| *i != 91) {
        let row = &rows[i];
        let key = num(row, "key");
        let cipher = row["binary_reads"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| num(r, "address"))
            .filter(|a| !(*a >= key && *a < key + 32))
            .min()
            .unwrap();
        let out = plain
            .iter()
            .find(|s| {
                s.value == row["text"].as_str().unwrap() && s.data_offset == cipher - 0x100000000
            })
            .unwrap();
        assert_eq!(out.data_offset, cipher - 0x100000000);
        assert_eq!(out.data_len, 32);
        assert_eq!(out.method, crate::StringMethod::XorDecode);
    }
    assert!(super::super::extract_macho(&m, 0, 33).is_empty());
    assert!(super::super::extract_macho(&m, u64::MAX, 4).is_empty());
}
#[test]
fn runtime_rejects_missing_constants_and_bad_text_without_suppressing_other_literals() {
    let code = code();
    assert!(extract(&code, &[], 0, 4).is_empty());
    let (bytes, _) = arm_slice();
    let mut changed = bytes.to_vec();
    let rows = rows();
    for i in [593, 595] {
        let row = &rows[i];
        let key = num(row, "key");
        let cipher = row["binary_reads"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| num(r, "address"))
            .filter(|a| !(*a >= key && *a < key + 32))
            .min()
            .unwrap();
        // First byte becomes invalid UTF-8, second case an embedded NUL.
        changed[(cipher - 0x100000000) as usize] =
            changed[(key - 0x100000000) as usize] ^ if i == 593 { 0xff } else { 0 };
    }
    let Object::Mach(Mach::Binary(m)) = Object::parse(&changed).unwrap() else {
        panic!("arm")
    };
    // Other fully determined XOR literals remain available. The unresolved
    // saved-register seed is still deferred rather than guessed.
    let out = super::super::extract_macho(&m, 0, 4);
    assert_eq!(out.len(), 381); // Two corrupted IDs; 86 names remain.
    for i in [91, 593, 595] {
        assert!(
            !out.iter()
                .any(|s| s.value == rows[i]["text"].as_str().unwrap())
        );
    }
}
#[test]
fn public_pipeline_recovers_297_arm_ids_without_an_x86_slice() {
    let (bytes, _) = arm_slice();
    let opts = crate::ExtractOptions {
        use_cache: false,
        caller_provides_symbols: true,
        filter_garbage: true,
        ..Default::default()
    };
    let out = crate::extract_strings_with_options(bytes, &opts);
    let rows = rows();
    for i in (1..596).step_by(2).filter(|i| *i != 91) {
        assert!(
            out.iter()
                .any(|s| s.value == rows[i]["text"].as_str().unwrap()
                    && s.method == crate::StringMethod::XorDecode)
        );
    }
}
#[test]
fn benign_swift_webview_has_no_pointer_xor_matches() {
    let bytes = crate::test_fixture("testdata/macho/swift_small_strings_webview.macho");
    let Object::Mach(Mach::Binary(m)) = Object::parse(bytes).unwrap() else {
        panic!("thin benign")
    };
    assert!(super::super::extract_macho(&m, 0, 4).is_empty());
}
