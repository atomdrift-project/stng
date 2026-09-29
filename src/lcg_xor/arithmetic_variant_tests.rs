#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use goblin::{Object, mach::Mach};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
struct Specimen {
    kind: String,
    file: String,
    sha256: String,
    stages: Vec<Stage>,
}
#[derive(Deserialize)]
struct Stage {
    name: String,
    sha256: String,
    length: usize,
    offset: u64,
    span: u32,
}
fn specimens() -> Vec<Specimen> {
    serde_json::from_str(include_str!(
        "../../testdata/macho/arithmetic_variants_expected.json"
    ))
    .unwrap()
}
fn data(s: &Specimen) -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/macho")
            .join(&s.file),
    )
    .unwrap()
}
fn slice(data: &[u8]) -> &[u8] {
    let Object::Mach(Mach::Fat(fat)) = Object::parse(data).unwrap() else {
        panic!("fat")
    };
    let a = fat
        .arches()
        .unwrap()
        .into_iter()
        .find(|a| a.cputype == goblin::mach::constants::cputype::CPU_TYPE_X86_64)
        .unwrap();
    assert_eq!(a.offset, 4096);
    &data[a.offset as usize..(a.offset + a.size) as usize]
}
fn parsed(data: &[u8]) -> MachO<'_> {
    let Object::Mach(Mach::Binary(m)) = Object::parse(data).unwrap() else {
        panic!("thin")
    };
    m
}
fn hash(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}
fn check(out: &[ExtractedString], s: &Specimen, base: u64) {
    for stage in &s.stages {
        let got = out
            .iter()
            .find(|v| {
                hash(v.value.as_bytes()) == stage.sha256
                    && v.data_offset == stage.offset - 4096 + base
            })
            .unwrap_or_else(|| panic!("{} {} missing exact stage", s.file, stage.name));
        assert_eq!(got.value.len(), stage.length);
        assert_eq!(got.data_len, stage.span);
        assert_eq!(got.method, StringMethod::Base64ObfuscatedDecode);
    }
}
fn instructions(m: &MachO<'_>) -> Vec<Instruction> {
    for seg in &m.segments {
        for (sec, bytes) in seg.sections().unwrap() {
            if sec.name().ok() == Some("__text") {
                return Decoder::with_ip(64, bytes, sec.addr, DecoderOptions::NONE)
                    .into_iter()
                    .filter(|i| i.mnemonic() != Mnemonic::Nop)
                    .collect();
            }
        }
    }
    panic!("text")
}
fn width(kind: &str) -> usize {
    match kind {
        "dispatch" => 33,
        "permuted" => 18,
        "four" => 15,
        _ => panic!("kind"),
    }
}
fn recognize(kind: &str, ins: &[Instruction]) -> Option<ArithmeticTables> {
    match kind {
        "dispatch" => {
            arithmetic_state_machine_loop(ins).map(|(addresses, length)| ArithmeticTables {
                addresses,
                length,
                subtract_address: None,
                permutation: None,
                literal_tail: None,
            })
        }
        "permuted" => arithmetic_permuted_table_loop(ins),
        "four" => arithmetic_four_table_loop(ins),
        _ => panic!("kind"),
    }
}
fn loops<'a>(kind: &str, ins: &'a [Instruction]) -> Vec<&'a [Instruction]> {
    ins.windows(width(kind))
        .filter(|s| recognize(kind, s).is_some())
        .collect()
}
fn file_offset(m: &MachO<'_>, addr: u64) -> usize {
    for seg in &m.segments {
        for (s, bytes) in seg.sections().unwrap() {
            if s.name().ok() == Some("__const")
                && addr >= s.addr
                && addr - s.addr < bytes.len() as u64
            {
                return s.offset as usize + (addr - s.addr) as usize;
            }
        }
    }
    panic!("constant outside sections")
}
#[test]
fn original_hashes_all_variant_stages_and_source_ranges() {
    for s in specimens() {
        let raw = data(&s);
        assert_eq!(hash(&raw), s.sha256);
        let thin = slice(&raw);
        let m = parsed(thin);
        for base in [0, 4096] {
            let out = extract_macho_arithmetic_strings(&m, base, 4);
            assert_eq!(out.len(), 3);
            check(&out, &s, base);
        }
    }
}
#[test]
fn public_pipeline_retains_stages_for_all_five_specimens() {
    let options = crate::ExtractOptions {
        use_cache: false,
        caller_provides_symbols: true,
        ..Default::default()
    };
    for s in specimens() {
        let raw = data(&s);
        check(
            &crate::extract_strings_with_options(&raw, &options),
            &s,
            4096,
        );
        check(
            &crate::extract_strings_with_options(slice(&raw), &options),
            &s,
            0,
        );
    }
}
#[test]
fn all_recognized_setup_and_loop_instructions_are_required() {
    for s in specimens() {
        let raw = data(&s);
        let m = parsed(slice(&raw));
        let ins = instructions(&m);
        let blocks = loops(&s.kind, &ins);
        assert!(blocks.len() >= 4, "{}", s.file);
        for block in blocks {
            for pos in 0..block.len() {
                let mut changed = block.to_vec();
                changed[pos].set_code(iced_x86::Code::Nopd);
                assert!(
                    recognize(&s.kind, &changed).is_none(),
                    "{} instruction {}",
                    s.file,
                    pos
                );
            }
        }
    }
}
#[test]
fn altered_loop_bounds_and_branch_targets_are_rejected() {
    for s in specimens() {
        let raw = data(&s);
        let m = parsed(slice(&raw));
        let ins = instructions(&m);
        for block in loops(&s.kind, &ins) {
            for (i, original) in block.iter().enumerate() {
                if original.op0_kind() == OpKind::NearBranch64
                    && original.mnemonic() != Mnemonic::Call
                {
                    let mut changed = block.to_vec();
                    changed[i].set_near_branch64(original.near_branch_target() + 1);
                    assert!(
                        recognize(&s.kind, &changed).is_none(),
                        "{} branch {i}",
                        s.file
                    );
                }
            }
            let index = match s.kind.as_str() {
                "dispatch" => 8,
                "permuted" => 16,
                _ => 13,
            };
            for value in [0, 3, 0x200003, u32::MAX] {
                let mut changed = block.to_vec();
                changed[index].set_immediate32(value);
                assert!(
                    recognize(&s.kind, &changed).is_none(),
                    "{} bound {value}",
                    s.file
                );
            }
        }
    }
}
#[test]
fn duplicate_negative_and_out_of_range_permutation_entries_reject_stage() {
    for s in specimens().into_iter().filter(|s| s.kind != "dispatch") {
        let raw = data(&s);
        let thin = slice(&raw);
        let m = parsed(thin);
        let ins = instructions(&m);
        let mut seen = Vec::new();
        for block in loops(&s.kind, &ins) {
            let tables = recognize(&s.kind, block).unwrap();
            if seen.contains(&tables) {
                continue;
            }
            seen.push(tables);
            let p = file_offset(&m, tables.permutation.unwrap());
            for value in [
                u32::from_le_bytes(thin[p + 4..p + 8].try_into().unwrap()),
                u32::MAX,
                (tables.length / 4) as u32,
            ] {
                let mut changed = thin.to_vec();
                changed[p..p + 4].copy_from_slice(&value.to_le_bytes());
                let out = extract_macho_arithmetic_strings(&parsed(&changed), 0, 4);
                assert!(out.len() < 3, "{} permutation", s.file);
            }
        }
    }
}
#[test]
fn malformed_primary_subtraction_and_mask_tables_reject_stage() {
    for s in specimens() {
        let raw = data(&s);
        let thin = slice(&raw);
        let m = parsed(thin);
        let ins = instructions(&m);
        for block in loops(&s.kind, &ins) {
            let t = recognize(&s.kind, block).unwrap();
            for addr in t.addresses.into_iter().chain(t.subtract_address) {
                let p = file_offset(&m, addr);
                let mut changed = thin.to_vec();
                changed[p] ^= 0x80;
                let out = extract_macho_arithmetic_strings(&parsed(&changed), 0, 4);
                assert!(out.len() < 3, "{} table {addr:x}", s.file);
            }
        }
    }
}

#[test]
fn another_complete_permutation_preserves_exact_output() {
    for s in specimens().into_iter().filter(|s| s.kind != "dispatch") {
        let raw = data(&s);
        let thin = slice(&raw);
        let m = parsed(thin);
        let ins = instructions(&m);
        let mut changed = thin.to_vec();
        let mut seen = Vec::new();
        for block in loops(&s.kind, &ins) {
            let t = recognize(&s.kind, block).unwrap();
            let address = t.permutation.unwrap();
            if seen.contains(&address) {
                continue;
            }
            seen.push(address);
            let p = file_offset(&m, address);
            let words: Vec<_> = thin[p..p + t.length].chunks_exact(4).collect();
            for (i, word) in words.iter().rev().enumerate() {
                changed[p + i * 4..p + i * 4 + 4].copy_from_slice(word);
            }
        }
        check(
            &extract_macho_arithmetic_strings(&parsed(&changed), 0, 4),
            &s,
            0,
        );
    }
}

#[test]
fn out_of_section_alphabet_references_reject_all_stages() {
    for s in specimens() {
        let raw = data(&s);
        let thin = slice(&raw);
        let m = parsed(thin);
        let ins = instructions(&m);
        let mut changed = thin.to_vec();
        let mut edits = 0;
        for block in loops(&s.kind, &ins) {
            let t = recognize(&s.kind, block).unwrap();
            if t.length != 512 {
                continue;
            }
            for instruction in block {
                if instruction.is_ip_rel_memory_operand()
                    && instruction.ip_rel_memory_address() == t.addresses[0]
                {
                    let pos = (instruction.ip() - 0x100000000) as usize;
                    let mut decoder =
                        Decoder::with_ip(64, &thin[pos..], instruction.ip(), DecoderOptions::NONE);
                    let decoded = decoder.decode();
                    let offsets = decoder.get_constant_offsets(&decoded);
                    assert_eq!(offsets.displacement_size(), 4);
                    let p = pos + offsets.displacement_offset();
                    changed[p..p + 4].copy_from_slice(&0x60000000u32.to_le_bytes());
                    edits += 1;
                }
            }
        }
        assert!(edits > 0);
        assert!(
            extract_macho_arithmetic_strings(&parsed(&changed), 0, 4).is_empty(),
            "{} invalid alphabet",
            s.file
        );
    }
}

#[test]
fn each_variant_obeys_minimum_length_and_provenance_overflow() {
    for s in specimens() {
        let raw = data(&s);
        let m = parsed(slice(&raw));
        for (minimum, count) in [(1, 3), (23, 2), (537, 1), (23863, 0)] {
            assert_eq!(
                extract_macho_arithmetic_strings(&m, 0, minimum).len(),
                count
            );
        }
        assert!(extract_macho_arithmetic_strings(&m, u64::MAX, 4).is_empty());
    }
}

fn arm_slice(data: &[u8]) -> &[u8] {
    let Object::Mach(Mach::Fat(fat)) = Object::parse(data).unwrap() else {
        panic!("fat")
    };
    let a = fat
        .arches()
        .unwrap()
        .into_iter()
        .find(|a| a.cputype == goblin::mach::constants::cputype::CPU_TYPE_ARM64)
        .unwrap();
    assert!(matches!(a.offset, 819200 | 1097728 | 1359872));
    &data[a.offset as usize..(a.offset + a.size) as usize]
}
fn arm_check(out: &[ExtractedString], s: &Specimen, base: u64) {
    let paired = s.file.contains("paired");
    for stage in &s.stages {
        let offset = match stage.name.as_str() {
            "gate" => 0xbeb48,
            "payload" => 0x3bd0,
            "tail" => 0xbe878,
            _ => panic!("stage"),
        } + if paired && stage.name != "payload" {
            24
        } else {
            0
        };
        let got = out
            .iter()
            .find(|v| hash(v.value.as_bytes()) == stage.sha256 && v.data_offset == base + offset)
            .expect("ARM independent stage");
        assert_eq!(got.data_len, stage.span);
        assert_eq!(got.value.len(), stage.length);
    }
}
#[test]
fn arm_dispatch_exact_stages_thin_and_fat_with_x86_disabled() {
    let opts = crate::ExtractOptions {
        use_cache: false,
        caller_provides_symbols: true,
        ..Default::default()
    };
    for s in specimens().into_iter().filter(|s| s.kind == "dispatch") {
        let mut raw = data(&s);
        let arm = arm_slice(&raw);
        let m = parsed(arm);
        for base in [0, 819200] {
            let out = extract_macho_arithmetic_strings(&m, base, 4);
            assert_eq!(out.len(), 3);
            arm_check(&out, &s, base);
        }
        arm_check(&crate::extract_strings_with_options(arm, &opts), &s, 0);
        let x86 = parsed(slice(&raw));
        let ins = instructions(&x86);
        let alphabet = loops("dispatch", &ins)
            .into_iter()
            .find(|block| recognize("dispatch", block).unwrap().length == 512)
            .unwrap();
        let offset = 4096 + (alphabet[0].ip() - 0x100000000) as usize;
        raw[offset] = 0xcc;
        arm_check(
            &crate::extract_strings_with_options(&raw, &opts),
            &s,
            819200,
        );
    }
}
#[test]
fn arm_dispatch_every_setup_and_state_transition_instruction_is_required() {
    for s in specimens().into_iter().filter(|s| s.kind == "dispatch") {
        let raw = data(&s);
        let original = arm_slice(&raw);
        for (start, end, remaining) in [
            (0x1e60, 0x1ee4, 0),
            (0x1f04, 0x1f88, 2),
            (0x1fd8, 0x2060, 2),
            (0x2094, 0x2118, 2),
        ] {
            for pos in (start..end).step_by(4) {
                let mut changed = original.to_vec();
                changed[pos..pos + 4].copy_from_slice(&0xd503201fu32.to_le_bytes());
                assert_eq!(
                    extract_macho_arithmetic_strings(&parsed(&changed), 0, 4).len(),
                    remaining,
                    "{} instruction {pos:x}",
                    s.file
                );
            }
        }
    }
}
#[test]
fn arm_dispatch_rejects_wrong_object_slots_bounds_registers_and_edges() {
    for s in specimens().into_iter().filter(|s| s.kind == "dispatch") {
        let raw = data(&s);
        let original = arm_slice(&raw);
        for (pos, bit) in [
            (0x1e68, 15),
            (0x1e78, 12),
            (0x1ebc, 10),
            (0x1e90, 10),
            (0x1e94, 0),
            (0x1ea4, 5),
            (0x1ecc, 5),
            (0x1ed4, 5),
            (0x1fe4, 5),
            (0x1fe0, 15),
            (0x1fec, 10),
            (0x2038, 10),
            (0x2050, 5),
            (0x20ac, 10),
        ] {
            let mut changed = original.to_vec();
            let word = u32::from_le_bytes(changed[pos..pos + 4].try_into().unwrap());
            changed[pos..pos + 4].copy_from_slice(&(word ^ (1 << bit)).to_le_bytes());
            assert!(
                extract_macho_arithmetic_strings(&parsed(&changed), 0, 4).len() < 3,
                "{} operand {pos:x}",
                s.file
            );
        }
    }
}
#[test]
fn arm_dispatch_bounds_and_bad_table_addresses_are_rejected() {
    for s in specimens().into_iter().filter(|s| s.kind == "dispatch") {
        let raw = data(&s);
        let original = arm_slice(&raw);
        for (pos, value) in [
            (0x1fe4, 0x52800013u32),
            (0x1fe4, 0x528000d3),
            (0x1e6c, 0x90000013),
            (0x1ff0, 0x90000015),
        ] {
            let mut changed = original.to_vec();
            changed[pos..pos + 4].copy_from_slice(&value.to_le_bytes());
            assert!(extract_macho_arithmetic_strings(&parsed(&changed), 0, 4).len() < 3);
        }
        assert!(extract_macho_arithmetic_strings(&parsed(original), u64::MAX, 4).is_empty());
        for (min, n) in [(23, 2), (537, 1), (23863, 0)] {
            assert_eq!(
                extract_macho_arithmetic_strings(&parsed(original), 0, min).len(),
                n
            );
        }
    }
}
#[test]
fn arm_dispatch_truncation_and_eight_candidate_limit() {
    for s in specimens().into_iter().filter(|s| s.kind == "dispatch") {
        let raw = data(&s);
        let block = &arm_slice(&raw)[0x1e60..0x1ee4];
        for end in 0..block.len() {
            assert!(arm64_arithmetic::tables(&block[..end], 0x100001e60).is_empty());
        }
        assert_eq!(arm64_arithmetic::tables(block, 0x100001e60).len(), 1);
        assert_eq!(
            arm64_arithmetic::tables(&block.repeat(9), 0x100001e60).len(),
            8
        );
        assert!(arm64_arithmetic::tables(block, u64::MAX).is_empty());
    }
}

#[test]
#[ignore = "manual extractor timing on parsed inputs"]
fn arithmetic_variant_extractor_timing() {
    for s in specimens() {
        let raw = data(&s);
        let m = parsed(slice(&raw));
        let start = std::time::Instant::now();
        for _ in 0..1000 {
            std::hint::black_box(extract_macho_arithmetic_strings(
                std::hint::black_box(&m),
                0,
                4,
            ));
        }
        println!(
            "{} x86: {:.3} us/call",
            s.file,
            start.elapsed().as_secs_f64() * 1000.0
        );
        if matches!(s.kind.as_str(), "dispatch" | "permuted" | "four") {
            let m = parsed(arm_slice(&raw));
            let start = std::time::Instant::now();
            for _ in 0..1000 {
                std::hint::black_box(extract_macho_arithmetic_strings(
                    std::hint::black_box(&m),
                    0,
                    4,
                ));
            }
            println!(
                "{} ARM: {:.3} us/call",
                s.file,
                start.elapsed().as_secs_f64() * 1000.0
            );
        }
    }
}

#[test]
fn arm_permutation_exact_stages_and_offsets() {
    for s in specimens().into_iter().filter(|s| s.kind == "permuted") {
        let raw = data(&s);
        assert_eq!(hash(&raw), s.sha256);
        let thin = arm_slice(&raw);
        for base in [0, 1097728] {
            let out = extract_macho_arithmetic_strings(&parsed(thin), base, 4);
            assert_eq!(out.len(), 3, "{}", s.file);
            for stage in &s.stages {
                let offset = match stage.name.as_str() {
                    "gate" => 0xfce90,
                    "payload" => 0x39d0,
                    "tail" => 0xfcad0,
                    _ => panic!("stage"),
                };
                let got = out
                    .iter()
                    .find(|v| hash(v.value.as_bytes()) == stage.sha256)
                    .unwrap();
                assert_eq!(got.value.len(), stage.length);
                assert_eq!(got.data_offset, base + offset);
                assert_eq!(got.data_len, stage.span);
            }
        }
    }
}

#[test]
fn arm_permutation_public_pipeline_thin_and_fat_without_x86() {
    let opts = crate::ExtractOptions {
        use_cache: false,
        caller_provides_symbols: true,
        ..Default::default()
    };
    for s in specimens().into_iter().filter(|s| s.kind == "permuted") {
        let mut raw = data(&s);
        let check =
            |out: Vec<ExtractedString>, base: u64| {
                for stage in &s.stages {
                    let offset = match stage.name.as_str() {
                        "gate" => 0xfce90,
                        "payload" => 0x39d0,
                        "tail" => 0xfcad0,
                        _ => panic!("stage"),
                    };
                    assert!(out.iter().any(|v| hash(v.value.as_bytes()) == stage.sha256
                        && v.data_offset == base + offset));
                }
            };
        check(
            crate::extract_strings_with_options(arm_slice(&raw), &opts),
            0,
        );
        let m = parsed(slice(&raw));
        for seg in &m.segments {
            for (sec, _) in seg.sections().unwrap() {
                if sec.name().ok() == Some("__text") {
                    let start = 4096 + sec.offset as usize;
                    let end = start + sec.size as usize;
                    // Delay mutation until the parsed view has been dropped.
                    let mut erased = raw.clone();
                    erased[start..end].fill(0xcc);
                    check(crate::extract_strings_with_options(&erased, &opts), 1097728);
                }
            }
        }
        raw.clear();
    }
}

#[test]
fn arm_permutation_requires_every_setup_loop_and_tail_instruction() {
    for s in specimens().into_iter().filter(|s| s.kind == "permuted") {
        let raw = data(&s);
        let original = arm_slice(&raw);
        for (start, end, remaining) in [
            (0x19e4, 0x1aa4, 0),
            (0x1afc, 0x1bbc, 2),
            (0x1c38, 0x1ce8, 2),
            (0x1d44, 0x1dfc, 2),
        ] {
            for pos in (start..end).step_by(4) {
                let mut changed = original.to_vec();
                changed[pos..pos + 4].copy_from_slice(&0xd503201fu32.to_le_bytes());
                assert_eq!(
                    extract_macho_arithmetic_strings(&parsed(&changed), 0, 4).len(),
                    remaining,
                    "{} NOP {pos:x}",
                    s.file
                );
            }
        }
    }
}

#[test]
fn arm_permutation_rejects_invalid_indexes_and_accepts_reordering() {
    for s in specimens().into_iter().filter(|s| s.kind == "permuted") {
        let raw = data(&s);
        let original = arm_slice(&raw);
        let reference = extract_macho_arithmetic_strings(&parsed(original), 0, 4);
        for (p, n, traversed, remaining) in [
            (0xfc8d0, 128, 128, 0),
            (0x101198, 1430, 1428, 2),
            (0xbe090, 63632, 63632, 2),
            (0xfcda0, 60, 60, 2),
        ] {
            for value in [
                u32::MAX,
                n as u32,
                u32::from_le_bytes(original[p + 4..p + 8].try_into().unwrap()),
            ] {
                let mut changed = original.to_vec();
                changed[p..p + 4].copy_from_slice(&value.to_le_bytes());
                assert_eq!(
                    extract_macho_arithmetic_strings(&parsed(&changed), 0, 4).len(),
                    remaining,
                    "{} invalid index {p:x}",
                    s.file
                );
            }
            let mut changed = original.to_vec();
            for i in 0..traversed {
                changed[p + i * 4..p + i * 4 + 4].copy_from_slice(
                    &original[p + (traversed - i - 1) * 4..p + (traversed - i) * 4],
                );
            }
            let out = extract_macho_arithmetic_strings(&parsed(&changed), 0, 4);
            assert_eq!(out.len(), 3);
            assert!(reference.iter().all(|v| {
                out.iter()
                    .any(|o| o.value == v.value && o.data_offset == v.data_offset)
            }));
        }
    }
}

#[test]
fn arm_permutation_literal_writes_override_unused_table_and_index_entries() {
    for s in specimens().into_iter().filter(|s| s.kind == "permuted") {
        let raw = data(&s);
        let original = arm_slice(&raw);
        let reference = extract_macho_arithmetic_strings(&parsed(original), 0, 4);
        let mut changed = original.to_vec();
        for pos in [0x1ba8, 0x1bb0] {
            let word = u32::from_le_bytes(original[pos..pos + 4].try_into().unwrap());
            let index = ((word >> 10) & 4095) as usize;
            for base in [0xfce90, 0xffb40, 0xfe4e8] {
                changed[base + 4 * index..base + 4 * index + 4].fill(0xff);
            }
        }
        changed[0x101198 + 1428 * 4..0x101198 + 1430 * 4].fill(0xff);
        let out = extract_macho_arithmetic_strings(&parsed(&changed), 0, 4);
        assert_eq!(out.len(), 3);
        assert!(
            reference
                .iter()
                .all(|v| out.iter().any(|o| o.value == v.value))
        );
        for pos in [0x1ba4, 0x1bac] {
            let mut changed = original.to_vec();
            changed[pos..pos + 4]
                .copy_from_slice(&(0x52800008u32 | (b'!' as u32) << 5).to_le_bytes());
            assert_eq!(
                extract_macho_arithmetic_strings(&parsed(&changed), 0, 4).len(),
                2
            );
        }
        // Duplicate literal destinations or overlap with the loop leave a hole.
        for index in [
            ((u32::from_le_bytes(original[0x1ba8..0x1bac].try_into().unwrap()) >> 10) & 4095),
            u32::from_le_bytes(original[0x101198..0x10119c].try_into().unwrap()),
        ] {
            let mut changed = original.to_vec();
            changed[0x1bb0..0x1bb4].copy_from_slice(&(0x390002c8 | index << 10).to_le_bytes());
            assert_eq!(
                extract_macho_arithmetic_strings(&parsed(&changed), 0, 4).len(),
                2
            );
        }
    }
}

#[test]
fn arm_permutation_rejects_bad_operands_bounds_and_table_data() {
    for s in specimens().into_iter().filter(|s| s.kind == "permuted") {
        let raw = data(&s);
        let original = arm_slice(&raw);
        for (pos, bit) in [
            (0x1a0c, 5),
            (0x1a14, 10),
            (0x1a98, 5),
            (0x1a84, 5),
            (0x1a30, 16),
            (0x1b74, 16),
            (0x1c44, 5),
            (0x1c48, 5),
            (0x1c54, 10),
            (0x1cc8, 5),
            (0x1ba8, 5),
            (0x1bb0, 10),
            (0x1bb4, 5),
        ] {
            let mut changed = original.to_vec();
            let w = u32::from_le_bytes(changed[pos..pos + 4].try_into().unwrap());
            changed[pos..pos + 4].copy_from_slice(&(w ^ (1 << bit)).to_le_bytes());
            assert!(
                extract_macho_arithmetic_strings(&parsed(&changed), 0, 4).len() < 3,
                "{} operand {pos:x}",
                s.file
            );
        }
        for base in [0xfc2d0, 0xfc6d0, 0xfc4d0] {
            let mut changed = original.to_vec();
            changed[base] ^= 0x80;
            assert!(extract_macho_arithmetic_strings(&parsed(&changed), 0, 4).is_empty());
        }
        for (min, count) in [(1, 3), (23, 2), (537, 1), (23863, 0)] {
            assert_eq!(
                extract_macho_arithmetic_strings(&parsed(original), 0, min).len(),
                count
            );
        }
        assert!(extract_macho_arithmetic_strings(&parsed(original), u64::MAX, 4).is_empty());
    }
}

#[test]
fn arm_permutation_truncation_overflow_and_candidate_limit() {
    for s in specimens().into_iter().filter(|s| s.kind == "permuted") {
        let raw = data(&s);
        let original = arm_slice(&raw);
        for (start, end) in [
            (0x19e4, 0x1aa4),
            (0x1afc, 0x1bbc),
            (0x1c38, 0x1ce8),
            (0x1d44, 0x1dfc),
        ] {
            let block = &original[start..end];
            let pc = 0x100000000 + start as u64;
            for n in 0..block.len() {
                assert!(
                    arm64_arithmetic::tables(&block[..n], pc).is_empty(),
                    "{start:x} prefix {n}"
                );
            }
            assert_eq!(arm64_arithmetic::tables(block, pc).len(), 1);
            assert_eq!(arm64_arithmetic::tables(&block.repeat(9), pc).len(), 8);
            assert!(arm64_arithmetic::tables(block, u64::MAX).is_empty());
        }
    }
}

fn four_specimen() -> Specimen {
    specimens().into_iter().find(|s| s.kind == "four").unwrap()
}
fn check_arm_four(out: &[ExtractedString], s: &Specimen, base: u64) {
    for stage in &s.stages {
        let offset = match stage.name.as_str() {
            "gate" => 0x13fa18,
            "payload" => 0x8028,
            "tail" => 0x13f568,
            _ => panic!("stage"),
        };
        let got = out
            .iter()
            .find(|v| hash(v.value.as_bytes()) == stage.sha256 && v.data_offset == base + offset)
            .expect("independent ARM four-table stage");
        assert_eq!(got.value.len(), stage.length);
        assert_eq!(got.data_len, stage.span);
        assert_eq!(got.method, StringMethod::Base64ObfuscatedDecode);
    }
}
#[test]
fn arm_four_table_independent_stages_and_public_thin_fat_pipeline() {
    let s = four_specimen();
    let raw = data(&s);
    assert_eq!(hash(&raw), s.sha256);
    let thin = arm_slice(&raw);
    for base in [0, 1359872] {
        let out = extract_macho_arithmetic_strings(&parsed(thin), base, 4);
        assert_eq!(out.len(), 3);
        check_arm_four(&out, &s, base);
    }
    let opts = crate::ExtractOptions {
        use_cache: false,
        caller_provides_symbols: true,
        ..Default::default()
    };
    check_arm_four(&crate::extract_strings_with_options(thin, &opts), &s, 0);
    let mut erased = raw.clone();
    for seg in &parsed(slice(&raw)).segments {
        for (sec, _) in seg.sections().unwrap() {
            if sec.name().ok() == Some("__text") {
                erased[4096 + sec.offset as usize..4096 + sec.offset as usize + sec.size as usize]
                    .fill(0xcc);
            }
        }
    }
    check_arm_four(
        &crate::extract_strings_with_options(&erased, &opts),
        &s,
        1359872,
    );
}
#[test]
fn arm_four_table_requires_all_setup_body_tail_and_allocation_instructions() {
    let raw = data(&four_specimen());
    let original = arm_slice(&raw);
    for (start, end, remaining) in [
        (0x46b0, 0x4774, 2),
        (0x4e58, 0x4f1c, 0),
        (0x57a4, 0x5868, 2),
        (0x5e6c, 0x5f40, 2),
    ] {
        for pos in (start..end).step_by(4) {
            let mut changed = original.to_vec();
            changed[pos..pos + 4].copy_from_slice(&0xd503201fu32.to_le_bytes());
            assert_eq!(
                extract_macho_arithmetic_strings(&parsed(&changed), 0, 4).len(),
                remaining,
                "NOP {pos:x}"
            );
        }
    }
}
#[test]
fn arm_four_table_rejects_invalid_permutations_and_accepts_reordering() {
    let s = four_specimen();
    let raw = data(&s);
    let original = arm_slice(&raw);
    for (p, n, traversed, remaining) in [
        (0x100928, 63632, 63632, 2),
        (0x13f368, 128, 128, 0),
        (0x13f928, 60, 60, 2),
        (0x145378, 1430, 1428, 2),
    ] {
        for value in [
            u32::MAX,
            n as u32,
            u32::from_le_bytes(original[p + 4..p + 8].try_into().unwrap()),
        ] {
            let mut changed = original.to_vec();
            changed[p..p + 4].copy_from_slice(&value.to_le_bytes());
            assert_eq!(
                extract_macho_arithmetic_strings(&parsed(&changed), 0, 4).len(),
                remaining,
                "index {p:x}"
            );
        }
        let mut changed = original.to_vec();
        for i in 0..traversed {
            changed[p + i * 4..p + i * 4 + 4]
                .copy_from_slice(&original[p + (traversed - i - 1) * 4..p + (traversed - i) * 4]);
        }
        check_arm_four(
            &extract_macho_arithmetic_strings(&parsed(&changed), 0, 4),
            &s,
            0,
        );
    }
}
#[test]
fn arm_four_table_literal_override_and_destination_coverage() {
    let s = four_specimen();
    let raw = data(&s);
    let original = arm_slice(&raw);
    let mut changed = original.to_vec();
    for i in [931, 703] {
        for base in [0x13fa18, 0x1426c8, 0x141070, 0x143d20] {
            changed[base + 4 * i..base + 4 * i + 4].fill(0xff);
        }
    }
    changed[0x145378 + 1428 * 4..0x145378 + 1430 * 4].fill(0xff);
    check_arm_four(
        &extract_macho_arithmetic_strings(&parsed(&changed), 0, 4),
        &s,
        0,
    );
    for (pos, value) in [
        (0x5f28, 0x52800008u32 | (b'!' as u32) << 5),
        (0x5f30, 0x52800008 | 256 << 5),
        (0x5f34, 0x39000268 | 931 << 10),
        (0x5f34, 0x39000268 | 603 << 10),
        (0x5f34, 0x39000268 | 1430 << 10),
    ] {
        let mut changed = original.to_vec();
        changed[pos..pos + 4].copy_from_slice(&value.to_le_bytes());
        assert_eq!(
            extract_macho_arithmetic_strings(&parsed(&changed), 0, 4).len(),
            2,
            "literal {pos:x} {value:x}"
        );
    }
}
#[test]
fn arm_four_table_bad_registers_branches_bounds_and_fourth_table_are_rejected() {
    let raw = data(&four_specimen());
    let original = arm_slice(&raw);
    for (pos, bit) in [
        (0x46dc, 0),
        (0x46e8, 15),
        (0x4734, 5),
        (0x4744, 16),
        (0x4754, 5),
        (0x4764, 10),
        (0x4768, 5),
        (0x4770, 26),
        (0x46d8, 10),
        (0x5f2c, 5),
    ] {
        let mut changed = original.to_vec();
        let w = u32::from_le_bytes(changed[pos..pos + 4].try_into().unwrap());
        changed[pos..pos + 4].copy_from_slice(&(w ^ (1 << bit)).to_le_bytes());
        assert!(
            extract_macho_arithmetic_strings(&parsed(&changed), 0, 4).len() < 3,
            "operand {pos:x}"
        );
    }
    for count in [0, 4, 7, 9, 65535] {
        let mut changed = original.to_vec();
        changed[0x46b8..0x46bc].copy_from_slice(&(0x52800009u32 | count << 5).to_le_bytes());
        assert_eq!(
            extract_macho_arithmetic_strings(&parsed(&changed), 0, 4).len(),
            2
        );
    }
    for base in [0x13eb68, 0x13ef68, 0x13ed68, 0x13f168] {
        let mut changed = original.to_vec();
        changed[base] ^= 128;
        assert!(extract_macho_arithmetic_strings(&parsed(&changed), 0, 4).is_empty());
    }
}
#[test]
fn arm_four_table_limits_truncation_and_provenance_overflow() {
    let raw = data(&four_specimen());
    let original = arm_slice(&raw);
    for (start, end) in [
        (0x46b0, 0x4774),
        (0x4e58, 0x4f1c),
        (0x57a4, 0x5868),
        (0x5e6c, 0x5f40),
    ] {
        let block = &original[start..end];
        let pc = 0x100000000 + start as u64;
        for n in 0..block.len() {
            assert!(
                arm64_arithmetic::tables(&block[..n], pc).is_empty(),
                "prefix {start:x} {n}"
            );
        }
        assert_eq!(arm64_arithmetic::tables(block, pc).len(), 1);
        assert_eq!(arm64_arithmetic::tables(&block.repeat(9), pc).len(), 8);
        assert!(arm64_arithmetic::tables(block, u64::MAX).is_empty());
    }
    for (min, count) in [(1, 3), (23, 2), (537, 1), (23863, 0)] {
        assert_eq!(
            extract_macho_arithmetic_strings(&parsed(original), 0, min).len(),
            count
        );
    }
    assert!(extract_macho_arithmetic_strings(&parsed(original), u64::MAX, 4).is_empty());
}
