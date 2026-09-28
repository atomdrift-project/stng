//! Recover literal arrays XORed through Rust's checked byte-index helper.
//!
//! A byte prefilter selects allocation sites; only two consecutive, completely
//! initialized arrays followed by the verified XOR loop are accepted. No
//! emulation, guessed keys, or pairwise search is performed.

use crate::{ExtractedString, StringMethod, classify_string};
use goblin::mach::MachO;
use iced_x86::{Decoder, DecoderOptions, Instruction, MemorySize, Mnemonic, OpKind, Register};

const MAX_CODE: usize = 8 * 1024 * 1024;
const MAX_ARRAY: usize = 4096;
const MAX_CANDIDATES: usize = 128;

pub(crate) fn extract_macho(
    macho: &MachO<'_>,
    slice_base: u64,
    min_length: usize,
) -> Vec<ExtractedString> {
    if macho.header.cputype != goblin::mach::constants::cputype::CPU_TYPE_X86_64 {
        return Vec::new();
    }
    for segment in &macho.segments {
        if segment.name().ok() != Some("__TEXT") {
            continue;
        }
        let Ok(sections) = segment.sections() else {
            continue;
        };
        for (section, code) in sections {
            if section.name().ok() != Some("__text") || code.len() > MAX_CODE {
                continue;
            }
            let mut results = Vec::new();
            // push 1; pop rsi; mov edi, length; call allocator
            for start in memchr::memmem::find_iter(code, b"\x6a\x01\x5e\xbf").take(MAX_CANDIDATES) {
                if let Some(value) = decode_pair(code, section.addr, start, min_length) {
                    let Some(offset) = slice_base
                        .checked_add(u64::from(section.offset))
                        .and_then(|n| n.checked_add(start as u64))
                    else {
                        continue;
                    };
                    results.push(ExtractedString {
                        kind: classify_string(&value.0),
                        value: value.0,
                        data_offset: offset,
                        data_len: value.1,
                        method: StringMethod::XorDecode,
                        ..Default::default()
                    });
                }
            }
            return results;
        }
    }
    Vec::new()
}

fn reg_move(i: &Instruction, dst: Register, src: Register) -> bool {
    i.mnemonic() == Mnemonic::Mov
        && i.op0_kind() == OpKind::Register
        && i.op1_kind() == OpKind::Register
        && i.op0_register() == dst
        && i.op1_register() == src
}

fn immediate(i: &Instruction) -> Option<u64> {
    Some(match i.op1_kind() {
        OpKind::Immediate8 => u64::from(i.immediate8()),
        OpKind::Immediate16 => u64::from(i.immediate16()),
        OpKind::Immediate32 => u64::from(i.immediate32()),
        OpKind::Immediate64 => i.immediate64(),
        OpKind::Immediate8to64 => i.immediate8to64() as u64,
        OpKind::Immediate32to64 => i.immediate32to64() as u64,
        _ => return None,
    })
}

fn preserved(r: Register) -> bool {
    matches!(
        r,
        Register::RBX | Register::R12 | Register::R13 | Register::R14 | Register::R15
    )
}

fn memory(i: &Instruction, base: Register, offset: u64) -> bool {
    i.memory_base() == base
        && i.memory_index() == Register::None
        && i.memory_displacement64() == offset
        && i.segment_prefix() == Register::None
}

struct Array {
    base: Register,
    allocator: u64,
    bytes: Vec<u8>,
}

fn read_array(d: &mut Decoder<'_>, min_length: usize) -> Option<Array> {
    let push = d.decode();
    let pop = d.decode();
    let size = d.decode();
    let call = d.decode();
    let save = d.decode();
    if push.mnemonic() != Mnemonic::Push
        || push.op0_kind() != OpKind::Immediate8to64
        || push.immediate8to64() != 1
        || pop.mnemonic() != Mnemonic::Pop
        || pop.op0_register() != Register::RSI
        || size.mnemonic() != Mnemonic::Mov
        || size.op0_register() != Register::EDI
        || size.op1_kind() != OpKind::Immediate32
        || call.mnemonic() != Mnemonic::Call
        || call.op0_kind() != OpKind::NearBranch64
        || !reg_move(&save, save.op0_register(), Register::RAX)
        || !preserved(save.op0_register())
    {
        return None;
    }
    let len = size.immediate32() as usize;
    if !(min_length.max(8)..=MAX_ARRAY).contains(&len) {
        return None;
    }
    let base = save.op0_register();
    let mut bytes = Vec::with_capacity(len);
    // Every iteration must write the next 1..8 bytes. Gaps, aliases, and
    // intervening instructions fail closed; length bounds the decode work.
    while bytes.len() < len {
        let first = d.decode();
        if first.mnemonic() != Mnemonic::Mov {
            return None;
        }
        let (store, value) = if first.op0_kind() == OpKind::Register {
            if first.op0_register() != Register::RAX || first.op1_kind() != OpKind::Immediate64 {
                return None;
            }
            let value = immediate(&first)?;
            let store = d.decode();
            if store.op1_kind() != OpKind::Register || store.op1_register() != first.op0_register()
            {
                return None;
            }
            (store, value)
        } else {
            (first, immediate(&first)?)
        };
        let width = match store.memory_size() {
            MemorySize::UInt8 => 1,
            MemorySize::UInt16 => 2,
            MemorySize::UInt32 => 4,
            MemorySize::UInt64 => 8,
            _ => return None,
        };
        if store.mnemonic() != Mnemonic::Mov
            || store.op0_kind() != OpKind::Memory
            || !memory(&store, base, bytes.len() as u64)
            || !matches!(width, 1 | 2 | 4 | 8)
            || bytes.len() + width > len
        {
            return None;
        }
        bytes.extend_from_slice(&value.to_le_bytes()[..width]);
    }
    Some(Array {
        base,
        allocator: call.near_branch_target(),
        bytes,
    })
}

fn decode_pair(code: &[u8], vma: u64, start: usize, min_length: usize) -> Option<(String, u32)> {
    // Even malformed candidates can decode at most this window.
    let end = start.saturating_add(MAX_ARRAY * 24 + 256).min(code.len());
    let mut d = Decoder::with_ip(
        64,
        code.get(start..end)?,
        vma.checked_add(start as u64)?,
        DecoderOptions::NONE,
    );
    let a = read_array(&mut d, min_length)?;
    let b = read_array(&mut d, min_length)?;
    if a.base == b.base || a.allocator != b.allocator || a.bytes.len() != b.bytes.len() {
        return None;
    }
    let s: [Instruction; 18] = std::array::from_fn(|_| d.decode());
    let index = match s[0].op0_register() {
        Register::R12D => Register::R12,
        Register::R13D => Register::R13,
        Register::R14D => Register::R14,
        Register::R15D => Register::R15,
        _ => return None,
    };
    let context = s[1].op0_register();
    let byte = s[9].op0_register();
    let registers = [a.base, b.base, index, context, Register::RBX];
    if registers.iter().any(|&r| !preserved(r))
        || registers
            .iter()
            .enumerate()
            .any(|(n, r)| registers[..n].contains(r))
        || s[0].mnemonic() != Mnemonic::Xor
        || s[0].op0_kind() != OpKind::Register
        || s[0].op1_kind() != OpKind::Register
        || s[0].op0_register() != s[0].op1_register()
        || s[1].mnemonic() != Mnemonic::Lea
        || s[1].op0_kind() != OpKind::Register
        || !s[1].is_ip_rel_memory_operand()
        || s[2].mnemonic() != Mnemonic::Cmp
        || s[2].op0_register() != index
        || immediate(&s[2])? != a.bytes.len() as u64
        || s[3].mnemonic() != Mnemonic::Je
        || s[3].near_branch_target() != s[17].next_ip()
        || s[9].mnemonic() != Mnemonic::Mov
        || s[9].op0_kind() != OpKind::Register
        || byte != Register::BL
        || s[9].op1_kind() != OpKind::Memory
        || !memory(&s[9], Register::RAX, 0)
        || s[15].mnemonic() != Mnemonic::Xor
        || s[15].op0_kind() != OpKind::Memory
        || s[15].op1_kind() != OpKind::Register
        || s[15].op1_register() != byte
        || !memory(&s[15], Register::RAX, 0)
        || s[16].mnemonic() != Mnemonic::Inc
        || s[16].op0_register() != index
        || s[17].mnemonic() != Mnemonic::Jmp
        || s[17].near_branch_target() != s[2].ip()
    {
        return None;
    }
    for (n, base) in [(4, a.base), (10, b.base)] {
        if s[n].mnemonic() != Mnemonic::Mov
            || s[n].op0_register() != Register::ESI
            || immediate(&s[n])? != a.bytes.len() as u64
            || !reg_move(&s[n + 1], Register::RDI, base)
            || !reg_move(&s[n + 2], Register::RDX, index)
            || !reg_move(&s[n + 3], Register::RCX, context)
            || s[n + 4].mnemonic() != Mnemonic::Call
            || s[n + 4].op0_kind() != OpKind::NearBranch64
        {
            return None;
        }
    }
    if s[8].near_branch_target() != s[14].near_branch_target()
        || !checked_index(code, vma, s[8].near_branch_target())
    {
        return None;
    }
    let decoded: Vec<_> = a.bytes.iter().zip(b.bytes).map(|(a, b)| a ^ b).collect();
    let value = String::from_utf8(decoded).ok()?;
    if value
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return None;
    }
    Some((value, u32::try_from(d.position()).ok()?))
}

fn checked_index(code: &[u8], vma: u64, target: u64) -> bool {
    let Some(offset) = target
        .checked_sub(vma)
        .and_then(|n| usize::try_from(n).ok())
    else {
        return false;
    };
    let Some(bytes) = code.get(offset..offset.saturating_add(32)) else {
        return false;
    };
    let mut d = Decoder::with_ip(64, bytes, target, DecoderOptions::NONE);
    let s: [Instruction; 5] = std::array::from_fn(|_| d.decode());
    s[0].mnemonic() == Mnemonic::Cmp
        && s[0].op0_kind() == OpKind::Register
        && s[0].op0_register() == Register::RDX
        && s[0].op1_kind() == OpKind::Register
        && s[0].op1_register() == Register::RSI
        && s[1].mnemonic() == Mnemonic::Jae
        && s[1].near_branch_target() == s[4].next_ip()
        && s[2].mnemonic() == Mnemonic::Add
        && s[2].op0_kind() == OpKind::Register
        && s[2].op0_register() == Register::RDI
        && s[2].op1_kind() == OpKind::Register
        && s[2].op1_register() == Register::RDX
        && reg_move(&s[3], Register::RAX, Register::RDI)
        && s[4].mnemonic() == Mnemonic::Ret
}
