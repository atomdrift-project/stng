//! XOR literals whose key pointer is computed by a short arithmetic helper.
//!
//! Fixed setup signatures gate bounded instruction decoding. A complete qword
//! XOR loop and matching consumer length are required before folding the key
//! helper's register-only arithmetic. Recovered bytes do not imply execution or
//! aliasing into later consumers. No memory emulation or key search is used.

mod arm64;

use crate::{ExtractedString, StringMethod, classify_string};
use goblin::mach::MachO;
use iced_x86::{Decoder, DecoderOptions, Instruction, MemorySize, Mnemonic, OpKind, Register};

const MAX_CODE: usize = 8 * 1024 * 1024;
const MAX_CANDIDATES: usize = 1024;
const MAX_LITERAL: usize = 512;
const SETUP: &[u8] = b"\x48\x89\x01\x48\x8b\x39\xc7\x01";

struct Region<'a> {
    addr: u64,
    offset: u64,
    bytes: &'a [u8],
}

impl Region<'_> {
    fn at(&self, addr: u64, len: usize) -> Option<&[u8]> {
        let start = usize::try_from(addr.checked_sub(self.addr)?).ok()?;
        self.bytes.get(start..start.checked_add(len)?)
    }

    fn decoder(&self, addr: u64, limit: usize) -> Option<Decoder<'_>> {
        let start = usize::try_from(addr.checked_sub(self.addr)?).ok()?;
        let end = start.checked_add(limit)?.min(self.bytes.len());
        Some(Decoder::with_ip(
            64,
            self.bytes.get(start..end)?,
            addr,
            DecoderOptions::NONE,
        ))
    }
}

pub(crate) fn extract_macho(
    macho: &MachO<'_>,
    slice_base: u64,
    min: usize,
) -> Vec<ExtractedString> {
    let arm64 = macho.header.cputype == goblin::mach::constants::cputype::CPU_TYPE_ARM64;
    if !arm64 && macho.header.cputype != goblin::mach::constants::cputype::CPU_TYPE_X86_64 {
        return Vec::new();
    }
    let mut code = None;
    let mut constants = Vec::new();
    for segment in &macho.segments {
        if segment.name().ok() != Some("__TEXT") {
            continue;
        }
        let Ok(sections) = segment.sections() else {
            continue;
        };
        for (section, bytes) in sections {
            let region = Region {
                addr: section.addr,
                offset: u64::from(section.offset),
                bytes,
            };
            match section.name().ok() {
                Some("__text") if bytes.len() <= MAX_CODE => code = Some(region),
                Some("__const" | "__cstring") => constants.push(region),
                _ => {}
            }
        }
    }
    let Some(code) = code else { return Vec::new() };
    if arm64 {
        return arm64::extract(&code, &constants, slice_base, min);
    }
    let mut output = Vec::new();
    for hit in memchr::memmem::find_iter(code.bytes, SETUP).take(MAX_CANDIDATES) {
        // RIP-relative LEA is 7 bytes; the stack LEA is 4–8 (RSP needs a SIB).
        let setup = [11, 12, 14, 15].into_iter().find_map(|back| {
            read_setup(&code, code.addr.checked_add(hit.checked_sub(back)? as u64)?)
        });
        let Some(setup) = setup else { continue };
        let Some((cipher, len)) = read_loop(&code, &setup) else {
            continue;
        };
        if len < min {
            continue;
        }
        let Some(key) = fold_helper(&code, setup.helper, setup.base, setup.seed) else {
            continue;
        };
        let Some(cipher_region) = constants.iter().find(|r| r.at(cipher, len).is_some()) else {
            continue;
        };
        let Some(encoded) = cipher_region.at(cipher, len) else {
            continue;
        };
        let Some(key_bytes) = constants.iter().find_map(|r| r.at(key, len)) else {
            continue;
        };
        let decoded: Vec<u8> = encoded.iter().zip(key_bytes).map(|(a, b)| a ^ b).collect();
        let Ok(value) = String::from_utf8(decoded) else {
            continue;
        };
        if !value
            .chars()
            .all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
        {
            continue;
        }
        let Some(offset) = slice_base
            .checked_add(cipher_region.offset)
            .and_then(|n| n.checked_add(cipher - cipher_region.addr))
        else {
            continue;
        };
        output.push(ExtractedString {
            kind: classify_string(&value),
            value,
            data_offset: offset,
            data_len: u32::try_from(len).unwrap_or(u32::MAX),
            method: StringMethod::XorDecode,
            ..Default::default()
        });
    }
    output
}

fn reg_move(i: &Instruction, dst: Register, src: Register) -> bool {
    i.mnemonic() == Mnemonic::Mov
        && i.op0_kind() == OpKind::Register
        && i.op1_kind() == OpKind::Register
        && i.op0_register() == dst
        && i.op1_register() == src
}

fn memory(i: &Instruction, base: Register, index: Register, displacement: u64) -> bool {
    i.memory_base() == base
        && i.memory_index() == index
        && i.memory_displacement64() == displacement
        && i.memory_index_scale() == 1
        && i.segment_prefix() == Register::None
}

fn rip_lea(i: &Instruction) -> bool {
    i.mnemonic() == Mnemonic::Lea
        && i.op0_kind() == OpKind::Register
        && (gpr_width(i.op0_register()) == 64)
        && i.op1_kind() == OpKind::Memory
        && i.is_ip_rel_memory_operand()
}

struct Setup {
    base: u64,
    seed: u64,
    helper: u64,
    after: u64,
    stack_reg: Register,
    stack_base: Register,
    stack_disp: u64,
}

fn read_setup(code: &Region<'_>, addr: u64) -> Option<Setup> {
    use Register::{ESI, None as NoReg, RAX, RBP, RCX, RDI, RSI};
    let mut d = code.decoder(addr, 64)?;
    let mut s = [Instruction::default(); 8];
    for i in &mut s {
        *i = d.decode();
    }
    if !rip_lea(&s[0])
        || s[0].op0_register() != RAX
        || s[1].mnemonic() != Mnemonic::Lea
        || s[1].op0_register() != RCX
        || !matches!(s[1].memory_base(), RBP | Register::RSP)
        || !memory(
            &s[1],
            s[1].memory_base(),
            NoReg,
            s[1].memory_displacement64(),
        )
        || s[2].mnemonic() != Mnemonic::Mov
        || s[2].op0_kind() != OpKind::Memory
        || !memory(&s[2], RCX, NoReg, 0)
        || s[2].op1_register() != RAX
        || s[3].mnemonic() != Mnemonic::Mov
        || s[3].op0_register() != RDI
        || s[3].op1_kind() != OpKind::Memory
        || !memory(&s[3], RCX, NoReg, 0)
        || s[4].mnemonic() != Mnemonic::Mov
        || s[4].op0_kind() != OpKind::Memory
        || s[4].memory_size() != MemorySize::UInt32
        || !memory(&s[4], RCX, NoReg, 0)
        || s[4].op1_kind() != OpKind::Immediate32
        || s[5].mnemonic() != Mnemonic::Lea
        || !(gpr_width(s[5].op0_register()) == 64)
        || matches!(s[5].op0_register(), RDI | RSI | RBP | Register::RSP)
        || !memory(
            &s[5],
            s[1].memory_base(),
            NoReg,
            s[1].memory_displacement64(),
        )
        || s[6].mnemonic() != Mnemonic::Mov
        || s[6].op0_register() != ESI
        || s[6].op1_kind() != OpKind::Memory
        || !memory(&s[6], s[5].op0_register(), NoReg, 0)
        || s[7].mnemonic() != Mnemonic::Call
        || s[7].op0_kind() != OpKind::NearBranch64
    {
        return None;
    }
    Some(Setup {
        base: s[0].ip_rel_memory_address(),
        seed: u64::from(s[4].immediate32()),
        helper: s[7].near_branch_target(),
        after: d.ip(),
        stack_reg: s[5].op0_register(),
        stack_base: s[1].memory_base(),
        stack_disp: s[1].memory_displacement64(),
    })
}

fn read_loop(code: &Region<'_>, setup: &Setup) -> Option<(u64, usize)> {
    use Register::{None as NoReg, RAX, RBP};
    let mut d = code.decoder(setup.after, 192)?;
    let zero = d.decode();
    if !matches!(zero.mnemonic(), Mnemonic::Xorps | Mnemonic::Pxor)
        || zero.op0_register() != Register::XMM0
        || zero.op1_register() != Register::XMM0
    {
        return None;
    }
    // Record stack stores, resolving a helper-preserved pointer if present.
    // The output buffer need not be the temporary slot used for the key seed.
    let mut zeros = [0; 12];
    let mut zero_count = 0;
    let mut counter = None;
    for _ in 0..12 {
        let i = d.decode();
        if i.mnemonic() == Mnemonic::Xor
            && i.op0_kind() == OpKind::Register
            && i.op1_kind() == OpKind::Register
            && i.op0_register() == i.op1_register()
            && (gpr_width(i.op0_register()) == 32)
            && !matches!(
                i.op0_register(),
                Register::EAX | Register::EBP | Register::ESP
            )
        {
            counter = wide_reg(i.op0_register());
            break;
        }
        if !matches!(i.mnemonic(), Mnemonic::Movaps | Mnemonic::Movdqa)
            || i.op0_kind() != OpKind::Memory
            || i.op1_register() != Register::XMM0
        {
            return None;
        }
        let disp = i.memory_displacement64();
        zeros[zero_count] = if memory(&i, setup.stack_base, NoReg, disp) {
            disp
        } else if matches!(
            setup.stack_reg,
            Register::RBX | Register::R12 | Register::R13 | Register::R14 | Register::R15
        ) && memory(&i, setup.stack_reg, NoReg, disp)
        {
            setup.stack_disp.wrapping_add(disp)
        } else {
            return None;
        };
        zero_count += 1;
    }
    let counter = counter?;
    let source = d.decode();
    if !rip_lea(&source)
        || matches!(source.op0_register(), RAX | RBP | Register::RSP)
        || source.op0_register() == counter
    {
        return None;
    }
    let src = source.op0_register();
    let mut first = d.decode();
    // LLVM sometimes restores an unrelated preserved register before the loop.
    if first.mnemonic() == Mnemonic::Mov
        && first.op0_kind() == OpKind::Register
        && first.op1_kind() == OpKind::Memory
        && matches!(
            first.op0_register(),
            Register::RBX | Register::R12 | Register::R13 | Register::R14 | Register::R15
        )
        && ![counter, src].contains(&first.op0_register())
        && memory(
            &first,
            setup.stack_base,
            NoReg,
            first.memory_displacement64(),
        )
    {
        first = d.decode();
    }
    let mut s = [Instruction::default(); 7];
    s[0] = first;
    for i in &mut s[1..] {
        *i = d.decode();
    }
    if s[0].mnemonic() != Mnemonic::Cmp
        || s[0].op0_register() != counter
        || s[1].mnemonic() != Mnemonic::Ja
        || s[1].op0_kind() != OpKind::NearBranch64
    {
        return None;
    }
    let len = usize::try_from(s[0].try_immediate(1).ok()?.checked_add(1)?).ok()?;
    if len == 0 || len > MAX_LITERAL || len % 8 != 0 {
        return None;
    }
    let tmp = s[2].op0_register();
    let output = s[4].memory_displacement64();
    if s[2].mnemonic() != Mnemonic::Mov
        || !(gpr_width(tmp) == 64)
        || [counter, src, RAX, RBP, Register::RSP].contains(&tmp)
        || s[2].op1_kind() != OpKind::Memory
        || s[2].memory_size() != MemorySize::UInt64
        || !(memory(&s[2], counter, src, 0) || memory(&s[2], src, counter, 0))
        || s[3].mnemonic() != Mnemonic::Xor
        || s[3].op0_register() != tmp
        || s[3].op1_kind() != OpKind::Memory
        || s[3].memory_size() != MemorySize::UInt64
        || !(memory(&s[3], RAX, counter, 0) || memory(&s[3], counter, RAX, 0))
        || s[4].mnemonic() != Mnemonic::Mov
        || s[4].op0_kind() != OpKind::Memory
        || s[4].op1_register() != tmp
        || !memory(&s[4], setup.stack_base, counter, output)
        || !(0..len)
            .step_by(16)
            .all(|n| zeros[..zero_count].contains(&output.wrapping_add(n as u64)))
        || s[5].mnemonic() != Mnemonic::Add
        || s[5].op0_register() != counter
        || s[5].try_immediate(1).ok()? != 8
        || s[6].mnemonic() != Mnemonic::Jmp
        || s[6].op0_kind() != OpKind::NearBranch64
        || s[6].near_branch_target() != s[0].ip()
        || s[1].near_branch_target() < s[6].next_ip()
        || !matching_call_length(code, s[1].near_branch_target(), len as u64)
    {
        return None;
    }
    Some((source.ip_rel_memory_address(), len))
}

// Reject a partial decode: the next call must consume exactly the loop's byte
// count. A tail loop or any intervening control flow is unsupported, not guessed.
fn matching_call_length(code: &Region<'_>, exit: u64, len: u64) -> bool {
    let Some(mut d) = code.decoder(exit, 192) else {
        return false;
    };
    let mut recent = [Instruction::default(); 4];
    for _ in 0..24 {
        let i = d.decode();
        if i.mnemonic() == Mnemonic::Call && i.op0_kind() == OpKind::NearBranch64 {
            for (push, pop, extra) in [
                (recent[2], recent[3], None),
                (recent[1], recent[2], Some(recent[3])),
            ] {
                if push.mnemonic() == Mnemonic::Push
                    && push.try_immediate(0).ok() == Some(len)
                    && pop.mnemonic() == Mnemonic::Pop
                    && ((matches!(pop.op0_register(), Register::RDX | Register::RCX)
                        && extra.is_none_or(|e| {
                            reg_move(&e, Register::RSI, e.op1_register())
                                && gpr_width(e.op1_register()) == 64
                        }))
                        || extra.is_some_and(|e| {
                            gpr_width(pop.op0_register()) == 64
                                && matches!(e.op0_register(), Register::RDX | Register::RCX)
                                && reg_move(&e, e.op0_register(), pop.op0_register())
                        }))
                {
                    return true;
                }
            }
            return false;
        }
        if !matches!(
            i.mnemonic(),
            Mnemonic::Mov
                | Mnemonic::Movaps
                | Mnemonic::Movdqa
                | Mnemonic::Movdqu
                | Mnemonic::Lea
                | Mnemonic::Push
                | Mnemonic::Pop
        ) {
            return false;
        }
        recent.rotate_left(1);
        recent[3] = i;
    }
    false
}

fn gpr_width(r: Register) -> u32 {
    use Register::*;
    if AL <= r && r <= R15L {
        8
    } else if AX <= r && r <= R15W {
        16
    } else if EAX <= r && r <= R15D {
        32
    } else if RAX <= r && r <= R15 {
        64
    } else {
        0
    }
}

fn wide_reg(r: Register) -> Option<Register> {
    use Register::*;
    const GPRS: [Register; 16] = [
        RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15,
    ];
    if !(gpr_width(r) == 32) {
        return Option::None;
    }
    GPRS.get((r as usize).checked_sub(EAX as usize)?).copied()
}

fn slot(r: Register) -> Option<usize> {
    use Register::*;
    Some(match r {
        RAX | EAX | AX | AL => 0,
        RCX | ECX | CX | CL => 1,
        RDX | EDX | DX | DL => 2,
        RSI | ESI | SI | SIL => 3,
        RDI | EDI | DI | DIL => 4,
        _ => return Option::None,
    })
}

fn mask(r: Register) -> Option<u64> {
    if gpr_width(r) == 8 {
        Some(0xff)
    } else if gpr_width(r) == 16 {
        Some(0xffff)
    } else if gpr_width(r) == 32 {
        Some(0xffff_ffff)
    } else if gpr_width(r) == 64 {
        Some(u64::MAX)
    } else {
        None
    }
}

fn read(regs: &[Option<u64>; 5], r: Register) -> Option<u64> {
    // High-byte registers have a different bit offset; this helper grammar
    // uses only low-byte/word aliases and rejects AH/BH/CH/DH.
    if matches!(r, Register::AH | Register::BH | Register::CH | Register::DH) {
        return None;
    }
    Some(regs[slot(r)?]? & mask(r)?)
}

fn operand(regs: &[Option<u64>; 5], i: &Instruction, op: u32) -> Option<u64> {
    if i.op_kind(op) == OpKind::Register {
        read(regs, i.op_register(op))
    } else {
        i.try_immediate(op).ok()
    }
}

#[allow(clippy::cast_possible_truncation)]
fn fold_helper(code: &Region<'_>, addr: u64, base: u64, seed: u64) -> Option<u64> {
    let mut d = code.decoder(addr, 128)?;
    let push = d.decode();
    let frame = d.decode();
    if push.mnemonic() != Mnemonic::Push
        || push.op0_register() != Register::RBP
        || !reg_move(&frame, Register::RBP, Register::RSP)
    {
        return None;
    }
    let mut regs = [None, None, None, Some(seed), Some(base)];
    for _ in 0..24 {
        let i = d.decode();
        if i.mnemonic() == Mnemonic::Pop && i.op0_register() == Register::RBP {
            let ret = d.decode();
            return (ret.mnemonic() == Mnemonic::Ret && ret.op_count() == 0)
                .then_some(regs[0]?)
                .filter(|&v| v >= base);
        }
        let dst = i.op0_register();
        let index = slot(dst)?;
        let width: u32 = if gpr_width(dst) == 32 {
            32
        } else if gpr_width(dst) == 64 {
            64
        } else {
            return None;
        };
        if i.op0_kind() != OpKind::Register || index == 4 || !matches!(width, 32 | 64) {
            return None;
        }
        let value = match i.mnemonic() {
            Mnemonic::Mov | Mnemonic::Movzx => operand(&regs, &i, 1)?,
            Mnemonic::Lea if i.op1_kind() == OpKind::Memory && !i.is_ip_rel_memory_operand() => {
                let base = if i.memory_base() == Register::None {
                    0
                } else {
                    read(&regs, i.memory_base())?
                };
                let index = if i.memory_index() == Register::None {
                    0
                } else {
                    read(&regs, i.memory_index())?
                };
                base.wrapping_add(index.wrapping_mul(u64::from(i.memory_index_scale())))
                    .wrapping_add(i.memory_displacement64())
            }
            Mnemonic::Imul if i.op_count() == 3 => {
                operand(&regs, &i, 1)?.wrapping_mul(operand(&regs, &i, 2)?)
            }
            Mnemonic::Inc => read(&regs, dst)?.wrapping_add(1),
            Mnemonic::Dec => read(&regs, dst)?.wrapping_sub(1),
            Mnemonic::Neg => read(&regs, dst)?.wrapping_neg(),
            Mnemonic::Not => !read(&regs, dst)?,
            op => {
                let a = read(&regs, dst)?;
                let b = operand(&regs, &i, 1)?;
                let shift = (b & (u64::from(width) - 1)) as u32;
                match op {
                    Mnemonic::Add => a.wrapping_add(b),
                    Mnemonic::Sub => a.wrapping_sub(b),
                    Mnemonic::Xor => a ^ b,
                    Mnemonic::Or => a | b,
                    Mnemonic::And => a & b,
                    Mnemonic::Imul => a.wrapping_mul(b),
                    Mnemonic::Shr => a >> shift,
                    Mnemonic::Sar if width == 32 => {
                        u64::from(((a as i32) >> shift).cast_unsigned())
                    }
                    Mnemonic::Sar => ((a as i64) >> shift).cast_unsigned(),
                    Mnemonic::Rol if width == 32 => u64::from((a as u32).rotate_left(shift)),
                    Mnemonic::Rol => a.rotate_left(shift),
                    Mnemonic::Shld => {
                        let n = (operand(&regs, &i, 2)? & (u64::from(width) - 1)) as u32;
                        if n == 0 {
                            a
                        } else {
                            (a << n) | (b >> (width - n))
                        }
                    }
                    _ => return None,
                }
            }
        };
        regs[index] = Some(value & mask(dst)?);
    }
    None
}

#[cfg(test)]
mod tests;
