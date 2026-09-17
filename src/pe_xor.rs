//! Bounded x86 repeating-XOR recovery. No OS calls, Rizin, or sample execution.
//!
//! A byte prefilter admits only four distinct MOV reg,imm32 instructions
//! followed by a direct CALL (two mapped pointers and two bounded lengths).
//! A small interpreter follows the callee and its helpers, accepting only
//! sequential in-place byte writes proven to be ciphertext XOR key bytes.
//! Unsupported operations, unknown inputs, malformed mappings and exhausted
//! budgets discard the entire candidate, including all partial strings.

use crate::{ExtractedString, StringFragment, StringMethod};
use goblin::pe::PE;
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};

const MAX_SCAN: usize = 4 * 1024 * 1024;
const MAX_ANCHORS: usize = 65536;
const MAX_CANDIDATES: usize = 4;
const MAX_STEPS: usize = 262144; // Shared by all candidates in a file.
const MAX_CODE: usize = 128;
const MAX_OUTPUT: usize = 16384;
const MAX_STACK: usize = 32;

#[derive(Clone, Copy, Default)]
struct Value {
    n: u32,
    known: bool,
    source: Option<usize>, // File provenance for the low byte.
    xor: Option<(usize, usize)>,
}
impl Value {
    fn number(n: u32) -> Self {
        Self {
            n,
            known: true,
            ..Self::default()
        }
    }
}

struct Image<'a, 'b> {
    pe: &'a PE<'b>,
    data: &'b [u8],
}
impl Image<'_, '_> {
    fn offset(&self, va: u32, len: usize, executable: bool) -> Option<usize> {
        let rva = u64::from(va).checked_sub(self.pe.image_base)?;
        for sec in &self.pe.sections {
            if executable && sec.characteristics & 0x2000_0000 == 0 {
                continue;
            }
            let delta = rva.checked_sub(u64::from(sec.virtual_address));
            let Some(delta) = delta else {
                continue;
            };
            if delta.checked_add(len as u64)? > u64::from(sec.size_of_raw_data) {
                continue;
            }
            let offset = usize::try_from(u64::from(sec.pointer_to_raw_data) + delta).ok()?;
            self.data.get(offset..offset.checked_add(len)?)?;
            return Some(offset);
        }
        None
    }
}

/// Slot and value mask for the supported general registers. Only low-byte
/// aliases are accepted: a high-byte alias (`AH`) would carry provenance for a
/// byte other than the one `Value::source` names, so it is rejected instead.
fn reg(r: Register) -> Option<(usize, u32)> {
    use Register::*;
    Some(match r {
        EAX => (0, u32::MAX),
        ECX => (1, u32::MAX),
        EDX => (2, u32::MAX),
        EBX => (3, u32::MAX),
        ESI => (6, u32::MAX),
        EDI => (7, u32::MAX),
        AL => (0, 255),
        CL => (1, 255),
        DL => (2, 255),
        BL => (3, 255),
        _ => return Option::None,
    })
}
fn get(regs: &[Value; 8], r: Register) -> Option<Value> {
    let (i, mask) = reg(r)?;
    let v = regs[i];
    if !v.known {
        return None;
    }
    // `source` and `xor` describe the low byte, which every alias here shares.
    Some(Value { n: v.n & mask, ..v })
}
fn set(regs: &mut [Value; 8], r: Register, v: Value) -> Option<()> {
    let (i, mask) = reg(r)?;
    if mask == u32::MAX {
        regs[i] = v;
    } else {
        // A partial write keeps the untouched bytes, so they must be known.
        if !regs[i].known {
            return None;
        }
        regs[i].n = (regs[i].n & !mask) | (v.n & mask);
        regs[i].source = v.source;
        regs[i].xor = v.xor;
    }
    Some(())
}
fn address(i: &Instruction, regs: &[Value; 8]) -> Option<u32> {
    if i.segment_prefix() != Register::None {
        return None;
    }
    let base = if i.memory_base() == Register::None {
        0
    } else {
        get(regs, i.memory_base())?.n
    };
    let index = if i.memory_index() == Register::None {
        0
    } else {
        get(regs, i.memory_index())?.n
    };
    Some(
        base.wrapping_add(index.wrapping_mul(i.memory_index_scale()))
            .wrapping_add(i.memory_displacement32()),
    )
}
fn operand(
    i: &Instruction,
    op: u32,
    regs: &[Value; 8],
    image: &Image<'_, '_>,
    output: &Output,
) -> Option<Value> {
    Some(match i.op_kind(op) {
        OpKind::Register => get(regs, i.op_register(op))?,
        OpKind::Immediate32 => Value::number(i.immediate32()),
        OpKind::Immediate8 => Value::number(u32::from(i.immediate8())),
        OpKind::Immediate8to32 => Value::number(i.immediate8to32().cast_unsigned()),
        OpKind::Memory => {
            let size = match i.memory_size() {
                iced_x86::MemorySize::UInt8 => 1,
                iced_x86::MemorySize::UInt32 => 4,
                _ => return None,
            };
            let at = image.offset(address(i, regs)?, size, false)?;
            // Reads must still refer to original bytes, never earlier writes.
            if at < output.start + output.bytes.len() && at + size > output.start {
                return None;
            }
            let n = if size == 1 {
                u32::from(image.data[at])
            } else {
                u32::from_le_bytes(image.data[at..at + 4].try_into().ok()?)
            };
            Value {
                source: Some(at),
                ..Value::number(n)
            }
        }
        _ => return None,
    })
}

struct Output {
    start: usize,
    bytes: Vec<u8>,
    /// File offset and length of the repeating key, known once `interpret`
    /// has proven the write provenance cyclic.
    key: (usize, usize),
}
fn interpret(
    image: &Image<'_, '_>,
    mut regs: [Value; 8],
    mut pc: u32,
    lengths: [usize; 2],
    steps: &mut usize,
) -> Option<Output> {
    let mut stack = [Value::default(); MAX_STACK];
    let mut sp = 1; // Sentinel return at stack[0].
    stack[0] = Value::number(u32::MAX);
    let mut code: Vec<(u32, Instruction)> = Vec::new();
    let mut output = Output {
        start: 0,
        bytes: Vec::new(),
        key: (0, 0),
    };
    // Key byte each output byte came from, proven cyclic before accepting.
    let mut keys: Vec<usize> = Vec::new();
    let mut zero = None;
    loop {
        *steps = steps.checked_sub(1)?;
        let ins = if let Some((_, i)) = code.iter().find(|(va, _)| *va == pc) {
            *i
        } else {
            if code.len() >= MAX_CODE {
                return None;
            }
            let at = image.offset(pc, 1, true)?;
            let mut decoder = Decoder::with_ip(
                32,
                &image.data[at..image.data.len().min(at + 15)],
                u64::from(pc),
                DecoderOptions::NONE,
            );
            let i = decoder.decode();
            if i.is_invalid() || i.has_rep_prefix() || i.has_repne_prefix() || i.has_lock_prefix() {
                return None;
            }
            image.offset(pc, i.len(), true)?;
            code.push((pc, i));
            i
        };
        pc = ins.next_ip32();
        match ins.mnemonic() {
            Mnemonic::Mov | Mnemonic::Movzx => {
                let v = operand(&ins, 1, &regs, image, &output)?;
                if ins.op0_kind() == OpKind::Register {
                    set(&mut regs, ins.op0_register(), v)?;
                } else if ins.op0_kind() == OpKind::Memory
                    && ins.memory_size() == iced_x86::MemorySize::UInt8
                {
                    let at = image.offset(address(&ins, &regs)?, 1, false)?;
                    let (a, b) = v.xor?;
                    let key = if a == at {
                        b
                    } else if b == at {
                        a
                    } else {
                        return None;
                    };
                    if output.bytes.is_empty() {
                        output.start = at;
                    }
                    if at != output.start + output.bytes.len() || output.bytes.len() >= MAX_OUTPUT {
                        return None;
                    }
                    output.bytes.push(v.n.to_le_bytes()[0]);
                    keys.push(key);
                } else {
                    return None;
                }
            }
            Mnemonic::Push => {
                if sp >= MAX_STACK {
                    return None;
                }
                stack[sp] = operand(&ins, 0, &regs, image, &output)?;
                sp += 1;
            }
            Mnemonic::Pop => {
                sp = sp.checked_sub(1)?;
                set(&mut regs, ins.op0_register(), stack[sp])?;
            }
            Mnemonic::Call => {
                if ins.op0_kind() != OpKind::NearBranch32 || sp >= MAX_STACK {
                    return None;
                }
                stack[sp] = Value::number(pc);
                sp += 1;
                pc = ins.near_branch32();
            }
            Mnemonic::Ret => {
                if ins.code() != iced_x86::Code::Retnd {
                    return None;
                }
                sp = sp.checked_sub(1)?;
                pc = stack[sp].n;
                if pc == u32::MAX && sp == 0 {
                    break;
                }
            }
            Mnemonic::Jmp | Mnemonic::Je | Mnemonic::Jne => {
                if ins.op0_kind() != OpKind::NearBranch32 {
                    return None;
                }
                let take = match ins.mnemonic() {
                    Mnemonic::Jmp => true,
                    Mnemonic::Je => zero?,
                    _ => !zero?,
                };
                if take {
                    pc = ins.near_branch32();
                }
            }
            Mnemonic::Inc | Mnemonic::Dec => {
                let v = get(&regs, ins.op0_register())?;
                let n = if ins.mnemonic() == Mnemonic::Inc {
                    v.n.wrapping_add(1)
                } else {
                    v.n.wrapping_sub(1)
                };
                set(&mut regs, ins.op0_register(), Value::number(n))?;
                zero = Some(get(&regs, ins.op0_register())?.n == 0);
            }
            Mnemonic::Xor | Mnemonic::Add | Mnemonic::Sub | Mnemonic::Test | Mnemonic::Cmp => {
                let a = operand(&ins, 0, &regs, image, &output)?;
                let b = operand(&ins, 1, &regs, image, &output)?;
                let n = match ins.mnemonic() {
                    Mnemonic::Xor => a.n ^ b.n,
                    Mnemonic::Add => a.n.wrapping_add(b.n),
                    Mnemonic::Test => a.n & b.n,
                    _ => a.n.wrapping_sub(b.n),
                };
                let mask = if ins.op0_kind() == OpKind::Register {
                    reg(ins.op0_register())?.1
                } else if ins.memory_size() == iced_x86::MemorySize::UInt8 {
                    255
                } else {
                    u32::MAX
                };
                zero = Some(n & mask == 0);
                if !matches!(ins.mnemonic(), Mnemonic::Test | Mnemonic::Cmp) {
                    let mut v = Value::number(n);
                    if ins.mnemonic() == Mnemonic::Xor {
                        v.xor = a.source.zip(b.source);
                    }
                    set(&mut regs, ins.op0_register(), v)?;
                }
            }
            Mnemonic::Nop => {}
            _ => return None,
        }
    }
    // Require a complete bounded buffer, a real cyclic key, and no aliasing.
    let n = output.bytes.len();
    if !lengths.contains(&n) || n < 4 {
        return None;
    }
    let first = *keys.first()?;
    let key_len = keys
        .iter()
        .skip(1)
        .position(|&k| k == first)
        .map(|x| x + 1)?;
    if key_len > 64 || !lengths.contains(&key_len) {
        return None;
    }
    if keys
        .iter()
        .enumerate()
        .any(|(i, &k)| k != first + i % key_len)
    {
        return None;
    }
    if first < output.start + n && first + key_len > output.start {
        return None;
    }
    // Do not accept a decoder that overwrites any instruction it follows.
    for (va, instruction) in &code {
        let at = image.offset(*va, instruction.len(), true)?;
        if at < output.start + n && at + instruction.len() > output.start {
            return None;
        }
    }
    output.key = (first, key_len);
    Some(output)
}

/// Recover strings without guessing keys or scanning every possible alignment.
/// Budgets are per file, not per section or candidate.
pub(crate) fn extract(pe: &PE<'_>, data: &[u8], min_length: usize) -> Vec<ExtractedString> {
    if pe.header.coff_header.machine != 0x14c || pe.is_64 || pe.sections.len() > 96 {
        return Vec::new();
    }
    let image = Image { pe, data };
    let mut remaining = MAX_SCAN;
    let mut anchors = MAX_ANCHORS;
    let mut candidates = MAX_CANDIDATES;
    let mut steps = MAX_STEPS;
    let mut results = Vec::new();
    'sections: for sec in &pe.sections {
        if sec.characteristics & 0x2000_0000 == 0 {
            continue;
        }
        let start = sec.pointer_to_raw_data as usize;
        let len = (sec.size_of_raw_data as usize).min(remaining);
        let Some(code) = data.get(start..start.saturating_add(len)) else {
            continue;
        };
        remaining -= len;
        for call in memchr::memchr_iter(0xe8, code) {
            // Only `anchors` is spent here; the other budgets are checked where
            // they are consumed, keeping this loop down to one counter.
            if anchors == 0 {
                break 'sections;
            }
            anchors -= 1;
            // Four `mov reg, imm32` and then this CALL. This gate sees every
            // CALL byte in the file, so it reads the four opcodes before
            // building any state, from a fixed-size window that needs no
            // bounds checks. The accepted opcodes are the registers the
            // interpreter models — never ESP or EBP.
            if call + 5 > code.len() {
                continue;
            }
            let Some(setup) = code[..call].last_chunk::<20>() else {
                continue;
            };
            if !setup
                .iter()
                .step_by(5)
                .all(|&op| matches!(op, 0xb8..=0xbb | 0xbe..=0xbf))
            {
                continue;
            }
            // The immediates must be two mapped pointers and two bounded
            // lengths, written to distinct registers, with one length short
            // enough to be a key.
            let mut regs = [Value::default(); 8];
            let mut lengths = [0; 2];
            let plausible = 'setup: {
                let (mut lens, mut pointers) = (0, 0);
                for mov in setup.as_chunks::<5>().0 {
                    let r = usize::from(mov[0] - 0xb8);
                    if regs[r].known {
                        break 'setup false;
                    }
                    let n = u32::from_le_bytes([mov[1], mov[2], mov[3], mov[4]]);
                    regs[r] = Value::number(n);
                    if image.offset(n, 1, false).is_some() {
                        pointers += 1;
                    } else if n > 0 && u64::from(n) <= MAX_OUTPUT as u64 && lens < 2 {
                        lengths[lens] = n as usize;
                        lens += 1;
                    } else {
                        break 'setup false;
                    }
                }
                lens == 2 && pointers == 2 && lengths.iter().any(|&n| n <= 64)
            };
            if !plausible {
                continue;
            }
            let call_va = pe.image_base + u64::from(sec.virtual_address) + call as u64;
            let Ok(call_va) = u32::try_from(call_va) else {
                continue;
            };
            let displacement = u32::from_le_bytes([
                code[call + 1],
                code[call + 2],
                code[call + 3],
                code[call + 4],
            ]);
            let target = call_va.wrapping_add(5).wrapping_add(displacement);
            if image.offset(target, 1, true).is_none() {
                continue;
            }
            candidates -= 1;
            if let Some(output) = interpret(&image, regs, target, lengths, &mut steps) {
                let before = results.len();
                append_strings(&output, min_length, &mut results);
                tracing::debug!(
                    "PE XOR: {target:#x} decoded {} bytes at {:#x} under a {}-byte key at \
                     {:#x}, yielding {} strings",
                    output.bytes.len(),
                    output.start,
                    output.key.1,
                    output.key.0,
                    results.len() - before
                );
            } else {
                tracing::debug!("PE XOR: rejected {target:#x}, called from {call_va:#x}");
            }
            if candidates == 0 || steps == 0 {
                break 'sections;
            }
        }
        if remaining == 0 {
            break;
        }
    }
    if anchors == 0 || candidates == 0 || steps == 0 {
        tracing::debug!(
            "PE XOR: budget spent (anchors={anchors} candidates={candidates} steps={steps}), \
             keeping {} strings",
            results.len()
        );
    }
    results
}

fn append_strings(output: &Output, min_length: usize, out: &mut Vec<ExtractedString>) {
    let (key_start, key_len) = output.key;
    // ASCII and UTF-16LE; do not recursively invoke the full extraction pipeline.
    for width in [1, 2] {
        let mut at = 0;
        while at < output.bytes.len() {
            let start = at;
            while at < output.bytes.len()
                && (32..=126).contains(&output.bytes[at])
                && (width == 1 || output.bytes.get(at + 1) == Some(&0))
            {
                at += width;
            }
            let len = at - start;
            if len / width >= min_length
                && output.bytes.get(at) == Some(&0)
                && (width == 1 || output.bytes.get(at + 1) == Some(&0))
            {
                let value: String = output.bytes[start..at]
                    .iter()
                    .step_by(width)
                    .map(|&b| char::from(b))
                    .collect();
                out.push(ExtractedString {
                    kind: crate::classifier::classify_string(&value),
                    value,
                    data_offset: (output.start + start) as u64,
                    data_len: u32::try_from(len).unwrap_or(u32::MAX),
                    method: StringMethod::XorDecode,
                    fragments: Some(Box::new(vec![
                        StringFragment {
                            offset: (output.start + start) as u64,
                            length: len,
                        },
                        StringFragment {
                            offset: key_start as u64,
                            length: key_len,
                        },
                    ])),
                });
            }
            at = at.saturating_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn put32(b: &mut [u8], at: usize, n: u32) {
        b[at..at + 4].copy_from_slice(&n.to_le_bytes());
    }
    fn fixture(key: &[u8], inline: bool, base: u32, cipher: usize) -> Vec<u8> {
        let mut b = vec![0; 0x3000];
        b[..2].copy_from_slice(b"MZ");
        put32(&mut b, 0x3c, 0x80);
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        b[0x84..0x86].copy_from_slice(&0x14cu16.to_le_bytes());
        b[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        b[0x94..0x96].copy_from_slice(&224u16.to_le_bytes());
        b[0x98..0x9a].copy_from_slice(&0x10bu16.to_le_bytes());
        put32(&mut b, 0x98 + 28, base);
        put32(&mut b, 0x98 + 32, 0x1000);
        put32(&mut b, 0x98 + 36, 0x200);
        put32(&mut b, 0x98 + 56, 0x4000);
        put32(&mut b, 0x98 + 60, 0x200);
        b[0x178..0x17d].copy_from_slice(b".text");
        put32(&mut b, 0x180, 0x2e00);
        put32(&mut b, 0x184, 0x1000);
        put32(&mut b, 0x188, 0x2e00);
        put32(&mut b, 0x18c, 0x200);
        put32(&mut b, 0x19c, 0x60000020);
        let va = |off: usize| base + 0x1000 + u32::try_from(off - 0x200).unwrap();
        let plain = [
            b"InternetReadFile\0ShellExecuteW\0WriteFile\0https://example.invalid/payload\0"
                .as_slice(),
            b"ordinary recovered text\0ordinary recovered text\0",
        ]
        .concat();
        b[0x600..0x600 + key.len()].copy_from_slice(key);
        for (i, &x) in plain.iter().enumerate() {
            b[cipher + i] = x ^ key[i % key.len()];
        }
        let (src, dst) = if inline {
            (cipher, 0x600)
        } else {
            (0x600, cipher)
        };
        for (j, (op, n)) in [
            (0xb8, u32::try_from(key.len()).unwrap()),
            (0xbe, va(src)),
            (0xbf, va(dst)),
            (0xb9, u32::try_from(plain.len()).unwrap()),
        ]
        .into_iter()
        .enumerate()
        {
            b[0x200 + j * 5] = op;
            put32(&mut b, 0x201 + j * 5, n);
        }
        b[0x214] = 0xe8;
        put32(&mut b, 0x215, va(0x300).wrapping_sub(va(0x219)));
        if inline {
            // Different register roles, a memory XOR operand, and no helpers.
            let code = [
                0x8b, 0xd8, 0x8b, 0x17, 0x32, 0x16, 0x88, 0x16, 0x46, 0x47, 0x4b, 0x75, 0x04, 0x2b,
                0xf8, 0x8b, 0xd8, 0x49, 0x75, 0xee, 0xc3,
            ];
            b[0x300..0x300 + code.len()].copy_from_slice(&code);
        } else {
            // Split helper decoder: saves count while loading ciphertext,
            // calls XOR and store helpers, then rewinds the key each cycle.
            let code = [
                0x8b, 0xd8, 0x57, 0x53, 0x53, 0xe8, 0, 0, 0, 0, 0x85, 0xc0, 0x74, 0x07, 0x49, 0x75,
                0xf4, 0x5b, 0x5b, 0x5f, 0xc3, 0x5b, 0x2b, 0xf3, 0x53, 0xeb, 0xf3,
            ];
            b[0x300..0x300 + code.len()].copy_from_slice(&code);
            put32(&mut b, 0x306, va(0x380).wrapping_sub(va(0x30a)));
            let helper = [
                0x51, 0x8b, 0x0f, 0xe8, 0, 0, 0, 0, 0xe8, 0, 0, 0, 0, 0x47, 0x4b, 0x8b, 0xc3, 0x59,
                0xc3,
            ];
            b[0x380..0x380 + helper.len()].copy_from_slice(&helper);
            put32(&mut b, 0x384, va(0x400).wrapping_sub(va(0x388)));
            put32(&mut b, 0x389, va(0x420).wrapping_sub(va(0x38d)));
            b[0x400..0x405].copy_from_slice(&[0x8b, 0x06, 0x32, 0xc1, 0xc3]);
            b[0x420..0x424].copy_from_slice(&[0x88, 0x07, 0x46, 0xc3]);
        }
        b
    }
    fn strings(b: &[u8]) -> Vec<ExtractedString> {
        let pe = PE::parse(b).unwrap();
        extract(&pe, b, 4)
    }
    #[test]
    fn recovers_helpers_and_inline_with_varied_keys_addresses_and_registers() {
        for inline in [false, true] {
            for len in [1_u8, 7, 20, 31] {
                let key: Vec<_> = (0..len)
                    .map(|i| i.wrapping_mul(37).wrapping_add(71))
                    .collect();
                for (base, offset) in [(0x400000, 0x800), (0x12000000, 0x1700)] {
                    let b = fixture(&key, inline, base, offset);
                    let found = strings(&b);
                    let s = found
                        .iter()
                        .find(|s| s.value == "InternetReadFile")
                        .unwrap_or_else(|| panic!("inline={inline}, key={len}: {found:?}"));
                    assert_eq!(s.data_offset, offset as u64);
                    assert_eq!(s.method, StringMethod::XorDecode);
                    assert_eq!(
                        s.source_spans().collect::<Vec<_>>(),
                        vec![(offset as u64, 16), (0x600, u64::from(len))]
                    );
                    assert!(found.iter().any(|s| s.value == "ShellExecuteW"));
                }
            }
        }
    }
    #[test]
    fn refuses_unproven_partial_and_malformed_decoders() {
        for replacement in [
            vec![0xc3],
            vec![0xeb, 0xfe],
            vec![0x0f, 0x05],
            vec![0xff, 0xd0],
        ] {
            let mut b = fixture(b"test-key", false, 0x400000, 0x800);
            b[0x400..0x400 + replacement.len()].copy_from_slice(&replacement);
            assert!(strings(&b).is_empty());
        }
        let mut b = fixture(b"test-key", false, 0x400000, 0x800);
        put32(&mut b, 0x206, 0xfffffff0); // Invalid key VA.
        assert!(strings(&b).is_empty());
        let mut b = fixture(b"test-key", false, 0x400000, 0x800);
        put32(&mut b, 0x210, u32::MAX); // Unbounded buffer size.
        assert!(strings(&b).is_empty());
        let mut b = fixture(b"test-key", false, 0x400000, 0x800);
        b[0x401] = 0x07; // Both inputs read ciphertext, not a separate key.
        assert!(strings(&b).is_empty());
    }
    #[test]
    fn rejects_reads_of_modified_bytes_and_self_modifying_decoder() {
        let b = fixture(b"test-key", false, 0x400000, 0x300);
        let pe = PE::parse(&b).unwrap();
        let image = Image { pe: &pe, data: &b };
        let mut regs = [Value::default(); 8];
        for mov in b[0x200..0x214].as_chunks::<5>().0 {
            regs[usize::from(mov[0] - 0xb8)] =
                Value::number(u32::from_le_bytes(mov[1..].try_into().unwrap()));
        }
        let len = regs[1].n as usize;
        let mut steps = MAX_STEPS;
        assert!(interpret(&image, regs, 0x401100, [8, len], &mut steps).is_none());

        let instruction = Decoder::new(32, &[0x8b, 0x07], DecoderOptions::NONE).decode();
        let output = Output {
            start: 0x300,
            bytes: vec![0],
            key: (0x600, 1),
        };
        assert!(operand(&instruction, 1, &regs, &image, &output).is_none());
        regs[7].n += 1;
        assert!(operand(&instruction, 1, &regs, &image, &output).is_some());
    }

    #[test]
    fn respects_setup_order_machine_and_section_bounds() {
        let mut b = fixture(b"another-key", true, 0x400000, 0x800);
        let setup = b[0x200..0x214].to_vec();
        for i in 0..4 {
            b[0x200 + i * 5..0x205 + i * 5].copy_from_slice(&setup[(3 - i) * 5..(4 - i) * 5]);
        }
        assert!(strings(&b).iter().any(|s| s.value == "InternetReadFile"));
        let original = b.clone();
        put32(&mut b, 0x19c, 0x40000040); // Non-executable region.
        assert!(strings(&b).is_empty());
        let mut b = original.clone();
        put32(&mut b, 0x188, 0xfffffff0); // Section runs off the file.
        assert!(strings(&b).is_empty());
        let mut b = original;
        b[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        assert!(strings(&b).is_empty());
    }

    #[test]
    fn emits_wide_string_ciphertext_and_key_spans() {
        let mut output = Output {
            start: 0x800,
            bytes: Vec::new(),
            key: (0x600, 3),
        };
        for c in "Wide content".encode_utf16().chain([0]) {
            output.bytes.extend_from_slice(&c.to_le_bytes());
        }
        let mut out = Vec::new();
        append_strings(&output, 4, &mut out);
        let s = out.iter().find(|s| s.value == "Wide content").unwrap();
        assert_eq!(
            s.source_spans().collect::<Vec<_>>(),
            vec![(0x800, 24), (0x600, 3)]
        );
        output.bytes.pop();
        out.clear();
        append_strings(&output, 4, &mut out);
        assert!(out.is_empty(), "incomplete UTF-16 terminator");
    }

    #[test]
    fn shared_step_budget_terminates_loops() {
        let mut b = fixture(b"test-key", false, 0x400000, 0x800);
        b[0x300..0x302].copy_from_slice(&[0xeb, 0xfe]);
        let pe = PE::parse(&b).unwrap();
        let image = Image { pe: &pe, data: &b };
        let mut steps = 100;
        assert!(
            interpret(
                &image,
                [Value::default(); 8],
                0x401100,
                [8, 100],
                &mut steps
            )
            .is_none()
        );
        assert_eq!(steps, 0);
    }
    #[test]
    #[ignore = "manual release benchmark, no CI timing threshold"]
    fn benchmark_prefilter_and_recovery() {
        let b = fixture(b"arbitrary-key-1234567", false, 0x400000, 0x800);
        if let Ok(path) = std::env::var("STNG_XOR_FIXTURE_OUT") {
            std::fs::write(path, &b).unwrap();
        }
        let pe = PE::parse(&b).unwrap();
        let start = Instant::now();
        for _ in 0..1000 {
            std::hint::black_box(extract(&pe, &b, 4));
        }
        eprintln!("decoder: {:?}/file", start.elapsed() / 1000);
        let mut clean = b.clone();
        clean[0x200..].fill(0x90);
        let pe = PE::parse(&clean).unwrap();
        let start = Instant::now();
        for _ in 0..100000 {
            std::hint::black_box(extract(&pe, &clean, 4));
        }
        eprintln!("no candidate (12 KiB): {:?}/file", start.elapsed() / 100000);
        // Large code section with realistic call-byte density, but no setup.
        clean.resize(1024 * 1024 + 0x200, 0x90);
        put32(&mut clean, 0x188, 1024 * 1024);
        for at in (0x200..clean.len()).step_by(32) {
            clean[at] = 0xe8;
        }
        let pe = PE::parse(&clean).unwrap();
        let start = Instant::now();
        for _ in 0..1000 {
            std::hint::black_box(extract(&pe, &clean, 4));
        }
        eprintln!(
            "no candidate (1 MiB, dense CALLs): {:?}/file",
            start.elapsed() / 1000
        );
        for name in [
            "rtc.dll",
            "hello_windows.exe",
            "does-nothing-windows-amd64.exe",
        ] {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/testdata")
                .join(name);
            let Ok(bytes) = std::fs::read(path) else {
                continue;
            };
            let Ok(pe) = PE::parse(&bytes) else {
                continue;
            };
            if pe.header.coff_header.machine != 0x14c || pe.is_64 {
                // `extract` returns before touching these, so timing them would
                // report the machine check rather than the scan.
                eprintln!("benign {name}: skipped, not an x86 PE");
                continue;
            }
            let start = Instant::now();
            for _ in 0..1000 {
                assert!(
                    extract(&pe, &bytes, 4).is_empty(),
                    "unexpected decode in {name}"
                );
            }
            eprintln!(
                "benign {name} ({} bytes): {:?}/file",
                bytes.len(),
                start.elapsed() / 1000
            );
        }
        let mut bad = b.clone();
        bad[0x300..0x302].copy_from_slice(&[0xeb, 0xfe]);
        let pe = PE::parse(&bad).unwrap();
        let start = Instant::now();
        for _ in 0..100 {
            assert!(extract(&pe, &bad, 4).is_empty());
        }
        eprintln!(
            "budget-exhausting decoder: {:?}/file",
            start.elapsed() / 100
        );
        if let Ok(path) = std::env::var("STNG_XOR_SAMPLE") {
            let b = std::fs::read(path).unwrap();
            let pe = PE::parse(&b).unwrap();
            let start = Instant::now();
            for _ in 0..1000 {
                std::hint::black_box(extract(&pe, &b, 4));
            }
            eprintln!(
                "analyst specimen decoder: {:?}/file",
                start.elapsed() / 1000
            );
        }
    }
    #[test]
    #[ignore = "local analyst specimen; not required by CI"]
    fn analyst_sample() {
        let path = std::env::var("STNG_XOR_SAMPLE").expect("set STNG_XOR_SAMPLE");
        let b = std::fs::read(path).unwrap();
        let now = Instant::now();
        let found = strings(&b);
        eprintln!("sample recovery including PE parse: {:?}", now.elapsed());
        for s in &found {
            eprintln!("{} @ {:#x}", s.value, s.data_offset);
        }
        assert!(found.iter().any(|s| s.value == "InternetReadFile"));
        assert!(found.iter().any(|s| s.value == "ShellExecuteW"));
        assert!(found.iter().any(|s| s.value == "packaging-labelling.com"));
    }
}
