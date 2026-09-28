//! Constant buffers passed to a verified x86_64 repeating-byte XOR helper.
//! The complete helper signature gates all instruction decoding and state.
//! This is a bounded initializer grammar, not a general x86 emulator.

use crate::{ExtractedString, StringMethod, classify_string};
use goblin::mach::MachO;
use iced_x86::{Decoder, DecoderOptions, Instruction, MemorySize, Mnemonic, OpKind, Register};

const MAX_CODE: usize = 1024 * 1024;
const STACK: usize = 8192;
const MAX_LITERAL: usize = 4096;
const MAX_CALLS: usize = 512;
const MAX_OUTPUT: usize = 64 * 1024;
// for signed i in [0,rdx): rdi[i] ^= rsi[i % rcx]. Full body through RET,
// including its branches and stack counter. No sample-specific keys or data.
const HELPER: &[u8] = b"\x49\x89\xd0\x48\xc7\x44\x24\xf8\0\0\0\0\x4c\x39\x44\x24\xf8\x7d\x31\x66\x2e\x0f\x1f\x84\0\0\0\0\0\x0f\x1f\0\x4c\x8b\x4c\x24\xf8\x4c\x89\xc8\x48\x99\x48\xf7\xf9\x0f\xb6\x04\x16\x42\x30\x04\x0f\x49\xff\xc1\x4c\x89\x4c\x24\xf8\x4c\x39\x44\x24\xf8\x7c\xdc\xc3";

#[derive(Clone, Copy, Default)]
enum Value {
    #[default]
    Unknown,
    Imm(u64),
    Stack(i64),
}
impl Value {
    fn add(self, n: i64) -> Self {
        match self {
            Self::Imm(x) => Self::Imm(x.wrapping_add_signed(n)),
            Self::Stack(x) => x.checked_add(n).map_or(Self::Unknown, Self::Stack),
            Self::Unknown => Self::Unknown,
        }
    }
    fn imm(self) -> Option<u64> {
        if let Self::Imm(x) = self {
            Some(x)
        } else {
            None
        }
    }
}
struct Region<'a> {
    addr: u64,
    offset: u64,
    bytes: &'a [u8],
}
impl Region<'_> {
    fn at(&self, addr: u64, n: usize) -> Option<&[u8]> {
        let pos = usize::try_from(addr.checked_sub(self.addr)?).ok()?;
        self.bytes.get(pos..pos.checked_add(n)?)
    }
}
// Architectural GPR ordering: RAX,RCX,RDX,RBX,RSP,RBP,RSI,RDI,R8..R15.
fn reg(r: Register) -> Option<(usize, usize)> {
    if (Register::RAX..=Register::R15).contains(&r) {
        Some((r as usize - Register::RAX as usize, 8))
    } else if (Register::EAX..=Register::R15D).contains(&r) {
        Some((r as usize - Register::EAX as usize, 4))
    } else {
        None
    }
}
fn vector(r: Register) -> Option<usize> {
    (Register::XMM0..=Register::XMM15)
        .contains(&r)
        .then(|| r as usize - Register::XMM0 as usize)
}
fn range(v: Value, n: usize) -> Option<std::ops::Range<usize>> {
    let Value::Stack(p) = v else { return None };
    let p = usize::try_from(p).ok()?;
    let end = p.checked_add(n)?;
    (end <= STACK).then_some(p..end)
}
struct State {
    regs: [Value; 16],
    vectors: [Option<[u8; 16]>; 16],
    bytes: Box<[u8; STACK]>,
    epochs: Box<[u32; STACK]>,
    epoch: u32,
}
impl State {
    fn new() -> Self {
        let mut s = Self {
            regs: [Value::Unknown; 16],
            vectors: [None; 16],
            bytes: Box::new([0; STACK]),
            epochs: Box::new([0; STACK]),
            epoch: 1,
        };
        s.regs[4] = Value::Stack(STACK as i64);
        s
    }
    fn reset(&mut self) {
        self.regs.fill(Value::Unknown);
        self.vectors.fill(None);
        self.epoch += 1;
    }
    fn get(&self, r: Register) -> Value {
        let Some((idx, width)) = reg(r) else {
            return Value::Unknown;
        };
        match (self.regs[idx], width) {
            (Value::Imm(v), 4) => Value::Imm(v & 0xffff_ffff),
            (v, 8) => v,
            _ => Value::Unknown,
        }
    }
    fn set(&mut self, r: Register, v: Value) -> bool {
        let Some((idx, width)) = reg(r) else {
            return false;
        };
        self.regs[idx] = match (v, width) {
            (Value::Imm(v), 4) => Value::Imm(v & 0xffff_ffff),
            (v, 8) => v,
            _ => Value::Unknown,
        };
        true
    }
    fn address(&self, i: &Instruction) -> Value {
        if i.segment_prefix() != Register::None || i.memory_index() != Register::None {
            return Value::Unknown;
        }
        if i.is_ip_rel_memory_operand() {
            return Value::Imm(i.ip_rel_memory_address());
        }
        self.get(i.memory_base())
            .add(i.memory_displacement64() as i64)
    }
    fn read<'a>(&'a self, v: Value, n: usize, constants: &'a [Region<'_>]) -> Option<&'a [u8]> {
        if let Some(r) = range(v, n) {
            return self.epochs[r.clone()]
                .iter()
                .all(|e| *e == self.epoch)
                .then(|| &self.bytes[r]);
        }
        if let Value::Imm(p) = v {
            return constants.iter().find_map(|c| c.at(p, n));
        }
        None
    }
    fn write(&mut self, v: Value, n: usize, bytes: Option<&[u8]>) {
        if let Some(r) = range(v, n) {
            if let Some(bytes) = bytes {
                self.bytes[r.clone()].copy_from_slice(bytes);
                self.epochs[r].fill(self.epoch);
            } else {
                self.epochs[r].fill(0)
            }
        } else {
            self.epoch += 1
        }
    }
    fn call_clobbers(&mut self) {
        for idx in [0, 1, 2, 6, 7, 8, 9, 10, 11] {
            self.regs[idx] = Value::Unknown
        }
        self.vectors.fill(None);
    }
    fn red_zone(&mut self) {
        // A call invalidates the caller's red zone, even for known callees.
        self.write(self.regs[4].add(-128), 128, None);
    }
    fn step(&mut self, i: &Instruction, constants: &[Region<'_>]) -> bool {
        let src = || {
            if i.op1_kind() == OpKind::Register {
                self.get(i.op1_register())
            } else {
                i.try_immediate(1).ok().map_or(Value::Unknown, Value::Imm)
            }
        };
        match i.mnemonic() {
            Mnemonic::Nop => true,
            Mnemonic::Push if reg(i.op0_register()).is_some_and(|(_, w)| w == 8) => {
                self.regs[4] = self.regs[4].add(-8);
                self.write(self.regs[4], 8, None);
                true
            }
            Mnemonic::Add | Mnemonic::Sub if i.op0_kind() == OpKind::Register => {
                let Some(n) = i.try_immediate(1).ok() else {
                    return false;
                };
                let n = if i.mnemonic() == Mnemonic::Sub {
                    n.wrapping_neg()
                } else {
                    n
                };
                self.set(i.op0_register(), self.get(i.op0_register()).add(n as i64))
            }
            Mnemonic::Lea if i.op0_kind() == OpKind::Register && i.op1_kind() == OpKind::Memory => {
                self.set(i.op0_register(), self.address(i))
            }
            Mnemonic::Mov => {
                if i.op0_kind() == OpKind::Register {
                    let Some((_, n)) = reg(i.op0_register()) else {
                        return false;
                    };
                    let v = if i.op1_kind() == OpKind::Memory {
                        self.read(self.address(i), n, constants)
                            .map_or(Value::Unknown, |b| {
                                let mut raw = [0; 8];
                                raw[..n].copy_from_slice(b);
                                Value::Imm(u64::from_le_bytes(raw))
                            })
                    } else {
                        src()
                    };
                    self.set(i.op0_register(), v)
                } else if i.op0_kind() == OpKind::Memory {
                    let n = match i.memory_size() {
                        MemorySize::UInt8 => 1,
                        MemorySize::UInt16 => 2,
                        MemorySize::UInt32 => 4,
                        MemorySize::UInt64 => 8,
                        _ => return false,
                    };
                    let value = src().imm().map(u64::to_le_bytes);
                    self.write(self.address(i), n, value.as_ref().map(|b| &b[..n]));
                    true
                } else {
                    false
                }
            }
            Mnemonic::Movups | Mnemonic::Movaps | Mnemonic::Movdqu | Mnemonic::Movdqa => {
                if i.op0_kind() == OpKind::Register && i.op1_kind() == OpKind::Memory {
                    let Some(idx) = vector(i.op0_register()) else {
                        return false;
                    };
                    self.vectors[idx] = self
                        .read(self.address(i), 16, constants)
                        .and_then(|b| b.try_into().ok());
                    true
                } else if i.op0_kind() == OpKind::Memory && i.op1_kind() == OpKind::Register {
                    let Some(idx) = vector(i.op1_register()) else {
                        return false;
                    };
                    let bytes = self.vectors[idx];
                    self.write(self.address(i), 16, bytes.as_ref().map(|b| b.as_slice()));
                    true
                } else {
                    false
                }
            }
            _ => false,
        }
    }
}

pub(crate) fn extract_macho(
    macho: &MachO<'_>,
    slice_base: u64,
    min: usize,
) -> Vec<ExtractedString> {
    if macho.header.cputype != goblin::mach::constants::cputype::CPU_TYPE_X86_64 {
        return Vec::new();
    }
    let mut code = None;
    let mut stubs = None;
    let mut constants = [None, None];
    for seg in &macho.segments {
        if seg.name().ok() != Some("__TEXT") {
            continue;
        }
        let Ok(sections) = seg.sections() else {
            continue;
        };
        for (s, bytes) in sections {
            let r = Region {
                addr: s.addr,
                offset: u64::from(s.offset),
                bytes,
            };
            match s.name().ok() {
                Some("__text") if bytes.len() <= MAX_CODE => code = Some(r),
                Some("__stubs") => stubs = Some(r),
                Some("__const") => constants[0] = Some(r),
                Some("__cstring") => constants[1] = Some(r),
                _ => {}
            }
        }
    }
    let Some(code) = code else { return Vec::new() };
    let Some(file_start) = slice_base.checked_add(code.offset) else {
        return Vec::new();
    };
    if code.addr.checked_add(code.bytes.len() as u64).is_none()
        || file_start.checked_add(code.bytes.len() as u64).is_none()
    {
        return Vec::new();
    }
    let helpers: Vec<_> = memchr::memmem::find_iter(code.bytes, HELPER)
        .take(16)
        .map(|p| code.addr + p as u64)
        .collect();
    if helpers.is_empty() {
        return Vec::new();
    }
    let target = |i: &Instruction| {
        (i.mnemonic() == Mnemonic::Call && i.op0_kind() == OpKind::NearBranch64)
            .then(|| i.near_branch_target())
    };
    let last = Decoder::with_ip(64, code.bytes, code.addr, DecoderOptions::NONE)
        .into_iter()
        .filter(|i| target(i).is_some_and(|p| helpers.contains(&p)))
        .map(|i| i.next_ip())
        .last();
    let Some(last) = last else { return Vec::new() };
    let constants: Vec<_> = constants.into_iter().flatten().collect();
    let imports = macho.imports().unwrap_or_default();
    let memcpy: Vec<_> = imports
        .iter()
        .filter(|i| matches!(i.name, "memcpy" | "_memcpy"))
        .map(|i| i.address)
        .collect();
    let is_memcpy = |p| {
        let Some(b) = stubs.as_ref().and_then(|s| s.at(p, 6)) else {
            return false;
        };
        if b[..2] != [0xff, 0x25] {
            return false;
        }
        let disp = i32::from_le_bytes(b[2..].try_into().unwrap());
        p.checked_add(6)
            .and_then(|p| p.checked_add_signed(i64::from(disp)))
            .is_some_and(|slot| memcpy.contains(&slot))
    };
    let mut state = State::new();
    let mut scratch = [0; MAX_LITERAL];
    let mut output = Vec::new();
    let (mut start, mut calls, mut output_bytes) = (0, 0, 0);
    for i in Decoder::with_ip(64, code.bytes, code.addr, DecoderOptions::NONE) {
        if i.ip() >= last {
            break;
        }
        let end = (i.next_ip() - code.addr) as usize;
        if let Some(p) = target(&i) {
            calls += 1;
            if calls > MAX_CALLS {
                break;
            }
            state.red_zone();
            let len = state.regs[2].imm().and_then(|n| usize::try_from(n).ok());
            let dest = state.regs[7];
            let source = state.regs[6];
            if helpers.contains(&p) {
                let key_len = state.regs[1].imm().and_then(|n| usize::try_from(n).ok());
                if let (Some(len), Some(k)) = (
                    len.filter(|n| *n <= MAX_LITERAL),
                    key_len.filter(|n| (1..=32).contains(n)),
                ) {
                    let separate = range(dest, len)
                        .zip(range(source, k))
                        .is_some_and(|(a, b)| a.end <= b.start || b.end <= a.start);
                    if separate
                        && let (Some(cipher), Some(key)) = (
                            state.read(dest, len, &constants),
                            state.read(source, k, &constants),
                        )
                    {
                        for n in 0..len {
                            scratch[n] = cipher[n] ^ key[n % k]
                        }
                        state.write(dest, len, Some(&scratch[..len]));
                        let text = scratch[..len].strip_suffix(&[0]).unwrap_or(&scratch[..len]);
                        if text.len() >= min
                            && text
                                .iter()
                                .all(|b| b.is_ascii_graphic() || b.is_ascii_whitespace())
                        {
                            if output_bytes + text.len() > MAX_OUTPUT {
                                break;
                            }
                            output_bytes += text.len();
                            let value = String::from_utf8(text.to_vec()).unwrap();
                            output.push(ExtractedString {
                                kind: classify_string(&value),
                                value,
                                data_offset: file_start + start as u64,
                                data_len: (end - start) as u32,
                                method: StringMethod::XorDecode,
                                ..Default::default()
                            });
                        }
                    } else {
                        state.epoch += 1
                    }
                } else {
                    state.epoch += 1
                }
                state.call_clobbers();
                start = end;
            } else if is_memcpy(p) {
                if let Some(len) = len.filter(|n| *n <= MAX_LITERAL)
                    && range(dest, len).is_some()
                    && let Some(b) = state.read(source, len, &constants)
                {
                    scratch[..len].copy_from_slice(b);
                    state.write(dest, len, Some(&scratch[..len]));
                } else {
                    state.epoch += 1
                }
                state.call_clobbers();
            } else {
                state.reset();
                start = end
            }
        } else if !state.step(&i, &constants) {
            state.reset();
            start = end
        }
    }
    output
}
