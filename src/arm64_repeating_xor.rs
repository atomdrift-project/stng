//! Constant initialization feeding a verified ARM64 repeating-key XOR helper.
//! No key search: the call supplies both buffer lengths and the initialized key.
//! The initializer grammar is deliberately small; unsupported instructions and
//! unknown calls invalidate tracked state. A helper signature gates stack state.

use crate::{ExtractedString, StringMethod, classify_string};
use goblin::mach::MachO;

const MAX_CODE: usize = 1024 * 1024;
const STACK_SIZE: usize = 8192;
const MAX_LITERAL: usize = 4096;
const MAX_HELPERS: usize = 16;
const MAX_CALLS: usize = 512;
const MAX_OUTPUT: usize = 64 * 1024;

// x0[i] ^= x1[i % x3], for signed i in [0,x2). The full body proves the
// operation, bounds, memory effects, and preservation of x19..x29 and SP.
const HELPER: [u32; 17] = [
    0xd10043ff, 0xf90007ff, 0xf94007e8, 0xeb02011f, 0x5400016a, 0xf94007e8, 0x9ac30d09, 0x9b03a129,
    0x38696829, 0x3868680a, 0x4a0a0129, 0x38286809, 0x91000508, 0xf90007e8, 0x17fffff4, 0x910043ff,
    0xd65f03c0,
];

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
            Self::Imm(v) => Self::Imm(v.wrapping_add_signed(n)),
            Self::Stack(v) => v.checked_add(n).map_or(Self::Unknown, Self::Stack),
            Self::Unknown => Self::Unknown,
        }
    }
    fn imm(self) -> Option<u64> {
        if let Self::Imm(v) = self {
            Some(v)
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
    fn at(&self, addr: u64, size: usize) -> Option<&[u8]> {
        let start = usize::try_from(addr.checked_sub(self.addr)?).ok()?;
        self.bytes.get(start..start.checked_add(size)?)
    }
}

struct State {
    regs: [Value; 31],
    vectors: [Option<[u8; 16]>; 32],
    bytes: Box<[u8; STACK_SIZE]>,
    epochs: Box<[u32; STACK_SIZE]>,
    epoch: u32,
}

impl State {
    fn new() -> Self {
        Self {
            regs: [Value::Unknown; 31],
            vectors: [None; 32],
            bytes: Box::new([0; STACK_SIZE]),
            epochs: Box::new([0; STACK_SIZE]),
            epoch: 1,
        }
    }
    fn reset(&mut self) {
        self.regs.fill(Value::Unknown);
        self.vectors.fill(None);
        self.invalidate_memory();
    }
    fn invalidate_memory(&mut self) {
        // Fewer than three invalidations per instruction; MAX_CODE prevents wrap.
        self.epoch += 1;
    }
    fn caller_clobbers(&mut self) {
        self.regs[..19].fill(Value::Unknown);
        self.regs[30] = Value::Unknown;
        self.vectors.fill(None);
        // BL overwrites x30; the frame pointer and saved x19..x29 survive.
    }
    fn base(&self, r: usize) -> Value {
        if r == 31 {
            Value::Stack(0)
        } else {
            self.regs[r]
        }
    }
    fn range(addr: Value, size: usize) -> Option<std::ops::Range<usize>> {
        let Value::Stack(offset) = addr else {
            return None;
        };
        let start = usize::try_from(offset).ok()?;
        let end = start.checked_add(size)?;
        (end <= STACK_SIZE).then_some(start..end)
    }
    fn read<'a>(
        &'a self,
        addr: Value,
        size: usize,
        constants: &'a [Region<'_>],
    ) -> Option<&'a [u8]> {
        if let Value::Imm(va) = addr {
            return constants.iter().find_map(|r| r.at(va, size));
        }
        let range = Self::range(addr, size)?;
        self.epochs[range.clone()]
            .iter()
            .all(|&e| e == self.epoch)
            .then(|| &self.bytes[range])
    }
    fn write(&mut self, addr: Value, size: usize, value: Option<&[u8]>) {
        let Some(range) = Self::range(addr, size) else {
            // An unresolved destination could alias any tracked stack byte.
            self.invalidate_memory();
            return;
        };
        if let Some(bytes) = value {
            self.bytes[range.clone()].copy_from_slice(bytes);
            self.epochs[range].fill(self.epoch);
        } else {
            self.epochs[range].fill(0);
        }
    }
}

fn word(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes[..4].try_into().unwrap())
}

fn adrp(w: u32, pc: u64) -> Option<(usize, u64)> {
    if w & 0x9f00_0000 != 0x9000_0000 {
        return None;
    }
    let imm = i64::from(((w >> 5) & 0x7ffff) << 2 | ((w >> 29) & 3));
    Some((
        (w & 31) as usize,
        (pc & !4095).wrapping_add_signed((imm << 43 >> 43) << 12),
    ))
}

fn branch(w: u32, pc: u64) -> Option<u64> {
    (w & 0xfc00_0000 == 0x9400_0000)
        .then(|| pc.wrapping_add_signed((i64::from(w & 0x03ff_ffff) << 38) >> 36))
}

pub(crate) fn extract_macho(
    macho: &MachO<'_>,
    slice_base: u64,
    min: usize,
) -> Vec<ExtractedString> {
    if macho.header.cputype != goblin::mach::constants::cputype::CPU_TYPE_ARM64 {
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
    if code.addr.checked_add(code.bytes.len() as u64).is_none() {
        return Vec::new();
    }
    let Some(file_start) = slice_base.checked_add(code.offset) else {
        return Vec::new();
    };
    if file_start.checked_add(code.bytes.len() as u64).is_none() {
        return Vec::new();
    }
    let mut signature = [0; HELPER.len() * 4];
    for (bytes, w) in signature.chunks_exact_mut(4).zip(HELPER) {
        bytes.copy_from_slice(&w.to_le_bytes());
    }
    let helpers: Vec<u64> = memchr::memmem::find_iter(code.bytes, &signature)
        .filter(|n| n % 4 == 0)
        .take(MAX_HELPERS)
        .map(|n| code.addr + n as u64)
        .collect();
    if helpers.is_empty() {
        return Vec::new();
    }
    let constants: Vec<_> = constants.into_iter().flatten().collect();
    let Some(last_call) = code
        .bytes
        .as_chunks::<4>()
        .0
        .iter()
        .enumerate()
        .rposition(|(idx, b)| {
            branch(word(b), code.addr + (idx * 4) as u64)
                .is_some_and(|target| helpers.contains(&target))
        })
    else {
        return Vec::new();
    };
    let imports = macho.imports().unwrap_or_default();
    let memcpy_slots: Vec<u64> = imports
        .iter()
        .filter(|i| matches!(i.name, "memcpy" | "_memcpy"))
        .map(|i| i.address)
        .collect();
    let is_memcpy = |target| -> bool {
        let Some(b) = stubs.as_ref().and_then(|r| r.at(target, 12)) else {
            return false;
        };
        let Some((16, page)) = adrp(word(b), target) else {
            return false;
        };
        let load = word(&b[4..]);
        // ADRP x16; LDR x16,[x16,#imm]; BR x16, bound to dyld's memcpy import.
        load & 0xffc0_03ff == 0xf940_0210
            && word(&b[8..]) == 0xd61f_0200
            && page
                .checked_add(u64::from((load >> 10) & 4095) * 8)
                .is_some_and(|slot| memcpy_slots.contains(&slot))
    };
    let mut state = State::new();
    let mut results = Vec::new();
    let mut output_bytes = 0;
    let mut folded_calls = 0;
    let mut start = 0;
    for (idx, b) in code.bytes.as_chunks::<4>().0[..=last_call]
        .iter()
        .enumerate()
    {
        let w = word(b);
        let pc = code.addr + (idx * 4) as u64;
        if let Some(target) = branch(w, pc) {
            if helpers.contains(&target) {
                folded_calls += 1;
                if let Some(len) = state.regs[2].imm().and_then(|n| usize::try_from(n).ok())
                    && let Some(key_len) = state.regs[3].imm().and_then(|n| usize::try_from(n).ok())
                    && (1..=MAX_LITERAL).contains(&len)
                    && len <= MAX_OUTPUT - output_bytes
                    && (1..=32).contains(&key_len)
                    && let Some(cipher_range) = State::range(state.regs[0], len)
                    && let Some(key_range) = State::range(state.regs[1], key_len)
                    && (cipher_range.end <= key_range.start || key_range.end <= cipher_range.start)
                    && let Some(cipher) = state.read(state.regs[0], len, &constants)
                    && let Some(key) = state.read(state.regs[1], key_len, &constants)
                {
                    let decoded: Vec<u8> = cipher
                        .iter()
                        .enumerate()
                        .map(|(i, b)| b ^ key[i % key_len])
                        .collect();
                    let dst = state.regs[0];
                    state.write(dst, len, Some(&decoded));
                    let text = decoded.strip_suffix(&[0]).unwrap_or(&decoded);
                    if text.len() >= min
                        && text
                            .iter()
                            .all(|b| b.is_ascii_graphic() || b.is_ascii_whitespace())
                        && let Ok(value) = std::str::from_utf8(text)
                    {
                        output_bytes += len;
                        results.push(ExtractedString {
                            value: value.to_string(),
                            kind: classify_string(value),
                            data_offset: file_start + start as u64,
                            data_len: (idx * 4 + 4 - start) as u32,
                            method: StringMethod::XorDecode,
                            ..Default::default()
                        });
                    }
                } else {
                    state.invalidate_memory();
                }
                state.caller_clobbers();
                // Each literal gets its own construction/call evidence span.
                start = idx * 4 + 4;
            } else if is_memcpy(target) {
                folded_calls += 1;
                let data = state.regs[2]
                    .imm()
                    .and_then(|n| usize::try_from(n).ok())
                    .filter(|&n| n <= MAX_LITERAL)
                    .and_then(|n| state.read(state.regs[1], n, &constants).map(<[u8]>::to_vec));
                if let Some(data) = data {
                    let dst = state.regs[0];
                    state.write(dst, data.len(), Some(&data));
                } else {
                    state.invalidate_memory();
                }
                state.caller_clobbers();
            } else {
                state.reset();
                start = idx * 4 + 4;
            }
        } else if !initialize(&mut state, w, pc, &constants) {
            state.reset();
            start = idx * 4 + 4;
        }
        if output_bytes >= MAX_OUTPUT || folded_calls >= MAX_CALLS {
            break;
        }
    }
    results
}

/// Fold only literal construction and copies. Register and stack provenance are
/// separate; loads cannot reinterpret an integer as an arbitrary stack address.
fn initialize(s: &mut State, w: u32, pc: u64, constants: &[Region<'_>]) -> bool {
    let rd = (w & 31) as usize;
    let rn = ((w >> 5) & 31) as usize;
    if let Some((rd, addr)) = adrp(w, pc) {
        if rd < 31 {
            s.regs[rd] = Value::Imm(addr);
        }
        return true;
    }
    if w & 0x7f80_0000 == 0x5280_0000 || w & 0x7f80_0000 == 0x7280_0000 {
        if rd == 31 {
            return true;
        }
        let shift = ((w >> 21) & 3) * 16;
        if w >> 31 == 0 && shift >= 32 {
            return false;
        }
        let imm = u64::from((w >> 5) & 0xffff) << shift;
        let value = if w & 0x2000_0000 == 0 {
            Some(imm)
        } else {
            s.regs[rd].imm().map(|v| (v & !(0xffff << shift)) | imm)
        };
        s.regs[rd] = value.map_or(Value::Unknown, |v| {
            Value::Imm(if w >> 31 == 0 { v & 0xffff_ffff } else { v })
        });
        return true;
    }
    if w & 0xff80_0000 == 0x9100_0000 {
        if rd == 31 {
            return false;
        }
        s.regs[rd] = s
            .base(rn)
            .add(i64::from((w >> 10) & 4095) << (if w & (1 << 22) != 0 { 12 } else { 0 }));
        return true;
    }
    // Offset-only scalar or Q-vector loads/stores; no writeback or register offsets.
    let (size, load, vector, offset, second) =
        if w & 0x3b00_0000 == 0x3900_0000 || w & 0x3b20_0c00 == 0x3800_0000 {
            let vector = w & (1 << 26) != 0;
            let opc = (w >> 22) & 3;
            let size = if vector {
                if w >> 30 != 0 || opc < 2 {
                    return false;
                }
                16
            } else {
                if opc > 1 {
                    return false;
                }
                1 << (w >> 30)
            };
            let offset = if w & (1 << 24) != 0 {
                i64::from((w >> 10) & 4095) * size as i64
            } else {
                (i64::from((w >> 12) & 511) << 55) >> 55
            };
            (size, opc & 1 != 0, vector, offset, None)
        } else if w & 0xff80_0000 == 0xad00_0000 {
            (
                16,
                w & (1 << 22) != 0,
                true,
                ((i64::from((w >> 15) & 127) << 57) >> 57) * 16,
                Some(((w >> 10) & 31) as usize),
            )
        } else {
            return false;
        };
    let addr = s.base(rn).add(offset);
    for (r, addr) in [(Some(rd), addr), (second, addr.add(size as i64))] {
        let Some(r) = r else { continue };
        if load {
            let bytes = s.read(addr, size, constants);
            if vector {
                s.vectors[r] = bytes.and_then(|b| b.try_into().ok());
            } else if r < 31 {
                s.regs[r] = bytes.map_or(Value::Unknown, |b| {
                    let mut n = [0; 8];
                    n[..size].copy_from_slice(b);
                    Value::Imm(u64::from_le_bytes(n))
                });
            }
        } else {
            let bytes = if vector {
                s.vectors[r]
            } else {
                let value = if r == 31 { Some(0) } else { s.regs[r].imm() };
                value.map(|v| {
                    let mut b = [0; 16];
                    b[..8].copy_from_slice(&v.to_le_bytes());
                    b
                })
            };
            s.write(addr, size, bytes.as_ref().map(|b| &b[..size]));
        }
    }
    true
}
