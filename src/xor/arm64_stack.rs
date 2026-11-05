//! Narrow ARM64 stack-XOR extraction for Mach-O malware.
//!
//! This intentionally handles a small compiler-shaped subset:
//! MOVZ/MOVK immediate construction, ADD-immediate stack pointers, unsigned
//! LDR/STR stack accesses (general and q registers), LDP/STP of q registers,
//! vector EOR, and BL sink detection. Any other instruction forgets the
//! registers it writes. That covers binaries that build ciphertext and XOR
//! pads as stack immediates, XOR them in vector registers, and reuse the same
//! pad for command strings and filesystem/browser-wallet target strings.

use crate::classifier::classify_string;
use crate::types::{ExtractedString, StringKind, StringMethod};
use aho_corasick::AhoCorasick;
use goblin::mach::MachO;
use goblin::mach::constants::S_ATTR_SOME_INSTRUCTIONS;
use goblin::mach::constants::cputype::CPU_TYPE_ARM64;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

// The known stack-XOR family is compact. Above this size, only pay for the
// specialized disassembly when the ordinary extraction pass says the image is
// opaque.
const SMALL_INPUT: usize = 1024 * 1024;
const FEW_STRINGS: usize = 64;

/// Stack slots the decoders may visit per file, summed over calls. Each call
/// scans every slot recorded so far, so a section of stores and calls costs
/// quadratic time. The largest real sample seen uses ~2^24.
const MAX_DECODE_WORK: usize = 1 << 28;
/// Distinct stack slots tracked per section. Past this the map starts over.
const MAX_SLOTS: usize = 1 << 16;
/// Distinct XOR pads kept per section. Every later store is tried against
/// each pad, so the count multiplies per-store work; real samples recover
/// a handful (4 in the largest fixture).
const MAX_PADS: usize = 64;
/// Blob starts tried per store: every slot up to 128 bytes below it, and the
/// store itself.
const MAX_STARTS: usize = 129;

#[derive(Debug, Clone, Copy)]
pub(crate) struct AdmissionProfile {
    /// Bytes the extractor would disassemble (one architecture for fat files).
    pub(crate) input_size: usize,
    /// Bytes represented by `string_count`/`string_bytes` (the whole image).
    pub(crate) content_size: usize,
    pub(crate) string_count: usize,
    pub(crate) string_bytes: usize,
}

#[derive(Debug, Clone)]
enum RegValue {
    Imm(u64),
    Ptr(i64),
    Bytes(Vec<u8>),
}

/// A known vector register: its bytes, and where they came from.
#[derive(Debug, Clone)]
struct Vector {
    bytes: Vec<u8>,
    /// The stack offset it was loaded from.
    loaded_from: Option<i64>,
    /// For an EOR result, where each operand was loaded from.
    xor_of: Option<[Option<i64>; 2]>,
}

/// Extract printable strings produced by XORing stack-resident ARM64 immediates.
pub(crate) fn extract_arm64_stack_xor_strings(
    macho: &MachO<'_>,
    imports_system: impl FnOnce() -> bool,
    arch_data: &[u8],
    arch_base_offset: u64,
    profile: AdmissionProfile,
    min_length: usize,
) -> Vec<ExtractedString> {
    if macho.header.cputype != CPU_TYPE_ARM64 || !should_extract(profile) {
        return Vec::new();
    }
    if !imports_system() {
        return Vec::new();
    }

    let mut results = Vec::new();
    let mut budget = Budget(MAX_DECODE_WORK);

    for (section, _) in crate::binary::macho_sections(macho) {
        if (section.flags & S_ATTR_SOME_INSTRUCTIONS) == 0 || section.size < 4 {
            continue;
        }

        let start = section.offset as usize;
        let Ok(size) = usize::try_from(section.size) else {
            continue;
        };
        let Some(end) = start.checked_add(size) else {
            continue;
        };
        let Some(code) = arch_data.get(start..end) else {
            continue;
        };

        results.extend(extract_section(
            code,
            arch_base_offset + u64::from(section.offset),
            min_length,
            &mut budget,
        ));
    }

    results.sort_by_key(|r| (r.data_offset, r.value.len()));
    crate::types::dedup_by_value(&mut results);
    results
}

/// Whether the binary `layout` describes imports `system(3)`, which the
/// stack-XOR families this pass targets run their decoded commands through.
pub(crate) fn imports_system(layout: Option<&binform::Binary<'_>>) -> bool {
    layout.is_some_and(|layout| {
        layout
            .imports()
            .iter()
            .any(|import| is_system_import(&import.name))
    })
}

fn is_system_import(name: &str) -> bool {
    matches!(name, "system" | "_system")
}

fn should_extract(profile: AdmissionProfile) -> bool {
    if profile.input_size <= SMALL_INPUT {
        return true;
    }

    // An opaque image: either very few printable runs, or printable content
    // covering less than roughly 0.1% of it. A large, transparent app
    // with thousands of ordinary strings has little to gain from this narrow
    // malware-family extractor.
    profile.string_count < FEW_STRINGS
        || profile.string_bytes.saturating_mul(1024) < profile.content_size
}

/// Stack slots the decoders may still visit in this file.
struct Budget(usize);

impl Budget {
    /// Charge a decoder call for the slots it will scan; false once spent.
    fn spend(&mut self, slots: usize) -> bool {
        if let Some(left) = self.0.checked_sub(slots) {
            self.0 = left;
            return true;
        }
        if self.0 > 0 {
            tracing::debug!(MAX_DECODE_WORK, "arm64 stack XOR: decode budget exhausted");
            self.0 = 0;
        }
        false
    }
}

/// Bytes stored at a stack offset, and the file offset of the store.
struct Slot {
    bytes: Vec<u8>,
    at: u64,
}

/// The emulated stack, by offset from the entry stack pointer.
type Stack = HashMap<i64, Slot>;

fn extract_section(
    code: &[u8],
    section_file_offset: u64,
    min_length: usize,
    budget: &mut Budget,
) -> Vec<ExtractedString> {
    let mut regs: HashMap<u8, RegValue> = HashMap::with_capacity(32);
    let mut memory = Stack::new();
    let mut sink_results = Vec::new();
    let mut decoded_arg_starts = HashSet::new();
    let mut decoded_blob_state: HashMap<i64, (usize, usize, u64)> = HashMap::new();
    let mut recovered_pads: Vec<Vec<u8>> = Vec::new();
    let mut seen_pads: HashSet<Vec<u8>> = HashSet::new();
    let mut seen_values = HashSet::new();
    let mut vectors: HashMap<u8, Vector> = HashMap::new();
    // Stack offsets a vector EOR overwrote with `ciphertext ^ pad`, where the
    // ciphertext was, and the offset of the pad.
    let mut decrypted: HashMap<i64, i64> = HashMap::new();
    let mut building = Building::default();
    for (idx, chunk) in code.as_chunks::<4>().0.iter().enumerate() {
        let word = u32::from_le_bytes(*chunk);
        let instr_off = (idx * 4) as u64;
        let at = section_file_offset + instr_off;

        if let Some((rd, value)) = decode_mov_wide(word, &regs) {
            regs.insert(rd, RegValue::Imm(value));
            continue;
        }

        if let Some((rd, rn, imm)) = decode_add_imm(word) {
            if let Some(base) = ptr_offset(&regs, rn) {
                regs.insert(rd, RegValue::Ptr(base + imm));
            } else {
                regs.remove(&rd);
            }
            continue;
        }

        // BL: a call, whose x0 may point at a decoded string.
        let is_bl = word & 0xfc00_0000 == 0x9400_0000;
        if is_bl
            && let Some(&RegValue::Ptr(arg0)) = regs.get(&0)
            && decrypted.contains_key(&arg0)
            && decoded_arg_starts.insert(arg0)
        {
            let decoded = decrypted_arg(&memory, &decrypted, arg0, at, min_length);
            for pad in decoded.pads {
                if recovered_pads.len() < MAX_PADS && seen_pads.insert(pad.clone()) {
                    recovered_pads.push(pad);
                }
            }
            append_unique_results(&mut sink_results, decoded.results, &mut seen_values);
        }
        if is_bl {
            if let Some(RegValue::Ptr(arg0)) = regs.get(&0)
                && decoded_arg_starts.insert(*arg0)
                && budget.spend(memory.len())
            {
                let decoded = decode_stack_arg_with_candidate_pads(
                    &memory,
                    *arg0,
                    section_file_offset + instr_off,
                    min_length,
                );
                for pad in decoded.pads {
                    if recovered_pads.len() >= MAX_PADS {
                        tracing::debug!(MAX_PADS, "arm64 stack XOR: pad list full");
                        break;
                    }
                    if seen_pads.insert(pad.clone()) {
                        recovered_pads.push(pad);
                    }
                }
                append_unique_results(&mut sink_results, decoded.results, &mut seen_values);
            }
            // The call may change every caller-saved register.
            regs.retain(|&r, _| (19..=29).contains(&r));
            vectors.clear();
            continue;
        }

        if let Some((vd, vn, vm, len)) = decode_vector_eor(word) {
            let result = match (vectors.get(&vn), vectors.get(&vm)) {
                (Some(a), Some(b)) if a.bytes.len() >= len && b.bytes.len() >= len => {
                    Some(Vector {
                        bytes: a
                            .bytes
                            .iter()
                            .zip(&b.bytes)
                            .take(len)
                            .map(|(x, y)| x ^ y)
                            .collect(),
                        loaded_from: None,
                        xor_of: Some([a.loaded_from, b.loaded_from]),
                    })
                }
                _ => None,
            };
            match result {
                Some(result) => vectors.insert(vd, result),
                None => vectors.remove(&vd),
            };
            continue;
        }

        let accesses = decode_unsigned_mem(word)
            .map(|mem| vec![mem])
            .or_else(|| decode_vector_pair(word));
        if let Some(accesses) = accesses {
            for mem in accesses {
                let Some(base) = ptr_offset(&regs, mem.rn) else {
                    // An address off the modelled stack: a load's register
                    // becomes unknown, and a store is not tracked.
                    if mem.load {
                        forget(&mut regs, &mut vectors, &mem);
                    }
                    continue;
                };
                let disp = base + mem.disp;
                if mem.load {
                    load(&memory, &mut regs, &mut vectors, &mem, disp);
                    continue;
                }
                decrypted.remove(&disp);
                let Some(bytes) = stored_bytes(&regs, &vectors, &mem) else {
                    // An unknown value overwrites what the slots held.
                    clobber(&mut memory, disp, mem.size);
                    continue;
                };
                if let Some(pad) = vectors
                    .get(&mem.rt)
                    .filter(|_| mem.vector)
                    .and_then(|v| v.xor_of)
                    .and_then(|[a, b]| match (a, b) {
                        (Some(a), Some(pad)) | (Some(pad), Some(a)) if a == disp => Some(pad),
                        _ => None,
                    })
                {
                    decrypted.insert(disp, pad);
                }
                if memory.len() >= MAX_SLOTS && !memory.contains_key(&disp) {
                    tracing::debug!(MAX_SLOTS, "arm64 stack XOR: slot map full, starting over");
                    memory.clear();
                    decoded_blob_state.clear();
                    decrypted.clear();
                    append_unique_results(&mut sink_results, building.finish(), &mut seen_values);
                }
                clobber(&mut memory, disp, bytes.len());
                memory.insert(disp, Slot { bytes, at });
                // The decoder walks every slot, then tries each pad on up to
                // `MAX_STARTS` blobs.
                if !recovered_pads.is_empty()
                    && budget.spend(memory.len() + MAX_STARTS * recovered_pads.len())
                {
                    let decoded = decode_recent_stack_blobs_with_pads(
                        &memory,
                        disp,
                        &recovered_pads,
                        &mut decoded_blob_state,
                        section_file_offset + instr_off,
                        min_length,
                    );
                    for (start, found) in decoded {
                        building.add(start, found);
                    }
                }
            }
            continue;
        }

        // Anything else forgets the registers it may write; an instruction
        // whose writes are not known forgets every register.
        match crate::arm64::effects::writes(word) {
            Some(mask) => regs.retain(|&r, _| mask & (1 << r) == 0),
            None => regs.clear(),
        }
        if writes_vectors(word) {
            vectors.clear();
        }
    }

    append_unique_results(&mut sink_results, building.finish(), &mut seen_values);
    sink_results
}

/// Strings decoded from stack blobs as the code builds them, by the stack
/// offset each starts at. A blob is decoded after every store into it, so
/// each stage of a string being built decodes too; only the most complete
/// is kept.
#[derive(Default)]
struct Building(HashMap<i64, Vec<ExtractedString>>);

impl Building {
    /// Record `found`, decoded from the blob at `start`. A decode extending
    /// one already held replaces it; one an earlier decode covers is dropped.
    fn add(&mut self, start: i64, found: ExtractedString) {
        let held = self.0.entry(start).or_default();
        if held.iter().any(|s| s.value.starts_with(&found.value)) {
            return;
        }
        match held.iter().position(|s| found.value.starts_with(&s.value)) {
            Some(i) => held[i] = found,
            None => held.push(found),
        }
    }

    /// Every string kept, in stack order, without those that are a piece of
    /// a string decoded from an earlier start: the same bytes read from
    /// partway in.
    fn finish(&mut self) -> Vec<ExtractedString> {
        let mut strings: Vec<(i64, ExtractedString)> = self
            .0
            .drain()
            .flat_map(|(start, held)| held.into_iter().map(move |s| (start, s)))
            .collect();
        strings.sort_by_key(|(start, s)| (*start, s.data_offset));
        let inside = |start: i64, value: &str| {
            strings.iter().any(|(earlier, s)| {
                usize::try_from(start - earlier).is_ok_and(|skip| {
                    skip > 0
                        && s.value
                            .get(skip..)
                            .is_some_and(|rest| rest.starts_with(value))
                })
            })
        };
        let keep: Vec<bool> = strings
            .iter()
            .map(|(start, s)| !inside(*start, &s.value))
            .collect();
        strings
            .into_iter()
            .zip(keep)
            .filter_map(|((_, s), keep)| keep.then_some(s))
            .collect()
    }
}

/// Whether `word` is in an encoding class that can write a vector register:
/// SIMD&FP data processing, or a SIMD&FP load.
fn writes_vectors(word: u32) -> bool {
    let op0 = (word >> 25) & 0xf;
    op0 & 0x7 == 0x7 || (op0 & 0x5 == 0x4 && (word >> 26) & 1 == 1 && (word >> 22) & 1 == 1)
}

/// `EOR Vd.<8B|16B>, Vn, Vm`: the registers, and the bytes it writes.
fn decode_vector_eor(word: u32) -> Option<(u8, u8, u8, usize)> {
    if word & 0xbfe0_fc00 != 0x2e20_1c00 {
        return None;
    }
    let len = if (word >> 30) & 1 == 1 { 16 } else { 8 };
    Some((
        (word & 0x1f) as u8,
        ((word >> 5) & 0x1f) as u8,
        ((word >> 16) & 0x1f) as u8,
        len,
    ))
}

/// `LDP`/`STP` of two vector registers, signed offset: one access each.
fn decode_vector_pair(word: u32) -> Option<Vec<MemInsn>> {
    if word & 0x3f80_0000 != 0x2d00_0000 {
        return None;
    }
    let size = match word >> 30 {
        0 => 4,
        1 => 8,
        2 => 16,
        _ => return None,
    };
    let load = (word >> 22) & 1 == 1;
    // imm7 is signed, in units of the register size.
    let imm7 = i64::from((word >> 15) & 0x7f);
    let imm7 = if imm7 & 0x40 != 0 { imm7 - 0x80 } else { imm7 };
    let rn = ((word >> 5) & 0x1f) as u8;
    let disp = imm7 * size as i64;
    let access = |rt: u32, disp: i64| MemInsn {
        rt: (rt & 0x1f) as u8,
        rn,
        disp,
        size,
        load,
        vector: true,
        sign_extend_to: None,
    };
    Some(vec![
        access(word, disp),
        access(word >> 10, disp + size as i64),
    ])
}

/// Forget the register a load from an untracked address writes.
fn forget(regs: &mut HashMap<u8, RegValue>, vectors: &mut HashMap<u8, Vector>, mem: &MemInsn) {
    if mem.vector {
        vectors.remove(&mem.rt);
    } else {
        regs.remove(&mem.rt);
    }
}

/// Load `mem.size` bytes at stack offset `disp` into the register.
fn load(
    memory: &Stack,
    regs: &mut HashMap<u8, RegValue>,
    vectors: &mut HashMap<u8, Vector>,
    mem: &MemInsn,
    disp: i64,
) {
    let bytes = collect_contiguous(memory, disp, mem.size)
        .filter(|bytes| bytes.len() >= mem.size)
        .map(|mut bytes| {
            bytes.truncate(mem.size);
            bytes
        });
    match (bytes, mem.vector) {
        (Some(bytes), true) => {
            vectors.insert(
                mem.rt,
                Vector {
                    bytes,
                    loaded_from: Some(disp),
                    xor_of: None,
                },
            );
        }
        (Some(mut bytes), false) if mem.rt != 31 => {
            if let Some(width) = mem.sign_extend_to {
                let fill = if bytes.last().is_some_and(|&b| b & 0x80 != 0) {
                    0xff
                } else {
                    0
                };
                bytes.resize(width, fill);
            }
            regs.insert(mem.rt, RegValue::Bytes(bytes));
        }
        _ => forget(regs, vectors, mem),
    }
}

/// The bytes a store writes, when its register's value is known. The zero
/// register stores zeros.
fn stored_bytes(
    regs: &HashMap<u8, RegValue>,
    vectors: &HashMap<u8, Vector>,
    mem: &MemInsn,
) -> Option<Vec<u8>> {
    if mem.vector {
        let bytes = &vectors.get(&mem.rt)?.bytes;
        return bytes.get(..mem.size).map(<[u8]>::to_vec);
    }
    if mem.rt == 31 {
        return Some(vec![0; mem.size]);
    }
    match regs.get(&mem.rt)? {
        RegValue::Imm(value) => Some(value.to_le_bytes()[..mem.size].to_vec()),
        RegValue::Bytes(bytes) => bytes.get(..mem.size).map(<[u8]>::to_vec),
        RegValue::Ptr(_) => None,
    }
}

/// Drop every slot a store of `len` bytes at `disp` overwrites. A slot holds
/// at most 16 bytes, so only those starting up to 15 bytes before can reach it.
fn clobber(memory: &mut Stack, disp: i64, len: usize) {
    for start in disp - 15..disp + len as i64 {
        if memory
            .get(&start)
            .is_some_and(|slot| start + slot.bytes.len() as i64 > disp)
        {
            memory.remove(&start);
        }
    }
}

/// The string a call's first argument points at, which vector EORs wrote
/// over its ciphertext, and the pad they used.
fn decrypted_arg(
    memory: &Stack,
    decrypted: &HashMap<i64, i64>,
    arg0: i64,
    at: u64,
    min_length: usize,
) -> StackDecodeResults {
    let mut results = Vec::new();
    let mut pads = Vec::new();
    // The decrypted run from `arg0` whose pad is one run too.
    let pad_start = decrypted[&arg0];
    let mut len = 0;
    while let Some(Slot { bytes, .. }) = memory.get(&(arg0 + len))
        && decrypted.get(&(arg0 + len)) == Some(&(pad_start + len))
    {
        len += bytes.len() as i64;
    }
    let len = usize::try_from(len).unwrap_or(0);
    if let (Some(plain), Some(pad)) = (
        collect_contiguous(memory, arg0, len),
        collect_contiguous(memory, pad_start, len),
    ) && plain.len() >= len
        && pad.len() >= len
        && looks_printable(&plain[..len])
    {
        let value = String::from_utf8_lossy(&plain[..len])
            .split('\0')
            .next()
            .unwrap_or("")
            .trim_end()
            .to_string();
        if value.len() >= min_length && looks_like_useful_decoded_string(&value) {
            let key = pad[..len].to_vec();
            results.push(ExtractedString {
                value: format!("0x{}", crate::bytes::to_hex(&key)),
                // The key is located at the store that wrote its first bytes.
                data_offset: memory.get(&pad_start).map_or(at, |slot| slot.at),
                method: StringMethod::XorStackPair,
                kind: Some(StringKind::XorKey),
                ..Default::default()
            });
            pads.push(key);
            results.push(ExtractedString {
                kind: classify_string(&value).or(Some(StringKind::StackString)),
                value,
                data_offset: at,
                method: StringMethod::XorStackPair,
                ..Default::default()
            });
        }
    }
    StackDecodeResults { results, pads }
}

fn ptr_offset(regs: &HashMap<u8, RegValue>, rn: u8) -> Option<i64> {
    if rn == 31 {
        return Some(0);
    }
    match regs.get(&rn) {
        Some(RegValue::Ptr(offset)) => Some(*offset),
        _ => None,
    }
}

fn decode_mov_wide(word: u32, regs: &HashMap<u8, RegValue>) -> Option<(u8, u64)> {
    let mov = crate::arm64::move_wide(word).filter(|mov| mov.rd != 31)?;
    let rd = u8::try_from(mov.rd).ok()?;
    if !mov.keep {
        return Some((rd, mov.imm));
    }
    // MOVK keeps the other bits, so an unknown register stays unknown.
    let Some(RegValue::Imm(before)) = regs.get(&rd) else {
        return None;
    };
    Some((rd, before & !(0xffff << mov.shift) | mov.imm))
}

fn decode_add_imm(word: u32) -> Option<(u8, u8, i64)> {
    if (word & 0x1f00_0000) != 0x1100_0000 || ((word >> 30) & 1) != 0 {
        return None;
    }
    let rd = (word & 0x1f) as u8;
    let rn = ((word >> 5) & 0x1f) as u8;
    let mut imm = i64::from((word >> 10) & 0xfff);
    if ((word >> 22) & 1) != 0 {
        imm <<= 12;
    }
    Some((rd, rn, imm))
}

struct MemInsn {
    rt: u8,
    rn: u8,
    disp: i64,
    size: usize,
    load: bool,
    /// A vector (SIMD&FP) register rather than a general one.
    vector: bool,
    /// For `LDRS*`, the register width the value is sign-extended to.
    sign_extend_to: Option<usize>,
}

struct StackDecodeResults {
    results: Vec<ExtractedString>,
    pads: Vec<Vec<u8>>,
}

/// `LDR`/`STR`/`LDRS*` with an unsigned immediate offset, of a general or
/// vector register. `PRFM` and unallocated encodings are `None`.
fn decode_unsigned_mem(word: u32) -> Option<MemInsn> {
    if (word & 0x3b00_0000) != 0x3900_0000 {
        return None;
    }
    let size_code = (word >> 30) & 0x3;
    let opc = (word >> 22) & 0x3;
    let vector = (word >> 26) & 1 == 1;
    let (size, load, sign_extend_to) = match (vector, size_code, opc) {
        (true, 0, 2 | 3) => (16, opc == 3, None),
        (_, _, 0 | 1) => (1 << size_code, opc == 1, None),
        (false, 0..=2, 2) => (1 << size_code, true, Some(8)),
        (false, 0 | 1, 3) => (1 << size_code, true, Some(4)),
        _ => return None,
    };
    let imm12 = i64::from((word >> 10) & 0xfff);
    Some(MemInsn {
        rt: (word & 0x1f) as u8,
        rn: ((word >> 5) & 0x1f) as u8,
        disp: imm12 * size as i64,
        size,
        load,
        vector,
        sign_extend_to,
    })
}

fn decode_stack_arg_with_candidate_pads(
    memory: &Stack,
    cipher_start: i64,
    instr_off: u64,
    min_length: usize,
) -> StackDecodeResults {
    let Some(cipher) = collect_contiguous(memory, cipher_start, 128) else {
        return StackDecodeResults {
            results: Vec::new(),
            pads: Vec::new(),
        };
    };
    if cipher.len() < min_length {
        return StackDecodeResults {
            results: Vec::new(),
            pads: Vec::new(),
        };
    }
    if cipher.get(..4).is_none_or(looks_printable) {
        return StackDecodeResults {
            results: Vec::new(),
            pads: Vec::new(),
        };
    }

    let mut results = Vec::new();
    let mut pads = Vec::new();
    let mut seen = HashSet::new();
    let mut starts: Vec<i64> = memory.keys().copied().collect();
    starts.sort_unstable();

    for pad_start in starts {
        if pad_start == cipher_start {
            continue;
        }
        let Some(pad) = collect_contiguous(memory, pad_start, cipher.len().max(32)) else {
            continue;
        };
        let max_len = cipher.len().min(pad.len()).min(64);
        for len in [16usize, 32, 48, 64] {
            if len < min_length || len > max_len {
                continue;
            }
            let decoded: Vec<u8> = cipher[..len]
                .iter()
                .zip(&pad[..len])
                .map(|(&x, &y)| x ^ y)
                .collect();
            if !looks_printable(&decoded) {
                continue;
            }
            let decoded_text = String::from_utf8_lossy(&decoded);
            let value = decoded_text
                .split('\0')
                .next()
                .unwrap_or("")
                .trim_end()
                .to_string();
            if value.len() < min_length
                || !looks_like_useful_decoded_string(&value)
                || !seen.insert(value.clone())
            {
                continue;
            }

            let kind = classify_string(&value).or(Some(StringKind::StackString));
            let key_len = pad.len().min(32).max(len);
            let key = pad[..key_len].to_vec();
            let key_value = format!("0x{}", crate::bytes::to_hex(&key));
            if !pads.contains(&key) {
                pads.push(key);
            }
            if seen.insert(key_value.clone()) {
                // The key is located at the store that wrote its first bytes.
                results.push(ExtractedString {
                    value: key_value,
                    data_offset: memory.get(&pad_start).map_or(instr_off, |slot| slot.at),
                    method: StringMethod::XorStackPair,
                    kind: Some(StringKind::XorKey),
                    ..Default::default()
                });
            }
            results.push(ExtractedString {
                value,
                data_offset: instr_off,
                method: StringMethod::XorStackPair,
                kind,
                ..Default::default()
            });
        }
    }

    StackDecodeResults { results, pads }
}

fn decode_recent_stack_blobs_with_pads(
    memory: &Stack,
    write_start: i64,
    pads: &[Vec<u8>],
    decoded_blob_state: &mut HashMap<i64, (usize, usize, u64)>,
    instr_off: u64,
    min_length: usize,
) -> Vec<(i64, ExtractedString)> {
    let mut results = Vec::new();
    let mut seen = HashSet::new();
    let mut starts: Vec<i64> = memory
        .keys()
        .copied()
        .filter(|&start| start <= write_start && write_start - start <= 128)
        .collect();
    starts.push(write_start);
    starts.sort_unstable();
    starts.dedup();

    for start in starts {
        let Some(cipher) = collect_contiguous(memory, start, 192) else {
            continue;
        };
        if cipher.len() < min_length {
            continue;
        }
        // FNV-1a
        let cipher_hash = cipher
            .iter()
            .fold(0xcbf2_9ce4_8422_2325_u64, |hash, &byte| {
                (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
            });
        let (prev_len, prev_pad_count, prev_hash) =
            decoded_blob_state.get(&start).copied().unwrap_or((0, 0, 0));
        if prev_len >= cipher.len() && prev_pad_count >= pads.len() && prev_hash == cipher_hash {
            continue;
        }
        let pad_start = if prev_len >= cipher.len() && prev_hash == cipher_hash {
            prev_pad_count
        } else {
            0
        };
        decoded_blob_state.insert(start, (cipher.len(), pads.len(), cipher_hash));

        for pad in &pads[pad_start..] {
            if pad.is_empty() {
                continue;
            }
            // A pad covers the string it was built for; bytes past it are
            // another string's, and a wrapped pad only garbles them.
            let decoded: Vec<u8> = cipher
                .iter()
                .zip(pad)
                .map(|(&byte, &key)| byte ^ key)
                .collect();

            for raw_value in printable_runs(&decoded, min_length) {
                if !MARKERS.is_match(&raw_value) {
                    continue;
                }
                let Some(value) = normalize_decoded_value(&raw_value, min_length) else {
                    continue;
                };
                if !looks_like_useful_decoded_string(&value) || !seen.insert(value.clone()) {
                    continue;
                }
                results.push((
                    start,
                    ExtractedString {
                        kind: classify_string(&value).or(Some(StringKind::StackString)),
                        value,
                        data_offset: instr_off,
                        method: StringMethod::XorStackPair,
                        ..Default::default()
                    },
                ));
            }
        }
    }

    results
}

fn printable_runs(decoded: &[u8], min_length: usize) -> Vec<String> {
    let mut runs = Vec::new();
    let mut start = None;

    for (idx, byte) in decoded
        .iter()
        .copied()
        .chain(std::iter::once(0))
        .enumerate()
    {
        let is_printable = byte.is_ascii_graphic() || byte == b' ' || byte == b'\t';
        match (start, is_printable) {
            (None, true) => start = Some(idx),
            (Some(run_start), false) => {
                if idx - run_start >= min_length {
                    let text = String::from_utf8_lossy(&decoded[run_start..idx])
                        .trim()
                        .to_string();
                    if text.len() >= min_length {
                        runs.push(text);
                    }
                }
                start = None;
            }
            _ => {}
        }
    }

    runs
}

/// Where a stealer target begins in a decoded run: anything before one of
/// these, if it is at most 24 bytes in, is stack noise.
const ANCHORS: &[&str] = &[
    "osascript",
    "dscl",
    "/Users/",
    "/Library/",
    "Library/",
    "Application Support",
    "BraveSoftware/",
    "Google/",
    "Chrome",
    "Chromium",
    "Cookies",
    "Login Data",
    "accounts-metadata/",
    ".electrum",
    ".walletwasabi",
    "Monero/",
    "Bitcoin",
    "wallet.dat",
    "Ledger",
    "ledger-wallet",
    "Exodus",
    "Atomic",
];

/// A decoded run is worth normalizing only if it names a stealer target or
/// the commands around one.
static MARKERS: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(
            ANCHORS
                .iter()
                .chain(&["killall", "terminal", "keychain", "wallet"]),
        )
        .unwrap_or_else(crate::invalid_pattern)
});

fn normalize_decoded_value(value: &str, min_length: usize) -> Option<String> {
    let mut value = value.trim().to_string();
    if value.len() < min_length {
        return None;
    }

    for anchor in ANCHORS {
        if let Some(idx) = value.find(anchor)
            && idx > 0
            && idx <= 24
        {
            value = value[idx..].to_string();
            break;
        }
    }

    value = value
        .trim_start_matches(|c: char| {
            c.is_ascii_punctuation() && c != '/' && c != '.' && c != '~' && c != '$'
        })
        .to_string();

    // A decoded value runs on into whatever followed it on the stack. These
    // targets end where their last path component does; the first found,
    // in this order, cuts the value there. (`killall Terminal` only as a
    // prefix: the word appears inside longer commands.)
    const ENDS: &[&str] = &[
        "login.keychain-db",
        "login.keychain",
        ".electrum-ltc/wallets",
        ".electrum/wallets",
        ".walletwasabi/client/Wallets",
        "Monero/wallets",
        "wallet.dat",
        "BraveSoftware/Brave-Browser",
        "Google/Chrome for Testing",
        "Google/Chrome Canary",
        "Google/Chrome Beta",
        "Google/Chrome Dev",
    ];
    if value.starts_with("killall Terminal") {
        value.truncate("killall Terminal".len());
    } else if let Some(end) = ENDS
        .iter()
        .find_map(|end| value.find(end).map(|at| at + end.len()))
    {
        value.truncate(end);
    }

    if value.starts_with("osascript")
        && !(value.contains("osascript -e '") || value.contains("osascript -e \""))
    {
        return None;
    }

    if value.len() >= min_length {
        Some(value)
    } else {
        None
    }
}

fn collect_contiguous(memory: &Stack, start: i64, max_len: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut pos = start;
    while out.len() < max_len {
        let Some(Slot { bytes: chunk, .. }) = memory.get(&pos) else {
            break;
        };
        if chunk.is_empty() {
            break;
        }
        out.extend_from_slice(chunk);
        pos += chunk.len() as i64;
    }
    if out.is_empty() { None } else { Some(out) }
}

fn looks_printable(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes
            .iter()
            .all(|&b| b.is_ascii_graphic() || b == b' ' || b == b'\t' || b == 0)
}

fn looks_like_useful_decoded_string(s: &str) -> bool {
    if matches!(
        classify_string(s),
        Some(
            StringKind::ShellCmd
                | StringKind::AppleScript
                | StringKind::SuspiciousPath
                | StringKind::Path
                | StringKind::Url
        )
    ) {
        return true;
    }
    // What macOS stealers decode: tools they run, and the browser, keychain
    // and wallet stores they read. A listed word covers its extensions
    // (`wallet` covers `wallet.dat`).
    const MARKERS: &[&str] = &[
        "killall",
        "terminal",
        "dscl",
        "/users/",
        "library/",
        "application support",
        "keychain",
        "cookies",
        "login data",
        "wallet",
        "electrum",
        "exodus",
        "atomic",
        "ledger",
        "monero",
        "bitcoin",
        "wasabi",
        "chrome",
        "chromium",
        "brave",
        "safari",
        "sqlite",
        "osascript",
        "chmod",
        "curl",
    ];
    let lower = s.to_ascii_lowercase();
    MARKERS.iter().any(|marker| lower.contains(marker))
}

fn append_unique_results(
    out: &mut Vec<ExtractedString>,
    results: Vec<ExtractedString>,
    seen: &mut HashSet<String>,
) {
    for result in results {
        if seen.insert(result.value.clone()) {
            out.push(result);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_movz_movk_wide_immediate() {
        let mut regs = HashMap::new();
        let (rd, value) = decode_mov_wide(0x528e_1288, &regs).expect("movz");
        assert_eq!(rd, 8);
        assert_eq!(value, 0x7094);
        regs.insert(rd, RegValue::Imm(value));
        let (_, value) = decode_mov_wide(0x72a6_2348, &regs).expect("movk");
        assert_eq!(value, 0x311a_7094);
    }

    #[test]
    fn decodes_add_sp_lsl12() {
        let (rd, rn, imm) = decode_add_imm(0x9140_13e9).expect("add");
        assert_eq!((rd, rn, imm), (9, 31, 0x4000));
    }

    #[test]
    fn decodes_str_w_unsigned_offset() {
        let mem = decode_unsigned_mem(0xb904_8128).expect("str");
        assert_eq!(mem.rt, 8);
        assert_eq!(mem.rn, 9);
        assert_eq!(mem.disp, 0x480);
        assert_eq!(mem.size, 4);
        assert!(!mem.load);
    }

    #[test]
    fn decodes_q_register_loads_stores_and_pairs() {
        // DynamicHub: ldr q1, [sp, #0x4730]; str q0, [sp, #0x4720].
        let ldr = decode_unsigned_mem(0x3dd1_cfe1).expect("ldr q");
        assert_eq!((ldr.rt, ldr.rn, ldr.disp, ldr.size), (1, 31, 0x4730, 16));
        assert!(ldr.load && ldr.vector);
        let str = decode_unsigned_mem(0x3d91_cbe0).expect("str q");
        assert_eq!((str.rt, str.disp, str.size), (0, 0x4720, 16));
        assert!(!str.load && str.vector);
        // ldp q2, q3, [x8]
        let pair = decode_vector_pair(0xad40_0d02).expect("ldp q");
        assert_eq!(
            pair.iter()
                .map(|m| (m.rt, m.rn, m.disp))
                .collect::<Vec<_>>(),
            [(2, 8, 0), (3, 8, 16)]
        );
        // eor.16b v0, v2, v0
        assert_eq!(decode_vector_eor(0x6e20_1c40), Some((0, 2, 0, 16)));
        // prfm pldl1keep, [x0] is not a store.
        assert!(decode_unsigned_mem(0xf980_0000).is_none());
    }

    /// The shape DynamicHub compiles to: ciphertext and pad built on the
    /// stack with word stores, XORed in q registers, the plaintext stored
    /// back over the ciphertext, and its address passed to a call.
    #[test]
    fn decodes_vector_xor_written_back_over_its_ciphertext() {
        let plain: Vec<u8> = b"killall Terminal".iter().copied().chain([0; 16]).collect();
        let pad: Vec<u8> = (0..32u8).map(|i| 0x80 | i.wrapping_mul(7)).collect();
        let cipher: Vec<u8> = plain.iter().zip(&pad).map(|(p, k)| p ^ k).collect();
        let mut words = Vec::new();
        // Each 32-bit word: movz w8, #lo; movk w8, #hi, lsl 16; str w8, [sp, #at].
        let mut store_words = |bytes: &[u8], base: u32| {
            for (i, w) in bytes.chunks(4).enumerate() {
                let value = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
                let at = base + 4 * i as u32;
                words.push(0x5280_0000 | (value & 0xffff) << 5 | 8);
                words.push(0x72a0_0000 | (value >> 16) << 5 | 8);
                words.push(0xb900_0000 | (at / 4) << 10 | 31 << 5 | 8);
            }
        };
        store_words(&pad, 0x100);
        store_words(&cipher, 0x200);
        words.extend([
            0x9100_0000 | 0x100 << 10 | 31 << 5 | 8, // add x8, sp, #0x100
            0x3dc0_0000 | 0x20 << 10 | 31 << 5,      // ldr q0, [sp, #0x200]
            0x3dc0_0000 | 0x21 << 10 | 31 << 5 | 1,  // ldr q1, [sp, #0x210]
            0xad40_0d02,                             // ldp q2, q3, [x8]
            0x6e20_1c40,                             // eor.16b v0, v2, v0
            0x6e21_1c61,                             // eor.16b v1, v3, v1
            0x3d80_0000 | 0x20 << 10 | 31 << 5,      // str q0, [sp, #0x200]
            0x3d80_0000 | 0x21 << 10 | 31 << 5 | 1,  // str q1, [sp, #0x210]
            0x9100_0000 | 0x200 << 10 | 31 << 5,     // add x0, sp, #0x200
            0x9400_0000,                             // bl
        ]);
        let code: Vec<u8> = words.iter().flat_map(|w: &u32| w.to_le_bytes()).collect();
        let call = (code.len() - 4) as u64;

        let found = extract_section(&code, 0, 4, &mut Budget(MAX_DECODE_WORK));
        let decoded = found
            .iter()
            .find(|s| s.value == "killall Terminal")
            .expect("plaintext recovered");
        assert_eq!(
            (decoded.method, decoded.data_offset),
            (StringMethod::XorStackPair, call)
        );
        let key = found
            .iter()
            .find(|s| s.kind == Some(StringKind::XorKey))
            .expect("pad reported");
        assert_eq!(key.value, format!("0x{}", crate::bytes::to_hex(&pad)));
        // At the first store of the pad: the third word of the program.
        assert_eq!(key.data_offset, 8);
    }

    #[test]
    fn system_import_match_is_exact() {
        assert!(is_system_import("_system"));
        assert!(is_system_import("system"));
        assert!(!is_system_import("__ZNSt3__112system_errorC1Ev"));
        assert!(!is_system_import("__ZNSt3__14__fs10filesystem8__statusEv"));
        assert!(!is_system_import("_systemstats_init"));
    }

    #[test]
    fn compact_inputs_are_admitted_even_when_string_rich() {
        assert!(should_extract(AdmissionProfile {
            input_size: SMALL_INPUT,
            content_size: SMALL_INPUT,
            string_count: 10_000,
            string_bytes: SMALL_INPUT / 2,
        }));
    }

    #[test]
    fn large_opaque_inputs_are_admitted() {
        assert!(should_extract(AdmissionProfile {
            input_size: 16 * SMALL_INPUT,
            content_size: 16 * SMALL_INPUT,
            string_count: FEW_STRINGS - 1,
            string_bytes: SMALL_INPUT,
        }));
        assert!(should_extract(AdmissionProfile {
            input_size: 16 * SMALL_INPUT,
            content_size: 16 * SMALL_INPUT,
            string_count: 1_000,
            string_bytes: 8 * 1024,
        }));
    }

    #[test]
    fn large_string_rich_inputs_are_rejected() {
        assert!(!should_extract(AdmissionProfile {
            input_size: 16 * SMALL_INPUT,
            content_size: 16 * SMALL_INPUT,
            string_count: 1_000,
            string_bytes: 256 * 1024,
        }));
    }
}
