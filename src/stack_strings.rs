//! Extraction of stack-constructed strings (immediate values).
//!
//! Identifies strings built at runtime via:
//! - Immediate loads to registers (`mov reg, imm`).
//! - Immediate stores to memory (`mov [mem], imm`).
//! - Register stores to memory (`mov [mem], reg`).
//!
//! Tracks register state and memory offsets to correctly reconstruct
//! strings that are built out-of-order or with overlaps.

// This codebase targets 64-bit hosts only: usize = u64, so u64-to-usize casts are lossless.
#![allow(clippy::cast_possible_truncation)]

use crate::types::{ExtractedString, StringFragment, StringKind, StringMethod};
use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind, Register};
use std::collections::{HashMap, HashSet};

/// Check if bytes are printable ASCII and meet minimum length.
fn check_printable(bytes: &[u8], min_length: usize) -> Option<String> {
    let mut trimmed = bytes;
    while let Some((last, rest)) = trimmed.split_last() {
        if *last == 0 {
            trimmed = rest;
        } else {
            break;
        }
    }
    if trimmed.len() < min_length {
        return None;
    }
    if trimmed.iter().all(|&b| b.is_ascii_graphic() || b == b' ') {
        return String::from_utf8(trimmed.to_vec()).ok();
    }
    None
}

/// Score a decoded string for likelihood of being valid text.
fn score_decoded_string(s: &str) -> i32 {
    let mut score = 0i32;
    for c in s.chars() {
        if c.is_ascii_alphabetic() {
            score += 3;
        } else if c.is_ascii_digit() {
            score += 1;
        } else if matches!(c, '_' | '-' | '.' | '/' | ':' | ' ') {
            score += 2;
        } else if c.is_ascii_punctuation() {
            // neutral
        } else {
            score -= 1;
        }
    }
    score
}

/// Extract strings constructed on the stack.
pub(crate) fn extract_stack_strings(data: &[u8], min_length: usize) -> Vec<ExtractedString> {
    let extractor = StackStringExtractor::new(data, min_length, None, 0, 0);
    extractor.extract()
}

/// Extract strings with full file context for resolving RIP-relative addresses.
pub(crate) fn extract_stack_strings_with_context(
    section_data: &[u8],
    min_length: usize,
    full_data: &[u8],
    section_vma: u64,
    image_base: u64,
) -> Vec<ExtractedString> {
    let extractor = StackStringExtractor::new(
        section_data,
        min_length,
        Some(full_data),
        section_vma,
        image_base,
    );
    extractor.extract()
}

struct StackStringExtractor<'a> {
    data: &'a [u8],
    min_length: usize,
    full_data: Option<&'a [u8]>,
    section_vma: u64,
    image_base: u64,
    // Register state: (Value, Instruction Offset, Flavor)
    regs: HashMap<Register, (String, u64, String)>,
    // Raw (non-printable) immediate bytes held in registers, kept for XOR pairing.
    raw_regs: HashMap<Register, Vec<u8>>,
    // XMM register state: raw bytes (16 bytes each) for SSE operations.
    xmm_regs: HashMap<Register, [u8; 16]>,
    // Captured stack writes: grouped by Base Register index -> Vec<StackWrite>
    writes: HashMap<Register, Vec<StackWrite>>,
    // Non-printable raw blobs written to the stack, grouped by base register.
    raw_blobs: HashMap<Register, Vec<RawBlob>>,
}

#[derive(Debug, Clone)]
struct StackWrite {
    string: String,
    disp: i64,
    instr_off: u64,
    flavor: String,
}

#[derive(Debug, Clone)]
struct RawBlob {
    bytes: Vec<u8>,
    disp: i64,
    instr_off: u64,
}

impl<'a> StackStringExtractor<'a> {
    fn new(
        data: &'a [u8],
        min_length: usize,
        full_data: Option<&'a [u8]>,
        section_vma: u64,
        image_base: u64,
    ) -> Self {
        Self {
            data,
            min_length,
            full_data,
            section_vma,
            image_base,
            regs: HashMap::with_capacity(16),
            raw_regs: HashMap::with_capacity(16),
            xmm_regs: HashMap::with_capacity(16),
            writes: HashMap::with_capacity(8),
            raw_blobs: HashMap::with_capacity(8),
        }
    }

    fn extract(mut self) -> Vec<ExtractedString> {
        let mut results = Vec::new();

        // First pass: look for loop-based string building patterns
        results.extend(self.extract_loop_built_strings());

        let mut decoder = Decoder::with_ip(64, self.data, self.section_vma, DecoderOptions::NONE);

        while decoder.can_decode() {
            let instr = decoder.decode();
            if instr.is_invalid() {
                break;
            }

            let instr_off = instr.ip() - self.section_vma;

            match instr.mnemonic() {
                // --- 1. MOV ---
                Mnemonic::Mov => {
                    let op0_kind = instr.op0_kind();
                    let op1_kind = instr.op1_kind();

                    match (op0_kind, op1_kind) {
                        // mov reg, imm
                        (OpKind::Register, OpKind::Immediate32)
                        | (OpKind::Register, OpKind::Immediate64)
                        | (OpKind::Register, OpKind::Immediate32to64) => {
                            let reg = instr.op0_register();
                            let imm_len = if op1_kind == OpKind::Immediate64 {
                                8
                            } else {
                                4
                            };
                            // Extract immediate bytes directly from the instruction's data if possible,
                            // or use iced's value. Using raw bytes is safer for printable check.
                            let imm_val = if op1_kind == OpKind::Immediate64 {
                                instr.immediate64().to_le_bytes().to_vec()
                            } else {
                                instr.immediate32().to_le_bytes().to_vec()
                            };

                            if let Some(s) = check_printable(&imm_val, self.min_length) {
                                let flavor = if imm_len == 8 { "movabs" } else { "mov_r32" };
                                self.regs.insert(reg, (s, instr_off, flavor.into()));
                                self.raw_regs.remove(&reg);
                            } else {
                                self.regs.remove(&reg);
                                self.raw_regs.insert(reg, imm_val);
                            }
                        }
                        // mov [mem], imm
                        (OpKind::Memory, OpKind::Immediate32)
                        | (OpKind::Memory, OpKind::Immediate32to64) => {
                            let base = instr.memory_base();
                            let disp = instr.memory_displacement64() as i64;
                            let imm_val = instr.immediate32().to_le_bytes();

                            if let Some(s) = check_printable(&imm_val, 4) {
                                self.add_write(base, disp, s, instr_off, "mov_mem_imm32".into());
                            } else {
                                self.add_raw_blob(base, disp, imm_val.to_vec(), instr_off);
                            }
                        }
                        // mov [mem], imm8
                        (OpKind::Memory, OpKind::Immediate8) => {
                            let base = instr.memory_base();
                            let disp = instr.memory_displacement64() as i64;
                            let b = instr.immediate8();
                            if b.is_ascii_graphic() || b == b' ' {
                                self.add_write(
                                    base,
                                    disp,
                                    (b as char).to_string(),
                                    instr_off,
                                    "stack_array".into(),
                                );
                            }
                        }
                        // mov [mem], reg
                        (OpKind::Memory, OpKind::Register) => {
                            let base = instr.memory_base();
                            let disp = instr.memory_displacement64() as i64;
                            let src_reg = instr.op1_register();

                            if let Some((s, _off, flavor)) = self.regs.get(&src_reg).cloned() {
                                self.add_write(base, disp, s, instr_off, flavor);
                            }
                            if let Some(raw) = self.raw_regs.get(&src_reg).cloned() {
                                self.add_raw_blob(base, disp, raw, instr_off);
                            }
                        }
                        _ => {}
                    }
                }
                // --- 2. SSE MOV (MOVUPS/MOVAPS) ---
                Mnemonic::Movups | Mnemonic::Movaps | Mnemonic::Movdqu | Mnemonic::Movdqa => {
                    let op0_kind = instr.op0_kind();
                    let op1_kind = instr.op1_kind();

                    match (op0_kind, op1_kind) {
                        // Load from memory to XMM (especially RIP-relative)
                        (OpKind::Register, OpKind::Memory) => {
                            let dst_reg = instr.op0_register();
                            if (Register::XMM0..=Register::XMM15).contains(&dst_reg)
                                && let Some(data) = self.read_memory_for_instr(&instr, 1, 16)
                            {
                                let mut arr = [0u8; 16];
                                arr.copy_from_slice(&data);
                                self.xmm_regs.insert(dst_reg, arr);
                            }
                        }
                        // Store from XMM to memory
                        (OpKind::Memory, OpKind::Register) => {
                            let src_reg = instr.op1_register();
                            if (Register::XMM0..=Register::XMM15).contains(&src_reg)
                                && let Some(data) = self.xmm_regs.get(&src_reg).cloned()
                            {
                                let base = instr.memory_base();
                                let disp = instr.memory_displacement64() as i64;
                                self.add_raw_blob(base, disp, data.to_vec(), instr_off);
                            }
                        }
                        _ => {}
                    }
                }
                // --- 3. ALU XOR (vget case) ---
                Mnemonic::Xor => {
                    let op1_kind = instr.op1_kind();
                    let imm_val = match op1_kind {
                        OpKind::Immediate8
                        | OpKind::Immediate8to16
                        | OpKind::Immediate8to32
                        | OpKind::Immediate8to64 => Some(vec![instr.immediate8()]),
                        OpKind::Immediate16 => Some(instr.immediate16().to_le_bytes().to_vec()),
                        OpKind::Immediate32 | OpKind::Immediate32to64 => {
                            Some(instr.immediate32().to_le_bytes().to_vec())
                        }
                        OpKind::Immediate64 => Some(instr.immediate64().to_le_bytes().to_vec()),
                        _ => None,
                    };

                    if let Some(val) = imm_val
                        && let Some(s) = check_printable(&val, self.min_length.min(val.len()))
                    {
                        self.add_write(
                            Register::None,
                            instr_off as i64,
                            s,
                            instr_off,
                            "alu_imm".into(),
                        );
                    }
                }
                // --- 4. Control Flow (Finalize/Clear) ---
                Mnemonic::Ret
                | Mnemonic::Call
                | Mnemonic::Jmp
                | Mnemonic::Jrcxz
                | Mnemonic::Je
                | Mnemonic::Jne
                | Mnemonic::Jl
                | Mnemonic::Jle
                | Mnemonic::Jg
                | Mnemonic::Jge
                | Mnemonic::Jb
                | Mnemonic::Jbe
                | Mnemonic::Ja
                | Mnemonic::Jae
                | Mnemonic::Js
                | Mnemonic::Jns
                | Mnemonic::Jp
                | Mnemonic::Jnp
                | Mnemonic::Jo
                | Mnemonic::Jno => {
                    results.extend(self.finalize_writes());
                    self.regs.clear();
                    self.raw_regs.clear();
                    self.xmm_regs.clear();
                }
                _ => {}
            }
        }

        results.extend(self.finalize_writes());
        results
    }

    fn read_memory_for_instr(
        &self,
        instr: &iced_x86::Instruction,
        op: u32,
        size: usize,
    ) -> Option<Vec<u8>> {
        if instr.op_kind(op) != OpKind::Memory {
            return None;
        }

        let base = instr.memory_base();
        if base == Register::RIP {
            // Calculate target RIP-relative address
            let next_rip = instr.next_ip();
            let disp = instr.memory_displacement64();
            let target_vma = next_rip.wrapping_add(disp);
            let target_file_offset = target_vma.saturating_sub(self.image_base) as usize;

            let read_from = self.full_data.unwrap_or(self.data);
            if let Some(end) = target_file_offset.checked_add(size)
                && end <= read_from.len()
            {
                return Some(read_from[target_file_offset..end].to_vec());
            }
        }
        None
    }

    fn add_write(&mut self, base: Register, disp: i64, s: String, instr_off: u64, flavor: String) {
        self.writes.entry(base).or_default().push(StackWrite {
            string: s,
            disp,
            instr_off,
            flavor,
        });
    }

    fn add_raw_blob(&mut self, base: Register, disp: i64, bytes: Vec<u8>, instr_off: u64) {
        self.raw_blobs.entry(base).or_default().push(RawBlob {
            bytes,
            disp,
            instr_off,
        });
    }

    fn finalize_writes(&mut self) -> Vec<ExtractedString> {
        let mut results = Vec::new();
        let writes_map = std::mem::take(&mut self.writes);

        for (base, mut writes) in writes_map {
            if writes.is_empty() {
                continue;
            }

            writes.sort_by_key(|write| write.disp);

            let mut iter = writes.into_iter();
            let Some(first) = iter.next() else { continue };

            let mut current = ExtractedString {
                value: first.string,
                data_offset: first.instr_off,
                method: StringMethod::StackString,
                kind: Some(StringKind::StackString),
                fragments: Some(vec![StringFragment {
                    offset: first.instr_off,
                    length: 0, // updated below
                    flavor: Some(first.flavor),
                }]),
                ..Default::default()
            };
            // Set first fragment length correctly
            if let Some(frags) = &mut current.fragments {
                frags[0].length = current.value.len();
            }

            let mut current_end_disp = first.disp + current.value.len() as i64;

            for w in iter {
                let gap = w.disp - current_end_disp;
                let allowed_gap = if base == Register::None { 16 } else { 4 };

                if gap <= allowed_gap {
                    if gap >= 0 {
                        current.value.push_str(&w.string);
                        if let Some(frags) = &mut current.fragments {
                            frags.push(StringFragment {
                                offset: w.instr_off,
                                length: w.string.len(),
                                flavor: Some(w.flavor),
                            });
                        }
                        current_end_disp = w.disp + w.string.len() as i64;
                    } else {
                        // Overlap
                        let overlap = current_end_disp - w.disp;
                        if overlap >= 0 && overlap < w.string.len() as i64 {
                            let new_part = &w.string[usize::try_from(overlap).unwrap_or(0)..];
                            current.value.push_str(new_part);
                            if let Some(frags) = &mut current.fragments {
                                frags.push(StringFragment {
                                    offset: w.instr_off,
                                    length: w.string.len(),
                                    flavor: Some(w.flavor),
                                });
                            }
                            current_end_disp = w.disp + w.string.len() as i64;
                        }
                    }
                } else {
                    results.push(current);
                    let string_len = w.string.len();
                    current = ExtractedString {
                        value: w.string,
                        data_offset: w.instr_off,
                        method: StringMethod::StackString,
                        kind: Some(StringKind::StackString),
                        fragments: Some(vec![StringFragment {
                            offset: w.instr_off,
                            length: string_len,
                            flavor: Some(w.flavor),
                        }]),
                        ..Default::default()
                    };
                    current_end_disp = w.disp + string_len as i64;
                }
            }
            results.push(current);
        }

        results = self.merge_adjacent_fragments(results);
        results.extend(self.finalize_garble_pairs());
        results.retain(|s| s.value.len() >= self.min_length);
        results
    }

    fn merge_adjacent_fragments(&self, mut strings: Vec<ExtractedString>) -> Vec<ExtractedString> {
        if strings.is_empty() {
            return strings;
        }

        let mut merged = Vec::new();
        let mut current_group = vec![strings.remove(0)];

        for next_str in strings {
            if let Some(last) = current_group.last() {
                let last_end = last.data_offset + last.value.len() as u64;
                let gap = next_str.data_offset as i64 - last_end as i64;

                if (-4..8).contains(&gap) && (last.value.len() < 4 || next_str.value.len() < 4) {
                    current_group.push(next_str);
                } else {
                    if current_group.len() > 1 {
                        merged.push(self.merge_group(&current_group));
                    } else {
                        merged.extend(current_group);
                    }
                    current_group = vec![next_str];
                }
            }
        }

        if !current_group.is_empty() {
            if current_group.len() > 1 {
                merged.push(self.merge_group(&current_group));
            } else {
                merged.extend(current_group);
            }
        }
        merged
    }

    fn merge_group(&self, group: &[ExtractedString]) -> ExtractedString {
        if group.is_empty() {
            return Default::default();
        }
        if group.len() == 1 {
            return group[0].clone();
        }

        let mut merged_value = String::new();
        let first_offset = group[0].data_offset;
        let mut merged_fragments = Vec::new();

        for s in group {
            merged_value.push_str(&s.value);
            if let Some(frags) = &s.fragments {
                merged_fragments.extend(frags.iter().cloned());
            }
        }

        ExtractedString {
            value: merged_value,
            data_offset: first_offset,
            method: StringMethod::StackString,
            kind: Some(StringKind::StackString),
            fragments: if merged_fragments.is_empty() {
                None
            } else {
                Some(merged_fragments)
            },
            ..Default::default()
        }
    }

    fn finalize_garble_pairs(&mut self) -> Vec<ExtractedString> {
        let raw_blobs = std::mem::take(&mut self.raw_blobs);
        let mut results = Vec::new();

        for (_base, blobs) in raw_blobs {
            if blobs.len() < 2 {
                continue;
            }

            let mut by_len: HashMap<usize, Vec<usize>> = HashMap::new();
            for (idx, blob) in blobs.iter().enumerate() {
                by_len.entry(blob.bytes.len()).or_default().push(idx);
            }

            for (chunk_size, mut indices) in by_len {
                if indices.len() < 2 {
                    continue;
                }
                // Cap pairing to avoid O(n^2) blowup on crafted binaries
                indices.truncate(500);

                struct Pair {
                    decoded: String,
                    disp_lo: i64,
                    disp_hi: i64,
                    instr_off: u64,
                }
                let mut pair_seen: HashSet<(i64, i64)> = HashSet::new();
                let mut pairs: Vec<Pair> = Vec::new();

                for (i, &idx_i) in indices.iter().enumerate() {
                    let a = &blobs[idx_i];
                    for &idx_j in &indices[i + 1..] {
                        let b = &blobs[idx_j];
                        let disp_lo = a.disp.min(b.disp);
                        let disp_hi = a.disp.max(b.disp);

                        let mut best: Option<(String, i32)> = None;
                        for op in [
                            (|x: u8, y: u8| x ^ y) as fn(u8, u8) -> u8,
                            |x, y| x.wrapping_sub(y),
                            |x, y| x.wrapping_add(y),
                        ] {
                            let decoded_bytes: Vec<u8> = a
                                .bytes
                                .iter()
                                .zip(b.bytes.iter())
                                .map(|(&x, &y)| op(x, y))
                                .collect();

                            if let Some(decoded) = check_printable(&decoded_bytes, 1) {
                                let score = score_decoded_string(&decoded);
                                if best.as_ref().is_none_or(|b| score > b.1) {
                                    best = Some((decoded, score));
                                }
                            }
                        }

                        if let Some((decoded, _)) = best
                            && pair_seen.insert((disp_lo, disp_hi))
                        {
                            pairs.push(Pair {
                                decoded,
                                disp_lo,
                                disp_hi,
                                instr_off: a.instr_off.min(b.instr_off),
                            });
                        }
                    }
                }

                if pairs.is_empty() {
                    continue;
                }

                let chunk_stride = chunk_size as i64;
                pairs.sort_unstable_by(|a, b| {
                    let ka = a.disp_hi - a.disp_lo;
                    let kb = b.disp_hi - b.disp_lo;
                    ka.cmp(&kb).then(a.disp_lo.cmp(&b.disp_lo))
                });

                let mut seen: HashSet<String> = HashSet::new();
                let mut i = 0;
                while i < pairs.len() {
                    let key_offset = pairs[i].disp_hi - pairs[i].disp_lo;
                    let mut value = pairs[i].decoded.clone();
                    let mut min_off = pairs[i].instr_off;
                    let mut j = i + 1;
                    while j < pairs.len() {
                        let p = &pairs[j];
                        if p.disp_hi - p.disp_lo != key_offset {
                            break;
                        }
                        if p.disp_lo != pairs[j - 1].disp_lo + chunk_stride {
                            break;
                        }
                        value.push_str(&p.decoded);
                        min_off = min_off.min(p.instr_off);
                        j += 1;
                    }

                    let trimmed = value.trim_end_matches('\0');
                    if trimmed.len() >= self.min_length && seen.insert(trimmed.to_string()) {
                        results.push(ExtractedString {
                            value: trimmed.to_string(),
                            data_offset: min_off,
                            method: StringMethod::XorStackPair,
                            kind: Some(StringKind::StackString),
                            ..Default::default()
                        });
                    }
                    i = j;
                }
            }
        }
        results
    }

    fn extract_loop_built_strings(&self) -> Vec<ExtractedString> {
        let mut results = Vec::new();
        let mut i = 0;
        while i + 4 < self.data.len() {
            if self.data[i] == 0x66 && self.data[i + 1] == 0xC7 && self.data[i + 2] == 0x00 {
                let b1 = self.data[i + 3];
                let b2 = self.data[i + 4];
                if (b1.is_ascii_graphic() || b1 == b' ')
                    && (b2.is_ascii_graphic() || b2 == b' ' || b2 == 0)
                {
                    let start_pos = i;
                    let mut chunk = String::new();
                    chunk.push(b1 as char);
                    if b2 != 0 {
                        chunk.push(b2 as char);
                    }

                    let mut k = i + 5;
                    while k + 4 < self.data.len() {
                        if self.data[k] == 0x66
                            && self.data[k + 1] == 0xC7
                            && self.data[k + 2] == 0x00
                        {
                            let b3 = self.data[k + 3];
                            let b4 = self.data[k + 4];
                            chunk.push(b3 as char);
                            if b4 != 0 {
                                chunk.push(b4 as char);
                            } else {
                                k += 5;
                                break;
                            }
                            k += 5;
                        } else {
                            break;
                        }
                    }

                    if chunk.len() >= self.min_length && self.looks_like_real_string(&chunk) {
                        results.push(ExtractedString {
                            value: chunk,
                            data_offset: start_pos as u64,
                            method: StringMethod::StackString,
                            kind: Some(StringKind::StackString),
                            ..Default::default()
                        });
                    }
                    i = k;
                    continue;
                }
            }
            i += 1;
        }
        results
    }

    fn looks_like_real_string(&self, s: &str) -> bool {
        if s.len() < 4 {
            return false;
        }
        let special_count = s.chars().filter(|c| !c.is_alphanumeric()).count();
        if special_count > s.len() / 2 {
            return false;
        }
        let mut alphanumeric_runs = 0;
        let mut in_run = false;
        for c in s.chars() {
            if c.is_alphanumeric() {
                if !in_run {
                    alphanumeric_runs += 1;
                    in_run = true;
                }
            } else {
                in_run = false;
            }
        }
        alphanumeric_runs >= 2
    }
}
