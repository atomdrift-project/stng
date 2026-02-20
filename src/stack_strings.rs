//! Extraction of stack-constructed strings (immediate values).
//!
//! Identifies strings built at runtime via:
//! - Immediate loads to registers (`mov reg, imm`).
//! - Immediate stores to memory (`mov [mem], imm`).
//! - Register stores to memory (`mov [mem], reg`).
//!
//! Tracks register state and memory offsets to correctly reconstruct
//! strings that are built out-of-order or with overlaps.

use crate::types::{ExtractedString, StringFragment, StringKind, StringMethod};
use std::collections::{HashMap, HashSet};

/// Extract strings constructed on the stack.
pub fn extract_stack_strings(data: &[u8], min_length: usize) -> Vec<ExtractedString> {
    let extractor = StackStringExtractor::new(data, min_length);
    extractor.extract()
}

struct StackStringExtractor<'a> {
    data: &'a [u8],
    min_length: usize,
    // Register state: (Value, Instruction Offset, Flavor)
    regs: [Option<(String, u64, String)>; 16],
    // Raw (non-printable) immediate bytes held in registers, kept for XOR pairing.
    raw_regs: [Option<Vec<u8>>; 16],
    // Captured stack writes: grouped by (Base Reg, Index Reg, Scale) -> Vec<StackWrite>
    // We simplify: group by "Base Register" and assume standard stack frames.
    // If base is RIP (0x05 in ModRM), we track it separately?
    // For now, simple Base Reg grouping.
    writes: HashMap<u8, Vec<StackWrite>>,
    // Non-printable raw blobs written to the stack, grouped by base register.
    // Pairs of same-length blobs are XOR'd at finalization to recover obfuscated strings.
    raw_blobs: HashMap<u8, Vec<RawBlob>>,
}

#[derive(Debug, Clone)]
struct StackWrite {
    string: String,
    disp: i64,      // Displacement from base register
    instr_off: u64, // Offset of the instruction that wrote this
    flavor: String, // "movabs", "mov_byte", etc.
}

/// A raw (non-printable) immediate blob written to the stack, kept as XOR candidate.
#[derive(Debug, Clone)]
struct RawBlob {
    bytes: Vec<u8>,
    disp: i64, // Displacement from base register (stack slot position)
    instr_off: u64,
}

impl<'a> StackStringExtractor<'a> {
    fn new(data: &'a [u8], min_length: usize) -> Self {
        Self {
            data,
            min_length,
            regs: Default::default(),
            raw_regs: Default::default(),
            writes: HashMap::new(),
            raw_blobs: HashMap::new(),
        }
    }

    fn extract(mut self) -> Vec<ExtractedString> {
        let mut results = Vec::new();

        // First pass: look for loop-based string building patterns
        // Used by kworker_pretenders and similar malware
        // Pattern: repeated "mov word [mem], imm" with ASCII-decodable immediates
        results.extend(self.extract_loop_built_strings());

        let mut i = 0;
        while i < self.data.len() {
            // Decode instruction at i
            // We only care about:
            // 1. mov reg, imm (B8..BF, C7)
            // 2. mov [mem], imm (C6, C7)
            // 3. mov [mem], reg (88, 89)
            // 4. Control flow (reset state)

            // Skip prefixes
            let mut p = i;
            let mut rex = 0u8;
            let mut _segment = 0u8;

            loop {
                if p >= self.data.len() {
                    break;
                }
                let b = self.data[p];
                match b {
                    0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 => _segment = b,
                    0x66 | 0x67 | 0xF0 | 0xF2 | 0xF3 => {} // Ignore other prefixes
                    0x40..=0x4F => rex = b,
                    _ => break,
                }
                p += 1;
            }
            let opcode_start = p;
            if opcode_start >= self.data.len() {
                break;
            }
            let opcode = self.data[opcode_start];

            let mut handled = false;
            let mut len = 0;

            // --- 1. mov reg, imm ---
            // B8+rd: mov r32/r64, imm
            if (0xB8..=0xBF).contains(&opcode) {
                let reg = (opcode & 0x07) + if (rex & 1) != 0 { 8 } else { 0 };
                let is_64 = (rex & 8) != 0;
                let imm_len = if is_64 { 8 } else { 4 };

                if opcode_start + 1 + imm_len <= self.data.len() {
                    let imm_data = &self.data[opcode_start + 1..opcode_start + 1 + imm_len];
                    if let Some(s) = check_printable(imm_data, self.min_length) {
                        self.regs[reg as usize] = Some((
                            s,
                            i as u64,
                            if is_64 {
                                "movabs".into()
                            } else {
                                "mov_r32".into()
                            },
                        ));
                        self.raw_regs[reg as usize] = None;
                    } else {
                        self.regs[reg as usize] = None;
                        // Keep the raw bytes for XOR-pair detection at finalization.
                        self.raw_regs[reg as usize] = Some(imm_data.to_vec());
                    }
                    len = (opcode_start - i) + 1 + imm_len;
                    handled = true;
                }
            }
            // C7 /0: mov r/m, imm32
            else if opcode == 0xC7 {
                // Need ModRM
                if opcode_start + 2 <= self.data.len() {
                    let modrm = self.data[opcode_start + 1];
                    let reg_op = (modrm >> 3) & 7;
                    if reg_op == 0 {
                        // /0
                        let (op_len, base, disp) = self.decode_modrm(opcode_start + 1, rex);
                        if op_len > 0 && opcode_start + 1 + op_len + 4 <= self.data.len() {
                            let imm_offset = opcode_start + 1 + op_len;
                            let imm_data = &self.data[imm_offset..imm_offset + 4];

                            // Check if destination is register or memory
                            let mod_bits = modrm >> 6;
                            if mod_bits == 3 {
                                // mov reg, imm32
                                let dst_reg = (modrm & 7) + if (rex & 1) != 0 { 8 } else { 0 };
                                if let Some(s) = check_printable(imm_data, self.min_length) {
                                    self.regs[dst_reg as usize] =
                                        Some((s, i as u64, "mov_r32".into()));
                                } else {
                                    self.regs[dst_reg as usize] = None;
                                }
                            } else if let Some(base_reg) = base {
                                // mov [mem], imm32
                                if let Some(s) = check_printable(imm_data, 4) {
                                    // Always 4 bytes for C7
                                    self.add_write(
                                        base_reg,
                                        disp,
                                        s,
                                        i as u64,
                                        "mov_mem_imm32".into(),
                                    );
                                } else {
                                    // Non-printable: keep as XOR-pair candidate.
                                    self.add_raw_blob(base_reg, disp, imm_data.to_vec(), i as u64);
                                }
                            }
                            len = (opcode_start - i) + 1 + op_len + 4;
                            handled = true;
                        }
                    }
                }
            }
            // --- 2. mov [mem], imm8 ---
            // C6 /0: mov r/m8, imm8
            else if opcode == 0xC6 {
                if opcode_start + 2 <= self.data.len() {
                    let modrm = self.data[opcode_start + 1];
                    let reg_op = (modrm >> 3) & 7;
                    if reg_op == 0 {
                        let (op_len, base, disp) = self.decode_modrm(opcode_start + 1, rex);
                        if op_len > 0 && opcode_start + 1 + op_len < self.data.len() {
                            let imm_offset = opcode_start + 1 + op_len;
                            let b = self.data[imm_offset];

                            // Only memory stores
                            let mod_bits = modrm >> 6;
                            if mod_bits != 3 {
                                if let Some(base_reg) = base {
                                    if b.is_ascii_graphic() || b == b' ' {
                                        let s = (b as char).to_string();
                                        self.add_write(
                                            base_reg,
                                            disp,
                                            s,
                                            i as u64,
                                            "stack_array".into(),
                                        );
                                    }
                                }
                            }
                            len = (opcode_start - i) + 1 + op_len + 1;
                            handled = true;
                        }
                    }
                }
            }
            // --- 3. mov [mem], reg ---
            // 88 /r: mov r/m8, r8
            // 89 /r: mov r/m, r
            else if opcode == 0x88 || opcode == 0x89 {
                if opcode_start + 2 <= self.data.len() {
                    let modrm = self.data[opcode_start + 1];
                    let src_reg = ((modrm >> 3) & 7) + if (rex & 4) != 0 { 8 } else { 0 };

                    let (op_len, base, disp) = self.decode_modrm(opcode_start + 1, rex);
                    if op_len > 0 {
                        let mod_bits = modrm >> 6;
                        if mod_bits != 3 {
                            // Store to memory
                            if let Some(base_reg) = base {
                                // Check if we have a printable string in src_reg.
                                if let Some((s, _orig_off, flavor)) = &self.regs[src_reg as usize] {
                                    self.add_write(
                                        base_reg,
                                        disp,
                                        s.clone(),
                                        i as u64,
                                        flavor.clone(),
                                    );
                                }
                                // Also propagate non-printable raw bytes for XOR-pair detection.
                                if let Some(raw) = self.raw_regs[src_reg as usize].clone() {
                                    self.add_raw_blob(base_reg, disp, raw, i as u64);
                                }
                            }
                        }
                        len = (opcode_start - i) + 1 + op_len;
                        handled = true;
                    }
                }
            }
            // --- 4. Control Flow / Clear ---
            // C3 (ret), E8 (call), E9 (jmp), EB (jmp short), FF (call/jmp indirect)
            // 7x (jcc), 0F 8x (jcc long)
            else if opcode == 0xC3
                || opcode == 0xCB
                || opcode == 0xE8
                || opcode == 0xE9
                || opcode == 0xEB
            {
                results.extend(self.finalize_writes());
                self.clear_regs();
                len = 1;
                if opcode == 0xE8 || opcode == 0xE9 {
                    len = 5;
                }
                // approx
                else if opcode == 0xEB {
                    len = 2;
                }
                handled = true;
            }
            // ALU reg, imm32 (81 /r id) - To support "xor reg, imm" string loading
            else if opcode == 0x81 {
                // Check if it's an ALU op.
                // We don't track ALU results in registers (too complex), but we can extract the immediate
                // if it looks like a string, assuming it might be part of an obfuscated load.
                // This handles the `vget` case where `xor rdx, "cAMD"` contained the string.
                if opcode_start + 6 <= self.data.len() {
                    let imm_data = &self.data[opcode_start + 2..opcode_start + 6];
                    if let Some(s) = check_printable(imm_data, self.min_length) {
                        // We found a string in an ALU instruction.
                        // We can't map it to a memory write easily, so we treat it as a standalone stack string.
                        // We store it as a "write" to a dummy register (e.g. 0xFF) or just emit it directly?
                        // We can't emit directly because we return at the end.
                        // Let's add it to a special "Global" list or just generic base 0xFF?
                        // Better: Treat as a write to "Global" (base 255) with linear displacement (file offset).
                        self.add_write(255, i as i64, s, i as u64, "alu_imm32".into());
                    }
                    len = 6;
                    handled = true;
                }
            }

            if !handled {
                i += 1;
            } else {
                i += len;
            }
        }

        results.extend(self.finalize_writes());
        results
    }

    // Returns (length of ModRM+SIB+Disp, BaseReg, Displacement)
    fn decode_modrm(&self, offset: usize, rex: u8) -> (usize, Option<u8>, i64) {
        if offset >= self.data.len() {
            return (0, None, 0);
        }
        let modrm = self.data[offset];
        let mod_bits = modrm >> 6;
        let rm = modrm & 7;
        let base_reg_idx = rm + if (rex & 1) != 0 { 8 } else { 0 };

        let mut len = 1;
        let mut base = Some(base_reg_idx);
        let mut disp: i64 = 0;

        if mod_bits == 3 {
            // Register mode
            return (1, None, 0);
        }

        let has_sib = rm == 4;
        if has_sib {
            if offset + 1 >= self.data.len() {
                return (0, None, 0);
            }
            let sib = self.data[offset + 1];
            len += 1;
            let base_in_sib = sib & 7;
            // SIB base with REX.B
            let real_base = base_in_sib + if (rex & 1) != 0 { 8 } else { 0 };

            if mod_bits == 0 && base_in_sib == 5 {
                base = None; // disp32 only
            } else {
                base = Some(real_base);
            }
        } else if mod_bits == 0 && rm == 5 {
            // RIP relative (32-bit disp)
            base = None; // We don't resolve RIP, treat as independent
        }

        if mod_bits == 1 {
            if offset + len + 1 > self.data.len() {
                return (0, None, 0);
            }
            disp = self.data[offset + len] as i8 as i64;
            len += 1;
        } else if mod_bits == 2
            || (mod_bits == 0 && rm == 5)
            || (has_sib && mod_bits == 0 && (self.data[offset + 1] & 7) == 5)
        {
            if offset + len + 4 > self.data.len() {
                return (0, None, 0);
            }
            let disp32 = u32::from_le_bytes(
                self.data[offset + len..offset + len + 4]
                    .try_into()
                    .expect("bounds checked above"),
            );
            disp = disp32 as i32 as i64;
            len += 4;
        }

        (len, base, disp)
    }

    fn add_write(&mut self, base: u8, disp: i64, s: String, instr_off: u64, flavor: String) {
        self.writes.entry(base).or_default().push(StackWrite {
            string: s,
            disp,
            instr_off,
            flavor,
        });
    }

    fn add_raw_blob(&mut self, base: u8, disp: i64, bytes: Vec<u8>, instr_off: u64) {
        self.raw_blobs.entry(base).or_default().push(RawBlob {
            bytes,
            disp,
            instr_off,
        });
    }

    fn clear_regs(&mut self) {
        for r in self.regs.iter_mut() {
            *r = None;
        }
        for r in self.raw_regs.iter_mut() {
            *r = None;
        }
    }

    fn finalize_writes(&mut self) -> Vec<ExtractedString> {
        let mut results = Vec::new();
        let writes = std::mem::take(&mut self.writes);

        // Process each base register group
        for (base, mut writes) in writes {
            if writes.is_empty() {
                continue;
            }

            // Sort by displacement to find memory order
            writes.sort_by(|a, b| a.disp.cmp(&b.disp));

            // Merge logic
            let mut current = ExtractedString {
                value: String::new(),
                data_offset: 0,
                section: None,
                method: StringMethod::StackString,
                kind: StringKind::StackString,
                library: None,
                fragments: Some(Vec::new()),
                ..Default::default()
            };

            // We need to initialize 'current' with the first write
            let mut first = true;
            let mut current_end_disp = 0;

            for w in writes {
                if first {
                    current.value = w.string.clone();
                    current.data_offset = w.instr_off;
                    if let Some(frags) = &mut current.fragments {
                        frags.push(StringFragment {
                            offset: w.instr_off,
                            length: w.string.len(),
                            flavor: Some(w.flavor),
                        });
                    }
                    current_end_disp = w.disp + w.string.len() as i64;
                    first = false;
                    continue;
                }

                let gap = w.disp - current_end_disp;

                // For memory writes (base < 255), allow a small gap to account for
                // character-by-character assembly where each instruction writes to successive bytes.
                // Some instructions may have implicit padding or alignment that creates small gaps.
                // For instruction-embedded strings (base == 255), we allow a small gap (e.g. 16 bytes)
                // to merge strings from sequential instructions.
                // Threshold: 4 bytes covers most cases (mov dword writes with 1-byte gaps between them)
                let allowed_gap = if base == 255 { 16 } else { 4 };

                if gap <= allowed_gap {
                    if gap >= 0 {
                        // Strict adjacency or small gap
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
                        // Overlap (gap < 0)
                        // w.disp starts BEFORE current ends.
                        // This is the overwrite case (React2Shell).
                        // We need to merge them intelligently.
                        let overlap = current_end_disp - w.disp;
                        if overlap < w.string.len() as i64 {
                            let new_part_start = overlap as usize;
                            if new_part_start < w.string.len() {
                                let new_part = &w.string[new_part_start..];
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
                    }
                } else {
                    // Gap > 0: split into distinct strings
                    results.push(current);
                    current = ExtractedString {
                        value: w.string.clone(),
                        data_offset: w.instr_off,
                        section: None,
                        method: StringMethod::StackString,
                        kind: StringKind::StackString,
                        library: None,
                        fragments: Some(vec![StringFragment {
                            offset: w.instr_off,
                            length: w.string.len(),
                            flavor: Some(w.flavor),
                        }]),
                        ..Default::default()
                    };
                    current_end_disp = w.disp + w.string.len() as i64;
                }
            }
            results.push(current);
        }

        // Second pass: merge adjacent short fragments that were split due to small gaps.
        // This handles character-by-character assembly like "[k" "w" "o" "r" "k" "e" "r" "]"
        // where fragments end up in the results list but should be combined.
        results = self.merge_adjacent_fragments(results);

        // Append any strings recovered by XOR-pairing of non-printable stack blobs.
        results.extend(self.finalize_xor_pairs());

        // Final sanity check: filter out very short merged strings
        results.retain(|s| s.value.len() >= self.min_length);
        results
    }

    /// Merge adjacent short fragments that likely belong together.
    /// This catches cases where character-by-character assembly creates many 1-2 byte fragments.
    fn merge_adjacent_fragments(&self, mut strings: Vec<ExtractedString>) -> Vec<ExtractedString> {
        if strings.is_empty() {
            return strings;
        }

        let mut merged = Vec::new();
        let mut current_group = vec![strings.remove(0)];

        for next_str in strings {
            let last = current_group.last().expect("current_group is never empty");

            // Check if this string is adjacent to the last one (within a small gap)
            // and both are short (suggesting character-by-character assembly)
            let last_end = last.data_offset + last.value.len() as u64;
            let gap = next_str.data_offset as i64 - last_end as i64;

            // Merge if:
            // 1. Strings are adjacent or very close (gap < 8 bytes, accounting for instruction padding)
            // 2. At least one of them is short (< 4 bytes, suggesting fragments)
            // 3. Neither is suspiciously garbage-like
            if (-4..8).contains(&gap) && (last.value.len() < 4 || next_str.value.len() < 4) {
                // They likely belong together
                current_group.push(next_str);
            } else {
                // End the current group and merge it
                if current_group.len() > 1 {
                    merged.push(self.merge_group(&current_group));
                } else {
                    merged.extend(current_group);
                }
                current_group = vec![next_str];
            }
        }

        // Handle the last group
        if !current_group.is_empty() {
            if current_group.len() > 1 {
                merged.push(self.merge_group(&current_group));
            } else {
                merged.extend(current_group);
            }
        }

        merged
    }

    /// Merge a group of adjacent fragments into a single string.
    fn merge_group(&self, group: &[ExtractedString]) -> ExtractedString {
        if group.is_empty() {
            return ExtractedString {
                value: String::new(),
                data_offset: 0,
                section: None,
                method: StringMethod::StackString,
                kind: StringKind::StackString,
                ..Default::default()
            };
        }

        if group.len() == 1 {
            return group[0].clone();
        }

        let mut merged_value = String::new();
        let first_offset = group[0].data_offset;
        let mut merged_fragments = Vec::new();

        for s in group.iter() {
            merged_value.push_str(&s.value);
            if let Some(frags) = &s.fragments {
                merged_fragments.extend(frags.clone());
            }
            // If there's a gap to the next string, we might want to note it
            // but for now we just concatenate
        }

        ExtractedString {
            value: merged_value,
            data_offset: first_offset,
            section: group[0].section.clone(),
            method: StringMethod::StackString,
            kind: StringKind::StackString,
            library: None,
            fragments: if merged_fragments.is_empty() {
                None
            } else {
                Some(merged_fragments)
            },
            ..Default::default()
        }
    }

    /// XOR all pairs of same-length non-printable blobs within each base-register group.
    ///
    /// This recovers strings obfuscated with the BrickStorm / garble pattern:
    /// two raw immediate constants are placed on the stack and XOR'd byte-by-byte
    /// in a counted loop before being passed to `runtime.slicebytetostring`.
    /// Neither half is printable on its own; XOR of the pair yields the plaintext.
    /// Detect XOR-encoded strings from pairs of non-printable stack blobs.
    ///
    /// BrickStorm and garble-obfuscated binaries encode strings as two parallel
    /// sequences of immediates ("ciphertext" and "key") written to different areas
    /// of the same stack frame.  Each ciphertext[i] XOR key[i] yields one chunk
    /// of the plaintext; consecutive chunks reconstruct the full string.
    ///
    /// Algorithm:
    /// 1. Try every unique pair of same-size blobs; record any that XOR to printable
    ///    bytes, along with each blob's stack displacement.
    /// 2. Group pairs by `key_offset = |disp_a − disp_b|`.  Within a group, pairs
    ///    whose lower displacement advances by exactly `chunk_size` per step form a
    ///    consecutive sequence that decodes one multi-chunk string.
    /// 3. Merge each sequence and emit the concatenated result.
    fn finalize_xor_pairs(&mut self) -> Vec<ExtractedString> {
        let raw_blobs = std::mem::take(&mut self.raw_blobs);
        let mut results = Vec::new();

        for (_base, blobs) in raw_blobs {
            if blobs.len() < 2 {
                continue;
            }

            // Group blob indices by their byte length so we only pair same-size blobs.
            let mut by_len: HashMap<usize, Vec<usize>> = HashMap::new();
            for (idx, blob) in blobs.iter().enumerate() {
                by_len.entry(blob.bytes.len()).or_default().push(idx);
            }

            for (chunk_size, indices) in by_len {
                if indices.len() < 2 {
                    continue;
                }

                // Phase 1 – enumerate all valid XOR pairs, keyed by canonical
                // (disp_lo, disp_hi) so we don't add the same pair twice.
                struct Pair {
                    decoded: String,
                    disp_lo: i64,
                    disp_hi: i64,
                    instr_off: u64,
                }
                let mut pair_seen: HashSet<(i64, i64)> = HashSet::new();
                let mut pairs: Vec<Pair> = Vec::new();

                for i in 0..indices.len() {
                    for j in (i + 1)..indices.len() {
                        let a = &blobs[indices[i]];
                        let b = &blobs[indices[j]];
                        let xored: Vec<u8> = a
                            .bytes
                            .iter()
                            .zip(b.bytes.iter())
                            .map(|(x, y)| x ^ y)
                            .collect();
                        // Accept any pair that XOR-decodes to at least one printable byte;
                        // the full-sequence length gate comes in phase 2.
                        if let Some(decoded) = check_printable(&xored, 1) {
                            let disp_lo = a.disp.min(b.disp);
                            let disp_hi = a.disp.max(b.disp);
                            if pair_seen.insert((disp_lo, disp_hi)) {
                                pairs.push(Pair {
                                    decoded,
                                    disp_lo,
                                    disp_hi,
                                    instr_off: a.instr_off.min(b.instr_off),
                                });
                            }
                        }
                    }
                }

                if pairs.is_empty() {
                    continue;
                }

                // Phase 2 – sort by (key_offset, disp_lo) then greedily merge
                // consecutive pairs that share the same key_offset and whose
                // lower displacement advances by exactly chunk_size per step.
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

                    // Trim any null padding from the last chunk then apply min_length.
                    let trimmed = value.trim_end_matches('\0');
                    if trimmed.len() >= self.min_length && seen.insert(trimmed.to_string()) {
                        results.push(ExtractedString {
                            value: trimmed.to_string(),
                            data_offset: min_off,
                            section: None,
                            method: StringMethod::XorStackPair,
                            kind: StringKind::StackString,
                            ..Default::default()
                        });
                    }
                    i = j;
                }
            }
        }

        results
    }

    /// Extract strings built using loop-based patterns.
    /// Detects patterns like: mov word [rax], imm; ... strlen; ... mov word [rax], imm
    /// Used by malware like kworker_pretenders that builds strings iteratively.
    fn extract_loop_built_strings(&self) -> Vec<ExtractedString> {
        let mut results = Vec::new();

        // Collect all "mov word [mem], imm16" instructions with ASCII immediates
        let mut mov_word_instrs = Vec::new();
        let mut i = 0;
        while i + 4 < self.data.len() {
            if self.data[i] == 0x66 && self.data[i + 1] == 0xC7 && self.data[i + 2] == 0x00 {
                let b1 = self.data[i + 3];
                let b2 = self.data[i + 4];

                // Accept patterns where:
                // - b1 is printable ASCII (first byte of the 2-byte immediate)
                // - b2 is either printable ASCII or null (second byte - null acts as string terminator)
                let is_valid = (b1.is_ascii_graphic() || b1 == b' ')
                    && (b2.is_ascii_graphic() || b2 == b' ' || b2 == 0);
                if is_valid {
                    mov_word_instrs.push((i, b1, b2));
                    i += 5;
                    continue;
                }
            }
            i += 1;
        }

        // Group consecutive mov word instructions within a function/block
        // A new group starts if gap changes significantly or we hit invalid chars
        let mut j = 0;
        while j < mov_word_instrs.len() {
            let (start_pos, b1, b2) = mov_word_instrs[j];
            let mut chunk = String::new();
            chunk.push(b1 as char);

            // Only add b2 if it's not a null terminator
            let is_terminated = b2 == 0;
            if !is_terminated {
                chunk.push(b2 as char);
            }

            let mut k = j + 1;
            let expected_gap = if k < mov_word_instrs.len() {
                (mov_word_instrs[k].0 - start_pos) as i64
            } else {
                37 // Default kworker pattern gap
            };

            while k < mov_word_instrs.len() {
                let (pos, b3, b4) = mov_word_instrs[k];
                let gap = (pos - start_pos) as i64;
                let prev_pos = if k > 0 {
                    mov_word_instrs[k - 1].0
                } else {
                    start_pos
                };
                let current_gap = (pos - prev_pos) as i64;

                // Stop if:
                // 1. Gap changes significantly (likely different loop/string)
                // 2. String would be unreasonably long
                // 3. We've hit a null terminator (end of string)
                let gap_variance = (current_gap - expected_gap).abs();
                if gap_variance > 2 || gap > 500 || chunk.len() > 64 {
                    break;
                }

                chunk.push(b3 as char);
                // Only add b4 if it's not a null terminator
                if b4 != 0 {
                    chunk.push(b4 as char);
                } else {
                    // We've hit the end of the string
                    k += 1;
                    break;
                }
                k += 1;
            }

            // If we have at least 2 pairs (4+ chars), it's likely a real string
            // Also check that it doesn't look like random garbage
            if chunk.len() >= self.min_length
                && chunk.len() < 256
                && self.looks_like_real_string(&chunk)
            {
                let chunk_len = chunk.len();
                results.push(ExtractedString {
                    value: chunk,
                    data_offset: start_pos as u64,
                    section: None,
                    method: StringMethod::StackString,
                    kind: StringKind::StackString,
                    library: None,
                    fragments: Some(vec![StringFragment {
                        offset: start_pos as u64,
                        length: chunk_len,
                        flavor: Some("mov_word_loop".into()),
                    }]),
                    ..Default::default()
                });
            }

            j = k.max(j + 1);
        }

        results
    }

    /// Check if a string looks like it was intentionally constructed
    /// rather than random bytes that happen to be printable.
    fn looks_like_real_string(&self, s: &str) -> bool {
        // Very short strings are less reliable
        if s.len() < 4 {
            return false;
        }

        // Strings that are all special characters are suspicious
        let special_count = s.chars().filter(|c| !c.is_alphanumeric()).count();
        if special_count > s.len() / 2 {
            return false;
        }

        // Common malware strings patterns
        let suspicious_patterns = [
            "[kworker]",
            "bashrc",
            "profile",
            ".ICE",
            "/tmp",
            "/etc",
            "home",
            "user",
            "root",
            "bin",
            "lib",
            "var",
            "proc",
        ];

        for pattern in &suspicious_patterns {
            if s.contains(pattern) {
                return true;
            }
        }

        // If it has multiple alphanumeric runs, it's likely real
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

fn check_printable(bytes: &[u8], min_length: usize) -> Option<String> {
    // Filter out nulls if they are at the end (padding)
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

    // Must be all printable/valid ascii (or utf8)
    if trimmed.iter().all(|&b| b.is_ascii_graphic() || b == b' ') {
        return String::from_utf8(trimmed.to_vec()).ok();
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::StringMethod;

    fn c7_rsp(disp: u8, imm: u32) -> Vec<u8> {
        let [b0, b1, b2, b3] = imm.to_le_bytes();
        vec![0xC7, 0x44, 0x24, disp, b0, b1, b2, b3]
    }

    fn movabs_rax(imm: u64) -> Vec<u8> {
        let mut v = vec![0x48, 0xB8];
        v.extend_from_slice(&imm.to_le_bytes());
        v
    }

    fn mov_rsp_rax(disp: u8) -> Vec<u8> {
        vec![0x48, 0x89, 0x44, 0x24, disp]
    }

    fn xor_pairs(code: &[u8], min_len: usize) -> Vec<String> {
        extract_stack_strings(code, min_len)
            .into_iter()
            .filter(|s| s.method == StringMethod::XorStackPair)
            .map(|s| s.value)
            .collect()
    }

    #[test]
    fn test_c7_xor_pair_path() {
        let mut code = Vec::new();
        code.extend(c7_rsp(0x10, 0xe0ce_fe50));
        code.extend(c7_rsp(0x14, 0xa89a_bf00));
        code.push(0xC3);
        let decoded = xor_pairs(&code, 4);
        assert!(
            decoded.contains(&"PATH".to_string()),
            "expected PATH in {decoded:?}"
        );
    }

    #[test]
    fn test_c7_xor_pair_term() {
        let mut code = Vec::new();
        code.extend(c7_rsp(0x10, 0xd0bb_9388));
        code.extend(c7_rsp(0x14, 0x9de9_d6dc));
        code.push(0xC3);
        let decoded = xor_pairs(&code, 4);
        assert!(
            decoded.contains(&"TERM".to_string()),
            "expected TERM in {decoded:?}"
        );
    }

    #[test]
    fn test_c7_xor_pair_home() {
        let mut code = Vec::new();
        code.extend(c7_rsp(0x10, 0xdb70_ed3a));
        code.extend(c7_rsp(0x14, 0x9e3d_a272));
        code.push(0xC3);
        let decoded = xor_pairs(&code, 4);
        assert!(
            decoded.contains(&"HOME".to_string()),
            "expected HOME in {decoded:?}"
        );
    }

    #[test]
    fn test_two_functions_each_with_xor_pair() {
        let mut code = Vec::new();
        code.extend(c7_rsp(0x10, 0xe0ce_fe50));
        code.extend(c7_rsp(0x14, 0xa89a_bf00));
        code.push(0xC3);
        code.extend(c7_rsp(0x10, 0xd0bb_9388));
        code.extend(c7_rsp(0x14, 0x9de9_d6dc));
        code.push(0xC3);
        let decoded = xor_pairs(&code, 4);
        assert!(
            decoded.contains(&"PATH".to_string()),
            "missing PATH in {decoded:?}"
        );
        assert!(
            decoded.contains(&"TERM".to_string()),
            "missing TERM in {decoded:?}"
        );
    }

    #[test]
    fn test_movabs_xor_pair_8bytes() {
        let blob1: u64 = u64::from_le_bytes([0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8]);
        let blob2: u64 = u64::from_le_bytes([0xBC, 0x91, 0x93, 0x88, 0x9E, 0x94, 0x8D, 0xD5]);
        let mut code = Vec::new();
        code.extend(movabs_rax(blob1));
        code.extend(mov_rsp_rax(0x10));
        code.extend(movabs_rax(blob2));
        code.extend(mov_rsp_rax(0x18));
        code.push(0xC3);
        let decoded = xor_pairs(&code, 4);
        assert!(
            decoded.contains(&"Content-".to_string()),
            "expected 'Content-' in {decoded:?}"
        );
    }

    #[test]
    fn test_single_blob_no_output() {
        let mut code = Vec::new();
        code.extend(c7_rsp(0x10, 0xe0ce_fe50));
        code.push(0xC3);
        assert!(
            xor_pairs(&code, 4).is_empty(),
            "single blob should produce no output"
        );
    }

    #[test]
    fn test_xor_result_nonprintable_no_output() {
        let mut code = Vec::new();
        code.extend(c7_rsp(0x10, 0x0101_0101));
        code.extend(c7_rsp(0x14, 0x0202_0202));
        code.push(0xC3);
        assert!(
            xor_pairs(&code, 4).is_empty(),
            "non-printable XOR result should produce no output"
        );
    }

    #[test]
    fn test_printable_blob_not_xor_candidate() {
        let mut code = Vec::new();
        code.extend(c7_rsp(0x10, 0x4443_4241)); // "ABCD" — printable
        code.extend(c7_rsp(0x14, 0xe0ce_fe50)); // non-printable
        code.push(0xC3);
        assert!(
            xor_pairs(&code, 4).is_empty(),
            "printable blob should not be XOR candidate"
        );
    }

    #[test]
    fn test_xor_result_below_min_length_filtered() {
        let b1 = u32::from_le_bytes([0xAA, 0xBB, 0x00, 0x00]);
        let b2 = u32::from_le_bytes([0xEB, 0xDB, 0x00, 0x00]);
        let mut code = Vec::new();
        code.extend(c7_rsp(0x10, b1));
        code.extend(c7_rsp(0x14, b2));
        code.push(0xC3);
        assert!(
            xor_pairs(&code, 4).is_empty(),
            "short XOR result should be filtered"
        );
    }

    #[test]
    fn test_regular_stack_strings_still_detected() {
        let shell_val: u64 = 0x0000_004c_4c45_4853;
        let mut code = Vec::new();
        code.extend(movabs_rax(shell_val));
        code.extend(mov_rsp_rax(0x10));
        code.extend(c7_rsp(0x18, 0xe0ce_fe50));
        code.extend(c7_rsp(0x1c, 0xa89a_bf00));
        code.push(0xC3);
        let all = extract_stack_strings(&code, 4);
        assert!(
            all.iter().any(|s| s.value.contains("SHELL")),
            "regular 'SHELL' missing"
        );
        assert!(
            all.iter()
                .any(|s| s.value == "PATH" && s.method == StringMethod::XorStackPair),
            "XOR-pair 'PATH' missing"
        );
    }

    #[test]
    fn test_blobs_across_call_not_paired() {
        let mut code = Vec::new();
        code.extend(c7_rsp(0x10, 0xe0ce_fe50));
        code.push(0xE8);
        code.extend([0x00u8, 0x00, 0x00, 0x00]);
        code.extend(c7_rsp(0x10, 0xa89a_bf00));
        code.push(0xC3);
        assert!(
            xor_pairs(&code, 4).is_empty(),
            "cross-scope blobs should not pair"
        );
    }

    #[test]
    fn test_three_blobs_only_valid_pair_emitted() {
        let mut code = Vec::new();
        code.extend(c7_rsp(0x10, 0xe0ce_fe50));
        code.extend(c7_rsp(0x14, 0xa89a_bf00));
        code.extend(c7_rsp(0x18, 0x0101_0101));
        code.push(0xC3);
        let decoded = xor_pairs(&code, 4);
        assert_eq!(
            decoded,
            vec!["PATH"],
            "expected exactly [PATH], got {decoded:?}"
        );
    }

    #[test]
    fn test_duplicate_xor_results_deduplicated() {
        let mut code = Vec::new();
        code.extend(c7_rsp(0x10, 0xe0ce_fe50));
        code.extend(c7_rsp(0x14, 0xa89a_bf00));
        code.extend(c7_rsp(0x18, 0xe0ce_fe50));
        code.extend(c7_rsp(0x1c, 0xa89a_bf00));
        code.push(0xC3);
        let decoded = xor_pairs(&code, 4);
        assert_eq!(
            decoded.iter().filter(|s| *s == "PATH").count(),
            1,
            "expected exactly one 'PATH', got {decoded:?}"
        );
    }

    #[test]
    fn test_self_xor_all_zeros_filtered() {
        let mut code = Vec::new();
        code.extend(c7_rsp(0x10, 0xe0ce_fe50));
        code.extend(c7_rsp(0x14, 0xe0ce_fe50));
        code.push(0xC3);
        assert!(
            xor_pairs(&code, 4).is_empty(),
            "self-XOR should produce nothing"
        );
    }

    #[test]
    fn test_three_chunk_merge_c7() {
        let ct0: u32 = 0xFFFF_FFFF;
        let ct1: u32 = 0xFEFE_FEFE;
        let ct2: u32 = 0xFDFD_FDFD;
        let k0: u32 = u32::from_le_bytes([0xBE, 0xBD, 0xBC, 0xBB]);
        let k1: u32 = u32::from_le_bytes([0xBB, 0xB8, 0xB9, 0xB6]);
        let k2: u32 = u32::from_le_bytes([0xB4, 0xB7, 0xB6, 0xB1]);
        let mut code = Vec::new();
        code.extend(c7_rsp(0, ct0));
        code.extend(c7_rsp(4, ct1));
        code.extend(c7_rsp(8, ct2));
        code.extend(c7_rsp(64, k0));
        code.extend(c7_rsp(68, k1));
        code.extend(c7_rsp(72, k2));
        code.push(0xC3);
        let decoded = xor_pairs(&code, 4);
        assert!(
            decoded.contains(&"ABCDEFGHIJKL".to_string()),
            "expected merged string: {decoded:?}"
        );
        assert!(
            !decoded.contains(&"ABCD".to_string()),
            "'ABCD' should be merged: {decoded:?}"
        );
    }

    #[test]
    fn test_three_chunk_merge_movabs() {
        let ct0 = u64::from_le_bytes([0xFF; 8]);
        let ct1 = u64::from_le_bytes([0xFE; 8]);
        let ct2 = u64::from_le_bytes([0xFD; 8]);
        let k0 = u64::from_le_bytes([0xBE, 0xBD, 0xBC, 0xBB, 0xBA, 0xB9, 0xB8, 0xB7]);
        let k1 = u64::from_le_bytes([0xB7, 0xB4, 0xB5, 0xB2, 0xB3, 0xB0, 0xB1, 0xAE]);
        let k2 = u64::from_le_bytes([0xAC, 0xAF, 0xAE, 0xA9, 0xA8, 0xAB, 0xAA, 0xA5]);
        let mut code = Vec::new();
        code.extend(movabs_rax(ct0));
        code.extend(mov_rsp_rax(0));
        code.extend(movabs_rax(ct1));
        code.extend(mov_rsp_rax(8));
        code.extend(movabs_rax(ct2));
        code.extend(mov_rsp_rax(16));
        code.extend(movabs_rax(k0));
        code.extend(mov_rsp_rax(48));
        code.extend(movabs_rax(k1));
        code.extend(mov_rsp_rax(56));
        code.extend(movabs_rax(k2));
        code.extend(mov_rsp_rax(64));
        code.push(0xC3);
        let decoded = xor_pairs(&code, 4);
        assert!(
            decoded.contains(&"ABCDEFGHIJKLMNOPQRSTUVWX".to_string()),
            "expected 24-char merged string: {decoded:?}"
        );
    }

    #[test]
    fn test_react2shell_stack_strings() {
        use std::path::PathBuf;
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("testdata/malware/react2shell");
        let data = match std::fs::read(&d) {
            Ok(d) => d,
            Err(_) => return, // skip if binary not present
        };
        let strings = extract_stack_strings(&data, 4);
        let interesting: Vec<String> = strings
            .iter()
            .map(|s| s.value.clone())
            .filter(|s| s.contains("/proc/"))
            .collect();
        assert!(
            interesting.contains(&"/proc/version".to_string()),
            "Should contain '/proc/version', found: {interesting:?}"
        );
        assert!(
            !interesting.contains(&"/proc/veversion".to_string()),
            "Should NOT contain mangled '/proc/veversion'"
        );
        assert!(
            interesting.contains(&"/proc/self/setgroups".to_string()),
            "Should contain '/proc/self/setgroups', found: {interesting:?}"
        );
        assert!(
            interesting.contains(&"/proc/self/gid_map".to_string()),
            "Should contain '/proc/self/gid_map'"
        );
        assert!(
            interesting.contains(&"/proc/self/uid_map".to_string()),
            "Should contain '/proc/self/uid_map'"
        );
    }

    #[test]
    fn test_multi_chunk_merge() {
        let ct0: u32 = 0xFFFF_FFFF;
        let ct1: u32 = 0xFEFE_FEFE;
        let k0: u32 = u32::from_le_bytes([0xBE, 0xBD, 0xBC, 0xBB]);
        let k1: u32 = u32::from_le_bytes([0xBB, 0xB8, 0xB9, 0xB6]);
        let mut code = Vec::new();
        code.extend(c7_rsp(0, ct0));
        code.extend(c7_rsp(4, ct1));
        code.extend(c7_rsp(32, k0));
        code.extend(c7_rsp(36, k1));
        code.push(0xC3);
        let decoded = xor_pairs(&code, 4);
        assert!(
            decoded.contains(&"ABCDEFGH".to_string()),
            "expected merged 'ABCDEFGH': {decoded:?}"
        );
        assert!(
            !decoded.contains(&"ABCD".to_string()),
            "'ABCD' should be merged: {decoded:?}"
        );
        assert!(
            !decoded.contains(&"EFGH".to_string()),
            "'EFGH' should be merged: {decoded:?}"
        );
    }
}
