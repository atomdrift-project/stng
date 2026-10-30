//! ARM64 strings addressed by ADRP+ADD with a MOV length: passed as call
//! arguments, or stored as `{ptr, len}` pairs on the stack.

use super::{Scan, arm64_preserved, decode_rodata_string, is_valid_utf8_string, looks_like_key};
use crate::classifier::classify_string;
use crate::types::{ExtractedString, StringKind, StringMethod};
use std::collections::HashSet;

pub(super) fn extract_inline_strings_arm64(
    text_data: &[u8],
    text_addr: u64,
    rodata_data: &[u8],
    rodata_addr: u64,
    min_length: usize,
) -> Vec<ExtractedString> {
    let mut strings = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    let scan = Scan::new(text_data, text_addr, rodata_data, rodata_addr, min_length);
    let mut preserved = arm64_preserved::Context::new(text_data, text_addr);

    // ARM64 instructions are a fixed 4 bytes.
    let mut i = 0;
    while i + 4 <= text_data.len() {
        let inst = u32::from_le_bytes([
            text_data[i],
            text_data[i + 1],
            text_data[i + 2],
            text_data[i + 3],
        ]);

        // BL (branch with link): 0x94xxxxxx
        if (inst & 0xFC000000) == 0x94000000 {
            if let Some((value, address)) =
                preserved.recover(i, rodata_data, rodata_addr, min_length)
                && seen.insert(value.clone())
            {
                strings.push(ExtractedString {
                    kind: classify_string(&value),
                    value,
                    data_offset: address,
                    method: StringMethod::InstructionPattern,
                    ..Default::default()
                });
            }
            extract_arm64_inline_string(i, &scan, &mut strings, &mut seen);
        }

        i += 4;
    }

    extract_arm64_stored_strings(
        text_data,
        text_addr,
        rodata_data,
        rodata_addr,
        min_length,
        &mut strings,
        &mut seen,
    );

    strings
}

/// How many instructions a register's decoded pointer or length stays usable.
/// Go writes a composite literal's elements one after another, but reuses a
/// length register across elements of equal length: a table of paths may load
/// `x4 = 7` once and store it with two pointers eight instructions apart. Beyond a short window the value
/// is more likely stale than reused, and a stale length over Go's packed
/// rodata decodes into a plausible but wrong string.
pub(super) const ARM64_STORED_WINDOW: usize = 24;

/// Recover strings whose header Go stores rather than passes: the elements of
/// a `[]string` or struct literal built on the stack.
///
/// ```text
/// adrp x2, page ; add x2, x2, #lo12   // pointer into rodata
/// mov  x3, #17                         // length
/// stp  x2, x3, [sp, #0x90]             // string header {ptr, len}
/// ```
///
/// No call follows, so the BL-anchored scan never sees these — which is how
/// every path in a Go implant's credential-file table went missing from its
/// arm64 builds while the amd64 builds of the same source kept them.
///
/// A forward scan tracks, per register, the rodata pointer an `ADRP`+`ADD`
/// produced and the immediate a `MOVZ` / `ORR Rd, XZR, #imm` loaded, and
/// decodes a string when an `STP` stores that pointer and length as a pair.
/// State is conservative: any branch clears every register, any other
/// register-writing instruction clears its destination, and values expire
/// after [`ARM64_STORED_WINDOW`] instructions.
pub(super) fn extract_arm64_stored_strings(
    text_data: &[u8],
    text_addr: u64,
    rodata_data: &[u8],
    rodata_addr: u64,
    min_length: usize,
    strings: &mut Vec<ExtractedString>,
    seen: &mut HashSet<String>,
) {
    #[derive(Clone, Copy)]
    enum Reg {
        Unknown,
        /// ADRP result: a page address awaiting its ADD.
        Page(u64),
        /// A decoded rodata address.
        Ptr(u64),
        /// A small immediate — a candidate length.
        Len(u64),
    }

    // Each slot records the straight-line run (`epoch`) and instruction that
    // set it. A branch invalidates every register by advancing the epoch
    // rather than clearing the table: branches are a sizeable fraction of all
    // instructions, and this runs over the text of millions of files a day.
    #[derive(Clone, Copy)]
    struct Slot {
        reg: Reg,
        epoch: u32,
        at: u32,
    }

    let rodata_end = rodata_addr.saturating_add(rodata_data.len() as u64);
    let mut slots = [Slot {
        reg: Reg::Unknown,
        epoch: 0,
        at: 0,
    }; 32];
    let mut epoch: u32 = 1;
    let window = ARM64_STORED_WINDOW as u32;

    for (idx, word) in text_data.as_chunks::<4>().0.iter().enumerate() {
        let inst = u32::from_le_bytes(*word);
        let now = idx as u32;
        let rd = (inst & 0x1F) as usize;
        let get = |slots: &[Slot; 32], r: usize| {
            let s = slots[r];
            if s.epoch == epoch && now - s.at <= window {
                s.reg
            } else {
                Reg::Unknown
            }
        };
        let set = |slots: &mut [Slot; 32], r: usize, reg: Reg| {
            slots[r] = Slot {
                reg,
                epoch,
                at: now,
            };
        };

        // Branches end a straight-line run: B, BL, B.cond, CBZ/CBNZ, TBZ/TBNZ,
        // BR/BLR/RET. Nothing known before one can be trusted after it.
        let branch = (inst & 0x7C00_0000) == 0x1400_0000 // B, BL
            || (inst & 0xFF00_0010) == 0x5400_0000 // B.cond
            || (inst & 0x7E00_0000) == 0x3400_0000 // CBZ, CBNZ
            || (inst & 0x7E00_0000) == 0x3600_0000 // TBZ, TBNZ
            || (inst & 0xFE1F_FC1F) == 0xD61F_0000; // BR, BLR, RET
        if branch {
            epoch = epoch.wrapping_add(1);
            continue;
        }

        // ADRP Xd, page
        if (inst & 0x9F00_0000) == 0x9000_0000 {
            let page = text_addr
                .checked_add((idx * 4) as u64)
                .and_then(|pc| crate::arm64::adrp_page(pc, inst));
            set(&mut slots, rd, page.map_or(Reg::Unknown, Reg::Page));
            continue;
        }

        // ADD Xd, Xn, #imm12 (64-bit, unshifted) completing an ADRP.
        if (inst & 0xFFC0_0000) == 0x9100_0000 {
            let rn = ((inst >> 5) & 0x1F) as usize;
            let reg = match get(&slots, rn) {
                Reg::Page(page) => page
                    .checked_add(u64::from((inst >> 10) & 0xFFF))
                    .filter(|addr| (rodata_addr..rodata_end).contains(addr))
                    .map_or(Reg::Unknown, Reg::Ptr),
                _ => Reg::Unknown,
            };
            set(&mut slots, rd, reg);
            continue;
        }

        // MOVZ Xd, #imm, or ORR Xd, XZR, #bitmask — both load an immediate.
        let is_movz = (inst & 0x7F80_0000) == 0x5280_0000;
        let is_orr_imm = (inst & 0x7F80_0000) == 0x3200_0000 && ((inst >> 5) & 0x1F) == 31;
        if is_movz || is_orr_imm {
            set(
                &mut slots,
                rd,
                decode_arm_mov_immediate(inst).map_or(Reg::Unknown, Reg::Len),
            );
            continue;
        }

        // STP Xt1, Xt2, [...] — 64-bit general registers, any addressing mode.
        if matches!(inst & 0xFFC0_0000, 0xA900_0000 | 0xA980_0000 | 0xA880_0000) {
            let rt2 = ((inst >> 10) & 0x1F) as usize;
            if let (Reg::Ptr(addr), Reg::Len(len)) = (get(&slots, rd), get(&slots, rt2))
                && let Some(s) = decode_rodata_string(addr, len, rodata_data, rodata_addr)
                && s.len() >= min_length
                && seen.insert(s.clone())
            {
                let kind = classify_string(&s);
                strings.push(ExtractedString {
                    value: s,
                    data_offset: addr,
                    method: StringMethod::InstructionPattern,
                    kind,
                    ..Default::default()
                });
            }
            continue;
        }

        // Every other store reads its registers; everything else that is not
        // a store may write Rd (and a load pair Rt2 as well).
        // A store is a load/store-class instruction with the L bit clear;
        // load-literal has no L bit and is a load.
        let load_store_class = (inst & 0x0A00_0000) == 0x0800_0000;
        let load_literal = (inst & 0x3B00_0000) == 0x1800_0000;
        if !(load_store_class && !load_literal && (inst & 0x0040_0000) == 0) {
            set(&mut slots, rd, Reg::Unknown);
            if (inst & 0x3A40_0000) == 0x2840_0000 {
                set(&mut slots, ((inst >> 10) & 0x1F) as usize, Reg::Unknown);
            }
        }
    }
}

/// Recover the inline string(s) loaded ahead of a BL call site.
///
/// Walks backward for `ADRP Rd, page; ADD Rd, Rd, #lo12` (the rodata pointer)
/// and reads the immediately following `MOVZ`/`ORR` as the length — Go emits the
/// length right after the address. The length register must differ from `Rd`
/// (a length MOV into the pointer register would clobber it), and
/// [`decode_arm64_string`] validates the slice, so an unrelated MOV is rejected.
pub(super) fn extract_arm64_inline_string(
    bl_pos: usize,
    scan: &Scan<'_>,
    strings: &mut Vec<ExtractedString>,
    seen: &mut HashSet<String>,
) {
    let Scan {
        text: text_data,
        min_length,
        ..
    } = *scan;
    let word = |o: usize| {
        u32::from_le_bytes([
            text_data[o],
            text_data[o + 1],
            text_data[o + 2],
            text_data[o + 3],
        ])
    };

    // Need room for ADRP, ADD, and the length MOV before the BL.
    let max_lookback = bl_pos.min(20 * 4);
    let mut lookback = 12;
    while lookback <= max_lookback {
        let pos = bl_pos - lookback;

        let inst1 = word(pos);
        let inst2 = word(pos + 4);
        let mut len_pos = pos + 8;
        let mut inst3 = word(len_pos);

        // ADRP Rd, page ; ADD Rd, Rd, #imm12 — same Rd in both.
        let addr_reg = inst1 & 0x1F;
        let is_adrp = (inst1 & 0x9F000000) == 0x90000000;
        let is_add = (inst2 & 0xFFC00000) == 0x91000000
            && (inst2 & 0x1F) == addr_reg
            && ((inst2 >> 5) & 0x1F) == addr_reg;
        if !is_adrp || !is_add || addr_reg == 31 {
            lookback += 4;
            continue;
        }
        // Rust may set up a separate stack result pointer between the string
        // address and length. Require this exact harmless instruction and an
        // immediately following length/call, not an arbitrary instruction gap.
        if pos + 16 == bl_pos
            && inst3 & 0xffc003e0 == 0x910003e0
            && inst3 & 31 != addr_reg
            && inst3 & 31 != 31
        {
            len_pos = pos + 12;
            inst3 = word(len_pos);
        }
        // MOVZ Rn, #imm or ORR Rn, XZR, #bitmask (the length) into a register
        // other than the pointer.
        let len_reg = inst3 & 0x1F;
        let is_len =
            len_reg != addr_reg && len_reg != 31 && decode_arm_mov_immediate(inst3).is_some();

        // Only understood, independent argument setup may separate the length
        // from this call. In particular, do not carry a pointer across another
        // call, branch, load/writeback, or a write to either argument register.
        let preserved = (len_pos + 4..bl_pos).step_by(4).all(|at| {
            let inst = word(at);
            if inst == 0xd503201f {
                return true;
            } // NOP
            let dst = inst & 31;
            dst != addr_reg
                && dst != len_reg
                && dst != 31
                && (decode_arm_mov_immediate(inst).is_some()
                    || inst & 0xffc003e0 == 0x910003e0
                    || inst & 0x7fe0ffe0 == 0x2a0003e0)
        });
        if is_adrp
            && is_add
            && is_len
            && preserved
            && let Some((s, str_addr)) = decode_arm64_string(inst1, inst2, inst3, pos, scan)
            && s.len() >= min_length
            && seen.insert(s.clone())
        {
            // Preserve the map-access hint: runtime map lookups load the key in
            // x2 and its length in x3.
            let kind = if addr_reg == 2 && len_reg == 3 && looks_like_key(&s) {
                Some(StringKind::MapKey)
            } else {
                classify_string(&s)
            };
            strings.push(ExtractedString {
                value: s,
                data_offset: str_addr,
                method: StringMethod::InstructionPattern,
                kind,
                ..Default::default()
            });
        }

        lookback += 4;
    }
}

/// Decode ARM64 ADRP+ADD instructions to extract string address and length.
///
/// Returns the decoded string along with its absolute virtual address so callers
/// can record a unique `data_offset` per inline string (rather than collapsing
/// every inline string at the section base, which dedup-by-offset would prune
/// down to a single survivor).
pub(super) fn decode_arm64_string(
    inst1: u32,
    inst2: u32,
    inst3: u32,
    pos: usize,
    scan: &Scan<'_>,
) -> Option<(String, u64)> {
    let Scan {
        text_addr,
        rodata: rodata_data,
        rodata_addr,
        rodata_end,
        ..
    } = *scan;
    // ADRP + ADD: the string's address.
    let str_addr = crate::arm64::adrp_add(text_addr.checked_add(pos as u64)?, inst1, inst2)?;

    // Decode MOV/ORR: extract length
    let str_len = decode_arm_mov_immediate(inst3)?;

    // Validate
    if str_addr < rodata_addr || str_addr >= rodata_end {
        return None;
    }

    if str_len == 0 || str_len > 1000 {
        return None;
    }

    let rodata_offset = str_addr.checked_sub(rodata_addr)? as usize;
    let end = rodata_offset.checked_add(str_len as usize)?;
    if end > rodata_data.len() {
        return None;
    }

    let bytes = &rodata_data[rodata_offset..end];
    let s = std::str::from_utf8(bytes).ok()?;

    if is_valid_utf8_string(s) {
        Some((s.to_string(), str_addr))
    } else {
        None
    }
}

/// Decode ARM64 MOV/ORR immediate value.
pub(super) fn decode_arm_mov_immediate(inst: u32) -> Option<u64> {
    // MOVZ Wd/Xd zeroes every lane not supplied by its immediate. A W write
    // zero-extends into the corresponding X register; lanes 32/48 are reserved.
    if inst & 0x7f80_0000 == 0x5280_0000 {
        return crate::arm64::move_wide(inst).map(|mov| mov.imm);
    }
    // ORR Rd, ZR, #imm is a constant load; ORR from a live register is not.
    if (inst & 0x7f800000) == 0x32000000 && (inst >> 5) & 31 == 31 {
        return crate::arm64::bitmask_imm(inst).filter(|&v| v > 0 && v <= 1000);
    }

    None
}

#[cfg(test)]
mod argument_tests;
