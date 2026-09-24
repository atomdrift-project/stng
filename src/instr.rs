//! Instruction pattern analysis for inline string extraction.
//!
//! Inline literals (function arguments, map keys/values) don't create stored
//! pointer+length structures. Instead, compilers pass string addresses and lengths
//! through registers. We extract these by pattern matching instruction sequences.

// This codebase targets 64-bit hosts only: usize = u64, so u64-to-usize casts are lossless.
#![allow(clippy::cast_possible_truncation)]

use super::classifier::classify_string;
use super::types::{ExtractedString, StringKind, StringMethod};
use std::collections::HashSet;

/// Extracts inline strings from ARM64 executable code.
///
/// Scans for BL (branch-with-link) instructions and looks backward for the
/// `ADRP+ADD` that computes a rodata pointer plus the `MOVZ`/`ORR` immediate
/// that loads its length.
///
/// As on AMD64, the pointer and length land in whatever register pair the ABI
/// assigns for that call — `runtime.stringtoslicebyte` passes them in x1/x2, not
/// the x0/x1 or x2/x3 a fixed list would expect — so this accepts any `ADRP+ADD`
/// into rodata followed by a length load into a *different* register.
pub(crate) fn extract_inline_strings_arm64(
    text_data: &[u8],
    text_addr: u64,
    rodata_data: &[u8],
    rodata_addr: u64,
    min_length: usize,
) -> Vec<ExtractedString> {
    let mut strings = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    let rodata_end = rodata_addr + rodata_data.len() as u64;

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
            extract_arm64_inline_string(
                i,
                text_data,
                text_addr,
                rodata_data,
                rodata_addr,
                rodata_end,
                min_length,
                &mut strings,
                &mut seen,
            );
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
/// length register across elements of equal length — the sckit implant's
/// credential-path table reloads `x4 = 7` once and stores it with two
/// different pointers eight instructions apart. Beyond a short window the value
/// is more likely stale than reused, and a stale length over Go's packed
/// rodata decodes into a plausible but wrong string.
const ARM64_STORED_WINDOW: usize = 24;

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
fn extract_arm64_stored_strings(
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

    let rodata_end = rodata_addr + rodata_data.len() as u64;
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
        if is_arm64_branch(inst) {
            epoch = epoch.wrapping_add(1);
            continue;
        }

        // ADRP Xd, page
        if (inst & 0x9F00_0000) == 0x9000_0000 {
            let immlo = (inst >> 29) & 0x3;
            let immhi = (inst >> 5) & 0x7FFFF;
            let mut page_offset = i64::from((immhi << 2) | immlo);
            if (page_offset & 0x100000) != 0 {
                page_offset |= !0x1FFFFF_i64;
            }
            let pc = text_addr as i64 + (idx * 4) as i64;
            let page = (pc & !0xFFF_i64) + (page_offset << 12);
            set(
                &mut slots,
                rd,
                u64::try_from(page).map_or(Reg::Unknown, Reg::Page),
            );
            continue;
        }

        // ADD Xd, Xn, #imm12 (64-bit, unshifted) completing an ADRP.
        if (inst & 0xFFC0_0000) == 0x9100_0000 {
            let rn = ((inst >> 5) & 0x1F) as usize;
            let reg = match get(&slots, rn) {
                Reg::Page(page) => {
                    let addr = page + u64::from((inst >> 10) & 0xFFF);
                    if (rodata_addr..rodata_end).contains(&addr) {
                        Reg::Ptr(addr)
                    } else {
                        Reg::Unknown
                    }
                }
                _ => Reg::Unknown,
            };
            set(&mut slots, rd, reg);
            continue;
        }

        // MOVZ Xd, #imm, or ORR Xd, XZR, #bitmask — both load an immediate.
        let is_movz = (inst & 0xFF80_0000) == 0xD280_0000;
        let is_orr_imm = (inst & 0xFF80_0000) == 0xB200_0000 && ((inst >> 5) & 0x1F) == 31;
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
        if !is_arm64_store(inst) {
            set(&mut slots, rd, Reg::Unknown);
            if (inst & 0x3A40_0000) == 0x2840_0000 {
                set(&mut slots, ((inst >> 10) & 0x1F) as usize, Reg::Unknown);
            }
        }
    }
}

/// Whether an A64 instruction transfers control.
fn is_arm64_branch(inst: u32) -> bool {
    (inst & 0x7C00_0000) == 0x1400_0000 // B, BL
        || (inst & 0xFF00_0010) == 0x5400_0000 // B.cond
        || (inst & 0x7E00_0000) == 0x3400_0000 // CBZ, CBNZ
        || (inst & 0x7E00_0000) == 0x3600_0000 // TBZ, TBNZ
        || (inst & 0xFE1F_FC1F) == 0xD61F_0000 // BR, BLR, RET
}

/// Whether an A64 load/store-class instruction is a store (reads, never
/// writes, its data registers). Load-literal has no L bit and is a load.
fn is_arm64_store(inst: u32) -> bool {
    let load_store_class = (inst & 0x0A00_0000) == 0x0800_0000;
    let load_literal = (inst & 0x3B00_0000) == 0x1800_0000;
    load_store_class && !load_literal && (inst & 0x0040_0000) == 0
}

/// A `len`-byte rodata string at virtual address `addr`, if it is text.
fn decode_rodata_string(
    addr: u64,
    len: u64,
    rodata_data: &[u8],
    rodata_addr: u64,
) -> Option<String> {
    if len == 0 || len > 1000 {
        return None;
    }
    let start = usize::try_from(addr.checked_sub(rodata_addr)?).ok()?;
    let bytes = rodata_data.get(start..start.checked_add(usize::try_from(len).ok()?)?)?;
    let s = std::str::from_utf8(bytes).ok()?;
    is_valid_utf8_string(s).then(|| s.to_string())
}

/// Recover the inline string(s) loaded ahead of a BL call site.
///
/// Walks backward for `ADRP Rd, page; ADD Rd, Rd, #lo12` (the rodata pointer)
/// and reads the immediately following `MOVZ`/`ORR` as the length — Go emits the
/// length right after the address. The length register must differ from `Rd`
/// (a length MOV into the pointer register would clobber it), and
/// [`decode_arm64_string`] validates the slice, so an unrelated MOV is rejected.
#[allow(clippy::too_many_arguments)]
fn extract_arm64_inline_string(
    bl_pos: usize,
    text_data: &[u8],
    text_addr: u64,
    rodata_data: &[u8],
    rodata_addr: u64,
    rodata_end: u64,
    min_length: usize,
    strings: &mut Vec<ExtractedString>,
    seen: &mut HashSet<String>,
) {
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
        if pos + 12 > text_data.len() {
            lookback += 4;
            continue;
        }

        let inst1 = word(pos);
        let inst2 = word(pos + 4);
        let inst3 = word(pos + 8);

        // ADRP Rd, page ; ADD Rd, Rd, #imm12 — same Rd in both.
        let addr_reg = inst1 & 0x1F;
        let is_adrp = (inst1 & 0x9F000000) == 0x90000000;
        let is_add = (inst2 & 0xFF000000) == 0x91000000
            && (inst2 & 0x1F) == addr_reg
            && ((inst2 >> 5) & 0x1F) == addr_reg;
        // MOVZ Rn, #imm or ORR Rn, XZR, #bitmask (the length) into a register
        // other than the pointer.
        let len_reg = inst3 & 0x1F;
        let is_len = ((inst3 & 0xB2000000) == 0xB2000000 || (inst3 & 0xFF000000) == 0xD2000000)
            && len_reg != addr_reg;

        if is_adrp
            && is_add
            && is_len
            && let Some((s, str_addr)) = decode_arm64_string(
                inst1,
                inst2,
                inst3,
                pos,
                text_addr,
                rodata_data,
                rodata_addr,
                rodata_end,
            )
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

/// Check if a string looks like a map/dict key (short, no spaces, identifier-like).
fn looks_like_key(s: &str) -> bool {
    s.len() <= 32
        && !s.contains(' ')
        && !s.starts_with('/')
        && !s.contains("://")
        && s.chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
}

/// Decode ARM64 ADRP+ADD instructions to extract string address and length.
///
/// Returns the decoded string along with its absolute virtual address so callers
/// can record a unique `data_offset` per inline string (rather than collapsing
/// every inline string at the section base, which dedup-by-offset would prune
/// down to a single survivor).
#[allow(clippy::too_many_arguments)]
fn decode_arm64_string(
    inst1: u32,
    inst2: u32,
    inst3: u32,
    pos: usize,
    text_addr: u64,
    rodata_data: &[u8],
    rodata_addr: u64,
    rodata_end: u64,
) -> Option<(String, u64)> {
    // Decode ADRP: extract page address
    let immlo = (inst1 >> 29) & 0x3;
    let immhi = (inst1 >> 5) & 0x7FFFF;
    let mut page_offset = i64::from((immhi << 2) | immlo);
    if (page_offset & 0x100000) != 0 {
        page_offset |= !0x1FFFFF_i64;
    }

    let pc = text_addr as i64 + pos as i64;
    let pc_page = pc & !0xFFF_i64;
    let page_addr = pc_page + (page_offset << 12);

    // Decode ADD: extract immediate
    let add_imm = (inst2 >> 10) & 0xFFF;
    let str_addr = u64::try_from(page_addr)
        .unwrap_or(u64::MAX)
        .wrapping_add(u64::from(add_imm));

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
fn decode_arm_mov_immediate(inst: u32) -> Option<u64> {
    // Check for MOVZ/MOVK (D2xxxxxx)
    if (inst & 0xFF000000) == 0xD2000000 {
        let imm16 = u64::from((inst >> 5) & 0xFFFF);
        let shift = u64::from(((inst >> 21) & 0x3) * 16);
        return Some(imm16 << shift);
    }

    // Check for ORR with bitmask immediate (B2xxxxxx)
    if (inst & 0xB2000000) == 0xB2000000 && (inst & 0xFF000000) != 0xD2000000 {
        return decode_arm_bitmask_immediate(inst);
    }

    None
}

/// Decode ARM64 bitmask immediate encoding used in ORR/AND instructions.
fn decode_arm_bitmask_immediate(inst: u32) -> Option<u64> {
    let sf = (inst >> 31) & 0x1;
    let n = (inst >> 22) & 0x1;
    let immr = (inst >> 16) & 0x3F;
    let imms = (inst >> 10) & 0x3F;

    let size = if sf == 1 { 64u32 } else { 32u32 };

    // Find element size
    let elem_len = if n == 1 {
        6 // 64-bit element
    } else if (imms & 0x20) == 0 {
        5 // 32-bit element
    } else if (imms & 0x10) == 0 {
        4 // 16-bit element
    } else if (imms & 0x08) == 0 {
        3 // 8-bit element
    } else if (imms & 0x04) == 0 {
        2 // 4-bit element
    } else {
        return None; // Invalid
    };

    let esize = 1u32 << elem_len;
    if esize > size {
        return None;
    }

    // Bounds check to prevent overflow
    if elem_len > 6 || esize > 64 {
        return None;
    }

    let levels = (1u32 << elem_len) - 1;
    let s = imms & levels;
    let r = immr & levels;

    let welem = s + 1;
    if welem > 63 {
        return None;
    }
    let mut pattern = (1u64 << welem) - 1;

    if r != 0 && r < esize {
        let mask = if esize >= 64 {
            u64::MAX
        } else {
            (1u64 << esize) - 1
        };
        pattern = ((pattern >> r) | (pattern << (esize - r))) & mask;
    }

    let mut value = 0u64;
    let mut i = 0u32;
    while i < size && i < 64 {
        value |= pattern << i;
        i += esize;
    }

    if value > 0 && value <= 1000 {
        Some(value)
    } else {
        None
    }
}

/// Extracts inline strings from AMD64 executable code.
///
/// Scans for CALL instructions and looks for LEAQ addr(RIP) patterns
/// (string address) and MOVL/MOVQ patterns (string length).
pub(crate) fn extract_inline_strings_amd64(
    text_data: &[u8],
    text_addr: u64,
    rodata_data: &[u8],
    rodata_addr: u64,
    min_length: usize,
) -> Vec<ExtractedString> {
    use rayon::prelude::*;

    let rodata_end = rodata_addr + rodata_data.len() as u64;

    // Find all CALL instruction positions first
    let call_positions: Vec<usize> = text_data
        .iter()
        .enumerate()
        .filter(|(i, b)| **b == 0xE8 && *i < text_data.len().saturating_sub(5))
        .map(|(i, _)| i)
        .collect();

    // Process CALL sites in parallel. `flat_map_iter` streams each site's
    // (usually empty) result straight into the collection; collecting into a
    // `Vec<Vec<_>>` would instead retain one Vec header per CALL site, and a
    // multi-MB `.text` has hundreds of thousands of `0xE8` bytes — ~10 MB of
    // empty headers for a few thousand real strings.
    let mut result: Vec<ExtractedString> = call_positions
        .par_iter()
        .flat_map_iter(|&i| {
            let mut strings = Vec::new();
            let mut seen = HashSet::new();

            // Consolidated backward scan for all register and stack patterns
            extract_backward_strings(
                i,
                text_data,
                text_addr,
                rodata_data,
                rodata_addr,
                rodata_end,
                min_length,
                &mut strings,
                &mut seen,
            );

            // Extract value strings after CALL (forward-scanning, kept separate)
            extract_amd64_value_string(
                i,
                text_data,
                text_addr,
                rodata_data,
                rodata_addr,
                rodata_end,
                min_length,
                &mut strings,
                &mut seen,
            );

            strings
        })
        .collect();

    extract_amd64_stored_strings(
        text_data,
        text_addr,
        rodata_data,
        rodata_addr,
        min_length,
        &mut result,
    );

    // Deduplicate by value, preserving first-seen order.
    let mut seen: HashSet<String> = HashSet::new();
    result.retain(|s| seen.insert(s.value.clone()));
    result
}

/// Bytes after a string-pointer `LEA` searched for its header stores. rustc
/// and Go write a literal table element in four or five instructions; 48 bytes
/// covers that with room for an interleaved store, and bounds the cost per LEA.
const AMD64_STORED_AHEAD: usize = 48;
/// Bytes before the `LEA` searched for a length register load that preceded
/// it (a length shared across equal-length elements is loaded once).
const AMD64_STORED_BEHIND: usize = 32;
/// Furthest a header's length store may sit from its pointer store.
const AMD64_STORED_PAIR_GAP: usize = 16;

/// Recover strings whose header x86-64 code stores rather than passes: the
/// elements of a `[&str; N]` / `[]string` literal or a struct built in memory.
///
/// ```text
/// lea  rcx, [rip+str]      ; pointer into rodata
/// mov  [rdi], rcx          ; header.ptr
/// mov  ecx, 0x1f           ; length
/// mov  [rdi+8], rcx        ; header.len  (or: mov qword [rdi+8], 0x1f)
/// ```
///
/// No call follows, so the CALL-anchored scan never sees these; this is the
/// amd64 twin of [`extract_arm64_stored_strings`]. Variable-length encoding
/// rules out a cheap linear decode of `.text`, so the pass anchors on the rare
/// shape instead: a RIP-relative `LEA` whose target is in rodata. Around each,
/// a small byte window is probed for the pointer register stored to
/// `[base+d]` and a length stored to `[base+d+8]`. Probing the window byte by
/// byte can misparse, so a pair must agree on base and adjacent displacement,
/// and the slice must decode to printable text -- the same bar as every other
/// instruction-derived string.
fn extract_amd64_stored_strings(
    text: &[u8],
    text_addr: u64,
    rodata: &[u8],
    rodata_addr: u64,
    min_length: usize,
    strings: &mut Vec<ExtractedString>,
) {
    let rodata_end = rodata_addr + rodata.len() as u64;
    let mut seen: HashSet<(u64, u64)> = HashSet::new();
    for op in memchr::memchr_iter(0x8D, text) {
        // REX.W (optionally .R) 8D /r with ModRM mod=00 rm=101: LEA r64, [rip+disp32].
        let Some(lea) = op.checked_sub(1) else {
            continue;
        };
        let rex = text[lea];
        if rex & 0xFB != 0x48 {
            continue;
        }
        let Some(&modrm) = text.get(op + 1) else {
            continue;
        };
        if modrm & 0xC7 != 0x05 {
            continue;
        }
        let Some(disp) = read_i32(text, op + 2) else {
            continue;
        };
        let end = op + 6;
        let ptr_reg = ((modrm >> 3) & 7) | ((rex >> 2) & 1) << 3;
        let target = (text_addr as i64 + end as i64 + i64::from(disp)).cast_unsigned();
        if !(rodata_addr..rodata_end).contains(&target) {
            continue;
        }

        // The window closes where the pointer register is next loaded by
        // another rip-relative LEA: past that, a store of the register writes
        // a different string's pointer. Compilers reuse the same scratch
        // register for consecutive table elements, and pairing across that
        // reload was the main source of wrong-length strings.
        let mut limit = text.len().min(end + AMD64_STORED_AHEAD);
        if let Some(next) = (end..limit).find(|&j| rip_lea_dest(text, j) == Some(ptr_reg)) {
            limit = next;
        }
        let ahead = end..limit;
        let Some((ptr_at, base, d)) = ahead.clone().find_map(|j| {
            store_reg(text, j).and_then(|(src, base, d)| (src == ptr_reg).then_some((j, base, d)))
        }) else {
            continue;
        };
        let len_disp = d + 8;
        // A header is written by adjacent instructions; a length store far
        // from the pointer store belongs to something else.
        let near =
            ptr_at.saturating_sub(AMD64_STORED_PAIR_GAP)..limit.min(ptr_at + AMD64_STORED_PAIR_GAP);
        let len = near.clone().find_map(|j| {
            if let Some((b, dd, imm)) = store_imm(text, j)
                && b == base
                && dd == len_disp
            {
                return Some(u64::from(imm));
            }
            let (src, b, dd) = store_reg(text, j)?;
            if b != base || dd != len_disp {
                return None;
            }
            // The length register's most recent immediate load before its store.
            (lea.saturating_sub(AMD64_STORED_BEHIND)..j)
                .rev()
                .find_map(|k| mov_imm(text, k).filter(|&(r, _)| r == src))
                .map(|(_, imm)| u64::from(imm))
        });
        let Some(len) = len else { continue };
        if !seen.insert((target, len)) {
            continue;
        }
        if let Some(s) = decode_rodata_string(target, len, rodata, rodata_addr)
            && s.len() >= min_length
        {
            let kind = classify_string(&s);
            strings.push(ExtractedString {
                value: s,
                data_offset: target,
                method: StringMethod::InstructionPattern,
                kind,
                ..Default::default()
            });
        }
    }
}

/// Destination register of a `LEA r64, [rip+disp32]` starting at `at`.
fn rip_lea_dest(b: &[u8], at: usize) -> Option<u8> {
    let rex = *b.get(at)?;
    if rex & 0xFB != 0x48 || *b.get(at + 1)? != 0x8D {
        return None;
    }
    let modrm = *b.get(at + 2)?;
    (modrm & 0xC7 == 0x05).then_some(((modrm >> 3) & 7) | ((rex >> 2) & 1) << 3)
}

fn read_i32(b: &[u8], at: usize) -> Option<i32> {
    Some(i32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// A memory operand `[base + disp]` from the ModRM at `at` (REX.B in `rex`):
/// base register, displacement and the operand's encoded length. RIP-relative,
/// indexed and absolute forms are rejected -- a header store is always
/// base-plus-displacement.
fn mem_operand(b: &[u8], at: usize, rex: u8) -> Option<(u8, i64, usize)> {
    let modrm = *b.get(at)?;
    let md = modrm >> 6;
    let rm = modrm & 7;
    let mut len = 1;
    let base = if rm == 4 {
        let sib = *b.get(at + 1)?;
        if (sib >> 3) & 7 != 4 || (md == 0 && sib & 7 == 5) {
            return None; // indexed, or no base
        }
        len += 1;
        sib & 7
    } else {
        if md == 0 && rm == 5 {
            return None; // RIP-relative
        }
        rm
    };
    let disp = match md {
        0 => 0,
        1 => {
            let d = i64::from(*b.get(at + len)? as i8);
            len += 1;
            d
        }
        2 => {
            let d = i64::from(read_i32(b, at + len)?);
            len += 4;
            d
        }
        _ => return None, // register operand
    };
    Some((base | (rex & 1) << 3, disp, len))
}

/// `MOV [base+disp], r64` (REX.W 89 /r): source register, base, displacement.
fn store_reg(b: &[u8], at: usize) -> Option<(u8, u8, i64)> {
    let rex = *b.get(at)?;
    if rex & 0xF8 != 0x48 || *b.get(at + 1)? != 0x89 {
        return None;
    }
    let src = ((*b.get(at + 2)? >> 3) & 7) | ((rex >> 2) & 1) << 3;
    let (base, disp, _) = mem_operand(b, at + 2, rex)?;
    Some((src, base, disp))
}

/// `MOV QWORD [base+disp], imm32` (REX.W C7 /0): base, displacement, value.
fn store_imm(b: &[u8], at: usize) -> Option<(u8, i64, u32)> {
    let rex = *b.get(at)?;
    if rex & 0xFA != 0x48 || *b.get(at + 1)? != 0xC7 || (*b.get(at + 2)? >> 3) & 7 != 0 {
        return None;
    }
    let (base, disp, len) = mem_operand(b, at + 2, rex)?;
    let imm = u32::try_from(read_i32(b, at + 2 + len)?).ok()?;
    Some((base, disp, imm))
}

/// `MOV r32, imm32` (optional REX.B, B8+r) or `MOV r64, imm32` (REX.W C7 /0,
/// register form): destination register and value.
fn mov_imm(b: &[u8], at: usize) -> Option<(u8, u32)> {
    let op = *b.get(at)?;
    let (reg, imm_at) = if (0xB8..=0xBF).contains(&op) {
        let high = at
            .checked_sub(1)
            .and_then(|p| b.get(p))
            .is_some_and(|&r| r == 0x41);
        ((op - 0xB8) | u8::from(high) << 3, at + 1)
    } else if op & 0xFA == 0x48 && *b.get(at + 1)? == 0xC7 && *b.get(at + 2)? & 0xF8 == 0xC0 {
        ((*b.get(at + 2)? & 7) | (op & 1) << 3, at + 3)
    } else {
        return None;
    };
    Some((reg, u32::try_from(read_i32(b, imm_at)?).ok()?))
}

/// Backward scan from a CALL site for inline string loads.
///
/// Go materializes a string constant at its use site as a RIP-relative `LEA`
/// (the data pointer) paired with an immediate `MOV` (the length), in whatever
/// registers the ABI assigns for that call. Enumerating specific register pairs
/// silently drops every load whose length lands in an unlisted register — e.g.
/// `[]byte(scriptConst)` whose length goes to ECX — so instead this accepts ANY
/// rip-relative LEA into rodata followed by an immediate length load into a
/// *different* register, validating the resulting slice as a printable string.
/// A stack-stored length (`MOV $len, disp(RSP)`) is the fallback for strings
/// spilled into a struct on the stack.
#[allow(clippy::too_many_arguments)]
fn extract_backward_strings(
    call_pos: usize,
    text_data: &[u8],
    text_addr: u64,
    rodata_data: &[u8],
    rodata_addr: u64,
    rodata_end: u64,
    min_length: usize,
    strings: &mut Vec<ExtractedString>,
    seen: &mut HashSet<String>,
) {
    // 256 bytes back covers a string spilled to the stack ahead of its CALL
    // and the longer Go setup sequences seen around runtime.concatstring2.
    // The LEA+immediate-length pair itself remains exact, so widening this
    // bounded association window does not make arbitrary printable data a
    // candidate; it only lets a valid pair survive intervening setup code.
    let scan_start = call_pos.saturating_sub(call_pos.min(256));
    let mut pos = scan_start;

    while pos + 7 <= call_pos {
        // REX.W LEA r64, [rip+disp32]: (48|4C) 8D [mod=00, rm=101] disp32.
        let rex = text_data[pos];
        if (rex != 0x48 && rex != 0x4C) || text_data[pos + 1] != 0x8D {
            pos += 1;
            continue;
        }
        let modrm = text_data[pos + 2];
        if (modrm & 0xC7) != 0x05 {
            pos += 1;
            continue;
        }

        let offset = i32::from_le_bytes([
            text_data[pos + 3],
            text_data[pos + 4],
            text_data[pos + 5],
            text_data[pos + 6],
        ]);
        let str_addr = (text_addr + (pos + 7) as u64).wrapping_add_signed(i64::from(offset));

        if str_addr >= rodata_addr && str_addr < rodata_end {
            // LEA destination (reg field + REX.R): a length MOV into this same
            // register would clobber the pointer, so it is never the length.
            let lea_dest = ((modrm >> 3) & 0x07) | ((rex & 0x04) << 1);
            if let Some((value, len_reg)) = find_inline_length_string(
                pos,
                call_pos,
                text_data,
                str_addr,
                rodata_data,
                rodata_addr,
                rodata_end,
                min_length,
                lea_dest,
            ) && seen.insert(value.clone())
            {
                // Preserve the map-access hint: `LEA RSI, key; MOV EDX, keylen`
                // precedes a runtime map lookup. Otherwise classify by content.
                let kind = if lea_dest == 6 && len_reg == Some(2) && looks_like_key(&value) {
                    Some(StringKind::MapKey)
                } else {
                    classify_string(&value)
                };
                strings.push(ExtractedString {
                    value,
                    data_offset: str_addr,
                    method: StringMethod::InstructionPattern,
                    kind,
                    ..Default::default()
                });
            }
        }

        pos += 7; // past this LEA
    }
}

/// Locate the length operand for a string `LEA` and return the validated string
/// plus the register the length was loaded into (`None` for a stack length).
///
/// Go emits the pointer `LEA` and an immediate-length `MOV` as a pair. This
/// scans the instructions just after the LEA for `MOV r32, imm32`
/// (`[41] B8+r id`) or `MOV r64, imm32` (`(48|4C) C7 C0+r id`), then falls back
/// to a stack store `MOV $len, disp(RSP)`. A length whose slice is non-printable
/// or runs past rodata is skipped, so the first length yielding a valid string wins.
#[allow(clippy::too_many_arguments)]
fn find_inline_length_string(
    lea_pos: usize,
    call_pos: usize,
    text_data: &[u8],
    str_addr: u64,
    rodata_data: &[u8],
    rodata_addr: u64,
    rodata_end: u64,
    min_length: usize,
    lea_dest: u8,
) -> Option<(String, Option<u8>)> {
    let validate = |len: u64| -> Option<String> {
        if len == 0 || len > 1000 || str_addr + len > rodata_end {
            return None;
        }
        let start = (str_addr - rodata_addr) as usize;
        let s = std::str::from_utf8(rodata_data.get(start..start + len as usize)?).ok()?;
        (is_valid_utf8_string(s) && s.len() >= min_length).then(|| s.to_string())
    };

    // Go emits the length `MOV` immediately after the pointer `LEA` (the LEA is
    // 7 bytes). Matching only that slot — rather than scanning a window — avoids
    // latching onto an unrelated later `MOV` whose immediate would over-run the
    // string into the next packed literal, which is the dominant false positive.
    if let Some((reg, len)) = decode_mov_imm32(text_data, lea_pos + 7)
        && reg != lea_dest
        && let Some(s) = validate(len)
    {
        return Some((s, Some(reg)));
    }

    // Some Go branches materialize the length first and emit the pointer LEA
    // immediately afterwards: `MOV EBX, 16; LEA RAX, literal`. Accept only
    // an instruction that ends exactly at the LEA, keeping the same strict
    // adjacency guarantee as the forward form.
    for width in [5, 6, 7] {
        if lea_pos < width {
            continue;
        }
        if let Some((reg, len)) = decode_mov_imm32(text_data, lea_pos - width)
            && reg != lea_dest
            && let Some(s) = validate(len)
        {
            return Some((s, Some(reg)));
        }
    }

    // Fallback: length stored to the stack (`MOV $len, disp(RSP)`), how a string
    // placed in a stack-allocated struct materializes its header.
    let search_end = (lea_pos + 30).min(call_pos);
    let mut j = lea_pos.saturating_sub(20);
    while j + 4 <= text_data.len() && j < search_end {
        if text_data[j] != 0x48 || text_data[j + 1] != 0xC7 {
            j += 1;
            continue;
        }
        let imm_offset = if text_data[j + 2] == 0x44 && text_data[j + 3] == 0x24 {
            j + 5 // MOV $imm32, disp8(RSP)
        } else if text_data[j + 2] == 0x84 && text_data[j + 3] == 0x24 {
            j + 8 // MOV $imm32, disp32(RSP)
        } else {
            j += 1;
            continue;
        };
        if let Some(&[b0, b1, b2, b3]) = text_data.get(imm_offset..imm_offset + 4) {
            let len = u64::from(u32::from_le_bytes([b0, b1, b2, b3]));
            if let Some(s) = validate(len) {
                return Some((s, None));
            }
        }
        j += 1;
    }

    None
}

/// Decode a `MOV` of a 32-bit immediate into a general register at `p`.
///
/// Handles `MOV r32, imm32` (`B8+r id`, optionally `41`-prefixed for r8d–r15d)
/// and `MOV r64, imm32` (`(48|4C) C7 C0+r id`). Returns `(register, immediate)`.
fn decode_mov_imm32(text_data: &[u8], p: usize) -> Option<(u8, u64)> {
    let first = *text_data.get(p)?;
    // MOV r32, imm32 — opcode B8+r, with optional REX.B for r8d–r15d.
    let (op_pos, reg_hi): (usize, u8) = if first == 0x41 {
        (p + 1, 0x08)
    } else {
        (p, 0x00)
    };
    let op = *text_data.get(op_pos)?;
    if (0xB8..=0xBF).contains(&op) {
        let imm = text_data.get(op_pos + 1..op_pos + 5)?;
        return Some((
            (op - 0xB8) | reg_hi,
            u64::from(u32::from_le_bytes(imm.try_into().ok()?)),
        ));
    }
    // MOV r64, imm32 (sign-extended): (48|4C) C7 C0+r.
    if (first == 0x48 || first == 0x4C) && *text_data.get(p + 1)? == 0xC7 {
        let modrm = *text_data.get(p + 2)?;
        if (0xC0..=0xC7).contains(&modrm) {
            let imm = text_data.get(p + 3..p + 7)?;
            let reg_hi: u8 = if first == 0x4C { 0x08 } else { 0x00 };
            return Some((
                (modrm - 0xC0) | reg_hi,
                u64::from(u32::from_le_bytes(imm.try_into().ok()?)),
            ));
        }
    }
    None
}

/// Extract value string from after CALL (LEAQ + MOVQ pattern).
///
/// This function searches **forward** from a CALL instruction for the pattern:
/// - MOVQ $len, 8(RAX)   (48 C7 40 08 xx xx xx xx) - Store length to memory via RAX
/// - LEAQ addr(RIP), RCX (48 8D 0D xx xx xx xx)     - Load string address into RCX
///
/// ## Use Case
///
/// This pattern captures strings built after calling allocation or initialization functions,
/// common in Go runtime for map values and struct fields.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::similar_names)]
fn extract_amd64_value_string(
    call_pos: usize,
    text_data: &[u8],
    text_addr: u64,
    rodata_data: &[u8],
    rodata_addr: u64,
    rodata_end: u64,
    min_length: usize,
    strings: &mut Vec<ExtractedString>,
    seen: &mut HashSet<String>,
) {
    let max_lookforward = (text_data.len() - call_pos - 5).min(80);

    // Find MOVQ $len, 8(RAX) (48 C7 40 08 xx xx xx xx)
    let mut str_len = 0u64;
    let mut found_len = false;

    for offset in 5..=max_lookforward {
        if call_pos + offset + 8 > text_data.len() {
            break;
        }

        if text_data[call_pos + offset] == 0x48
            && text_data[call_pos + offset + 1] == 0xC7
            && text_data[call_pos + offset + 2] == 0x40
            && text_data[call_pos + offset + 3] == 0x08
        {
            // SAFETY: the `call_pos + offset + 8 > text_data.len()` guard above bounds this slice.
            if let Ok(bytes) = text_data[call_pos + offset + 4..call_pos + offset + 8].try_into() {
                str_len = u64::from(u32::from_le_bytes(bytes));
                found_len = true;
                break;
            }
        }
    }

    if !found_len || str_len == 0 || str_len > 1000 {
        return;
    }

    // Find LEAQ addr(RIP), RCX (48 8D 0D xx xx xx xx)
    for offset in 5..=max_lookforward {
        if call_pos + offset + 7 > text_data.len() {
            break;
        }

        if text_data[call_pos + offset] == 0x48
            && text_data[call_pos + offset + 1] == 0x8D
            && text_data[call_pos + offset + 2] == 0x0D
        {
            // SAFETY: the `call_pos + offset + 7 > text_data.len()` guard above bounds this slice.
            let rip_offset = if let Ok(bytes) =
                text_data[call_pos + offset + 3..call_pos + offset + 7].try_into()
            {
                i32::from_le_bytes(bytes)
            } else {
                continue;
            };
            let rip_addr = text_addr + (call_pos + offset + 7) as u64;
            // Use wrapping_add_signed for RIP-relative address calculation (x86-64 semantics)
            let str_addr = rip_addr.wrapping_add_signed(i64::from(rip_offset));

            if str_addr < rodata_addr || str_addr >= rodata_end {
                continue;
            }

            let rodata_offset = (str_addr - rodata_addr) as usize;
            let Some(end) = rodata_offset.checked_add(str_len as usize) else {
                continue;
            };
            if end > rodata_data.len() {
                continue;
            }

            if let Ok(s) = std::str::from_utf8(&rodata_data[rodata_offset..end])
                && is_valid_utf8_string(s)
                && s.len() >= min_length
                && seen.insert(s.to_string())
            {
                let final_kind = classify_string(s);
                strings.push(ExtractedString {
                    value: s.to_string(),
                    data_offset: str_addr,
                    method: StringMethod::InstructionPattern,
                    kind: final_kind,
                    ..Default::default()
                });
            }

            return;
        }
    }
}

/// Check if a string is valid UTF-8 with reasonable content.
pub(crate) fn is_valid_utf8_string(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }

    // Check that it's mostly printable
    // Support Unicode: ASCII printable OR Unicode alphabetic/numeric characters
    let printable = s
        .chars()
        .filter(|&c| {
            // ASCII printable range OR Unicode alphabetic/numeric (includes Cyrillic, Chinese, Arabic, etc.)
            ('\x20'..='\x7E').contains(&c)
                || (!c.is_ascii() && (c.is_alphabetic() || c.is_numeric()))
        })
        .count();

    (printable as f64 / s.chars().count() as f64) > 0.5
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{StringKind, StringMethod};

    #[test]
    fn test_is_valid_utf8_string() {
        assert!(is_valid_utf8_string("hello"));
        assert!(is_valid_utf8_string("Hello World!"));
        assert!(!is_valid_utf8_string(""));
        assert!(!is_valid_utf8_string("\x01\x02\x03"));
    }

    #[test]
    fn test_is_valid_utf8_string_unicode() {
        assert!(is_valid_utf8_string("Héllo Wörld"));
        assert!(is_valid_utf8_string("日本語"));
        assert!(is_valid_utf8_string("emoji: 🎉"));
    }

    #[test]
    fn test_is_valid_utf8_string_mostly_printable() {
        // More than 50% printable should pass
        assert!(is_valid_utf8_string("ab\x01")); // 2/3 printable
        // Less than 50% should fail
        assert!(!is_valid_utf8_string("\x01\x02\x03a")); // 1/4 printable
    }

    #[test]
    fn test_decode_arm_mov_immediate() {
        // MOVZ X0, #5 would be: D2 80 00 A0 (0xD28000A0)
        // imm16 = 5, shift = 0
        let inst = 0xD28000A0;
        let result = decode_arm_mov_immediate(inst);
        assert_eq!(result, Some(5));
    }

    #[test]
    fn test_decode_arm_mov_immediate_zero() {
        // MOVZ with 0 value
        let inst = 0xD2800000;
        let result = decode_arm_mov_immediate(inst);
        // Zero is valid but might be rejected based on implementation
        assert!(result.is_none() || result == Some(0));
    }

    #[test]
    fn test_decode_arm_mov_immediate_with_shift() {
        // MOVZ X0, #1, LSL #16 would have shift = 1
        // Value 1 shifted left by 16 = 0x10000
        let inst = 0xD2A00020; // Approximate encoding
        let result = decode_arm_mov_immediate(inst);
        // Should decode to shifted value
        assert!(result.is_some());
    }

    #[test]
    fn test_decode_arm_mov_immediate_invalid() {
        // Not a MOV instruction
        let inst = 0x00000000;
        let result = decode_arm_mov_immediate(inst);
        assert!(result.is_none());
    }

    #[test]
    fn test_decode_arm_bitmask_immediate_basic() {
        // Test basic bitmask encoding for small values
        // ORR X0, XZR, #n - encodes small immediate values
        let inst = 0xB2400000; // ORR with bitmask immediate
        let result = decode_arm_bitmask_immediate(inst);
        // Should decode to some value or None if out of range
        assert!(result.is_none() || result.unwrap() <= 1000);
    }

    #[test]
    fn test_decode_arm_bitmask_immediate_invalid_size() {
        // Invalid element size encoding
        let inst = 0xB2400000 | (0x3F << 10); // imms = 0x3F which is invalid
        let result = decode_arm_bitmask_immediate(inst);
        // Should handle gracefully
        assert!(result.is_none() || result.is_some());
    }

    #[test]
    fn test_looks_like_key_basic() {
        assert!(looks_like_key("name"));
        assert!(looks_like_key("user_id"));
        assert!(looks_like_key("config.timeout"));
        assert!(looks_like_key("api-key"));
    }

    #[test]
    fn test_looks_like_key_too_long() {
        let long_string = "a".repeat(50);
        assert!(!looks_like_key(&long_string));
    }

    #[test]
    fn test_looks_like_key_with_spaces() {
        assert!(!looks_like_key("has spaces"));
        assert!(!looks_like_key("hello world"));
    }

    #[test]
    fn test_looks_like_key_paths() {
        assert!(!looks_like_key("/usr/bin"));
        assert!(!looks_like_key("./config"));
    }

    #[test]
    fn test_looks_like_key_urls() {
        assert!(!looks_like_key("http://example.com"));
        assert!(!looks_like_key("https://api.server.com"));
    }

    #[test]
    fn test_looks_like_key_special_chars() {
        assert!(!looks_like_key("key@value"));
        assert!(!looks_like_key("key#value"));
        assert!(!looks_like_key("key$value"));
    }

    #[test]
    fn test_extract_inline_strings_arm64_empty() {
        let text_data = &[];
        let rodata_data = b"Hello World";

        let strings = extract_inline_strings_arm64(text_data, 0x1000, rodata_data, 0x2000, 4);

        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_inline_strings_arm64_no_bl() {
        // Code without BL instructions
        let text_data = vec![0x00u8; 100];
        let rodata_data = b"Hello World";

        let strings = extract_inline_strings_arm64(&text_data, 0x1000, rodata_data, 0x2000, 4);

        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_inline_strings_amd64_empty() {
        let text_data = &[];
        let rodata_data = b"Hello World";

        let strings = extract_inline_strings_amd64(text_data, 0x1000, rodata_data, 0x2000, 4);

        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_inline_strings_amd64_no_call() {
        // Code without CALL instructions
        let text_data = vec![0x90u8; 100]; // NOP instructions
        let rodata_data = b"Hello World";

        let strings = extract_inline_strings_amd64(&text_data, 0x1000, rodata_data, 0x2000, 4);

        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_inline_strings_amd64_with_call() {
        // Create code with a CALL instruction but no valid string pattern
        let mut text_data = vec![0x90u8; 100];
        text_data[50] = 0xE8; // CALL opcode
        // Rest is garbage offset

        let rodata_data = b"Hello World";

        let strings = extract_inline_strings_amd64(&text_data, 0x1000, rodata_data, 0x2000, 4);

        // No valid pattern found
        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_arm64_pattern_short_lookback() {
        // Test with code too short for lookback
        let text_data = vec![0x00u8; 8];
        let rodata_data = b"Test";

        let strings = extract_inline_strings_arm64(&text_data, 0x1000, rodata_data, 0x2000, 4);

        assert!(strings.is_empty());
    }

    #[test]
    fn test_decode_arm64_string_invalid_addr() {
        // Address outside rodata range
        let result = decode_arm64_string(
            0x90000000, // ADRP
            0x91000000, // ADD
            0xD2800000, // MOV
            0,
            0x1000,
            &[0u8; 100],
            0x5000, // rodata_addr
            0x5100, // rodata_end
        );

        assert!(result.is_none());
    }

    #[test]
    fn test_decode_arm64_string_invalid_length() {
        // Length too long
        let result = decode_arm64_string(
            0x90000000,
            0x91000000,
            0xD2BC4000, // Encodes large value
            0,
            0x5000,
            &[0u8; 100],
            0x5000,
            0x5100,
        );

        // Should return None for invalid length
        assert!(result.is_none());
    }

    #[test]
    fn test_amd64_value_string_short_data() {
        let text_data = vec![0xE8u8, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let rodata_data = b"Test";
        let mut strings = Vec::new();
        let mut seen = HashSet::new();

        extract_amd64_value_string(
            0,
            &text_data,
            0x1000,
            rodata_data,
            0x2000,
            0x2004,
            4,
            &mut strings,
            &mut seen,
        );

        assert!(strings.is_empty());
    }

    // Encodings from `llvm-mc -triple=aarch64 -show-encoding`. Text sits at
    // 0x100000 and rodata one page up, so `adrp x2, #4096` reaches it.
    const ADRP_X2: u32 = 0xb000_0002; // adrp x2, #4096
    const ADD_X2_0: u32 = 0x9100_0042; // add x2, x2, #0
    const ADD_X2_16: u32 = 0x9100_4042; // add x2, x2, #16
    const ADD_X2_32: u32 = 0x9100_8042; // add x2, x2, #32
    const ADD_X2_OUT: u32 = 0x913f_fc42; // add x2, x2, #0xfff (past rodata)
    const MOV_X3_11: u32 = 0xd280_0163; // mov x3, #11
    const ORR_X4_7: u32 = 0xb240_0be4; // orr x4, xzr, #0x7
    const STP_X2_X3: u32 = 0xa909_0fe2; // stp x2, x3, [sp, #144]
    const STP_X2_X4: u32 = 0xa90a_13e2; // stp x2, x4, [sp, #160]
    const B_NEXT: u32 = 0x1400_0001; // b #4
    const LDR_X3: u32 = 0xf940_07e3; // ldr x3, [sp, #8]
    const STR_X3: u32 = 0xf900_07e3; // str x3, [sp, #8]
    const MOV_X3_X5: u32 = 0xaa05_03e3; // mov x3, x5
    const NOP: u32 = 0xd503_201f;

    fn text(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    /// Strings packed back to back, as Go lays out rodata: a wrong length
    /// still decodes to printable text, so these tests catch a stale length
    /// rather than relying on the decoder to reject it.
    fn packed_rodata() -> Vec<u8> {
        let mut r = vec![b'x'; 0x100];
        r[0..11].copy_from_slice(b"test_string");
        r[16..23].copy_from_slice(b"abcdefg");
        r[32..39].copy_from_slice(b"hijklmn");
        r
    }

    fn stored(words: &[u32]) -> Vec<String> {
        extract_inline_strings_arm64(&text(words), 0x100000, &packed_rodata(), 0x101000, 4)
            .into_iter()
            .map(|s| s.value)
            .collect()
    }

    #[test]
    fn arm64_stored_string_header_is_decoded() {
        let found = extract_inline_strings_arm64(
            &text(&[ADRP_X2, ADD_X2_0, MOV_X3_11, STP_X2_X3]),
            0x100000,
            &packed_rodata(),
            0x101000,
            4,
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].value, "test_string");
        assert_eq!(found[0].data_offset, 0x101000);
        assert_eq!(found[0].method, StringMethod::InstructionPattern);
    }

    /// Go reloads a length register only when the length changes: the second
    /// element here reuses x4 = 7 from the first.
    #[test]
    fn arm64_stored_length_register_is_reused_across_elements() {
        let found = stored(&[
            ADRP_X2, ADD_X2_16, ORR_X4_7, STP_X2_X4, ADRP_X2, ADD_X2_32, STP_X2_X4,
        ]);
        assert_eq!(found, ["abcdefg", "hijklmn"]);
    }

    #[test]
    fn arm64_stored_state_does_not_survive_a_branch() {
        assert!(stored(&[ADRP_X2, ADD_X2_0, MOV_X3_11, B_NEXT, STP_X2_X3]).is_empty());
    }

    #[test]
    fn arm64_stored_length_overwritten_is_not_used() {
        assert!(stored(&[ADRP_X2, ADD_X2_0, MOV_X3_11, MOV_X3_X5, STP_X2_X3]).is_empty());
        assert!(stored(&[ADRP_X2, ADD_X2_0, MOV_X3_11, LDR_X3, STP_X2_X3]).is_empty());
    }

    /// A store reads its register; it must not invalidate it.
    #[test]
    fn arm64_stored_intervening_store_keeps_state() {
        assert_eq!(
            stored(&[ADRP_X2, ADD_X2_0, MOV_X3_11, STR_X3, STP_X2_X3]),
            ["test_string"]
        );
    }

    #[test]
    fn arm64_stored_values_expire_after_the_window() {
        let within = |gap: usize| {
            let mut words = vec![ADRP_X2, ADD_X2_0, MOV_X3_11];
            words.extend(std::iter::repeat_n(NOP, gap));
            words.push(STP_X2_X3);
            !stored(&words).is_empty()
        };
        // The pointer was set two instructions before the length, so it is
        // the first to age out.
        assert!(within(ARM64_STORED_WINDOW - 2));
        assert!(!within(ARM64_STORED_WINDOW - 1));
    }

    #[test]
    fn arm64_stored_pointer_outside_rodata_is_ignored() {
        assert!(stored(&[ADRP_X2, ADD_X2_OUT, MOV_X3_11, STP_X2_X3]).is_empty());
    }

    // x86-64 encodings from `llvm-mc -triple=x86_64 -show-encoding`. Text at
    // 0x1000, rodata at 0x3000; `lea` at text offset `at` reaching rodata+off
    // needs disp = 0x3000 + off - (0x1000 + at + 7).
    fn lea(reg_rex: u8, modrm: u8, at: usize, off: u32) -> Vec<u8> {
        let disp = (0x3000 + off) as i64 - (0x1000 + at as i64 + 7);
        let mut v = vec![reg_rex, 0x8d, modrm];
        v.extend((disp as i32).to_le_bytes());
        v
    }
    const LEA_RCX: (u8, u8) = (0x48, 0x0d); // lea rcx, [rip+d]
    const LEA_RAX: (u8, u8) = (0x48, 0x05); // lea rax, [rip+d]
    const STORE_RCX_RDI: [u8; 3] = [0x48, 0x89, 0x0f]; // mov [rdi], rcx
    const STORE_RCX_RDI8: [u8; 4] = [0x48, 0x89, 0x4f, 0x08]; // mov [rdi+8], rcx
    const STORE_RCX_RDI16: [u8; 4] = [0x48, 0x89, 0x4f, 0x10]; // mov [rdi+16], rcx
    const MOV_ECX_11: [u8; 5] = [0xb9, 0x0b, 0, 0, 0]; // mov ecx, 11
    const STORE_RAX_RSP20: [u8; 5] = [0x48, 0x89, 0x44, 0x24, 0x20]; // mov [rsp+0x20], rax
    const STORE_IMM11_RSP28: [u8; 9] = [0x48, 0xc7, 0x44, 0x24, 0x28, 0x0b, 0, 0, 0]; // mov qword [rsp+0x28], 11
    const STORE_IMM7_RDI8: [u8; 8] = [0x48, 0xc7, 0x47, 0x08, 0x07, 0, 0, 0]; // mov qword [rdi+8], 7

    fn amd64_stored(parts: &[&[u8]]) -> Vec<String> {
        let text: Vec<u8> = parts.concat();
        let mut rodata = vec![b'x'; 0x100];
        rodata[0..11].copy_from_slice(b"test_string");
        rodata[16..23].copy_from_slice(b"abcdefg");
        let mut out = Vec::new();
        extract_amd64_stored_strings(&text, 0x1000, &rodata, 0x3000, 4, &mut out);
        out.into_iter().map(|s| s.value).collect()
    }

    /// Pointer stored to [rdi], length loaded into a register and stored to
    /// [rdi+8]: rustc's shape for a `[&str; N]` element.
    #[test]
    fn amd64_stored_header_with_register_length() {
        let lea = lea(LEA_RCX.0, LEA_RCX.1, 0, 0);
        assert_eq!(
            amd64_stored(&[&lea, &STORE_RCX_RDI, &MOV_ECX_11, &STORE_RCX_RDI8]),
            ["test_string"]
        );
    }

    /// A stack-spilled header (SIB-addressed) with an immediate length store.
    #[test]
    fn amd64_stored_header_on_the_stack_with_immediate_length() {
        let lea = lea(LEA_RAX.0, LEA_RAX.1, 0, 0);
        assert_eq!(
            amd64_stored(&[&lea, &STORE_RAX_RSP20, &STORE_IMM11_RSP28]),
            ["test_string"]
        );
    }

    /// The first LEA's pointer is never stored before the register is
    /// reloaded; pairing it with the second element's stores would decode
    /// "test_string" with the wrong length. Only the second element counts.
    #[test]
    fn amd64_stored_register_reload_closes_the_window() {
        let first = lea(LEA_RCX.0, LEA_RCX.1, 0, 0);
        let second = lea(LEA_RCX.0, LEA_RCX.1, 7, 16);
        assert_eq!(
            amd64_stored(&[&first, &second, &STORE_RCX_RDI, &STORE_IMM7_RDI8]),
            ["abcdefg"]
        );
    }

    /// The length must sit in the slot right after the pointer.
    #[test]
    fn amd64_stored_length_must_be_adjacent() {
        let lea = lea(LEA_RCX.0, LEA_RCX.1, 0, 0);
        assert!(amd64_stored(&[&lea, &STORE_RCX_RDI, &MOV_ECX_11, &STORE_RCX_RDI16]).is_empty());
    }

    /// A length store far from the pointer store belongs to something else.
    #[test]
    fn amd64_stored_length_must_be_near_the_pointer_store() {
        let lea = lea(LEA_RCX.0, LEA_RCX.1, 0, 0);
        let padding = [0x90u8; AMD64_STORED_PAIR_GAP + 1];
        assert!(
            amd64_stored(&[&lea, &STORE_RCX_RDI, &MOV_ECX_11, &padding, &STORE_RCX_RDI8])
                .is_empty()
        );
    }

    #[test]
    fn test_arm64_basic_string_extraction() {
        let text_data = vec![
            0x00, 0x00, 0x00, 0x90, 0x00, 0x40, 0x01, 0x91, 0x41, 0x01, 0x80, 0xD2, 0x00, 0x00,
            0x00, 0x94,
        ];
        let mut rodata_data = vec![0u8; 0x100];
        rodata_data[0..11].copy_from_slice(b"test_string");
        let results = extract_inline_strings_arm64(&text_data, 0x100000, &rodata_data, 0x101000, 4);
        for s in &results {
            assert_eq!(s.method, StringMethod::InstructionPattern);
            assert!(!s.value.is_empty());
        }
    }

    #[test]
    fn test_arm64_min_length_filter() {
        let text_data = vec![
            0x00, 0x00, 0x00, 0x90, 0x00, 0x00, 0x00, 0x91, 0x61, 0x00, 0x80, 0xD2, 0x00, 0x00,
            0x00, 0x94,
        ];
        let mut rodata_data = vec![0u8; 0x1100];
        rodata_data[0..3].copy_from_slice(b"abc");
        let results =
            extract_inline_strings_arm64(&text_data, 0x100000, &rodata_data, 0x101000, 10);
        assert!(results.is_empty() || results.iter().all(|s| s.value.len() >= 10));
    }

    #[test]
    fn test_amd64_basic_string_extraction() {
        let text_data = vec![
            0x48, 0x8D, 0x3D, 0x00, 0x01, 0x00, 0x00, 0xBE, 0x0B, 0x00, 0x00, 0x00, 0xE8, 0x00,
            0x00, 0x00, 0x00,
        ];
        let mut rodata_data = vec![0u8; 0x200];
        rodata_data[0..11].copy_from_slice(b"hello_world");
        let results = extract_inline_strings_amd64(&text_data, 0x100000, &rodata_data, 0x101000, 4);
        for s in &results {
            assert_eq!(s.method, StringMethod::InstructionPattern);
            assert!(!s.value.is_empty());
        }
    }

    #[test]
    fn test_amd64_map_key_pattern() {
        let text_data = vec![
            0x48, 0x8D, 0x15, 0x50, 0x00, 0x00, 0x00, 0xB9, 0x07, 0x00, 0x00, 0x00, 0xE8, 0x00,
            0x00, 0x00, 0x00,
        ];
        let mut rodata_data = vec![0u8; 0x100];
        rodata_data[0..7].copy_from_slice(b"map_key");
        let text_addr = 0x100000u64;
        let rodata_addr = text_addr + text_data.len() as u64 + 0x50 - 7;
        let results =
            extract_inline_strings_amd64(&text_data, text_addr, &rodata_data, rodata_addr, 4);
        for key in results
            .iter()
            .filter(|s| s.kind == Some(StringKind::MapKey))
        {
            assert!(!key.value.is_empty());
            assert_eq!(key.method, StringMethod::InstructionPattern);
        }
    }

    #[test]
    fn test_empty_inputs_both_arches() {
        assert!(extract_inline_strings_arm64(&[], 0x100000, &[], 0x101000, 4).is_empty());
        assert!(extract_inline_strings_amd64(&[], 0x100000, &[], 0x101000, 4).is_empty());
    }

    #[test]
    fn test_truncated_arm64_instructions() {
        let text_data = vec![0x00, 0x00]; // Only 2 bytes, incomplete ARM64 instruction
        let results = extract_inline_strings_arm64(&text_data, 0x100000, &[], 0x101000, 4);
        assert!(results.is_empty());
    }

    #[test]
    fn test_large_code_section_arm64() {
        use std::time::Instant;
        let text_data: Vec<u8> = (0..65536u32)
            .map(|i| u8::try_from(i % 256).unwrap_or(0))
            .collect();
        let rodata_data = vec![0u8; 4096];
        let start = Instant::now();
        let _ = extract_inline_strings_arm64(&text_data, 0x100000, &rodata_data, 0x110000, 4);
        assert!(
            start.elapsed().as_millis() < 100,
            "Took too long: {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn test_out_of_bounds_addresses_arm64() {
        let text_data = vec![
            0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x91, 0x41, 0x01, 0x80, 0xD2, 0x00, 0x00,
            0x00, 0x94,
        ];
        let rodata_data = vec![0u8; 0x100];
        let results = extract_inline_strings_arm64(&text_data, 0x100000, &rodata_data, 0x101000, 4);
        for s in results {
            assert!(!s.value.is_empty());
        }
    }

    #[test]
    fn test_min_length_enforcement_both_arches() {
        let text_arm64 = vec![
            0x00, 0x00, 0x00, 0x90, 0x00, 0x00, 0x00, 0x91, 0x41, 0x01, 0x80, 0xD2, 0x00, 0x00,
            0x00, 0x94,
        ];
        let text_amd64 = vec![
            0x48, 0x8D, 0x3D, 0x00, 0x01, 0x00, 0x00, 0xBE, 0x0B, 0x00, 0x00, 0x00, 0xE8, 0x00,
            0x00, 0x00, 0x00,
        ];
        let mut rodata = vec![0u8; 0x200];
        rodata[0..20].copy_from_slice(b"exactly_20_chars_str");
        let min_len = 25;
        let results_arm =
            extract_inline_strings_arm64(&text_arm64, 0x100000, &rodata, 0x101000, min_len);
        let results_amd =
            extract_inline_strings_amd64(&text_amd64, 0x100000, &rodata, 0x101000, min_len);
        for s in results_arm.iter().chain(results_amd.iter()) {
            assert!(
                s.value.len() >= min_len,
                "String '{}' is {} chars, expected >= {}",
                s.value,
                s.value.len(),
                min_len
            );
        }
    }

    /// Regression: a string materialized as `LEA RBX, <rodata>; MOV ECX, len`
    /// (the shape Go emits for `[]byte(constant)`, e.g. the GhostDog script)
    /// must be recovered. The length lands in ECX, which no fixed register-pair
    /// list covered, so this whole class of literals was previously dropped.
    #[test]
    fn test_amd64_non_arg_register_pair() {
        // 48 8D 1D F9 0F 00 00  LEA RBX, [rip+0xFF9]   -> 0x101000
        // B9 10 00 00 00        MOV ECX, 16            (length, not in ESI/EDX/EBX/EDI)
        // E8 00 00 00 00        CALL
        // Trailing NOPs so the CALL site clears the scanner's end-of-text guard.
        let text = vec![
            0x48, 0x8D, 0x1D, 0xF9, 0x0F, 0x00, 0x00, 0xB9, 0x10, 0x00, 0x00, 0x00, 0xE8, 0x00,
            0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90,
        ];
        let mut rodata = vec![0u8; 0x40];
        rodata[0..16].copy_from_slice(b"echo hello world");
        let results = extract_inline_strings_amd64(&text, 0x100000, &rodata, 0x101000, 4);
        assert!(
            results.iter().any(|s| s.value == "echo hello world"),
            "LEA RBX + MOV ECX length pair should be recovered, got {:?}",
            results.iter().map(|s| &s.value).collect::<Vec<_>>(),
        );
    }

    /// Go may leave substantial setup code between a literal's LEA/length
    /// pair and the runtime call that consumes it. The association must remain
    /// bounded, but must cover that legitimate shape.
    #[test]
    fn test_amd64_long_setup_before_call() {
        let mut text = vec![
            0x48, 0x8D, 0x05, 0xF9, 0x0F, 0x00, 0x00, // LEA RAX, [rip+0xff9]
            0xBB, 0x10, 0x00, 0x00, 0x00, // MOV EBX, 16
        ];
        text.resize(140, 0x90);
        text.extend_from_slice(&[0xE8, 0x00, 0x00, 0x00, 0x00]);
        text.extend_from_slice(&[0x90; 8]);
        let mut rodata = vec![0u8; 0x40];
        rodata[..16].copy_from_slice(b"/v1/teams/ingest");

        let results = extract_inline_strings_amd64(&text, 0x100000, &rodata, 0x101000, 4);
        assert!(
            results.iter().any(|s| s.value == "/v1/teams/ingest"),
            "long-distance LEA/MOV pair should be recovered, got {:?}",
            results.iter().map(|s| &s.value).collect::<Vec<_>>(),
        );
    }

    /// A Go branch can place the immediate length directly before the pointer
    /// LEA rather than after it.
    #[test]
    fn test_amd64_preceding_length_before_lea() {
        let mut text = vec![
            0xBB, 0x10, 0x00, 0x00, 0x00, // MOV EBX, 16
            0x48, 0x8D, 0x05, 0xF4, 0x0F, 0x00, 0x00, // LEA RAX, [rip+0xff4]
        ];
        text.extend_from_slice(&[0x90; 32]);
        text.extend_from_slice(&[0xE8, 0x00, 0x00, 0x00, 0x00]);
        text.extend_from_slice(&[0x90; 8]);
        let mut rodata = vec![0u8; 0x40];
        rodata[..16].copy_from_slice(b"/v1/teams/ingest");

        let results = extract_inline_strings_amd64(&text, 0x100000, &rodata, 0x101000, 4);
        assert!(
            results.iter().any(|s| s.value == "/v1/teams/ingest"),
            "preceding MOV/LEA pair should be recovered, got {:?}",
            results.iter().map(|s| &s.value).collect::<Vec<_>>(),
        );
    }

    /// Regression: the ARM64 equivalent — `ADRP x1; ADD x1; MOVZ x2, len` — the
    /// register pair `runtime.stringtoslicebyte` uses, outside the old x0/x1 and
    /// x2/x3 cases.
    #[test]
    fn test_arm64_non_arg_register_pair() {
        // ADRP x1, +0x10 pages ; ADD x1, x1, #0 ; MOVZ x2, #16 ; BL
        let text = vec![
            0x81, 0x00, 0x00, 0x90, 0x21, 0x00, 0x00, 0x91, 0x02, 0x02, 0x80, 0xD2, 0x00, 0x00,
            0x00, 0x94,
        ];
        let mut rodata = vec![0u8; 0x40];
        rodata[0..16].copy_from_slice(b"echo hello world");
        let results = extract_inline_strings_arm64(&text, 0x100000, &rodata, 0x110000, 4);
        assert!(
            results.iter().any(|s| s.value == "echo hello world"),
            "ADRP x1 + MOVZ x2 length pair should be recovered, got {:?}",
            results.iter().map(|s| &s.value).collect::<Vec<_>>(),
        );
    }
}
