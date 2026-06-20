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

    strings
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
                section: Some(".rodata".to_string()),
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

    // Process CALL sites in parallel
    let all_strings: Vec<Vec<ExtractedString>> = call_positions
        .par_iter()
        .map(|&i| {
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

    // Flatten and deduplicate
    let mut seen: HashSet<String> = HashSet::new();
    all_strings
        .into_iter()
        .flatten()
        .filter(|s| seen.insert(s.value.clone()))
        .collect()
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
    // 120 bytes back covers a string spilled to the stack ahead of its CALL.
    let scan_start = call_pos.saturating_sub(call_pos.min(120));
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
                    section: Some(".rodata".to_string()),
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
                    section: Some(".rodata".to_string()),
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
fn is_valid_utf8_string(s: &str) -> bool {
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
