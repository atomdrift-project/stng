//! x86-64 strings addressed by RIP-relative LEA with an immediate length:
//! passed in registers or pushed, stored as `{ptr, len}` pairs, or found by
//! scanning back from a length load.

use super::{Scan, decode_rodata_string, is_valid_utf8_string, looks_like_key};
use crate::classifier::classify_string;
use crate::types::{ExtractedString, StringKind, StringMethod};
use std::collections::HashSet;

/// Extracts inline strings from AMD64 executable code.
///
/// Scans for CALL instructions and looks for LEAQ addr(RIP) patterns
/// (string address) and MOVL/MOVQ or adjacent PUSH/POP patterns (string length).
pub(super) fn extract_inline_strings_amd64(
    text_data: &[u8],
    text_addr: u64,
    rodata_data: &[u8],
    rodata_addr: u64,
    min_length: usize,
) -> Vec<ExtractedString> {
    use rayon::prelude::*;

    let scan = Scan::new(text_data, text_addr, rodata_data, rodata_addr, min_length);

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
        .with_min_len(crate::par::MIN_ITEMS_PER_JOB)
        .flat_map_iter(|&i| {
            let mut strings = Vec::new();
            let mut seen = HashSet::new();

            // Consolidated backward scan for all register and stack patterns
            extract_backward_strings(i, &scan, &mut strings, &mut seen);

            // Extract value strings after CALL (forward-scanning, kept separate)
            extract_amd64_value_string(i, &scan, &mut strings, &mut seen);

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
pub(super) const AMD64_STORED_AHEAD: usize = 48;

/// Bytes before the `LEA` searched for a length register load that preceded
/// it (a length shared across equal-length elements is loaded once).
pub(super) const AMD64_STORED_BEHIND: usize = 32;

/// Furthest a header's length store may sit from its pointer store.
pub(super) const AMD64_STORED_PAIR_GAP: usize = 16;

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
pub(super) fn extract_amd64_stored_strings(
    text: &[u8],
    text_addr: u64,
    rodata: &[u8],
    rodata_addr: u64,
    min_length: usize,
    strings: &mut Vec<ExtractedString>,
) {
    let rodata_end = rodata_addr.saturating_add(rodata.len() as u64);
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
        let Some(target) = text_addr
            .checked_add(end as u64)
            .and_then(|next| next.checked_add_signed(i64::from(disp)))
        else {
            continue;
        };
        if !(rodata_addr..rodata_end).contains(&target) {
            continue;
        }

        // The window closes where the pointer register is next loaded by
        // another rip-relative LEA: past that, a store of the register writes
        // a different string's pointer. Compilers reuse the same scratch
        // register for consecutive table elements, and pairing across that
        // reload was the main source of wrong-length strings.
        let mut limit = text.len().min(end + AMD64_STORED_AHEAD);
        // Stop at the next `LEA r64, [rip+disp32]` into the same register.
        if let Some(next) = (end..limit).find(|&j| {
            let Some(&[rex, op, modrm]) = text.get(j..j + 3) else {
                return false;
            };
            let dest = ((modrm >> 3) & 7) | ((rex >> 2) & 1) << 3;
            rex & 0xFB == 0x48 && op == 0x8D && modrm & 0xC7 == 0x05 && dest == ptr_reg
        }) {
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

pub(super) fn read_i32(b: &[u8], at: usize) -> Option<i32> {
    Some(i32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// A memory operand `[base + disp]` from the ModRM at `at` (REX.B in `rex`):
/// base register, displacement and the operand's encoded length. RIP-relative,
/// indexed and absolute forms are rejected -- a header store is always
/// base-plus-displacement.
pub(super) fn mem_operand(b: &[u8], at: usize, rex: u8) -> Option<(u8, i64, usize)> {
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
            let d = i64::from(b.get(at + len)?.cast_signed());
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
pub(super) fn store_reg(b: &[u8], at: usize) -> Option<(u8, u8, i64)> {
    let rex = *b.get(at)?;
    if rex & 0xF8 != 0x48 || *b.get(at + 1)? != 0x89 {
        return None;
    }
    let src = ((*b.get(at + 2)? >> 3) & 7) | ((rex >> 2) & 1) << 3;
    let (base, disp, _) = mem_operand(b, at + 2, rex)?;
    Some((src, base, disp))
}

/// `MOV QWORD [base+disp], imm32` (REX.W C7 /0): base, displacement, value.
pub(super) fn store_imm(b: &[u8], at: usize) -> Option<(u8, i64, u32)> {
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
pub(super) fn mov_imm(b: &[u8], at: usize) -> Option<(u8, u32)> {
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
pub(super) fn extract_backward_strings(
    call_pos: usize,
    scan: &Scan<'_>,
    strings: &mut Vec<ExtractedString>,
    seen: &mut HashSet<String>,
) {
    let Scan {
        text: text_data,
        text_addr,
        rodata_addr,
        rodata_end,
        ..
    } = *scan;
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
        let str_addr = text_addr
            .wrapping_add((pos + 7) as u64)
            .wrapping_add_signed(i64::from(offset));

        if str_addr >= rodata_addr && str_addr < rodata_end {
            // LEA destination (reg field + REX.R): a length MOV into this same
            // register would clobber the pointer, so it is never the length.
            let lea_dest = ((modrm >> 3) & 0x07) | ((rex & 0x04) << 1);
            if let Some((value, len_reg)) =
                find_inline_length_string(pos, call_pos, scan, str_addr, lea_dest)
                && seen.insert(value.clone())
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
pub(super) fn find_inline_length_string(
    lea_pos: usize,
    call_pos: usize,
    scan: &Scan<'_>,
    str_addr: u64,
    lea_dest: u8,
) -> Option<(String, Option<u8>)> {
    let Scan {
        text: text_data,
        rodata: rodata_data,
        rodata_addr,
        rodata_end,
        min_length,
        ..
    } = *scan;
    let validate = |len: u64| -> Option<String> {
        if len == 0 || len > 1000 || str_addr.checked_add(len)? > rodata_end {
            return None;
        }
        let start = str_addr.checked_sub(rodata_addr)? as usize;
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

    // Size-optimized Rust uses PUSH imm8; POP reg for small lengths. Permit
    // one intervening stack-address LEA for the call's output slot, but require
    // the length load to end at this CALL: no byte-window search or stale pair.
    if let Some((reg, len)) = decode_call_push_length(text_data, lea_pos + 7, call_pos, lea_dest)
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

/// Adjacent positive PUSH imm8 / POP r64 immediately before a CALL, optionally
/// preceded by a stack-address LEA into a third register. All operands must fit
/// before the CALL and neither setup instruction may overwrite the pointer.
pub(super) fn decode_call_push_length(
    b: &[u8],
    mut p: usize,
    call: usize,
    ptr: u8,
) -> Option<(u8, u64)> {
    let b = b.get(..call)?;
    let mut output_reg = None;
    if *b.get(p)? & 0xFB == 0x48 && *b.get(p + 1)? == 0x8D {
        let rex = b[p];
        let dest = ((b.get(p + 2)? >> 3) & 7) | ((rex >> 2) & 1) << 3;
        let (base, _, width) = mem_operand(b, p + 2, rex)?;
        if !matches!(base, 4 | 5) || dest == ptr || dest == 4 {
            return None;
        }
        output_reg = Some(dest);
        p += 2 + width;
    }
    if *b.get(p)? != 0x6A {
        return None;
    }
    // PUSH sign extends imm8; negative values are not string lengths.
    let len = *b.get(p + 1)?;
    if len == 0 || len > 127 {
        return None;
    }
    p += 2;
    let high = u8::from(*b.get(p)? == 0x41) << 3;
    p += usize::from(high != 0);
    let pop = *b.get(p)?;
    if !(0x58..=0x5F).contains(&pop) || p + 1 != call {
        return None;
    }
    let reg = (pop - 0x58) | high;
    (reg != ptr && reg != 4 && output_reg != Some(reg)).then_some((reg, u64::from(len)))
}

/// Decode a `MOV` of a 32-bit immediate into a general register at `p`.
///
/// Handles `MOV r32, imm32` (`B8+r id`, optionally `41`-prefixed for r8d–r15d)
/// and `MOV r64, imm32` (`(48|4C) C7 C0+r id`). Returns `(register, immediate)`.
pub(super) fn decode_mov_imm32(text_data: &[u8], p: usize) -> Option<(u8, u64)> {
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
    // MOV r64, imm32 (sign-extended): REX.W C7 /0 with ModRM.mod = 11. The
    // destination is ModRM.rm, so REX.B (bit 0) selects r8–r15.
    if first & 0xF8 == 0x48 && *text_data.get(p + 1)? == 0xC7 {
        let modrm = *text_data.get(p + 2)?;
        if (0xC0..=0xC7).contains(&modrm) {
            let imm = text_data.get(p + 3..p + 7)?;
            return Some((
                (modrm - 0xC0) | (first & 1) << 3,
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
#[allow(clippy::similar_names)]
pub(super) fn extract_amd64_value_string(
    call_pos: usize,
    scan: &Scan<'_>,
    strings: &mut Vec<ExtractedString>,
    seen: &mut HashSet<String>,
) {
    let Scan {
        text: text_data,
        text_addr,
        rodata: rodata_data,
        rodata_addr,
        rodata_end,
        min_length,
    } = *scan;
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
            let rip_addr = text_addr.wrapping_add((call_pos + offset + 7) as u64);
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

#[cfg(test)]
mod mov_imm32_tests;

#[cfg(test)]
mod push_length_tests;
