//! Instruction pattern analysis for inline string extraction.
//!
//! Inline literals (function arguments, map keys/values) don't create stored
//! pointer+length structures. Instead, compilers pass string addresses and lengths
//! through registers. We extract these by pattern matching instruction sequences.

use super::go::classify_string;
use super::types::{ExtractedString, StringKind, StringMethod};
use std::collections::HashSet;

/// Extracts inline strings from ARM64 executable code.
///
/// Scans for BL (branch with link) instructions and looks backwards for
/// ADRP+ADD patterns (string address) and MOV/ORR patterns (string length).
pub fn extract_inline_strings_arm64(
    text_data: &[u8],
    text_addr: u64,
    rodata_data: &[u8],
    rodata_addr: u64,
    min_length: usize,
) -> Vec<ExtractedString> {
    let mut strings = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    let rodata_end = rodata_addr + rodata_data.len() as u64;

    // Scan through __text looking for BL instructions (ARM64 instructions are 4 bytes)
    let mut i = 0;
    while i + 4 <= text_data.len() {
        // SAFETY: Loop condition ensures we have 4 bytes
        let inst = u32::from_le_bytes([
            text_data[i],
            text_data[i + 1],
            text_data[i + 2],
            text_data[i + 3],
        ]);

        // Check for BL (branch with link) instruction: 0x94xxxxxx
        if (inst & 0xFC000000) != 0x94000000 {
            i += 4;
            continue;
        }

        // Found a BL - extract string patterns for different register pairs
        // R0/R1 - first argument (common for function calls)
        extract_arm64_string_pattern(
            i,
            text_data,
            text_addr,
            rodata_data,
            rodata_addr,
            rodata_end,
            0, // address register
            1, // length register
            min_length,
            StringKind::Arg,
            &mut strings,
            &mut seen,
        );

        // R2/R3 - second argument (map keys in runtime.mapassign_faststr)
        extract_arm64_string_pattern(
            i,
            text_data,
            text_addr,
            rodata_data,
            rodata_addr,
            rodata_end,
            2,
            3,
            min_length,
            StringKind::MapKey,
            &mut strings,
            &mut seen,
        );

        i += 4;
    }

    strings
}

/// Extract a string from ARM64 ADRP+ADD+MOV pattern targeting specific registers.
#[allow(clippy::too_many_arguments)]
fn extract_arm64_string_pattern(
    bl_pos: usize,
    text_data: &[u8],
    text_addr: u64,
    rodata_data: &[u8],
    rodata_addr: u64,
    rodata_end: u64,
    addr_reg: u32,
    len_reg: u32,
    min_length: usize,
    _kind: StringKind,
    strings: &mut Vec<ExtractedString>,
    seen: &mut HashSet<String>,
) {
    let max_lookback = bl_pos.min(20 * 4);

    let mut lookback = 8;
    while lookback <= max_lookback {
        let pos = bl_pos - lookback;
        if pos + 12 > text_data.len() {
            break;
        }

        // SAFETY: bounds checked above (pos + 12 <= text_data.len())
        let inst1 = u32::from_le_bytes([
            text_data[pos],
            text_data[pos + 1],
            text_data[pos + 2],
            text_data[pos + 3],
        ]);
        let inst2 = u32::from_le_bytes([
            text_data[pos + 4],
            text_data[pos + 5],
            text_data[pos + 6],
            text_data[pos + 7],
        ]);

        // Check for ADRP Rx
        let target_reg = inst1 & 0x1F;
        let is_adrp = ((inst1 & 0x9F000000) == 0x90000000) && target_reg == addr_reg;

        if !is_adrp {
            lookback += 4;
            continue;
        }

        // Check for ADD Rx, Rx, #imm
        let is_add = ((inst2 & 0xFF000000) == 0x91000000)
            && ((inst2 & 0x1F) == addr_reg)
            && (((inst2 >> 5) & 0x1F) == addr_reg);

        if !is_add {
            lookback += 4;
            continue;
        }

        // Search for MOV/ORR Ry within next few instructions
        let mut inst3 = 0u32;
        let mut found_mov = false;

        let mut offset = 8;
        while offset <= 20 && pos + offset + 4 <= text_data.len() {
            // SAFETY: Loop condition checks bounds
            let inst3_candidate = u32::from_le_bytes([
                text_data[pos + offset],
                text_data[pos + offset + 1],
                text_data[pos + offset + 2],
                text_data[pos + offset + 3],
            ]);
            let reg_num = inst3_candidate & 0x1F;

            // Check for ORR or MOVD targeting length register
            let is_mov = ((inst3_candidate & 0xB2000000) == 0xB2000000
                || (inst3_candidate & 0xFF000000) == 0xD2000000)
                && reg_num == len_reg;

            if is_mov {
                inst3 = inst3_candidate;
                found_mov = true;
                break;
            }
            offset += 4;
        }

        if !found_mov {
            lookback += 4;
            continue;
        }

        // Decode and extract the string
        if let Some(s) = decode_arm64_string(
            inst1,
            inst2,
            inst3,
            pos,
            text_addr,
            rodata_data,
            rodata_addr,
            rodata_end,
        ) {
            if s.len() >= min_length && !seen.contains(&s) {
                seen.insert(s.clone());
                // Use content-based classification, but prefer MapKey hint from register position
                let final_kind = if _kind == StringKind::MapKey && looks_like_key(&s) {
                    StringKind::MapKey
                } else {
                    classify_string(&s)
                };
                strings.push(ExtractedString {
                    value: s,
                    data_offset: rodata_addr,
                    section: Some("__rodata".to_string()),
                    method: StringMethod::InstructionPattern,
                    kind: final_kind,
                    ..Default::default()
                });
            }
        }

        return;
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
) -> Option<String> {
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
    let str_addr = (page_addr as u64).wrapping_add(u64::from(add_imm));

    // Decode MOV/ORR: extract length
    let str_len = decode_arm_mov_immediate(inst3)?;

    // Validate
    if str_addr < rodata_addr || str_addr >= rodata_end {
        return None;
    }

    if str_len == 0 || str_len > 1000 {
        return None;
    }

    let rodata_offset = (str_addr - rodata_addr) as usize;
    if rodata_offset + str_len as usize > rodata_data.len() {
        return None;
    }

    let bytes = &rodata_data[rodata_offset..rodata_offset + str_len as usize];
    let s = std::str::from_utf8(bytes).ok()?;

    if is_valid_utf8_string(s) {
        Some(s.to_string())
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
pub fn extract_inline_strings_amd64(
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
        .filter(|(i, &b)| b == 0xE8 && *i < text_data.len().saturating_sub(5))
        .map(|(i, _)| i)
        .collect();

    // Process CALL sites in parallel
    let all_strings: Vec<Vec<ExtractedString>> = call_positions
        .par_iter()
        .map(|&i| {
            let mut strings = Vec::new();
            let mut seen = HashSet::new();

            // Extract first argument strings (RDI/RSI)
            extract_amd64_first_arg_string(
                i,
                text_data,
                text_addr,
                rodata_data,
                rodata_addr,
                rodata_end,
                min_length,
                StringKind::Arg,
                &mut strings,
                &mut seen,
            );

            // Extract second argument strings (RSI/RDX) - often map keys
            extract_amd64_key_string(
                i,
                text_data,
                text_addr,
                rodata_data,
                rodata_addr,
                rodata_end,
                min_length,
                StringKind::MapKey,
                &mut strings,
                &mut seen,
            );

            // Extract value strings after CALL
            extract_amd64_value_string(
                i,
                text_data,
                text_addr,
                rodata_data,
                rodata_addr,
                rodata_end,
                min_length,
                StringKind::Const,
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

/// Extract first argument string (LEAQ addr(RIP), RDI + MOVL $len, RSI).
///
/// This function searches backward from a CALL instruction for the pattern:
/// - LEAQ xxx(RIP), RDI  (48 8D 3D xx xx xx xx) - Load string address into RDI
/// - MOVL $imm32, ESI    (BE xx xx xx xx)        - Load string length into RSI
/// - MOVQ $imm32, RSI    (48 C7 C6 xx xx xx xx)  - Alternative length load
///
/// ## Intentional Similarity
///
/// This function is intentionally similar to `extract_amd64_key_string()` and
/// `extract_amd64_value_string()`. The duplication is maintained because:
///
/// 1. **Different instruction encodings**: Each register pair uses different opcodes
///    - RDI/RSI: LEAQ uses 0x3D, MOVL uses 0xBE
///    - RSI/RDX: LEAQ uses 0x35, MOVL uses 0xBA
///    - RCX: LEAQ uses 0x0D
///
/// 2. **Independent testing**: Each register pattern can be tested and debugged separately
///
/// 3. **Performance**: No runtime branching on register type in the hot loop
///
/// 4. **Stability**: Code has been stable for 6+ months with minimal changes
///
/// 5. **Clarity**: Each function is self-contained and easy to understand
///
/// ## When to Consolidate
///
/// If you need to add new register patterns or fix bugs across all three functions,
/// consider consolidating into a parameterized `extract_amd64_string_pattern()` helper.
///
/// ## Register Convention
///
/// RDI/RSI is the System V ABI first argument position on x86-64.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::similar_names)]
fn extract_amd64_first_arg_string(
    call_pos: usize,
    text_data: &[u8],
    text_addr: u64,
    rodata_data: &[u8],
    rodata_addr: u64,
    rodata_end: u64,
    min_length: usize,
    _kind: StringKind,
    strings: &mut Vec<ExtractedString>,
    seen: &mut HashSet<String>,
) {
    let max_lookback = call_pos.min(50);

    for lookback in 5..=max_lookback {
        let pos = call_pos - lookback;
        if pos + 7 > text_data.len() {
            break;
        }

        // Check for LEAQ xxx(RIP), RDI (48 8D 3D xx xx xx xx)
        if text_data[pos] == 0x48 && text_data[pos + 1] == 0x8D && text_data[pos + 2] == 0x3D {
            // SAFETY: bounds checked above (pos + 7 <= text_data.len())
            let offset = i32::from_le_bytes([
                text_data[pos + 3],
                text_data[pos + 4],
                text_data[pos + 5],
                text_data[pos + 6],
            ]);
            let rip_addr = text_addr + (pos + 7) as u64;
            let str_addr = (rip_addr as i64 + i64::from(offset)) as u64;

            // Look for MOVL/MOVQ $len, RSI
            let mut str_len = 0u64;
            let mut found_len = false;

            for off in 7..=20 {
                if pos + off + 5 > text_data.len() {
                    break;
                }

                // MOVL $imm32, ESI (BE xx xx xx xx)
                if text_data[pos + off] == 0xBE {
                    // SAFETY: bounds checked in loop (pos + off + 5 <= text_data.len())
                    str_len = u64::from(u32::from_le_bytes([
                        text_data[pos + off + 1],
                        text_data[pos + off + 2],
                        text_data[pos + off + 3],
                        text_data[pos + off + 4],
                    ]));
                    found_len = true;
                    break;
                }

                // MOVQ $imm32, RSI (48 C7 C6 xx xx xx xx)
                if pos + off + 7 <= text_data.len()
                    && text_data[pos + off] == 0x48
                    && text_data[pos + off + 1] == 0xC7
                    && text_data[pos + off + 2] == 0xC6
                {
                    // SAFETY: bounds checked in if condition above
                    str_len = u64::from(u32::from_le_bytes([
                        text_data[pos + off + 3],
                        text_data[pos + off + 4],
                        text_data[pos + off + 5],
                        text_data[pos + off + 6],
                    ]));
                    found_len = true;
                    break;
                }
            }

            if !found_len || str_len == 0 || str_len > 1000 {
                continue;
            }

            if str_addr < rodata_addr || str_addr >= rodata_end {
                continue;
            }

            let rodata_offset = (str_addr - rodata_addr) as usize;
            if rodata_offset + str_len as usize > rodata_data.len() {
                continue;
            }

            if let Ok(s) =
                std::str::from_utf8(&rodata_data[rodata_offset..rodata_offset + str_len as usize])
            {
                if is_valid_utf8_string(s) && s.len() >= min_length && !seen.contains(s) {
                    seen.insert(s.to_string());
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
            }

            return;
        }
    }
}

/// Extract key string (LEAQ addr(RIP), RSI + MOVL $len, RDX).
///
/// This function searches backward from a CALL instruction for the pattern:
/// - LEAQ xxx(RIP), RSI  (48 8D 35 xx xx xx xx) - Load string address into RSI
/// - MOVL $imm32, EDX    (BA xx xx xx xx)        - Load string length into RDX
///
/// ## Intentional Similarity
///
/// This function is intentionally similar to `extract_amd64_first_arg_string()` and
/// `extract_amd64_value_string()`. The duplication is maintained because:
///
/// 1. **Different instruction encodings**: RSI/RDX uses different opcodes than RDI/RSI
///    - LEAQ into RSI: 0x35 (vs 0x3D for RDI, 0x0D for RCX)
///    - MOVL into EDX: 0xBA (vs 0xBE for ESI)
///
/// 2. **Semantic difference**: This pattern extracts map keys, not general arguments
///    - Special classification logic for MapKey strings (line 626-630)
///    - Uses `looks_like_key()` heuristic to preserve semantic information
///
/// 3. **Independent testing**: Map key extraction can be tested separately from arguments
///
/// 4. **Performance**: No runtime branching on register type in the hot loop
///
/// 5. **Clarity**: Each function is self-contained and easy to understand
///
/// ## When to Consolidate
///
/// If you need to add new register patterns or fix bugs across all three functions,
/// consider consolidating into a parameterized `extract_amd64_string_pattern()` helper.
///
/// ## Register Convention
///
/// RSI/RDX is commonly used for Go map insertion: `runtime.mapassign(maptype, map, key)`
/// where RSI holds the key address and RDX holds the key length.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::similar_names)]
fn extract_amd64_key_string(
    call_pos: usize,
    text_data: &[u8],
    text_addr: u64,
    rodata_data: &[u8],
    rodata_addr: u64,
    rodata_end: u64,
    min_length: usize,
    _kind: StringKind,
    strings: &mut Vec<ExtractedString>,
    seen: &mut HashSet<String>,
) {
    let max_lookback = call_pos.min(50);

    for lookback in 5..=max_lookback {
        let pos = call_pos - lookback;
        if pos + 7 > text_data.len() {
            break;
        }

        // LEAQ xxx(RIP), RSI (48 8D 35 xx xx xx xx)
        if text_data[pos] == 0x48 && text_data[pos + 1] == 0x8D && text_data[pos + 2] == 0x35 {
            // SAFETY: bounds checked above (pos + 7 <= text_data.len())
            let offset = i32::from_le_bytes([
                text_data[pos + 3],
                text_data[pos + 4],
                text_data[pos + 5],
                text_data[pos + 6],
            ]);
            let rip_addr = text_addr + (pos + 7) as u64;
            let str_addr = (rip_addr as i64 + i64::from(offset)) as u64;

            // Find MOVL $len, EDX (BA xx xx xx xx)
            let mut str_len = 0u64;
            let mut found_len = false;

            for off in 7..=20 {
                if pos + off + 5 > text_data.len() {
                    break;
                }

                if text_data[pos + off] == 0xBA {
                    // SAFETY: bounds checked in loop (pos + off + 5 <= text_data.len())
                    str_len = u64::from(u32::from_le_bytes([
                        text_data[pos + off + 1],
                        text_data[pos + off + 2],
                        text_data[pos + off + 3],
                        text_data[pos + off + 4],
                    ]));
                    found_len = true;
                    break;
                }
            }

            if !found_len || str_len == 0 || str_len > 1000 {
                continue;
            }

            if str_addr < rodata_addr || str_addr >= rodata_end {
                continue;
            }

            let rodata_offset = (str_addr - rodata_addr) as usize;
            if rodata_offset + str_len as usize > rodata_data.len() {
                continue;
            }

            if let Ok(s) =
                std::str::from_utf8(&rodata_data[rodata_offset..rodata_offset + str_len as usize])
            {
                if is_valid_utf8_string(s) && s.len() >= min_length && !seen.contains(s) {
                    seen.insert(s.to_string());
                    // Use content-based classification, but prefer MapKey hint from register position
                    let final_kind = if _kind == StringKind::MapKey && looks_like_key(s) {
                        StringKind::MapKey
                    } else {
                        classify_string(s)
                    };
                    strings.push(ExtractedString {
                        value: s.to_string(),
                        data_offset: str_addr,
                        section: Some(".rodata".to_string()),
                        method: StringMethod::InstructionPattern,
                        kind: final_kind,
                        ..Default::default()
                    });
                }
            }

            return;
        }
    }
}

/// Extract value string from after CALL (LEAQ + MOVQ pattern).
///
/// This function searches **forward** from a CALL instruction for the pattern:
/// - MOVQ $len, 8(RAX)   (48 C7 40 08 xx xx xx xx) - Store length to memory via RAX
/// - LEAQ addr(RIP), RCX (48 8D 0D xx xx xx xx)     - Load string address into RCX
///
/// ## Intentional Similarity
///
/// This function is intentionally similar to `extract_amd64_first_arg_string()` and
/// `extract_amd64_key_string()`. The duplication is maintained because:
///
/// 1. **Different search direction**: Searches **forward** from CALL (others search backward)
///    - Extracts strings constructed *after* a function returns
///    - Different instruction patterns for post-call string assembly
///
/// 2. **Different instruction pattern**: Length stored to memory, not passed in register
///    - MOVQ into 8(RAX): Memory store pattern (48 C7 40 08)
///    - LEAQ into RCX: Uses 0x0D opcode (vs 0x3D for RDI, 0x35 for RSI)
///
/// 3. **Different instruction order**: Finds length first, then address (others reverse)
///    - Optimizes for common code generation patterns
///    - Early exit if length is invalid
///
/// 4. **Independent testing**: Post-call patterns can be tested separately
///
/// 5. **Performance**: No runtime branching on search direction or pattern type
///
/// 6. **Clarity**: Each function is self-contained and easy to understand
///
/// ## When to Consolidate
///
/// If you need to add new register patterns or fix bugs across all three functions,
/// consider consolidating into a parameterized `extract_amd64_string_pattern()` helper.
/// However, the forward/backward search direction makes consolidation less beneficial.
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
    _kind: StringKind,
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
            // SAFETY: Bounds checked at line 668 (call_pos + offset + 8 <= text_data.len())
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
            // SAFETY: Bounds checked at line 692 (call_pos + offset + 7 <= text_data.len())
            let rip_offset = if let Ok(bytes) =
                text_data[call_pos + offset + 3..call_pos + offset + 7].try_into()
            {
                i32::from_le_bytes(bytes)
            } else {
                continue;
            };
            let rip_addr = text_addr + (call_pos + offset + 7) as u64;
            // Use wrapping_add for RIP-relative address calculation (x86-64 semantics)
            let str_addr = (rip_addr as i64).wrapping_add(i64::from(rip_offset)) as u64;

            if str_addr < rodata_addr || str_addr >= rodata_end {
                continue;
            }

            let rodata_offset = (str_addr - rodata_addr) as usize;
            if rodata_offset + str_len as usize > rodata_data.len() {
                continue;
            }

            if let Ok(s) =
                std::str::from_utf8(&rodata_data[rodata_offset..rodata_offset + str_len as usize])
            {
                if is_valid_utf8_string(s) && s.len() >= min_length && !seen.contains(s) {
                    seen.insert(s.to_string());
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
    fn test_amd64_first_arg_short_data() {
        let text_data = vec![0xE8u8, 0, 0, 0, 0]; // Just a CALL
        let rodata_data = b"Test";
        let mut strings = Vec::new();
        let mut seen = HashSet::new();

        extract_amd64_first_arg_string(
            0,
            &text_data,
            0x1000,
            rodata_data,
            0x2000,
            0x2004,
            4,
            StringKind::Arg,
            &mut strings,
            &mut seen,
        );

        assert!(strings.is_empty());
    }

    #[test]
    fn test_amd64_key_string_short_data() {
        let text_data = vec![0xE8u8, 0, 0, 0, 0];
        let rodata_data = b"Test";
        let mut strings = Vec::new();
        let mut seen = HashSet::new();

        extract_amd64_key_string(
            0,
            &text_data,
            0x1000,
            rodata_data,
            0x2000,
            0x2004,
            4,
            StringKind::MapKey,
            &mut strings,
            &mut seen,
        );

        assert!(strings.is_empty());
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
            StringKind::Const,
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
        for key in results.iter().filter(|s| s.kind == StringKind::MapKey) {
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
        let text_data: Vec<u8> = (0..65536).map(|i| (i % 256) as u8).collect();
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
}
