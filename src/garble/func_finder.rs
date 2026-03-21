//! Function finder for garble-obfuscated binaries.
//!
//! When gopclntab is modified by garble (functab_off=0), we can't get function
//! addresses from pclntab. Instead, we find functions by scanning for CALL
//! instruction targets in the .text section.
//!
//! # Strategy
//!
//! 1. Scan .text for all CALL instructions (E8 rel32 and FF /2)
//! 2. Extract unique call targets within .text bounds
//! 3. Filter candidates that reference .rodata (likely init functions)
//! 4. Return sorted list of function entry points

use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind, Register};
use std::collections::HashSet;

/// Find all unique CALL targets within the .text section.
///
/// # Parameters
/// - `text`: .text section contents
/// - `text_va`: Virtual address of .text section
///
/// # Returns
/// Sorted list of unique function entry points.
pub fn find_call_targets(text: &[u8], text_va: u64) -> Vec<u64> {
    let mut targets = HashSet::new();
    let text_end = text_va + text.len() as u64;

    let mut decoder = Decoder::with_ip(64, text, text_va, DecoderOptions::NONE);

    for instr in decoder.iter() {
        if instr.mnemonic() == Mnemonic::Call {
            let target = match instr.op0_kind() {
                OpKind::NearBranch64 => Some(instr.near_branch64()),
                OpKind::NearBranch32 => Some(instr.near_branch32() as u64),
                _ => None,
            };

            if let Some(addr) = target {
                // Only include targets within .text bounds
                if addr >= text_va && addr < text_end {
                    targets.insert(addr);
                }
            }
        }
    }

    let mut result: Vec<_> = targets.into_iter().collect();
    result.sort_unstable();
    result
}

/// Candidate function for decryption.
#[derive(Debug, Clone)]
pub struct FuncCandidate {
    /// Function entry address
    pub entry: u64,
    /// Number of rodata references found
    pub rodata_refs: usize,
    /// Number of XOR instructions found
    pub xor_count: usize,
    /// Number of ADD/SUB instructions found
    pub arith_count: usize,
    /// Score based on heuristics (higher = more likely decryption)
    pub score: u32,
}

/// Find functions that likely perform string decryption.
///
/// Analyzes each function candidate and scores based on:
/// - References to .rodata section (encrypted data)
/// - XOR/ADD/SUB operations (decryption primitives)
/// - Loop patterns (iterating over bytes)
///
/// # Parameters
/// - `text`: .text section contents
/// - `text_va`: Virtual address of .text section
/// - `rodata_va`: Virtual address of .rodata section
/// - `rodata_len`: Length of .rodata section
/// - `candidates`: Function entry points to analyze
///
/// # Returns
/// Candidates sorted by score (highest first).
pub fn find_decrypt_candidates(
    text: &[u8],
    text_va: u64,
    rodata_va: u64,
    rodata_len: usize,
    candidates: &[u64],
) -> Vec<FuncCandidate> {
    let rodata_end = rodata_va + rodata_len as u64;

    let mut results = Vec::new();

    for &entry in candidates {
        // Skip if entry is outside .text
        let offset = entry.saturating_sub(text_va) as usize;
        if offset >= text.len() {
            continue;
        }

        // Analyze first ~200 bytes of function (or until RET)
        let func_bytes = &text[offset..std::cmp::min(offset + 200, text.len())];

        let analysis = analyze_function(func_bytes, entry, rodata_va, rodata_end);

        // Score the function based on decryption-like characteristics
        let score = (analysis.rodata_refs as u32 * 10)
            + (analysis.xor_count as u32 * 5)
            + (analysis.arith_count as u32 * 2)
            + if analysis.has_large_immediate { 5 } else { 0 }
            + if analysis.has_call_to_runtime { 3 } else { 0 };

        // Include if it looks like decryption code:
        // - References rodata AND (has xor/arith OR has large immediate)
        // - OR has multiple rodata refs (likely data loading)
        // - OR has xor with call to runtime (might be decryption + string conversion)
        let is_candidate = (analysis.rodata_refs > 0
            && (analysis.xor_count > 0
                || analysis.arith_count > 2
                || analysis.has_large_immediate))
            || analysis.rodata_refs >= 2
            || (analysis.xor_count > 0 && analysis.has_call_to_runtime);

        if is_candidate {
            results.push(FuncCandidate {
                entry,
                rodata_refs: analysis.rodata_refs,
                xor_count: analysis.xor_count,
                arith_count: analysis.arith_count,
                score,
            });
        }
    }

    // Sort by score (highest first)
    results.sort_by(|a, b| b.score.cmp(&a.score));
    results
}

/// Function analysis results.
struct FuncAnalysis {
    rodata_refs: usize,
    xor_count: usize,
    arith_count: usize,
    has_large_immediate: bool,
    has_call_to_runtime: bool,
}

/// Analyze a function's instructions.
fn analyze_function(
    func_bytes: &[u8],
    func_va: u64,
    rodata_start: u64,
    rodata_end: u64,
) -> FuncAnalysis {
    let mut rodata_refs = 0;
    let mut xor_count = 0;
    let mut arith_count = 0;
    let mut has_large_immediate = false;
    let mut has_call_to_runtime = false;

    let mut decoder = Decoder::with_ip(64, func_bytes, func_va, DecoderOptions::NONE);
    let mut instr_count = 0;

    for instr in decoder.iter() {
        instr_count += 1;

        // Stop at RET instruction or after analyzing 100 instructions
        if instr.mnemonic() == Mnemonic::Ret || instr_count > 100 {
            break;
        }

        // Count XOR instructions (but not xor reg,reg which is zeroing)
        if instr.mnemonic() == Mnemonic::Xor {
            // Check if it's not zeroing (xor reg, same-reg)
            if instr.op0_kind() == OpKind::Register
                && instr.op1_kind() == OpKind::Register
                && instr.op0_register() == instr.op1_register()
            {
                // This is zeroing, don't count
            } else {
                xor_count += 1;
            }
        }

        // Count ADD/SUB
        if matches!(instr.mnemonic(), Mnemonic::Add | Mnemonic::Sub) {
            arith_count += 1;
        }

        // Check for CALL instructions (might be to slicebytetostring)
        if instr.mnemonic() == Mnemonic::Call {
            has_call_to_runtime = true;
        }

        // Check for large immediate values (garble external keys)
        if instr.op_count() >= 2 {
            for op_idx in 0..instr.op_count() {
                match instr.op_kind(op_idx) {
                    OpKind::Immediate64 => {
                        let imm = instr.immediate64();
                        if imm > 0xFF && imm != u64::MAX {
                            has_large_immediate = true;
                        }
                    }
                    OpKind::Immediate32 | OpKind::Immediate32to64 => {
                        let imm = instr.immediate32();
                        if imm > 0xFF && imm != u32::MAX {
                            has_large_immediate = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        // Check for LEA with RIP-relative addressing into rodata
        if instr.mnemonic() == Mnemonic::Lea
            && instr.memory_base() == Register::RIP
        {
            let target = calc_rip_target(&instr);
            if target >= rodata_start && target < rodata_end {
                rodata_refs += 1;
            }
        }

        // Check for MOV with RIP-relative addressing into rodata
        if instr.mnemonic() == Mnemonic::Mov
            && instr.op1_kind() == OpKind::Memory
            && instr.memory_base() == Register::RIP
        {
            let target = calc_rip_target(&instr);
            if target >= rodata_start && target < rodata_end {
                rodata_refs += 1;
            }
        }
    }

    FuncAnalysis {
        rodata_refs,
        xor_count,
        arith_count,
        has_large_immediate,
        has_call_to_runtime,
    }
}

/// Calculate target address for RIP-relative instruction.
fn calc_rip_target(instr: &iced_x86::Instruction) -> u64 {
    // For RIP-relative addressing, iced-x86's memory_displacement64()
    // returns the effective address (target), not the raw displacement.
    instr.memory_displacement64()
}

/// Find init functions that likely initialize obfuscated strings.
///
/// In garble-compiled binaries, init functions (*.init, *.init.func1, etc.)
/// are where string decryption happens. We find them by:
/// 1. Looking for functions called early in _start/main
/// 2. Functions that reference rodata and perform XOR operations
/// 3. Functions with multiple CALL instructions (init chains)
///
/// # Parameters
/// - `text`: .text section contents
/// - `text_va`: Virtual address of .text section
/// - `rodata_va`: Virtual address of .rodata section
/// - `rodata_len`: Length of .rodata section
///
/// # Returns
/// List of init function candidates, sorted by likelihood.
pub fn find_init_functions(
    text: &[u8],
    text_va: u64,
    rodata_va: u64,
    rodata_len: usize,
) -> Vec<FuncCandidate> {
    // First, find all call targets
    let all_targets = find_call_targets(text, text_va);

    // Then filter to decrypt candidates
    find_decrypt_candidates(text, text_va, rodata_va, rodata_len, &all_targets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_call_targets() {
        // Create code with CALL instructions
        // E8 05 00 00 00 = call +5 (relative)
        let mut code = vec![0x90; 32]; // NOP padding
        code[0] = 0xE8; // CALL
        code[1] = 0x05; // +5 offset
        code[2] = 0x00;
        code[3] = 0x00;
        code[4] = 0x00;
        // Target is: 0x1000 + 5 + 5 = 0x100A

        let targets = find_call_targets(&code, 0x1000);
        assert_eq!(targets, vec![0x100A]);
    }

    #[test]
    fn test_find_call_targets_multiple() {
        let mut code = vec![0x90; 64];
        // First CALL at offset 0: call +10
        code[0] = 0xE8;
        code[1] = 0x0A;
        code[2] = 0x00;
        code[3] = 0x00;
        code[4] = 0x00;
        // Target: 0x1000 + 5 + 10 = 0x100F

        // Second CALL at offset 16: call +20
        code[16] = 0xE8;
        code[17] = 0x14;
        code[18] = 0x00;
        code[19] = 0x00;
        code[20] = 0x00;
        // Target: 0x1000 + 16 + 5 + 20 = 0x1029

        let targets = find_call_targets(&code, 0x1000);
        assert_eq!(targets.len(), 2);
        assert!(targets.contains(&0x100F));
        assert!(targets.contains(&0x1029));
    }
}
