//! Garble string decryption orchestration.
//!
//! This module ties together the gopclntab parser and x86-64 emulator
//! to extract obfuscated strings from garble-compiled Go binaries.
//!
//! # How Garble Works
//!
//! Garble creates a `Decrypt` method for each obfuscated struct. The method:
//! 1. Takes a receiver pointer to the obfuscated data in .rodata
//! 2. Performs transformation operations (XOR, shuffle, split, etc.)
//! 3. Calls `runtime.slicebytetostring` with the result
//!
//! # Extraction Strategy
//!
//! For each Decrypt function found in gopclntab:
//! 1. Set up emulator with .text, .rodata, .noptrdata sections
//! 2. Find all XREFs to the Decrypt function
//! 3. For each XREF, set up emulator state with receiver pointer
//! 4. Emulate until `slicebytetostring` call
//! 5. Capture the decrypted string bytes

use crate::types::{ExtractedString, StringMethod};

use super::emulator::{EmulationResult, Emulator};
use super::func_finder::{find_call_targets, find_decrypt_candidates};
use super::gopclntab::{GoVersion, Pclntab};

/// Result of garble string extraction.
#[derive(Debug)]
pub struct GarbleExtractResult {
    /// Extracted strings
    pub strings: Vec<ExtractedString>,
    /// Go version detected
    pub go_version: GoVersion,
    /// Number of Decrypt functions found
    pub decrypt_func_count: usize,
    /// Number of strings successfully extracted
    pub success_count: usize,
    /// Errors encountered during extraction
    pub errors: Vec<String>,
}

/// Section data for emulator setup.
pub struct SectionData<'a> {
    /// Section virtual address
    pub vaddr: u64,
    /// Section contents
    pub data: &'a [u8],
    /// Whether section is writable
    pub writable: bool,
}

/// Extract garble-obfuscated strings from a binary.
///
/// # Parameters
/// - `text`: .text section (code)
/// - `rodata`: .rodata section (encrypted data)
/// - `noptrdata`: .noptrdata section (Go runtime data), optional
/// - `gopclntab`: .gopclntab section contents
/// - `gopclntab_va`: Virtual address of .gopclntab
///
/// # Returns
/// Extraction results including strings and metadata.
pub fn extract_garble_strings<'a>(
    text: SectionData<'a>,
    rodata: SectionData<'a>,
    noptrdata: Option<SectionData<'a>>,
    gopclntab: &[u8],
    _gopclntab_va: u64,
) -> GarbleExtractResult {
    let mut result = GarbleExtractResult {
        strings: Vec::new(),
        go_version: GoVersion::Unknown,
        decrypt_func_count: 0,
        success_count: 0,
        errors: Vec::new(),
    };

    // Parse gopclntab to find function information
    let Some(pclntab) = Pclntab::parse(gopclntab, 0) else {
        result.errors.push("Failed to parse gopclntab".to_string());
        return result;
    };

    result.go_version = pclntab.go_version;

    // Find all Decrypt functions
    let decrypt_funcs = pclntab.find_decrypt_functions();
    result.decrypt_func_count = decrypt_funcs.len();

    if decrypt_funcs.is_empty() {
        // No Decrypt functions found - this binary might not use garble
        // or uses a different obfuscation approach
        return result;
    }

    // Find slicebytetostring for stopping condition
    let slicebytetostring_addr = pclntab
        .find_functions_containing("slicebytetostring")
        .first()
        .map(|f| f.entry_pc);

    // Set up emulator
    let mut emu = Emulator::new();

    // Load sections
    emu.load_section(text.vaddr, text.data, text.writable);
    emu.load_section(rodata.vaddr, rodata.data, rodata.writable);

    if let Some(noptrdata) = noptrdata {
        emu.load_section(noptrdata.vaddr, noptrdata.data, noptrdata.writable);
    }

    // Set up stack
    emu.setup_stack(64 * 1024);

    // Add slicebytetostring as target
    if let Some(addr) = slicebytetostring_addr {
        emu.add_target(addr, "runtime.slicebytetostring");
    }

    // For each Decrypt function, try to find call sites and emulate
    for decrypt_func in &decrypt_funcs {
        // Find XREFs to this function by scanning .text for CALL instructions
        // with the function's address as target
        let call_sites = find_call_sites(text.data, text.vaddr, decrypt_func.entry_pc);

        for call_site in call_sites {
            // For each call site, try to determine the receiver pointer
            // This requires analyzing the setup instructions before the CALL

            // Set up emulator to run from a few instructions before the call
            // to capture register setup
            let setup_start = call_site.saturating_sub(32);

            emu.set_rip(setup_start);

            // Emulate until we hit slicebytetostring
            match emu.run() {
                EmulationResult::HitTarget { bytes, len } => {
                    let effective_len = len.min(bytes.len());
                    if let Ok(s) = String::from_utf8(bytes[..effective_len].to_vec()) {
                        if s.len() >= 4 {
                            // Minimum useful string length
                            result.strings.push(ExtractedString {
                                value: s,
                                data_offset: call_site,
                                section: Some(".text".to_string()),
                                method: StringMethod::GarbleEmulated,
                                kind: None,
                                ..Default::default()
                            });
                            result.success_count += 1;
                        }
                    }
                }
                EmulationResult::Error(e) => {
                    result
                        .errors
                        .push(format!("Emulation error at {:#x}: {}", call_site, e));
                }
                _ => {
                    // Normal return, max instructions, or stopped - not an error
                }
            }
        }
    }

    // Deduplicate results
    let mut seen = std::collections::HashSet::new();
    result.strings.retain(|s| seen.insert(s.value.clone()));

    result
}

/// Find CALL instruction sites targeting a specific address.
fn find_call_sites(text: &[u8], text_va: u64, target: u64) -> Vec<u64> {
    use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind};

    let mut sites = Vec::new();

    let mut decoder = Decoder::with_ip(64, text, text_va, DecoderOptions::NONE);

    for instr in decoder.iter() {
        if instr.mnemonic() == Mnemonic::Call {
            let call_target = match instr.op0_kind() {
                OpKind::NearBranch64 => instr.near_branch64(),
                OpKind::NearBranch32 => instr.near_branch32() as u64,
                _ => continue,
            };

            if call_target == target {
                sites.push(instr.ip());
            }
        }
    }

    sites
}

/// Extract garble-obfuscated strings using function finder approach.
///
/// This version doesn't rely on gopclntab addresses - it finds functions
/// by scanning CALL targets and filtering by rodata references.
///
/// # Parameters
/// - `text`: .text section (code)
/// - `rodata`: .rodata section (encrypted data)
/// - `noptrdata`: .noptrdata section (Go runtime data), optional
/// - `slicebytetostring_addr`: Address of runtime.slicebytetostring, if known
///
/// # Returns
/// Extraction results including strings and metadata.
pub fn extract_garble_strings_v2<'a>(
    text: SectionData<'a>,
    rodata: SectionData<'a>,
    noptrdata: Option<SectionData<'a>>,
    slicebytetostring_addr: Option<u64>,
) -> GarbleExtractResult {
    let mut result = GarbleExtractResult {
        strings: Vec::new(),
        go_version: GoVersion::Unknown,
        decrypt_func_count: 0,
        success_count: 0,
        errors: Vec::new(),
    };

    // Find all CALL targets in .text
    let call_targets = find_call_targets(text.data, text.vaddr);

    // Filter to functions that look like decryption code
    let candidates = find_decrypt_candidates(
        text.data,
        text.vaddr,
        rodata.vaddr,
        rodata.data.len(),
        &call_targets,
    );

    result.decrypt_func_count = candidates.len();

    if candidates.is_empty() {
        result
            .errors
            .push("No decrypt candidates found".to_string());
        return result;
    }

    // Set up emulator
    let mut emu = Emulator::new();
    emu.max_instructions = 50_000; // Limit per function

    // Load sections
    emu.load_section(text.vaddr, text.data, false);
    emu.load_section(rodata.vaddr, rodata.data, false);

    if let Some(noptrdata) = noptrdata {
        emu.load_section(noptrdata.vaddr, noptrdata.data, noptrdata.writable);
    }

    // Set up stack
    emu.setup_stack(64 * 1024);

    // Add slicebytetostring as target
    if let Some(addr) = slicebytetostring_addr {
        emu.add_target(addr, "runtime.slicebytetostring");
    }

    // Try emulating each candidate function
    for candidate in candidates.iter().take(100) {
        // Limit to top 100 candidates
        // Reset emulator state for each attempt
        emu.cpu = super::emulator::CpuState::new(0x7FFF_0000_0000u64 + 64 * 1024 - 8);
        emu.set_rip(candidate.entry);
        emu.instructions_executed = 0;

        match emu.run() {
            EmulationResult::HitTarget { bytes, len } => {
                let effective_len = len.min(bytes.len());
                if let Ok(s) = String::from_utf8(bytes[..effective_len].to_vec()) {
                    if s.len() >= 4 && is_interesting_string(&s) {
                        result.strings.push(ExtractedString {
                            value: s,
                            data_offset: candidate.entry,
                            section: Some(".text".to_string()),
                            method: StringMethod::GarbleEmulated,
                            kind: None,
                            ..Default::default()
                        });
                        result.success_count += 1;
                    }
                }
            }
            EmulationResult::Error(e) => {
                // Only log errors for high-scoring candidates
                if candidate.score >= 20 {
                    result
                        .errors
                        .push(format!("Emulation error at {:#x}: {}", candidate.entry, e));
                }
            }
            _ => {
                // Normal return, max instructions, or stopped - not an error
            }
        }
    }

    // Deduplicate results
    let mut seen = std::collections::HashSet::new();
    result.strings.retain(|s| seen.insert(s.value.clone()));

    result
}

/// Check if a string is "interesting" (not garbage).
fn is_interesting_string(s: &str) -> bool {
    // Must have reasonable length
    if s.len() < 4 || s.len() > 1024 {
        return false;
    }

    // Must be mostly printable
    let printable_count = s.chars().filter(|c| !c.is_control() || *c == '\n').count();
    if printable_count < s.len() * 9 / 10 {
        return false;
    }

    // Skip if it's all same character
    let Some(first) = s.chars().next() else {
        return false;
    };
    if s.chars().all(|c| c == first) {
        return false;
    }

    true
}

/// Simplified extraction for testing - directly emulate a Decrypt function.
///
/// This is useful when you know the exact address and receiver pointer.
pub fn emulate_decrypt_function(
    text: &[u8],
    text_va: u64,
    rodata: &[u8],
    rodata_va: u64,
    decrypt_addr: u64,
    receiver_ptr: u64,
    slicebytetostring_addr: Option<u64>,
) -> Option<String> {
    let mut emu = Emulator::new();

    // Load sections
    emu.load_section(text_va, text, false);
    emu.load_section(rodata_va, rodata, false);

    // Set up stack
    emu.setup_stack(64 * 1024);

    // Set up target
    if let Some(addr) = slicebytetostring_addr {
        emu.add_target(addr, "runtime.slicebytetostring");
    }

    // Set receiver pointer in RAX (Go calling convention)
    emu.cpu.regs[0] = receiver_ptr;

    // Start at decrypt function
    emu.set_rip(decrypt_addr);

    // Run until target or completion
    match emu.run() {
        EmulationResult::HitTarget { bytes, len } => {
            let effective_len = len.min(bytes.len());
            String::from_utf8(bytes[..effective_len].to_vec()).ok()
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_call_sites() {
        // Create a small code section with a CALL instruction
        // E8 XX XX XX XX is CALL rel32
        let mut code = vec![0x90; 32]; // NOP padding

        // At offset 10, place CALL +5 (which would target offset 15+5=20 at VA)
        code[10] = 0xE8;
        code[11] = 0x05;
        code[12] = 0x00;
        code[13] = 0x00;
        code[14] = 0x00;

        let text_va = 0x1000;
        // CALL at 0x100A, target = 0x100A + 5 + 5 = 0x1014
        let target = 0x1014;

        let sites = find_call_sites(&code, text_va, target);
        assert_eq!(sites, vec![0x100A]);
    }

    #[test]
    fn test_no_decrypt_functions() {
        // Empty gopclntab should result in empty extraction
        let result = extract_garble_strings(
            SectionData {
                vaddr: 0x1000,
                data: &[0x90; 32],
                writable: false,
            },
            SectionData {
                vaddr: 0x2000,
                data: &[0; 32],
                writable: false,
            },
            None,
            &[0; 16],
            0x3000,
        );

        assert!(result.strings.is_empty());
        assert_eq!(result.decrypt_func_count, 0);
    }
}
