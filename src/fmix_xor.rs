//! Strings sealed by a MurmurHash3-finalizer keystream with ciphertext feedback.
//!
//! A macOS stealer (2026-09, bfc96a7fa7aa) inlines one decryption loop per
//! string. Every string is a self-contained record in constant data:
//!
//! ```text
//! seed: u32 LE | ciphertext | encrypted NUL | zero padding to 4 bytes
//! ```
//!
//! Byte `i` decrypts as `c[i] ^ fmix(prev * (C1 + 12) + seed + i * GOLDEN)`,
//! where `prev` is the seed's low byte for the first byte and the previous
//! ciphertext byte after that, and `fmix` is the MurmurHash3 32-bit finalizer
//! with its last shift shortened to 8.
//!
//! The key travels with each record, so no loop needs decoding and both slices
//! of a universal binary fall to the same pass. It runs only when `__text`
//! materializes all three mixer constants, then tries each 4-byte-aligned
//! offset of the constant-data sections. A record qualifies only when every byte
//! before the terminator is printable, the terminator decrypts to exactly NUL
//! and the padding after it is zero, so a random offset survives with odds
//! below 1 in 256 before the length floor applies.

use crate::{ExtractedString, StringMethod, classify_string};
use goblin::mach::MachO;
use goblin::mach::constants::{
    S_ATTR_PURE_INSTRUCTIONS, S_ATTR_SOME_INSTRUCTIONS, S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL,
    S_ZEROFILL, SECTION_TYPE,
};

const C1: u32 = 0x85eb_ca6b;
const C2: u32 = 0xc2b2_ae35;
const GOLDEN: u32 = 0x9e37_79b9;
const CONSTANTS: [u32; 3] = [C1, C2, GOLDEN];

const MAX_CODE: usize = 64 * 1024 * 1024;
const MAX_DATA: usize = 64 * 1024 * 1024;
const MAX_LEN: usize = 4096;
const MAX_STRINGS: usize = 65536;
/// Instructions allowed between an ARM64 `MOVZ` and the `MOVK` completing it.
const MAX_GAP: usize = 8;

pub(crate) fn extract_macho(
    macho: &MachO<'_>,
    slice_base: u64,
    min: usize,
) -> Vec<ExtractedString> {
    let mut code = None;
    let mut data = Vec::new();
    for segment in &macho.segments {
        let Ok(sections) = segment.sections() else {
            continue;
        };
        for (section, bytes) in sections {
            let kind = section.flags & SECTION_TYPE;
            if section.flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS) != 0 {
                if section.name().ok() == Some("__text") {
                    code = Some(bytes);
                }
            } else if !matches!(kind, S_ZEROFILL | S_GB_ZEROFILL | S_THREAD_LOCAL_ZEROFILL)
                && matches!(section.name(), Ok("__const" | "__data" | "__cstring"))
            {
                // Compiler metadata (Swift reflection, unwind tables) is dense
                // enough to forge a short record by chance; constants are not.
                data.push((section.addr, u64::from(section.offset), bytes));
            }
        }
    }
    if !code.is_some_and(|c| c.len() <= MAX_CODE && materializes_constants(c)) {
        return Vec::new();
    }

    let mut results = Vec::new();
    let mut budget = MAX_DATA;
    for (addr, offset, bytes) in data {
        if budget == 0 {
            break;
        }
        let bytes = &bytes[..bytes.len().min(budget)];
        budget -= bytes.len();
        let Some(base) = slice_base.checked_add(offset) else {
            continue;
        };
        // Records are 4-aligned in memory, not necessarily in the section.
        let mut pos = usize::try_from(addr.wrapping_neg() % 4).unwrap_or(0);
        while pos + 4 <= bytes.len() {
            let Some((value, len)) = record(bytes, pos) else {
                pos += 4;
                continue;
            };
            if value.len() >= min.max(1) {
                results.push(ExtractedString {
                    kind: classify_string(&value),
                    value,
                    data_offset: base + pos as u64,
                    data_len: u32::try_from(len).unwrap_or(u32::MAX),
                    method: StringMethod::XorDecode,
                    ..Default::default()
                });
                if results.len() == MAX_STRINGS {
                    return results;
                }
            }
            // Records never overlap; resume after this one's padding.
            pos += len;
        }
    }
    results
}

/// Whether `code` loads all three mixer constants, as raw little-endian
/// immediates (x86) or as an ARM64 `MOVZ`/`MOVK` pair into one register.
fn materializes_constants(code: &[u8]) -> bool {
    let mut found = CONSTANTS.map(|k| memchr::memmem::find(code, &k.to_le_bytes()).is_some());
    if found.iter().all(|f| *f) {
        return true;
    }
    let mut low: [Option<(usize, u32)>; 32] = [None; 32];
    let (words, _) = code.as_chunks::<4>();
    for (index, word) in words.iter().enumerate() {
        let w = u32::from_le_bytes(*word);
        let rd = (w & 31) as usize;
        let shift = (w >> 21) & 3;
        let imm = (w >> 5) & 0xffff;
        match (w & 0x7f80_0000, shift) {
            (0x5280_0000, 0) => low[rd] = Some((index, imm)),
            (0x7280_0000, 1) => {
                if let Some((at, lo)) = low[rd]
                    && index - at <= MAX_GAP
                    && let Some(k) = CONSTANTS.iter().position(|&k| k == imm << 16 | lo)
                {
                    found[k] = true;
                    if found.iter().all(|f| *f) {
                        return true;
                    }
                }
            }
            _ => {}
        }
    }
    false
}

/// Keystream byte for ciphertext feedback `prev` and running `state`.
fn keystream(prev: u8, state: u32) -> u8 {
    let mut h = u32::from(prev)
        .wrapping_mul(C1.wrapping_add(12))
        .wrapping_add(state);
    h ^= h >> 16;
    h = h.wrapping_mul(C1);
    h ^= h >> 13;
    h = h.wrapping_mul(C2);
    h ^= h >> 8;
    h.to_le_bytes()[0]
}

/// Decrypts the record at `pos`, returning its plaintext and its length in
/// bytes through the padding.
fn record(bytes: &[u8], pos: usize) -> Option<(String, usize)> {
    let seed = u32::from_le_bytes(bytes.get(pos..pos + 4)?.try_into().ok()?);
    let mut prev = seed.to_le_bytes()[0];
    let mut state = seed;
    let mut plain = Vec::new();
    for (i, &c) in bytes.get(pos + 4..)?.iter().take(MAX_LEN + 1).enumerate() {
        let p = c ^ keystream(prev, state);
        if p == 0 {
            let len = (4 + i + 1).next_multiple_of(4);
            let end = pos + len;
            let pad = bytes.get(pos + 4 + i + 1..end)?;
            if plain.is_empty() || pad.iter().any(|b| *b != 0) {
                return None;
            }
            return Some((String::from_utf8(plain).ok()?, len));
        }
        if !(p.is_ascii_graphic() || matches!(p, b' ' | b'\t' | b'\n' | b'\r')) {
            return None;
        }
        plain.push(p);
        prev = c;
        state = state.wrapping_add(GOLDEN);
    }
    None
}

#[cfg(test)]
mod tests;
