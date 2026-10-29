//! Instruction pattern analysis for inline string extraction.
//!
//! Inline literals (function arguments, map keys/values) don't create stored
//! pointer+length structures. Instead, compilers pass string addresses and lengths
//! through registers. We extract these by pattern matching instruction sequences.

// This codebase targets 64-bit hosts only: usize = u64, so u64-to-usize casts are lossless.
#![allow(clippy::cast_possible_truncation)]

use super::types::{Arch, ExtractedString};
use amd64::extract_inline_strings_amd64;
use arm64::extract_inline_strings_arm64;
mod amd64;
mod arm64;
mod arm64_preserved;

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
/// The code being scanned, the read-only data its instructions address, and
/// the shortest string worth reporting.
#[derive(Clone, Copy)]
struct Scan<'a> {
    text: &'a [u8],
    text_addr: u64,
    rodata: &'a [u8],
    rodata_addr: u64,
    rodata_end: u64,
    min_length: usize,
}

impl<'a> Scan<'a> {
    fn new(
        text: &'a [u8],
        text_addr: u64,
        rodata: &'a [u8],
        rodata_addr: u64,
        min_length: usize,
    ) -> Self {
        Self {
            text,
            text_addr,
            rodata,
            rodata_addr,
            rodata_end: rodata_addr.saturating_add(rodata.len() as u64),
            min_length,
        }
    }
}

/// Strings that `text`'s instructions address in `target` with an immediate
/// length; empty for an instruction set stng does not decode. Both are
/// `(address, bytes)`.
pub(crate) fn inline_strings(
    arch: Arch,
    (text_addr, text): (u64, &[u8]),
    (target_addr, target): (u64, &[u8]),
    min_length: usize,
) -> Vec<ExtractedString> {
    let mut strings = match arch {
        Arch::Aarch64 => {
            extract_inline_strings_arm64(text, text_addr, target, target_addr, min_length)
        }
        Arch::X86_64 => {
            extract_inline_strings_amd64(text, text_addr, target, target_addr, min_length)
        }
        _ => Vec::new(),
    };
    strings.retain(|s| s.value.len() >= min_length);
    strings
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

/// Check if a string looks like a map/dict key (short, no spaces, identifier-like).
fn looks_like_key(s: &str) -> bool {
    s.len() <= 32
        && !s.contains(' ')
        && !s.starts_with('/')
        && !s.contains("://")
        && s.chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
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
mod tests;
