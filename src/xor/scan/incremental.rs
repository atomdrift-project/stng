//! Incrementing keys, where each byte's key is the previous plus one.

use super::{Covered, REGION_RADIUS, XOR_PATTERNS, is_printable_byte_for_file_xor};
use crate::xor::classify::classify_xor_string;
use crate::{ExtractedString, StringMethod};
use std::sync::LazyLock;

/// Patterns long enough for an incremental-XOR anchor, with their index in
/// [`XOR_PATTERNS`]. Shorter ones produce too many chance hits to be evidence.
pub(super) const MIN_ANCHOR_LEN: usize = 4;

/// The first two encoded bytes of every incremental-XOR `(pattern, seed)`
/// pair, sorted, with a 64-Kbit filter over them. Seed 0 is excluded: that is
/// plain unobfuscated text, which normal extraction already covers.
pub(super) struct IncrementalAnchors {
    /// Bit `h` is set when some pair's encoding starts with the bytes `h`.
    filter: Vec<u64>,
    /// `(first two encoded bytes, pattern index, seed)`, by head.
    pairs: Vec<(u16, u8, u8)>,
}

pub(super) static INCREMENTAL_ANCHORS: LazyLock<IncrementalAnchors> = LazyLock::new(|| {
    let mut filter = vec![0u64; (1 << 16) / 64];
    let mut pairs = Vec::new();
    for (index, pattern) in XOR_PATTERNS.iter().enumerate() {
        if pattern.len() < MIN_ANCHOR_LEN {
            continue;
        }
        for seed in 1u8..=255 {
            let head = u16::from_be_bytes([pattern[0] ^ seed, pattern[1] ^ seed.wrapping_add(1)]);
            filter[usize::from(head) / 64] |= 1 << (head % 64);
            pairs.push((head, index as u8, seed));
        }
    }
    pairs.sort_unstable();
    IncrementalAnchors { filter, pairs }
});

/// Every `(pattern_index, offset, seed)` where `data` decodes to an
/// [`XOR_PATTERNS`] entry under incremental XOR — i.e. where
/// `data[offset + i] ^ (seed + i) == pattern[i]` for the whole pattern.
///
/// The first byte fixes the seed (`seed = data[offset] ^ pattern[0]`), so one
/// pass looking up each offset's first two bytes in [`IncrementalAnchors`]
/// finds every candidate pair, and only those are checked in full. Anchors
/// may overlap; each is independent evidence.
pub(super) fn find_incremental_anchors(data: &[u8]) -> Vec<(usize, usize, u8)> {
    let table = &*INCREMENTAL_ANCHORS;
    let mut anchors = Vec::new();
    for (offset, head) in data.windows(2).enumerate() {
        let head = u16::from_be_bytes([head[0], head[1]]);
        if table.filter[usize::from(head) / 64] & (1 << (head % 64)) == 0 {
            continue;
        }
        let first = table.pairs.partition_point(|p| p.0 < head);
        for &(_, index, seed) in table.pairs[first..].iter().take_while(|p| p.0 == head) {
            let pattern = XOR_PATTERNS[usize::from(index)];
            let decodes = data
                .get(offset..offset + pattern.len())
                .is_some_and(|window| {
                    window
                        .iter()
                        .zip(pattern.iter())
                        .enumerate()
                        .all(|(i, (&d, &p))| d ^ seed.wrapping_add(i as u8) == p)
                });
            if decodes {
                anchors.push((usize::from(index), offset, seed));
            }
        }
    }
    anchors
}

/// Extract strings using incremental XOR detection.
///
/// This function detects XOR obfuscation where the key increments for each byte:
/// `decoded[i] = data[i] ^ (seed + i)`.
///
/// It uses known plaintext patterns to derive candidate seeds, then validates
/// by checking if the pattern decodes correctly.
pub fn extract_incremental_xor_strings(
    data: &[u8],
    min_length: usize,
    excluded_ranges: &[(usize, usize)],
) -> Vec<ExtractedString> {
    let mut results = Vec::new();
    // Pre-seed with excluded_ranges (code sections). The per-offset loop
    // below skips offsets inside any covered range, so code segments are
    // never inspected.
    let mut covered = Covered::new(excluded_ranges);

    // Anchors, in the order the pattern-major/offset-ascending scan this
    // replaces would have found them — covered-range suppression depends on
    // that order, so the sort reproduces it exactly.
    let mut anchors = find_incremental_anchors(data);
    anchors.sort_unstable();

    for (_pattern_idx, offset, seed) in anchors {
        // Seed found! Extract strings from the surrounding 8KB region
        let region_start = offset.saturating_sub(REGION_RADIUS);
        let region_end = (offset + REGION_RADIUS).min(data.len());

        // Sole covered-range guard: skip offsets inside a caller
        // exclusion (e.g. a `.text` code section) or an already-extracted
        // region.
        if covered.contains(offset) {
            continue;
        }
        covered.insert(region_start, region_end);

        let mut pos = region_start;
        while pos < region_end {
            // Find start of printable run
            while pos < region_end {
                let current_key = seed.wrapping_add((pos.wrapping_sub(offset)) as u8);
                let decoded = data[pos] ^ current_key;
                // Skip if raw byte is 0 (key reflection artifact)
                if data[pos] != 0 && is_printable_byte_for_file_xor(decoded) {
                    break;
                }
                pos += 1;
            }

            if pos >= region_end {
                break;
            }

            // Collect printable run
            let start_pos = pos;
            let mut decoded_bytes = Vec::new();
            while pos < region_end {
                let current_key = seed.wrapping_add((pos.wrapping_sub(offset)) as u8);
                let decoded = data[pos] ^ current_key;
                // Stop if raw byte is 0 (key reflection artifact)
                if data[pos] != 0 && is_printable_byte_for_file_xor(decoded) {
                    decoded_bytes.push(decoded);
                    pos += 1;
                } else {
                    break;
                }
            }

            if decoded_bytes.len() >= min_length {
                let mut current_bytes = decoded_bytes;
                let mut current_start = start_pos;

                while current_bytes.len() >= min_length {
                    match String::from_utf8(current_bytes.clone()) {
                        Ok(s) => {
                            // Incremental XOR is high-FP: a single 4-byte anchor
                            // match triggers 4KB of speculative decoding. Only keep
                            // strings that the classifier affirms are meaningful
                            // — unclassified "any-alpha-char" noise should be dropped.
                            if s.chars().any(char::is_alphabetic)
                                && let Some(kind) = classify_xor_string(&s).kind()
                            {
                                results.push(ExtractedString {
                                    value: s,
                                    data_offset: current_start as u64,
                                    data_len: 0,
                                    method: StringMethod::XorDecode,
                                    kind: Some(kind),
                                    fragments: None,
                                });
                            }
                            break;
                        }
                        Err(e) => {
                            let valid_up_to = e.utf8_error().valid_up_to();
                            if valid_up_to >= min_length {
                                let mut valid_bytes = current_bytes.clone();
                                valid_bytes.truncate(valid_up_to);
                                if let Ok(s) = String::from_utf8(valid_bytes)
                                    && s.chars().any(char::is_alphabetic)
                                    && let Some(kind) = classify_xor_string(&s).kind()
                                {
                                    results.push(ExtractedString {
                                        value: s,
                                        data_offset: current_start as u64,
                                        data_len: 0,
                                        method: StringMethod::XorDecode,
                                        kind: Some(kind),
                                        fragments: None,
                                    });
                                }
                            }

                            // Skip the invalid sequence and try again with the rest
                            let error_len = e.utf8_error().error_len().unwrap_or(1);
                            let skip = valid_up_to + error_len;
                            if skip < current_bytes.len() {
                                current_bytes = current_bytes[skip..].to_vec();
                                current_start += skip;
                            } else {
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    // Deduplicate by offset + value
    results.sort_by_key(|s| s.data_offset);
    results.dedup_by(|a, b| a.data_offset == b.data_offset && a.value == b.value);

    results
}

#[cfg(test)]
mod anchor_tests;
