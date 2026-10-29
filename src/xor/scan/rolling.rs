//! Short (1-4 byte) rolling keys recovered from known plaintext, as .NET
//! stealers like Redline use.

use super::{Covered, REGION_RADIUS, is_printable_byte_for_file_xor};
use crate::xor::classify::classify_xor_string;
use crate::{ExtractedString, StringMethod};
use aho_corasick::AhoCorasick;
use std::sync::LazyLock;

/// Known plaintext patterns for rolling/index-based XOR detection.
/// These are common Windows environment variables and registry paths
/// found in .NET malware like Redline Stealer.
pub(super) const ROLLING_XOR_PATTERNS: &[&[u8]] = &[
    b"%USERPROFILE%",
    b"%APPDATA%",
    b"%LOCALAPPDATA%",
    b"%TEMP%",
    b"%PROGRAMDATA%",
    b"%SYSTEMROOT%",
    b"%HOMEDRIVE%",
    b"%HOMEPATH%",
    b"HKEY_LOCAL_MACHINE",
    b"HKEY_CURRENT_USER",
    b"HKEY_CLASSES_ROOT",
    b"SOFTWARE\\",
    b"\\Microsoft\\",
];

/// Longest rolling-XOR key tried.
pub(super) const MAX_ROLLING_KEY: usize = 4;

/// Rolling-XOR anchors, one automaton per key length k. In the stream
/// `data[j] ^ data[j - k]` a k-byte cycling key cancels out, so a pattern
/// XOR'd with any such key leaves the fixed signature `p[i] ^ p[i - k]`
/// (i ≥ k) there: one pass finds every pattern under every key of length k.
pub(super) static ROLLING_XOR_ANCHORS: LazyLock<Vec<AhoCorasick>> = LazyLock::new(|| {
    (1..=MAX_ROLLING_KEY)
        .map(|k| {
            let signatures = ROLLING_XOR_PATTERNS
                .iter()
                .map(|p| (k..p.len()).map(|i| p[i] ^ p[i - k]).collect::<Vec<u8>>());
            #[allow(clippy::expect_used)] // static, non-empty patterns
            AhoCorasick::new(signatures).expect("rolling XOR anchors")
        })
        .collect()
});

/// Extract strings using rolling/index-based XOR with known plaintext patterns.
///
/// This function detects XOR obfuscation where the key is short (1-4 bytes) and cycles.
/// It uses known plaintext patterns (Windows environment variables, registry paths)
/// to derive candidate keys, then validates by checking if multiple patterns decode
/// correctly with the same key.
///
/// This is common in .NET malware like Redline Stealer which XORs configuration
/// strings with short cycling keys.
pub(crate) fn extract_rolling_xor_with_known_plaintext(
    data: &[u8],
    min_length: usize,
    excluded_ranges: &[(usize, usize)],
) -> Vec<ExtractedString> {
    let mut results = Vec::new();
    // Offsets inside these are never inspected: code sections up front, then
    // each region already extracted.
    let mut covered = Covered::new(excluded_ranges);

    for key_len in 1..=MAX_ROLLING_KEY {
        let Some(stream_len) = data.len().checked_sub(key_len) else {
            continue;
        };
        let stream: Vec<u8> = (0..stream_len)
            .map(|j| data[j + key_len] ^ data[j])
            .collect();
        // Every (offset, pattern, key) where a pattern decodes under the key
        // derived at that offset, by offset. A match must end before the last
        // byte of `data`.
        let mut hits: Vec<(usize, usize, [u8; MAX_ROLLING_KEY])> = ROLLING_XOR_ANCHORS[key_len - 1]
            .find_overlapping_iter(&stream)
            .filter_map(|m| {
                let (offset, p) = (m.start(), m.pattern().as_usize());
                let pattern = ROLLING_XOR_PATTERNS[p];
                (offset + pattern.len() < data.len()).then(|| {
                    let mut key = [0u8; MAX_ROLLING_KEY];
                    for i in 0..key_len {
                        key[i] = data[offset + i] ^ pattern[i];
                    }
                    (offset, p, key)
                })
            })
            .collect();
        hits.sort_unstable();

        for p in 0..ROLLING_XOR_PATTERNS.len() {
            for &(offset, _, candidate_key) in hits.iter().filter(|h| h.1 == p) {
                if covered.contains(offset) {
                    continue;
                }
                let key = &candidate_key[..key_len];
                // An all-zero key is plaintext; a uniform multi-byte key is
                // a single-byte key, found at length 1.
                if key.iter().all(|&b| b == 0) || (key_len > 1 && key.iter().all(|&b| b == key[0]))
                {
                    continue;
                }
                // Require a second, different pattern within 2 KB under the same key.
                let near = hits.partition_point(|h| h.0 < offset.saturating_sub(2048))
                    ..hits.partition_point(|h| h.0 < offset + 2048);
                if !hits[near].iter().any(|h| h.1 != p && h.2 == candidate_key) {
                    continue;
                }

                // Valid key found — extract strings from an 8KB region around the match
                let region_start = offset.saturating_sub(REGION_RADIUS);
                let region_end = (offset + REGION_RADIUS).min(data.len());
                let region = &data[region_start..region_end];
                covered.insert(region_start, region_end);

                // The key is aligned to `offset`, where the pattern decoded.
                let skew = key_len - (offset - region_start) % key_len;
                let decoded: Vec<u8> = region
                    .iter()
                    .enumerate()
                    .map(|(i, &b)| b ^ key[(i + skew) % key_len])
                    .collect();
                let mut run_start = 0;
                for run in decoded.split(|&b| !is_printable_byte_for_file_xor(b)) {
                    let start = run_start;
                    run_start += run.len() + 1;
                    if run.len() >= min_length
                        && let Ok(s) = std::str::from_utf8(run)
                        && s.bytes().any(|b| b.is_ascii_alphabetic())
                    {
                        results.push(ExtractedString {
                            value: s.to_owned(),
                            data_offset: (region_start + start) as u64,
                            data_len: 0,
                            method: StringMethod::XorDecode,
                            kind: classify_xor_string(s).kind(),
                            fragments: None,
                        });
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
