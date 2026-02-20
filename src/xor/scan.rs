//! XOR scanning infrastructure for extracting obfuscated strings.
//!
//! Contains the Aho-Corasick–based XOR pattern automata, multi-byte key extraction,
//! and all `extract_custom_xor_strings` variants.

use super::classify::{
    classify_xor_string, clean_locale_trailing_garbage, clean_url_trailing_garbage,
    trim_consonant_clusters, trim_trailing_garbage,
};
use super::validate::{is_locale_string, is_printable_char};
use super::SKIP_XOR_KEYS;
use crate::validation;
use crate::{ExtractedString, StringKind, StringMethod};
use aho_corasick::AhoCorasick;
use rayon::prelude::*;
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::LazyLock;

/// Minimal high-signal patterns for XOR detection.
/// These short patterns catch a wide variety of malware indicators:
/// - `://` catches all URL schemes (http://, https://, ftp://, etc.)
/// - `/bin` catches Unix shell paths (/bin/sh, /bin/bash)
/// - `C:\` catches Windows paths
/// - `Mozilla` catches user agent strings
/// - `.exe` catches Windows executables (cmd.exe, powershell.exe)
/// - `passw` catches password/passwd variants
/// - `Library` catches macOS paths (/Library/...)
/// - `Ethereum` catches crypto wallet paths
/// - ` %s ` catches format strings (common in C code)
const XOR_PATTERNS: &[&[u8]] = &[
    b"://",
    b"/bin",
    b"C:\\",
    b"Mozilla",
    b".exe",
    b"passw",
    b"Library",
    b"Ethereum",
    b" %s ",
];

/// Metadata for a pattern in the Aho-Corasick automaton.
#[derive(Clone)]
pub(super) struct PatternInfo {
    pub(super) key: u8,
    pub(super) is_wide: bool,
}

/// Cached ASCII-only Aho-Corasick automaton (XOR'd patterns for keys 1..=255).
pub(super) static AUTOMATON_ASCII: LazyLock<(AhoCorasick, Vec<PatternInfo>)> =
    LazyLock::new(|| {
        let mut patterns: Vec<Vec<u8>> = Vec::new();
        let mut pattern_info: Vec<PatternInfo> = Vec::new();
        for key in 1u8..=255u8 {
            if SKIP_XOR_KEYS.contains(&key) {
                continue;
            }
            for prefix in XOR_PATTERNS {
                patterns.push(prefix.iter().map(|b| b ^ key).collect());
                pattern_info.push(PatternInfo {
                    key,
                    is_wide: false,
                });
            }
        }
        let ac = AhoCorasick::new(&patterns).expect("Failed to build automaton");
        (ac, pattern_info)
    });

/// Cached automaton with both ASCII and wide (UTF-16LE) patterns.
/// Used for PE binaries where wide strings are common.
pub(super) static AUTOMATON_WITH_WIDE: LazyLock<(AhoCorasick, Vec<PatternInfo>)> =
    LazyLock::new(|| {
        let mut patterns: Vec<Vec<u8>> = Vec::new();
        let mut pattern_info: Vec<PatternInfo> = Vec::new();
        for key in 1u8..=255u8 {
            if SKIP_XOR_KEYS.contains(&key) {
                continue;
            }
            for prefix in XOR_PATTERNS {
                patterns.push(prefix.iter().map(|b| b ^ key).collect());
                pattern_info.push(PatternInfo {
                    key,
                    is_wide: false,
                });
                patterns.push(prefix.iter().flat_map(|&b| [b ^ key, key]).collect());
                pattern_info.push(PatternInfo { key, is_wide: true });
            }
        }
        let ac = AhoCorasick::new(&patterns).expect("Failed to build automaton");
        (ac, pattern_info)
    });

/// Extract strings decoded with a specified XOR key.
///
/// Applies the given XOR key to the entire binary data and extracts meaningful strings.
/// The key is cycled for multi-byte keys (key[i % `key.len()`]).
///
/// # Arguments
/// * `data` - Binary data to scan
/// * `key` - XOR key bytes (single or multi-byte)
/// * `min_length` - Minimum string length
/// * `enable_early_termination` - If true, stops after finding MAX_STRINGS_BEFORE_EARLY_TERMINATION.
///   Should be true for auto-detection (speeds up candidate testing) and false for user-provided
///   keys (ensures complete extraction).
pub(crate) fn extract_custom_xor_strings(
    data: &[u8],
    key: &[u8],
    min_length: usize,
    enable_early_termination: bool,
) -> Vec<ExtractedString> {
    extract_custom_xor_strings_with_hints(
        data,
        key,
        min_length,
        None,
        true,
        enable_early_termination,
    )
}

/// Extract XOR strings with optional radare2 boundary hints.
/// Hints are tried first, and successful regions are excluded from file-wide scanning.
pub(crate) fn extract_custom_xor_strings_with_hints(
    data: &[u8],
    key: &[u8],
    min_length: usize,
    r2_hints: Option<&[crate::r2::StringBoundary]>,
    apply_filters: bool,
    enable_early_termination: bool,
) -> Vec<ExtractedString> {
    if key.is_empty() || data.is_empty() {
        return Vec::new();
    }

    // Track regions that have been successfully decoded with high quality
    let mut excluded_ranges: Vec<(usize, usize)> = Vec::new();

    // Step 1: Try radare2 hints first if available
    let mut hint_results = Vec::new();
    if let Some(hints) = r2_hints {
        tracing::info!("Trying {} radare2 string boundary hints", hints.len());
        hint_results = extract_xor_strings_from_hints(data, key, min_length, hints, apply_filters);

        // Mark high-quality hint results as excluded from file-wide scanning
        for result in &hint_results {
            if is_high_quality_string(result) {
                let start = result.data_offset as usize;
                let end = start + result.value.len();
                excluded_ranges.push((start, end));
            }
        }

        tracing::info!(
            "Radare2 hints produced {} strings, {} high-quality regions excluded",
            hint_results.len(),
            excluded_ranges.len()
        );
    }

    // Step 2: Continue with normal extraction, excluding hint regions
    extract_custom_xor_strings_filtered_with_exclusions(
        data,
        key,
        min_length,
        apply_filters,
        excluded_ranges,
        hint_results,
        enable_early_termination,
    )
}

fn extract_custom_xor_strings_filtered_with_exclusions(
    data: &[u8],
    key: &[u8],
    min_length: usize,
    apply_filters: bool,
    excluded_ranges: Vec<(usize, usize)>,
    hint_results: Vec<ExtractedString>,
    enable_early_termination: bool,
) -> Vec<ExtractedString> {
    if key.is_empty() || data.is_empty() {
        return Vec::new();
    }

    // Pattern-based XOR extraction:
    // - Scan every offset (each string starts from key[0])
    // - Remove byte-range overlaps (keep longest)
    if key.len() > 1 {
        let mut all_results = extract_custom_xor_strings_pattern_based_simple(
            data,
            key,
            min_length,
            apply_filters,
            &excluded_ranges,
            enable_early_termination,
        );

        // Remove byte-range overlaps: prefer high-value IOCs, then longest string.
        // Network IOCs (URL, IP) are priority 0 so they beat longer Const strings.
        all_results.sort_by_key(|s| {
            let priority = match s.kind {
                StringKind::Url | StringKind::IP | StringKind::IPPort => 0,
                StringKind::SuspiciousPath | StringKind::ShellCmd => 1,
                _ => 2,
            };
            (priority, std::cmp::Reverse(s.value.len()))
        });

        let mut kept = Vec::new();
        for candidate in all_results {
            let cand_start = candidate.data_offset as usize;
            let cand_end = cand_start + candidate.value.len();

            // Check if this byte range overlaps with any kept string
            let overlaps = kept.iter().any(|k: &ExtractedString| {
                let k_start = k.data_offset as usize;
                let k_end = k_start + k.value.len();
                !(cand_end <= k_start || cand_start >= k_end)
            });

            if !overlaps {
                kept.push(candidate);
            }
        }

        // Merge with hint results and apply overlap removal to them too
        for hint in hint_results {
            let hint_start = hint.data_offset as usize;
            let hint_end = hint_start + hint.value.len();

            // Check if this hint overlaps with any kept string
            let overlaps = kept.iter().any(|k: &ExtractedString| {
                let k_start = k.data_offset as usize;
                let k_end = k_start + k.value.len();
                !(hint_end <= k_start || hint_start >= k_end)
            });

            if !overlaps {
                kept.push(hint);
            }
        }

        // Sort by offset for output
        kept.sort_by_key(|s| s.data_offset);

        return kept;
    }

    // Single-byte key: use file-level XOR (simpler, same result either way)
    let mut results = Vec::new();
    let mut seen: HashSet<(u64, String)> = HashSet::new();

    // Decode the entire data with the XOR key
    let decoded: Vec<u8> = data
        .iter()
        .enumerate()
        .map(|(i, &byte)| byte ^ key[i % key.len()])
        .collect();

    // Scan for printable ASCII strings in the decoded data
    let mut start = 0;
    while start < decoded.len() {
        // Find start of printable run
        while start < decoded.len() && !is_printable_char(decoded[start]) {
            start += 1;
        }

        if start >= decoded.len() {
            break;
        }

        // Find end of printable run
        let mut end = start;
        while end < decoded.len() && is_printable_char(decoded[end]) {
            end += 1;
        }

        // Extract and validate the string
        if end - start >= min_length {
            // Check for double-null in original data (at same positions as decoded range)
            let mut double_null_pos = None;
            for offset in 0..(end - start).saturating_sub(1) {
                let raw_pos = start + offset;
                if raw_pos + 1 < data.len() && data[raw_pos] == 0 && data[raw_pos + 1] == 0 {
                    double_null_pos = Some(offset);
                    break;
                }
            }

            // Trim at double-null position if found
            let actual_end = if let Some(trim_pos) = double_null_pos {
                start + trim_pos
            } else {
                end
            };

            // Re-check minimum length after trimming
            if actual_end - start >= min_length {
                if let Ok(s) = String::from_utf8(decoded[start..actual_end].to_vec()) {
                    // Use same filtering as multi-byte XOR: classify + validation::is_garbage() in lib.rs
                    let kind_opt = if apply_filters {
                        classify_xor_string(&s)
                    } else {
                        Some(StringKind::Const)
                    };

                    if let Some(kind) = kind_opt {
                        // Additional sanity check: reject obvious garbage
                        let alnum = s.chars().filter(|c| c.is_alphanumeric()).count();
                        let alpha = s.chars().filter(|c| c.is_alphabetic()).count();

                        // Reject if < 50% alphanumeric (likely garbage)
                        // Use character count for proper Unicode support
                        let char_count = s.chars().count();
                        if char_count > 0 && alnum * 100 < char_count * 50 {
                            continue;
                        }

                        // Reject if has letters but poor vowel ratio (English-specific check)
                        // Only apply to ASCII text - skip for international text (Russian, Chinese, etc.)
                        // Also skip for encoded formats (base64, hex, unicode escapes) which don't have
                        // natural language vowel patterns
                        let is_encoded_format = matches!(
                            kind,
                            StringKind::Base64
                                | StringKind::UnicodeEscaped
                                | StringKind::HexEncoded
                                | StringKind::UrlEncoded
                        );
                        if !is_encoded_format && alpha >= 3 {
                            let has_non_ascii = !s.is_ascii();
                            if !has_non_ascii {
                                // Only check vowels for ASCII/English text
                                let vowels = s
                                    .chars()
                                    .filter(|c| {
                                        matches!(
                                            c.to_ascii_lowercase(),
                                            'a' | 'e' | 'i' | 'o' | 'u'
                                        )
                                    })
                                    .count();
                                let vowel_ratio = if alpha > 0 { vowels * 100 / alpha } else { 0 };
                                if !(10..=70).contains(&vowel_ratio) {
                                    continue;
                                }
                            }
                        }

                        let offset = start as u64;
                        if seen.insert((offset, s.clone())) {
                            let key_preview = if key.len() > 8 {
                                format!("{}...", String::from_utf8_lossy(&key[..8]))
                            } else {
                                String::from_utf8_lossy(key).to_string()
                            };

                            // Clean up URLs by removing trailing garbage
                            let cleaned_value = if matches!(kind, StringKind::Url) {
                                clean_url_trailing_garbage(&s)
                            } else {
                                s.clone()
                            };

                            results.push(ExtractedString {
                                value: cleaned_value,
                                data_offset: offset,
                                section: None,
                                method: StringMethod::XorDecode,
                                kind,
                                library: Some(format!("key:{key_preview}")),
                                fragments: None,
                                ..Default::default()
                            });
                        }
                    }
                }
            }
        }

        start = end + 1;
    }

    results
}

fn is_printable_byte_for_file_xor(b: u8) -> bool {
    // Accept ASCII printable characters
    if b.is_ascii_graphic() || b == b' ' || b == b'\t' || b == b'\n' {
        return true;
    }
    // Accept UTF-8 continuation bytes (0x80-0xBF) and UTF-8 start bytes (0xC0-0xF7)
    // This allows Unicode text (Russian, Chinese, Arabic, etc.) to pass through
    // Invalid UTF-8 will be caught later by String::from_utf8()
    (0x80..=0xF7).contains(&b)
}

/// Try XOR decoding at radare2 string boundary hints.
/// These locations are where r2 found null-terminated strings, making them
/// likely candidates for properly-terminated XOR'd strings.
fn extract_xor_strings_from_hints(
    data: &[u8],
    key: &[u8],
    min_length: usize,
    hints: &[crate::r2::StringBoundary],
    apply_filters: bool,
) -> Vec<ExtractedString> {
    let mut results = Vec::new();
    let mut seen: HashSet<(u64, String)> = HashSet::new();

    for hint in hints {
        let offset = hint.offset as usize;
        let max_len = hint.length;

        if offset >= data.len() {
            continue;
        }

        // Try file-level cycling (all key offsets)
        for key_offset in 0..key.len() {
            let mut decoded = Vec::new();
            let mut end = offset;

            // Decode up to hint.length bytes or until we hit non-printable
            while end < data.len() && (end - offset) < max_len {
                let actual_offset = end;
                let ki = (actual_offset + key_offset) % key.len();
                let decoded_byte = data[end] ^ key[ki];

                if is_printable_byte_for_file_xor(decoded_byte) {
                    decoded.push(decoded_byte);
                    end += 1;
                } else {
                    break;
                }
            }

            if decoded.len() < min_length {
                continue;
            }

            if let Ok(s) = String::from_utf8(decoded) {
                // Skip XOR key artifacts
                if apply_filters && is_xor_key_artifact(&s, key) {
                    continue;
                }

                // Classify
                let kind_opt = if apply_filters {
                    classify_xor_string(&s)
                } else {
                    Some(StringKind::Const)
                };

                if let Some(kind) = kind_opt {
                    if seen.insert((offset as u64, s.clone())) {
                        let key_preview = if key.len() > 8 {
                            format!("{}...", String::from_utf8_lossy(&key[..8]))
                        } else {
                            String::from_utf8_lossy(key).to_string()
                        };

                        results.push(ExtractedString {
                            value: s,
                            data_offset: offset as u64,
                            section: None,
                            method: StringMethod::XorDecode,
                            kind,
                            library: Some(format!("key:{key_preview}@hint")),
                            fragments: None,
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }

    results
}

/// Check if a string is high quality (worth excluding its region from file-wide scanning).
fn is_high_quality_string(s: &ExtractedString) -> bool {
    // High quality = shell commands, suspicious paths, URLs, crypto terms
    matches!(
        s.kind,
        StringKind::ShellCmd | StringKind::SuspiciousPath | StringKind::Url | StringKind::IP
    ) || {
        let vl = s.value.to_ascii_lowercase();
        vl.contains("ethereum") || vl.contains("bitcoin") || vl.contains("osascript")
    } || s.value.len() >= 30 // Long strings are usually significant
}

/// Check if a decoded string is likely just the XOR key itself (or fragments).
/// This happens when `XORing` null bytes with the key.
fn is_xor_key_artifact(s: &str, key: &[u8]) -> bool {
    // Convert key to string for comparison
    let key_str = String::from_utf8_lossy(key);

    // Exact match or substring of key
    if key_str.contains(s) || s.contains(key_str.as_ref()) {
        return true;
    }

    // Check if string is mostly composed of repeating key pattern
    // (happens when XORing the key with itself or null bytes)
    if s.len() >= key.len() {
        // Count how many characters match the key pattern
        let mut matches = 0;
        for (i, c) in s.chars().enumerate() {
            let key_char = key[i % key.len()] as char;
            if c == key_char {
                matches += 1;
            }
        }

        // If >70% of the string matches the key pattern, it's likely an artifact
        if (matches as u64 * 100) / s.len() as u64 > 70 {
            return true;
        }
    }

    // Check for key fragments (at least 8 consecutive chars from the key)
    if key.len() >= 8 {
        for window_size in (8..=key.len().min(s.len())).rev() {
            let key_str_bytes = key_str.as_bytes();
            for key_start in 0..=(key.len().saturating_sub(window_size)) {
                let key_fragment = &key_str_bytes[key_start..key_start + window_size];
                if let Ok(fragment_str) = std::str::from_utf8(key_fragment) {
                    if s.contains(fragment_str) {
                        return true;
                    }
                }
            }
        }
    }

    false
}

/// Maximum number of valid strings to find before early termination.
/// After finding this many validated strings (of any kind), we can stop scanning.
/// This provides diminishing returns - 50 strings is typically enough to identify
/// XOR-encoded content and extract key IOCs without scanning the entire file.
/// Testing shows this reduces scan time by 10-100x while preserving malware detection.
const MAX_STRINGS_BEFORE_EARLY_TERMINATION: usize = 50;

/// Simplified pattern-based extraction matching decode.py behavior.
/// Scans every offset, no overlap skipping, minimal filtering.
///
/// # Arguments
/// * `enable_early_termination` - If true, stops after finding MAX_STRINGS_BEFORE_EARLY_TERMINATION.
///   Should be true for auto-detection (speeds up candidate testing) and false for user-provided
///   keys (ensures complete extraction).
fn extract_custom_xor_strings_pattern_based_simple(
    data: &[u8],
    key: &[u8],
    min_length: usize,
    apply_filters: bool,
    excluded_ranges: &[(usize, usize)],
    enable_early_termination: bool,
) -> Vec<ExtractedString> {
    let start_time = std::time::Instant::now();

    let key_preview = if key.len() > 8 {
        format!("{}...", String::from_utf8_lossy(&key[..8]))
    } else {
        String::from_utf8_lossy(key).to_string()
    };

    // Track number of valid strings found across all parallel threads for early termination
    let strings_found = AtomicUsize::new(0);

    // Each position is independent, so process in parallel.
    // Use data.len() rather than data.len()-min_length: the inner length check filters
    // short results, and data.len()-min_length is off-by-one when data is exactly min_length.
    //
    // with_min_len coarsens granularity: without it, Rayon creates one task per byte offset
    // (potentially millions), and task dispatch/stealing overhead dominates. With min_len=4096,
    // each Rayon task processes a contiguous block of 4096 offsets, reducing task count to
    // data.len()/4096 ≈ a few hundred tasks for typical binaries.
    let results: Vec<ExtractedString> = (0..data.len())
        .into_par_iter()
        .with_min_len(4096)
        .filter_map(|pos| {
            // Early termination (only when enabled - typically for auto-detection):
            // After finding enough strings, additional matches provide diminishing returns.
            // This speeds up auto-detection 10-100x without missing key IOCs.
            if enable_early_termination
                && strings_found.load(Ordering::Relaxed) >= MAX_STRINGS_BEFORE_EARLY_TERMINATION
            {
                return None;
            }

            // XOR decode while printable: data[pos+j] ^ key[j % len(key)]
            // Fast early exit: if the first decoded byte is not printable, skip this position
            // immediately without any allocation or excluded-range check. Most positions fail
            // this single-byte test, so doing it first dramatically reduces overhead.
            let key_len = key.len();
            if !is_printable_byte_for_file_xor(data[pos] ^ key[0]) {
                return None;
            }

            // Skip excluded ranges (only checked after the fast printable pre-filter)
            if excluded_ranges
                .iter()
                .any(|&(start, end)| pos >= start && pos < end)
            {
                return None;
            }

            let mut decoded = Vec::new();

            // Track positions of single nulls in raw data (potential garbage boundaries)
            let mut null_positions = Vec::new();

            let max_len = std::cmp::min(1024, data.len() - pos);
            for j in 0..max_len {
                let raw = data[pos + j];
                let byte = raw ^ key[j % key_len];

                // Check for consecutive nulls in raw data (indicates end of actual string data),
                // but only stop if the XOR-decoded byte is also non-printable. When the decoded
                // byte is printable, the null is part of the encrypted payload, not zero padding.
                if raw == 0 && pos + j + 1 < data.len() && data[pos + j + 1] == 0 {
                    if !is_printable_byte_for_file_xor(byte) {
                        break;
                    }
                    // Single null at this position (consecutive null handled above)
                    null_positions.push(j);
                } else if raw == 0 {
                    // Single null (not followed by another null) - potential garbage boundary
                    null_positions.push(j);
                }

                if is_printable_byte_for_file_xor(byte) {
                    decoded.push(byte);
                } else {
                    break;
                }
            }

            // Trim at null boundaries if we detect garbage (consonant clusters)
            // Check all nulls, trim at the first one followed by garbage
            // Skip null at position 0 (start of string) as it's not a garbage boundary
            let mut trim_at: Option<usize> = None;
            for &null_pos in &null_positions {
                if null_pos == 0 {
                    continue; // Don't trim at start of string (inner loop continue, not outer)
                }
                if null_pos < decoded.len() {
                    let after_null = &decoded[null_pos..];
                    // Need at least 2 chars after null to detect garbage (e.g., "aTr")
                    if after_null.len() >= 2 {
                        let s_after = String::from_utf8_lossy(after_null);

                        // Count the longest run of *consecutive* ASCII consonants
                        // in the first 4 chars. A vowel in the middle resets the
                        // count, so "nder" (n-d-e-r) only scores 2 (n,d before the
                        // 'e'), whereas "zXkm" scores 4. This avoids trimming valid
                        // English suffixes like "-nder" in "Finder" while still
                        // cutting genuine garbage consonant clusters.
                        let check_len = after_null.len().min(4);
                        let max_consecutive = s_after
                            .chars()
                            .take(check_len)
                            .fold((0u32, 0u32), |(max, cur), c| {
                                if c.is_ascii_alphabetic() {
                                    let is_vowel = matches!(
                                        c.to_ascii_lowercase(),
                                        'a' | 'e' | 'i' | 'o' | 'u'
                                    );
                                    if is_vowel {
                                        (max, 0)
                                    } else {
                                        let next = cur + 1;
                                        (max.max(next), next)
                                    }
                                } else {
                                    (max, 0)
                                }
                            })
                            .0;

                        if max_consecutive >= 3 {
                            trim_at = Some(null_pos);
                            break; // Trim at first garbage boundary
                        }
                    }
                }
            }

            if let Some(trim_pos) = trim_at {
                decoded.truncate(trim_pos);
            }

            // Check minimum length after trimming
            if decoded.len() < min_length {
                return None;
            }

            // Convert to string - if full conversion fails, try to salvage valid UTF-8 prefix
            let s = match String::from_utf8(decoded) {
                Ok(s) => s,
                Err(e) => {
                    // UTF-8 conversion failed - try to salvage the valid prefix
                    // This handles cases where valid ASCII/UTF-8 data is followed by garbage
                    let valid_up_to = e.utf8_error().valid_up_to();
                    if valid_up_to >= min_length {
                        // We have enough valid UTF-8 data - recover bytes and use valid prefix
                        let mut bytes = e.into_bytes();
                        bytes.truncate(valid_up_to);
                        match String::from_utf8(bytes) {
                            Ok(s) => s,
                            Err(_) => return None, // Still invalid, skip
                        }
                    } else {
                        // Not enough valid data
                        return None;
                    }
                }
            };

            // Must have at least one letter, unless it's a known shell redirect/operator
            let is_shell_op = s.contains("2>&") || s.contains("2>/") || s.contains("1>&");
            if !is_shell_op && !s.chars().any(char::is_alphabetic) {
                return None;
            }

            // Apply early trimming before classification to remove obvious garbage
            // This ensures classification sees clean strings
            let trimmed_s = trim_consonant_clusters(&s);

            // Re-check minimum length after consonant cluster trimming
            if trimmed_s.len() < min_length {
                return None;
            }

            // Classify the string. When apply_filters=true, reject unclassified strings.
            // When apply_filters=false, still classify to assign the correct kind for
            // overlap resolution (IOCs win over generic Const strings of similar length).
            let kind = match classify_xor_string(&trimmed_s) {
                Some(k) => k,
                None => {
                    if apply_filters {
                        return None; // Filter rejected this string
                    }
                    StringKind::Const
                }
            };

            // Additional sanity check: reject obvious garbage even if classify passed it
            // Be especially strict when using automatically detected keys (paths)
            let key_is_likely_auto_detected =
                key_preview.starts_with('/') || key_preview.starts_with("C:\\");

            let alnum = trimmed_s
                .chars()
                .filter(|c: &char| c.is_alphanumeric())
                .count();
            let alpha = trimmed_s
                .chars()
                .filter(|c: &char| c.is_alphabetic())
                .count();

            // For auto-detected keys, require at least 60% alphanumeric (stricter)
            // For user-provided keys, require at least 50% alphanumeric
            // Use character count for proper Unicode support
            let char_count = trimmed_s.chars().count();
            let min_alnum_pct = if key_is_likely_auto_detected { 60 } else { 50 };
            if char_count > 0 && alnum * 100 < char_count * min_alnum_pct {
                return None;
            }

            // Reject if has letters but poor vowel ratio (linguistic check)
            // Only apply to ASCII/English text - skip for international text (Russian, Chinese, etc.)
            // Also skip for locale codes (e.g., zh_CN, fr_FR) which lack vowels by definition.
            // Skip for network IOCs (URLs, IPs which naturally contain consonant-heavy protocol
            // names like "http" or "ftp"). Always apply for other string types regardless of
            // apply_filters, since vowel ratio is a reliable noise filter even in unfiltered mode.
            let is_network_ioc =
                matches!(kind, StringKind::Url | StringKind::IP | StringKind::IPPort);
            if !is_network_ioc && alpha >= 3 && !is_locale_string(&trimmed_s) {
                let has_non_ascii = !trimmed_s.is_ascii();
                if !has_non_ascii {
                    // Only check vowels for ASCII/English text
                    let vowels = trimmed_s
                        .chars()
                        .filter(|c: &char| {
                            matches!(c.to_ascii_lowercase(), 'a' | 'e' | 'i' | 'o' | 'u')
                        })
                        .count();
                    let vowel_ratio = if alpha > 0 { vowels * 100 / alpha } else { 0 };

                    // For auto-detected keys, be stricter with vowel ratios
                    let (min_vowel, max_vowel) = if key_is_likely_auto_detected {
                        (12, 65) // Stricter range matching is_meaningful_string
                    } else {
                        (10, 70) // Slightly more lenient for user keys
                    };

                    if vowel_ratio < min_vowel || vowel_ratio > max_vowel {
                        return None;
                    }
                }
            }

            // Apply category-specific fine-tuning after consonant cluster trimming
            let cleaned_value = if matches!(kind, StringKind::Url) {
                clean_url_trailing_garbage(&trimmed_s)
            } else if matches!(kind, StringKind::SuspiciousPath) && is_locale_string(&trimmed_s) {
                clean_locale_trailing_garbage(&trimmed_s)
            } else if matches!(kind, StringKind::SuspiciousPath) {
                // Trim trailing backtick+letter pattern: XOR misalignment can produce e.g. `R at the end
                let s = trimmed_s.as_str();
                let bytes = s.as_bytes();
                if bytes.len() >= 2 {
                    if let Some(idx) = bytes.iter().rposition(|&b: &u8| b.is_ascii_alphabetic()) {
                        if idx > 0 && bytes[idx - 1] == b'`' {
                            s[..idx - 1].to_string()
                        } else {
                            trimmed_s
                        }
                    } else {
                        trimmed_s
                    }
                } else {
                    trimmed_s
                }
            } else if matches!(kind, StringKind::ShellCmd) {
                // For shell commands and AppleScript, use the existing trimmer
                trim_trailing_garbage(&trimmed_s).to_string()
            } else {
                trimmed_s
            };

            // Category-specific cleaning (URL trailing garbage, shell cmd trimming, etc.) can
            // shorten the string below min_length. Re-check after cleaning.
            if cleaned_value.len() < min_length {
                return None;
            }

            // Pre-filter garbage before overlap removal: a garbage string that wins the overlap
            // contest would leave the byte range uncovered (the garbage gets removed in post-processing
            // but nothing else can fill that range). Skip it here so shorter, valid strings can win.
            //
            // Strings with embedded control characters (except tab/newline) are garbage.
            // Newlines are valid in multi-line XOR payloads (AppleScript, shell commands, etc.).
            let has_embedded_control = cleaned_value
                .bytes()
                .any(|b| b < 0x20 && b != b'\t' && b != b'\n');
            if has_embedded_control || validation::is_garbage(&cleaned_value) {
                return None;
            }

            // Increment counter for early termination tracking
            strings_found.fetch_add(1, Ordering::Relaxed);

            Some(ExtractedString {
                value: cleaned_value,
                data_offset: pos as u64,
                section: None,
                method: StringMethod::XorDecode,
                kind,
                library: Some(format!("key:{}", key_preview)),
                fragments: None,
                ..Default::default()
            })
        })
        .collect();

    // Restore position order so the caller's overlap-removal logic is deterministic.
    // (par_iter does not preserve insertion order.)
    let mut results: Vec<ExtractedString> = results;
    results.sort_by_key(|s| s.data_offset);

    let final_count = strings_found.load(Ordering::Relaxed);
    if final_count >= MAX_STRINGS_BEFORE_EARLY_TERMINATION {
        tracing::info!(
            "XOR scan: {} strings in {:.2}s (early termination after {} strings)",
            results.len(),
            start_time.elapsed().as_secs_f64(),
            final_count
        );
    } else {
        tracing::info!(
            "XOR scan: {} strings in {:.2}s",
            results.len(),
            start_time.elapsed().as_secs_f64()
        );
    }

    results
}
