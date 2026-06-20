//! XOR scanning infrastructure for extracting obfuscated strings.
//!
//! Contains the Aho-Corasick–based XOR pattern automata, multi-byte key extraction,
//! rolling/index-based XOR detection for Windows environment variables,
//! and all `extract_custom_xor_strings` variants.

// This codebase targets 64-bit hosts only: usize = u64, so u64-to-usize casts are lossless.
#![allow(clippy::cast_possible_truncation)]

use super::SKIP_XOR_KEYS;
use super::classify::{
    classify_xor_string, clean_locale_trailing_garbage, clean_url_trailing_garbage,
    trim_consonant_clusters, trim_trailing_garbage,
};
use super::validate::is_locale_string;
use crate::validation;
use crate::{ExtractedString, StringKind, StringMethod};
use aho_corasick::AhoCorasick;
use rayon::prelude::*;
use std::collections::{BTreeMap, HashSet};
use std::sync::LazyLock;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Minimal high-signal patterns for XOR detection.
/// These short patterns catch a wide variety of malware indicators:
/// - `://` catches all URL schemes (http://, https://, ftp://, etc.)
/// - `/bin` catches Unix shell paths (/bin/sh, /bin/bash)
/// - `/proc` catches Linux process/network hiding rootkits (/proc/net/tcp, /proc/self/exe)
/// - `C:\` catches Windows paths
/// - `Mozilla` catches user agent strings
/// - `.exe` catches Windows executables (cmd.exe, powershell.exe)
/// - `.dll` catches Windows DLL names (bcrypt.dll, user32.dll) - common in covert dynamic loading
/// - `passw` catches password/passwd variants
/// - `Library` catches macOS paths (/Library/...)
/// - `Ethereum` catches crypto wallet paths
/// - ` %s ` catches format strings (common in C code)
/// - `ld.so` catches LD_PRELOAD rootkit injection (ld.so.preload)
/// - `BCrypt` catches Windows crypto API names (BCryptOpenAlgorithmProvider, etc.)
/// - `CreateProcess` catches process injection API names
pub(super) const XOR_PATTERNS: &[&[u8]] = &[
    b"://",
    b"/bin",
    b"/proc",
    b"C:\\",
    b"Mozilla",
    b".exe",
    b".dll",
    b"passw",
    b"Library",
    b"Ethereum",
    b" %s ",
    b"ld.so",
    b"BCrypt",
    b"CreateProcess",
];

/// Metadata for a pattern in the Aho-Corasick automaton.
#[derive(Clone)]
pub(super) struct PatternInfo {
    pub(super) key: u8,
    pub(super) is_wide: bool,
}

/// Cached ASCII-only Aho-Corasick automaton (XOR'd patterns for keys 1..=255).
#[allow(clippy::expect_used)]
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
#[allow(clippy::expect_used)]
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
        hint_results = extract_xor_strings_from_hints(data, key, min_length, hints, apply_filters);

        // Mark high-quality hint results as excluded from file-wide scanning
        for result in &hint_results {
            if is_high_quality_string(result) {
                let start = result.data_offset as usize;
                let end = start + result.value.len();
                excluded_ranges.push((start, end));
            }
        }
    }

    // Step 2: Continue with normal extraction, excluding hint regions
    extract_custom_xor_strings_filtered_with_exclusions(
        data,
        key,
        min_length,
        apply_filters,
        &excluded_ranges,
        hint_results,
        enable_early_termination,
    )
}

fn extract_custom_xor_strings_filtered_with_exclusions(
    data: &[u8],
    key: &[u8],
    min_length: usize,
    apply_filters: bool,
    excluded_ranges: &[(usize, usize)],
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
            excluded_ranges,
            enable_early_termination,
        );

        // Remove byte-range overlaps: prefer high-value IOCs, then longest string.
        // Network IOCs (URL, IP) are priority 0 so they beat longer Const strings.
        all_results.sort_by_key(|s| {
            let priority = match s.kind {
                Some(StringKind::Url) | Some(StringKind::IP) | Some(StringKind::IPPort) => 0,
                Some(StringKind::SuspiciousPath) | Some(StringKind::ShellCmd) => 1,
                _ => 2,
            };
            (priority, std::cmp::Reverse(s.value.len()))
        });

        // A candidate's byte range overlaps a kept string when neither sits wholly
        // before the other. Kept intervals are non-overlapping by construction, so a
        // new range can only collide with its nearest neighbour on each side — index
        // them by start offset (`start -> end`) for O(log k) checks instead of O(k).
        let mut kept = Vec::new();
        let mut kept_intervals: BTreeMap<usize, usize> = BTreeMap::new();
        let overlaps = |intervals: &BTreeMap<usize, usize>, start: usize, end: usize| {
            // Nearest interval starting at or before `start`: collides if it reaches past `start`.
            if let Some((_, &p_end)) = intervals.range(..=start).next_back()
                && p_end > start
            {
                return true;
            }
            // Nearest interval starting after `start`: collides if it begins before `end`.
            if let Some((&s_start, _)) = intervals.range(start..).next()
                && s_start < end
            {
                return true;
            }
            false
        };

        for candidate in all_results {
            let start = candidate.data_offset as usize;
            let end = start + candidate.value.len();
            if !overlaps(&kept_intervals, start, end) {
                kept_intervals.insert(start, end);
                kept.push(candidate);
            }
        }

        // Merge with hint results and apply overlap removal to them too
        for hint in hint_results {
            let start = hint.data_offset as usize;
            let end = start + hint.value.len();
            if !overlaps(&kept_intervals, start, end) {
                kept_intervals.insert(start, end);
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

    // Scan for printable ASCII strings in the decoded data.
    // Single-byte XOR keys produce many false-positive "printable" bytes in the 0x80..=0xF7
    // range from code sections. Restricting to ASCII-only eliminates coincidental UTF-8
    // sequences that cause O(N) Unicode char iteration on garbage strings.
    let is_ascii_printable = |b: u8| b.is_ascii_graphic() || b == b' ' || b == b'\t';

    let mut start = 0;
    while start < decoded.len() {
        // Find start of printable run
        while start < decoded.len() && !is_ascii_printable(decoded[start]) {
            start += 1;
        }

        if start >= decoded.len() {
            break;
        }

        // Find end of printable run
        let mut end = start;
        while end < decoded.len() && is_ascii_printable(decoded[end]) {
            end += 1;
        }

        // Extract and validate the string.
        // IMPORTANT: advance start before any early-exit to prevent infinite loops —
        // `continue` inside the inner block would otherwise re-scan the same run.
        let run_start = start;
        start = end + 1; // always advance, regardless of what happens below

        if end - run_start >= min_length {
            // Skip strings decoded from null-heavy regions (key reflection artifact)
            let raw_null_count = data[run_start..end].iter().filter(|&&b| b == 0).count();
            if raw_null_count * 2 > (end - run_start) {
                continue;
            }

            // Check for double-null in original data (at same positions as decoded range)
            let mut double_null_pos = None;
            for offset in 0..(end - run_start).saturating_sub(1) {
                let raw_pos = run_start + offset;
                if raw_pos + 1 < data.len() && data[raw_pos] == 0 && data[raw_pos + 1] == 0 {
                    double_null_pos = Some(offset);
                    break;
                }
            }

            // Trim at double-null position if found
            let actual_end = if let Some(trim_pos) = double_null_pos {
                run_start + trim_pos
            } else {
                end
            };

            // Re-check minimum length after trimming
            if actual_end - run_start >= min_length
                && let Ok(s) = String::from_utf8(decoded[run_start..actual_end].to_vec())
            {
                // Always classify to determine kind — used for vowel ratio bypass below.
                // When apply_filters is false, accept all classified strings (no rejection).
                let kind_opt = classify_xor_string(&s);

                if let Some(kind) = kind_opt {
                    // Additional sanity check: reject obvious garbage.
                    // Since single-byte XOR uses ASCII-only run detection, all strings are ASCII;
                    // use fast byte-based counting instead of slow Unicode char iteration.
                    let alnum = s.bytes().filter(u8::is_ascii_alphanumeric).count();
                    let alpha = s.bytes().filter(u8::is_ascii_alphabetic).count();

                    // Reject if < 50% alphanumeric (likely garbage)
                    let char_count = s.len(); // ASCII: len == char count
                    if char_count > 0 && alnum * 100 < char_count * 50 {
                        continue;
                    }

                    // Reject if has letters but poor vowel ratio (English-specific check).
                    // Skip for encoded formats (base64, hex, etc.) and high-value IOCs
                    // (SuspiciousPath/ShellCmd) which may not follow English vowel patterns.
                    // DLL names (bcrypt.dll), API names (BCryptDecrypt), and shell commands
                    // are valid targets even with 0% vowels.
                    let is_encoded_format = matches!(
                        kind,
                        Some(StringKind::Base64)
                            | Some(StringKind::UnicodeEscaped)
                            | Some(StringKind::HexEncoded)
                            | Some(StringKind::UrlEncoded)
                            | Some(StringKind::SuspiciousPath)
                            | Some(StringKind::ShellCmd)
                    );
                    if !is_encoded_format && alpha >= 3 {
                        let vowels = s
                            .bytes()
                            .filter(|&b| {
                                matches!(b.to_ascii_lowercase(), b'a' | b'e' | b'i' | b'o' | b'u')
                            })
                            .count();
                        let vowel_ratio = (vowels * 100).checked_div(alpha).unwrap_or(0);
                        if !(10..=70).contains(&vowel_ratio) {
                            continue;
                        }
                    }

                    let offset = run_start as u64;
                    if seen.insert((offset, s.clone())) {
                        // Use hex format consistent with the AC scan path ("xor:0xNN").
                        let source_tag = format!("xor:0x{:02X}", key[0]);

                        // Clean up URLs by removing trailing garbage
                        let cleaned_value = if matches!(kind, Some(StringKind::Url)) {
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
                            source: Some(source_tag),
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

/// Short, printable rendering of a key for `source` provenance strings.
fn key_preview(key: &[u8]) -> String {
    if key.len() > 8 {
        format!("{}...", String::from_utf8_lossy(&key[..8]))
    } else {
        String::from_utf8_lossy(key).into_owned()
    }
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

            // Skip strings decoded from null-heavy regions (key reflection artifact)
            let raw_null_count = data[offset..end].iter().filter(|&&b| b == 0).count();
            if raw_null_count * 2 > (end - offset) {
                continue;
            }

            if let Ok(s) = String::from_utf8(decoded) {
                // Skip XOR key artifacts
                if apply_filters && is_xor_key_artifact(&s, key) {
                    continue;
                }

                // Always classify so IOC-aware handling stays consistent between
                // hint-based extraction and file-wide scanning. In unfiltered mode
                // we still keep unclassified strings if classify_xor_string accepts them.
                let kind_opt = classify_xor_string(&s);

                if let Some(kind) = kind_opt
                    && seen.insert((offset as u64, s.clone()))
                {
                    let key_preview = key_preview(key);

                    results.push(ExtractedString {
                        value: s,
                        data_offset: offset as u64,
                        section: None,
                        method: StringMethod::XorDecode,
                        kind,
                        source: Some(format!("xor:key:{key_preview}@hint")),
                        fragments: None,
                        ..Default::default()
                    });
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
        Some(StringKind::ShellCmd)
            | Some(StringKind::SuspiciousPath)
            | Some(StringKind::Url)
            | Some(StringKind::IP)
    ) || s.value.len() >= 30 // Long strings are usually significant
        || {
            // Only the short, unclassified residual reaches the (allocating) lowercase scan.
            let vl = s.value.to_ascii_lowercase();
            vl.contains("ethereum") || vl.contains("bitcoin") || vl.contains("osascript")
        }
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
        let mut matches = 0usize;
        for (i, c) in s.chars().enumerate() {
            let key_char = key[i % key.len()] as char;
            if c == key_char {
                matches += 1;
            }
        }

        // If >70% of the string matches the key pattern, it's likely an artifact
        if (matches * 100) / s.len() > 70 {
            return true;
        }
    }

    // Check for key fragments (at least 8 consecutive chars from the key)
    if key.len() >= 8 {
        for window_size in (8..=key.len().min(s.len())).rev() {
            let key_str_bytes = key_str.as_bytes();
            for key_start in 0..=(key.len().saturating_sub(window_size)) {
                let key_fragment = &key_str_bytes[key_start..key_start + window_size];
                if let Ok(fragment_str) = std::str::from_utf8(key_fragment)
                    && s.contains(fragment_str)
                {
                    return true;
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
    let key_preview = key_preview(key);

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
    let mut results: Vec<ExtractedString> = (0..data.len())
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
                        // Count the longest run of consecutive ASCII consonants
                        // in the first 4 bytes. Operate directly on bytes — no
                        // UTF-8 conversion needed since we only check ASCII letters.
                        let check_len = after_null.len().min(4);
                        let max_consecutive = after_null[..check_len]
                            .iter()
                            .fold((0u32, 0u32), |(max, cur), &b| {
                                if b.is_ascii_alphabetic() {
                                    let is_vowel = matches!(
                                        b.to_ascii_lowercase(),
                                        b'a' | b'e' | b'i' | b'o' | b'u'
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

            // Skip strings decoded from null-heavy regions. When raw bytes are
            // mostly zero the XOR output is just the key text reflected back —
            // not actual encrypted content.
            let raw_null_count = data[pos..pos + decoded.len()]
                .iter()
                .filter(|&&b| b == 0)
                .count();
            if raw_null_count * 2 > decoded.len() {
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
                    None
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
            let is_network_ioc = matches!(
                kind,
                Some(StringKind::Url) | Some(StringKind::IP) | Some(StringKind::IPPort)
            );
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
                    let vowel_ratio = (vowels * 100).checked_div(alpha).unwrap_or(0);

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
            let cleaned_value = if matches!(kind, Some(StringKind::Url)) {
                clean_url_trailing_garbage(&trimmed_s)
            } else if matches!(kind, Some(StringKind::SuspiciousPath))
                && is_locale_string(&trimmed_s)
            {
                clean_locale_trailing_garbage(&trimmed_s)
            } else if matches!(kind, Some(StringKind::SuspiciousPath)) {
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
            } else if matches!(kind, Some(StringKind::ShellCmd)) {
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
                source: Some(format!("xor:key:{}", key_preview)),
                fragments: None,
                ..Default::default()
            })
        })
        .collect();

    // Restore position order so the caller's overlap-removal logic is deterministic.
    // (par_iter does not preserve insertion order.)
    results.sort_by_key(|s| s.data_offset);

    results
}

/// Known plaintext patterns for rolling/index-based XOR detection.
/// These are common Windows environment variables and registry paths
/// found in .NET malware like Redline Stealer.
const ROLLING_XOR_PATTERNS: &[&[u8]] = &[
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
    // Pre-seed covered_ranges with excluded_ranges (code sections). The
    // while-loop below already skips offsets inside any covered range, so
    // code segments are never inspected.
    let mut covered_ranges: Vec<(usize, usize)> = excluded_ranges.to_vec();

    // Try key lengths from 1 to 4 bytes
    for key_len in 1..=4usize {
        for pattern in ROLLING_XOR_PATTERNS {
            if pattern.len() < key_len {
                continue;
            }

            let max_offset = data.len().saturating_sub(pattern.len());
            let mut offset = 0;
            while offset < max_offset {
                // Skip offsets inside already-extracted regions
                if let Some(&(_, end)) = covered_ranges
                    .iter()
                    .find(|&&(start, end)| offset >= start && offset < end)
                {
                    offset = end;
                    continue;
                }

                // Derive candidate key on the stack (max 4 bytes)
                let mut candidate_key = [0u8; 4];
                candidate_key[..key_len]
                    .iter_mut()
                    .zip(&data[offset..])
                    .zip(pattern.iter())
                    .for_each(|((slot, &d), &p)| *slot = d ^ p);

                // Skip keys that are all zeros
                if candidate_key[..key_len].iter().all(|&b| b == 0) {
                    offset += 1;
                    continue;
                }
                // Skip keys where all bytes are identical (likely false positive)
                if key_len > 1
                    && candidate_key[..key_len]
                        .iter()
                        .all(|&b| b == candidate_key[0])
                {
                    offset += 1;
                    continue;
                }

                // Validate: does entire pattern decode correctly with this key?
                // Inline comparison — no allocation needed.
                let valid = (0..pattern.len())
                    .all(|i| (data[offset + i] ^ candidate_key[i % key_len]) == pattern[i]);
                if !valid {
                    offset += 1;
                    continue;
                }

                // Count how many OTHER patterns also decode correctly nearby
                let mut pattern_matches = 1u32;
                for other_pattern in ROLLING_XOR_PATTERNS {
                    if std::ptr::eq((*pattern).as_ptr(), (*other_pattern).as_ptr()) {
                        continue;
                    }

                    let search_start = offset.saturating_sub(2048);
                    let search_end =
                        (offset + 2048).min(data.len().saturating_sub(other_pattern.len()));

                    // Inline byte-wise XOR comparison — no allocation
                    if (search_start..search_end).any(|check_offset| {
                        (0..other_pattern.len()).all(|i| {
                            (data[check_offset + i] ^ candidate_key[i % key_len])
                                == other_pattern[i]
                        })
                    }) {
                        pattern_matches += 1;
                    }
                }

                if pattern_matches < 2 {
                    offset += 1;
                    continue;
                }

                // Valid key found — extract strings from an 8KB region around the match
                let region_start = offset.saturating_sub(4096);
                let region_end = (offset + 4096).min(data.len());
                let region = &data[region_start..region_end];
                covered_ranges.push((region_start, region_end));

                let key_hex = hex::encode(&candidate_key[..key_len]);

                let mut pos = 0;
                let mut decoded_bytes = Vec::with_capacity(128);
                while pos < region.len() {
                    // Find start of printable run
                    while pos < region.len() {
                        let decoded = region[pos] ^ candidate_key[pos % key_len];
                        if is_printable_byte_for_file_xor(decoded) {
                            break;
                        }
                        pos += 1;
                    }

                    if pos >= region.len() {
                        break;
                    }

                    // Collect printable run
                    decoded_bytes.clear();
                    let start_pos = pos;
                    while pos < region.len() {
                        let decoded = region[pos] ^ candidate_key[pos % key_len];
                        if is_printable_byte_for_file_xor(decoded) {
                            decoded_bytes.push(decoded);
                            pos += 1;
                        } else {
                            break;
                        }
                    }

                    if decoded_bytes.len() >= min_length
                        && let Ok(s) = String::from_utf8(decoded_bytes.clone())
                        && s.bytes().any(|b| b.is_ascii_alphabetic())
                    {
                        let file_offset = (region_start + start_pos) as u64;
                        let kind = classify_xor_string(&s).flatten();
                        results.push(ExtractedString {
                            value: s,
                            data_offset: file_offset,
                            section: None,
                            method: StringMethod::XorDecode,
                            kind,
                            source: Some(format!("xor:rolling:{}", key_hex)),
                            fragments: None,
                            ..Default::default()
                        });
                    }
                }

                // Jump past the extracted region
                offset = region_end;
            }
        }
    }

    // Deduplicate by offset + value
    results.sort_by_key(|s| s.data_offset);
    results.dedup_by(|a, b| a.data_offset == b.data_offset && a.value == b.value);

    results
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
    // Pre-seed covered_ranges with excluded_ranges (code sections). The
    // per-offset loop below skips offsets inside any covered range, so code
    // segments are never inspected.
    let mut covered_ranges: Vec<(usize, usize)> = excluded_ranges.to_vec();

    // Scan for patterns to find the seed
    for pattern in XOR_PATTERNS {
        if pattern.len() < 4 {
            continue;
        }
        let max_offset = data.len().saturating_sub(pattern.len());

        for offset in 0..max_offset {
            // Derive candidate seed: data[offset+i] ^ (seed + i) = pattern[i]
            // seed + i = data[offset+i] ^ pattern[i]
            // seed = (data[offset+i] ^ pattern[i]).wrapping_sub(i as u8)
            //
            // The covered-range check (caller exclusions + already-extracted
            // regions) is deferred until *after* a seed validates below. Seed
            // validation rejects virtually every offset in O(1), whereas the
            // covered-range scan is O(ranges) per offset; with `covered_ranges`
            // growing each time a seed is found, checking it up front made the
            // whole loop O(offsets × ranges) — quadratic on files that produce
            // many seeds (e.g. multi-MB ELF `.so` payloads, where it cost tens
            // of seconds on a single member). Validating first and skipping the
            // covered check below yields byte-identical output far faster.
            let seed = data[offset] ^ pattern[0];

            // Skip trivial seed 0 (already handled by normal extraction)
            if seed == 0 {
                continue;
            }

            // Validate seed with the rest of the pattern
            let mut valid = true;
            for i in 1..pattern.len() {
                let expected_key = seed.wrapping_add(i as u8);
                if (data[offset + i] ^ expected_key) != pattern[i] {
                    valid = false;
                    break;
                }
            }

            if valid {
                // Seed found! Extract strings from the surrounding 8KB region
                let region_start = offset.saturating_sub(4096);
                let region_end = (offset + 4096).min(data.len());

                // Sole covered-range guard: skip offsets inside a caller
                // exclusion (e.g. a `.text` code section) or an already-extracted
                // region. Only reached on a validated seed, so this O(ranges)
                // scan runs rarely instead of once per byte.
                if covered_ranges
                    .iter()
                    .any(|&(s, e)| offset >= s && offset < e)
                {
                    continue;
                }
                covered_ranges.push((region_start, region_end));

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
                                        && let Some(Some(kind)) = classify_xor_string(&s)
                                    {
                                        results.push(ExtractedString {
                                            value: s,
                                            data_offset: current_start as u64,
                                            section: None,
                                            method: StringMethod::XorDecode,
                                            kind: Some(kind),
                                            source: Some(format!(
                                                "xor:incremental:seed0x{:02x}",
                                                seed
                                            )),
                                            fragments: None,
                                            ..Default::default()
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
                                            && let Some(Some(kind)) = classify_xor_string(&s)
                                        {
                                            results.push(ExtractedString {
                                                value: s,
                                                data_offset: current_start as u64,
                                                section: None,
                                                method: StringMethod::XorDecode,
                                                kind: Some(kind),
                                                source: Some(format!(
                                                    "xor:incremental:seed0x{:02x}",
                                                    seed
                                                )),
                                                fragments: None,
                                                ..Default::default()
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
        }
    }

    // Deduplicate by offset + value
    results.sort_by_key(|s| s.data_offset);
    results.dedup_by(|a, b| a.data_offset == b.data_offset && a.value == b.value);

    results
}
