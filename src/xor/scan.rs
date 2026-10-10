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
/// - `VirtualAlloc` and `CallWindowProc` catch executable-memory dispatch chains
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
    b"VirtualAlloc",
    b"CallWindowProc",
];

/// Single-byte XOR anchors. XOR-ing adjacent bytes cancels a one-byte key:
/// `(p[i] ^ k) ^ (p[i + 1] ^ k) = p[i] ^ p[i + 1]`. So in the stream
/// `data[j] ^ data[j + 1]` each pattern leaves one fixed signature under every
/// key, and the key is recovered from the first byte. The UTF-16LE form
/// (each byte followed by the key itself) leaves `p0, p1, p1, p2, p2, …`.
/// Entries are `(pattern index, wide)`.
static SINGLE_BYTE_ANCHORS: LazyLock<(AhoCorasick, Vec<(usize, bool)>)> = LazyLock::new(|| {
    let mut signatures: Vec<Vec<u8>> = Vec::new();
    let mut info = Vec::new();
    for (i, p) in XOR_PATTERNS.iter().enumerate() {
        signatures.push(p.windows(2).map(|w| w[0] ^ w[1]).collect());
        info.push((i, false));
        let wide: Vec<u8> = p.iter().flat_map(|&b| [b, 0]).collect();
        signatures.push(wide.windows(2).map(|w| w[0] ^ w[1]).collect());
        info.push((i, true));
    }
    #[allow(clippy::expect_used)] // static, non-empty patterns
    let ac = AhoCorasick::new(&signatures).expect("single-byte XOR anchors");
    (ac, info)
});

/// Every `(offset, key, wide)` where an [`XOR_PATTERNS`] entry appears in
/// `data` XOR'd with a single-byte key (keys 0 and [`SKIP_XOR_KEYS`]
/// excluded), in UTF-16LE form too when `wide`. Sorted, so callers see a
/// deterministic order.
pub(super) fn single_byte_xor_anchors(data: &[u8], wide: bool) -> Vec<(usize, u8, bool)> {
    let stream: Vec<u8> = data.windows(2).map(|w| w[0] ^ w[1]).collect();
    let (ac, info) = &*SINGLE_BYTE_ANCHORS;
    let mut anchors: Vec<(usize, u8, bool)> = ac
        .find_overlapping_iter(&stream)
        .filter_map(|m| {
            let (pattern, is_wide) = info[m.pattern().as_usize()];
            let offset = m.start();
            let key = data[offset] ^ XOR_PATTERNS[pattern][0];
            (key != 0 && !SKIP_XOR_KEYS.contains(&key) && (wide || !is_wide))
                .then_some((offset, key, is_wide))
        })
        .collect();
    anchors.sort_unstable();
    anchors.dedup();
    anchors
}

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
    r2_hints: Option<&[crate::StringBoundary]>,
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
    let mut kept = Disjoint::default();
    if let [key] = key {
        // Maximal printable runs, disjoint by construction.
        kept.extend(single_byte_xor_strings(
            data,
            *key,
            min_length,
            excluded_ranges,
        ));
    } else {
        // Every offset is a candidate, so they overlap: prefer high-value
        // IOCs, then the longest string. Network IOCs (URL, IP) beat longer
        // Const strings.
        let mut candidates = extract_custom_xor_strings_pattern_based_simple(
            data,
            key,
            min_length,
            apply_filters,
            excluded_ranges,
            enable_early_termination,
        );
        candidates.sort_by_key(|s| {
            let priority = match s.kind {
                Some(StringKind::Url | StringKind::IP | StringKind::IPPort) => 0,
                Some(StringKind::SuspiciousPath | StringKind::ShellCmd) => 1,
                _ => 2,
            };
            (priority, std::cmp::Reverse(s.value.len()))
        });
        kept.extend(candidates);
    }
    // Strings decoded from rizin boundary hints fill whatever is left.
    kept.extend(hint_results);
    let mut kept = kept.strings;
    kept.sort_by_key(|s| s.data_offset);
    kept
}

/// Bytes on each side of a validated key that its region decodes.
const REGION_RADIUS: usize = 4096;

/// Byte ranges a scan must not inspect again: caller exclusions, then each
/// region already decoded. A list checked in full for every candidate was
/// quadratic: a file of repeated encoded anchors adds a region every 4 KiB,
/// and a binary can declare tens of thousands of code sections.
struct Covered {
    /// Exclusions, sorted and merged so one binary search answers.
    excluded: Vec<(usize, usize)>,
    /// Decoded regions, `start -> end`. Each spans at most
    /// `2 * REGION_RADIUS`, so only those starting that close before an
    /// offset can contain it.
    regions: BTreeMap<usize, usize>,
}

impl Covered {
    fn new(excluded: &[(usize, usize)]) -> Self {
        let mut sorted: Vec<_> = excluded.iter().copied().filter(|&(s, e)| s < e).collect();
        sorted.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(sorted.len());
        for (start, end) in sorted {
            match merged.last_mut() {
                Some(last) if start <= last.1 => last.1 = last.1.max(end),
                _ => merged.push((start, end)),
            }
        }
        Self {
            excluded: merged,
            regions: BTreeMap::new(),
        }
    }

    fn contains(&self, offset: usize) -> bool {
        let i = self.excluded.partition_point(|&(s, _)| s <= offset);
        (i > 0 && offset < self.excluded[i - 1].1)
            || self
                .regions
                .range(offset.saturating_sub(2 * REGION_RADIUS)..=offset)
                .any(|(_, &end)| offset < end)
    }

    fn insert(&mut self, start: usize, end: usize) {
        let kept = self.regions.entry(start).or_insert(end);
        *kept = (*kept).max(end);
    }
}

/// Strings whose byte ranges do not overlap, kept first come, first served.
#[derive(Default)]
struct Disjoint {
    strings: Vec<ExtractedString>,
    /// Kept ranges, `start -> end`. They never overlap, so a new range can
    /// only collide with its nearest neighbour on each side.
    ranges: BTreeMap<usize, usize>,
}

impl Disjoint {
    fn extend(&mut self, candidates: impl IntoIterator<Item = ExtractedString>) {
        for candidate in candidates {
            let start = candidate.data_offset as usize;
            let end = start + candidate.value.len();
            let before = self.ranges.range(..=start).next_back();
            let after = self.ranges.range(start..).next();
            if before.is_some_and(|(_, &e)| e > start) || after.is_some_and(|(&s, _)| s < end) {
                continue;
            }
            self.ranges.insert(start, end);
            self.strings.push(candidate);
        }
    }
}

/// Single-byte XOR: decode the whole file once and validate each printable
/// ASCII run, split at null padding.
fn single_byte_xor_strings(
    data: &[u8],
    key: u8,
    min_length: usize,
    excluded_ranges: &[(usize, usize)],
) -> Vec<ExtractedString> {
    let mut results = Vec::new();
    let mut seen: HashSet<(u64, String)> = HashSet::new();

    // Decode the entire data with the XOR key
    let decoded: Vec<u8> = data.iter().map(|&byte| byte ^ key).collect();

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

        // A single printable run can span several NUL-padded records: each stored
        // string is surrounded by NUL padding that XOR-decodes to a constant printable
        // byte (key 0x7a renders NUL as 'z', as in the 3CX libffmpeg C2 config). Split
        // the run at padding boundaries — runs of >=2 raw NULs — and validate each
        // non-pad segment on its own, so a real string is neither trimmed away with the
        // padding that precedes it nor rejected as part of a null-heavy run.
        let mut seg_start = run_start;
        while seg_start < end {
            // Skip leading raw-NUL padding.
            while seg_start < end && data[seg_start] == 0 {
                seg_start += 1;
            }
            // Extend until the next padding boundary (>=2 consecutive raw NULs) or end,
            // counting interior single NULs in the same pass for the density check below.
            let mut seg_end = seg_start;
            let mut raw_null_count = 0usize;
            while seg_end < end
                && !(data[seg_end] == 0 && seg_end + 1 < end && data[seg_end + 1] == 0)
            {
                raw_null_count += usize::from(data[seg_end] == 0);
                seg_end += 1;
            }
            let cur_start = seg_start;
            seg_start = seg_end + 1; // advance past the boundary NUL, regardless of outcome

            if seg_end - cur_start < min_length
                || excluded_ranges
                    .iter()
                    .any(|&(start, stop)| cur_start >= start && cur_start < stop)
            {
                continue;
            }

            // A segment still dominated by raw NULs is padding noise (key reflection
            // artifact), not a string.
            if raw_null_count * 2 > (seg_end - cur_start) {
                continue;
            }

            let Ok(s) = String::from_utf8(decoded[cur_start..seg_end].to_vec()) else {
                continue;
            };

            // Classify to reject garbage and pick the kind used by the vowel-ratio
            // bypass below. Unclassified strings are kept: these maximal ASCII runs
            // are far less noisy than the multi-byte scan's every-offset candidates.
            let Some(kind) = classify_xor_string(&s) else {
                continue;
            };

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
                Some(
                    StringKind::Base64
                        | StringKind::UnicodeEscaped
                        | StringKind::HexEncoded
                        | StringKind::UrlEncoded
                        | StringKind::SuspiciousPath
                        | StringKind::ShellCmd
                )
            );
            if !is_encoded_format && alpha >= 3 {
                let vowels = s
                    .bytes()
                    .filter(|&b| matches!(b.to_ascii_lowercase(), b'a' | b'e' | b'i' | b'o' | b'u'))
                    .count();
                let vowel_ratio = (vowels * 100).checked_div(alpha).unwrap_or(0);
                if !(10..=70).contains(&vowel_ratio) {
                    continue;
                }
            }

            let offset = cur_start as u64;
            if seen.insert((offset, s.clone())) {
                // Clean up URLs by removing trailing garbage
                let cleaned_value = if matches!(kind, Some(StringKind::Url)) {
                    clean_url_trailing_garbage(&s)
                } else {
                    s.clone()
                };

                results.push(ExtractedString {
                    value: cleaned_value,
                    data_offset: offset,
                    data_len: 0,
                    method: StringMethod::XorDecode,
                    kind,
                    fragments: None,
                });
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
    hints: &[crate::StringBoundary],
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
                    results.push(ExtractedString {
                        value: s,
                        data_offset: offset as u64,
                        data_len: 0,
                        method: StringMethod::XorDecode,
                        kind,
                        fragments: None,
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
        Some(StringKind::ShellCmd | StringKind::SuspiciousPath | StringKind::Url |
StringKind::IP)
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

/// First window scanned when terminating early; each later one doubles.
const EARLY_TERMINATION_WINDOW: usize = 4096;

/// Longest decode attempted from one offset.
const MAX_PATTERN_DECODE: usize = 1024;

/// Simplified pattern-based extraction matching decode.py behavior.
/// Scans every offset, no overlap skipping, minimal filtering.
///
/// Every offset whose XOR decode starts a printable run yields a candidate (the
/// caller resolves overlaps), so decoding each offset independently re-walks a
/// run once per offset inside it: quadratic on null padding, which a printable
/// key decodes to printable text. [`Alignment`] finds each run once per key
/// alignment instead, and only its survivors are decoded and classified.
///
/// # Arguments
/// * `enable_early_termination` - If true, returns only the first
///   MAX_STRINGS_BEFORE_EARLY_TERMINATION strings by offset. Should be true for
///   auto-detection (speeds up candidate testing) and false for user-provided
///   keys (ensures complete extraction).
fn extract_custom_xor_strings_pattern_based_simple(
    data: &[u8],
    key: &[u8],
    min_length: usize,
    apply_filters: bool,
    excluded_ranges: &[(usize, usize)],
    enable_early_termination: bool,
) -> Vec<ExtractedString> {
    let mut alignments: Vec<Alignment> =
        (0..key.len().min(data.len())).map(Alignment::new).collect();
    let mut scan = |limit: usize| {
        scan_alignments(
            &mut alignments,
            data,
            key,
            min_length,
            excluded_ranges,
            limit,
        )
    };
    let key_preview = key_preview(key);
    let finish = |&(pos, len): &(usize, usize)| {
        let decoded = data[pos..pos + len]
            .iter()
            .zip(key.iter().cycle())
            .map(|(b, k)| b ^ k)
            .collect();
        finish_xor_candidate(pos, decoded, min_length, apply_filters, &key_preview)
    };
    if !enable_early_termination {
        return scan(data.len())
            .par_iter()
            .with_min_len(crate::par::MIN_ITEMS_PER_JOB)
            .filter_map(finish)
            .collect();
    }
    // Keep the first strings by offset. Scanning windows that double in size,
    // and classifying their candidates in offset order, stops at the cut.
    let mut results = Vec::new();
    let (mut limit, mut window) = (0, EARLY_TERMINATION_WINDOW);
    while limit < data.len() {
        limit = limit.saturating_add(window).min(data.len());
        window = window.saturating_mul(2);
        for candidate in &scan(limit) {
            results.extend(finish(candidate));
            if results.len() == MAX_STRINGS_BEFORE_EARLY_TERMINATION {
                return results;
            }
        }
    }
    results
}

/// Advance every alignment to `limit`; the candidates found, by offset.
fn scan_alignments(
    alignments: &mut [Alignment],
    data: &[u8],
    key: &[u8],
    min_length: usize,
    excluded_ranges: &[(usize, usize)],
    limit: usize,
) -> Vec<(usize, usize)> {
    let job_len = crate::par::job_len(alignments.len(), limit);
    let mut candidates: Vec<(usize, usize)> = alignments
        .par_iter_mut()
        .with_min_len(job_len)
        .flat_map_iter(|a| a.scan(data, key, min_length, excluded_ranges, limit))
        .collect();
    candidates.sort_unstable();
    candidates
}

/// Pattern-scan state for the offsets `phase, phase + k, …` (k = key length),
/// resumable so early termination can stop partway through a file.
///
/// From each offset the decode runs while bytes stay printable, at most
/// [`MAX_PATTERN_DECODE`] bytes, and is cut at the first raw null that starts
/// garbage ([`starts_garbage`]). It survives if at least `min_length` long and
/// at most half raw nulls. Every offset of one alignment decodes a given byte
/// with the same key byte, so a run's end, and the first garbage null after a
/// point, hold for each later offset in that run: both are found once per run,
/// not once per offset.
struct Alignment {
    phase: usize,
    /// The next offset to scan.
    next: usize,
    /// Bytes from the current offset up to `run_end` decode printable.
    run_end: usize,
    /// No garbage null in [garbage_from, garbage); `garbage` is one, or run_end.
    garbage_from: usize,
    garbage: usize,
    /// Raw bytes from the current offset up to `zeros_end` are null.
    zeros_end: usize,
}

impl Alignment {
    fn new(phase: usize) -> Self {
        Self {
            phase,
            next: phase,
            run_end: 0,
            garbage_from: usize::MAX,
            garbage: 0,
            zeros_end: 0,
        }
    }

    /// The candidates at this alignment's offsets below `limit`, as
    /// `(offset, length)`.
    fn scan(
        &mut self,
        data: &[u8],
        key: &[u8],
        min_length: usize,
        excluded_ranges: &[(usize, usize)],
        limit: usize,
    ) -> Vec<(usize, usize)> {
        let (k, phase) = (key.len(), self.phase);
        let decode = |i: usize| data[i] ^ key[(i - phase) % k];
        let mut out = Vec::new();
        while self.next < limit.min(data.len()) {
            let pos = self.next;
            self.next += k;
            if pos >= self.run_end {
                self.run_end = pos;
                for &key_byte in key.iter().cycle() {
                    if self.run_end == data.len()
                        || !is_printable_byte_for_file_xor(data[self.run_end] ^ key_byte)
                    {
                        break;
                    }
                    self.run_end += 1;
                }
                self.garbage_from = usize::MAX;
            }
            let run_end = self.run_end;
            let end = run_end.min(pos + MAX_PATTERN_DECODE);
            if end - pos < min_length
                || excluded_ranges
                    .iter()
                    .any(|&(start, stop)| pos >= start && pos < stop)
            {
                continue;
            }
            // Inside null padding, which a printable key decodes to printable
            // text. A leading null run longer than half the longest possible
            // decode makes any cut of it more than half null, rejected below.
            if pos >= self.zeros_end {
                self.zeros_end = data[pos..]
                    .iter()
                    .position(|&b| b != 0)
                    .map_or(data.len(), |n| pos + n);
            }
            if (self.zeros_end - pos) * 2 > end - pos {
                continue;
            }
            if !(self.garbage_from <= pos + 1 && pos < self.garbage) {
                self.garbage_from = pos + 1;
                self.garbage = (pos + 1..run_end)
                    .find(|&i| data[i] == 0 && starts_garbage(decode, i, run_end))
                    .unwrap_or(run_end);
            }
            let garbage = self.garbage;
            let cut = if end == run_end {
                (garbage < end).then_some(garbage)
            } else if garbage + 4 <= end {
                Some(garbage)
            } else {
                // The decode cap ended this run early, so a null within three
                // bytes of `end` sees a shorter window than it did against the run.
                (end.saturating_sub(3).max(pos + 1)..end)
                    .find(|&i| data[i] == 0 && starts_garbage(decode, i, end))
            };
            let stop = cut.unwrap_or(end);
            let len = stop - pos;
            // Mostly-null source decodes to the key reflected back, not content.
            let nulls = data[pos..stop].iter().filter(|&&b| b == 0).count();
            if len >= min_length && nulls * 2 <= len {
                out.push((pos, len));
            }
        }
        out
    }
}

/// Whether the raw null at `i` starts garbage in a decode ending at `end`: at
/// least two decoded bytes remain, and the first (up to) four hold three
/// consecutive ASCII consonants.
fn starts_garbage(decode: impl Fn(usize) -> u8, i: usize, end: usize) -> bool {
    if end - i < 2 {
        return false;
    }
    let mut consonants = 0;
    for b in (i..end.min(i + 4)).map(decode) {
        let vowel = matches!(b.to_ascii_lowercase(), b'a' | b'e' | b'i' | b'o' | b'u');
        consonants = if b.is_ascii_alphabetic() && !vowel {
            consonants + 1
        } else {
            0
        };
        if consonants >= 3 {
            return true;
        }
    }
    false
}

/// Validate, clean and classify one decoded candidate from the pattern scan.
fn finish_xor_candidate(
    pos: usize,
    decoded: Vec<u8>,
    min_length: usize,
    apply_filters: bool,
    key_preview: &str,
) -> Option<ExtractedString> {
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
        Some(StringKind::Url | StringKind::IP | StringKind::IPPort)
    );
    if !is_network_ioc && alpha >= 3 && !is_locale_string(&trimmed_s) {
        let has_non_ascii = !trimmed_s.is_ascii();
        if !has_non_ascii {
            // Only check vowels for ASCII/English text
            let vowels = trimmed_s
                .chars()
                .filter(|c: &char| matches!(c.to_ascii_lowercase(), 'a' | 'e' | 'i' | 'o' | 'u'))
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
    } else if matches!(kind, Some(StringKind::SuspiciousPath)) && is_locale_string(&trimmed_s) {
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

    Some(ExtractedString {
        value: cleaned_value,
        data_offset: pos as u64,
        data_len: 0,
        method: StringMethod::XorDecode,
        kind,
        fragments: None,
    })
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

/// Longest rolling-XOR key tried.
const MAX_ROLLING_KEY: usize = 4;

/// Rolling-XOR anchors, one automaton per key length k. In the stream
/// `data[j] ^ data[j - k]` a k-byte cycling key cancels out, so a pattern
/// XOR'd with any such key leaves the fixed signature `p[i] ^ p[i - k]`
/// (i ≥ k) there: one pass finds every pattern under every key of length k.
static ROLLING_XOR_ANCHORS: LazyLock<Vec<AhoCorasick>> = LazyLock::new(|| {
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
                            kind: classify_xor_string(s).flatten(),
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

/// Patterns long enough for an incremental-XOR anchor, with their index in
/// [`XOR_PATTERNS`]. Shorter ones produce too many chance hits to be evidence.
const MIN_ANCHOR_LEN: usize = 4;

/// The first two encoded bytes of every incremental-XOR `(pattern, seed)`
/// pair, sorted, with a 64-Kbit filter over them. Seed 0 is excluded: that is
/// plain unobfuscated text, which normal extraction already covers.
struct IncrementalAnchors {
    /// Bit `h` is set when some pair's encoding starts with the bytes `h`.
    filter: Vec<u64>,
    /// `(first two encoded bytes, pattern index, seed)`, by head.
    pairs: Vec<(u16, u8, u8)>,
}

static INCREMENTAL_ANCHORS: LazyLock<IncrementalAnchors> = LazyLock::new(|| {
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
fn find_incremental_anchors(data: &[u8]) -> Vec<(usize, usize, u8)> {
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
                                && let Some(Some(kind)) = classify_xor_string(&s)
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
                                    && let Some(Some(kind)) = classify_xor_string(&s)
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
mod single_byte_tests {
    use super::*;

    #[test]
    fn single_byte_keys_merge_hints_and_honor_exclusions() {
        let key = 0x5a;
        let mut data = vec![0u8; 600];
        for (at, text) in [
            (100, &b"http://evil.example.com/payload.sh"[..]),
            (300, &b"C:\\Windows\\System32\\cmd.exe /c whoami"[..]),
        ] {
            for (i, &b) in text.iter().enumerate() {
                data[at + i] = b ^ key;
            }
        }
        let hint = ExtractedString {
            value: "rizin-found".to_owned(),
            data_offset: 500,
            method: StringMethod::XorDecode,
            ..Default::default()
        };
        let found = extract_custom_xor_strings_filtered_with_exclusions(
            &data,
            &[key],
            8,
            true,
            &[(300, 340)],
            vec![hint],
            false,
        );
        let values: Vec<&str> = found.iter().map(|s| s.value.as_str()).collect();
        assert!(
            values.contains(&"http://evil.example.com/payload.sh"),
            "{values:?}"
        );
        assert!(values.contains(&"rizin-found"), "hint dropped: {values:?}");
        assert!(
            !values.iter().any(|v| v.contains("cmd.exe")),
            "excluded: {values:?}"
        );
    }
}

#[cfg(test)]
mod reference;

#[cfg(test)]
mod incremental_anchor_tests {
    use super::{MIN_ANCHOR_LEN, XOR_PATTERNS, find_incremental_anchors};

    /// The original pattern-major, offset-ascending brute-force scan that
    /// [`find_incremental_anchors`] replaces. Kept here as the oracle: the
    /// Aho-Corasick inversion is only worth having if it is exactly equal.
    fn reference_anchors(data: &[u8]) -> Vec<(usize, usize, u8)> {
        let mut out = Vec::new();
        for (pattern_idx, pattern) in XOR_PATTERNS.iter().enumerate() {
            if pattern.len() < MIN_ANCHOR_LEN {
                continue;
            }
            // Inclusive: a pattern may end at the last byte.
            let Some(max_offset) = data.len().checked_sub(pattern.len()) else {
                continue;
            };
            for offset in 0..=max_offset {
                let seed = data[offset] ^ pattern[0];
                if seed == 0 {
                    continue;
                }
                let valid = (1..pattern.len())
                    .all(|i| (data[offset + i] ^ seed.wrapping_add(i as u8)) == pattern[i]);
                if valid {
                    out.push((pattern_idx, offset, seed));
                }
            }
        }
        out
    }

    fn assert_agrees(data: &[u8], label: &str) {
        let mut got = find_incremental_anchors(data);
        got.sort_unstable();
        let mut want = reference_anchors(data);
        want.sort_unstable();
        assert_eq!(got, want, "anchor mismatch on {label}");
    }

    /// `data[offset + i] = pattern[i] ^ (seed + i)` — what the scan looks for.
    fn encode(pattern: &[u8], seed: u8) -> Vec<u8> {
        pattern
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ seed.wrapping_add(i as u8))
            .collect()
    }

    #[test]
    fn matches_reference_on_planted_anchors() {
        // Every eligible pattern, at a spread of seeds including the wrapping
        // edges, planted in filler that must not itself anchor.
        for (idx, pattern) in XOR_PATTERNS.iter().enumerate() {
            if pattern.len() < MIN_ANCHOR_LEN {
                continue;
            }
            for seed in [1u8, 7, 128, 200, 255] {
                let mut data = vec![0u8; 32];
                data.extend(encode(pattern, seed));
                data.extend(vec![0u8; 32]);
                let anchors = find_incremental_anchors(&data);
                assert!(
                    anchors.contains(&(idx, 32, seed)),
                    "planted pattern {pattern:?} seed {seed} not found"
                );
                assert_agrees(&data, "planted");
                // Ending at the last byte of the input.
                let tail: Vec<u8> = vec![0u8; 8]
                    .into_iter()
                    .chain(encode(pattern, seed))
                    .collect();
                assert!(find_incremental_anchors(&tail).contains(&(idx, 8, seed)));
                assert_agrees(&tail, "planted at end");
            }
        }
    }

    #[test]
    fn matches_reference_on_pseudorandom_and_degenerate_input() {
        // Deterministic LCG: dense enough to produce chance anchors, which is
        // where an off-by-one in the inversion would show up.
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut data: Vec<u8> = Vec::with_capacity(64 * 1024);
        for _ in 0..64 * 1024 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            data.push((state >> 33) as u8);
        }
        assert_agrees(&data, "pseudorandom");

        assert_agrees(b"", "empty");
        assert_agrees(b"abc", "shorter than any pattern");
        assert_agrees(&vec![0u8; 4096], "all zeroes");
        assert_agrees(&vec![0xFFu8; 4096], "all ones");
        // Plain text: seed 0 is excluded, so unobfuscated patterns must not anchor.
        assert_agrees(b"https://example.com/bin/sh .exe .dll passw", "plaintext");
    }
}
