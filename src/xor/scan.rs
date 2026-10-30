//! XOR scanning infrastructure for extracting obfuscated strings.
//!
//! Contains the Aho-Corasick–based XOR pattern automata, multi-byte key extraction,
//! rolling/index-based XOR detection for Windows environment variables,
//! and all `extract_custom_xor_strings` variants.

// This codebase targets 64-bit hosts only: usize = u64, so u64-to-usize casts are lossless.
#![allow(clippy::cast_possible_truncation)]

mod incremental;
mod repeating;
mod rolling;

pub(crate) use incremental::extract_incremental_xor_strings;
use repeating::extract_custom_xor_strings_pattern_based_simple;
pub(crate) use rolling::extract_rolling_xor_with_known_plaintext;

use super::SKIP_XOR_KEYS;
use super::classify::{Verdict, classify_xor_string, clean_url_trailing_garbage};
use super::validate::{has_known_path_prefix, is_valid_xor_string, nul_ends_string, reads_as_text};
use crate::classifier::classify_string;
use crate::{ExtractedString, StringKind, StringMethod};
use aho_corasick::AhoCorasick;
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
        &[],
        true,
        enable_early_termination,
    )
}

/// Extract XOR strings, aimed first at the caller's string-extent hints.
/// Hints are tried first, and successful regions are excluded from file-wide scanning.
pub(crate) fn extract_custom_xor_strings_with_hints(
    data: &[u8],
    key: &[u8],
    min_length: usize,
    hints: &[crate::StringBoundary],
    apply_filters: bool,
    enable_early_termination: bool,
) -> Vec<ExtractedString> {
    if key.is_empty() || data.is_empty() {
        return Vec::new();
    }

    // Track regions that have been successfully decoded with high quality
    let mut excluded_ranges: Vec<(usize, usize)> = Vec::new();

    // Step 1: decode the disassembler's string extents first, if any.
    let mut hint_results = Vec::new();
    if !hints.is_empty() {
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
    let mut kept = Disjoint::new(key.len(), min_length);
    let excluded = Excluded::new(excluded_ranges);
    if let [key] = key {
        // Maximal printable runs, disjoint by construction.
        kept.extend(single_byte_xor_strings(data, *key, min_length, &excluded));
    } else {
        // Every offset is a candidate, so they overlap: prefer high-value
        // IOCs, then the longest string. Network IOCs (URL, IP) beat longer
        // Const strings.
        let mut candidates = extract_custom_xor_strings_pattern_based_simple(
            data,
            key,
            min_length,
            apply_filters,
            &excluded,
            enable_early_termination,
        );
        candidates.sort_by_key(|s| {
            let priority = match s.kind {
                Some(StringKind::Url | StringKind::Ip | StringKind::IpPort) => 0,
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

/// Caller-excluded byte ranges, sorted and merged so one binary search
/// answers. A list checked in full for every candidate was quadratic: a
/// binary can declare tens of thousands of code sections.
pub(super) struct Excluded(Vec<(usize, usize)>);

impl Excluded {
    pub(super) fn new(ranges: &[(usize, usize)]) -> Self {
        let mut sorted: Vec<_> = ranges.iter().copied().filter(|&(s, e)| s < e).collect();
        sorted.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(sorted.len());
        for (start, end) in sorted {
            match merged.last_mut() {
                Some(last) if start <= last.1 => last.1 = last.1.max(end),
                _ => merged.push((start, end)),
            }
        }
        Self(merged)
    }

    fn contains(&self, offset: usize) -> bool {
        let i = self.0.partition_point(|&(s, _)| s <= offset);
        i > 0 && offset < self.0[i - 1].1
    }
}

/// Byte ranges a scan must not inspect again: caller exclusions, then each
/// region already decoded. A file of repeated encoded anchors adds a region
/// every 4 KiB.
struct Covered {
    excluded: Excluded,
    /// Decoded regions, `start -> end`. Each spans at most
    /// `2 * REGION_RADIUS`, so only those starting that close before an
    /// offset can contain it.
    regions: BTreeMap<usize, usize>,
}

impl Covered {
    fn new(excluded: &[(usize, usize)]) -> Self {
        Self {
            excluded: Excluded::new(excluded),
            regions: BTreeMap::new(),
        }
    }

    fn contains(&self, offset: usize) -> bool {
        self.excluded.contains(offset)
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

/// Bytes a decoded run may overrun into the next string. Strings are often
/// encoded back to back, each from the start of the key, so a run decodes a
/// few garbage bytes of its neighbour before going unprintable.
const MAX_TAIL_OVERRUN: usize = 8;

/// Strings whose byte ranges do not overlap, kept first come, first served,
/// except that a short overrun into a string decoded at another key phase is
/// trimmed from the earlier string's tail rather than costing the later
/// string its place, when the later string classified as something, or is
/// long and the cut falls between words. At the same phase the later string is a suffix of the
/// earlier one, the same text, and nothing is trimmed.
struct Disjoint {
    /// Key length: offsets this far apart decode at the same key phase.
    period: usize,
    /// Shortest string worth keeping; trimming never goes below it.
    min_length: usize,
    strings: Vec<ExtractedString>,
    /// Kept ranges, `start -> (end, index into strings)`. They never overlap,
    /// so a new range can only collide with its nearest neighbour on each side.
    ranges: BTreeMap<usize, (usize, usize)>,
}

impl Disjoint {
    fn new(period: usize, min_length: usize) -> Self {
        Self {
            period,
            min_length,
            strings: Vec::new(),
            ranges: BTreeMap::new(),
        }
    }

    fn extend(&mut self, candidates: impl IntoIterator<Item = ExtractedString>) {
        for mut candidate in candidates {
            let start = candidate.data_offset as usize;
            let mut end = start + candidate.value.len();
            if let Some((&kept_start, &(kept_end, i))) = self.ranges.range(..=start).next_back()
                && kept_end > start
                && kept_end - start <= MAX_TAIL_OVERRUN
                && !(start - kept_start).is_multiple_of(self.period)
                && (candidate.kind.is_some()
                    || (candidate.value.len() > 2 * MAX_TAIL_OVERRUN
                        && !splits_word(&self.strings[i].value, start - kept_start)))
                && trim_tail(
                    &mut self.strings[i].value,
                    start - kept_start,
                    self.min_length,
                )
            {
                self.ranges.insert(kept_start, (start, i));
            }
            if let Some((&next, _)) = self.ranges.range(start + 1..).next()
                && next < end
                && end - next <= MAX_TAIL_OVERRUN
                && !(next - start).is_multiple_of(self.period)
                && trim_tail(&mut candidate.value, next - start, self.min_length)
            {
                end = next;
            }
            let before = self.ranges.range(..=start).next_back();
            let after = self.ranges.range(start..).next();
            if before.is_some_and(|(_, &(e, _))| e > start) || after.is_some_and(|(&s, _)| s < end)
            {
                continue;
            }
            self.ranges.insert(start, (end, self.strings.len()));
            self.strings.push(candidate);
        }
    }
}

/// Whether cutting `value` at byte `at` splits an alphanumeric run.
fn splits_word(value: &str, at: usize) -> bool {
    let b = value.as_bytes();
    at > 0 && at < b.len() && b[at - 1].is_ascii_alphanumeric() && b[at].is_ascii_alphanumeric()
}

/// Cut `value` to `len` bytes if that leaves a whole string of at least
/// `min_length` bytes.
fn trim_tail(value: &mut String, len: usize, min_length: usize) -> bool {
    if len < min_length.max(1) || !value.is_char_boundary(len) {
        return false;
    }
    value.truncate(len);
    true
}

/// Shortest NUL-terminated path object a single-byte pass keeps below its
/// length floor: a known directory plus a name, as in "/tmp/x".
const MIN_PATH_OBJECT_LEN: usize = 6;

/// What to make of a full-length single-byte decode `s` of `raw`. Unclassified
/// runs are kept (maximal ASCII runs are far less noisy than the multi-byte
/// scan's every-offset candidates) unless the raw bytes were already text. A
/// kept run is at least half alphanumeric and, unless it is an encoding or a
/// kind that need not read as English (`bcrypt.dll`, `BCryptDecrypt`, shell
/// commands), vowelled like natural language.
fn single_byte_verdict(s: &str, raw: &[u8]) -> Verdict {
    let Verdict::Keep(kind) = classify_xor_string(s) else {
        return Verdict::Reject;
    };
    if kind.is_none() && reads_as_text(raw) {
        return Verdict::Reject;
    }
    // The run is ASCII, so bytes are characters.
    let alnum = s.bytes().filter(u8::is_ascii_alphanumeric).count();
    if !s.is_empty() && alnum * 100 < s.len() * 50 {
        return Verdict::Reject;
    }
    let alpha = s.bytes().filter(u8::is_ascii_alphabetic).count();
    let exempt = matches!(
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
    if !exempt && alpha >= 3 {
        let vowels = s
            .bytes()
            .filter(|b| matches!(b.to_ascii_lowercase(), b'a' | b'e' | b'i' | b'o' | b'u'))
            .count();
        if !(10..=70).contains(&(vowels * 100 / alpha)) {
            return Verdict::Reject;
        }
    }
    Verdict::Keep(kind)
}

/// Single-byte XOR: decode the whole file once and validate each printable
/// ASCII run, split at null padding.
fn single_byte_xor_strings(
    data: &[u8],
    key: u8,
    min_length: usize,
    excluded: &Excluded,
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
        // the run at each NUL that ends a string (see `nul_ends_string`) and validate
        // each segment on its own, so a real string is neither trimmed away with the
        // padding that precedes it nor rejected as part of a null-heavy run.
        let mut seg_start = run_start;
        while seg_start < end {
            // Skip leading raw-NUL padding.
            while seg_start < end && data[seg_start] == 0 {
                seg_start += 1;
            }
            // Extend until the next terminating NUL or end, counting the NULs kept
            // inside (plaintext bytes equal to the key) for the density check below.
            let mut seg_end = seg_start;
            let mut raw_null_count = 0usize;
            while seg_end < end && !(data[seg_end] == 0 && nul_ends_string(data, seg_end, key)) {
                raw_null_count += usize::from(data[seg_end] == 0);
                seg_end += 1;
            }
            let cur_start = seg_start;
            seg_start = seg_end + 1; // advance past the boundary NUL, regardless of outcome

            // A whole NUL-terminated object naming a known directory is a path
            // even under the length floor: a loader's "/tmp/.b" is 7 bytes.
            let len = seg_end - cur_start;
            let is_object =
                cur_start > 0 && data[cur_start - 1] == 0 && data.get(seg_end) == Some(&0);
            let may_be_short_path = is_object && len >= MIN_PATH_OBJECT_LEN;
            if (len < min_length && !may_be_short_path) || excluded.contains(cur_start) {
                continue;
            }

            // A segment still dominated by raw NULs is padding noise (key reflection
            // artifact), not a string.
            if raw_null_count * 2 > len {
                continue;
            }

            let Ok(s) = String::from_utf8(decoded[cur_start..seg_end].to_vec()) else {
                continue;
            };

            if len < min_length {
                if has_known_path_prefix(&s) && is_valid_xor_string(&s) {
                    results.push(ExtractedString {
                        kind: classify_string(&s),
                        value: s,
                        data_offset: cur_start as u64,
                        method: StringMethod::XorDecode,
                        ..Default::default()
                    });
                }
                continue;
            }

            let Verdict::Keep(kind) = single_byte_verdict(&s, &data[cur_start..seg_end]) else {
                continue;
            };
            let offset = cur_start as u64;
            if seen.insert((offset, s.clone())) {
                let value = if kind == Some(StringKind::Url) {
                    clean_url_trailing_garbage(&s)
                } else {
                    s
                };
                results.push(ExtractedString {
                    value,
                    data_offset: offset,
                    method: StringMethod::XorDecode,
                    kind,
                    ..Default::default()
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

/// Try XOR decoding at the caller's string-extent hints: where a
/// disassembler found null-terminated strings, making them
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
                if let Verdict::Keep(kind) = classify_xor_string(&s)
                    && (kind.is_some() || !reads_as_text(&data[offset..end]))
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
StringKind::Ip)
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

#[cfg(test)]
mod single_byte_tests;

#[cfg(test)]
mod reference;
