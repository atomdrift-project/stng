//! String classification and validation for XOR-decoded strings.
//!
//! This module contains pure string utility functions used by the XOR extraction
//! pipeline to validate, classify, and clean decoded strings.

use super::key::{calculate_entropy, is_good_xor_key_candidate, score_xor_key_candidate};
use super::scan::{XOR_PATTERNS, extract_custom_xor_strings};
use super::validate::{
    has_known_path_prefix, is_locale_string, is_meaningful_string, is_printable_char, is_valid_ip,
    is_valid_port, is_valid_xor_string, looks_like_text,
};
use super::{MAX_AUTO_DETECT_SIZE, MAX_XOR_SCAN_SIZE, SKIP_XOR_KEYS};
use crate::{ExtractedString, StringKind, StringMethod, classifier::classify_string};
use rayon::prelude::*;
use std::collections::HashSet;

pub(crate) fn trim_consonant_clusters(s: &str) -> String {
    if s.len() < 8 {
        return s.to_string();
    }

    let chars: Vec<char> = s.chars().collect();
    let mut consonant_run = 0;
    let mut trim_pos = None;

    for (i, &c) in chars.iter().enumerate() {
        if c.is_ascii_alphabetic() {
            let is_vowel = matches!(c.to_ascii_lowercase(), 'a' | 'e' | 'i' | 'o' | 'u');
            if is_vowel {
                consonant_run = 0;
            } else {
                consonant_run += 1;
                // If we hit 4+ consonants in a row, mark this as potential trim point
                if consonant_run >= 4 && trim_pos.is_none() {
                    // Trim before the start of this consonant run
                    trim_pos = Some(i - 3);
                }
            }
        } else {
            // Non-letter resets the count
            consonant_run = 0;
        }
    }

    if let Some(pos) = trim_pos {
        // Make sure we're trimming at a reasonable boundary (at least 10 chars into the string)
        if pos >= 10 {
            return chars[..pos].iter().collect();
        }
    }

    s.to_string()
}

/// Clean trailing garbage from locale strings extracted via XOR decoding.
///
/// Locale strings often have trailing garbage after the last valid locale code.
/// This function trims them to prevent overlaps with adjacent strings.
///
/// Examples:
/// - `hy_AM;be_BY;kk_KZ;ru_RU;uk_UA;ffYztZORL` -> `hy_AM;be_BY;kk_KZ;ru_RU;uk_UA;`
pub(crate) fn clean_locale_trailing_garbage(s: &str) -> String {
    // Find the last valid locale separator (';' or ',')
    if let Some(last_sep) = s.rfind([';', ',']) {
        // Include the separator in the result
        let clean_len = last_sep + 1;
        if clean_len < s.len() {
            return s[..clean_len].to_string();
        }
    }

    // No separator found or nothing to trim
    s.to_string()
}

/// Clean trailing garbage from URLs extracted via XOR decoding.
///
/// URLs often have trailing garbage characters that pass printability checks
/// but aren't part of the actual URL. This function trims them to prevent
/// overlaps with adjacent strings.
///
/// Examples:
/// - `http://46.30.191.141n;uJ` -> `http://46.30.191.141`
/// - `https://evil.com/path?foo=barn;X` -> `https://evil.com/path?foo=bar`
pub(crate) fn clean_url_trailing_garbage(url: &str) -> String {
    // For URLs with embedded IPs: trim after the last IP octet
    if let Some(proto_end) = url.find("://") {
        let after_proto = &url[proto_end + 3..];

        // Check if it starts with an IP address
        if after_proto
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_digit())
        {
            // Find the end of the IP (last digit of last octet)
            let mut ip_end = 0;
            let mut dots = 0;

            for (i, c) in after_proto.char_indices() {
                if c.is_ascii_digit() {
                    ip_end = i + c.len_utf8();
                } else if c == '.' {
                    dots += 1;
                    if dots > 3 {
                        break; // Too many dots, not a valid IP
                    }
                } else if c == ':' && dots == 3 {
                    // Port number after IP - find end of port
                    let port_start = i + c.len_utf8();
                    if let Some(port_end_offset) =
                        after_proto[port_start..].find(|c: char| !c.is_ascii_digit())
                    {
                        ip_end = port_start + port_end_offset;
                    } else {
                        ip_end = after_proto.len();
                    }
                    break;
                } else {
                    // Non-IP character
                    break;
                }
            }

            // If we found a valid IP (3 dots), trim after it
            if dots == 3 && ip_end > 0 {
                let clean_len = proto_end + 3 + ip_end;
                if clean_len < url.len() {
                    return url[..clean_len].to_string();
                }
            }
        } else {
            // Domain-based URL: trim after last alphanumeric/slash/common URL chars
            let valid_url_chars: Vec<usize> = after_proto
                .char_indices()
                .filter(|(_, c)| {
                    c.is_alphanumeric()
                        || matches!(c, '/' | '.' | '-' | '_' | '?' | '=' | '&' | '%' | '#' | '+')
                })
                .map(|(i, c)| i + c.len_utf8())
                .collect();

            if let Some(&last_valid) = valid_url_chars.last() {
                let clean_len = proto_end + 3 + last_valid;
                if clean_len < url.len() {
                    return url[..clean_len].to_string();
                }
            }
        }
    }

    // No cleanup needed or couldn't parse
    url.to_string()
}

/// True if `value_lower` contains any 4-character alphanumeric window of
/// `key_lower` — meaning the "decoded" string is just a garbled copy of the key
/// (a self-XOR artifact), not genuine recovered plaintext. Both arguments must
/// already be ASCII-lowercased.
///
/// Windows are restricted to alphanumeric runs so we key off surviving text
/// shards (e.g. `auth`, `code`) rather than punctuation/whitespace fragments of
/// the key, which would match far too loosely.
fn value_is_key_echo(value_lower: &str, key_lower: &str) -> bool {
    const WIN: usize = 4;
    let key_bytes = key_lower.as_bytes();
    let value_bytes = value_lower.as_bytes();
    if key_bytes.len() < WIN || value_bytes.len() < WIN {
        return false;
    }
    key_bytes.windows(WIN).any(|w| {
        w.iter().all(u8::is_ascii_alphanumeric) && memchr::memmem::find(value_bytes, w).is_some()
    })
}

pub(crate) fn auto_detect_xor_key(
    data: &[u8],
    candidate_strings: &[ExtractedString],
    min_length: usize,
) -> Option<(Vec<u8>, String, u64)> {
    // Only auto-detect for small files
    if data.len() > MAX_AUTO_DETECT_SIZE {
        return None;
    }

    // Find candidate XOR keys by quality scoring.
    // Compute entropy once per candidate (shared by qualification check and scoring).
    let mut candidates_with_score: Vec<(u32, u64, &str)> = candidate_strings
        .iter()
        .filter(|s| !s.value.contains('_') && !s.value.starts_with("cstr."))
        .filter_map(|s| {
            let entropy = calculate_entropy(s.value.as_bytes());
            if is_good_xor_key_candidate(&s.value, entropy) {
                Some((
                    score_xor_key_candidate(&s.value, entropy),
                    s.data_offset,
                    s.value.as_str(),
                ))
            } else {
                None
            }
        })
        .collect();

    // Sort by score descending (best candidates first)
    candidates_with_score.sort_by(|a, b| {
        b.0.cmp(&a.0) // Score first (descending)
            .then(b.1.cmp(&a.1)) // Then offset (descending - prefer later strings as tiebreaker)
    });

    // Take top candidates instead of just last 5 by offset
    // Try up to 5 best-scored candidates (3-5 is usually sufficient and much faster)
    let candidates: Vec<(u64, &str)> = candidates_with_score
        .iter()
        .take(5)
        .map(|(_, offset, s)| (*offset, *s))
        .collect();

    if candidates.is_empty() {
        return None;
    }

    // OPTIMIZATION 1: Phase 1 Quick Pre-filter
    // Skip candidates that don't decode killer IOCs in first 32KB - saves time by avoiding full extraction
    let quick_scan_size = std::cmp::min(32768, data.len());
    let quick_data = &data[..quick_scan_size];
    let killer_patterns = [
        "osascript",
        "screencapture",
        "/bin/sh",
        "/bin/bash",
        "2>&1",
        "http://",
        "https://",
        "launchctl",
        "electrum",
        "ethereum",
        "exodus",
    ];

    // Build Aho-Corasick automaton for all killer patterns (byte-level, no UTF-8 needed)
    let killer_ac = aho_corasick::AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(killer_patterns)
        .ok();

    let mut promising_candidates = Vec::new();
    for (offset, candidate) in &candidates {
        let key = candidate.as_bytes();
        let decoded: Vec<u8> = quick_data
            .iter()
            .enumerate()
            .map(|(i, &byte)| byte ^ key[i % key.len()])
            .collect();

        // Search decoded bytes directly — no UTF-8 conversion needed
        let found = killer_ac.as_ref().is_some_and(|ac| ac.is_match(&decoded));
        if found {
            promising_candidates.push((*offset, *candidate));
        }
    }

    // Fall back to all candidates if Phase 1 eliminates everything (safety net)
    let candidates_to_test = if promising_candidates.is_empty() {
        candidates
    } else {
        promising_candidates
    };

    // OPTIMIZATION 2: Parallel candidate testing
    // Test all promising candidates in parallel for 2-3x speedup on multi-core CPUs
    let candidate_scores: Vec<(i32, u64, String, Vec<u8>)> = candidates_to_test
        .into_par_iter()
        .filter_map(|(offset, candidate): (u64, &str)| {
            let key = candidate.as_bytes().to_vec();
            // Enable early termination for auto-detection to speed up candidate testing
            let results = extract_custom_xor_strings(data, &key, min_length, true);

            // Sanity check: if we extracted way too many strings, it's likely noise
            if results.len() > 5000 {
                return None;
            }

            // Calculate weighted score based on decoded string quality.
            // Use a set of already-scored values to avoid counting duplicate strings
            // multiple times: real XOR keys decode to diverse content, but false-positive
            // keys (e.g., a library path XOR'd with near-zero code) produce repetitive
            // garbled copies of the key text that would otherwise inflate the score.
            let mut score = 0;
            let mut scored_values: HashSet<String> = HashSet::new();
            let key_lower = candidate.to_ascii_lowercase();

            for r in &results {
                let value_lower = r.value.to_ascii_lowercase();

                // Skip results that are merely garbled echoes of the key. When the
                // scanner derives a key from a token that repeats throughout a benign,
                // text-rich input (e.g. an OpenAPI schema repeating "OAuth2Authorization
                // Code"), XORing smears shards of the key across the output. Those shards
                // trip the short-keyword IOC classifiers ("auth", "key", "user", ...) and
                // would otherwise inflate the score past the confidence threshold. A real
                // key is high-entropy bytes whose windows never appear in genuinely
                // decoded plaintext, so true positives are unaffected. This generalizes
                // the exact-duplicate dedup above to near-duplicate key fragments.
                if value_is_key_echo(&value_lower, &key_lower) {
                    continue;
                }

                // CRITICAL: Shell commands and redirections (highest priority)
                if value_lower.contains("osascript")
                    || value_lower.contains("screencapture")
                    || value_lower.contains("/bin/sh")
                    || value_lower.contains("/bin/bash")
                    || value_lower.contains("2>&1")
                    || value_lower.contains("<<eod")
                    || value_lower.contains("<<eof")
                {
                    score += 100;
                }

                // Cryptocurrency terms (very high priority) - keywords are already lowercase
                for crypto in CRYPTO_KEYWORDS {
                    if value_lower.contains(crypto) {
                        score += 80;
                        break;
                    }
                }

                // Suspicious paths (very high priority) - only count unique values
                if matches!(r.kind, Some(StringKind::SuspiciousPath))
                    && scored_values.insert(value_lower.clone())
                {
                    score += 75;
                }

                // URLs and network indicators - only count unique values
                if matches!(
                    r.kind,
                    Some(StringKind::Url) | Some(StringKind::IP) | Some(StringKind::IPPort)
                ) && scored_values.insert(value_lower.clone())
                {
                    score += 50;
                }

                // Browser strings - keywords are already lowercase
                for browser in BROWSER_KEYWORDS {
                    if value_lower.contains(browser) {
                        score += 40;
                        break;
                    }
                }

                // Shell commands - only count unique values
                if matches!(r.kind, Some(StringKind::ShellCmd))
                    && scored_values.insert(value_lower.clone())
                {
                    score += 30;
                }

                // Locale strings (en-US, ru-RU pattern)
                if is_locale_string(&r.value) {
                    score += 25;
                }

                // Generic paths (lower priority, only if they match known prefixes)
                if matches!(r.kind, Some(StringKind::Path)) && has_known_path_prefix(&r.value) {
                    score += 10;
                }

                // Base64 (low priority)
                if matches!(r.kind, Some(StringKind::Base64)) {
                    score += 5;
                }
            }

            Some((score, offset, candidate.to_string(), key))
        })
        .collect();

    // Find the best candidate from parallel results
    let mut best_key: Option<(Vec<u8>, String, u64)> = None;
    let mut best_score = 0;

    for (score, offset, candidate, key) in candidate_scores {
        if score > best_score {
            best_score = score;
            best_key = Some((key, candidate, offset));
        }

        // Early termination: if we found a key with very high confidence
        if score > 500 {
            break;
        }
    }

    // Require VERY high score to avoid false positives from random XOR keys
    // Any key produces ~85% printable output, so we need EXTREMELY strong evidence
    // Minimum threshold: 300+ (2+ shell commands, multiple high-value IOCs, or clusters of URLs/IPs)
    // This filters out unobfuscated binaries - real XOR'd malware will have explicit
    // command & control URLs, shell commands, or cryptocurrency wallet paths.
    // Threshold is 375 (= 5 unique suspicious paths at 75 pts each). This rejects keys
    // that score only from a handful of garbled path matches (null-byte false positives)
    // while accepting real malware which typically has shell commands (100+ pts) or URLs.
    let min_xor_confidence_threshold = 375;

    if best_score >= min_xor_confidence_threshold {
        if let Some((ref _key, ref key_str, _)) = best_key {
            tracing::info!(
                "Auto-detected XOR key: '{}' (score: {})",
                key_str,
                best_score
            );
        }
    } else {
        return None;
    }

    best_key
}

/// Extract XOR-encoded strings from binary data.
///
/// Uses Aho-Corasick for efficient single-pass scanning of all XOR'd patterns.
///
/// # Arguments
/// * `data` - Binary data to scan
/// * `min_length` - Minimum string length
/// * `scan_wide` - Whether to scan for UTF-16LE (wide) patterns (use for PE binaries)
pub(crate) fn extract_xor_strings(
    data: &[u8],
    min_length: usize,
    scan_wide: bool,
) -> Vec<ExtractedString> {
    // Skip XOR scanning for very large files - too slow and unlikely to have simple XOR
    if data.len() > MAX_XOR_SCAN_SIZE {
        return Vec::new();
    }

    let (ac, pattern_info) = if scan_wide {
        &*super::scan::AUTOMATON_WITH_WIDE
    } else {
        &*super::scan::AUTOMATON_ASCII
    };
    let mut results = Vec::new();
    let mut seen: HashSet<(u64, String)> = HashSet::new();

    // Single pass through the data using overlapping matches
    for mat in ac.find_overlapping_iter(data) {
        let mat: aho_corasick::Match = mat;
        let info = &pattern_info[mat.pattern().as_usize()];
        let pos = mat.start();
        // Wide (UTF-16LE) and narrow matches differ only in the expander and the
        // provenance suffix; the recording is identical.
        let expanded = if info.is_wide {
            expand_xor_wide_string(data, pos, info.key, min_length)
        } else {
            expand_xor_string(data, pos, info.key, min_length)
        };
        if let Some((decoded, start, _end)) = expanded
            && let Some(kind) = classify_xor_string(&decoded)
        {
            let offset = start as u64;
            if seen.insert((offset, decoded.clone())) {
                results.push(ExtractedString {
                    value: decoded,
                    data_offset: offset,
                    section: None,
                    method: StringMethod::XorDecode,
                    kind,
                    fragments: None,
                });
            }
        }
    }

    // Also scan for IP addresses and hostnames
    scan_dotted_patterns(data, min_length, &mut results, &mut seen);

    results
}

/// Extract strings encrypted with multi-byte XOR keys detected by radare2 analysis.
///
/// Uses high-confidence keys from `r2::verify_xor_keys()` to decrypt data by cycling
/// through key bytes. Only attempts decryption with HIGH confidence keys to minimize
/// false positives.
///
/// # Arguments
/// * `data` - Binary data to scan
/// * `keys` - XOR key candidates from radare2 analysis
/// * `min_length` - Minimum string length
pub(crate) fn extract_multikey_xor_strings(
    data: &[u8],
    keys: &[crate::r2::XorKeyInfo],
    min_length: usize,
) -> Vec<ExtractedString> {
    use crate::r2::XorConfidence;
    let mut results = Vec::new();
    let mut seen: HashSet<(u64, String)> = HashSet::new();

    // Only use top high-confidence keys for decryption attempts
    for key_info in keys
        .iter()
        .filter(|k| matches!(k.confidence, XorConfidence::High))
        .take(100)
    // Increased to catch targeted binary keys that might be further down the list
    {
        let key_bytes_owned = if let Some(ref k) = key_info.key {
            k.clone()
        } else {
            let Ok(start) = usize::try_from(key_info.offset) else {
                continue;
            };
            let end = start.saturating_add(key_info.length).min(data.len());
            if start >= end {
                continue;
            }
            data[start..end].to_vec()
        };
        let key_bytes = &key_bytes_owned;

        if key_bytes.is_empty() {
            continue;
        }

        // Blind Decode Fallback: For HIGH confidence keys, try all shifts of the key
        // to find short or split strings (which won't match Aho-Corasick patterns).
        for shift in 0..key_bytes.len() {
            let decoded_full: Vec<u8> = data
                .iter()
                .enumerate()
                .map(|(i, &b)| b ^ key_bytes[(i + shift) % key_bytes.len()])
                .collect();

            // Use a much lower min_length for high-confidence blind decodes
            let blind_min_len = 6.min(min_length);

            let mut i = 0;
            while i < decoded_full.len() {
                if is_printable_char(decoded_full[i]) {
                    let start = i;
                    while i < decoded_full.len() && is_printable_char(decoded_full[i]) {
                        i += 1;
                    }
                    let len = i - start;
                    if len >= blind_min_len {
                        let s = String::from_utf8_lossy(&decoded_full[start..i]).to_string();
                        if let Some(kind) = classify_xor_string(&s)
                            && seen.insert((start as u64, s.clone()))
                        {
                            results.push(ExtractedString {
                                value: s,
                                data_offset: start as u64,
                                section: None,
                                method: StringMethod::XorDecode,
                                kind,
                                ..Default::default()
                            });
                        }
                    }
                } else {
                    i += 1;
                }
            }
        }

        // Build Aho-Corasick for all possible alignments of our patterns with this key.
        // For a key of length L, each pattern can be XOR'd in L different ways.
        let mut patterns = Vec::new();
        for prefix in XOR_PATTERNS {
            for shift in 0..key_bytes.len() {
                let xored: Vec<u8> = prefix
                    .iter()
                    .enumerate()
                    .map(|(i, &b): (usize, &u8)| b ^ key_bytes[(i + shift) % key_bytes.len()])
                    .collect();
                patterns.push(xored);
            }
        }

        let Ok(ac) = aho_corasick::AhoCorasick::new(patterns) else {
            continue;
        };

        // Single pass through data for all pattern alignments
        for mat in ac.find_overlapping_iter(data) {
            let mat: aho_corasick::Match = mat;
            let pattern_idx = mat.pattern().as_usize();
            // Original pattern index is pattern_idx / key_bytes.len()
            // Shift used was pattern_idx % key_bytes.len()
            let shift = pattern_idx % key_bytes.len();
            let pos = mat.start();

            // Correct alignment: key_bytes[0] should match at (pos - shift)
            // But we can just use expand_multikey_xor_string which handles arbitrary alignment
            if let Some((decoded, start, _end)) =
                expand_multikey_xor_string(data, pos, key_bytes, shift, min_length)
                && let Some(kind) = classify_xor_string(&decoded)
            {
                let offset = start as u64;
                if seen.insert((offset, decoded.clone())) {
                    results.push(ExtractedString {
                        value: decoded,
                        data_offset: offset,
                        section: None,
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

/// Expand outward from a match position to find the full multi-byte XOR'd string.
pub(crate) fn expand_multikey_xor_string(
    data: &[u8],
    match_pos: usize,
    key: &[u8],
    shift: usize,
    min_length: usize,
) -> Option<(String, usize, usize)> {
    if key.is_empty() {
        return None;
    }

    // Determine which key byte corresponds to data[match_pos]
    let pos_mod = match_pos % key.len();
    let offset_in_key = (if shift >= pos_mod {
        shift - pos_mod
    } else {
        shift + key.len() - pos_mod
    }) % key.len();

    let min_start = match_pos.saturating_sub(MAX_EXPAND_DISTANCE);
    let max_end = (match_pos + MAX_EXPAND_DISTANCE).min(data.len());

    // Expand backward
    let mut start = match_pos;
    while start > min_start {
        let k = key[(start - 1 + offset_in_key) % key.len()];
        let decoded = data[start - 1] ^ k;
        if !is_printable_char(decoded) {
            break;
        }
        start -= 1;
    }

    // Expand forward
    let mut end = match_pos;
    while end < max_end {
        let k = key[(end + offset_in_key) % key.len()];
        let decoded = data[end] ^ k;
        if !is_printable_char(decoded) {
            break;
        }
        end += 1;
    }

    if end - start < min_length {
        return None;
    }

    let decoded: Vec<u8> = data[start..end]
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[(start + i + offset_in_key) % key.len()])
        .collect();

    let s = String::from_utf8(decoded).ok()?;
    if s.len() < min_length {
        return None;
    }

    let (trimmed, trim_start) = trim_low_entropy(&s);
    let new_start = start + trim_start;
    let trimmed_end = new_start + trimmed.len();

    if !is_valid_xor_string(trimmed) {
        return None;
    }

    if is_meaningful_string(trimmed) {
        Some((trimmed.to_string(), new_start, trimmed_end))
    } else if is_meaningful_string(&s) {
        Some((s, start, end))
    } else {
        None
    }
}

/// Scan for XOR'd IP addresses and hostnames.
/// Uses memchr for fast scanning of XOR'd '.' bytes, then validates surroundings.
pub(crate) fn scan_dotted_patterns(
    data: &[u8],
    min_length: usize,
    results: &mut Vec<ExtractedString>,
    seen: &mut HashSet<(u64, String)>,
) {
    // Every byte is a '.' under exactly one key: `byte ^ '.'`. Derive that key
    // per position in a single pass instead of rescanning the whole buffer once
    // per candidate key (previously up to 255 memchr passes over `data`).
    for pos in 1..data.len().saturating_sub(1) {
        let raw = data[pos];
        let key = raw ^ b'.';
        if key == 0 || SKIP_XOR_KEYS.contains(&key) {
            continue;
        }

        // When the raw byte for '.' is a common structured-data separator,
        // numeric CSV/XAML patterns (e.g. Margin="30,10,30,0") decode as
        // fake IP addresses. Skip these keys for dotted-pattern scanning.
        if matches!(raw, b',' | b';' | b'|' | b'\t') {
            continue;
        }

        let prev = data[pos - 1] ^ key;
        let next = data[pos + 1] ^ key;

        // Check for IP address (digits around dot)
        if prev.is_ascii_digit() && next.is_ascii_digit() {
            if let Some((ip, start, _end)) = extract_ip_at_dot(data, pos, key)
                && ip.len() >= min_length.saturating_sub(2)
            {
                let offset = start as u64;
                if seen.insert((offset, ip.clone())) {
                    results.push(ExtractedString {
                        value: ip,
                        data_offset: offset,
                        section: None,
                        method: StringMethod::XorDecode,
                        kind: Some(StringKind::IP),
                        fragments: None,
                    });
                }
            }

            if let Some((ip_port, start, _end)) = extract_ip_port_at_pos(data, pos, key)
                && ip_port.len() >= min_length
            {
                let offset = start as u64;
                if seen.insert((offset, ip_port.clone())) {
                    results.push(ExtractedString {
                        value: ip_port,
                        data_offset: offset,
                        section: None,
                        method: StringMethod::XorDecode,
                        kind: Some(StringKind::IPPort),
                        fragments: None,
                    });
                }
            }
        }
        // Check for hostname (alphanumeric around dot, like evil.com)
        else if prev.is_ascii_alphanumeric()
            && next.is_ascii_alphanumeric()
            && let Some((hostname, start, _end)) =
                extract_hostname_at_dot(data, pos, key, min_length)
        {
            let offset = start as u64;
            if seen.insert((offset, hostname.clone())) {
                results.push(ExtractedString {
                    value: hostname,
                    data_offset: offset,
                    section: None,
                    method: StringMethod::XorDecode,
                    kind: Some(StringKind::Hostname),
                    fragments: None,
                });
            }
        }
    }
}

/// Extract a hostname starting from a dot position.
pub(crate) fn extract_hostname_at_dot(
    data: &[u8],
    dot_pos: usize,
    key: u8,
    min_length: usize,
) -> Option<(String, usize, usize)> {
    // Expand backward
    let mut start = dot_pos;
    while start > 0 {
        let decoded = data[start - 1] ^ key;
        if decoded.is_ascii_alphanumeric() || decoded == b'-' || decoded == b'.' {
            start -= 1;
        } else {
            break;
        }
    }

    // Expand forward
    let mut end = dot_pos + 1;
    while end < data.len() {
        let decoded = data[end] ^ key;
        if decoded.is_ascii_alphanumeric() || decoded == b'-' || decoded == b'.' {
            end += 1;
        } else {
            break;
        }
    }

    if end - start < min_length {
        return None;
    }

    let decoded: Vec<u8> = data[start..end].iter().map(|b| b ^ key).collect();
    let hostname = String::from_utf8(decoded).ok()?;

    // Basic validation: must have at least one dot
    if !hostname.contains('.') {
        return None;
    }

    // Skip common false positives
    if hostname.starts_with('.') || hostname.ends_with('.') || hostname.contains("..") {
        return None;
    }

    // Must have at least 2 parts (e.g., "evil.com")
    let parts: Vec<&str> = hostname.split('.').collect();
    if parts.len() < 2 {
        return None;
    }

    // Only accept .com TLD for single-byte XOR (too many false positives otherwise)
    let tld = parts.last()?;
    if !tld.eq_ignore_ascii_case("com") {
        return None;
    }

    // Reject hostnames with uppercase letters - real hostnames are lowercase
    if hostname.chars().any(|c| c.is_ascii_uppercase()) {
        return None;
    }

    // Reject hostnames with digits in domain parts (before TLD)
    // Real domains rarely have digits except in subdomains like "ns1" or "cdn2"
    for (i, part) in parts.iter().enumerate() {
        if i == parts.len() - 1 {
            continue; // Skip TLD
        }
        if part.chars().any(|c| c.is_ascii_digit()) {
            return None;
        }
    }

    // Domain part (before TLD) should have reasonable chars, not just repeated
    let domain = parts.first()?;
    if domain.len() < 2 {
        return None;
    }

    // Reject if domain is just repeated characters (like "zzz" or "nnn")
    let first_char = domain.chars().next()?;
    if domain.chars().all(|c| c == first_char) {
        return None;
    }

    // Reject hostnames with too many repeated characters (like "ccccccT.cc")
    let unique_chars: std::collections::HashSet<char> =
        hostname.chars().filter(|&c| c != '.').collect();
    let non_dot_len = hostname.chars().filter(|&c| c != '.').count();
    if non_dot_len > 6 && unique_chars.len() * 3 < non_dot_len {
        return None;
    }

    // Reject runs of 4+ consecutive identical characters (like "moooooob" or "lmmmmmj")
    let mut prev_char = '\0';
    let mut run_len = 1;
    for c in hostname.chars() {
        if c == prev_char {
            run_len += 1;
            if run_len >= 4 {
                return None;
            }
        } else {
            prev_char = c;
            run_len = 1;
        }
    }

    // Reject segments starting or ending with hyphen (invalid DNS)
    for part in &parts {
        if part.starts_with('-') || part.ends_with('-') {
            return None;
        }
    }

    // Reject if any single character dominates (>40% of non-dot chars)
    if non_dot_len >= 8 {
        for &c in &unique_chars {
            let count = hostname.chars().filter(|&x| x == c).count();
            if count * 100 / non_dot_len > 40 {
                return None;
            }
        }
    }

    Some((hostname, start, end))
}

/// Maximum expansion distance in each direction from match position.
const MAX_EXPAND_DISTANCE: usize = 200;

/// Distinct byte count in an 8-slot ring buffer, allocation-free. Used to
/// detect low-entropy (near-constant) regions while expanding an XOR run —
/// cheaper than collecting an 8-element `HashSet` on every expansion step.
fn distinct_bytes(buf: &[u8; 8]) -> usize {
    buf.iter()
        .enumerate()
        .filter(|&(i, b)| !buf[..i].contains(b))
        .count()
}

/// Expand outward from a match position to find the full XOR'd string.
pub(crate) fn expand_xor_string(
    data: &[u8],
    match_pos: usize,
    key: u8,
    min_length: usize,
) -> Option<(String, usize, usize)> {
    let min_start = match_pos.saturating_sub(MAX_EXPAND_DISTANCE);
    let max_end = (match_pos + MAX_EXPAND_DISTANCE).min(data.len());

    // For high-byte keys (>0x7F): null bytes in the raw binary decode to the key value itself
    // (raw=0x00 → decoded=0x00^K=K). These decoded-K values fall in the 0x80-0xF7 range,
    // which is_printable_char accepts as UTF-8 lead bytes, but they are actually null bytes
    // (string terminators) and must not be included in the expanded string.
    // For low-byte keys (<0x80): null bytes decode to printable ASCII (e.g., key=0x77→decoded='w').
    // These are naturally rejected by is_printable_char when the raw byte is 0x00 (not 'w'),
    // so no special handling is needed.
    let stop_on_key_byte = key > 0x7F;

    let mut start = match_pos;
    let mut recent_backward: [u8; 8] = [0; 8];
    let mut backward_idx = 0;
    while start > min_start {
        let decoded = data[start - 1] ^ key;
        if !is_printable_char(decoded) || (stop_on_key_byte && decoded == key) {
            break;
        }
        // Track recent chars to detect low-entropy regions
        recent_backward[backward_idx % 8] = decoded;
        backward_idx += 1;
        if backward_idx >= 8 && distinct_bytes(&recent_backward) <= 2 {
            // We've hit a low-entropy region - stop expansion
            break;
        }
        start -= 1;
    }

    // Expand forward with same logic.
    let mut end = match_pos;
    let mut recent_forward: [u8; 8] = [0; 8];
    let mut forward_idx = 0;
    while end < max_end {
        let decoded = data[end] ^ key;
        if !is_printable_char(decoded) || (stop_on_key_byte && decoded == key) {
            break;
        }
        recent_forward[forward_idx % 8] = decoded;
        forward_idx += 1;
        if forward_idx >= 8 && distinct_bytes(&recent_forward) <= 2 {
            // Stop expansion but don't backtrack - let trim_low_entropy handle the suffix
            break;
        }
        end += 1;
    }

    if end - start < min_length {
        return None;
    }

    let decoded: Vec<u8> = data[start..end].iter().map(|b| b ^ key).collect();
    let s = String::from_utf8(decoded).ok()?;

    if s.len() < min_length {
        return None;
    }

    // Trim low-entropy prefix/suffix (common XOR artifact from null padding)
    let (trimmed, trim_start) = trim_low_entropy(&s);
    let new_start = start + trim_start;
    let trimmed_end = new_start + trimmed.len();

    // Reject if the original string fails validation (garbage decode).
    if !is_valid_xor_string(&s) {
        return None;
    }

    // If the trimmed version passes validation, prefer it (cleaner output).
    // If trimming produced an invalid fragment (e.g. "bcrypt.d" from "bcrypt.dll"),
    // fall back to the original rather than rejecting entirely.
    if is_valid_xor_string(trimmed) && is_meaningful_string(trimmed) {
        Some((trimmed.to_string(), new_start, trimmed_end))
    } else if is_meaningful_string(&s) {
        Some((s, start, end))
    } else {
        None
    }
}

/// Trim low-entropy prefix/suffix from a string (XOR artifacts from padding).
/// Returns the trimmed string slice and the number of bytes trimmed from the start.
pub(crate) fn trim_low_entropy(s: &str) -> (&str, usize) {
    let bytes = s.as_bytes();
    if bytes.len() < 4 {
        return (s, 0);
    }

    // Trim leading repeated characters (common XOR artifact from null padding)
    let mut start = 0;
    let first_byte = bytes[0];
    while start < bytes.len() && bytes[start] == first_byte {
        start += 1;
    }
    // Only trim if we found a run of 2+ identical chars
    if start < 2 {
        start = 0;
    }

    // Trim trailing repeated characters
    let mut end = bytes.len();
    if end > start {
        let last_byte = bytes[end - 1];
        while end > start && bytes[end - 1] == last_byte {
            end -= 1;
        }
        // Only trim if we found a run of 2+ identical chars
        if bytes.len() - end < 2 {
            end = bytes.len();
        }
    }

    if start >= end || end - start < 4 {
        return (s, 0);
    }

    (std::str::from_utf8(&bytes[start..end]).unwrap_or(s), start)
}

/// Expand a UTF-16LE XOR'd string from a match position.
pub(crate) fn expand_xor_wide_string(
    data: &[u8],
    match_pos: usize,
    key: u8,
    min_length: usize,
) -> Option<(String, usize, usize)> {
    let mut start = match_pos;
    while start >= 2 {
        let lo = data[start - 2] ^ key;
        let hi = data[start - 1] ^ key;
        if hi != 0 || !is_printable_char(lo) {
            break;
        }
        start -= 2;
    }

    let mut end = match_pos;
    while end + 1 < data.len() {
        let lo = data[end] ^ key;
        let hi = data[end + 1] ^ key;
        if hi != 0 || !is_printable_char(lo) {
            break;
        }
        end += 2;
    }

    let byte_len = end - start;
    if byte_len < min_length * 2 {
        return None;
    }

    let mut decoded = String::with_capacity(byte_len / 2);
    let mut i = start;
    while i + 1 < end {
        let lo = data[i] ^ key;
        decoded.push(lo as char);
        i += 2;
    }

    // Reject strings with unusual punctuation
    if !is_valid_xor_string(&decoded) {
        return None;
    }

    if is_meaningful_string(&decoded) {
        Some((decoded, start, end))
    } else {
        None
    }
}

/// Try to extract a full IP address starting from a dot position.
/// Walk backward from `dot_pos` over XOR'd ASCII digits and up to three dots to
/// find where the dotted-decimal IP begins.
fn ip_scan_start(data: &[u8], dot_pos: usize, key: u8) -> usize {
    let mut start = dot_pos;
    let mut dots_before = 0;
    while start > 0 {
        let decoded = data[start - 1] ^ key;
        if decoded == b'.' {
            dots_before += 1;
            if dots_before > 3 {
                break;
            }
        } else if !decoded.is_ascii_digit() {
            break;
        }
        start -= 1;
    }
    start
}

pub(crate) fn extract_ip_at_dot(
    data: &[u8],
    dot_pos: usize,
    key: u8,
) -> Option<(String, usize, usize)> {
    let start = ip_scan_start(data, dot_pos, key);

    let mut end = dot_pos + 1;
    let mut dots_after = 0;
    while end < data.len() {
        let decoded = data[end] ^ key;
        if decoded == b'.' {
            dots_after += 1;
            if dots_after > 3 {
                break;
            }
        } else if !decoded.is_ascii_digit() {
            break;
        }
        end += 1;
    }

    let decoded: Vec<u8> = data[start..end].iter().map(|b| b ^ key).collect();
    let ip_str = String::from_utf8(decoded).ok()?;

    if !is_valid_ip(&ip_str) {
        return None;
    }

    // Reject when the raw bytes are already a plausible structured plaintext
    // of the form "digits-separator-digits..." — e.g. Go's embedded timezone
    // data `10-11-12-08-09+13` XORs under key 0x03 to `23.22.21.3;.3:.20...`,
    // producing a spurious IP. If the raw bytes are entirely digits plus a
    // single punctuation separator (and contain that separator), the original
    // data is already meaningful and the XOR match is a coincidence.
    let raw = &data[start..end];
    if !raw.is_empty() && raw.iter().all(|&b| b.is_ascii_digit() || is_numeric_sep(b)) {
        let seps: std::collections::BTreeSet<u8> =
            raw.iter().copied().filter(|b| is_numeric_sep(*b)).collect();
        if seps.len() == 1 {
            return None;
        }
    }

    if looks_like_data_table(data, start, end) {
        return None;
    }

    Some((ip_str, start, end))
}

/// ASCII punctuation bytes that commonly separate numeric fields in
/// legitimate plaintext (timezone offsets, dates, versions, CSV, ranges).
fn is_numeric_sep(b: u8) -> bool {
    matches!(b, b'-' | b'+' | b':' | b'/' | b'.' | b',' | b';' | b'_')
}

/// Returns true when the bytes in a window around `[start..end]` are dominated
/// by control-range values (< 0x20), indicating the match sits inside a
/// structured binary data table (VDBE opcodes, B-tree index pages, resource
/// tables) rather than XOR ciphertext. Real XOR-encoded strings in rodata
/// have varied byte values in their neighborhood because the plaintext spans
/// mixed characters; a slice of a small-integer table does not.
fn looks_like_data_table(data: &[u8], start: usize, end: usize) -> bool {
    const RADIUS: usize = 32;
    const THRESHOLD_PERCENT: usize = 85;
    const MIN_WINDOW: usize = 24;

    let lo = start.saturating_sub(RADIUS);
    let hi = end.saturating_add(RADIUS).min(data.len());
    let window = &data[lo..hi];
    if window.len() < MIN_WINDOW {
        return false;
    }
    let low = window.iter().filter(|&&b| b < 0x20).count();
    low * 100 >= window.len() * THRESHOLD_PERCENT
}

/// Try to extract IP:port starting from a dot position in the IP.
pub(crate) fn extract_ip_port_at_pos(
    data: &[u8],
    dot_pos: usize,
    key: u8,
) -> Option<(String, usize, usize)> {
    // First find the IP part
    let start = ip_scan_start(data, dot_pos, key);

    // Find end of IP and check for colon
    let mut end = dot_pos + 1;
    let mut dots_after = 0;
    while end < data.len() {
        let decoded = data[end] ^ key;
        if decoded == b'.' {
            dots_after += 1;
            if dots_after > 3 {
                break;
            }
        } else if decoded == b':' {
            // Found colon - now look for port
            end += 1;
            while end < data.len() {
                let d = data[end] ^ key;
                if !d.is_ascii_digit() {
                    break;
                }
                end += 1;
            }
            break;
        } else if !decoded.is_ascii_digit() {
            break;
        }
        end += 1;
    }

    let decoded: Vec<u8> = data[start..end].iter().map(|b| b ^ key).collect();
    let ip_port_str = String::from_utf8(decoded).ok()?;

    // Validate IP:port format
    if let Some((ip, port)) = ip_port_str.rsplit_once(':')
        && is_valid_ip(ip)
        && is_valid_port(port)
        && !looks_like_data_table(data, start, end)
    {
        return Some((ip_port_str, start, end));
    }

    None
}

/// Keywords that indicate credential/sensitive data when XOR-encoded.
const CREDENTIAL_KEYWORDS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "username",
    "user",
    "secret",
    "token",
    "apikey",
    "api_key",
    "bearer",
    "auth",
    "credential",
    "private",
    "key",
    "admin",
    "root",
];

/// Well-known suspicious paths that indicate malicious activity.
const SUSPICIOUS_PATHS: &[&str] = &[
    // Linux rootkit indicators
    "/proc/net/",
    "ld.so.preload",
    // Credential/key theft targets
    "/Library/Ethereum/keystore",
    "/Library/Application Support/Ethereum",
    "/.ssh/",
    "/.aws/",
    "/.gnupg/",
    "/Library/Keychains/",
    "/Keychain",
    "/wallet.dat",
    "/Library/Cookies",
    // Crypto wallet directories commonly targeted by malware
    "Wallets/Guarda",
    "Wallets/atomic",
    "Wallets/BitPay",
    "Wallets/Ethereum",
    "Wallets/Electrum",
    "Wallets/Electrum-LTC",
    "Wallets/ElectronCash",
    "Wallets/Sparrow",
    "Wallets/Monero",
    "Wallets/Jaxx",
    "Wallets/MyMonero",
    "Wallets/Coinomi",
    "Wallets/Daedalus",
    "Wallets/Wasabi",
    "Wallets/Blockstream",
    "Wallets/",
    "Exodus/exodus.wallet",
    "Exodus/exodus.conf",
    ".electrum/wallets",
    ".electrum-ltc/wallets",
    ".electron-cash/wallets",
    ".sparrow/wallets",
    "Monero/wallets",
    ".walletwasabi/",
    "Neon/storage/userWallet",
    "Daedalus Mainnet/wallets",
    "Blockstream/Green/Wallets",
    "com.bitpay.wallet",
    "/trezor.txt",
    "/specter.txt",
];

/// Trim trailing garbage from extracted strings.
/// This removes characters at the end that don't look like legitimate content.
pub(crate) fn trim_trailing_garbage(s: &str) -> &str {
    // First, check for common shell redirections and terminators that mark natural endpoints
    let natural_endpoints = [
        "2>&1",
        "2>/dev/null",
        ">/dev/null",
        ">&1",
        ">&2",
        " &",
        "EOD",
        "EOF",
    ];

    // Find the last occurrence of any natural endpoint
    let mut natural_end: Option<usize> = None;
    for endpoint in &natural_endpoints {
        if let Some(pos) = s.rfind(endpoint) {
            let candidate_end = pos + endpoint.len();
            natural_end = Some(natural_end.map_or(candidate_end, |prev| prev.max(candidate_end)));
        }
    }

    // If we found a natural endpoint, trim there
    if let Some(end_pos) = natural_end {
        return &s[..end_pos];
    }

    // Check for file extensions as natural endpoints (e.g., .php, .exe, .dll, .so)
    let file_extensions = [
        ".php", ".exe", ".dll", ".so", ".dylib", ".js", ".py", ".rb", ".pl", ".sh", ".html",
        ".xml", ".json", ".txt", ".log", ".conf", ".cfg",
    ];
    for ext in &file_extensions {
        if let Some(pos) = s.rfind(ext) {
            let candidate_end = pos + ext.len();
            natural_end = Some(natural_end.map_or(candidate_end, |prev| prev.max(candidate_end)));
        }
    }

    if let Some(end_pos) = natural_end {
        return &s[..end_pos];
    }

    // Otherwise, work backwards from the end looking for the last legitimate character
    let chars: Vec<char> = s.chars().collect();
    let mut i = chars.len();

    while i > 0 {
        i -= 1;
        let c = chars[i];

        // Stop at clear delimiters
        if c == '"' || c == '\'' || c == ')' || c == ']' || c == '}' || c == '>' {
            return s.char_indices().nth(i + 1).map_or(s, |(pos, _)| &s[..pos]);
        }

        // Stop at alphanumeric followed by whitespace or punctuation that suggests a boundary
        if c.is_ascii_alphanumeric() {
            // Check if the next character (if exists) suggests this is the end
            if i + 1 < chars.len() {
                let next = chars[i + 1];
                // If followed by unusual characters, this might be the real end
                if !next.is_ascii_alphanumeric()
                    && next != '/'
                    && next != '.'
                    && next != '-'
                    && next != '_'
                {
                    return s.char_indices().nth(i + 1).map_or(s, |(pos, _)| &s[..pos]);
                }
            } else {
                // Last character is alphanumeric - keep whole string
                return s;
            }
        }
    }

    s
}

/// Well-known shell commands and tools (for lenient matching with trailing garbage).
const SHELL_COMMANDS: &[&str] = &[
    "screencapture",
    "osascript",
    "curl ",
    "wget ",
    "bash ",
    "sh ",
    "sleep ",
    "rm -rf",
    "python ",
    "perl ",
    "ruby ",
    "powershell",
    "cmd.exe",
    "/bin/sh",
    "/bin/bash",
    "2>&1",
    "<<eod",
    "<<eof",
    ">/dev/null",
];

/// Shell executable paths that should be classified as suspicious.
const SHELL_EXECUTABLE_PATHS: &[&str] = &[
    "/bin/sh",
    "/bin/bash",
    "/bin/zsh",
    "/bin/dash",
    "/usr/bin/bash",
    "/usr/bin/sh",
    "/usr/bin/python",
    "/usr/bin/perl",
    "/usr/bin/ruby",
    "cmd.exe",
    "powershell.exe",
];

/// Cryptocurrency-related terms indicating wallet/keystore access (all lowercase).
const CRYPTO_KEYWORDS: &[&str] = &[
    "ethereum",
    "bitcoin",
    "electrum",
    "wallet",
    "keystore",
    "monero",
    "litecoin",
    "dogecoin",
    "cryptocurrency",
    "mnemonic",
    "seed phrase",
];

/// Browser and application identifiers (all lowercase).
const BROWSER_KEYWORDS: &[&str] = &[
    "safari", "chrome", "firefox", "mozilla", "webkit", "chromium", "opera", "edge",
];

/// Trim obvious garbage from the end of XOR-decoded strings.
/// Check if a string contains locale codes (language_COUNTRY or language-COUNTRY format).
/// These are often used in malware for geofencing/targeting specific regions.
///
/// Common locale patterns:
/// - en_US, en-US (English - United States)
/// - ru_RU, ru-RU (Russian - Russia)
/// - zh_CN, zh-CN (Chinese - China)
/// - Lists: "en_US;fr_FR;de_DE" or "ru_RU;be_BY;kk_KZ"
pub(crate) fn has_multiple_locales(s: &str) -> bool {
    // Common locale codes (top 15 global locales + CIS countries for malware detection)
    const COMMON_LOCALES: &[&str] = &[
        "en_US", "en-US", // English (US)
        "en_GB", "en-GB", // English (UK)
        "zh_CN", "zh-CN", // Chinese (China)
        "es_ES", "es-ES", // Spanish (Spain)
        "es_MX", "es-MX", // Spanish (Mexico)
        "fr_FR", "fr-FR", // French (France)
        "de_DE", "de-DE", // German (Germany)
        "ja_JP", "ja-JP", // Japanese (Japan)
        "pt_BR", "pt-BR", // Portuguese (Brazil)
        "ru_RU", "ru-RU", // Russian (Russia)
        "it_IT", "it-IT", // Italian (Italy)
        "ko_KR", "ko-KR", // Korean (Korea)
        "ar_SA", "ar-SA", // Arabic (Saudi Arabia)
        "hi_IN", "hi-IN", // Hindi (India)
        "tr_TR", "tr-TR", // Turkish (Turkey)
        // CIS countries (common in DPRK malware geofencing)
        "hy_AM", "hy-AM", // Armenian
        "be_BY", "be-BY", // Belarusian
        "kk_KZ", "kk-KZ", // Kazakh
        "uk_UA", "uk-UA", // Ukrainian
        "uz_UZ", "uz-UZ", // Uzbek
    ];

    // Count how many locale codes are present
    let mut locale_count = 0;
    for locale in COMMON_LOCALES {
        if s.contains(locale) {
            locale_count += 1;
            if locale_count >= 2 {
                return true; // Found at least 2 locale codes (likely a geofencing list)
            }
        }
    }

    // Single locale might be legitimate, but lists of locales are suspicious
    false
}

/// Classify an XOR-decoded string. The nested `Option` is three-state:
/// `None` = reject; `Some(None)` = keep, no specific kind; `Some(Some(k))` = keep as `k`.
pub(crate) fn classify_xor_string(s: &str) -> Option<Option<StringKind>> {
    // FIRST: Check for high-value IOCs that should bypass strict filtering.
    // These checks must come BEFORE is_partial_xor_decode to avoid false rejections
    // of legitimate paths like /proc/net/tcp that could superficially resemble
    // partial decodes of Windows environment variables.

    // Check for locale strings (common in malware geofencing)
    if has_multiple_locales(s) {
        return Some(Some(StringKind::SuspiciousPath));
    }

    // Check for well-known suspicious paths (even with garbage around them)
    for sus_path in SUSPICIOUS_PATHS {
        if s.contains(sus_path) {
            return Some(Some(StringKind::SuspiciousPath));
        }
    }

    // Check for Windows DLL names - covert dynamic loading is a strong malware indicator.
    // Names like "bcrypt.dll" have no vowels and would fail linguistic checks without this.
    if s.ends_with(".dll") || s.ends_with(".DLL") {
        return Some(Some(StringKind::SuspiciousPath));
    }

    // Check for Windows crypto/process API names - indicate AES decryption or injection.
    // These are resolved dynamically via GetProcAddress to evade static analysis.
    let win_api_patterns = [
        "BCryptOpenAlgorithmProvider",
        "BCryptGenerateSymmetricKey",
        "BCryptCloseAlgorithmProvider",
        "BCryptSetProperty",
        "BCryptDecrypt",
        "BCryptDestroyKey",
        "CreateProcessW",
        "CreateProcessA",
        "VirtualAllocEx",
        "WriteProcessMemory",
        "GetProcAddress",
        "LoadLibraryW",
        "LoadLibraryA",
        "FindWindowExW",
        "GetWindowThreadProcessId",
        "ShowWindow",
    ];
    for api in &win_api_patterns {
        if s.contains(api) {
            return Some(Some(StringKind::SuspiciousPath));
        }
    }

    // EARLY REJECTION: Check for partial/failed XOR decodes before any classification.
    // These are strings that start like known patterns (e.g., "%USERPROFILE%") but
    // diverge into garbage (e.g., "%UsERP4NFINE%\"). Must check this BEFORE
    // is_meaningful_string() which might pass these due to acceptable vowel ratios.
    if super::validate::is_partial_xor_decode(s) {
        return None;
    }

    // Defer lowercase allocation until needed for case-insensitive checks.
    let lower = s.to_ascii_lowercase();

    // Check for shell executable paths (before shell commands)
    for exe_path in SHELL_EXECUTABLE_PATHS {
        if lower.contains(exe_path) {
            return Some(Some(StringKind::SuspiciousPath));
        }
    }

    // Check for well-known shell commands (even with trailing garbage)
    for cmd in SHELL_COMMANDS {
        if lower.contains(cmd) {
            return Some(Some(StringKind::ShellCmd));
        }
    }

    // Check for credential keywords
    for keyword in CREDENTIAL_KEYWORDS {
        if lower.contains(keyword) {
            return Some(Some(StringKind::SuspiciousPath));
        }
    }

    // Check for browser/app data exfiltration targets
    let exfil_indicators = [
        "extension settings",
        "local storage",
        "cookies",
        "bookmarks",
        "history",
        "preferences",
        "session",
        "cache",
        "telegram",
        "discord",
        "slack",
        "signal",
        "whatsapp",
        "tdata",
        "desktop folder",
        "documents folder",
    ];

    for indicator in &exfil_indicators {
        if lower.contains(indicator) {
            return Some(Some(StringKind::SuspiciousPath));
        }
    }

    // Quick check for URLs/IPs before strict filtering
    if lower.contains("http://") || lower.contains("https://") || lower.contains("://") {
        // Likely a URL, allow through
        let kind = classify_string(s);
        if matches!(kind, Some(StringKind::Url)) {
            return Some(kind);
        }
    }

    // Check for IP addresses (pattern: digits.digits.digits.digits)
    if s.chars().filter(|&c| c == '.').count() == 3 {
        let segments: Vec<&str> = s.split('.').collect();
        if segments.len() == 4
            && segments.iter().all(|seg| {
                !seg.is_empty() && seg.chars().all(|c| c.is_ascii_digit()) && seg.len() <= 3
            })
        {
            // Likely an IP address, allow through
            let kind = classify_string(s);
            if matches!(kind, Some(StringKind::IP) | Some(StringKind::IPPort)) {
                return Some(kind);
            }
        }
    }

    // SECOND: Check if string looks like well-formed text
    // If it passes linguistic validation, trust it
    if is_meaningful_string(s) {
        // String looks legitimate - classify it
        let kind = classify_string(s);

        // Accept meaningful strings that classify as high-value IOCs
        // NOTE: Const is intentionally excluded - it must pass strict validation below
        // NOTE: Path is intentionally excluded - paths must go through strict validation below
        if matches!(
            kind,
            Some(StringKind::SuspiciousPath)
                | Some(StringKind::ShellCmd)
                | Some(StringKind::IP)
                | Some(StringKind::IPPort)
                | Some(StringKind::Url)
        ) {
            return Some(kind);
        }
    }

    // Reject strings dominated by a single character (e.g. repeated spaces XORed)
    // This catches false positives like sequences of spaces being XORed into valid base64 chars.
    let char_count = s.chars().count();
    if char_count >= 16 {
        let mut char_counts = std::collections::HashMap::new();
        let mut max_count = 0;
        for c in s.chars() {
            let entry = char_counts.entry(c).or_insert(0);
            *entry += 1;
            if *entry > max_count {
                max_count = *entry;
            }
        }
        if max_count * 2 > char_count {
            return None;
        }
    }

    // SECOND+: Check for encoded data formats directly
    // Base64, hex, and url-encoded strings don't pass linguistic checks but are high-value IOCs.
    // classify_string handles proper format validation (length, charset, structure).
    {
        let kind = classify_string(s);
        if matches!(
            kind,
            Some(StringKind::Base64) | Some(StringKind::HexEncoded) | Some(StringKind::UrlEncoded)
        ) {
            return Some(kind);
        }
        // XOR decoding may strip trailing '=' padding from base64 (e.g., '=' XOR 0x42 = 0x7F,
        // which is non-printable and gets cut off by the scan). Try re-adding padding.
        let remainder = s.len() % 4;
        if remainder == 2 || remainder == 3 {
            let padding = if remainder == 2 { "==" } else { "=" };
            let padded = format!("{s}{padding}");
            if matches!(classify_string(&padded), Some(StringKind::Base64)) {
                return Some(Some(StringKind::Base64));
            }
        }
    }

    // THIRD: For strings that don't pass linguistic checks, apply strict filtering
    if !is_valid_xor_string(s) {
        return None;
    }

    // Classify remaining strings that passed strict validation
    let kind = classify_string(s);

    match kind {
        Some(StringKind::IP)
        | Some(StringKind::IPPort)
        | Some(StringKind::Url)
        | Some(StringKind::SuspiciousPath)
        | Some(StringKind::UnicodeEscaped)
        | Some(StringKind::HexEncoded)
        | Some(StringKind::UrlEncoded)
        | Some(StringKind::Registry)
        | Some(StringKind::Base64) => Some(kind),
        Some(StringKind::ShellCmd) | Some(StringKind::AppleScript) => {
            // Reject obvious garbage that starts with backtick but no valid command
            if s.starts_with('`')
                && !s[1..]
                    .trim_start()
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic())
            {
                None
            } else {
                Some(kind)
            }
        }
        Some(StringKind::Path) => {
            // STRICT PATH VALIDATION: Only accept paths matching known OS patterns

            // Check for known UNIX/macOS path prefixes
            let has_known_prefix = has_known_path_prefix(s);

            // Check for Windows paths with drive letter
            let is_windows_path = s.len() > 3
                && s.chars().nth(1) == Some(':')
                && s.chars().nth(2) == Some('\\')
                && s.chars().next().is_some_and(|c| c.is_ascii_alphabetic());

            // Check for relative paths with proper structure
            let is_relative_path = (s.starts_with("./") || s.starts_with("../"))
                && s.matches('/').count() >= 2
                && s.split('/')
                    .filter(|p| !p.is_empty() && *p != "." && *p != "..")
                    .count()
                    >= 1;

            if !has_known_prefix && !is_windows_path && !is_relative_path {
                return None;
            }

            // Reject if path has too many non-path characters
            let bad_chars = s
                .chars()
                .filter(|&c| {
                    !c.is_alphanumeric()
                        && !matches!(c, '/' | '\\' | '.' | '_' | '-' | ' ' | ':' | '%')
                })
                .count();

            // Reject if > 10% bad characters
            if bad_chars * 10 > s.len() {
                return None;
            }

            // For UNIX paths, ensure they have proper structure
            if s.starts_with('/') {
                let parts: Vec<&str> = s.split('/').filter(|p| !p.is_empty()).collect();

                // Single-level paths (like "/something") need to match known patterns
                if parts.len() == 1 {
                    let name = parts[0];

                    // Check if it matches known single-level paths
                    let known_single_level = [
                        "bin",
                        "etc",
                        "usr",
                        "var",
                        "tmp",
                        "dev",
                        "opt",
                        "home",
                        "root",
                        "Library",
                        "Users",
                        "Applications",
                        "System",
                        "private",
                    ];

                    if !known_single_level.contains(&name) {
                        // For other single-level paths, apply strict validation
                        let has_upper = name.chars().any(|c| c.is_ascii_uppercase());
                        let has_lower = name.chars().any(|c| c.is_ascii_lowercase());
                        let has_digit = name.chars().any(|c| c.is_ascii_digit());

                        // Reject paths with mixed case + digits (garbage pattern)
                        if has_upper && has_lower && has_digit {
                            return None;
                        }

                        // Reject if it alternates between upper/lower too much (gibberish)
                        let mut case_changes = 0;
                        let mut prev_was_upper = false;
                        for c in name.chars().filter(char::is_ascii_alphabetic) {
                            let is_upper = c.is_ascii_uppercase();
                            if prev_was_upper != is_upper {
                                case_changes += 1;
                            }
                            prev_was_upper = is_upper;
                        }
                        // Real paths rarely change case more than 2-3 times
                        if case_changes > 3 {
                            return None;
                        }
                    }
                }

                // Multi-level paths should have reasonable component names
                for part in &parts {
                    // Each component should be mostly alphanumeric
                    let alnum = part.chars().filter(char::is_ascii_alphanumeric).count();
                    if !part.is_empty() && alnum * 100 / part.len() < 60 {
                        return None;
                    }
                }
            }

            Some(kind)
        }
        _ => {
            // Generic fallback for Const and other types
            // Apply additional quality checks to avoid false positives
            // Use character count for proper Unicode support
            let char_count = s.chars().count();

            // Reject strings with too many special characters
            let special_chars = s
                .chars()
                .filter(|&c| {
                    !c.is_alphanumeric() && !c.is_whitespace() && c != '-' && c != '_' && c != '.'
                })
                .count();

            // Reject if > 40% special characters (garbage indicator)
            if char_count > 0 && special_chars * 10 > char_count * 4 {
                return None;
            }

            // Longer strings with spaces should look like natural text
            if char_count >= 30 && s.contains(' ') {
                if looks_like_text(s) {
                    return Some(None);
                }
                return None;
            }

            // Short strings: must be mostly alphanumeric
            // Use character count for proper Unicode support
            let char_count = s.chars().count();
            let alnum = s.chars().filter(|c| c.is_alphanumeric()).count();
            if char_count > 0 && alnum * 10 < char_count * 6 {
                // < 60% alphanumeric = likely garbage
                return None;
            }

            Some(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        clean_url_trailing_garbage, extract_ip_at_dot, looks_like_data_table, value_is_key_echo,
    };

    #[test]
    fn clean_url_trailing_garbage_handles_multibyte_domain_url() {
        assert_eq!(
            clean_url_trailing_garbage("http://hackers.Tv/indexяhph,l1Ĉ"),
            "http://hackers.Tv/indexяhph,l1Ĉ"
        );
    }

    #[test]
    fn clean_url_trailing_garbage_trims_after_multibyte_domain_url() {
        assert_eq!(
            clean_url_trailing_garbage("http://hackers.Tv/indexяhph,l1Ĉ!@"),
            "http://hackers.Tv/indexяhph,l1Ĉ"
        );
    }

    #[test]
    fn clean_url_trailing_garbage_handles_ip_port_before_multibyte_suffix() {
        assert_eq!(
            clean_url_trailing_garbage("http://46.30.191.141:8080Ĉgarbage"),
            "http://46.30.191.141:8080"
        );
    }

    // Place the 9 raw bytes that XOR-decode to "32.93.2.3" under key 0x33
    // (0x00 0x01 0x1d 0x0a 0x00 0x1d 0x01 0x1d 0x00) inside a window filled
    // with other small integers — the shape of sqlite3's VDBE opcode or
    // B-tree index tables. The extracted "IP" passes is_valid_ip but the
    // surrounding region is clearly a data table, not ciphertext.
    fn low_byte_table_with_ip_pattern() -> (Vec<u8>, usize) {
        let mut data = vec![
            0x02, 0x00, 0x0c, 0x04, 0x00, 0x05, 0x01, 0x0a, 0x00, 0x08, 0x00, 0x03, 0x07, 0x01,
            0x0f, 0x00, 0x02, 0x00, 0x0c, 0x04, 0x00, 0x05, 0x01, 0x0a, 0x00, 0x08, 0x00, 0x03,
            0x07, 0x01, 0x0f, 0x00,
        ];
        let ip_offset = data.len();
        data.extend_from_slice(&[0x00, 0x01, 0x1d, 0x0a, 0x00, 0x1d, 0x01, 0x1d, 0x00]);
        data.extend_from_slice(&[
            0x02, 0x00, 0x0c, 0x04, 0x00, 0x05, 0x01, 0x0a, 0x00, 0x08, 0x00, 0x03, 0x07, 0x01,
            0x0f, 0x00, 0x02, 0x00, 0x0c, 0x04, 0x00, 0x05, 0x01, 0x0a, 0x00, 0x08, 0x00, 0x03,
            0x07, 0x01, 0x0f, 0x00,
        ]);
        // The first '.' in the decoded IP sits two bytes in (index ip_offset + 2).
        (data, ip_offset + 2)
    }

    #[test]
    fn data_table_context_rejects_spurious_ip() {
        let (data, dot_pos) = low_byte_table_with_ip_pattern();
        assert!(
            extract_ip_at_dot(&data, dot_pos, 0x33).is_none(),
            "IP-shaped match inside a low-byte data table must be rejected"
        );
    }

    #[test]
    fn varied_context_preserves_real_ip() {
        // Same 9-byte raw pattern under key 0x33, but embedded in .rodata-like
        // bytes (printable strings, pointers): the neighborhood is varied, so
        // the match survives. This guards against the new filter over-rejecting.
        // Boundary byte 0x13 flanks the IP so the walk terminates cleanly
        // (0x13 ^ 0x33 = 0x20 space, not a digit/dot).
        let mut data: Vec<u8> = b"GET /index.html HTTP/1.1 Host example com ".to_vec();
        data.push(0x13);
        let ip_offset = data.len();
        data.extend_from_slice(&[0x00, 0x01, 0x1d, 0x0a, 0x00, 0x1d, 0x01, 0x1d, 0x00]);
        data.push(0x13);
        data.extend_from_slice(b" User-Agent Mozilla 5.0 Windows NT 10.0 trailing");
        let dot_pos = ip_offset + 2;
        let extracted = extract_ip_at_dot(&data, dot_pos, 0x33);
        assert_eq!(
            extracted.map(|(ip, _, _)| ip),
            Some("32.93.2.3".to_string()),
            "real XOR-encoded IP in varied context should still be extracted"
        );
    }

    #[test]
    fn looks_like_data_table_thresholds() {
        // All-low-byte window: structured table.
        let low = vec![0x03u8; 64];
        assert!(looks_like_data_table(&low, 20, 29));

        // All-high-byte window: definitely not a table.
        let high = vec![0x80u8; 64];
        assert!(!looks_like_data_table(&high, 20, 29));

        // Mixed window (~12% low): random-looking ciphertext.
        let mut mixed = vec![0x55u8; 64];
        for i in (0..64).step_by(8) {
            mixed[i] = 0x03;
        }
        assert!(!looks_like_data_table(&mixed, 20, 29));

        // Tiny buffer: can't judge, don't reject.
        let tiny = vec![0x00u8; 8];
        assert!(!looks_like_data_table(&tiny, 0, 8));
    }

    #[test]
    fn key_echo_flags_garbled_copies_of_key() {
        // Real reproduction: an OpenAPI schema repeating "OAuth2AuthorizationCode"
        // makes the scanner derive that token as a key; XORing smears "auth"/"code"
        // shards across the output. Those shards must be recognized as key echoes.
        let key = "\"oauth2authorizationcode\": {";
        for garbage in [
            "l 6w]d8authm",          // contains key shard "auth"
            "8tt1tm2authfxczatilnl", // contains "auth", "atil" shards
            "p*%rtj8authorizc#!*<",  // contains "authoriz" shard
            "i<aht38authoriz",
        ] {
            assert!(
                value_is_key_echo(garbage, key),
                "expected {garbage:?} to be flagged as an echo of {key:?}"
            );
        }
    }

    #[test]
    fn key_echo_ignores_genuine_plaintext() {
        // A real key is high-entropy bytes; genuinely decoded plaintext shares no
        // alphanumeric window with it, so true positives must NOT be flagged.
        let key = "sup3rs3cr3tk3y!!".to_ascii_lowercase();
        for real in [
            "http://evil.example.com/gate.php",
            "/bin/sh -c 'curl http://1.2.3.4/x'",
            "schtasks /create /tn updater",
        ] {
            assert!(
                !value_is_key_echo(real, &key),
                "did not expect {real:?} to be flagged as an echo of {key:?}"
            );
        }
        // Punctuation/whitespace windows of the key must not match (we only key off
        // alphanumeric shards), and sub-window inputs are ignored.
        assert!(!value_is_key_echo("ab", "abcdef"));
        assert!(!value_is_key_echo("nothing in common", "\": { } ,"));
    }

    // End-to-end: a benign, text-rich buffer that repeats an "auth"-laden token
    // must NOT yield a spurious auto-detected XOR key (and therefore no XOR
    // strings). This is the authgent_server false positive in miniature.
    #[test]
    fn repetitive_auth_text_yields_no_xor_strings() {
        let mut data = String::new();
        for _ in 0..40 {
            data.push_str(
                "\"OAuth2AuthorizationCode\": { \"authorizationUrl\": \"/authorize\", \
                 \"tokenUrl\": \"/token\", \"scopes\": {} },\n",
            );
        }
        let opts = crate::ExtractOptions::new(6)
            .with_garbage_filter(true)
            .with_xor(None);
        let strings = crate::extract_strings_with_options(data.as_bytes(), &opts);
        let xor_count = strings
            .iter()
            .filter(|s| {
                matches!(
                    s.method,
                    crate::StringMethod::XorDecode | crate::StringMethod::XorStackPair
                )
            })
            .count();
        assert_eq!(
            xor_count, 0,
            "repetitive benign auth text must not auto-detect an XOR key"
        );
    }
}
