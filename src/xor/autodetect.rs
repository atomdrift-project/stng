//! Single-byte or short repeating key auto-detection: candidate keys from
//! the file's own strings, scored by what they decode.

use super::MAX_AUTO_DETECT_SIZE;
use super::key::{is_good_xor_key_candidate, score_xor_key_candidate};
use super::scan::extract_custom_xor_strings;
use super::validate::{has_known_path_prefix, is_locale_string};
use crate::bytes::entropy;
use crate::{ExtractedString, StringKind};
use rayon::prelude::*;
use std::collections::HashSet;
use std::sync::LazyLock;

/// True if `value_lower` contains any 4-character alphanumeric window of
/// `key_lower` — meaning the "decoded" string is just a garbled copy of the key
/// (a self-XOR artifact), not genuine recovered plaintext. Both arguments must
/// already be ASCII-lowercased.
///
/// Windows are restricted to alphanumeric runs so we key off surviving text
/// shards (e.g. `auth`, `code`) rather than punctuation/whitespace fragments of
/// the key, which would match far too loosely.
pub(super) fn value_is_key_echo(value_lower: &str, key_lower: &str) -> bool {
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

/// Strings that, decoded under a candidate key, make it worth a full scan.
#[allow(clippy::expect_used)] // static patterns
pub(super) static KILLER_PATTERNS: LazyLock<aho_corasick::AhoCorasick> = LazyLock::new(|| {
    aho_corasick::AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build([
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
        ])
        .expect("killer patterns")
});

/// How strongly the strings decoded under `key` look like a real payload:
/// shell commands, crypto and browser targets, network indicators and paths,
/// weighted by how rarely noise produces each. A value counts once, so
/// garbled repeats of one string cannot inflate the score.
pub(super) fn decode_score(results: &[ExtractedString], key: &str) -> i32 {
    // Use a set of already-scored values to avoid counting duplicate strings
    // multiple times: real XOR keys decode to diverse content, but false-positive
    // keys (e.g., a library path XOR'd with near-zero code) produce repetitive
    // garbled copies of the key text that would otherwise inflate the score.
    let mut score = 0;
    let mut scored_values: HashSet<String> = HashSet::new();
    let key_lower = key.to_ascii_lowercase();

    for r in results {
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
            Some(StringKind::Url | StringKind::Ip | StringKind::IpPort)
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
        if matches!(r.kind, Some(StringKind::ShellCmd)) && scored_values.insert(value_lower.clone())
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
    score
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
            let entropy = entropy(s.value.as_bytes());
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

    let mut promising_candidates = Vec::new();
    for (offset, candidate) in &candidates {
        let key = candidate.as_bytes();
        let decoded: Vec<u8> = quick_data
            .iter()
            .enumerate()
            .map(|(i, &byte)| byte ^ key[i % key.len()])
            .collect();

        // Search decoded bytes directly — no UTF-8 conversion needed
        let found = KILLER_PATTERNS.is_match(&decoded);
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
    // Each candidate scans the whole input, so test them in parallel once the
    // input is large enough to repay it (see `crate::par`).
    let job_len = crate::par::job_len(candidates_to_test.len(), data.len());
    let candidate_scores: Vec<(i32, u64, String, Vec<u8>)> = candidates_to_test
        .into_par_iter()
        .with_min_len(job_len)
        .filter_map(|(offset, candidate): (u64, &str)| {
            let key = candidate.as_bytes().to_vec();
            // Enable early termination for auto-detection to speed up candidate testing
            let results = extract_custom_xor_strings(data, &key, min_length, true);

            // Sanity check: if we extracted way too many strings, it's likely noise
            if results.len() > 5000 {
                return None;
            }

            let score = decode_score(&results, candidate);
            Some((score, offset, candidate.to_string(), key))
        })
        .collect();

    // The first candidate with the highest score wins.
    let mut best: Option<(i32, Vec<u8>, String, u64)> = None;
    for (score, offset, candidate, key) in candidate_scores {
        if score > best.as_ref().map_or(0, |b| b.0) {
            best = Some((score, key, candidate, offset));
        }
    }

    // Any key decodes to mostly printable bytes, so a key must earn a high
    // score: 375 is five distinct suspicious paths (75 each). A handful of
    // garbled path matches does not reach it; real samples, with shell
    // commands (100+) or C2 URLs, do.
    let (score, key, key_str, offset) = best.filter(|b| b.0 >= 375)?;
    // A `?` field, not interpolation: the key is the sample's bytes, and
    // Debug escapes the CR or newline that would forge a log line.
    tracing::info!(key = ?key_str, score, "Auto-detected XOR key");
    Some((key, key_str, offset))
}

/// Cryptocurrency-related terms indicating wallet/keystore access (all lowercase).
pub(super) const CRYPTO_KEYWORDS: &[&str] = &[
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
pub(super) const BROWSER_KEYWORDS: &[&str] = &[
    "safari", "chrome", "firefox", "mozilla", "webkit", "chromium", "opera", "edge",
];
