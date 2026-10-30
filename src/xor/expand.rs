//! Single-byte XOR pattern hits grown into whole strings: dotted hostnames
//! and IP addresses, wide strings, and runs bounded by entropy.

use super::classify::{Verdict, classify_xor_string};
use super::scan::XOR_PATTERNS;
use super::validate::{
    is_meaningful_string, is_printable_char, is_valid_ip, is_valid_port, is_valid_xor_string,
    nul_ends_string, reads_as_text,
};
use super::{MAX_XOR_SCAN_SIZE, SKIP_XOR_KEYS};
use crate::{ExtractedString, StringKind, StringMethod};
use std::collections::HashSet;

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

    let mut results = Vec::new();
    let mut seen: HashSet<(u64, String)> = HashSet::new();

    for (pos, key, is_wide) in super::scan::single_byte_xor_anchors(data, scan_wide) {
        // Wide (UTF-16LE) and narrow matches differ only in the expander and the
        // provenance suffix; the recording is identical.
        let expanded = if is_wide {
            expand_xor_wide_string(data, pos, key, min_length)
        } else {
            expand_xor_string(data, pos, key, min_length)
        };
        if let Some((decoded, start, end)) = expanded
            && let Verdict::Keep(kind) = classify_xor_string(&decoded)
            && (kind.is_some() || !reads_as_text(&data[start..end]))
        {
            let offset = start as u64;
            if seen.insert((offset, decoded.clone())) {
                results.push(ExtractedString {
                    value: decoded,
                    data_offset: offset,
                    // True source extent `[start, end)` — for a wide xor string
                    // this is 2× the decoded length, which `value.len()` misses.
                    data_len: u32::try_from(end - start).unwrap_or(u32::MAX),
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

/// Strings decrypted with multi-byte XOR keys found at `key_offsets`: the
/// offsets of data a disassembler saw code load next to a `xor`
/// ([`ExternalHints::xor_key_offsets`](crate::ExternalHints)). The key's
/// length is unknown, so 16, 32 and 8 bytes are tried at each.
pub(crate) fn extract_multikey_xor_strings(
    data: &[u8],
    key_offsets: &[u64],
    min_length: usize,
) -> Vec<ExtractedString> {
    // Blind decoding reads the whole file once per key rotation, up to 56
    // per key offset, and the disassembler reports as many offsets as the
    // binary shows it loads. Bound it in input size, in bytes decoded (about
    // 256 passes over the largest input) and in strings kept.
    const MAX_BLIND_RESULTS: usize = 5000;
    const MAX_BLIND_WORK: usize = 256 * MAX_XOR_SCAN_SIZE;
    let mut blind = data.len() <= MAX_XOR_SCAN_SIZE;
    let mut blind_work = 0usize;
    let mut decoded_full = Vec::new();
    let mut results = Vec::new();
    let mut seen: HashSet<(u64, String)> = HashSet::new();

    // The key's length is unknown, so try the common ones at each offset; the
    // first 100 (offset, length) pairs bound the work.
    let keys = key_offsets
        .iter()
        .flat_map(|&offset| [16, 32, 8].map(|length| (offset, length)))
        .take(100);
    for (offset, length) in keys {
        let Ok(start) = usize::try_from(offset) else {
            continue;
        };
        let end = start.saturating_add(length).min(data.len());
        if start >= end {
            continue;
        }
        let key_bytes = &data[start..end];

        // Decode under every rotation of the key, to find short or split
        // strings that no Aho-Corasick pattern would anchor.
        for shift in 0..key_bytes.len() {
            if !blind || results.len() >= MAX_BLIND_RESULTS {
                break;
            }
            blind_work += data.len();
            if blind_work > MAX_BLIND_WORK {
                tracing::debug!(
                    MAX_BLIND_WORK,
                    "multi-key XOR: blind decode budget exhausted"
                );
                blind = false;
                break;
            }
            decoded_full.clear();
            decoded_full.extend(
                data.iter()
                    .enumerate()
                    .map(|(i, &b)| b ^ key_bytes[(i + shift) % key_bytes.len()]),
            );

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
                        if let Verdict::Keep(kind) = classify_xor_string(&s)
                            && seen.insert((start as u64, s.clone()))
                        {
                            results.push(ExtractedString {
                                value: s,
                                data_offset: start as u64,
                                // Single-byte xor is 1:1 over `[start, i)`.
                                data_len: u32::try_from(len).unwrap_or(u32::MAX),
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
            let pattern_idx = mat.pattern().as_usize();
            // Original pattern index is pattern_idx / key_bytes.len()
            // Shift used was pattern_idx % key_bytes.len()
            let shift = pattern_idx % key_bytes.len();
            let pos = mat.start();

            // Correct alignment: key_bytes[0] should match at (pos - shift)
            // But we can just use expand_multikey_xor_string which handles arbitrary alignment
            if let Some((decoded, start, end)) =
                expand_multikey_xor_string(data, pos, key_bytes, shift, min_length)
                && let Verdict::Keep(kind) = classify_xor_string(&decoded)
            {
                let offset = start as u64;
                if seen.insert((offset, decoded.clone())) {
                    results.push(ExtractedString {
                        value: decoded,
                        data_offset: offset,
                        data_len: u32::try_from(end - start).unwrap_or(u32::MAX),
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
    // per candidate key.
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
            if let Some((ip, start, end)) = extract_ip_at_dot(data, pos, key)
                && ip.len() >= min_length.saturating_sub(2)
            {
                let offset = start as u64;
                if seen.insert((offset, ip.clone())) {
                    results.push(ExtractedString {
                        value: ip,
                        data_offset: offset,
                        data_len: u32::try_from(end - start).unwrap_or(u32::MAX),
                        method: StringMethod::XorDecode,
                        kind: Some(StringKind::Ip),
                        fragments: None,
                    });
                }
            }

            if let Some((ip_port, start, end)) = extract_ip_port_at_pos(data, pos, key)
                && ip_port.len() >= min_length
            {
                let offset = start as u64;
                if seen.insert((offset, ip_port.clone())) {
                    results.push(ExtractedString {
                        value: ip_port,
                        data_offset: offset,
                        data_len: u32::try_from(end - start).unwrap_or(u32::MAX),
                        method: StringMethod::XorDecode,
                        kind: Some(StringKind::IpPort),
                        fragments: None,
                    });
                }
            }
        }
        // Check for hostname (alphanumeric around dot, like evil.com)
        else if prev.is_ascii_alphanumeric()
            && next.is_ascii_alphanumeric()
            && let Some((hostname, start, end)) =
                extract_hostname_at_dot(data, pos, key, min_length)
        {
            let offset = start as u64;
            if seen.insert((offset, hostname.clone())) {
                results.push(ExtractedString {
                    value: hostname,
                    data_offset: offset,
                    data_len: u32::try_from(end - start).unwrap_or(u32::MAX),
                    method: StringMethod::XorDecode,
                    kind: Some(StringKind::Hostname),
                    fragments: None,
                });
            }
        }
    }
}

/// Longest DNS name (RFC 1035): a longer run of hostname bytes is not one.
pub(super) const MAX_HOSTNAME: usize = 253;

/// Extract a hostname starting from a dot position.
pub(crate) fn extract_hostname_at_dot(
    data: &[u8],
    dot_pos: usize,
    key: u8,
    min_length: usize,
) -> Option<(String, usize, usize)> {
    let is_host_byte = |i: usize| {
        let decoded = data[i] ^ key;
        decoded.is_ascii_alphanumeric() || decoded == b'-' || decoded == b'.'
    };
    // Expand at most one byte past the longest legal name each way: callers
    // try every dot, so an unbounded walk is quadratic in a long run.
    let mut start = dot_pos;
    while start > 0 && dot_pos - start <= MAX_HOSTNAME && is_host_byte(start - 1) {
        start -= 1;
    }
    let mut end = dot_pos + 1;
    while end < data.len() && end - dot_pos <= MAX_HOSTNAME && is_host_byte(end) {
        end += 1;
    }

    if end - start < min_length || end - start > MAX_HOSTNAME {
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
pub(super) const MAX_EXPAND_DISTANCE: usize = 200;

/// Distinct byte count in an 8-slot ring buffer, allocation-free. Used to
/// detect low-entropy (near-constant) regions while expanding an XOR run —
/// cheaper than collecting an 8-element `HashSet` on every expansion step.
pub(super) fn distinct_bytes(buf: &[u8; 8]) -> usize {
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

    // A raw NUL decodes to the key itself (0x00 ^ K = K), which is printable
    // for most keys, so the printable test alone runs through terminators and
    // into every neighboring string: a table of NUL-terminated paths under key
    // 0x26 ('&') expanded to "&&/proc/self/fd/&&/var/tmp/.b&&&&&/tmp/.b&…",
    // which fails validation, so not even the anchored path was reported.
    // [`nul_ends_string`] tells a terminator from a plaintext byte equal to
    // the key.
    let mut start = match_pos;
    let mut recent_backward: [u8; 8] = [0; 8];
    let mut backward_idx = 0;
    while start > min_start {
        let decoded = data[start - 1] ^ key;
        if !is_printable_char(decoded)
            || (data[start - 1] == 0 && nul_ends_string(data, start - 1, key))
        {
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
        if !is_printable_char(decoded) || (data[end] == 0 && nul_ends_string(data, end, key)) {
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
    // Same reach as the narrow expander, in UTF-16 units: callers expand
    // every hit, so an unbounded walk is quadratic in a long run.
    let reach = 2 * MAX_EXPAND_DISTANCE;
    let mut start = match_pos;
    while start >= 2 && match_pos - start < reach {
        let lo = data[start - 2] ^ key;
        let hi = data[start - 1] ^ key;
        if hi != 0 || !is_printable_char(lo) {
            break;
        }
        start -= 2;
    }

    let mut end = match_pos;
    while end + 1 < data.len() && end - match_pos < reach {
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
pub(super) fn ip_scan_start(data: &[u8], dot_pos: usize, key: u8) -> usize {
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
pub(super) fn is_numeric_sep(b: u8) -> bool {
    matches!(b, b'-' | b'+' | b':' | b'/' | b'.' | b',' | b';' | b'_')
}

/// Returns true when the bytes in a window around `[start..end]` are dominated
/// by control-range values (< 0x20), indicating the match sits inside a
/// structured binary data table (VDBE opcodes, B-tree index pages, resource
/// tables) rather than XOR ciphertext. Real XOR-encoded strings in rodata
/// have varied byte values in their neighborhood because the plaintext spans
/// mixed characters; a slice of a small-integer table does not.
pub(super) fn looks_like_data_table(data: &[u8], start: usize, end: usize) -> bool {
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
