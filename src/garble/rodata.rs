//! Garble rodata byte-pair scanner.
//!
//! Garble's "simple" transformation stores encrypted data and key as
//! same-length byte arrays in .rodata. This module finds such pairs and
//! tries XOR/ADD/SUB to recover the original strings.

use crate::types::{ExtractedString, StringKind, StringMethod};
use std::collections::{HashMap, HashSet};

use super::ops::GarbleOp;

/// Extract garble-obfuscated strings from rodata by pairing byte arrays.
///
/// Garble's "simple" transformation stores encrypted data and key as byte arrays in
/// .rodata. This function finds same-length non-printable byte sequences and tries
/// combining them with XOR/ADD/SUB to recover the original strings.
///
/// # Parameters
/// - `rodata`: The .rodata section contents
/// - `rodata_file_offset`: File offset where rodata starts (for reporting)
/// - `min_length`: Minimum string length to extract
pub fn extract_garble_rodata_strings(
    rodata: &[u8],
    rodata_file_offset: u64,
    min_length: usize,
) -> Vec<ExtractedString> {
    // Configuration
    const MIN_BLOB_LEN: usize = 4; // Minimum blob length to consider
    const MAX_BLOB_LEN: usize = 256; // Maximum blob length (garble strings are typically short)
    const MAX_PAIR_DISTANCE: usize = 8192; // Max distance between key and data in bytes
    const MIN_SCORE_THRESHOLD: i32 = 12; // Minimum score to accept a result

    let mut results = Vec::new();
    let mut seen_strings: HashSet<String> = HashSet::new();

    // Find all non-printable byte blobs
    let blobs = find_nonprintable_blobs(rodata, MIN_BLOB_LEN, MAX_BLOB_LEN);
    if blobs.len() < 2 {
        return results;
    }

    // Group blobs by length
    let mut by_len: HashMap<usize, Vec<(usize, &[u8])>> = HashMap::new();
    for (offset, blob) in &blobs {
        by_len.entry(blob.len()).or_default().push((*offset, *blob));
    }

    // Reusable buffer to avoid per-pair allocation
    let mut buf = Vec::with_capacity(MAX_BLOB_LEN);

    // For each length group, try pairing blobs that are close together
    for (_len, group) in by_len {
        if group.len() < 2 {
            continue;
        }

        // Sort by offset for efficient distance checking
        let mut sorted = group;
        sorted.sort_by_key(|(off, _)| *off);

        // Try pairs within MAX_PAIR_DISTANCE
        for i in 0..sorted.len() {
            for j in (i + 1)..sorted.len() {
                let (off_a, blob_a) = sorted[i];
                let (off_b, blob_b) = sorted[j];

                // Stop if too far apart
                if off_b - off_a > MAX_PAIR_DISTANCE {
                    break;
                }

                // Try all operators, keep the best result
                let mut best: Option<(String, i32)> = None;

                for op in GarbleOp::ALL {
                    if let Some((s, score)) = try_decode_pair(
                        blob_a,
                        blob_b,
                        op,
                        min_length,
                        MIN_SCORE_THRESHOLD,
                        &mut buf,
                    ) {
                        if best.as_ref().is_none_or(|(_, bs)| score > *bs) {
                            best = Some((s, score));
                        }
                    }
                }

                if let Some((decoded, _score)) = best {
                    // Reject strings that look like random noise rather than real text
                    if !is_meaningful_decoded_string(&decoded) {
                        continue;
                    }
                    // Deduplicate
                    if seen_strings.insert(decoded.clone()) {
                        results.push(ExtractedString {
                            value: decoded,
                            data_offset: rodata_file_offset + off_a as u64,
                            section: Some(".rodata".to_string()),
                            method: StringMethod::GarbleRodata,
                            kind: StringKind::Const,
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }

    results
}

/// Decode a blob pair with the given operator, returning the decoded string and
/// score only if every byte is printable and the score meets the threshold.
///
/// Uses a caller-provided buffer to avoid allocation on the hot path.
/// Returns `None` as soon as a non-printable byte is encountered (early exit).
fn try_decode_pair(
    blob_a: &[u8],
    blob_b: &[u8],
    op: GarbleOp,
    min_length: usize,
    min_score: i32,
    buf: &mut Vec<u8>,
) -> Option<(String, i32)> {
    buf.clear();
    let mut score = 0i32;
    // Maximum possible score remaining (3 points per byte for letters)
    let len = blob_a.len();

    for (i, (&a, &b)) in blob_a.iter().zip(blob_b.iter()).enumerate() {
        let byte = op.apply(a, b);

        // Early exit: non-printable byte (allow trailing nulls handled later)
        if byte == 0 {
            // Null byte — treat as end of string (trailing padding)
            // Everything from here on must also be null for this to be valid
            let rest_null = blob_a[i + 1..]
                .iter()
                .zip(blob_b[i + 1..].iter())
                .all(|(&ra, &rb)| op.apply(ra, rb) == 0);
            if !rest_null {
                return None;
            }
            break;
        }

        if !byte.is_ascii_graphic() && byte != b' ' {
            return None;
        }

        // Inline scoring — bail early if score can't possibly reach threshold
        if byte.is_ascii_alphabetic() {
            score += 3;
        } else if byte.is_ascii_digit() {
            score += 1;
        } else if matches!(byte, b'_' | b'-' | b'.' | b'/' | b':' | b' ') {
            score += 2;
        }
        // Punctuation: +0, control chars already filtered above

        // Max remaining score: 3 per remaining byte
        let remaining = (len - i - 1) as i32 * 3;
        if score + remaining < min_score {
            return None;
        }

        buf.push(byte);
    }

    if buf.len() < min_length {
        return None;
    }
    if score < min_score {
        return None;
    }

    // buf is known-ASCII, so from_utf8 is infallible
    Some((String::from_utf8(buf.clone()).ok()?, score))
}

/// Find non-printable byte sequences in data.
/// Returns (offset, slice) for each blob found.
pub fn find_nonprintable_blobs(data: &[u8], min_len: usize, max_len: usize) -> Vec<(usize, &[u8])> {
    let mut blobs = Vec::new();
    let mut i = 0;

    while i < data.len() {
        // Skip printable bytes
        if is_printable_byte(data[i]) {
            i += 1;
            continue;
        }

        // Found a non-printable byte, find the extent of this blob
        let start = i;
        while i < data.len() && !is_printable_byte(data[i]) {
            i += 1;
        }
        let len = i - start;

        // Check length constraints
        if len >= min_len && len <= max_len {
            blobs.push((start, &data[start..i]));
        }
    }

    blobs
}

/// Check if a byte is printable ASCII (or common whitespace).
#[inline]
pub fn is_printable_byte(b: u8) -> bool {
    b.is_ascii_graphic() || b == b' ' || b == b'\t' || b == b'\n' || b == b'\r'
}

/// Score a decoded string for likelihood of being valid text.
///
/// Higher scores indicate more "real" looking strings (letters, common punctuation).
/// Used to pick the best operator when multiple produce printable output.
pub fn score_decoded_string(s: &str) -> i32 {
    let mut score = 0i32;
    for c in s.chars() {
        if c.is_ascii_alphabetic() {
            score += 3; // Letters are strong signal
        } else if c.is_ascii_digit() {
            score += 1; // Digits are OK
        } else if matches!(c, '_' | '-' | '.' | '/' | ':' | ' ') {
            score += 2; // Common string characters
        } else if c.is_ascii_punctuation() {
            // Other punctuation is neutral
        } else {
            score -= 1; // Control chars or unusual chars are bad
        }
    }
    score
}

/// Check if bytes are printable ASCII and meet minimum length.
pub fn check_printable(bytes: &[u8], min_length: usize) -> Option<String> {
    // Filter out nulls if they are at the end (padding)
    let mut trimmed = bytes;
    while let Some((last, rest)) = trimmed.split_last() {
        if *last == 0 {
            trimmed = rest;
        } else {
            break;
        }
    }

    if trimmed.len() < min_length {
        return None;
    }

    // Must be all printable/valid ascii (or utf8)
    if trimmed.iter().all(|&b| b.is_ascii_graphic() || b == b' ') {
        return String::from_utf8(trimmed.to_vec()).ok();
    }

    None
}

/// Check if a decoded string looks like meaningful text rather than random noise.
///
/// Garble rodata pairing can produce false positives when non-printable byte
/// sequences in large rodata sections (e.g., wasm bytecode, lookup tables) happen
/// to XOR/ADD/SUB to printable ASCII. This function rejects common noise patterns:
/// - Strings with no vowels, digits, or common separators (e.g., "HHGQ", "JQJQJ")
/// - Strings dominated by a single repeated character (e.g., "MMMMM")
/// - Strings with alternating repetitive patterns (e.g., "AQAQA", "OQOQO")
fn is_meaningful_decoded_string(s: &str) -> bool {
    let bytes = s.as_bytes();
    let len = bytes.len();

    // Short strings need higher quality evidence
    if len < 6 {
        // For short strings, require at least one lowercase letter or digit.
        // Real garble strings almost always contain lowercase or digits
        // (e.g., "malware.com", "config", "http://").
        let has_lower_or_digit = bytes
            .iter()
            .any(|&b| b.is_ascii_lowercase() || b.is_ascii_digit());
        if !has_lower_or_digit {
            return false;
        }
    }

    // Reject strings dominated by a single character (>60% same byte)
    let mut counts = [0u32; 128];
    for &b in bytes {
        if (b as usize) < 128 {
            counts[b as usize] += 1;
        }
    }
    let max_count = counts.iter().copied().max().unwrap_or(0);
    if max_count as usize * 5 > len * 3 {
        // >60% one character
        return false;
    }

    // Reject alternating repetitive patterns (period <= 3)
    // Detects "AQAQA", "JQJQJ", "OQOQO", etc.
    if len >= 5 {
        for period in 1..=3 {
            if !len.is_multiple_of(period) && !(len - 1).is_multiple_of(period) {
                continue;
            }
            let repeats = bytes.windows(period).skip(1).all(|w| w == &bytes[..period]);
            if repeats {
                return false;
            }
        }
    }

    // Require at least one vowel or digit in strings of 5+ characters.
    // Real text in any language using Latin script will have vowels.
    if len >= 5 {
        let has_vowel_or_digit = bytes.iter().any(|&b| {
            matches!(
                b,
                b'a' | b'e' | b'i' | b'o' | b'u' | b'A' | b'E' | b'I' | b'O' | b'U' | b'0'..=b'9'
            )
        });
        if !has_vowel_or_digit {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_pair_detection() {
        // Simulate garble's simple transformation with non-printable key
        let plaintext = b"malware.com";
        // Use high bytes that are definitely non-printable
        let key: Vec<u8> = (0..plaintext.len())
            .map(|i| (0x80 + i as u8).wrapping_mul(3))
            .collect();

        let encrypted: Vec<u8> = plaintext
            .iter()
            .zip(key.iter())
            .map(|(&p, &k)| p ^ k)
            .collect();

        // Verify both blobs are non-printable
        assert!(encrypted.iter().all(|&b| !is_printable_byte(b)));
        assert!(key.iter().all(|&b| !is_printable_byte(b)));

        // Build rodata with encrypted data followed by key (with printable padding between)
        let mut rodata = Vec::new();
        rodata.extend_from_slice(&encrypted);
        rodata.extend_from_slice(b"PADDING123"); // Printable padding to separate blobs
        rodata.extend_from_slice(&key);

        let results = extract_garble_rodata_strings(&rodata, 4, 4);

        assert!(!results.is_empty(), "expected to find XOR pair");
        assert!(
            results.iter().any(|s| s.value == "malware.com"),
            "expected 'malware.com' in results: {:?}",
            results.iter().map(|s| &s.value).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_is_printable() {
        assert!(is_printable_byte(b'a'));
        assert!(is_printable_byte(b' '));
        assert!(is_printable_byte(b'\t'));
        assert!(!is_printable_byte(0x00));
        assert!(!is_printable_byte(0x80));
    }

    #[test]
    fn test_score_string() {
        // All letters = high score
        assert!(score_decoded_string("malware") > 10);

        // Mixed = moderate score
        assert!(score_decoded_string("file.exe") > 5);

        // Mostly non-printable = low/negative score
        assert!(score_decoded_string("\x01\x02\x03") < 0);
    }
}
