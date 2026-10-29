//! Base64 strings decoded to text: UTF-8 or UTF-16LE, and zlib streams
//! inflated within a shared budget.

use super::embedded::deobfuscate_concatenation;
use super::{MAX_DECODED_SIZE, MIN_BASE64_LENGTH, decoded_to_text, looks_like_utf16le};
use crate::{ExtractedString, StringKind, StringMethod};
use rayon::prelude::*;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Bytes zlib inflation may produce across one decoder pass. Each payload is
/// capped at [`MAX_DECODED_SIZE`], but 14 KB of input inflates to that, so
/// without a shared total a megabyte of such lines held gigabytes.
pub(super) const MAX_INFLATED_PER_PASS: usize = 4 * MAX_DECODED_SIZE;

/// Decode base64-encoded strings from a list of extracted strings.
///
/// Returns a vector of newly decoded strings with `StringMethod::Base64Decode`.
/// Also attempts to deobfuscate concatenated strings first.
pub(crate) fn decode_base64_strings(strings: &[ExtractedString]) -> Vec<ExtractedString> {
    let budget = AtomicUsize::new(MAX_INFLATED_PER_PASS);
    strings
        .par_iter()
        .with_min_len(crate::par::MIN_ITEMS_PER_JOB)
        .filter_map(|s| {
            // Try normal base64 decoding first
            if (s.kind == Some(StringKind::Base64) || is_likely_base64(&s.value))
                && let Some(decoded) = decode_base64_string(s, &budget)
            {
                return Some(decoded);
            }

            // If that didn't work, try deobfuscating concatenation first
            if let Some(deobfuscated) = deobfuscate_concatenation(&s.value)
                && is_likely_base64(&deobfuscated)
            {
                // Create a temporary ExtractedString with deobfuscated content
                let temp = ExtractedString {
                    value: deobfuscated,
                    data_offset: s.data_offset,
                    // The decoded payload occupies the parent's source bytes,
                    // not the (shorter) deobfuscated form.
                    data_len: s.contiguous_source_len(),
                    method: s.method,
                    kind: s.kind,
                    ..Default::default()
                };

                return decode_base64_string(&temp, &budget);
            }

            None
        })
        .collect()
}

/// Decode Base64 whose required terminal padding may be partly or wholly
/// omitted. Reject excess padding, interior padding, and nonzero unused bits.
pub(super) fn decode_base64_bytes(value: &str) -> Option<Vec<u8>> {
    // Bound allocation before handing an attacker-controlled token to Base64.
    if value.len() > MAX_DECODED_SIZE.div_ceil(3) * 4 {
        return None;
    }
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value)
        .or_else(|_| {
            let unpadded = value.trim_end_matches('=');
            let required = (4 - unpadded.len() % 4) % 4;
            if value.len() - unpadded.len() > required {
                return Err(base64::DecodeError::InvalidPadding);
            }
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD_NO_PAD, unpadded)
        })
        .ok()
        .filter(|bytes| bytes.len() <= MAX_DECODED_SIZE)
}

/// Recover text from Base64 output, including the common Base64 → zlib chain.
/// The bool marks a validated compression stream or wide-text signature, which
/// is stronger evidence than the ASCII quality heuristic for plain Base64.
/// Inflated bytes are charged to `budget`; once it is spent, compressed
/// payloads are refused.
pub(super) fn base64_payload_to_text(
    decoded: Vec<u8>,
    budget: &AtomicUsize,
) -> Option<(String, bool)> {
    if decoded.len() > MAX_DECODED_SIZE {
        return None;
    }
    // RFC 1950: DEFLATE, a window no larger than 32 KiB, and valid FCHECK.
    // Do not restrict this to 78 9c: fast/stored/best compression and smaller
    // windows have different headers. Dictionary streams are rejected by the
    // inflater because analysis must not load an external dictionary.
    let has_zlib_header = decoded.get(..2).is_some_and(|header| {
        header[0] & 0x0f == 8
            && header[0] >> 4 <= 7
            && u16::from_be_bytes([header[0], header[1]]).is_multiple_of(31)
    });
    // A header is only a candidate: ordinary text such as "x = answer" starts
    // with the valid 78 20 dictionary header. If inflation fails, preserve the
    // existing plain-text path, but never coerce compressed binary into text.
    let inflated = has_zlib_header.then(|| inflate_zlib(&decoded)).flatten();
    if let Some(inflated) = &inflated
        && budget
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |left| {
                left.checked_sub(inflated.len())
            })
            .is_err()
    {
        tracing::warn!(
            "zlib inflation budget of {MAX_INFLATED_PER_PASS} bytes spent; payload skipped"
        );
        return None;
    }
    let is_zlib = inflated.is_some();
    let bytes = inflated.unwrap_or(decoded);
    let is_wide = looks_like_utf16le(&bytes);
    let text = decoded_to_text(bytes)?;
    // A valid compressed binary is not a string payload, even when its bytes
    // happen to be legal UTF-8 (e.g. a NUL-filled image header).
    if has_zlib_header
        && text
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return None;
    }
    Some((text, is_zlib || is_wide))
}

/// Inflate the first complete zlib stream, verifying its checksum and trailer.
/// Like Python's zlib.decompress, ignore bytes after that stream: appending junk
/// must not hide code that the runtime would execute. Cap output while inflating;
/// never accept text emitted before a bad checksum or a truncated trailer.
pub(super) fn inflate_zlib(input: &[u8]) -> Option<Vec<u8>> {
    use flate2::{Decompress, FlushDecompress, Status};

    let mut decoder = Decompress::new(true);
    let mut output = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let before_in = decoder.total_in();
        let before_out = decoder.total_out();
        let offset = usize::try_from(before_in).ok()?;
        // One extra byte distinguishes an exact-limit payload from a bomb.
        let room = chunk.len().min(MAX_DECODED_SIZE + 1 - output.len());
        let status = decoder
            .decompress(&input[offset..], &mut chunk[..room], FlushDecompress::None)
            .ok()?;
        let produced = usize::try_from(decoder.total_out() - before_out).ok()?;
        output.extend_from_slice(&chunk[..produced]);
        if output.len() > MAX_DECODED_SIZE {
            return None;
        }
        if status == Status::StreamEnd {
            return (!output.is_empty()).then_some(output);
        }
        // This also rejects a truncated stream that already emitted readable
        // text: exhausted input is not proof of a complete compressed stream.
        if decoder.total_in() == before_in && decoder.total_out() == before_out {
            return None;
        }
    }
}

/// Attempt to decode a single base64 string.
pub(super) fn decode_base64_string(
    s: &ExtractedString,
    budget: &AtomicUsize,
) -> Option<ExtractedString> {
    if s.value.len() < MIN_BASE64_LENGTH {
        return None;
    }

    let decoded = decode_base64_bytes(s.value.trim())?;

    let (decoded_str, validated_payload) = base64_payload_to_text(decoded, budget)?;

    // Reject if decoded string is too short or just whitespace
    let trimmed = decoded_str.trim();
    if trimmed.len() < 4 {
        return None;
    }

    // Reject if input is more text-like than output (false positive detection)
    // e.g., "IWorkItemQueriesExt2" decoding to binary garbage. Skipped for wide
    // text and checksum-verified zlib streams: their signatures already validate
    // the encoding, and Unicode source would lose this ASCII comparison. Score the
    // trimmed decode: a trailing newline (routine in `base64 -d <<< …` and
    // `echo … | base64` payloads) is not a quality defect, and penalizing it
    // would sink genuine short commands like `/bin/rm\n` below their base64.
    if !validated_payload {
        let input_quality = crate::text::quality(s.value.as_bytes()).0;
        let output_quality = crate::text::quality(trimmed.as_bytes()).0;
        if input_quality > output_quality {
            return None;
        }
    }

    // Classify before moving
    let kind = crate::classify_string(&decoded_str);

    // Create new ExtractedString with decoded content. The decoded text lives
    // in the encoded source's bytes — inherit the parent base64 string's extent,
    // not the decoded length.
    Some(ExtractedString {
        value: decoded_str,
        data_offset: s.data_offset,
        data_len: s.contiguous_source_len(),
        method: StringMethod::Base64Decode,
        kind,
        ..Default::default()
    })
}

/// Check if a string looks like base64-encoded data.
pub(super) fn is_likely_base64(s: &str) -> bool {
    if s.len() < MIN_BASE64_LENGTH {
        return false;
    }

    // Padding may be omitted, but a remainder of one is never valid.
    if s.len() % 4 == 1 {
        return false;
    }

    // Single pass: count base64-alphabet chars, the leading run of lowercase
    // (to reject lowerCamelCase identifiers), and which case/digit classes
    // appear. (Previously three separate passes over the string.)
    let mut base64_chars = 0usize;
    let mut consecutive_lower_at_start = 0;
    let mut leading_run_done = false;
    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' {
            base64_chars += 1;
        }
        if c.is_ascii_lowercase() {
            has_lower = true;
            if !leading_run_done {
                consecutive_lower_at_start += 1;
            }
        } else {
            leading_run_done = true;
            if c.is_ascii_uppercase() {
                has_upper = true;
            } else if c.is_ascii_digit() {
                has_digit = true;
            }
        }
    }

    // If >= 80% base64 characters, likely encoded
    if (base64_chars as f32 / s.len() as f32) < 0.8 {
        return false;
    }

    // Reject lowerCamelCase identifiers (4+ consecutive lowercase at start)
    // Like "wants10KeepAlive", "maxReceiveBuffer"
    if consecutive_lower_at_start >= 4 {
        return false;
    }

    // Real base64 has mixed case and digits, not just CamelCase
    has_upper && has_lower && has_digit
}
