//! String decoders for base64, hex, URL-encoding, and unicode escapes.
//!
//! This module provides decoders for common string encoding schemes found in malware.
//! Each decoder attempts to decode strings and validates the result to minimize false positives.

mod base64_text;
mod embedded;

use crate::{ExtractedString, StringKind, StringMethod};
pub(crate) use base64_text::decode_base64_strings;
use base64_text::is_likely_base64;
use data_encoding::{BASE32, BASE32_NOPAD};
pub(crate) use embedded::{extract_embedded_base64, extract_embedded_hex};
use rayon::prelude::*;

/// Minimum length for base64 strings to attempt decoding.
///
/// 12 is the shortest base64 that carries a meaningful short command: a
/// 7–9 byte payload (`/bin/rm`, `uname -a`) encodes to exactly 12 chars, and
/// obfuscated droppers hide exactly those primitives in `base64 -d <<< …`
/// one-liners. The embedded-base64 regex starts candidates at 8 characters;
/// this floor decides which of them are decoded. The input-vs-output quality
/// gate below — not this floor — is what rejects short
/// identifiers that merely look like base64.
pub(crate) const MIN_BASE64_LENGTH: usize = 12;

/// Minimum length for hex-encoded strings to attempt decoding
pub(crate) const MIN_HEX_LENGTH: usize = 16;

/// Maximum size for decoded output (to prevent memory exhaustion)
pub(crate) const MAX_DECODED_SIZE: usize = 10 * 1024 * 1024; // 10MB

/// Validate freshly decoded bytes as printable text, enforcing the size cap.
///
/// Pure-ASCII payloads (tabs/newlines allowed) skip UTF-8 re-validation since ASCII
/// is always valid UTF-8; anything else must parse as UTF-8. Oversized or non-text
/// payloads yield `None` so callers can `?` straight out.
fn decoded_to_text(decoded: Vec<u8>) -> Option<String> {
    if decoded.len() > MAX_DECODED_SIZE {
        return None;
    }
    // Clean ASCII text (tabs/newlines allowed) is valid UTF-8 as-is.
    if decoded
        .iter()
        .all(|&b| b.is_ascii() && (!b.is_ascii_control() || b == b'\n' || b == b'\r' || b == b'\t'))
    {
        return String::from_utf8(decoded).ok();
    }
    // Windows payloads are frequently encoded as little-endian UTF-16 — most
    // notably `powershell -EncodedCommand`, but the same wide-char form shows up
    // in registry blobs, .lnk files, and obfuscated scripts of every filetype.
    // Such bytes are *technically* valid UTF-8 (interleaved NULs are valid
    // single-byte UTF-8), so we must test for the wide-char form before falling
    // back to a plain UTF-8 decode that would yield a NUL-filled string.
    if let Some(s) = decode_utf16le(&decoded) {
        return Some(s);
    }
    std::str::from_utf8(&decoded).ok().map(str::to_string)
}

/// Cheap test for the little-endian UTF-16 wide-text signature: an even length
/// and a clear majority of zero high bytes — the shape of wide-encoded Latin
/// text such as Windows commands, paths, and URLs. Random binary has a ~0.4%
/// chance per code unit of a zero high byte, so this reliably rejects it.
fn looks_like_utf16le(bytes: &[u8]) -> bool {
    bytes.len() >= 4
        && bytes.len().is_multiple_of(2)
        && bytes
            .as_chunks::<2>()
            .0
            .iter()
            .filter(|c| c[1] == 0)
            .count()
            * 2
            >= bytes.len() / 2
}

/// Decode bytes as little-endian UTF-16, but only when they actually look like
/// wide text (see [`looks_like_utf16le`]); arbitrary binary must not be coerced
/// into Unicode.
fn decode_utf16le(bytes: &[u8]) -> Option<String> {
    if !looks_like_utf16le(bytes) {
        return None;
    }
    let code_units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let decoded = String::from_utf16(&code_units).ok()?;
    // Drop a leading byte-order mark and reject control-heavy results that
    // slipped past the heuristic.
    let s = decoded.trim_start_matches('\u{feff}');
    if s.chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return None;
    }
    Some(s.to_string())
}

/// Decode hex-encoded strings from a list of extracted strings.
///
/// Returns a vector of newly decoded strings with `StringMethod::HexDecode`.
pub(crate) fn decode_hex_strings(strings: &[ExtractedString]) -> Vec<ExtractedString> {
    strings
        .par_iter()
        .with_min_len(crate::par::MIN_ITEMS_PER_JOB)
        .filter(|s| s.kind == Some(StringKind::HexEncoded) || is_likely_hex(&s.value))
        .flat_map_iter(decode_hex_variants)
        .collect()
}

/// Decode whole-string hex values, and scan the decoded bytes for embedded
/// single-byte-XOR strings. Some carriers apply XOR after hex encoding, so the
/// ordinary text-only hex decoder rejects the intermediate binary and hides
/// the plaintext from the XOR scanner. Keep this second pass bounded: encoded
/// inputs over 1 MiB would exceed the existing 512 KiB XOR key-detection
/// budget once decoded and are unlikely to be useful as string carriers.
fn decode_hex_variants(s: &ExtractedString) -> Vec<ExtractedString> {
    const MAX_DECODED_XOR_BYTES: usize = crate::xor::MAX_AUTO_DETECT_SIZE;

    if s.value.len() < MIN_HEX_LENGTH || !s.value.len().is_multiple_of(2) {
        return Vec::new();
    }
    let Some(decoded) = crate::bytes::from_hex(s.value.trim().as_bytes()) else {
        return Vec::new();
    };

    let mut xor_results = Vec::new();
    if decoded.len() <= MAX_DECODED_XOR_BYTES {
        let xor_hits = crate::xor::extract_xor_strings(&decoded, 10, false);
        let mut key_counts = [0usize; 256];
        for hit in &xor_hits {
            if let Ok(offset) = usize::try_from(hit.data_offset)
                && let (Some(encoded), Some(decoded_byte)) =
                    (decoded.get(offset), hit.value.as_bytes().first())
            {
                key_counts[usize::from(encoded ^ decoded_byte)] += 1;
            }
        }
        xor_results = xor_hits;

        // Pattern hits identify the likely key cheaply. Expand only keys with
        // an independent trigger so strings such as CallWindowProcA,
        // which may lack their own trigger (for example mixed-case `.Dll`),
        // are recovered without trying all 255 keys.
        for (key, count) in (0..=u8::MAX).zip(key_counts) {
            if count == 0 || crate::xor::SKIP_XOR_KEYS.contains(&key) {
                continue;
            }
            xor_results.extend(crate::xor::extract_custom_xor_strings_with_hints(
                &decoded,
                &[key],
                10,
                &[],
                true,
                false,
            ));
        }
    }

    let mut results = Vec::new();
    if let Some(decoded_text) = decoded_to_text(decoded)
        && decoded_text.trim().len() >= 4
    {
        results.push(ExtractedString {
            data_offset: s.data_offset,
            data_len: u32::try_from(s.value.len()).unwrap_or(u32::MAX),
            kind: crate::classify_string(&decoded_text),
            value: decoded_text,
            method: StringMethod::HexDecode,
            ..Default::default()
        });
    }

    for found in &mut xor_results {
        // XOR offsets refer to the hex-decoded byte stream. Each such byte
        // occupies two source characters in the original file.
        found.data_offset = s
            .data_offset
            .saturating_add(found.data_offset.saturating_mul(2));
        found.data_len = found.data_len.saturating_mul(2);
    }
    results.extend(xor_results);

    results
}

/// Decode URL-encoded strings from a list of extracted strings.
///
/// Returns a vector of newly decoded strings with `StringMethod::UrlDecode`.
pub(crate) fn decode_url_strings(strings: &[ExtractedString]) -> Vec<ExtractedString> {
    strings
        .par_iter()
        .with_min_len(crate::par::MIN_ITEMS_PER_JOB)
        .filter(|s| s.kind == Some(StringKind::UrlEncoded) || is_likely_url_encoded(&s.value))
        .filter_map(decode_url_string)
        .collect()
}

/// True if any `%XX` escape decodes to an unreserved character (ASCII
/// alphanumeric). Legitimate URL encoding only escapes reserved/unsafe
/// characters; percent-encoding an alphanumeric (`%75` = `u`) is the signature
/// of deliberate obfuscation, not normal URL syntax.
fn encodes_unreserved_char(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 2 < bytes.len() {
        if bytes[i] == b'%'
            && let (Some(hi), Some(lo)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            )
        {
            #[allow(clippy::cast_possible_truncation)]
            let decoded = (hi * 16 + lo) as u8;
            if decoded.is_ascii_alphanumeric() {
                return true;
            }
            i += 3;
            continue;
        }
        i += 1;
    }
    false
}

/// Attempt to decode a single URL-encoded string.
fn decode_url_string(s: &ExtractedString) -> Option<ExtractedString> {
    // Must contain at least one % escape sequence
    if !s.value.contains('%') {
        return None;
    }

    // A URL's percent-encoding is legitimate syntax, not an encoded payload:
    // `…?title=Special%3ASearch` or `#:~:text=Function%3A%20foo` decode to the
    // same readable URL, hiding nothing. Skip when the string carries a URL
    // scheme and only escapes reserved characters; decode it only when an
    // *unreserved* char is percent-encoded (`%75` = `u`), the signature of
    // deliberate obfuscation that legitimate URL encoders never produce.
    if s.value.contains("://") && !encodes_unreserved_char(&s.value) {
        return None;
    }

    // Percent-decode. A `%` not followed by two hex digits stays as it is, and
    // `+` stays a plus.
    let mut bytes = Vec::with_capacity(s.value.len());
    let mut rest = s.value.as_bytes();
    while let Some((&b, tail)) = rest.split_first() {
        if b == b'%'
            && let [h, l, ..] = tail
            && let (Some(h), Some(l)) = (crate::bytes::hex_digit(*h), crate::bytes::hex_digit(*l))
        {
            bytes.push(h << 4 | l);
            rest = &tail[2..];
        } else {
            bytes.push(b);
            rest = tail;
        }
    }
    let decoded = String::from_utf8(bytes).ok()?;

    // Must be different from original (actually encoded)
    if decoded == s.value {
        return None;
    }

    // Reject if too short
    if decoded.trim().len() < 4 {
        return None;
    }

    // Classify before moving
    let kind = crate::classify_string(&decoded);

    Some(ExtractedString {
        value: decoded,
        data_offset: s.data_offset,
        method: StringMethod::UrlDecode,
        kind,
        ..Default::default()
    })
}

/// Decode unicode escape sequences from a list of extracted strings.
///
/// Returns a vector of newly decoded strings with `StringMethod::UnicodeEscapeDecode`.
pub(crate) fn decode_unicode_escape_strings(strings: &[ExtractedString]) -> Vec<ExtractedString> {
    strings
        .par_iter()
        .with_min_len(crate::par::MIN_ITEMS_PER_JOB)
        .filter(|s| {
            s.kind == Some(StringKind::UnicodeEscaped)
                || s.value.contains("\\x")
                || s.value.contains("\\u")
                || s.value.contains("\\U")
        })
        .filter_map(decode_unicode_escape_string)
        .collect()
}

/// Attempt to decode a single unicode-escaped string.
fn decode_unicode_escape_string(s: &ExtractedString) -> Option<ExtractedString> {
    // Must contain escape sequences
    if !s.value.contains("\\x") && !s.value.contains("\\u") && !s.value.contains("\\U") {
        return None;
    }

    let decoded = decode_unicode_escapes(&s.value)?;

    // Must be different from original
    if decoded == s.value {
        return None;
    }

    // Reject if too short
    if decoded.trim().len() < 4 {
        return None;
    }

    // Classify before moving
    let kind = crate::classify_string(&decoded);

    Some(ExtractedString {
        value: decoded,
        data_offset: s.data_offset,
        method: StringMethod::UnicodeEscapeDecode,
        kind,
        ..Default::default()
    })
}

/// Decode unicode escape sequences in a string.
///
/// Handles `\xHH`, `\uHHHH`, and `\UHHHHHHHH`, and — importantly for triage —
/// a redundant escaping backslash in front of them: `\\xHH`, `\\uHHHH`, and
/// `\\UHHHHHHHH`. That doubled form is a string escape written inside another
/// escaped string (a Python or JS literal embedded in a JSON/gyp string, say),
/// a common obfuscation layer. Decoding through it recovers the greppable
/// payload (`catch_warnings`, `__import__`, `node payload.js`) instead of the
/// half-decoded `\c\a\t\c\h...` a single-layer pass leaves behind. The strict
/// hex-digit-count requirement keeps benign text like `C:\\Users` untouched,
/// since `Users` is not eight hex digits.
fn decode_unicode_escapes(s: &str) -> Option<String> {
    let chars: Vec<char> = s.chars().collect();
    let mut result = String::with_capacity(s.len());
    let mut i = 0;
    let mut changed = false;

    while i < chars.len() {
        if chars[i] == '\\' {
            // The escape letter is at i+1, or i+2 when a redundant backslash
            // precedes it.
            let esc = if chars.get(i + 1) == Some(&'\\') {
                i + 2
            } else {
                i + 1
            };
            let width = match chars.get(esc) {
                Some('x') => 2,
                Some('u') => 4,
                Some('U') => 8,
                _ => 0,
            };
            // Too few digits, non-hex digits, and invalid code points (lone
            // surrogates, beyond U+10FFFF) are not escapes.
            if width > 0
                && let Some(digits) = chars.get(esc + 1..esc + 1 + width)
                && let Some(code) = crate::bytes::hex_number(&digits.iter().collect::<String>())
                && let Some(decoded) = char::from_u32(code)
            {
                result.push(decoded);
                changed = true;
                i = esc + 1 + width;
                continue;
            }
            // Not a decodable escape: emit the backslash and move on. The
            // character after it is reprocessed on the next iteration, so no
            // trailing hex digits are dropped.
            result.push('\\');
            i += 1;
        } else {
            result.push(chars[i]);
            i += 1;
        }
    }

    if changed { Some(result) } else { None }
}

/// Check if a string looks like hex-encoded data.
fn is_likely_hex(s: &str) -> bool {
    if s.len() < MIN_HEX_LENGTH || !s.len().is_multiple_of(2) {
        return false;
    }

    s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Check if a string looks like URL-encoded data.
fn is_likely_url_encoded(s: &str) -> bool {
    if !s.contains('%') {
        return false;
    }

    // Count valid %XX sequences
    let mut percent_count = 0;
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            percent_count += 1;
            i += 3;
            continue;
        }
        i += 1;
    }

    // At least 3 valid %XX sequences
    percent_count >= 3
}

/// Decode base32-encoded strings from a list of extracted strings.
///
/// Returns a vector of newly decoded strings with `StringMethod::Base32Decode`.
pub(crate) fn decode_base32_strings(strings: &[ExtractedString]) -> Vec<ExtractedString> {
    strings
        .par_iter()
        .with_min_len(crate::par::MIN_ITEMS_PER_JOB)
        .filter(|s| s.kind == Some(StringKind::Base32) || is_likely_base32(&s.value))
        .filter_map(decode_base32_string)
        .collect()
}

/// Attempt to decode a single base32 string.
fn decode_base32_string(s: &ExtractedString) -> Option<ExtractedString> {
    if s.value.len() < 16 {
        return None;
    }

    // Try decoding with padding
    let decoded = BASE32
        .decode(s.value.trim().as_bytes())
        .or_else(|_| BASE32_NOPAD.decode(s.value.trim().as_bytes()))
        .ok()?;

    let decoded_str = decoded_to_text(decoded)?;

    // Reject if decoded string is too short or just whitespace
    let trimmed = decoded_str.trim();
    if trimmed.len() < 4 {
        return None;
    }

    // Classify before moving
    let kind = crate::classify_string(&decoded_str);

    // Create new ExtractedString with decoded content
    Some(ExtractedString {
        value: decoded_str,
        data_offset: s.data_offset,
        method: StringMethod::Base32Decode,
        kind,
        ..Default::default()
    })
}

/// Decode strings that are base64 only after a rot13 rotation.
///
/// rot13 is not a decoder that can be offered blindly: every alphabetic string
/// is valid rot13 input, so rotating everything would double the string table
/// with noise. The gate is therefore on the *result* -- rotate, and keep it only
/// when the rotation turns something that was not base64 into something that is,
/// then decode that base64 and emit the payload. Ordinary prose and identifiers
/// do not become valid base64 by being rotated, so the false-positive rate is
/// governed by `is_likely_base64`, which already demands mixed case, digits and
/// a length that is a multiple of four.
///
/// The shape this exists for hides a payload in plain sight: the chunks sit in
/// the source as long alphanumeric literals, and only the ones that were also
/// rotated fail to decode for a reader who tries base64 first. A W4SP-family
/// PyPI stealer splits its payload across four such literals, rot13-ing two of
/// them, and reassembles the pieces with `codecs.decode(chunk, 'rot13')` --
/// where even the string `rot13` is written as hex escapes so it cannot be
/// grepped.
pub(crate) fn decode_rot13_base64_strings(strings: &[ExtractedString]) -> Vec<ExtractedString> {
    strings
        .par_iter()
        .with_min_len(crate::par::MIN_ITEMS_PER_JOB)
        .filter_map(decode_rot13_base64_string)
        .collect()
}

/// Rotate a single string by 13 and decode the result as base64.
fn decode_rot13_base64_string(s: &ExtractedString) -> Option<ExtractedString> {
    let value = s.value.trim();
    if value.len() < MIN_BASE64_LENGTH {
        return None;
    }
    // rot13 maps the base64 alphabet onto itself -- letters rotate, digits and
    // `+/=` are untouched -- so a rotated payload still *looks* like base64 and
    // "is it base64 already?" cannot separate the two readings. What separates
    // them is which one decodes to plausible text: at most one will, since the
    // other is the same bytes read 13 letters out of phase. If the string
    // decodes as-is, it is ordinary base64 and belongs to the plain decoder.
    let unrotated_decodes = |v: &str| -> bool {
        let whole = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, v)
            .ok()
            .and_then(decoded_to_text);
        if whole.is_some() {
            return true;
        }
        // Truncate to a whole base64 quartet, but only on a char boundary. The
        // input is an arbitrary extracted string, so it can hold multi-byte
        // UTF-8, and a byte index landing mid-scalar panics the slice.
        let keep = v.len() - v.len() % 4;
        let keep = if v.is_char_boundary(keep) {
            keep
        } else {
            return false;
        };
        keep >= MIN_BASE64_LENGTH
            && base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &v[..keep])
                .ok()
                .and_then(decoded_to_text)
                .is_some()
    };
    if unrotated_decodes(value) {
        return None;
    }

    let rotated: String = value.chars().map(|c| crate::text::rot(c, 13)).collect();
    if !is_likely_base64(&rotated) {
        return None;
    }

    // Same fragment problem the fuzzy path handles: a payload split across
    // several literals leaves each piece with an arbitrary length mod 4, so the
    // whole string may not decode while its longest valid prefix does. Try the
    // string as it stands, then the prefix.
    let decoded_str =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, rotated.as_str())
            .ok()
            .and_then(decoded_to_text)
            .or_else(|| {
                let keep = rotated.len() - rotated.len() % 4;
                if keep < MIN_BASE64_LENGTH || !rotated.is_char_boundary(keep) {
                    return None;
                }
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &rotated[..keep])
                    .ok()
                    .and_then(decoded_to_text)
            })?;
    if decoded_str.trim().len() < 4 {
        return None;
    }

    let kind = crate::classify_string(&decoded_str);
    Some(ExtractedString {
        value: decoded_str,
        data_offset: s.data_offset,
        method: StringMethod::Rot13Base64Decode,
        kind,
        ..Default::default()
    })
}

/// Decode base85-encoded strings from a list of extracted strings.
///
/// Returns a vector of newly decoded strings with `StringMethod::Base85Decode`.
pub(crate) fn decode_base85_strings(strings: &[ExtractedString]) -> Vec<ExtractedString> {
    strings
        .par_iter()
        .with_min_len(crate::par::MIN_ITEMS_PER_JOB)
        .filter(|s| s.kind == Some(StringKind::Base85) || is_likely_base85(&s.value))
        .filter_map(decode_base85_string)
        .collect()
}

/// Attempt to decode a single base85 string (ASCII85 format).
fn decode_base85_string(s: &ExtractedString) -> Option<ExtractedString> {
    if s.value.len() < 20 {
        return None;
    }

    // Try ASCII85 decoding
    let input = s.value.trim();
    let decoded = decode_ascii85(input)?;

    let decoded_str = decoded_to_text(decoded)?;

    // Reject if decoded string is too short or just whitespace
    let trimmed = decoded_str.trim();
    if trimmed.len() < 4 {
        return None;
    }

    // Classify before moving
    let kind = crate::classify_string(&decoded_str);

    Some(ExtractedString {
        value: decoded_str,
        data_offset: s.data_offset,
        method: StringMethod::Base85Decode,
        kind,
        ..Default::default()
    })
}

/// Decode ASCII85 encoded data; `None` if it is not valid ASCII85.
/// ASCII85 uses characters from '!' (33) to 'u' (117), plus 'z' for four zero bytes.
pub(crate) fn decode_ascii85(s: &str) -> Option<Vec<u8>> {
    let mut result = Vec::new();
    let mut group = Vec::new();

    // Only the Adobe `<~ … ~>` frame is syntax; `<` and `>` inside it are
    // digits (27 and 29), and a stray `~` is invalid.
    let s = s.trim();
    let s = s.strip_prefix("<~").unwrap_or(s);
    let s = s.strip_suffix("~>").unwrap_or(s);
    for ch in s.chars() {
        match ch {
            ' ' | '\t' | '\n' | '\r' => {
                // Skip whitespace
                continue;
            }
            'z' => {
                // 'z' represents four zero bytes (shorthand)
                if !group.is_empty() {
                    return None; // 'z' must not appear in the middle of a group
                }
                result.extend_from_slice(&[0u8; 4]);
            }
            '!'..='u' => {
                group.push((ch as u8) - b'!');
                if group.len() == 5 {
                    // Decode 5 base85 digits to 4 bytes
                    let mut value: u32 = 0;
                    for &digit in &group {
                        value = value
                            .checked_mul(85)
                            .and_then(|v| v.checked_add(u32::from(digit)))?;
                    }
                    result.extend_from_slice(&value.to_be_bytes());
                    group.clear();
                }
            }
            _ => {
                // Invalid character
                return None;
            }
        }
    }

    // Handle remaining partial group
    if !group.is_empty() {
        let original_len = group.len();
        // Pad with 'u' (84) to make 5 digits
        while group.len() < 5 {
            group.push(84);
        }

        let mut value: u32 = 0;
        for &digit in &group {
            value = value
                .checked_mul(85)
                .and_then(|v| v.checked_add(u32::from(digit)))?;
        }

        let bytes = value.to_be_bytes();
        let output_len = original_len - 1; // Output n-1 bytes for n input characters
        result.extend_from_slice(&bytes[..output_len]);
    }

    Some(result)
}

/// Check if a string looks like base32-encoded data.
fn is_likely_base32(s: &str) -> bool {
    if s.len() < 16 {
        return false;
    }

    // Single pass validation using bytes
    let bytes = s.as_bytes();
    let mut valid_count = 0;
    let mut has_letters = false;
    let mut has_digits = false;

    for &b in bytes {
        match b {
            b'A'..=b'Z' => {
                has_letters = true;
                valid_count += 1;
            }
            b'2'..=b'7' => {
                has_digits = true;
                valid_count += 1;
            }
            b'=' => valid_count += 1,
            _ => {}
        }
    }

    // Must have both letters and digits
    has_letters && has_digits && (valid_count * 10 >= s.len() * 9)
}

fn is_likely_base85(s: &str) -> bool {
    // Require minimum length
    if s.len() < 20 {
        return false;
    }

    // Check for ASCII85 delimiters (<~ and ~>)
    let has_delimiters = s.starts_with("<~") && s.ends_with("~>");

    // If it has delimiters, validate by attempting to decode
    if has_delimiters {
        let original_quality = crate::text::quality(s.as_bytes()).0;
        if let Some(decoded) = decode_ascii85(s)
            && let Ok(decoded_str) = String::from_utf8(decoded)
        {
            let decoded_quality = crate::text::quality(decoded_str.as_bytes()).0;
            // Decoded should be better quality (at least 5 points higher)
            return decoded_quality > original_quality + 5;
        }
        // If decode fails or quality is worse, reject
        return false;
    }

    // Count valid ASCII85 characters
    let bytes = s.as_bytes();
    let mut valid_count = 0;
    let mut has_special_chars = false;

    for &b in bytes {
        if matches!(b, b'!'..=b'u' | b'z') {
            valid_count += 1;
            // Look for special chars that are unlikely in normal text
            if matches!(
                b,
                b'!' | b'"' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b','
            ) {
                has_special_chars = true;
            }
        }
    }

    // For shorter strings (< 50), use moderate threshold + special char check
    if s.len() < 50 {
        if !has_special_chars || valid_count * 10 < s.len() * 9 {
            return false;
        }
    } else {
        // For longer strings, be stricter
        if valid_count * 100 < s.len() * 95 {
            return false;
        }
    }

    // Final validation: try decoding and check quality
    let original_quality = crate::text::quality(s.as_bytes()).0;
    if let Some(decoded) = decode_ascii85(s)
        && let Ok(decoded_str) = String::from_utf8(decoded)
    {
        let decoded_quality = crate::text::quality(decoded_str.as_bytes()).0;
        // Decoded should be better quality (at least 5 points higher)
        return decoded_quality > original_quality + 5;
    }

    // If can't decode or quality is worse, it's not real base85
    false
}

/// Decode "spaced" ASCII — text whose characters are each followed by a NUL
/// or a space (`H e l l o`), as UTF-16LE text looks when read as bytes.
/// `None` unless at least 70% of the byte pairs have that shape.
#[must_use]
pub fn decode_spaced_ascii(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    if bytes.len() < 6 {
        return None;
    }
    let mut wide_pairs = 0;
    let mut total_pairs = 0;
    for i in (0..bytes.len() - 1).step_by(2) {
        total_pairs += 1;
        if (bytes[i].is_ascii_graphic() || bytes[i] == b' ')
            && (bytes[i + 1] == 0 || bytes[i + 1] == b' ')
        {
            wide_pairs += 1;
        }
    }
    if total_pairs < 4 || wide_pairs * 100 / total_pairs < 70 {
        return None;
    }
    let mut decoded = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_graphic() || bytes[i] == b' ' {
            decoded.push(bytes[i]);
            if i + 1 < bytes.len() && (bytes[i + 1] == 0 || bytes[i + 1] == b' ') {
                i += 2;
                continue;
            }
            i += 1;
        } else {
            i += 1;
        }
    }
    let result = String::from_utf8(decoded).ok()?;
    if result.trim().len() >= 4 {
        Some(result.trim().to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod rot13_base64_tests;

#[cfg(test)]
mod zlib_tests;
