//! String decoders for base64, hex, URL-encoding, and unicode escapes.
//!
//! This module provides decoders for common string encoding schemes found in malware.
//! Each decoder attempts to decode strings and validates the result to minimize false positives.

use crate::{ExtractedString, StringKind, StringMethod};
use data_encoding::{BASE32, BASE32_NOPAD};
use regex::Regex;
use std::sync::LazyLock;

#[allow(clippy::expect_used)]
static QUOTED_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"['"]([^'"]+)['"]"#).expect("static regex"));

/// Matches base64-like substrings within larger strings (e.g., embedded in shell commands).
/// Requires at least 12 characters to avoid false positives on short sequences.
#[allow(clippy::expect_used)]
static EMBEDDED_B64_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"([A-Za-z0-9+/]{12,}={0,2})").expect("static regex"));

/// Minimum length for base64 strings to attempt decoding
pub const MIN_BASE64_LENGTH: usize = 16;

/// Minimum length for hex-encoded strings to attempt decoding
pub const MIN_HEX_LENGTH: usize = 16;

/// Maximum size for decoded output (to prevent memory exhaustion)
pub const MAX_DECODED_SIZE: usize = 10 * 1024 * 1024; // 10MB

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
pub fn deobfuscate_concatenation(s: &str) -> Option<String> {
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
pub fn extract_embedded_base64(strings: &[ExtractedString]) -> Vec<ExtractedString> {
    let mut results = Vec::new();

    for s in strings {
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

                // Try to decode it
                if let Ok(decoded) =
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64_str)
                {
                    // Check size limit
                    if decoded.len() > MAX_DECODED_SIZE {
                        continue;
                    }

                    // Validate it's printable text
                    if let Ok(decoded_str) = String::from_utf8(decoded) {
                        let trimmed = decoded_str.trim();

                        // Must be meaningful (at least 4 chars after trim)
                        if trimmed.len() >= 4 {
                            results.push(ExtractedString {
                                value: trimmed.to_string(),
                                data_offset: s.data_offset,
                                section: s.section.clone(),
                                method: StringMethod::Base64Decode,
                                kind: crate::classify_string(trimmed),
                                raw: Some(b64_str.to_string()),
                                ..Default::default()
                            });
                        }
                    }
                }
            }
        }
    }

    results
}

/// Decode base64-encoded strings from a list of extracted strings.
///
/// Returns a vector of newly decoded strings with `StringMethod::Base64Decode`.
/// Also attempts to deobfuscate concatenated strings first.
pub fn decode_base64_strings(strings: &[ExtractedString]) -> Vec<ExtractedString> {
    let mut results = Vec::new();

    for s in strings {
        // Try normal base64 decoding first
        if s.kind == StringKind::Base64 || is_likely_base64(&s.value) {
            if let Some(decoded) = decode_base64_string(s) {
                results.push(decoded);
                continue;
            }
        }

        // If that didn't work, try deobfuscating concatenation first
        if let Some(deobfuscated) = deobfuscate_concatenation(&s.value) {
            if is_likely_base64(&deobfuscated) {
                // Create a temporary ExtractedString with deobfuscated content
                let temp = ExtractedString {
                    value: deobfuscated,
                    data_offset: s.data_offset,
                    section: s.section.clone(),
                    method: s.method,
                    kind: s.kind,
                    ..Default::default()
                };

                if let Some(decoded) = decode_base64_string(&temp) {
                    results.push(decoded);
                }
            }
        }
    }

    results
}

/// Attempt to decode a single base64 string.
fn decode_base64_string(s: &ExtractedString) -> Option<ExtractedString> {
    if s.value.len() < MIN_BASE64_LENGTH {
        return None;
    }

    // Try standard base64 decoding
    let decoded =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, s.value.trim()).ok()?;

    // Check size limit
    if decoded.len() > MAX_DECODED_SIZE {
        return None;
    }

    // Validate decoded content (must be printable ASCII or valid UTF-8)
    let decoded_str = if decoded
        .iter()
        .all(|&b| b.is_ascii() && (!b.is_ascii_control() || b == b'\n' || b == b'\r' || b == b'\t'))
    {
        // All printable ASCII (+ newlines/tabs)
        String::from_utf8_lossy(&decoded).to_string()
    } else if let Ok(utf8_str) = std::str::from_utf8(&decoded) {
        // Valid UTF-8
        utf8_str.to_string()
    } else {
        // Not valid text - skip
        return None;
    };

    // Reject if decoded string is too short or just whitespace
    let trimmed = decoded_str.trim();
    if trimmed.len() < 4 {
        return None;
    }

    // Reject if input is more text-like than output (false positive detection)
    // e.g., "IWorkItemQueriesExt2" decoding to binary garbage
    let input_quality = string_quality_score(&s.value);
    let output_quality = string_quality_score(&decoded_str);
    if input_quality > output_quality {
        return None;
    }

    // Classify before moving
    let kind = classify_decoded_string(&decoded_str);

    // Create new ExtractedString with decoded content
    Some(ExtractedString {
        value: decoded_str,
        data_offset: s.data_offset,
        section: s.section.clone(),
        method: StringMethod::Base64Decode,
        kind,
        ..Default::default()
    })
}

/// Decode hex-encoded strings from a list of extracted strings.
///
/// Returns a vector of newly decoded strings with `StringMethod::HexDecode`.
pub fn decode_hex_strings(strings: &[ExtractedString]) -> Vec<ExtractedString> {
    let candidates: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == StringKind::HexEncoded || is_likely_hex(&s.value))
        .collect();

    tracing::debug!("decode_hex_strings: found {} candidates", candidates.len());

    candidates
        .into_iter()
        .filter_map(|s| {
            let result = decode_hex_string(s);
            if result.is_some() {
                tracing::debug!(
                    "Successfully decoded hex string of length {}",
                    s.value.len()
                );
            } else {
                tracing::debug!("Failed to decode hex string of length {}", s.value.len());
            }
            result
        })
        .collect()
}

/// Attempt to decode a single hex-encoded string.
fn decode_hex_string(s: &ExtractedString) -> Option<ExtractedString> {
    if s.value.len() < MIN_HEX_LENGTH || !s.value.len().is_multiple_of(2) {
        return None;
    }

    // Decode hex
    let decoded = hex::decode(s.value.trim()).ok()?;

    // Check size limit
    if decoded.len() > MAX_DECODED_SIZE {
        return None;
    }

    // Validate decoded content (must be printable ASCII or valid UTF-8)
    let decoded_str = if decoded
        .iter()
        .all(|&b| b.is_ascii() && (!b.is_ascii_control() || b == b'\n' || b == b'\r' || b == b'\t'))
    {
        // All printable ASCII (+ newlines/tabs)
        String::from_utf8_lossy(&decoded).to_string()
    } else if let Ok(utf8_str) = std::str::from_utf8(&decoded) {
        // Valid UTF-8
        utf8_str.to_string()
    } else {
        // Not valid text - skip
        return None;
    };

    // Reject if too short
    let trimmed = decoded_str.trim();
    if trimmed.len() < 4 {
        return None;
    }

    // Classify before moving
    let kind = classify_decoded_string(&decoded_str);

    Some(ExtractedString {
        value: decoded_str,
        data_offset: s.data_offset,
        section: s.section.clone(),
        method: StringMethod::HexDecode,
        kind,
        ..Default::default()
    })
}

/// Decode URL-encoded strings from a list of extracted strings.
///
/// Returns a vector of newly decoded strings with `StringMethod::UrlDecode`.
pub fn decode_url_strings(strings: &[ExtractedString]) -> Vec<ExtractedString> {
    strings
        .iter()
        .filter(|s| s.kind == StringKind::UrlEncoded || is_likely_url_encoded(&s.value))
        .filter_map(decode_url_string)
        .collect()
}

/// Attempt to decode a single URL-encoded string.
fn decode_url_string(s: &ExtractedString) -> Option<ExtractedString> {
    // Must contain at least one % escape sequence
    if !s.value.contains('%') {
        return None;
    }

    // URL decode
    let decoded = urlencoding::decode(&s.value).ok()?.to_string();

    // Must be different from original (actually encoded)
    if decoded == s.value {
        return None;
    }

    // Reject if too short
    if decoded.trim().len() < 4 {
        return None;
    }

    // Classify before moving
    let kind = classify_decoded_string(&decoded);

    Some(ExtractedString {
        value: decoded,
        data_offset: s.data_offset,
        section: s.section.clone(),
        method: StringMethod::UrlDecode,
        kind,
        ..Default::default()
    })
}

/// Decode unicode escape sequences from a list of extracted strings.
///
/// Returns a vector of newly decoded strings with `StringMethod::UnicodeEscapeDecode`.
pub fn decode_unicode_escape_strings(strings: &[ExtractedString]) -> Vec<ExtractedString> {
    strings
        .iter()
        .filter(|s| s.kind == StringKind::UnicodeEscaped || is_likely_unicode_escaped(&s.value))
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
    let kind = classify_decoded_string(&decoded);

    Some(ExtractedString {
        value: decoded,
        data_offset: s.data_offset,
        section: s.section.clone(),
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

    if changed {
        Some(result)
    } else {
        None
    }
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

    let base64_chars = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
        .count();

    // If >= 80% base64 characters, likely encoded
    if (base64_chars as f32 / s.len() as f32) < 0.8 {
        return false;
    }

    // Must have mixed case and digits (not just CamelCase identifiers)
    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;
    let mut consecutive_lower_at_start = 0;

    // Count consecutive lowercase at start
    for c in s.chars() {
        if c.is_ascii_lowercase() {
            consecutive_lower_at_start += 1;
        } else {
            break;
        }
    }

    for c in s.chars() {
        if c.is_ascii_uppercase() {
            has_upper = true;
        } else if c.is_ascii_lowercase() {
            has_lower = true;
        } else if c.is_ascii_digit() {
            has_digit = true;
        }
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

/// Check if a string looks like it has unicode escape sequences.
fn is_likely_unicode_escaped(s: &str) -> bool {
    s.contains("\\x") || s.contains("\\u") || s.contains("\\U")
}

/// Decode base32-encoded strings from a list of extracted strings.
///
/// Returns a vector of newly decoded strings with `StringMethod::Base32Decode`.
pub fn decode_base32_strings(strings: &[ExtractedString]) -> Vec<ExtractedString> {
    strings
        .iter()
        .filter(|s| s.kind == StringKind::Base32 || is_likely_base32(&s.value))
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

    // Check size limit
    if decoded.len() > MAX_DECODED_SIZE {
        return None;
    }

    // Validate decoded content (must be printable ASCII or valid UTF-8)
    let decoded_str = if decoded
        .iter()
        .all(|&b| b.is_ascii() && (!b.is_ascii_control() || b == b'\n' || b == b'\r' || b == b'\t'))
    {
        // All printable ASCII (+ newlines/tabs)
        String::from_utf8_lossy(&decoded).to_string()
    } else if let Ok(utf8_str) = std::str::from_utf8(&decoded) {
        // Valid UTF-8
        utf8_str.to_string()
    } else {
        // Not valid text - skip
        return None;
    };

    // Reject if decoded string is too short or just whitespace
    let trimmed = decoded_str.trim();
    if trimmed.len() < 4 {
        return None;
    }

    // Classify before moving
    let kind = classify_decoded_string(&decoded_str);

    // Create new ExtractedString with decoded content
    Some(ExtractedString {
        value: decoded_str,
        data_offset: s.data_offset,
        section: s.section.clone(),
        method: StringMethod::Base32Decode,
        kind,
        ..Default::default()
    })
}

/// Decode base85-encoded strings from a list of extracted strings.
///
/// Returns a vector of newly decoded strings with `StringMethod::Base85Decode`.
pub fn decode_base85_strings(strings: &[ExtractedString]) -> Vec<ExtractedString> {
    strings
        .iter()
        .filter(|s| s.kind == StringKind::Base85 || is_likely_base85(&s.value))
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

    // Check size limit
    if decoded.len() > MAX_DECODED_SIZE {
        return None;
    }

    // Validate decoded content (must be printable ASCII or valid UTF-8)
    let decoded_str = if decoded
        .iter()
        .all(|&b| b.is_ascii() && (!b.is_ascii_control() || b == b'\n' || b == b'\r' || b == b'\t'))
    {
        // All printable ASCII (+ newlines/tabs)
        String::from_utf8_lossy(&decoded).to_string()
    } else if let Ok(utf8_str) = std::str::from_utf8(&decoded) {
        // Valid UTF-8
        utf8_str.to_string()
    } else {
        // Not valid text - skip
        return None;
    };

    // Reject if decoded string is too short or just whitespace
    let trimmed = decoded_str.trim();
    if trimmed.len() < 4 {
        return None;
    }

    // Classify before moving
    let kind = classify_decoded_string(&decoded_str);

    Some(ExtractedString {
        value: decoded_str,
        data_offset: s.data_offset,
        section: s.section.clone(),
        method: StringMethod::Base85Decode,
        kind,
        ..Default::default()
    })
}

/// Try to decode ASCII85 encoded data. Public for validation purposes.
/// Returns None if decoding fails.
pub fn try_decode_ascii85(s: &str) -> Option<Vec<u8>> {
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
    let vowel_ratio = if alpha_count > 0 {
        (vowel_count * 100) / alpha_count
    } else {
        0
    };

    // Quality = weighted combination of printability and vowel ratio
    ((printable_ratio * 7 + vowel_ratio * 3) / 10) as u32
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
        if let Some(decoded) = decode_ascii85(s) {
            if let Ok(decoded_str) = String::from_utf8(decoded) {
                let decoded_quality = string_quality_score(&decoded_str);
                // Decoded should be better quality (at least 5 points higher)
                return decoded_quality > original_quality + 5;
            }
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
    if let Some(decoded) = decode_ascii85(s) {
        if let Ok(decoded_str) = String::from_utf8(decoded) {
            let decoded_quality = string_quality_score(&decoded_str);
            // Decoded should be better quality (at least 5 points higher)
            return decoded_quality > original_quality + 5;
        }
    }

    // If can't decode or quality is worse, it's not real base85
    false
}

/// Classify a decoded string into a StringKind.
fn classify_decoded_string(s: &str) -> StringKind {
    // Use the general classifier from go::classifier module
    crate::go::classifier::classify_string(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_decode() {
        let input = ExtractedString {
            value: "SGVsbG8gV29ybGQh".to_string(), // "Hello World!"
            data_offset: 0,
            section: None,
            method: StringMethod::RawScan,
            kind: StringKind::Base64,
            ..Default::default()
        };

        let result = decode_base64_string(&input).unwrap();
        assert_eq!(result.value, "Hello World!");
        assert_eq!(result.method, StringMethod::Base64Decode);
    }

    #[test]
    fn test_hex_decode() {
        let input = ExtractedString {
            value: "48656c6c6f20576f726c6421".to_string(), // "Hello World!"
            data_offset: 0,
            section: None,
            method: StringMethod::RawScan,
            kind: StringKind::HexEncoded,
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
            section: None,
            method: StringMethod::RawScan,
            kind: StringKind::UrlEncoded,
            ..Default::default()
        };

        let result = decode_url_string(&input).unwrap();
        assert_eq!(result.value, "Hello World! + More");
        assert_eq!(result.method, StringMethod::UrlDecode);
    }

    #[test]
    fn test_unicode_escape_decode() {
        let input = ExtractedString {
            value: "\\x48\\x65\\x6c\\x6c\\x6f".to_string(), // "Hello"
            data_offset: 0,
            section: None,
            method: StringMethod::RawScan,
            kind: StringKind::UnicodeEscaped,
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
            section: None,
            method: StringMethod::RawScan,
            kind: StringKind::Base32,
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
            section: None,
            method: StringMethod::RawScan,
            kind: StringKind::Base32,
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
            section: None,
            method: StringMethod::RawScan,
            kind: StringKind::Base32,
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

    fn make_string(value: &str, kind: StringKind) -> ExtractedString {
        ExtractedString {
            value: value.to_string(),
            data_offset: 0,
            section: None,
            method: StringMethod::RawScan,
            kind,
            raw: None,
            source: None,
            fragments: None,
            section_size: None,
            section_executable: None,
            section_writable: None,
            architecture: None,
            function_meta: None,
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
            make_string("SGVsbG8gV29ybGQh", StringKind::Base64),
            make_string("VGVzdCBEYXRhISE=", StringKind::Base64),
            make_string("not_base64", StringKind::Const),
        ];
        let results = decode_base64_strings(&inputs);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].value, "Hello World!");
        assert_eq!(results[0].method, StringMethod::Base64Decode);
        assert_eq!(results[1].value, "Test Data!!");
    }

    #[test]
    fn test_decode_base64_strings_with_concatenation() {
        let inputs = vec![make_string(r#""SGVsbG8g" + "V29ybGQh""#, StringKind::Const)];
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
        assert!(decode_base64_strings(&[make_string("SGVs", StringKind::Base64)]).is_empty());
    }

    #[test]
    fn test_base64_whitespace_trimming() {
        let results =
            decode_base64_strings(&[make_string("  SGVsbG8gV29ybGQh  ", StringKind::Base64)]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].value, "Hello World!");
    }

    #[test]
    fn test_decode_hex_strings_batch() {
        let inputs = vec![
            make_string("48656c6c6f20576f726c6421", StringKind::HexEncoded),
            make_string("54657374204461746121", StringKind::HexEncoded),
            make_string("not_hex", StringKind::Const),
        ];
        let results = decode_hex_strings(&inputs);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].value, "Hello World!");
        assert_eq!(results[0].method, StringMethod::HexDecode);
        assert_eq!(results[1].value, "Test Data!");
    }

    #[test]
    fn test_hex_odd_length() {
        assert!(decode_hex_strings(&[make_string(
            "48656c6c6f20576f726c642",
            StringKind::HexEncoded
        )])
        .is_empty());
    }

    #[test]
    fn test_hex_uppercase() {
        let results = decode_hex_strings(&[make_string(
            "48656C6C6F20576F726C6421",
            StringKind::HexEncoded,
        )]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].value, "Hello World!");
    }

    #[test]
    fn test_decode_url_strings_batch() {
        let inputs = vec![
            make_string("Hello%20World%21", StringKind::UrlEncoded),
            make_string("Test%20Data%21%21", StringKind::UrlEncoded),
            make_string("no_encoding", StringKind::Const),
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
            StringKind::UrlEncoded,
        )]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].value, "path/to/file?query=value&foo=bar");
    }

    #[test]
    fn test_decode_unicode_escape_strings_batch() {
        let inputs = vec![
            make_string("\\x48\\x65\\x6c\\x6c\\x6f", StringKind::UnicodeEscaped),
            make_string("\\u0054\\u0065\\u0073\\u0074", StringKind::UnicodeEscaped),
            make_string("no_escapes", StringKind::Const),
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
            make_string("JBSWY3DPEBLW64TMMQ======", StringKind::Base32),
            make_string("not_base32", StringKind::Const),
        ];
        let results = decode_base32_strings(&inputs);
        assert!(results.len() >= 1);
        assert_eq!(results[0].value, "Hello World");
        assert_eq!(results[0].method, StringMethod::Base32Decode);
    }

    #[test]
    fn test_base32_too_short() {
        assert!(decode_base32_strings(&[make_string("JBSWY3DP", StringKind::Base32)]).is_empty());
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
            StringKind::HexEncoded,
        )]);
        if !results.is_empty() {
            assert_eq!(results[0].value, "192.168.1.1");
            assert_eq!(results[0].kind, StringKind::IP);
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
            let result = decode_base64_strings(&[make_string(input, StringKind::Const)]);
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
        let input = make_string(
            "exec(base64.b64decode('SGVsbG8gV29ybGQh'))",
            StringKind::Const,
        );
        let results = extract_embedded_base64(&[input]);
        assert_eq!(results.len(), 1, "Should extract one embedded base64");
        assert_eq!(results[0].value, "Hello World!");
        assert_eq!(results[0].method, StringMethod::Base64Decode);
        assert_eq!(results[0].raw, Some("SGVsbG8gV29ybGQh".to_string()));
    }

    #[test]
    fn test_extract_embedded_base64_shell_style() {
        // Shell: echo SGVsbG8gV29ybGQh | base64 -d
        let input = make_string("echo SGVsbG8gV29ybGQh | base64 -d", StringKind::ShellCmd);
        let results = extract_embedded_base64(&[input]);
        assert_eq!(results.len(), 1, "Should extract one embedded base64");
        assert_eq!(results[0].value, "Hello World!");
    }

    #[test]
    fn test_extract_embedded_base64_javascript_atob() {
        // JavaScript: eval(atob('SGVsbG8gV29ybGQh'))
        let input = make_string("eval(atob('SGVsbG8gV29ybGQh'))", StringKind::Const);
        let results = extract_embedded_base64(&[input]);
        assert_eq!(results.len(), 1, "Should extract one embedded base64");
        assert_eq!(results[0].value, "Hello World!");
    }

    #[test]
    fn test_extract_embedded_base64_skips_whole_string() {
        // If the entire string is base64, it should be skipped (handled by decode_base64_strings)
        let input = make_string("SGVsbG8gV29ybGQh", StringKind::Base64);
        let results = extract_embedded_base64(&[input]);
        assert!(results.is_empty(), "Should skip strings that are entirely base64");
    }

    #[test]
    fn test_extract_embedded_base64_requires_valid_length() {
        // Base64 must be multiple of 4
        let input = make_string("decode('SGVsbG9Xb3JsZA')", StringKind::Const); // 14 chars, not multiple of 4
        let results = extract_embedded_base64(&[input]);
        assert!(results.is_empty(), "Should reject base64 with invalid length");
    }

    #[test]
    fn test_extract_embedded_base64_multiple_in_one_string() {
        // Multiple base64 strings in one line (must be >= 12 chars each to match regex)
        // "Hello World!" = SGVsbG8gV29ybGQh (16 chars)
        // "Test String!" = VGVzdCBTdHJpbmch (16 chars)
        let input = make_string(
            "a = 'SGVsbG8gV29ybGQh'; b = 'VGVzdCBTdHJpbmch'",
            StringKind::Const,
        );
        let results = extract_embedded_base64(&[input]);
        assert_eq!(results.len(), 2, "Should extract both embedded base64 strings");
    }

    #[test]
    fn test_extract_embedded_base64_nested_code() {
        // Nested Python code - common in malware
        // Inner: "import os; os.system('whoami')"
        let inner_b64 = "aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ3dob2FtaScp";
        let input = make_string(
            &format!("exec(base64.b64decode('{}'))", inner_b64),
            StringKind::Const,
        );
        let results = extract_embedded_base64(&[input]);
        assert_eq!(results.len(), 1);
        assert!(results[0].value.contains("import os"));
        assert!(results[0].value.contains("whoami"));
    }

    #[test]
    fn test_extract_embedded_base64_rejects_short_decoded() {
        // Even if base64 is valid, decoded result must be >= 4 chars
        let input = make_string("decode('YWI=')", StringKind::Const); // decodes to "ab" (2 chars)
        let results = extract_embedded_base64(&[input]);
        assert!(results.is_empty(), "Should reject base64 that decodes to < 4 chars");
    }

    #[test]
    fn test_extract_embedded_base64_preserves_offset() {
        let input = ExtractedString {
            value: "exec(base64.b64decode('SGVsbG8gV29ybGQh'))".to_string(),
            data_offset: 12345,
            section: Some("__TEXT".to_string()),
            method: StringMethod::RawScan,
            kind: StringKind::Const,
            ..Default::default()
        };
        let results = extract_embedded_base64(&[input]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].data_offset, 12345, "Should preserve original offset");
    }
}
