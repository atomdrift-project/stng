//! Fuzzy base64 extraction for obfuscated malware samples.
//!
//! This module handles base64 strings that have been obfuscated through:
//! - base64url characters concatenated in (`'_'` for `/`, `'-'` for `+`)
//! - String concatenation artifacts (e.g., ' + ', '" + "')
//! - Interspersed garbage characters
//! - Partial corruption

use crate::types::{ExtractedString, StringMethod};
use rayon::prelude::*;
use regex::Regex;
use std::collections::HashMap;
use std::ops::Range;
use std::sync::LazyLock;

static CONCAT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"['"]\s*\+\s*['"]([A-Za-z0-9])['"]\s*\+\s*['"]"#)
        .unwrap_or_else(crate::invalid_pattern)
});
static ASSIGNMENT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"=\s*["']([^"']+)["']"#).unwrap_or_else(crate::invalid_pattern));

/// Minimum length for a base64 segment to be considered valid
const MIN_BASE64_SEGMENT: usize = 32;

/// Minimum percentage of valid base64 characters for fuzzy extraction
const MIN_BASE64_PURITY: f32 = 0.65;

/// Common obfuscation patterns found in JavaScript/VBScript malware
const JS_CONCAT_PATTERNS: &[&str] = &["' + '", "\" + \"", "' +  '", "\" +  \"", " + ", "'+", "\"+"];

/// base64url characters and their standard-alphabet equivalents. Valid
/// base64 characters are never substituted: a concatenated `'A'` is an `A`.
const COMMON_SUBSTITUTIONS: &[(char, char)] = &[('_', '/'), ('-', '+')];

/// Extract and decode obfuscated base64 strings from extracted strings.
///
/// This function attempts multiple strategies:
/// 1. Detect and apply character substitution patterns
/// 2. Strip string concatenation artifacts
/// 3. Extract base64 runs from noisy data
/// 4. Decode with error tolerance
pub(crate) fn extract_fuzzy_base64(strings: &[ExtractedString]) -> Vec<ExtractedString> {
    // A string can yield up to three decodings; `flat_map_iter` parallelises
    // across strings while preserving each string's strategy order.
    strings
        .par_iter()
        .with_min_len(crate::par::MIN_ITEMS_PER_JOB)
        .flat_map_iter(|s| {
            let mut local = Vec::new();

            // Skip if already decoded or too short
            if s.value.len() < MIN_BASE64_SEGMENT {
                return local;
            }

            // Skip XorDecode strings: their base64 value is already decoded by
            // decode_base64_strings. The XorDecode representation (showing the
            // base64 payload) must be preserved in output.
            if s.method == StringMethod::XorDecode {
                return local;
            }

            // Try different extraction strategies
            if let Some(decoded) = try_deobfuscate_js_base64(&s.value) {
                local.push(create_decoded_string(s, decoded));
            }

            if let Some((decoded, span)) = try_fuzzy_extract(&s.value) {
                let mut decoded = create_decoded_string(s, decoded);
                // Cite the run that was decoded, not the whole string, when
                // the string's text is its source bytes verbatim.
                if s.fragments.is_none()
                    && u32::try_from(s.value.len()) == Ok(s.contiguous_source_len())
                {
                    decoded.data_offset = s.data_offset + span.start as u64;
                    decoded.data_len = u32::try_from(span.len()).unwrap_or(u32::MAX);
                }
                local.push(decoded);
            }

            // Try extracting from substrings if this looks like a variable assignment
            if s.value.contains('=')
                && s.value.contains('"')
                && let Some(decoded) = extract_from_assignment(&s.value)
            {
                local.push(create_decoded_string(s, decoded));
            }

            local
        })
        .collect()
}

/// Attempt to deobfuscate JavaScript-style base64 obfuscation.
///
/// Handles concatenated pieces (`"abc' + 'def"`), with base64url `'_'` and
/// `'-'` pieces read as `/` and `+`.
fn try_deobfuscate_js_base64(input: &str) -> Option<String> {
    // First, try to detect what the placeholder characters are
    let substitutions = detect_substitutions(input);

    // Apply substitutions and strip concatenation
    let mut cleaned = input.to_string();

    // Apply detected substitutions
    for (from, to) in substitutions {
        // Handle patterns like ' + 'A' + '
        let pattern_single = format!("' + '{from}' + '");
        cleaned = cleaned.replace(&pattern_single, &to.to_string());

        let pattern_double = format!("\" + \"{from}\" + \"");
        cleaned = cleaned.replace(&pattern_double, &to.to_string());

        // Also handle end patterns
        let pattern_end1 = format!("' + '{from}'");
        cleaned = cleaned.replace(&pattern_end1, &to.to_string());

        let pattern_end2 = format!("'{from}'  + '");
        cleaned = cleaned.replace(&pattern_end2, &to.to_string());
    }

    // Strip concatenation artifacts
    for pattern in JS_CONCAT_PATTERNS {
        cleaned = cleaned.replace(pattern, "");
    }

    // Remove quotes and spaces
    cleaned = cleaned.replace('\'', "");
    cleaned = cleaned.replace('"', "");
    cleaned = cleaned.replace(' ', "");

    // Remove JavaScript variable declarations and assignments
    // Look for patterns like "var X =", "let X =", "const X =", or just "X ="
    if let Some(eq_pos) = cleaned.find('=') {
        // Take everything after the first '='
        cleaned = cleaned[eq_pos + 1..].to_string();
    }

    // Also remove semicolons and other common JS syntax
    cleaned = cleaned.replace(';', "");
    cleaned = cleaned.replace(',', "");

    // Extract only valid base64 characters
    let base64_only: String = cleaned
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
        .collect();

    if !is_base64_like(&base64_only, MIN_BASE64_PURITY) {
        return None;
    }

    decode_base64_fuzzy(&base64_only)
}

/// Detect character substitution patterns by analyzing the string.
///
/// Looks for patterns like `' + 'X' + '` where X appears in positions
/// where base64 would expect '+' or '/' characters.
fn detect_substitutions(input: &str) -> Vec<(char, char)> {
    let mut substitutions = Vec::new();

    // Look for single-character patterns between concatenation operators
    let mut candidates: HashMap<char, usize> = HashMap::new();
    for cap in CONCAT_RE.captures_iter(input) {
        if let Some(ch) = cap.get(1).and_then(|m| m.as_str().chars().next()) {
            *candidates.entry(ch).or_insert(0) += 1;
        }
    }

    for (from, to) in COMMON_SUBSTITUTIONS {
        if candidates.get(from).is_some_and(|&count| count > 2) {
            substitutions.push((*from, *to));
        }
    }

    substitutions
}

/// Extract base64 from variable assignment patterns.
///
/// Handles: `var x = "base64data..."`
fn extract_from_assignment(input: &str) -> Option<String> {
    ASSIGNMENT_RE
        .captures_iter(input)
        .filter_map(|cap| cap.get(1))
        .find_map(|value| try_deobfuscate_js_base64(value.as_str()))
}

/// Fuzzy extraction: decode the longest run of mostly-base64 characters,
/// whitespace inside it dropped. Returns the decoded text and the byte range
/// of `input` it was decoded from.
///
/// This is useful when the base64 is corrupted or has interspersed garbage.
fn try_fuzzy_extract(input: &str) -> Option<(String, Range<usize>)> {
    let mut best = 0..0;
    let mut start = None;
    // Whitespace continues a run; any other non-base64 character, or the
    // end of `input`, closes it.
    for (i, ch) in input.char_indices().chain([(input.len(), '\0')]) {
        if is_base64_char(ch) {
            start.get_or_insert(i);
        } else if !ch.is_whitespace()
            && let Some(s) = start.take()
            && i - s > best.len()
            && is_base64_like(&input[s..i], MIN_BASE64_PURITY)
        {
            best = s..i;
        }
    }
    if best.len() < MIN_BASE64_SEGMENT {
        return None;
    }
    let segment = input[best.clone()].trim_end();
    let span = best.start..best.start + segment.len();

    let joined: String = segment.chars().filter(|c| is_base64_char(*c)).collect();
    let decoded = decode_base64_fuzzy(&joined);
    if decoded.as_deref().is_some_and(decoded_cleanly) {
        return decoded.map(|text| (text, span));
    }
    // Whitespace joins base64 wrapped across lines, but also pulls in the
    // words around a single token: a misaligned join fails to decode, and an
    // aligned one (`echo` + token) decodes to garbage ahead of the payload.
    // The longest token on its own then reads cleanly.
    let token = segment
        .split_whitespace()
        .filter(|token| token.len() >= MIN_BASE64_SEGMENT)
        .max_by_key(|token| token.len())
        .and_then(|token| {
            let start = token.as_ptr().addr() - input.as_ptr().addr();
            Some((decode_base64_fuzzy(token)?, start..start + token.len()))
        });
    match (decoded, token) {
        (_, Some(token)) if decoded_cleanly(&token.0) => Some(token),
        (Some(text), _) => Some((text, span)),
        (None, token) => token,
    }
}

/// Whether a lossy decode was valid UTF-8 throughout.
fn decoded_cleanly(text: &str) -> bool {
    !text.contains(char::REPLACEMENT_CHARACTER)
}

/// Check if a character is valid in base64
fn is_base64_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '+' || ch == '/' || ch == '='
}

/// Check if a string looks like base64 with given purity threshold
fn is_base64_like(s: &str, min_purity: f32) -> bool {
    if s.len() < MIN_BASE64_SEGMENT {
        return false;
    }

    let base64_count = s.chars().filter(|c| is_base64_char(*c)).count();
    let purity = base64_count as f32 / s.len() as f32;

    purity >= min_purity
}

/// Decode base64 with error tolerance
fn decode_base64_fuzzy(input: &str) -> Option<String> {
    use base64::Engine;

    // Try standard base64 first
    if let Ok(decoded_bytes) = base64::engine::general_purpose::STANDARD.decode(input) {
        match String::from_utf8(decoded_bytes) {
            Ok(decoded_str) if is_meaningful_decoded(&decoded_str) => {
                return Some(decoded_str);
            }
            Ok(_) => {
                // Valid UTF-8 but not meaningful; try lossy path with the same bytes
                // (no-op here since it's already valid UTF-8, but fall through)
            }
            Err(err) => {
                // Not valid UTF-8; recover bytes and try lossy decoding
                let decoded_bytes = err.into_bytes();
                let decoded_str = String::from_utf8_lossy(&decoded_bytes).into_owned();
                if is_meaningful_decoded(&decoded_str) {
                    return Some(decoded_str);
                }
            }
        }
    }

    // Try with padding adjustments
    for padding in 0..=3 {
        let mut padded = input.to_string();
        padded.push_str(&"=".repeat(padding));

        if let Ok(decoded_bytes) = base64::engine::general_purpose::STANDARD.decode(&padded) {
            let decoded_str = String::from_utf8_lossy(&decoded_bytes).into_owned();
            if is_meaningful_decoded(&decoded_str) {
                return Some(decoded_str);
            }
        }
    }

    // Last resort: decode the longest valid prefix.
    //
    // Padding can only rescue a string whose length is 2 or 3 past a multiple
    // of four. A *fragment* -- one piece of a payload split across several
    // literals and concatenated at runtime -- has an arbitrary length mod 4,
    // and when that remainder is 1 no amount of padding is legal, so every
    // attempt above fails and the whole piece is lost. Dropping the trailing
    // 1-3 characters costs at most two bytes of the tail and recovers the rest,
    // which for an 11KB chunk is the difference between reading the payload and
    // seeing nothing at all. `is_meaningful_decoded` still gates the result, so
    // truncating a string that was never base64 yields nothing.
    let keep = input.len() - input.len() % 4;
    if keep >= MIN_BASE64_SEGMENT
        && keep != input.len()
        && let Ok(decoded_bytes) = base64::engine::general_purpose::STANDARD.decode(&input[..keep])
    {
        let decoded_str = String::from_utf8_lossy(&decoded_bytes).into_owned();
        if is_meaningful_decoded(&decoded_str) {
            return Some(decoded_str);
        }
    }

    None
}

/// Check if decoded string looks meaningful (not garbage)
fn is_meaningful_decoded(s: &str) -> bool {
    if s.len() < 10 {
        return false;
    }

    // Check for reasonable printable character ratio
    let printable = s
        .chars()
        .filter(|c| c.is_ascii_graphic() || c.is_whitespace())
        .count();

    let ratio = printable as f32 / s.len() as f32;

    // At least 60% printable for meaningful content
    if ratio < 0.6 {
        return false;
    }

    // Look for common indicators of meaningful content
    let has_spaces = s.contains(' ');
    let lower = s.to_lowercase();
    let has_common_words = ["function", "http", "powershell", "script"]
        .iter()
        .any(|word| lower.contains(word))
        || s.contains('$')
        || s.contains("://");

    has_spaces || has_common_words
}

/// Create a new ExtractedString from a decoded value.
fn create_decoded_string(original: &ExtractedString, decoded: String) -> ExtractedString {
    let kind = crate::classifier::classify_string(&decoded);
    ExtractedString {
        value: decoded,
        data_offset: original.data_offset,
        // The payload occupies the obfuscated base64 source, not the decoded form.
        data_len: original.contiguous_source_len(),
        method: StringMethod::Base64ObfuscatedDecode,
        kind,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_split_js_base64() {
        // This encodes to "function powershell -command ..." which meets meaningful_decoded requirements
        // Base64 for: "function powershell -command invoke-expression"
        let input = "ZnVuY3Rpb24gcG93ZXJzaGVsbCAtY29tbWFuZCBpbnZva2' + 'A' + 'ZS1leHByZXNzaW9u";
        let result = try_deobfuscate_js_base64(input);

        let decoded = result.expect("split base64 should decode");
        assert!(decoded.contains("powershell"), "{decoded:?}");
    }

    #[test]
    fn extracts_embedded_base64() {
        // Must have >= MIN_BASE64_SEGMENT (32 chars) and decode to meaningful content (>= 10 chars, >= 60% printable)
        // "function powershell script code" in base64
        let input = "xxx ZnVuY3Rpb24gcG93ZXJzaGVsbCBzY3JpcHQgY29kZQ== yyy";
        let (decoded, span) = try_fuzzy_extract(input).expect("embedded base64 should decode");
        assert!(decoded.contains("powershell script"), "{decoded:?}");
        assert_eq!(&input[span], "ZnVuY3Rpb24gcG93ZXJzaGVsbCBzY3JpcHQgY29kZQ==");
    }

    #[test]
    fn a_word_before_a_token_is_not_decoded_into_it() {
        // `echo` is four base64 characters, so joining it to the token keeps
        // the join aligned and decodes to garbage ahead of the URL.
        let input = "u=$(echo aHR0cHM6Ly9ldmlsLnRlc3QveC5zaA== | base64 -d)";
        let (decoded, span) = try_fuzzy_extract(input).expect("the token should decode");
        assert_eq!(decoded, "https://evil.test/x.sh");
        assert_eq!(&input[span], "aHR0cHM6Ly9ldmlsLnRlc3QveC5zaA==");
    }

    #[test]
    fn base64_like_needs_32_chars() {
        // Must be >= MIN_BASE64_SEGMENT (32 chars)
        assert!(is_base64_like(
            "SGVsbG8gV29ybGQhCg==SGVsbG8gV29ybGQhCg==",
            0.8
        )); // 40 chars
        assert!(!is_base64_like("not base64!!!", 0.8));
        assert!(!is_base64_like("short", 0.8));
        assert!(!is_base64_like("SGVsbG8gV29ybGQhCg==", 0.8)); // Too short (20 chars < 32)
    }
}

#[cfg(test)]
mod fragment_tests {
    use super::*;

    /// A payload split across several literals leaves each piece with an
    /// arbitrary length mod 4. Padding cannot rescue a remainder of 1, so
    /// before the prefix fallback the whole chunk was lost.
    #[test]
    fn recovers_leading_fragment_of_split_payload() {
        use base64::Engine;
        let payload = "import os\nimport threading\nfrom urllib.request import urlopen\n\
                       hook = \"https://discord.com/api/webhooks/1088/abc\"\n";
        let full = base64::engine::general_purpose::STANDARD.encode(payload);
        // Cut so the fragment length is 1 past a multiple of four -- the case
        // no padding can make legal.
        let mut cut = full.len() - 8;
        while cut % 4 != 1 {
            cut -= 1;
        }
        let fragment = &full[..cut];
        assert_eq!(fragment.len() % 4, 1);
        let out = decode_base64_fuzzy(fragment).expect("leading fragment should decode");
        assert!(out.contains("import os"), "got: {out:.60}");
        assert!(out.contains("discord.com/api/webhooks"));
    }

    /// The fallback must not turn arbitrary text into a "decoded" string just
    /// because trimming it produced a length divisible by four.
    #[test]
    fn truncation_does_not_manufacture_decodings() {
        for v in [
            "the quick brown fox jumps over the lazy dog and keeps running onwards",
            "/usr/local/share/doc/example/README.markdown.and.more.text.here.txt",
        ] {
            assert!(decode_base64_fuzzy(v).is_none(), "should not decode: {v}");
        }
    }
}
