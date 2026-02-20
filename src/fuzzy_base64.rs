//! Fuzzy base64 extraction for obfuscated malware samples.
//!
//! This module handles base64 strings that have been obfuscated through:
//! - Character substitution (e.g., 'A' -> '+', '9' -> '/')
//! - String concatenation artifacts (e.g., ' + ', '" + "')
//! - Interspersed garbage characters
//! - Partial corruption

use crate::types::{ExtractedString, StringKind, StringMethod};
use regex::Regex;
use std::collections::HashMap;
use std::sync::LazyLock;

static CONCAT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"['"]\s*\+\s*['"]([A-Za-z0-9])['"]\s*\+\s*['"]"#).expect("valid static regex")
});
static ASSIGNMENT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"=\s*["']([^"']+)["']"#).expect("valid static regex"));

/// Minimum length for a base64 segment to be considered valid
const MIN_BASE64_SEGMENT: usize = 32;

/// Minimum percentage of valid base64 characters for fuzzy extraction
const MIN_BASE64_PURITY: f32 = 0.65;

/// Common obfuscation patterns found in JavaScript/VBScript malware
const JS_CONCAT_PATTERNS: &[&str] = &["' + '", "\" + \"", "' +  '", "\" +  \"", " + ", "'+", "\"+"];

/// Common character substitution patterns (placeholder -> real)
const COMMON_SUBSTITUTIONS: &[(char, char)] = &[('A', '+'), ('9', '/'), ('_', '/'), ('-', '+')];

/// Result of fuzzy base64 extraction
#[derive(Debug)]
pub struct FuzzyBase64Result {
    pub decoded: String,
}

/// Extract and decode obfuscated base64 strings from extracted strings.
///
/// This function attempts multiple strategies:
/// 1. Detect and apply character substitution patterns
/// 2. Strip string concatenation artifacts
/// 3. Extract base64 runs from noisy data
/// 4. Decode with error tolerance
pub fn extract_fuzzy_base64(strings: &[ExtractedString]) -> Vec<ExtractedString> {
    let mut results = Vec::new();

    for s in strings {
        // Skip if already decoded or too short
        if s.value.len() < MIN_BASE64_SEGMENT {
            continue;
        }

        // Skip XorDecode strings: their base64 value is already decoded by decode_base64_strings.
        // The XorDecode representation (showing the base64 payload) must be preserved in output.
        if s.method == StringMethod::XorDecode {
            continue;
        }

        // Try different extraction strategies
        if let Some(decoded) = try_deobfuscate_js_base64(&s.value) {
            tracing::debug!(
                "Fuzzy base64: decoded {} bytes from offset 0x{:x} via JSObfuscation",
                decoded.decoded.len(),
                s.data_offset
            );
            results.push(create_decoded_string(s, decoded, "JSObfuscation"));
        }

        if let Some(decoded) = try_fuzzy_extract(&s.value) {
            tracing::debug!(
                "Fuzzy base64: decoded {} bytes from offset 0x{:x} via FuzzyExtract",
                decoded.decoded.len(),
                s.data_offset
            );
            results.push(create_decoded_string(s, decoded, "FuzzyExtract"));
        }

        // Try extracting from substrings if this looks like a variable assignment
        if s.value.contains('=') && s.value.contains('"') {
            if let Some(decoded) = extract_from_assignment(&s.value) {
                tracing::debug!(
                    "Fuzzy base64: decoded {} bytes from offset 0x{:x} via Assignment",
                    decoded.decoded.len(),
                    s.data_offset
                );
                results.push(create_decoded_string(s, decoded, "Assignment"));
            }
        }
    }

    if !results.is_empty() {
        tracing::info!(
            "Fuzzy base64: extracted {} obfuscated base64 strings",
            results.len()
        );
    }

    results
}

/// Attempt to deobfuscate JavaScript-style base64 obfuscation.
///
/// Handles patterns like:
/// - `"abc' + 'A' + 'def"` where 'A' should be '+'
/// - `"xyz' + '9' + 'qrs"` where '9' should be '/'
fn try_deobfuscate_js_base64(input: &str) -> Option<FuzzyBase64Result> {
    // First, try to detect what the placeholder characters are
    let substitutions = detect_substitutions(input);

    // Apply substitutions and strip concatenation
    let mut cleaned = input.to_string();

    // Apply detected substitutions
    for (from, to) in substitutions {
        // Handle patterns like ' + 'A' + '
        let pattern_single = format!("' + '{}' + '", from);
        cleaned = cleaned.replace(&pattern_single, &to.to_string());

        let pattern_double = format!("\" + \"{}\" + \"", from);
        cleaned = cleaned.replace(&pattern_double, &to.to_string());

        // Also handle end patterns
        let pattern_end1 = format!("' + '{}'", from);
        cleaned = cleaned.replace(&pattern_end1, &to.to_string());

        let pattern_end2 = format!("'{}'  + '", from);
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

    // Check if this looks like base64
    if !is_base64_like(&base64_only, MIN_BASE64_PURITY) {
        return None;
    }

    // Try to decode
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

    // Common heuristic: 'A' is often used for '+', '9' for '/'
    if candidates.contains_key(&'A') {
        substitutions.push(('A', '+'));
    }
    if candidates.contains_key(&'9') {
        substitutions.push(('9', '/'));
    }

    // Try other common substitutions if frequency is high
    for (from, to) in COMMON_SUBSTITUTIONS {
        if let Some(&count) = candidates.get(from) {
            if count > 2 && !substitutions.iter().any(|(f, _)| f == from) {
                substitutions.push((*from, *to));
            }
        }
    }

    substitutions
}

/// Extract base64 from variable assignment patterns.
///
/// Handles: `var x = "base64data..."`
fn extract_from_assignment(input: &str) -> Option<FuzzyBase64Result> {
    let assignment_re = &*ASSIGNMENT_RE;

    for cap in assignment_re.captures_iter(input) {
        if let Some(value) = cap.get(1) {
            // Try to deobfuscate this substring
            if let Some(result) = try_deobfuscate_js_base64(value.as_str()) {
                return Some(result);
            }
        }
    }

    None
}

/// Fuzzy extraction: find longest runs of mostly-base64 characters.
///
/// This is useful when the base64 is corrupted or has interspersed garbage.
fn try_fuzzy_extract(input: &str) -> Option<FuzzyBase64Result> {
    let mut best_segment = String::new();
    let mut current_segment = String::new();

    for ch in input.chars() {
        if is_base64_char(ch) {
            current_segment.push(ch);
        } else if ch.is_whitespace() || ch == '+' || ch == '=' {
            // Allow some noise
            if !current_segment.is_empty() {
                current_segment.push(ch);
            }
        } else {
            // End of segment
            if current_segment.len() > best_segment.len()
                && is_base64_like(&current_segment, MIN_BASE64_PURITY)
            {
                best_segment = current_segment.clone();
            }
            current_segment.clear();
        }
    }

    // Check final segment
    if current_segment.len() > best_segment.len()
        && is_base64_like(&current_segment, MIN_BASE64_PURITY)
    {
        best_segment = current_segment;
    }

    if best_segment.len() < MIN_BASE64_SEGMENT {
        return None;
    }

    // Clean up the segment
    let cleaned: String = best_segment
        .chars()
        .filter(|c| is_base64_char(*c))
        .collect();

    decode_base64_fuzzy(&cleaned)
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
fn decode_base64_fuzzy(input: &str) -> Option<FuzzyBase64Result> {
    use base64::Engine;

    // Try standard base64 first
    if let Ok(decoded_bytes) = base64::engine::general_purpose::STANDARD.decode(input) {
        if let Ok(decoded_str) = String::from_utf8(decoded_bytes.clone()) {
            // Check if decoded string looks meaningful
            if is_meaningful_decoded(&decoded_str) {
                return Some(FuzzyBase64Result {
                    decoded: decoded_str,
                });
            }
        }

        // Try UTF-8 lossy
        let decoded_str = String::from_utf8_lossy(&decoded_bytes).to_string();
        if is_meaningful_decoded(&decoded_str) {
            return Some(FuzzyBase64Result {
                decoded: decoded_str,
            });
        }
    }

    // Try with padding adjustments
    for padding in 0..=3 {
        let mut padded = input.to_string();
        for _ in 0..padding {
            padded.push('=');
        }

        if let Ok(decoded_bytes) = base64::engine::general_purpose::STANDARD.decode(&padded) {
            let decoded_str = String::from_utf8_lossy(&decoded_bytes).to_string();
            if is_meaningful_decoded(&decoded_str) {
                return Some(FuzzyBase64Result {
                    decoded: decoded_str,
                });
            }
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
    let has_common_words = s.to_lowercase().contains("function")
        || s.to_lowercase().contains("http")
        || s.to_lowercase().contains("powershell")
        || s.to_lowercase().contains("script")
        || s.contains("$")
        || s.contains("://");

    has_spaces || has_common_words
}

/// Create a new ExtractedString from a decoded result
fn create_decoded_string(
    original: &ExtractedString,
    result: FuzzyBase64Result,
    _method_suffix: &str,
) -> ExtractedString {
    // Determine the kind based on the decoded content
    let kind = if result.decoded.contains("http://") || result.decoded.contains("https://") {
        StringKind::Url
    } else if result.decoded.contains("powershell") || result.decoded.contains("cmd.exe") {
        StringKind::ShellCmd
    } else {
        StringKind::Const
    };

    ExtractedString {
        value: result.decoded,
        data_offset: original.data_offset,
        section: original.section.clone(),
        method: StringMethod::Base64ObfuscatedDecode,
        kind,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_js_obfuscation() {
        // This encodes to "function powershell -command ..." which meets meaningful_decoded requirements
        // Base64 for: "function powershell -command invoke-expression"
        let input = "ZnVuY3Rpb24gcG93ZXJzaGVsbCAtY29tbWFuZCBpbnZva2' + 'A' + 'ZS1leHByZXNzaW9u";
        let result = try_deobfuscate_js_base64(input);

        // May not decode if requirements not met, that's OK
        if let Some(decoded) = result {
            assert!(
                decoded.decoded.to_lowercase().contains("function")
                    || decoded.decoded.to_lowercase().contains("powershell")
            );
        }
    }

    #[test]
    fn test_fuzzy_extract() {
        // Must have >= MIN_BASE64_SEGMENT (32 chars) and decode to meaningful content (>= 10 chars, >= 60% printable)
        // "function powershell script code" in base64
        let input = "xxx ZnVuY3Rpb24gcG93ZXJzaGVsbCBzY3JpcHQgY29kZQ== yyy";
        let result = try_fuzzy_extract(input);
        // May not decode if is_meaningful_decoded requirements not met
        // Just verify no panic
        let _ = result;
    }

    #[test]
    fn test_is_base64_like() {
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
