//! Encoding detection for string classification.
//!
//! Detects Base64, Base32, Base58, Base85, hex, Unicode escape, URL encoding, and cryptographic hashes.

/// Check if a string looks like a cryptographic hash (MD5, SHA1, SHA256, SHA512).
///
/// Returns true for hex strings of length 32/40/64/128 that decode to mostly non-printable bytes.
/// This distinguishes hashes from hex-encoded ASCII text.
pub(super) fn is_cryptographic_hash(s: &str) -> bool {
    // Must be a valid hash length: MD5=32, SHA1=40, SHA256=64, SHA512=128
    if !matches!(s.len(), 32 | 40 | 64 | 128) {
        return false;
    }

    // Must be all hex digits
    if !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }

    // Decode and check printability - hashes decode to random bytes (<30% printable)
    let decoded: Vec<u8> = (0..s.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect();

    if decoded.is_empty() {
        return false;
    }

    let printable = decoded.iter().filter(|b| b.is_ascii_graphic()).count();

    // Hashes typically have <50% printable bytes (random distribution)
    // Hex-encoded text has >70% printable (mostly ASCII text)
    // Use 50% threshold for safety margin
    printable * 2 < decoded.len()
}

/// Check if a string looks like base64-encoded data
pub(super) fn is_base64(s: &str) -> bool {
    // Must be reasonably long (short base64 could be anything)
    if s.len() < 16 {
        return false;
    }

    // Must be properly padded (length must be multiple of 4)
    if !s.len().is_multiple_of(4) {
        return false;
    }

    // Single pass: validate characters AND track consecutive uppercase at start
    let bytes = s.as_bytes();
    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;
    let mut consecutive_upper_at_start = 0;
    let mut found_non_upper = false;

    for &b in bytes {
        match b {
            b'A'..=b'Z' => {
                has_upper = true;

                // Track consecutive uppercase at start only
                if !found_non_upper {
                    consecutive_upper_at_start += 1;
                }
            }
            b'a'..=b'z' => {
                has_lower = true;

                if !found_non_upper {
                    found_non_upper = true;
                }
            }
            b'0'..=b'9' => {
                has_digit = true;

                if !found_non_upper {
                    found_non_upper = true;
                }
            }
            b'+' | b'/' | b'=' => {
                if !found_non_upper {
                    found_non_upper = true;
                }
            }
            _ => return false, // Invalid character (including spaces)
        }
    }

    // Must have mixed case and digits (good entropy)
    if !has_upper || !has_lower || !has_digit {
        return false;
    }

    // Reject obvious identifier patterns
    // Base64 can have random CamelCase patterns, so we only reject very specific cases

    // 1. Very long uppercase prefixes (4+) indicate framework prefixes (HTTP*, POST*, NSURL*, XML*)
    // Real base64 rarely starts with 4+ consecutive uppercase (only ~1.7% chance)
    if consecutive_upper_at_start >= 4 {
        return false;
    }

    // 2. Go-specific package/type name patterns (http2, grpc, proto keywords)
    // These are distinctive and unlikely in random base64
    if s.len() < 40 {
        let lower = s.to_lowercase();
        if lower.contains("http2") || lower.contains("grpc") || lower.contains("proto") {
            return false;
        }
    }

    // 3. Reject lowerCamelCase identifiers
    // These start with many consecutive lowercase letters (like "wants10KeepAlive")
    // Real base64 has random case distribution, unlikely to start with 4+ consecutive lowercase
    let mut consecutive_lower_at_start = 0;
    for &b in bytes {
        if b.is_ascii_lowercase() {
            consecutive_lower_at_start += 1;
        } else {
            break;
        }
    }

    // Reject if starts with 4+ consecutive lowercase (clear lowerCamelCase pattern)
    if consecutive_lower_at_start >= 4 {
        return false;
    }

    // Exclude sequential patterns (alphabet lookups, test data)
    if s.contains("ABCDE") || s.contains("012345") || s.contains("the ") || s.contains("and ") {
        return false;
    }

    // Reject strings with long runs of consecutive digits (8+).
    // These are typically ASN.1 certificate timestamps (e.g. "201229235959Z0b1")
    // or version-like data, not real base64.
    {
        let mut digit_run = 0u32;
        for &b in bytes {
            if b.is_ascii_digit() {
                digit_run += 1;
                if digit_run >= 8 {
                    return false;
                }
            } else {
                digit_run = 0;
            }
        }
    }

    // Final check: if input looks like readable text and output is garbage, reject
    // e.g., "IWorkItemQueriesExt2" (readable identifier) decodes to binary garbage
    // Only apply when input has high vowel ratio (indicates real words, not random chars)
    if let Ok(decoded) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, s) {
        let (input_quality, input_vowel_ratio) = text_quality_score(s.as_bytes());

        // Skip check if input has many repeated characters (encoded binary, not readable text)
        // e.g., "TVqQAAMAAAAEAAAA" has many 'A's from null bytes
        let max_char_count = bytes
            .iter()
            .fold([0u8; 256], |mut acc, &b| {
                acc[b as usize] = acc[b as usize].saturating_add(1);
                acc
            })
            .into_iter()
            .max()
            .unwrap_or(0);
        let max_char_ratio = (max_char_count as usize * 100) / bytes.len();
        if max_char_ratio > 30 && bytes.len() >= 24 {
            return true; // Likely encoded binary, not a readable identifier
        }

        // For short strings (< 24 chars) with high character repetition AND
        // few input vowels, verify the decoded output is mostly printable.
        // This catches x86 instruction patterns like "rtVHHtRHt2HtLHHu" where
        // repeated opcodes (e.g. 'H' = REX prefix) inflate max_char_ratio but
        // the decoded output is largely non-printable.
        // Strings with many vowels (like "TVqQAAMAAAAEAAAA") skip this check
        // since the repetition comes from null-byte padding in real encoded data.
        if max_char_ratio > 30 && bytes.len() < 24 && input_vowel_ratio < 10 {
            let printable = decoded
                .iter()
                .filter(|&&b| b.is_ascii_graphic() || b == b' ')
                .count();
            if printable * 2 < decoded.len() {
                return false;
            }
        }

        // Only check quality comparison if input looks like natural language
        // Real identifiers have ~30%+ vowels; random base64-ish strings have ~20%
        if input_vowel_ratio >= 28 {
            let (output_quality, _) = text_quality_score(&decoded);

            // If input is more readable than output, it's likely an identifier, not base64
            if input_quality > output_quality {
                return false;
            }
        }
    }

    true
}

/// Calculate text quality score (0-100) and vowel ratio.
/// Higher quality = more text-like. Returns (quality, vowel_ratio).
fn text_quality_score(bytes: &[u8]) -> (u32, u32) {
    if bytes.is_empty() {
        return (0, 0);
    }

    let mut alpha = 0usize;
    let mut vowel = 0usize;
    let mut printable = 0usize;

    for &b in bytes {
        if b.is_ascii_alphabetic() {
            alpha += 1;
            if matches!(b.to_ascii_lowercase(), b'a' | b'e' | b'i' | b'o' | b'u') {
                vowel += 1;
            }
        }
        if b.is_ascii_graphic() || b == b' ' {
            printable += 1;
        }
    }

    let printable_ratio = (printable * 100) / bytes.len();
    let vowel_ratio = if alpha > 0 { (vowel * 100) / alpha } else { 0 };

    // Weighted combination: printability matters most, vowel ratio indicates natural language
    let quality = u32::try_from((printable_ratio * 7 + vowel_ratio * 3) / 10).unwrap_or(0);
    (quality, u32::try_from(vowel_ratio).unwrap_or(0))
}

/// Check if a string looks like hex-encoded ASCII data
pub(super) fn is_hex_encoded(s: &str) -> bool {
    // Must be reasonably long (at least 16 chars = 8 decoded bytes)
    if s.len() < 16 {
        return false;
    }

    // Must be even length (pairs of hex digits)
    if !s.len().is_multiple_of(2) {
        return false;
    }

    // Must be all hex digits
    if !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }

    // Decode and check if mostly printable ASCII
    let decoded: Vec<u8> = (0..s.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect();

    if decoded.is_empty() {
        return false;
    }

    let printable = decoded
        .iter()
        .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        .count();

    // At least 70% printable
    printable * 10 > decoded.len() * 7
}

/// Check if a string looks like Unicode-escaped data (\xXX or \uXXXX format)
pub(super) fn is_unicode_escaped(s: &str) -> bool {
    // Must be reasonably long
    if s.len() < 20 {
        return false;
    }

    // Count escape sequences
    let mut escape_count = 0;
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(&next) = chars.peek() {
                if next == 'x' || next == 'u' {
                    escape_count += 1;
                }
            }
        }
    }

    // Need at least 5 escape sequences to be confident
    if escape_count < 5 {
        return false;
    }

    // Try to decode and check if result is mostly printable
    let decoded = decode_unicode_escapes(s);
    if decoded.is_empty() {
        return false;
    }

    let printable = decoded
        .iter()
        .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        .count();

    // At least 60% printable (slightly more lenient than hex)
    printable * 10 > decoded.len() * 6
}

/// Decode Unicode escape sequences from a string
pub(super) fn decode_unicode_escapes(s: &str) -> Vec<u8> {
    let mut result = Vec::new();
    let mut chars = s.chars();

    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(next) = chars.next() {
                match next {
                    // \xXX format (2 hex digits)
                    'x' => {
                        let hex: String = chars.by_ref().take(2).collect();
                        if hex.len() == 2 {
                            if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                                result.push(byte);
                                continue;
                            }
                        }
                        // Failed to parse, add literal characters
                        result.push(b'\\');
                        result.push(b'x');
                        result.extend(hex.as_bytes());
                    }
                    // \uXXXX format (4 hex digits)
                    'u' => {
                        let hex: String = chars.by_ref().take(4).collect();
                        if hex.len() == 4 {
                            if let Ok(codepoint) = u16::from_str_radix(&hex, 16) {
                                // Convert to UTF-8
                                if let Some(ch) = char::from_u32(codepoint as u32) {
                                    let mut buf = [0u8; 4];
                                    let encoded = ch.encode_utf8(&mut buf);
                                    result.extend_from_slice(encoded.as_bytes());
                                    continue;
                                }
                            }
                        }
                        // Failed to parse, add literal characters
                        result.push(b'\\');
                        result.push(b'u');
                        result.extend(hex.as_bytes());
                    }
                    // Other escape sequences - just add as-is
                    _ => {
                        result.push(b'\\');
                        let mut buf = [0u8; 4];
                        result.extend_from_slice(next.encode_utf8(&mut buf).as_bytes());
                    }
                }
            } else {
                result.push(b'\\');
            }
        } else {
            // Regular character
            let mut buf = [0u8; 4];
            result.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        }
    }

    result
}

/// Check if a string looks like URL-encoded data (%XX format)
pub(super) fn is_url_encoded(s: &str) -> bool {
    // Must be reasonably long
    if s.len() < 12 {
        return false;
    }

    // Quick check: must contain '%' to be URL-encoded
    if !s.as_bytes().contains(&b'%') {
        return false;
    }

    // Count VALID percent-encoded sequences (%XX where XX are hex digits)
    // Also track if any decode to control characters (sign of C format strings)
    let mut valid_percent_count = 0;
    let mut total_percent_count = 0;
    let mut control_char_count = 0;
    let chars: Vec<char> = s.chars().collect();

    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '%' {
            total_percent_count += 1;
            // Check if followed by two hex digits
            if i + 2 < chars.len()
                && chars[i + 1].is_ascii_hexdigit()
                && chars[i + 2].is_ascii_hexdigit()
            {
                valid_percent_count += 1;

                // Check what this decodes to
                let hex: String = [chars[i + 1], chars[i + 2]].iter().collect();
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    // Control characters (0x00-0x1F except tab/newline/carriage return, and 0x7F)
                    // are unusual in real URL encoding and common in C format strings
                    // (e.g., %02d where %02 decodes to STX)
                    if byte < 0x09
                        || (byte > 0x0D && byte < 0x20)
                        || byte == 0x7F
                        || byte == 0x0B
                        || byte == 0x0C
                    {
                        control_char_count += 1;
                    }
                }

                i += 3;
                continue;
            }
        }
        i += 1;
    }

    // Need at least 2 VALID %XX sequences (not just % signs)
    if valid_percent_count < 2 {
        return false;
    }

    // If most decoded bytes are control characters, it's likely a C format string
    // not URL encoding (e.g., "%02d" decodes %02 to STX control char)
    if control_char_count > 0 && control_char_count * 2 >= valid_percent_count {
        return false;
    }

    // Most % signs should be valid %XX sequences (reject printf format strings)
    if total_percent_count > 0 && valid_percent_count * 10 < total_percent_count * 7 {
        return false;
    }

    // Try to decode and check if result is mostly printable
    let decoded = decode_url_encoding(s);
    if decoded.is_empty() {
        return false;
    }

    let printable = decoded
        .iter()
        .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        .count();

    // At least 60% printable
    printable * 10 > decoded.len() * 6
}

/// Decode URL-encoded string (%XX format)
pub(super) fn decode_url_encoding(s: &str) -> Vec<u8> {
    let mut result = Vec::new();
    let mut chars = s.chars();

    while let Some(c) = chars.next() {
        if c == '%' {
            // Try to read two hex digits
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte);
                    continue;
                }
            }
            // Failed to parse, add literal characters
            result.push(b'%');
            result.extend(hex.as_bytes());
        } else if c == '+' {
            // In URL encoding, + represents space
            result.push(b' ');
        } else {
            // Regular character
            let mut buf = [0u8; 4];
            result.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        }
    }

    result
}

/// Check if a string looks like Base32-encoded data
pub(super) fn is_base32(s: &str) -> bool {
    // Must be reasonably long (at least 16 chars = 10 bytes)
    if s.len() < 16 {
        return false;
    }

    // Single pass: validate all constraints at once
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
            b'=' => valid_count += 1, // Padding
            // Invalid characters for Base32
            b'0' | b'1' | b'8' | b'9' | b'a'..=b'z' => return false,
            _ => {} // Other invalid chars reduce the valid percentage
        }
    }

    // Must have both letters and digits (not pure text or pure numbers)
    if !has_letters || !has_digits {
        return false;
    }

    // At least 90% valid Base32 characters
    valid_count * 10 >= s.len() * 9
}

/// Check if a string looks like Base58-encoded data (Bitcoin alphabet)
pub(super) fn is_base58(s: &str) -> bool {
    // Must be reasonably long (Bitcoin addresses are typically 26-35 chars)
    if s.len() < 20 {
        return false;
    }

    // Single pass validation
    // Base58 alphabet: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
    // Excludes: 0, O, I, l (confusing characters)
    let bytes = s.as_bytes();
    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;
    let mut camel_case_transitions = 0;
    let mut consecutive_upper_at_start = 0;
    let mut found_non_upper = false;
    let mut prev_was_lower = false;

    for &b in bytes {
        let is_upper = matches!(b, b'A'..=b'H' | b'J'..=b'N' | b'P'..=b'Z');
        let is_lower = matches!(b, b'a'..=b'k' | b'm'..=b'z');

        match b {
            b'1'..=b'9' => has_digit = true,
            b'A'..=b'H' | b'J'..=b'N' | b'P'..=b'Z' => has_upper = true,
            b'a'..=b'k' | b'm'..=b'z' => has_lower = true,
            // Invalid characters for Base58 (0, O, I, l)
            _ => return false,
        }

        // Detect CamelCase/PascalCase patterns
        if prev_was_lower && is_upper {
            camel_case_transitions += 1;
        }

        // Track consecutive uppercase letters at the START only
        // (characteristic of class names like "NSKnown", "XMLParser", "UIViewController")
        if !found_non_upper {
            if is_upper {
                consecutive_upper_at_start += 1;
            } else {
                found_non_upper = true;
            }
        }

        prev_was_lower = is_lower;
    }

    // Base58 must have all three types
    if !(has_upper && has_lower && has_digit) {
        return false;
    }

    // Reject strings that look like class names/identifiers:
    // 1. Long uppercase prefixes (3+) indicate framework prefixes (NSU*, HTTP*, XML*)
    if consecutive_upper_at_start >= 3 {
        return false;
    }

    // 2. Two-letter prefixes with CamelCase = class names (NS*, UI*, CA*)
    //    e.g., "NSKnownKeysDictionary1"
    if consecutive_upper_at_start >= 2 && camel_case_transitions >= 2 {
        return false;
    }

    // 3. Single uppercase start + many transitions = structured identifier
    //    e.g., "TheQuickBrownFoxJumpsOverTheLazyDog1"
    //    Use 7+ to avoid false positives on crypto addresses (some have 6 by chance)
    if consecutive_upper_at_start == 1 && camel_case_transitions >= 7 {
        return false;
    }

    // 4. Go package/type names (common patterns)
    //    These start lowercase but contain distinctive keywords
    if s.len() < 40 {
        let lower = s.to_lowercase();
        if lower.contains("http2") || lower.contains("grpc") || lower.contains("proto") {
            return false;
        }
    }

    // 5. Reject readable identifiers: if input is more text-like than it would be as base58
    //    Real base58 is random; readable PascalCase identifiers have high vowel ratios
    let (_, input_vowel_ratio) = text_quality_score(s.as_bytes());
    if input_vowel_ratio >= 28 {
        // High vowel ratio indicates readable text, not random encoding
        return false;
    }

    true
}

/// Calculate string quality score (0-100). Higher scores = better quality text.
pub(super) fn string_quality_score(s: &str) -> u32 {
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
    // Good English text has ~40% vowels, ~90%+ printable
    u32::try_from((printable_ratio * 7 + vowel_ratio * 3) / 10).unwrap_or(0)
}

/// Check if a string looks like Base85-encoded data (ASCII85 or Z85)
pub(super) fn is_base85(s: &str) -> bool {
    // Require minimum length
    if s.len() < 20 {
        return false;
    }

    // Check for ASCII85 delimiters (<~ and ~>)
    let has_delimiters = s.starts_with("<~") && s.ends_with("~>");

    // If it has proper delimiters and reasonable length, validate by decoding
    if has_delimiters && s.len() >= 20 && s.len() < 10000 {
        return validate_base85_by_decoding(s);
    }

    // Single pass validation
    // ASCII85 uses '!' (33) to 'u' (117), plus 'z' for zero bytes
    let bytes = s.as_bytes();
    let mut valid_count = 0;
    let mut has_lowercase = false;
    let mut has_punctuation = false;
    let mut is_env_var_like = true;
    let mut unique_char_count = 0;
    let mut seen_chars = 0u128; // Bitmap for tracking up to 128 unique chars efficiently

    for &b in bytes {
        // Check if valid ASCII85 character
        if matches!(b, b'!'..=b'u' | b'z') {
            valid_count += 1;

            // Track character diversity without allocation
            let bit_pos = b as u32;
            if bit_pos < 128 && (seen_chars & (1u128 << bit_pos)) == 0 {
                seen_chars |= 1u128 << bit_pos;
                unique_char_count += 1;
            }
        }

        // Track character types for filtering false positives
        match b {
            b'a'..=b'z' => has_lowercase = true,
            b'!'..=b'/' | b':'..=b'@' | b'['..=b'`' | b'{'..=b'~' => has_punctuation = true,
            _ => {}
        }

        // Check if it could be an environment variable
        if !matches!(b, b'A'..=b'Z' | b'_' | b'0'..=b'9') {
            is_env_var_like = false;
        }
    }

    // Reject environment variable patterns
    if is_env_var_like {
        return false;
    }

    // Reject strings that look like URLs, paths, function names, or normal text
    if s.contains("://")
        || s.contains("http")
        || s.starts_with('@')
        || s.starts_with('/')
        || s.contains("apple")
        || s.contains("Apple")
        || s.contains("Authority")
        || s.contains("plist")
        || s.contains("version")
        || s.contains('.') && s.split('.').count() > 2
        || s.starts_with('+')
        || s.starts_with(' ')
    {
        return false;
    }

    // Reject passwd-style entries: username:*:uid:gid:comment:home:shell
    if s.contains(":*:")
        || (s.matches(':').count() >= 6
            && (s.contains("/usr/bin/") || s.contains("/bin/") || s.contains("/var/")))
    {
        return false;
    }

    // Reject strings that look like character sets or pure punctuation
    let punct_count = s.bytes().filter(u8::is_ascii_punctuation).count();
    if punct_count * 2 > s.len() {
        return false;
    }

    // Reject strings that look like base64 (end with = padding, contain + or /)
    // Real ASCII85 uses z for compression, not = for padding
    if s.ends_with('=') || s.contains('+') && s.contains('/') {
        return false;
    }

    // Must have lowercase or punctuation (not just uppercase)
    if !has_lowercase && !has_punctuation {
        return false;
    }

    // For longer strings (>= 50), be very strict to reduce false positives
    if s.len() >= 50 {
        // Require 98% valid chars AND good character distribution
        if valid_count * 100 < s.len() * 98 || unique_char_count < 15 {
            return false;
        }
        // Still need to validate by decoding - fall through
    }

    // For shorter strings, use moderate threshold
    if valid_count * 10 < s.len() * 9 {
        return false;
    }

    // Must have good character distribution (at least 8 unique chars)
    if unique_char_count < 8 {
        return false;
    }

    // Reject readable identifiers: high vowel ratio indicates text, not encoding
    let (_, input_vowel_ratio) = text_quality_score(s.as_bytes());
    if input_vowel_ratio >= 28 {
        return false;
    }

    // Final validation: try decoding and check if result is higher quality
    validate_base85_by_decoding(s)
}

/// Validate base85 by attempting to decode and checking if result is higher quality.
/// Returns true only if decoding produces better text than the original.
fn validate_base85_by_decoding(s: &str) -> bool {
    use crate::decoders::try_decode_ascii85;

    let original_quality = string_quality_score(s);

    // Try to decode
    if let Some(decoded_bytes) = try_decode_ascii85(s) {
        // Check if decoded is valid UTF-8 and higher quality
        if let Ok(decoded_str) = String::from_utf8(decoded_bytes) {
            let decoded_quality = string_quality_score(&decoded_str);

            // Decoded should be better quality (at least 5 points higher)
            // Otherwise it's probably not actually base85
            return decoded_quality > original_quality + 5;
        }
    }

    // If we can't decode or result is worse, it's not real base85
    false
}
