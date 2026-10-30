//! String validation utilities.
//!
//! Functions for validating and filtering string candidates to remove garbage
//! and low-quality strings.

mod recognize;
mod shape;

use recognize::is_recognized_ioc;
use shape::is_statistical_garbage;

/// Character-class counts for a candidate, gathered in one pass.
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
    second_char: Option<char>,
    last_char: char,
    all_same: bool,
    /// Lowercase ASCII vowels; the word-likeness rules only look at lowercase.
    vowels: usize,
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
        let mut second_char = None;
        let mut vowels = 0usize;

        for c in s.chars() {
            char_count += 1;
            if char_count == 2 {
                second_char = Some(c);
            }
            if matches!(c, 'a' | 'e' | 'i' | 'o' | 'u') {
                vowels += 1;
            }
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
            second_char,
            last_char,
            all_same,
            has_non_hex_letter,
            alphanumeric,
            char_count,
            vowels,
        }
    }

    /// A lone `0` or `1` leading the string, not the start of a longer number:
    /// real identifiers rarely start that way.
    fn suspicious_leading_digit(&self) -> bool {
        matches!(self.first_char, '0' | '1')
            && self.second_char.is_some_and(|c| !c.is_ascii_digit())
    }
}

/// Determines if a string appears to be garbage/noise rather than meaningful content.
///
/// Fast path: Check if long strings with normal patterns are obviously valid.
///
/// This avoids expensive analysis for the common case.
fn is_fast_path_valid_with_kind(
    s: &str,
    len: usize,
    kind: Option<crate::types::StringKind>,
) -> bool {
    if len >= 12 {
        let bytes = s.as_bytes();
        let first = bytes[0];
        // Quick check for all-same-character strings (garbage)
        if bytes.iter().all(|&b| b == first) {
            return false;
        }
        // If it starts with a letter and has mostly alphanumeric + common punctuation, it's valid.
        // Single pass: collect everything needed for the ratio check and reloc rejection.
        if first.is_ascii_alphabetic() {
            let mut simple_count = 0usize;
            let mut letter_counts = [0u32; 26];
            let mut has_non_ascii = false;
            let mut uppercase = 0usize;
            let mut digit = 0usize;
            let mut special = 0usize;

            for &b in bytes {
                if b.is_ascii_alphanumeric() || matches!(b, b' ' | b'_' | b'-' | b'.' | b'/') {
                    simple_count += 1;
                }
                if b.is_ascii_lowercase() {
                    letter_counts[(b - b'a') as usize] += 1;
                } else if !b.is_ascii() {
                    has_non_ascii = true;
                } else if b.is_ascii_uppercase() {
                    uppercase += 1;
                } else if b.is_ascii_digit() {
                    digit += 1;
                } else if b != b' ' {
                    // ASCII, not alphanumeric, not space
                    special += 1;
                }
            }

            if simple_count * 100 / len >= 80 {
                let max_letter = letter_counts.iter().max().copied().unwrap_or(0) as usize;
                // For pure-ASCII strings char_count == len, avoiding an extra O(n) scan.
                let char_count = if has_non_ascii {
                    s.chars().count()
                } else {
                    len
                };

                if has_non_ascii {
                    // Reloc pattern: one letter dominates with non-ASCII noise
                    if char_count > 0 && max_letter * 100 / char_count > 30 {
                        return false;
                    }
                } else if char_count <= 25 && max_letter >= 3 {
                    // All-ASCII reloc pattern: dominant letter + mixed uppercase/digits/special
                    if max_letter * 100 / char_count >= 35
                        && uppercase >= 2
                        && (digit >= 1 || special >= 2)
                    {
                        return false;
                    }
                }
                return true;
            }
        }
    }

    // If the extractor already classified this string (or classify_string
    // recognises it now), it is not garbage.  When a classifier-produced
    // `kind` hint is passed in we skip `classify_string`, the costliest step
    // on the garbage-filter path.  Extractor-only labels
    // (`Overlay`, `Section`, `Import`, …) fall through to the real
    // classifier because those labels don't imply content recognition.
    if s.is_ascii() {
        if kind.is_some_and(crate::types::StringKind::is_classifier_output) {
            return true;
        }
        if crate::classifier::classify_string(s).is_some() {
            return true;
        }
    }

    false
}

/// Fast path: Check if string is obviously garbage without deep analysis.
fn is_fast_path_garbage(s: &str, original: &str, len: usize) -> bool {
    // Empty or single character
    if len == 0 || len == 1 {
        return true;
    }

    // Reject strings with embedded control characters. `s` is already trimmed
    // (whitespace, including `\n`, `\t`, and ` `, is stripped by `str::trim`),
    // so anything that survives is embedded mid-string and is genuine noise.
    if s.chars().any(char::is_control) {
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
    if len < 30 && (s.contains("\\x") || s.contains("\\u") || s.contains("\\U")) {
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

/// This heuristic detects common patterns of misaligned reads and low-value strings:
/// - Short strings with non-alphanumeric characters
/// - Strings ending with backtick + letter + spaces (misaligned Go data)
/// - Strings with very low alphanumeric ratio
/// - Strings that are mostly whitespace padding
/// - Strings with embedded null or control characters
#[must_use]
pub fn is_garbage(s: &str) -> bool {
    is_garbage_with_context(s, &crate::types::StringContext::empty())
}

/// [`is_garbage`] informed by what the caller knows about the string.
///
/// `kind` exempts strings an extractor already recognised. `in_code_section`
/// and `arch` scope the code-only rules: the x86 register save-sequence
/// detector runs only when the string may come from code (`None` or
/// `Some(true)`) of an x86-family binary (`None` or an x86 `Arch`). Source
/// files and other non-binary inputs should pass `in_code_section:
/// Some(false)`, so those rules stay off. A default
/// [`StringContext`](crate::types::StringContext) assumes nothing; it is what
/// [`is_garbage`] passes.
#[must_use]
pub fn is_garbage_with_context(s: &str, ctx: &crate::types::StringContext) -> bool {
    let trimmed = s.trim();
    let len = trimmed.len();

    // Short environment assignments in data sections can resemble random
    // uppercase identifier noise. Retain the conventional NAME=value shape
    // so a real setting such as HISTSIZE=0 remains searchable. Do not exempt
    // strings recovered from executable code, where accidental bytes are
    // common, or values containing whitespace/control characters.
    if ctx.in_code_section != Some(true)
        && let Some((name, value)) = trimmed.split_once('=')
        && (5..=64).contains(&name.len())
        && name.as_bytes()[0].is_ascii_uppercase()
        && name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        && !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|b| b.is_ascii_graphic() && b != b'=')
    {
        return false;
    }

    // A trailing label separator does not change what a string is. Field names
    // (`TracerPid:` in /proc/<pid>/status, `VmRSS:`), header names
    // (`Content-Length:`) and struct labels are their identifier plus a colon,
    // yet the colon alone was enough to flip the verdict: it adds a character
    // class and a run, which no short-identifier pattern here tolerates
    // (`is_pascal_case` allows one uppercase and no specials), and strings
    // under 12 bytes never reach the fast path that accepts
    // punctuation. `TracerPid` survived extraction from a real ELF while
    // `TracerPid:` did not. Judge the stem instead; the guard keeps this to
    // identifier-shaped labels so arbitrary junk ending in a colon still gets
    // the full analysis on its own merits.
    if let Some(stem) = trimmed.strip_suffix(':')
        && stem.len() >= 3
        && !stem.ends_with(':')
        && stem
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        return is_garbage_with_context(stem, ctx);
    }

    // Fast path: obvious valid strings (kind-aware: skips classify_string re-call)
    if is_fast_path_valid_with_kind(trimmed, len, ctx.kind) {
        return false;
    }

    // Fast path: obvious garbage
    if is_fast_path_garbage(trimmed, s, len) {
        return true;
    }

    // Classifier-produced kinds (URL, Path, Email, …) skip the 20+ IOC
    // pattern sweep — the classifier has already recognised the string as a
    // specific pattern.  Extractor-only labels (Overlay, Section, Import,
    // StackString, …) still run through `is_recognized_ioc` and the
    // statistical checks because those labels don't imply content
    // recognition — they indicate *provenance*.
    if ctx
        .kind
        .is_some_and(crate::types::StringKind::is_classifier_output)
    {
        return false;
    }

    // Known IOC patterns (malware indicators, crypto, auth tokens, etc.)
    if is_recognized_ioc(trimmed, len) {
        return false;
    }

    // Statistical analysis (character distribution, patterns, transitions).
    // `len` stays the byte length although `CharStats` counts characters: a
    // multi-byte character then weighs more in every ratio, which keeps the
    // filter strict on non-ASCII text. The thresholds are tuned to that;
    // character counts admit Unicode-table noise.
    let stats = CharStats::from_str(trimmed);
    is_statistical_garbage(trimmed, len, &stats, ctx)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod dotnet_tests;

#[cfg(test)]
mod label_string_tests;
