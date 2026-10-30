//! Statistical shapes of garbage: short identifiers and words, binary and
//! relocation-table fragments, x86 register saves, excess non-ASCII, and
//! chaotic character-class mixing.

use super::CharStats;

/// Returns true if a very short string (2-6 chars) looks like random binary garbage.
pub(super) fn is_short_identifier_garbage(s: &str, len: usize, stats: &CharStats) -> bool {
    if !(2..=6).contains(&len) {
        return false;
    }
    let is_all_upper = stats.upper == len;
    let is_all_lower = stats.lower == len;
    let is_all_digit = stats.digit == len;
    // Digit + uppercase patterns like "8BIM", "3DES" are valid
    // But single leading 0 or 1 is suspicious (real identifiers use meaningful numbers)
    let has_suspicious_leading_digit = stats.suspicious_leading_digit();
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
    // camelCase identifiers: lowercase first char, exactly one uppercase
    // somewhere in the middle, lowercase tail. At 4+ chars this matches
    // short brand/Hungarian names (`iPad`, `iMac`, `hWnd`, `lpSz`), which a
    // longer floor would filter out with the noise.
    let is_camel_case = len >= 4
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

    // Lowercase strings of four or more letters with no vowel are random.
    if is_all_lower && len >= 4 && stats.vowels == 0 {
        return true;
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
    // Identifier-shaped alphanumeric strings (`iPad`, `hWnd`, `Argon2`) have
    // a same-class run of ≥ 2 even at 4–6 chars and should be kept.
    if looks_like_word_like(s, len, stats) {
        return false;
    }
    // Short multi-word fragments (`JMP +5`) — at least 4 alphanumeric chars
    // with whitespace separating tokens. Garbage like `5c 9` or `VW N` has
    // too few alphanumeric chars to clear this bar.
    if stats.whitespace > 0 && stats.alphanumeric >= 4 {
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
pub(super) fn is_short_binary_garbage(s: &str, len: usize, stats: &CharStats) -> bool {
    if len > 6 {
        return false;
    }
    // All-uppercase + punctuation is usually misaligned binary (`MD%`, `AB#`).
    // Whitespace flips the meaning — `JMP +5` is a disassembly fragment, not
    // noise, so a multi-word string with this shape is kept.
    if stats.upper > 0 && stats.special > 0 && stats.alpha == stats.upper && stats.whitespace == 0 {
        return true;
    }
    if stats.special > 0 && len <= 5 {
        // Function-call shapes (`Run()`, `F(x)`, `fn()`) are meaningful code
        // even at short lengths. Balanced parens accounting for every special
        // char is a strong signal.
        let is_function_call = stats.open_parens > 0
            && stats.open_parens == stats.close_parens
            && stats.open_parens + stats.close_parens == stats.special
            && stats.alphanumeric > 0;
        if is_function_call {
            return false;
        }
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

/// Detect x86-64 register save/restore byte sequences that decoded as
/// printable ASCII when the string scanner read them out of `.text`.
///
/// Function prologues that save callee-saved registers r12-r15 emit
/// `41 54 41 55 41 56 41 57` (`push r12 … push r15`), which the scanner
/// reads as the literal text `ATAUAVAW`.  Epilogue / REX-prefix
/// combinations yield variants like `AVAUATSH`, `AWAVAUATL`, `AXAY`.
/// These are scattered throughout `.text` of any non-trivial binary
/// and dominate the strings list with no analytic value.
///
/// Two-tier detection:
///
/// * **Multi-pair (high confidence):** ≥2 occurrences of byte `0x41`
///   (`A`, the REX.B prefix) followed by a push/pop opcode byte
///   (`0x50-0x5F`, `P-_`).  No real string contains two `A`+pushpop
///   pairs — they only arise from saving / restoring extended r8-r15
///   registers in succession.
/// * **Single-pair + digit at length 4 (medium confidence):** exactly
///   one such pair, has a digit, and every byte is in the x86 opcode
///   range `0x30-0x39 ∪ 0x40-0x5F`.  Catches short fragments like
///   `AWE1`, `7ARI`.  Length cap to 4 keeps common architecture /
///   protocol identifiers (`ARM64`, `AMD64`, `APRIL1`) safe.
///
/// Magic numbers stay safe because they neither contain ≥2 REX-pairs
/// nor (at length 4 with a digit) start at byte 0x41 followed by an
/// opcode byte: `BSJB`, `RIFF`, `RSDS`, `8BIM`, `IDAT`, `IHDR`, `IEND`,
/// `MSCF`, `EXIF`, `DICM`, `COFF`, `CAFE`, `BEEF`, `DEAD`, `FEED` all
/// pass through.
///
/// **Scoping:** the rule is x86-only (REX prefix is x86-64 instruction
/// encoding) and code-only (asm fragments leak from `.text`-like
/// sections, never from `.rodata`/`.data`/`.symtab`/etc.).  A
/// `StringContext` with a non-x86 `arch` or `in_code_section ==
/// Some(false)` skips the rule; unknown (`None`) applies it.
///
/// **Known false positives** (only when the rule actually runs): rare
/// English words / proper nouns that happen to decode as multiple
/// REX-pairs — `ATLAS` (`AT`, `AS`), `AVATAR` (`AV`, `AT`, `AR`).
/// Accepted cost of a byte-level heuristic; a binary that genuinely
/// embeds the literal token `ATLAS` typically does so inside a longer
/// string ("ATLAS connect failed") that the scanner extracts as a
/// single unit, not as the isolated 5-byte word.
pub(super) fn is_x86_save_sequence_fragment(
    s: &str,
    len: usize,
    stats: &CharStats,
    ctx: &crate::types::StringContext,
) -> bool {
    // Architecture scoping: skip when the caller has confirmed the
    // binary is non-x86. `None` means "unknown" — we still run the
    // rule because most binaries today are x86-family.
    if let Some(arch) = ctx.arch
        && !arch.is_x86_family()
    {
        return false;
    }

    // Section scoping: REX-prefix + push/pop bytes only originate in
    // executable sections. When the caller knows the string is NOT in a
    // code section, skip the rule; `None` (unknown) still runs it.
    if ctx.in_code_section == Some(false) {
        return false;
    }

    if !(4..=12).contains(&len) {
        return false;
    }
    // Asm fragments are uppercase + digits, no lowercase / whitespace
    // / punctuation. Real text gets handled elsewhere.
    if stats.lower > 0 || stats.whitespace > 0 || stats.special > 0 {
        return false;
    }

    let bytes = s.as_bytes();

    // Count REX.B + push/pop pairs (`A` = 0x41, push/pop = 0x50-0x5F).
    let rex_pairs = bytes
        .windows(2)
        .filter(|w| w[0] == b'A' && (0x50..=0x5F).contains(&w[1]))
        .count();

    if rex_pairs >= 2 {
        return true;
    }

    if rex_pairs == 1 && len == 4 && stats.digit > 0 {
        let all_in_asm_range = bytes
            .iter()
            .all(|&b| (0x30..=0x39).contains(&b) || (0x40..=0x5F).contains(&b));
        if all_in_asm_range {
            return true;
        }
    }

    false
}

/// Detect PE relocation table patterns like "xçx&xìxÇx..." or "uHu}uQu\uYu0u"
/// where a single lowercase letter repeats frequently with other characters between.
pub(super) fn is_reloc_table_pattern(s: &str, len: usize) -> bool {
    if len < 8 {
        return false;
    }

    // Count frequency of each lowercase letter
    let mut letter_counts = [0u32; 26];
    let mut non_ascii_count = 0usize;
    let mut special_count = 0usize;
    let mut uppercase_count = 0usize;
    let mut digit_count = 0usize;
    let mut char_count = 0usize;

    for c in s.chars() {
        char_count += 1;
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

    if char_count < 6 {
        return false;
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
pub(super) fn has_excess_non_ascii(s: &str, len: usize, stats: &CharStats) -> bool {
    // Bytes, not characters: `len` is a byte length (see is_garbage_with_context).
    let non_ascii_bytes = len - stats.ascii_count;
    if non_ascii_bytes == 0 {
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
        let alpha_percentage = (stats.alpha * 100)
            .checked_div(stats.char_count)
            .unwrap_or(0);
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
        if (alpha_percentage < 90 || has_noise_punct) && non_ascii_bytes * 100 / len > 20 {
            return true;
        }
        if len < 10 && non_ascii_bytes >= 2 {
            return true;
        }

        // Multiple non-ASCII chars in short strings with mixed case is likely garbage
        // e.g., "uDuntßñ6OlÇÕ" - even if they're alphabetic, the pattern is random
        if non_ascii_bytes >= 3 && len < 20 && stats.upper > 0 && stats.lower > 0 {
            // If has digits mixed in, even more suspicious
            if stats.digit > 0 {
                return true;
            }
            // If has 3+ non-ASCII characters in a short string, likely garbage
            // unless it's a recognizable language pattern
            let non_ascii_ratio = non_ascii_bytes * 100 / len;
            if non_ascii_ratio > 25 {
                return true;
            }
        }

        // Repetitive patterns with non-ASCII are likely misaligned binary data
        // e.g., "zçz&zÇzÌzhzµzyz½z{zHz}zQz..." - single char repeated with noise
        if non_ascii_bytes >= 3 && stats.noise_punct >= 3 {
            return true;
        }
    } else {
        // Longer strings (>=30 chars)
        if non_ascii_bytes * 100 / len > 30 {
            return true;
        }
        // Repetitive patterns with non-ASCII and noise punctuation
        if non_ascii_bytes >= 3 && stats.noise_punct >= 3 {
            return true;
        }
    }

    // Detect repetitive single-char patterns like "zçz&zÇz..." where one letter
    // appears very frequently (>30% of chars) with non-ASCII mixed in
    if non_ascii_bytes >= 1 && len >= 10 {
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
    if non_ascii_bytes >= 1 && stats.char_count <= 8 && stats.first_char.is_ascii_digit() {
        return true;
    }

    false
}

/// Returns true if the string is a plausible identifier or word-like sequence
/// that the chaos / mixed-case-digit / short-identifier filters would
/// otherwise reject for having too many class transitions.
///
/// Two shapes are accepted:
/// * **Pure ASCII letters, length ≥ 7** (`AbCdEfGh`, `TheQuickBrownFox`,
///   `PaSsWoRd`): a long sequence of nothing but letters is almost certainly
///   meaningful even when case alternates frequently. Pure all-caps and
///   all-lowercase are handled elsewhere; this arm covers the mixed-case
///   middle ground.
/// * **Pure ASCII alphanumeric with a ≥2-char same-class run** (`MD5Hash`,
///   `Ed25519`, `Curve25519`, `ToInt32`, `Argon2`, `CallByName`, `iPad`,
///   `hWnd`): one same-class run of length ≥ 2 (a multi-letter word, an
///   acronym, or a multi-digit version number) is enough structure to
///   distinguish a real identifier from noise like `A1b2c3` or `AaBbCc`,
///   where every position is in a different class than its neighbour.
pub(super) fn looks_like_word_like(s: &str, len: usize, stats: &CharStats) -> bool {
    if stats.upper == 0 || stats.lower == 0 {
        return false;
    }
    // Pure ASCII letters: 7+ chars is enough signal on its own.
    if len >= 7 && stats.alpha == len && stats.ascii_count == len {
        return true;
    }
    // Pure ASCII alphanumeric — letters and optional digits, nothing else.
    // The class-run check below is too permissive at very short lengths
    // (4-char patterns like `Ilu4` or `cwZd` always hit a 2-char run and are
    // indistinguishable from real garbage), so this arm only fires at 5+.
    if len < 5 || stats.upper + stats.lower + stats.digit != len || stats.ascii_count != len {
        return false;
    }
    let class = |b: u8| -> u8 {
        if b.is_ascii_uppercase() {
            0
        } else if b.is_ascii_lowercase() {
            1
        } else {
            2 // digit
        }
    };
    let bytes = s.as_bytes();
    let mut max_run = 1usize;
    let mut cur_run = 1usize;
    for i in 1..bytes.len() {
        if class(bytes[i]) == class(bytes[i - 1]) {
            cur_run += 1;
            if cur_run > max_run {
                max_run = cur_run;
            }
        } else {
            cur_run = 1;
        }
    }
    max_run >= 2
}

/// Returns true if the string's character class run pattern indicates random/garbage data.
pub(super) fn has_chaotic_char_pattern(s: &str, len: usize, stats: &CharStats) -> bool {
    if len < 6 {
        return false;
    }
    // Identifier-shaped or all-letter strings (CallByName, FooBarBaz,
    // ToInt32, AbCdEfGh) have short Upper/Lower runs by construction and
    // would otherwise trip the run-length and transition-ratio checks below.
    if looks_like_word_like(s, len, stats) {
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

    // Stream the class-run metrics in one pass: every char belongs to exactly one
    // run, and runs are separated by transitions, so there are `transitions + 1`
    // runs covering `char_count` characters (len >= 6 guarantees char_count >= 1).
    let mut transitions = 0usize;
    let mut char_count = 0usize;
    let mut prev_class: Option<CharClass> = None;
    for c in s.chars() {
        let class = if c.is_ascii_uppercase() {
            CharClass::Upper
        } else if c.is_ascii_lowercase() {
            CharClass::Lower
        } else if c.is_ascii_digit() {
            CharClass::Digit
        } else if c.is_whitespace() {
            CharClass::Whitespace
        } else {
            CharClass::Special
        };
        char_count += 1;
        if prev_class.is_some_and(|p| p != class) {
            transitions += 1;
        }
        prev_class = Some(class);
    }

    let num_runs = transitions + 1;
    let avg_run_length = char_count as f32 / num_runs as f32;

    let max_class_count = stats
        .upper
        .max(stats.lower)
        .max(stats.digit)
        .max(stats.special);
    let is_mostly_one_class = max_class_count * 100 / len > 70;

    let alphanumeric = stats.alphanumeric;
    let lower = stats.lower;
    let special = stats.special;
    let digit = stats.digit;

    let looks_like_path = (s.contains('/') || s.contains('\\'))
        && alphanumeric >= 3
        && special * 100 / len <= 30
        && (alphanumeric == 0 || lower * 100 / alphanumeric >= 40)
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
        && s.split('.').filter(|seg| !seg.is_empty()).count() >= 2
        && special * 100 / len <= 20;
    let looks_like_version = (s.starts_with("go") || s.starts_with('v') || s.starts_with('V'))
        && s.contains('.')
        && digit > 0;
    let looks_like_base64 = len >= 16
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
    // Multi-word fragments (assembly output like `MOV EAX, 0`, formatted
    // text, list literals) have whitespace separating meaningful tokens.
    // Their Upper/Lower/Special run pattern looks "chaotic" by the
    // class-transition metric, but the whitespace is itself the structure.
    // Guards: all-ASCII (excludes non-ASCII noise like `` `C dJe`eN{Û ``) and
    // at most one noise-punct char (excludes random punctuation like
    // `ZFI7% eE;*\\Y` that happens to contain one space).
    let looks_like_multi_word = stats.whitespace > 0
        && alphanumeric >= 4
        && stats.ascii_count == len
        && stats.noise_punct <= 1;
    let is_structured_pattern = looks_like_path
        || looks_like_url
        || looks_like_domain
        || looks_like_version
        || looks_like_base64
        || looks_like_format_string
        || looks_like_multi_word;

    if !is_mostly_one_class && !is_structured_pattern {
        if transitions * 100 / len > 60 {
            return true;
        }
        if avg_run_length < 2.0 && len >= 8 {
            return true;
        }
        if len <= 7 && avg_run_length < 1.5 && transitions >= 4 {
            return true;
        }
    }
    false
}

/// Whether a string of at most ten characters fails to look like a word,
/// code or number: no vowels among lowercase and digits (`gvjc54`), rare
/// shapes of short lowercase words (`oujr`, `kmnro`), doubled endings in short
/// uppercase (`ZYII`), digit-suffixed fragments (`kmo8`), repeated digits
/// (`3333`), noise punctuation, unbalanced brackets, and case-and-digit mixes
/// that are neither versions nor word-like (`A1b2c3`).
pub(super) fn is_short_word_garbage(s: &str, len: usize, stats: &CharStats) -> bool {
    // Short strings (4-10 chars) with mixed case and digits that don't look like identifiers
    // e.g., "gvjc54" - lowercase + digit but no vowels and doesn't follow naming conventions
    if (4..=10).contains(&len) && stats.lower > 0 && stats.digit > 0 && stats.upper == 0 {
        // If no vowels and has digits embedded in lowercase, likely garbage
        if stats.vowels == 0 && stats.lower >= 3 && stats.digit >= 1 {
            return true;
        }
    }

    // Short all-lowercase strings (4-5 chars) that don't look like real words
    // e.g., "oujr", "omor", "kmnro" - unusual phonotactic patterns
    if (4..=5).contains(&len) && stats.lower == len && stats.digit == 0 && stats.upper == 0 {
        // At most one vowel: likely random, unless a common word
        if stats.vowels <= 1 {
            let known_short = [
                "type", "func", "test", "temp", "sync", "async", "null", "char", "path", "text",
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
        // If has 0-1 vowels and ends with digit, likely garbage
        if stats.vowels <= 1 && stats.last_char.is_ascii_digit() {
            // Whitelist known patterns (encoding, crypto, architecture suffixes)
            if !matches!(s, "sha1" | "utf8") {
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

    // Short strings with noise punctuation are garbage — unless the string
    // also contains whitespace, in which case it's likely a multi-word
    // fragment (assembly output like `MOV EAX, 0`, list literals, formatted
    // text) where the punctuation is structural rather than noise.
    if len <= 10 && stats.noise_punct > 0 && stats.whitespace == 0 {
        return true;
    }

    if len <= 4 && stats.alphanumeric < len / 2 {
        return true;
    }

    if len <= 8 && (stats.open_parens != stats.close_parens || stats.quotes == 1) {
        return true;
    }

    // Medium-length strings with mixed case and digits are noise from compressed data
    if (5..=10).contains(&len) && stats.digit > 0 && stats.upper > 0 && stats.lower > 0 {
        let looks_like_version =
            s.starts_with("go") || s.starts_with('v') || s.starts_with('V') || s.contains('.');
        // Crypto/algorithm names (`MD5Hash`, `SHA256Init`, `Curve25519`,
        // `Ed25519`, `ToInt32`) all match this rule but are valid identifiers.
        // `looks_like_word_like` keeps them while still rejecting random
        // patterns like `A1b2c3` where no class has a ≥2-char run.
        if !looks_like_version && !looks_like_word_like(s, len, stats) {
            return true;
        }
    }

    false
}

/// Perform statistical analysis to determine if string is garbage.
///
/// This is the fallback when fast paths and IOC recognition don't apply.
pub(super) fn is_statistical_garbage(
    s: &str,
    len: usize,
    stats: &CharStats,
    ctx: &crate::types::StringContext,
) -> bool {
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

    if is_short_word_garbage(s, len, stats) {
        return true;
    }

    // Strings with multiple consecutive quotes are likely misaligned data
    if s.contains("\"\"") || s.contains("'''") {
        return true;
    }

    // Pattern: ends with backtick + single letter (Go misaligned reads)
    let bytes = s.as_bytes();
    if len >= 2
        && let Some(idx) = bytes.iter().rposition(|&b| b.is_ascii_alphabetic())
        && idx > 0
        && bytes[idx - 1] == b'`'
    {
        return true;
    }

    if is_short_binary_garbage(s, len, stats) {
        return true;
    }

    if is_x86_save_sequence_fragment(s, len, stats, ctx) {
        return true;
    }

    // Consistent-case alphanumeric patterns (7-8 chars) are valid identifiers
    // e.g., "UTF16LE", "BASE64" - patterns like encoding names, algorithms
    // Reject alternating patterns like "0a1b2c3d" (too many transitions)
    // Reject single leading 0 or 1 (unusual in real identifiers)
    // (4-6 char patterns are handled by is_short_identifier_garbage)
    let has_suspicious_leading_digit = stats.suspicious_leading_digit();
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

    if len >= 6
        && stats.digit > 0
        && stats.alpha > 0
        && stats.alternations >= 4
        && stats.alternations * 2 >= len
    {
        return true;
    }

    if stats.char_count > 6 && stats.alphanumeric * 100 / stats.char_count < 30 {
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

    // More than a third whitespace is padding or layout, not text.
    if stats.whitespace > 0 && stats.whitespace * 100 / len > 33 {
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
