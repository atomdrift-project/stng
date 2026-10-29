//! Whether decoded text is meaningful: common words, file extensions, and
//! letter statistics shaped like English (or alphabetic non-ASCII text).

use aho_corasick::AhoCorasick;
use std::sync::LazyLock;

/// Common English words and computing terms that indicate legitimate text.
/// Used to boost confidence that decoded text is real vs garbage.
pub(super) const COMMON_WORDS: &[&str] = &[
    // Very common English words (3-5 letters)
    "the",
    "and",
    "for",
    "are",
    "but",
    "not",
    "you",
    "all",
    "can",
    "her",
    "was",
    "one",
    "our",
    "out",
    "day",
    "get",
    "has",
    "him",
    "his",
    "how",
    "man",
    "new",
    "now",
    "old",
    "see",
    "two",
    "way",
    "who",
    "boy",
    "did",
    "its",
    "let",
    "put",
    "say",
    "she",
    "too",
    "use",
    "your",
    "into",
    "just",
    "like",
    "make",
    "many",
    "over",
    "such",
    "take",
    "than",
    "them",
    "then",
    "these",
    "think",
    "through",
    "time",
    "very",
    "when",
    "work",
    "would",
    // System/Path words
    "Users",
    "Library",
    "Application",
    "Support",
    "Local",
    "Storage",
    "AppData",
    "Program",
    "Files",
    "System",
    "Windows",
    "Containers",
    "Cache",
    "Temp",
    "private",
    "public",
    "Desktop",
    "Documents",
    "Downloads",
    "Pictures",
    "Music",
    "Videos",
    // Common file extensions (targets for exfiltration)
    "plist",
    "json",
    "conf",
    "config",
    "sqlite",
    "wallet",
    "keystore",
    "screenshot",
    "Bookmarks",
    "Cookies",
    "History",
    "Preferences",
    // Application names
    "Safari",
    "Chrome",
    "Firefox",
    "Telegram",
    "Discord",
    "Slack",
    // Crypto/Security (exfiltration targets)
    "Wallet",
    "Wallets",
    "Ethereum",
    "Exodus",
    "Electrum",
    "Monero",
    "Bitcoin",
    "password",
    "passwd",
    "token",
    "session",
    "cookie",
    "credential",
    "secret",
];

/// Case-insensitive automaton for [`COMMON_WORDS`].
#[allow(clippy::expect_used)]
pub(super) static COMMON_WORDS_AC: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(COMMON_WORDS)
        .expect("static patterns")
});

/// Automaton for common file extensions.
#[allow(clippy::expect_used)]
pub(super) static FILE_EXTENSION_AC: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::new([
        ".plist",
        ".json",
        ".conf",
        ".sqlite",
        ".jpg",
        ".png",
        ".txt",
        ".log",
        ".xml",
        ".db",
        ".dat",
        ".wallet",
        ".keystore",
        ".dll",
        ".exe",
    ])
    .expect("static patterns")
});

/// Count how many distinct COMMON_WORDS appear in `s` (matched case-insensitively).
/// Stops counting after reaching `limit` to allow early exits in callers.
pub(crate) fn count_common_word_matches(s: &str, limit: usize) -> usize {
    let ac = &*COMMON_WORDS_AC;
    let mut matched = [false; COMMON_WORDS.len()];
    let mut count = 0;
    for mat in ac.find_iter(s) {
        let pid = mat.pattern().as_usize();
        if !matched[pid] {
            matched[pid] = true;
            count += 1;
            if count >= limit {
                break;
            }
        }
    }
    count
}

/// Per-class character counts. Case and vowels are tracked for ASCII
/// letters only: they are English-specific.
#[derive(Clone, Copy, Default)]
pub(super) struct Letters {
    alpha: usize,
    digit: usize,
    vowel: usize,
    upper: usize,
    lower: usize,
    punct: usize,
    spaces: usize,
    has_non_ascii: bool,
}

impl Letters {
    fn count(s: &str) -> Self {
        let mut n = Self::default();
        for c in s.chars() {
            if c.is_alphabetic() {
                n.alpha += 1;
                n.has_non_ascii |= !c.is_ascii();
                if c.is_ascii_uppercase() {
                    n.upper += 1;
                } else if c.is_ascii_lowercase() {
                    n.lower += 1;
                }
                if matches!(c.to_ascii_lowercase(), 'a' | 'e' | 'i' | 'o' | 'u') {
                    n.vowel += 1;
                }
            } else if c.is_numeric() {
                n.digit += 1;
            } else if c.is_ascii_punctuation() {
                n.punct += 1;
            } else if c == ' ' {
                n.spaces += 1;
            }
        }
        n
    }
}

/// Whether ASCII text with five or more letters is shaped like English: a
/// vowel ratio of 12-65% (English runs 35-45%), no run of more than six
/// consonants, case that is consistent, Title or camelCase, and not a bare
/// run of capitals or of vowelless lowercase.
pub(super) fn english_shaped(s: &str, n: &Letters) -> bool {
    let Letters {
        alpha,
        digit,
        vowel,
        upper,
        lower,
        punct,
        spaces,
        ..
    } = *n;
    // English-specific analysis for ASCII text
    let vowel_ratio = (vowel as u64 * 100) / alpha as u64;

    // English text typically has 35-45% vowels
    // Be lenient: accept 12-65%
    if !(12..=65).contains(&vowel_ratio) {
        return false;
    }

    // Check for word-like structure (not random letters)
    // Count consonant clusters (more than 4 consecutive consonants is suspicious)
    let chars: Vec<char> = s.chars().collect();
    let mut max_consonant_run = 0;
    let mut consonant_run = 0;

    for &c in &chars {
        if c.is_ascii_alphabetic() && !matches!(c.to_ascii_lowercase(), 'a' | 'e' | 'i' | 'o' | 'u')
        {
            consonant_run += 1;
            max_consonant_run = max_consonant_run.max(consonant_run);
        } else {
            consonant_run = 0;
        }
    }

    // English rarely has >5 consecutive consonants (e.g., "catchphrase" has 4)
    if max_consonant_run > 6 {
        return false;
    }

    // Check case consistency (Title Case, lowercase, UPPERCASE, or camelCase are OK)
    // Random case mixing like "rAnDoM" is suspicious
    if alpha > 8 && upper > 0 && lower > 0 {
        // If we have mixed case, check if it's structured
        let has_spaces_or_separators =
            spaces > 0 || s.contains('/') || s.contains('.') || s.contains('_');

        // Title Case or camelCase with separators is fine
        // Random mixing without structure is bad
        if !has_spaces_or_separators {
            // Check if it's camelCase (starts lowercase, has capitals mid-word)
            let starts_lower = chars[0].is_ascii_lowercase();
            let has_mid_caps = chars
                .windows(2)
                .any(|w| w[0].is_ascii_lowercase() && w[1].is_ascii_uppercase());

            if !starts_lower && !has_mid_caps {
                // Not Title, not camel, not consistent - likely garbage
                let upper_ratio = (upper as u64 * 100) / alpha as u64;
                // Reject if 20-80% uppercase (random mixing)
                if (20..=80).contains(&upper_ratio) {
                    return false;
                }
            }
        }
    }

    // Reject all-caps with no punctuation/digits (likely garbage like "ABCDEFGH")
    if upper > 0 && lower == 0 && alpha > 6 && punct == 0 && digit == 0 && spaces == 0 {
        return false;
    }

    // Reject all-lowercase with no vowels (like "bcdfghjk")
    if lower > 0 && upper == 0 && vowel == 0 && alpha > 4 {
        return false;
    }
    true
}

/// Check if a string looks like well-formed text using linguistic patterns.
/// This recognizes legitimate English/computing text without hardcoded keyword lists.
pub(crate) fn is_meaningful_string(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }

    let len = s.len();
    // For ASCII strings (the common case), len == char_count. Only count chars for Unicode.
    let char_count = if s.is_ascii() { len } else { s.chars().count() };
    let n = Letters::count(s);
    let Letters {
        alpha,
        digit,
        vowel,
        has_non_ascii,
        ..
    } = n;

    let alnum = alpha + digit;

    // Must be at least 50% alphanumeric (relaxed from 60% to catch "Bookmarks.plist")
    // Use character count for proper Unicode support
    if char_count > 0 && (alnum as u64 * 100) / (char_count as u64) < 50 {
        return false;
    }

    // Check for common file extensions (exfiltration targets)
    let has_file_extension = FILE_EXTENSION_AC.is_match(s);

    if has_file_extension {
        // File paths are high value - just check basic quality
        // For non-ASCII text (e.g., Russian folder names), vowel count is 0, so skip that check
        // For DLL/EXE names like "bcrypt.dll", vowel count can be 0 - accept anyway
        if alpha >= 3 {
            return true;
        }
    }

    // Check if string contains common words (case-insensitive matching via AhoCorasick).
    // We only need to know if count is 0, 1, or ≥2 so we stop scanning at 2.
    let word_matches = count_common_word_matches(s, 2);

    // Strong signal: 2+ common words = likely legitimate
    if word_matches >= 2 {
        return true;
    }

    // Medium signal: 1 common word + reasonable quality
    if word_matches >= 1 && alpha >= 5 {
        // For non-ASCII text, skip vowel check (vowel is 0 for Russian/Chinese/etc.)
        if has_non_ascii {
            return true;
        }
        let vowel_ratio = if alpha > 0 {
            (vowel as u64 * 100) / alpha as u64
        } else {
            0
        };
        // Very lenient with common words present
        if vowel_ratio >= 8 {
            return true;
        }
    }

    // Linguistic analysis for strings without known words
    // ONLY apply English-specific checks (vowels, consonants) to ASCII text
    if alpha >= 5 {
        // For non-ASCII text (Russian, Chinese, Arabic, etc.), skip English-specific analysis
        // Just rely on the alphanumeric percentage check above (>=50%)
        if has_non_ascii {
            // Non-ASCII alphabetic text passed the alphanumeric check, accept it
            return true;
        }

        if !english_shaped(s, &n) {
            return false;
        }
    }

    // Check character diversity (reject repetitive strings like "aaaaaaa")
    let unique: std::collections::HashSet<char> = s.chars().collect();
    if unique.len() * 3 < len && len > 10 {
        return false;
    }

    // Reject strings with too many backslashes (path separators are OK, but not excessive)
    let backslash_count = s.chars().filter(|&c| c == '\\').count();
    if backslash_count > 3 && backslash_count * 4 > len {
        return false;
    }

    true
}
