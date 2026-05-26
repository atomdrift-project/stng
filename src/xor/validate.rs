//! String validation helpers for XOR-decoded strings.
//!
//! Pure predicate functions that determine whether a decoded string is
//! meaningful, valid, or matches known patterns (IPs, ports, locale codes,
//! paths). Shared by the classify and scan submodules.

use aho_corasick::AhoCorasick;
use std::sync::OnceLock;

pub(crate) fn is_printable_char(b: u8) -> bool {
    // Accept ASCII printable characters
    if b.is_ascii_graphic() || b == b' ' || b == b'\t' {
        return true;
    }
    // Accept UTF-8 continuation bytes (0x80-0xBF) and UTF-8 start bytes (0xC0-0xF7)
    // This allows Unicode text (Russian, Chinese, Arabic, etc.) to pass through
    // Invalid UTF-8 will be caught later by String::from_utf8()
    (0x80..=0xF7).contains(&b)
}

/// Check if a decoded XOR string is valid (not garbage with unusual punctuation).
/// Returns true if the string passes basic sanity checks.
pub(crate) fn is_valid_xor_string(s: &str) -> bool {
    // Check for specific malicious indicators (not just any system path)
    // Uses cached case-insensitive Aho-Corasick automata — no allocation
    let has_shell_command = shell_command_automaton().is_match(s);

    let has_suspicious_path = suspicious_path_automaton().is_match(s)
        || s.contains("/tmp/") && (s.contains(".sh") || s.contains("payload"));

    // Windows API names dynamically resolved via GetProcAddress to evade static analysis.
    // These have long consonant runs (e.g., "BCryptS..." = 7 consonsants) that would
    // otherwise fail the is_meaningful_string linguistic check.
    let has_win_api = win_api_automaton().is_match(s);

    let has_suspicious_url = s.contains("://") && !s.contains("apple.com");

    // Check for IP addresses (likely C2 infrastructure) - pattern: N.N.N.N
    let has_ip = memchr::memchr_iter(b'.', s.as_bytes()).count() == 3
        && s.split('.')
            .filter(|seg| {
                !seg.is_empty() && seg.len() <= 3 && seg.bytes().all(|b| b.is_ascii_digit())
            })
            .count()
            == 4;

    // Check for unicode escape sequences (legitimate obfuscation)
    let has_unicode_escapes = s.contains("\\x") || s.contains("\\u");

    // Check for shell heredoc patterns
    let has_heredoc =
        s.contains("<<") && (s.contains("EOF") || s.contains("EOD") || s.contains("END"));

    // Count truly bad punctuation (control chars and unusual symbols)
    // Allow newlines in heredocs
    let control_chars = s
        .chars()
        .filter(|&c| {
            if has_heredoc && c == '\n' {
                return false;
            }
            matches!(c, '\x00'..='\x1f' | '\x7f')
        })
        .count();

    // If string has SPECIFIC malicious indicators OR encoding, allow them
    // This bypass ensures high-value IOCs pass validation even with unusual chars
    if has_shell_command
        || has_suspicious_path
        || has_win_api
        || has_suspicious_url
        || has_ip
        || has_unicode_escapes
        || has_heredoc
    {
        // Only reject if mostly control characters (> 30%)
        return control_chars * 3 < s.len();
    }

    // For all other strings, apply strict filtering
    // But allow certain metacharacters in specific contexts
    let has_xml_tags = s.starts_with('<') && s.ends_with('>') && !s.contains(' ');
    let has_shell_metacharacters = s.contains('<') || s.contains('>') || s.contains('|');
    let looks_like_shell = has_shell_metacharacters
        && s.len() >= 15
        && ((s.contains("EOF") || s.contains("END"))
            || (s.contains(">>") || s.contains("<<"))
            || (s.contains("/dev/") && s.contains('>'))
            || (s.contains("2>&1") || s.contains("1>&2")));

    let bad_punct_count = s
        .chars()
        .filter(|&c| {
            // Allow <, > for XML tags or shell commands
            if (has_xml_tags || looks_like_shell) && matches!(c, '<' | '>') {
                return false;
            }
            // Allow | for shell commands
            if looks_like_shell && c == '|' {
                return false;
            }
            matches!(
                c,
                '^' | '~' | '`' | '[' | ']' | '{' | '}' | '<' | '>' | '|' | '\x00'
                    ..='\x1f' | '\x7f' // Control characters
            )
        })
        .count();

    // Count "questionable" punctuation that can appear in valid strings
    let questionable_punct = s
        .chars()
        .filter(|&c| matches!(c, '$' | '#' | '@' | '!' | '"' | '\'' | '\\'))
        .count();

    // Count additional special chars that often indicate garbage (but can be legitimate)
    let additional_special = s
        .chars()
        .filter(|&c| matches!(c, ':' | '+' | '=' | '*' | '&' | '%'))
        .count();

    // Reject if we have ANY bad punctuation characters
    if bad_punct_count > 0 {
        return false;
    }

    // Also reject strings with excessive "questionable" punctuation
    // Allow max 2 questionable punctuation chars, or 20% of string length
    if questionable_punct > 2 && questionable_punct * 5 > s.len() {
        return false;
    }

    // Reject if total special character density is too high (likely garbage)
    let total_special = questionable_punct + additional_special;
    if !s.is_empty() && (total_special as u64 * 100) / s.len() as u64 > 40 {
        return false;
    }

    // Always check meaningfulness for non-IOC strings
    // This catches garbage fragments like " j3/ N1 9-P" that have few special chars
    // but lack linguistic patterns (vowels, word structure, etc.)
    if !is_meaningful_string(s) {
        return false;
    }

    // Reject partial XOR decodes that start like known patterns but diverge
    // (e.g., "%UsERP4NFINE%\" instead of "%USERPROFILE%\")
    if is_partial_xor_decode(s) {
        return false;
    }

    true
}

/// Common English words and computing terms that indicate legitimate text.
/// Used to boost confidence that decoded text is real vs garbage.
const COMMON_WORDS: &[&str] = &[
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

/// Cached AhoCorasick automaton for COMMON_WORDS (all patterns stored lowercase).
#[allow(clippy::expect_used)]
pub(crate) fn get_common_words_automaton() -> &'static AhoCorasick {
    static CACHE: OnceLock<AhoCorasick> = OnceLock::new();
    CACHE.get_or_init(|| {
        let patterns: Vec<String> = COMMON_WORDS
            .iter()
            .map(|w| w.to_ascii_lowercase())
            .collect();
        AhoCorasick::new(&patterns).expect("static patterns")
    })
}

/// Cached automaton for shell command indicators (case-insensitive).
#[allow(clippy::expect_used)]
fn shell_command_automaton() -> &'static AhoCorasick {
    static CACHE: OnceLock<AhoCorasick> = OnceLock::new();
    CACHE.get_or_init(|| {
        AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build([
                "osascript",
                "screencapture",
                "bash ",
                "sh -",
                "curl ",
                "wget ",
                "chmod ",
                "python ",
                "perl ",
                "ruby ",
                "/bin/",
                "sleep ",
                " rm ",
                "rm -",
                "echo ",
                "kill ",
                "ps ",
                "powershell",
                "cmd.exe",
                "xattr",
            ])
            .expect("static patterns")
    })
}

/// Cached automaton for suspicious path indicators (case-insensitive).
#[allow(clippy::expect_used)]
fn suspicious_path_automaton() -> &'static AhoCorasick {
    static CACHE: OnceLock<AhoCorasick> = OnceLock::new();
    CACHE.get_or_init(|| {
        AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build([
                "ethereum/keystore",
                "/etc/passwd",
                "/etc/shadow",
                "appdata",
                "programdata",
                "launchagents",
                "launchdaemons",
                // Linux rootkit indicators
                "/proc/net/",
                "ld.so.preload",
                "/proc/self/",
            ])
            .expect("static patterns")
    })
}

/// Cached automaton for Windows API names resolved via GetProcAddress (dynamic loading).
/// These indicate covert capability loading and commonly fail linguistic checks due to
/// long consonant runs (e.g., "BCryptS..." = 7 consecutive consonants).
#[allow(clippy::expect_used)]
fn win_api_automaton() -> &'static AhoCorasick {
    static CACHE: OnceLock<AhoCorasick> = OnceLock::new();
    CACHE.get_or_init(|| {
        AhoCorasick::new([
            // Windows crypto API (AES-CBC decryption capability)
            "BCrypt",
            // Windows process injection / execution APIs
            "CreateProcess",
            "VirtualAlloc",
            "WriteProcessMemory",
            "ReadProcessMemory",
            "GetProcAddress",
            "LoadLibrary",
            "FindWindow",
            "GetWindow",
            "ShowWindow",
            // Registry / persistence APIs
            "RegOpenKey",
            "RegSetValue",
            "RegCreateKey",
        ])
        .expect("static patterns")
    })
}

/// Cached automaton for common file extensions.
#[allow(clippy::expect_used)]
fn file_extension_automaton() -> &'static AhoCorasick {
    static CACHE: OnceLock<AhoCorasick> = OnceLock::new();
    CACHE.get_or_init(|| {
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
    })
}

/// Count how many distinct COMMON_WORDS appear in `lower_s` (already lowercased).
/// Stops counting after reaching `limit` to allow early exits in callers.
pub(crate) fn count_common_word_matches(lower_s: &str, limit: usize) -> usize {
    let ac = get_common_words_automaton();
    let mut matched = [false; COMMON_WORDS.len()];
    let mut count = 0;
    for mat in ac.find_iter(lower_s) {
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

/// Check if a string looks like well-formed text using linguistic patterns.
/// This recognizes legitimate English/computing text without hardcoded keyword lists.
pub(crate) fn is_meaningful_string(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }

    let len = s.len();
    // For ASCII strings (the common case), len == char_count. Only count chars for Unicode.
    let char_count = if s.is_ascii() { len } else { s.chars().count() };
    let mut alpha = 0usize;
    let mut digit = 0usize;
    let mut vowel = 0usize;
    let mut upper = 0usize;
    let mut lower = 0usize;
    let mut punct = 0usize;
    let mut spaces = 0usize;
    let mut has_non_ascii = false;

    for c in s.chars() {
        // Support Unicode alphabetic characters (Cyrillic, Chinese, Arabic, etc.)
        if c.is_alphabetic() {
            alpha += 1;
            if !c.is_ascii() {
                has_non_ascii = true;
            }
            // Only track case and vowels for ASCII (English-specific)
            if c.is_ascii_alphabetic() {
                if c.is_ascii_uppercase() {
                    upper += 1;
                } else {
                    lower += 1;
                }
                if matches!(c.to_ascii_lowercase(), 'a' | 'e' | 'i' | 'o' | 'u') {
                    vowel += 1;
                }
            }
        } else if c.is_numeric() {
            digit += 1;
        } else if c.is_ascii_punctuation() {
            punct += 1;
        } else if c == ' ' {
            spaces += 1;
        }
    }

    let alnum = alpha + digit;

    // Must be at least 50% alphanumeric (relaxed from 60% to catch "Bookmarks.plist")
    // Use character count for proper Unicode support
    if char_count > 0 && (alnum as u64 * 100) / (char_count as u64) < 50 {
        return false;
    }

    // Check for common file extensions (exfiltration targets)
    let has_file_extension = file_extension_automaton().is_match(s);

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
    let lower_s = s.to_ascii_lowercase();
    let word_matches = count_common_word_matches(&lower_s, 2);

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
            if c.is_ascii_alphabetic()
                && !matches!(c.to_ascii_lowercase(), 'a' | 'e' | 'i' | 'o' | 'u')
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

pub(crate) fn is_valid_ip(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }

    let mut octets: Vec<u16> = Vec::with_capacity(4);
    for part in &parts {
        match part.parse::<u16>() {
            Ok(n) if n <= 255 => octets.push(n),
            _ => return false,
        }
        // Reject leading zeros (e.g., "01.02.03.04")
        if part.len() > 1 && part.starts_with('0') {
            return false;
        }
    }

    // Reject x.0.0.0 patterns
    if octets.len() == 4 && octets[1] == 0 && octets[2] == 0 && octets[3] == 0 {
        return false;
    }

    // Reject localhost and reserved
    if s == "127.0.0.1" || s == "0.0.0.0" || s.starts_with("127.") {
        return false;
    }

    // Reject if first octet is 0 (0.x.x.x is not valid for hosts)
    if octets[0] == 0 {
        return false;
    }

    // Reject if first octet < 10 (very low octets are usually XOR artifacts, not real C2)
    if octets[0] < 10 {
        return false;
    }

    // Reject if all four octets are the same (clear XOR artifact like 182.182.182.182)
    if octets[0] == octets[1] && octets[1] == octets[2] && octets[2] == octets[3] {
        return false;
    }

    // Reject if .0 appears in first or last octet (only allow in middle two)
    if octets[0] == 0 || octets[3] == 0 {
        return false;
    }

    // Reject version-like patterns where last three octets are all small (< 10)
    // e.g., 30.2.2.4, 33.4.2.2 - these look like version numbers, not real IPs
    // But exclude private IP ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
    let is_private = octets[0] == 10
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 168);
    if !is_private && octets[1] < 10 && octets[2] < 10 && octets[3] < 10 {
        return false;
    }

    true
}

pub(crate) fn is_valid_port(s: &str) -> bool {
    matches!(s.parse::<u32>(), Ok(n) if n > 0 && n <= 65535)
}

/// Well-known UNIX/macOS/Windows path prefixes.
const KNOWN_PATH_PREFIXES: &[&str] = &[
    // UNIX/Linux common paths
    "/bin/",
    "/usr/bin/",
    "/usr/local/",
    "/etc/",
    "/var/",
    "/tmp/",
    "/dev/",
    "/proc/",
    "/sys/",
    "/opt/",
    "/home/",
    "/root/",
    // macOS specific
    "/Library/",
    "/Users/",
    "/Applications/",
    "/System/Library/",
    "/private/",
    // Windows paths
    "C:\\Windows\\",
    "C:\\Program Files\\",
    "C:\\Users\\",
    "C:\\ProgramData\\",
    "C:\\Temp\\",
    "%APPDATA%",
    "%USERPROFILE%",
];

/// Check if a string is a locale identifier (e.g., en-US, ru-RU, zh-CN).
pub(crate) fn is_locale_string(s: &str) -> bool {
    let s = s.trim();
    if s.len() < 5 || s.len() > 6 {
        return false;
    }

    let chars: Vec<char> = s.chars().collect();
    if chars.len() < 5 {
        return false;
    }

    // Pattern: 2-3 lowercase + underscore/hyphen + 2-3 uppercase
    // en-US, ru-RU, zh-CN, eng-US, etc.
    let has_separator = chars[2] == '_'
        || chars[2] == '-'
        || (chars.len() == 6 && (chars[3] == '_' || chars[3] == '-'));

    if !has_separator {
        return false;
    }

    let sep_idx = if chars[2] == '_' || chars[2] == '-' {
        2
    } else {
        3
    };

    // Check lowercase before separator
    for &ch in chars.iter().take(sep_idx) {
        if !ch.is_ascii_lowercase() {
            return false;
        }
    }

    // Check uppercase after separator
    for &ch in chars.iter().skip(sep_idx + 1) {
        if !ch.is_ascii_uppercase() {
            return false;
        }
    }

    true
}

/// Check if a path starts with a known OS path prefix.
pub(crate) fn has_known_path_prefix(path: &str) -> bool {
    for prefix in KNOWN_PATH_PREFIXES {
        if path.starts_with(prefix) {
            return true;
        }
    }

    // Also check for relative paths
    // ./ with any name (common for malware: ./malware, ./payload, etc.)
    // ../ needs at least 2 levels
    if let Some(after_dot_slash) = path.strip_prefix("./") {
        // Must have some content after ./ and the first character must be alphanumeric
        if !after_dot_slash.is_empty()
            && let Some(first_char) = after_dot_slash.chars().next()
            && first_char.is_ascii_alphanumeric()
        {
            return true;
        }
    }

    if path.starts_with("../") {
        return path.matches('/').count() >= 2; // At least 2 levels
    }

    false
}

/// Known plaintext patterns that malware commonly XOR-encodes.
/// Used to detect partial/incorrect XOR decodes.
///
/// These should be COMPLETE patterns (not prefixes) that, when partially decoded,
/// indicate a wrong XOR key. Protocol prefixes like "http://" are intentionally
/// excluded since they naturally have content after them.
const KNOWN_XOR_PLAINTEXTS: &[&str] = &[
    "%USERPROFILE%",
    "%APPDATA%",
    "%LOCALAPPDATA%",
    "%TEMP%",
    "%PROGRAMDATA%",
    "%SYSTEMROOT%",
    "HKEY_LOCAL_MACHINE",
    "HKEY_CURRENT_USER",
];

/// Check if a string is a "near-miss" XOR decode - starts like a known pattern
/// but diverges into garbage. These are usually wrong-key decodes and should be rejected.
///
/// Returns true if the string looks like a failed/partial XOR decode.
pub(crate) fn is_partial_xor_decode(s: &str) -> bool {
    // Only check ASCII strings - non-ASCII can't be these patterns
    if !s.is_ascii() {
        return false;
    }

    // Only check strings that could be partial matches
    if s.len() < 6 {
        return false;
    }

    for pattern in KNOWN_XOR_PLAINTEXTS {
        // Check if string starts similarly to a known pattern
        let prefix_len = pattern.len().min(5).min(s.len());
        let pattern_chars: Vec<char> = pattern.chars().take(prefix_len).collect();
        let string_chars: Vec<char> = s.chars().take(prefix_len).collect();

        // Count matching characters at the start (case-insensitive)
        let matching_chars = pattern_chars
            .iter()
            .zip(string_chars.iter())
            .filter(|(a, b)| a.eq_ignore_ascii_case(b))
            .count();

        // If at least 60% of prefix matches but the full pattern doesn't match
        if matching_chars >= (prefix_len * 3 / 5) {
            // Check if the full pattern matches
            if s.len() >= pattern.len() {
                let pattern_lower = pattern.to_ascii_lowercase();
                let s_lower = s.to_ascii_lowercase();
                if s_lower.starts_with(&pattern_lower) {
                    // Full match - not a partial decode
                    continue;
                }
            }

            // Partial match - count how many characters diverge
            let mut divergence_start = 0;
            let mut divergence_count = 0;

            for (i, (pc, sc)) in pattern.chars().zip(s.chars()).enumerate() {
                if !pc.eq_ignore_ascii_case(&sc) {
                    if divergence_start == 0 {
                        divergence_start = i;
                    }
                    divergence_count += 1;
                }
            }

            // If we have matches at the start but significant divergence after
            if divergence_start > 0 && divergence_start <= 8 && divergence_count >= 2 {
                // Count character type mismatches: digits where letters expected, etc.
                let mut type_mismatches = 0;
                let mut wrong_letter_count = 0;

                for (i, (pc, sc)) in pattern.chars().zip(s.chars()).enumerate() {
                    if i >= divergence_start {
                        // If pattern has letter but string has non-letter (or vice versa)
                        if pc.is_ascii_alphabetic() && !sc.is_ascii_alphabetic() {
                            type_mismatches += 1;
                        }
                        // Count letters that are wrong (different letter, not just case)
                        if pc.is_ascii_alphabetic()
                            && sc.is_ascii_alphabetic()
                            && !pc.eq_ignore_ascii_case(&sc)
                        {
                            wrong_letter_count += 1;
                        }
                    }
                }

                // If we have type mismatches (digit where letter expected), it's bad
                if type_mismatches >= 1 {
                    return true;
                }

                // If multiple wrong letters in a row, likely bad decode
                if wrong_letter_count >= 3 {
                    return true;
                }

                // Get the divergent part for additional checks
                let divergent_part: String = s.chars().skip(divergence_start).collect();

                // Check if the divergent part contains garbage characters
                let garbage_chars = divergent_part
                    .chars()
                    .filter(|c| {
                        !c.is_ascii_alphanumeric()
                            && !matches!(*c, '\\' | '/' | ':' | '.' | '_' | '-' | '%')
                    })
                    .count();

                let div_char_count = divergent_part.chars().count();

                // If any garbage in what should be clean path-like content
                if div_char_count > 2 && garbage_chars >= 1 {
                    return true;
                }

                // Check for case inconsistency (mixed case in what should be consistent)
                let upper_in_div = divergent_part
                    .chars()
                    .filter(char::is_ascii_uppercase)
                    .count();
                let lower_in_div = divergent_part
                    .chars()
                    .filter(char::is_ascii_lowercase)
                    .count();
                let alpha_in_div = upper_in_div + lower_in_div;

                // Wild case mixing is suspicious (e.g., "ROViLE" instead of "ROFILE")
                if alpha_in_div >= 4 && upper_in_div > 0 && lower_in_div > 0 {
                    let upper_ratio = upper_in_div * 100 / alpha_in_div;
                    if (20..=80).contains(&upper_ratio) {
                        return true;
                    }
                }
            }
        }
    }

    false
}

/// Check if a string looks like natural/structured text (not random garbage).
/// Used for generic XOR classification of longer strings with spaces.
pub(crate) fn looks_like_text(s: &str) -> bool {
    let words: Vec<&str> = s.split_whitespace().collect();

    // Need at least 3 words
    if words.len() < 3 {
        return false;
    }

    // Count character types
    let mut alpha = 0usize;
    let mut digit = 0usize;
    let mut space = 0usize;

    for c in s.chars() {
        if c.is_ascii_alphabetic() {
            alpha += 1;
        } else if c.is_ascii_digit() {
            digit += 1;
        } else if c == ' ' {
            space += 1;
        }
    }

    let len = s.len();

    // Must be mostly alphanumeric + spaces (at least 80%)
    let text_chars = alpha + digit + space;
    if (text_chars as u64 * 100) / (len as u64) < 80 {
        return false;
    }

    // Alphabetic chars should dominate (at least 50% of non-space)
    let non_space = len - space;
    if non_space > 0 && (alpha as u64 * 100) / (non_space as u64) < 50 {
        return false;
    }

    // Reasonable word lengths (average 2-15 chars)
    let avg_word_len = non_space / words.len().max(1);
    if !(2..=15).contains(&avg_word_len) {
        return false;
    }

    true
}
