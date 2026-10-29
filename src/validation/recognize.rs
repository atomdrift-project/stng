//! Shapes that make a string meaningful whatever its statistics: IOCs,
//! code, identifiers and tokens, locales, MAC and IPv6 addresses.

use aho_corasick::AhoCorasick;
use std::sync::LazyLock;

/// Mining software and its command-line flags. Pool URLs are the
/// classifier's `MiningPool`; these have no kind of their own.
#[allow(clippy::expect_used)]
pub(super) static MINER_SOFTWARE: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::new([
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

/// Literal shell-command indicators, batched into one Aho-Corasick pass
/// (replaces eight independent `contains` scans in `is_shell_command_string`).
#[allow(clippy::expect_used)]
pub(super) static SHELL_INDICATORS: LazyLock<AhoCorasick> = LazyLock::new(|| {
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
pub(super) static IOC_SUBSTRING: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::new(IOC_SUBSTRING_PATTERNS).expect("valid IOC substring patterns")
});

/// Pattern strings for [`IOC_SUBSTRING`] — order matters (the index of a
/// matched pattern is consumed by [`ioc_substring_match`] for per-pattern
/// length constraints).  Only patterns that are "match = IOC, unconditional"
/// belong here.  Compound checks (`CN=` + `DC=`) and validated checks
/// (`2>&1` requires alnum/ASCII-ratio gate) stay as explicit checks.
pub(super) const IOC_SUBSTRING_PATTERNS: &[&str] = &[
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
pub(super) fn ioc_substring_match(s: &str, len: usize) -> bool {
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
pub(super) static CODE_PATTERNS: LazyLock<AhoCorasick> = LazyLock::new(|| {
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

/// String of length ≥8 composed entirely of `[0-9a-fA-F:-]`, with at
/// least 6 hex digits drawn from ≥4 distinct hex characters. Catches
/// UUIDs, MD5/SHA hashes, MAC addresses, IPv6 address fragments,
/// OpenSSH key fingerprints, and build IDs that the statistical filter
/// would otherwise drop as chaotic. The diversity floor rejects
/// degenerate same-char runs like `aaaaaaaa` or `12121212`.
pub(super) fn is_hex_id_run(s: &str, len: usize) -> bool {
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
pub(super) fn is_token_id_run(s: &str, len: usize) -> bool {
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

/// Telegram bot API token: `<bot_id>:<auth_token>`.
///
/// Official shape (docs + observed rotations): bot_id is 8–16 ASCII digits,
/// auth_token is 30–48 chars drawn from the base64url alphabet
/// (`[A-Za-z0-9_-]`). The chaos filter otherwise drops these because digits
/// → `:` → upper → lower → `-` flips character class on almost every byte.
pub(super) fn is_telegram_bot_token(s: &str, len: usize) -> bool {
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
pub(super) fn is_swift_mangled_symbol(s: &str, len: usize) -> bool {
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

pub(super) fn is_code_pattern(s: &str) -> bool {
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

pub(super) fn is_obfuscated_js(s: &str) -> bool {
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

pub(super) fn is_comma_separated_list(s: &str, len: usize) -> bool {
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

pub(super) fn is_shell_command_string(s: &str) -> bool {
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

pub(super) fn is_mac_address_or_ipv6(s: &str, len: usize) -> bool {
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

pub(super) fn is_locale_code(s: &str, len: usize) -> bool {
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

/// Check if string matches known Indicator of Compromise patterns.
///
/// These are high-value strings that should never be filtered.
pub(super) fn is_recognized_ioc(s: &str, len: usize) -> bool {
    // File-glob patterns (`*.exe`, `*.dll`, `*.tmp`) — high-value malware
    // indicators that would otherwise be killed by the short-string
    // noise-punctuation filter because `*` is in the noise set.
    if s.strip_prefix("*.").is_some_and(|ext| {
        !ext.is_empty() && ext.len() <= 6 && ext.bytes().all(|b| b.is_ascii_alphanumeric())
    }) {
        return true;
    }
    if MINER_SOFTWARE.is_match(s) || (s.contains("-o ") && s.contains("-u ")) {
        return true;
    }
    // Batched substring sweep: `.onion`, `HKLM\`, `HKCU\`, `HKEY_`, `LDAP://`,
    // `-----BEGIN`, `-----END`, `2>&1`, `<<`.  One AC find replaces the
    // eight-plus individual `s.contains(...)` scans these checks used to do.
    if ioc_substring_match(s, len) {
        return true;
    }

    // A URL with a real host is an IOC however odd its surroundings: an
    // empty JSON value (`""`) or a non-ASCII hostname beside it must not get
    // a config string discarded as garbage. Long strings are left to the
    // filter: those are documents (XMP packets, schemas) citing namespaces.
    if len <= 256 && crate::ioc::has_url_authority(s) {
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

    // Code
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

    // Long hex strings are crypto hashes or keys, MD5 through SHA-512. A
    // misaligned read may add a stray non-hex byte, hence 95% rather than all.
    if (32..=128).contains(&len) {
        let hex_count = s.bytes().filter(u8::is_ascii_hexdigit).count();
        if hex_count * 100 / len > 95 {
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
        || (s.contains(" > ") && s.split_whitespace().count() >= 2)
    {
        let alnum_count = s.bytes().filter(u8::is_ascii_alphanumeric).count();
        let ascii_chars = s.bytes().filter(u8::is_ascii).count();
        let char_count = s.chars().count();
        if alnum_count >= 3 && char_count > 0 && ascii_chars * 100 / char_count > 80 {
            return true;
        }
    }

    false
}
