//! What a decoded XOR candidate is: kept or rejected, its kind, and the
//! trailing junk a misaligned decode leaves on it.

use super::validate::{
    has_known_path_prefix, is_meaningful_string, is_valid_xor_string, looks_like_text,
};
use crate::classifier::{classify_string, names_targeted_location};
use crate::{ExtractedString, StringKind};

pub(crate) fn trim_consonant_clusters(s: &str) -> String {
    if s.len() < 8 {
        return s.to_string();
    }

    let chars: Vec<char> = s.chars().collect();
    let mut consonant_run = 0;
    let mut trim_pos = None;

    for (i, &c) in chars.iter().enumerate() {
        if c.is_ascii_alphabetic() {
            let is_vowel = matches!(c.to_ascii_lowercase(), 'a' | 'e' | 'i' | 'o' | 'u');
            if is_vowel {
                consonant_run = 0;
            } else {
                consonant_run += 1;
                // If we hit 4+ consonants in a row, mark this as potential trim point
                if consonant_run >= 4 && trim_pos.is_none() {
                    // Trim before the start of this consonant run
                    trim_pos = Some(i - 3);
                }
            }
        } else {
            // Non-letter resets the count
            consonant_run = 0;
        }
    }

    if let Some(pos) = trim_pos {
        // Trim only a cluster in the final word, at least 10 chars in. A word
        // followed by more words is text: an identifier such as `aflst` in
        // "set end of aflst to item i of fl" is not a decoding failure.
        if pos >= 10 && !chars[pos..].iter().any(|c| c.is_whitespace()) {
            return chars[..pos].iter().collect();
        }
    }

    s.to_string()
}

/// Clean trailing garbage from locale strings extracted via XOR decoding.
///
/// Locale strings often have trailing garbage after the last valid locale code.
/// This function trims them to prevent overlaps with adjacent strings.
///
/// Examples:
/// - `hy_AM;be_BY;kk_KZ;ru_RU;uk_UA;ffYztZORL` -> `hy_AM;be_BY;kk_KZ;ru_RU;uk_UA;`
pub(crate) fn clean_locale_trailing_garbage(s: &str) -> String {
    // Find the last valid locale separator (';' or ',')
    if let Some(last_sep) = s.rfind([';', ',']) {
        // Include the separator in the result
        let clean_len = last_sep + 1;
        if clean_len < s.len() {
            return s[..clean_len].to_string();
        }
    }

    // No separator found or nothing to trim
    s.to_string()
}

/// Clean trailing garbage from URLs extracted via XOR decoding.
///
/// URLs often have trailing garbage characters that pass printability checks
/// but aren't part of the actual URL. This function trims them to prevent
/// overlaps with adjacent strings.
///
/// Examples:
/// - `http://46.30.191.141n;uJ` -> `http://46.30.191.141`
/// - `https://evil.com/path?foo=barn;X` -> `https://evil.com/path?foo=bar`
pub(crate) fn clean_url_trailing_garbage(url: &str) -> String {
    // For URLs with embedded IPs: trim after the last IP octet
    if let Some(proto_end) = url.find("://") {
        let after_proto = &url[proto_end + 3..];

        // Check if it starts with an IP address
        if after_proto
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_digit())
        {
            // Find the end of the IP (last digit of last octet)
            let mut ip_end = 0;
            let mut dots = 0;

            for (i, c) in after_proto.char_indices() {
                if c.is_ascii_digit() {
                    ip_end = i + c.len_utf8();
                } else if c == '.' {
                    dots += 1;
                    if dots > 3 {
                        break; // Too many dots, not a valid IP
                    }
                } else if c == ':' && dots == 3 {
                    // Port number after IP - find end of port
                    let port_start = i + c.len_utf8();
                    if let Some(port_end_offset) =
                        after_proto[port_start..].find(|c: char| !c.is_ascii_digit())
                    {
                        ip_end = port_start + port_end_offset;
                    } else {
                        ip_end = after_proto.len();
                    }
                    break;
                } else {
                    // Non-IP character
                    break;
                }
            }

            // If we found a valid IP (3 dots), trim after it
            if dots == 3 && ip_end > 0 {
                let clean_len = proto_end + 3 + ip_end;
                if clean_len < url.len() {
                    return url[..clean_len].to_string();
                }
            }
        } else {
            // Domain-based URL: trim after last alphanumeric/slash/common URL chars
            let valid_url_chars: Vec<usize> = after_proto
                .char_indices()
                .filter(|(_, c)| {
                    c.is_alphanumeric()
                        || matches!(c, '/' | '.' | '-' | '_' | '?' | '=' | '&' | '%' | '#' | '+')
                })
                .map(|(i, c)| i + c.len_utf8())
                .collect();

            if let Some(&last_valid) = valid_url_chars.last() {
                let clean_len = proto_end + 3 + last_valid;
                if clean_len < url.len() {
                    return url[..clean_len].to_string();
                }
            }
        }
    }

    // No cleanup needed or couldn't parse
    url.to_string()
}

/// Keywords that indicate credential/sensitive data when XOR-encoded.
const CREDENTIAL_KEYWORDS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "username",
    "user",
    "secret",
    "token",
    "apikey",
    "api_key",
    "bearer",
    "auth",
    "credential",
    "private",
    "key",
    "admin",
    "root",
];

/// Trim trailing garbage from extracted strings.
/// This removes characters at the end that don't look like legitimate content.
pub(crate) fn trim_trailing_garbage(s: &str) -> &str {
    // First, check for common shell redirections and terminators that mark natural endpoints
    let natural_endpoints = [
        "2>&1",
        "2>/dev/null",
        ">/dev/null",
        ">&1",
        ">&2",
        " &",
        "EOD",
        "EOF",
    ];

    // Find the last occurrence of any natural endpoint
    let mut natural_end: Option<usize> = None;
    for endpoint in &natural_endpoints {
        if let Some(pos) = s.rfind(endpoint) {
            let candidate_end = pos + endpoint.len();
            natural_end = Some(natural_end.map_or(candidate_end, |prev| prev.max(candidate_end)));
        }
    }

    // If we found a natural endpoint, trim there
    if let Some(end_pos) = natural_end {
        return &s[..end_pos];
    }

    // Check for file extensions as natural endpoints (e.g., .php, .exe, .dll, .so)
    let file_extensions = [
        ".php", ".exe", ".dll", ".so", ".dylib", ".js", ".py", ".rb", ".pl", ".sh", ".html",
        ".xml", ".json", ".txt", ".log", ".conf", ".cfg",
    ];
    for ext in &file_extensions {
        if let Some(pos) = s.rfind(ext) {
            let candidate_end = pos + ext.len();
            natural_end = Some(natural_end.map_or(candidate_end, |prev| prev.max(candidate_end)));
        }
    }

    if let Some(end_pos) = natural_end {
        return &s[..end_pos];
    }

    // Otherwise, work backwards from the end looking for the last legitimate character
    let chars: Vec<char> = s.chars().collect();
    let mut i = chars.len();

    while i > 0 {
        i -= 1;
        let c = chars[i];

        // Stop at clear delimiters
        if c == '"' || c == '\'' || c == ')' || c == ']' || c == '}' || c == '>' {
            return s.char_indices().nth(i + 1).map_or(s, |(pos, _)| &s[..pos]);
        }

        // Stop at alphanumeric followed by whitespace or punctuation that suggests a boundary
        if c.is_ascii_alphanumeric() {
            // Check if the next character (if exists) suggests this is the end
            if i + 1 < chars.len() {
                let next = chars[i + 1];
                // If followed by unusual characters, this might be the real end
                if !next.is_ascii_alphanumeric()
                    && next != '/'
                    && next != '.'
                    && next != '-'
                    && next != '_'
                {
                    return s.char_indices().nth(i + 1).map_or(s, |(pos, _)| &s[..pos]);
                }
            } else {
                // Last character is alphanumeric - keep whole string
                return s;
            }
        }
    }

    s
}

/// Well-known shell commands and tools (for lenient matching with trailing garbage).
const SHELL_COMMANDS: &[&str] = &[
    "screencapture",
    "osascript",
    "curl ",
    "wget ",
    "bash ",
    "sh ",
    "sleep ",
    "rm -rf",
    "python ",
    "perl ",
    "ruby ",
    "powershell",
    "cmd.exe",
    "/bin/sh",
    "/bin/bash",
    "2>&1",
    "<<eod",
    "<<eof",
    ">/dev/null",
];

/// Shell executable paths that should be classified as suspicious.
const SHELL_EXECUTABLE_PATHS: &[&str] = &[
    "/bin/sh",
    "/bin/bash",
    "/bin/zsh",
    "/bin/dash",
    "/usr/bin/bash",
    "/usr/bin/sh",
    "/usr/bin/python",
    "/usr/bin/perl",
    "/usr/bin/ruby",
    "cmd.exe",
    "powershell.exe",
];

/// Trim obvious garbage from the end of XOR-decoded strings.
/// Check if a string contains locale codes (language_COUNTRY or language-COUNTRY format).
/// These are often used in malware for geofencing/targeting specific regions.
///
/// Common locale patterns:
/// - en_US, en-US (English - United States)
/// - ru_RU, ru-RU (Russian - Russia)
/// - zh_CN, zh-CN (Chinese - China)
/// - Lists: "en_US;fr_FR;de_DE" or "ru_RU;be_BY;kk_KZ"
pub(crate) fn has_multiple_locales(s: &str) -> bool {
    // Common locale codes (top 15 global locales + CIS countries for malware detection)
    const COMMON_LOCALES: &[&str] = &[
        "en_US", "en-US", // English (US)
        "en_GB", "en-GB", // English (UK)
        "zh_CN", "zh-CN", // Chinese (China)
        "es_ES", "es-ES", // Spanish (Spain)
        "es_MX", "es-MX", // Spanish (Mexico)
        "fr_FR", "fr-FR", // French (France)
        "de_DE", "de-DE", // German (Germany)
        "ja_JP", "ja-JP", // Japanese (Japan)
        "pt_BR", "pt-BR", // Portuguese (Brazil)
        "ru_RU", "ru-RU", // Russian (Russia)
        "it_IT", "it-IT", // Italian (Italy)
        "ko_KR", "ko-KR", // Korean (Korea)
        "ar_SA", "ar-SA", // Arabic (Saudi Arabia)
        "hi_IN", "hi-IN", // Hindi (India)
        "tr_TR", "tr-TR", // Turkish (Turkey)
        // CIS countries, which malware geofencing commonly checks
        "hy_AM", "hy-AM", // Armenian
        "be_BY", "be-BY", // Belarusian
        "kk_KZ", "kk-KZ", // Kazakh
        "uk_UA", "uk-UA", // Ukrainian
        "uz_UZ", "uz-UZ", // Uzbek
    ];

    // Count how many locale codes are present
    let mut locale_count = 0;
    for locale in COMMON_LOCALES {
        if s.contains(locale) {
            locale_count += 1;
            if locale_count >= 2 {
                return true; // Found at least 2 locale codes (likely a geofencing list)
            }
        }
    }

    // Single locale might be legitimate, but lists of locales are suspicious
    false
}

/// Give strings the XOR scan produced the classifier's kinds, as for any other
/// string, once the scan is done with its evidence. Only `SuspiciousPath` and
/// `ShellCmd` can come from [`classify_xor_string`]'s own indicator lists;
/// every other kind already is the classifier's, or the scan's own `XorKey`.
pub(crate) fn report_kinds(strings: &mut [ExtractedString]) {
    for s in strings {
        if matches!(
            s.kind,
            Some(StringKind::SuspiciousPath | StringKind::ShellCmd)
        ) {
            s.kind = classify_string(&s.value);
        }
    }
}

/// Judge a speculative XOR decode. The nested `Option` is three-state:
/// `None` = reject; `Some(None)` = keep, no specific evidence; `Some(Some(k))`
/// = keep on evidence `k`.
///
/// Evidence is usually the classifier's kind, but a known indicator the
/// classifier has no kind for (a Windows API or DLL name, a locale list, a
/// credential or browser word) counts as `SuspiciousPath` or `ShellCmd`. The
/// scan's own trimming, overlap and English-shape checks key on evidence;
/// [`report_kinds`] gives the strings it keeps their reported kinds.
/// Whether `s` is XML markup: it starts and ends with a tag, and every `<`
/// opens a tag whose name starts with a letter (after `/`, `?` or `!`).
fn is_markup(s: &str) -> bool {
    if !(s.starts_with('<') && s.ends_with('>')) {
        return false;
    }
    let mut rest = s;
    while let Some(open) = rest.find('<') {
        let Some(len) = rest[open..].find('>') else {
            return false;
        };
        let tag = &rest[open + 1..open + len];
        if tag.contains('<')
            || !tag
                .trim_start_matches(['/', '?', '!'])
                .starts_with(|c: char| c.is_ascii_alphabetic())
        {
            return false;
        }
        rest = &rest[open + len + 1..];
    }
    true
}

/// What the XOR filter makes of a decoded candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Noise from a wrong key or alignment.
    Reject,
    /// Plausible plaintext, with the kind the classifier gave it, if any.
    Keep(Option<StringKind>),
}

impl Verdict {
    /// The kind of a kept candidate; `None` when rejected or unclassified.
    pub(crate) fn kind(self) -> Option<StringKind> {
        match self {
            Self::Keep(kind) => kind,
            Self::Reject => None,
        }
    }
}

/// Windows crypto and process APIs, resolved via `GetProcAddress` to hide
/// AES decryption or injection from static imports.
const WIN_API_NAMES: &[&str] = &[
    "BCryptOpenAlgorithmProvider",
    "BCryptGenerateSymmetricKey",
    "BCryptCloseAlgorithmProvider",
    "BCryptSetProperty",
    "BCryptDecrypt",
    "BCryptDestroyKey",
    "CreateProcessW",
    "CreateProcessA",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "GetProcAddress",
    "LoadLibraryW",
    "LoadLibraryA",
    "FindWindowExW",
    "GetWindowThreadProcessId",
    "ShowWindow",
];

/// Browser and messenger data that stealers exfiltrate.
const EXFIL_TARGETS: &[&str] = &[
    "extension settings",
    "local storage",
    "cookies",
    "bookmarks",
    "history",
    "preferences",
    "session",
    "cache",
    "telegram",
    "discord",
    "slack",
    "signal",
    "whatsapp",
    "tdata",
    "desktop folder",
    "documents folder",
];

/// Geofencing locales, stealer targets, DLL names and dynamically resolved
/// APIs: worth keeping even inside noise. DLL names like `bcrypt.dll` have no
/// vowels and would fail the linguistic checks.
fn named_target(s: &str) -> Option<StringKind> {
    (has_multiple_locales(s)
        || names_targeted_location(s)
        || s.ends_with(".dll")
        || s.ends_with(".DLL")
        || WIN_API_NAMES.iter().any(|api| s.contains(api)))
    .then_some(StringKind::SuspiciousPath)
}

/// Shells, shell commands, credential words and exfiltration targets in the
/// lowercased candidate, tolerating trailing garbage.
fn keyword_kind(lower: &str) -> Option<StringKind> {
    let has = |words: &[&str]| words.iter().any(|w| lower.contains(w));
    if has(SHELL_EXECUTABLE_PATHS) {
        Some(StringKind::SuspiciousPath)
    } else if has(SHELL_COMMANDS) {
        Some(StringKind::ShellCmd)
    } else if has(CREDENTIAL_KEYWORDS) || has(EXFIL_TARGETS) {
        Some(StringKind::SuspiciousPath)
    } else {
        None
    }
}

/// A decoded path is kept only in a known shape: a known Unix/macOS prefix, a
/// drive letter, or a relative path with a real component; few characters
/// paths do not use; and Unix components that are mostly alphanumeric.
fn plausible_path(s: &str) -> bool {
    let b = s.as_bytes();
    let is_windows_path =
        b.len() > 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\';
    let is_relative_path = (s.starts_with("./") || s.starts_with("../"))
        && s.matches('/').count() >= 2
        && s.split('/').any(|p| !p.is_empty() && p != "." && p != "..");
    if !has_known_path_prefix(s) && !is_windows_path && !is_relative_path {
        return false;
    }

    let bad_chars = s
        .chars()
        .filter(|&c| {
            !c.is_alphanumeric() && !matches!(c, '/' | '\\' | '.' | '_' | '-' | ' ' | ':' | '%')
        })
        .count();
    if bad_chars * 10 > s.len() {
        return false;
    }
    if !s.starts_with('/') {
        return true;
    }

    let parts: Vec<&str> = s.split('/').filter(|p| !p.is_empty()).collect();
    if let [name] = parts[..] {
        const TOP_LEVEL: &[&str] = &[
            "bin",
            "etc",
            "usr",
            "var",
            "tmp",
            "dev",
            "opt",
            "home",
            "root",
            "Library",
            "Users",
            "Applications",
            "System",
            "private",
        ];
        if !TOP_LEVEL.contains(&name) {
            // Mixed case with digits, or case flipping more than a real
            // name does, is gibberish.
            let has_upper = name.chars().any(|c| c.is_ascii_uppercase());
            let has_lower = name.chars().any(|c| c.is_ascii_lowercase());
            let has_digit = name.chars().any(|c| c.is_ascii_digit());
            if has_upper && has_lower && has_digit {
                return false;
            }
            let mut case_changes = 0;
            let mut prev_was_upper = false;
            for c in name.chars().filter(char::is_ascii_alphabetic) {
                let is_upper = c.is_ascii_uppercase();
                if prev_was_upper != is_upper {
                    case_changes += 1;
                }
                prev_was_upper = is_upper;
            }
            if case_changes > 3 {
                return false;
            }
        }
    }
    parts.iter().all(|part| {
        part.chars().filter(char::is_ascii_alphanumeric).count() * 100 / part.len() >= 60
    })
}

/// The fallback for unclassified (or `Const`) candidates: at most 40%
/// punctuation; prose when long and spaced; otherwise mostly alphanumeric.
fn plausible_generic(s: &str) -> bool {
    let char_count = s.chars().count();
    let special_chars = s
        .chars()
        .filter(|&c| !c.is_alphanumeric() && !c.is_whitespace() && !matches!(c, '-' | '_' | '.'))
        .count();
    if char_count > 0 && special_chars * 10 > char_count * 4 {
        return false;
    }
    if char_count >= 30 && s.contains(' ') {
        return looks_like_text(s);
    }
    let alnum = s.chars().filter(|c| c.is_alphanumeric()).count();
    !(char_count > 0 && alnum * 10 < char_count * 6)
}

/// Whether one character makes up over half of a 16+ character candidate:
/// a run like repeated spaces XORed into a valid-looking alphabet.
fn dominated_by_one_char(s: &str) -> bool {
    let char_count = s.chars().count();
    if char_count < 16 {
        return false;
    }
    let mut counts = std::collections::HashMap::new();
    let mut max_count = 0;
    for c in s.chars() {
        let count = counts.entry(c).or_insert(0);
        *count += 1;
        max_count = max_count.max(*count);
    }
    max_count * 2 > char_count
}

pub(crate) fn classify_xor_string(s: &str) -> Verdict {
    // Several rules below need the classifier's verdict; compute it once, and
    // only on paths that ask.
    let classified = std::cell::LazyCell::new(|| classify_string(s));

    // High-value indicators bypass strict filtering. They come before the
    // partial-decode check so that real paths like /proc/net/tcp, which can
    // resemble a half-decoded %VAR%, are not rejected.
    if let Some(kind) = named_target(s) {
        return Verdict::Keep(Some(kind));
    }

    // EARLY REJECTION: Check for partial/failed XOR decodes before any classification.
    // These are strings that start like known patterns (e.g., "%USERPROFILE%") but
    // diverge into garbage (e.g., "%UsERP4NFINE%\"). Must check this BEFORE
    // is_meaningful_string() which might pass these due to acceptable vowel ratios.
    if super::validate::is_partial_xor_decode(s) {
        return Verdict::Reject;
    }

    if let Some(kind) = keyword_kind(&s.to_ascii_lowercase()) {
        return Verdict::Keep(Some(kind));
    }

    // Persistence plists and entitlements are spelled out tag by tag.
    if is_markup(s) {
        return Verdict::Keep(None);
    }

    // Quick check for URLs/IPs before strict filtering
    if s.contains("://") {
        // Likely a URL, allow through
        let kind = *classified;
        if matches!(kind, Some(StringKind::Url)) {
            return Verdict::Keep(kind);
        }
    }

    // Check for IP addresses (pattern: digits.digits.digits.digits)
    if s.chars().filter(|&c| c == '.').count() == 3 {
        let segments: Vec<&str> = s.split('.').collect();
        if segments.len() == 4
            && segments.iter().all(|seg| {
                !seg.is_empty() && seg.chars().all(|c| c.is_ascii_digit()) && seg.len() <= 3
            })
        {
            // Likely an IP address, allow through
            let kind = *classified;
            if matches!(kind, Some(StringKind::Ip | StringKind::IpPort)) {
                return Verdict::Keep(kind);
            }
        }
    }

    // SECOND: Check if string looks like well-formed text
    // If it passes linguistic validation, trust it
    if is_meaningful_string(s) {
        // String looks legitimate - classify it
        let kind = *classified;

        // Accept meaningful strings that classify as high-value IOCs
        // NOTE: Const is intentionally excluded - it must pass strict validation below
        // NOTE: Path is intentionally excluded - paths must go through strict validation below
        if matches!(
            kind,
            Some(
                StringKind::SuspiciousPath
                    | StringKind::ShellCmd
                    | StringKind::Ip
                    | StringKind::IpPort
                    | StringKind::Url
            )
        ) {
            return Verdict::Keep(kind);
        }
    }

    if dominated_by_one_char(s) {
        return Verdict::Reject;
    }

    // SECOND+: Check for encoded data formats directly
    // Base64, hex, and url-encoded strings don't pass linguistic checks but are high-value IOCs.
    // classify_string handles proper format validation (length, charset, structure).
    {
        let kind = *classified;
        if matches!(
            kind,
            Some(StringKind::Base64 | StringKind::HexEncoded | StringKind::UrlEncoded)
        ) {
            return Verdict::Keep(kind);
        }
        // XOR decoding may strip trailing '=' padding from base64 (e.g., '=' XOR 0x42 = 0x7F,
        // which is non-printable and gets cut off by the scan). Try re-adding padding.
        let remainder = s.len() % 4;
        if remainder == 2 || remainder == 3 {
            let padding = if remainder == 2 { "==" } else { "=" };
            let padded = format!("{s}{padding}");
            if matches!(classify_string(&padded), Some(StringKind::Base64)) {
                return Verdict::Keep(Some(StringKind::Base64));
            }
        }
    }

    // THIRD: For strings that don't pass linguistic checks, apply strict filtering
    if !is_valid_xor_string(s) {
        return Verdict::Reject;
    }

    // Classify remaining strings that passed strict validation
    let kind = *classified;

    match kind {
        Some(
            StringKind::Ip
            | StringKind::IpPort
            | StringKind::Url
            | StringKind::SuspiciousPath
            | StringKind::UnicodeEscaped
            | StringKind::HexEncoded
            | StringKind::UrlEncoded
            | StringKind::Registry
            | StringKind::Base64,
        ) => Verdict::Keep(kind),
        Some(StringKind::ShellCmd | StringKind::AppleScript) => {
            // Reject obvious garbage that starts with backtick but no valid command
            if s.starts_with('`')
                && !s[1..]
                    .trim_start()
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic())
            {
                Verdict::Reject
            } else {
                Verdict::Keep(kind)
            }
        }
        Some(StringKind::Path) if plausible_path(s) => Verdict::Keep(kind),
        Some(StringKind::Path) => Verdict::Reject,
        _ if plausible_generic(s) => Verdict::Keep(None),
        _ => Verdict::Reject,
    }
}

#[cfg(test)]
mod tests;
