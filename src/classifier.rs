//! String classification by semantic type.
//!
//! Classifies extracted strings as URLs, IPs, paths, shell commands, code
//! fragments, encoding schemes, and other security-relevant categories.

mod code;
pub(crate) mod encoding;
mod network;

pub(crate) use network::names_targeted_location;

use crate::types::StringKind;
use aho_corasick::AhoCorasick;
use std::sync::LazyLock;

/// Ransomware note markers. A string is a candidate only if it contains one of
/// these; every classified string is checked, so they share one automaton.
static RANSOM_INDICATORS: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::new(["ENCRYPTED", "DECRYPT", "RANSOM"]).unwrap_or_else(crate::invalid_pattern)
});

/// LDAP/AD path markers — necessary-condition gate for the precise check below.
static LDAP_INDICATORS: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::new(["LDAP://", "CN=", "DC="]).unwrap_or_else(crate::invalid_pattern)
});

/// URL schemes, including database connection strings.
const URL_SCHEMES: &[&str] = &[
    "http://",
    "https://",
    "ftp://",
    "postgresql://",
    "mysql://",
    "redis://",
    "mongodb://",
    "ssh://",
    "tcp://",
    "udp://",
];

/// Prefixes that make a string a path, absolute or relative.
const PATH_PREFIXES: &[&str] = &["/", "C:\\", "./", "../"];

/// Config, credential and project files worth reporting even without a
/// directory, matched as a suffix.
const WELL_KNOWN_FILES: &[&str] = &[
    ".DS_Store",
    ".localized",
    ".bashrc",
    ".zshrc",
    ".profile",
    ".bash_profile",
    ".gitignore",
    ".gitconfig",
    ".ssh/",
    ".aws/",
    ".docker/",
    "authorized_keys",
    "id_rsa",
    "id_ed25519",
    "known_hosts",
    ".npmrc",
    ".yarnrc",
    "package.json",
    "Cargo.toml",
    "go.mod",
    "requirements.txt",
];

/// Environment variables too short or plain to be recognized by shape
/// (an underscore or a `GO` prefix).
const KNOWN_ENV_VARS: &[&str] = &[
    // POSIX/Unix
    "PATH",
    "HOME",
    "USER",
    "SHELL",
    "TERM",
    "LANG",
    "PWD",
    "TMP",
    "TEMP",
    "TMPDIR",
    "EDITOR",
    "PAGER",
    "MAIL",
    "LOGNAME",
    "HOSTNAME",
    "DISPLAY",
    "TZ",
    "UID",
    "GID",
    "EUID",
    "EGID",
    // Locale
    "LC_ALL",
    "LC_CTYPE",
    "LC_COLLATE",
    "LC_MESSAGES",
    "LC_MONETARY",
    "LC_NUMERIC",
    "LC_TIME",
    // Terminal
    "COLUMNS",
    "LINES",
    "COLORTERM",
    "CLICOLOR",
    "LSCOLORS",
    // Build
    "CC",
    "CXX",
    "CFLAGS",
    "CXXFLAGS",
    "LDFLAGS",
    "MAKE",
    "AR",
    "AS",
    "LD",
    "NM",
    "RANLIB",
    "STRIP",
    // Language toolchains
    "JAVA_HOME",
    "PYTHONPATH",
    "NODE_PATH",
    "RUBYLIB",
    "PERL5LIB",
    "CARGO_HOME",
    "RUSTUP_HOME",
    "GOPATH",
    "GOROOT",
    "GOBIN",
    "GOCACHE",
    // XDG base directories
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
    "XDG_STATE_HOME",
    "XDG_RUNTIME_DIR",
    // Security/auth
    "SSH_AUTH_SOCK",
    "SSH_AGENT_PID",
    "GPG_AGENT_INFO",
    "SUDO_USER",
    "SUDO_UID",
    "SUDO_GID",
    "SUDO_COMMAND",
    // Proxies
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "FTP_PROXY",
    "NO_PROXY",
    "ALL_PROXY",
    // Debugging
    "DEBUG",
    "VERBOSE",
    "TRACE",
    // Loaders
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "GLIBC_TUNABLES",
    "DYLD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_FRAMEWORK_PATH",
    // Windows
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMFILES",
    "SYSTEMROOT",
    "WINDIR",
    "USERPROFILE",
    "COMPUTERNAME",
];

type Detector = fn(&str) -> Option<StringKind>;

/// High-value indicators, checked first so that, for example, a stratum URL
/// is a mining pool and a JWT is not mistaken for base64.
const INDICATORS: &[Detector] = &[
    ctf_flag,
    guid,
    |s| encoding::is_cryptographic_hash(s).then_some(StringKind::Hash),
    network::classify_crypto_address,
    // A string with `@` and `.` that is not an email falls through to the
    // URL, path and command checks (`https://user@host/`, `git@host:org/repo`).
    classify_email,
    tor_address,
    jwt,
    network::classify_api_key,
    sql_injection,
    xss,
    |s| {
        (LDAP_INDICATORS.is_match(s)
            && (s.contains("LDAP://") || (s.contains("CN=") && s.contains("DC="))))
        .then_some(StringKind::LdapPath)
    },
    |s| (s.starts_with("Global\\") || s.starts_with("Local\\")).then_some(StringKind::Mutex),
    ransom_note,
    mining_pool,
];

/// Code, commands and locations. Code comes before commands so a script that
/// runs `curl` is still a script, and injection wrappers (`;`, `|`, `$()`)
/// before generic shell commands because they are the stronger signal.
const SYNTAX: &[Detector] = &[
    |s| code::is_php_code(s).then_some(StringKind::PhpCode),
    |s| code::is_python_code(s).then_some(StringKind::PythonCode),
    |s| code::is_javascript_code(s).then_some(StringKind::JavaScriptCode),
    |s| code::is_applescript(s).then_some(StringKind::AppleScript),
    command_injection,
    |s| code::is_shell_command(s).then_some(StringKind::ShellCmd),
    |s| {
        if s.starts_with(|c: char| c.is_ascii_digit()) {
            network::classify_ip(s)
        } else {
            None
        }
    },
    |s| is_registry_path(s).then_some(StringKind::Registry),
    |s| network::names_targeted_location(s).then_some(StringKind::SuspiciousPath),
    |s| {
        WELL_KNOWN_FILES
            .iter()
            .any(|f| s.ends_with(f))
            .then_some(StringKind::FilePath)
    },
];

/// Encodings, which need the whole string, from most to least constrained
/// alphabet.
const ENCODINGS: &[Detector] = &[
    |s| encoding::is_unicode_escaped(s).then_some(StringKind::UnicodeEscaped),
    |s| encoding::is_url_encoded(s).then_some(StringKind::UrlEncoded),
    |s| encoding::is_hex_encoded(s).then_some(StringKind::HexEncoded),
    |s| encoding::is_base58(s).then_some(StringKind::Base58),
    |s| encoding::is_base32(s).then_some(StringKind::Base32),
    |s| encoding::is_base85(s).then_some(StringKind::Base85),
    |s| encoding::is_base64(s).then_some(StringKind::Base64),
];

/// Classify a general string by its content.
/// Note: Section names are detected via goblin, not pattern matching here.
pub fn classify_string(s: &str) -> Option<StringKind> {
    if s.len() < 3 {
        return None;
    }
    // The high-value kinds of a long string are prefix-anchored, and the
    // encodings would need a full-content scan.
    if s.len() > 1000 {
        return classify_prefix(&s[..s.floor_char_boundary(256)]);
    }
    let detect = |detectors: &[Detector]| detectors.iter().find_map(|d| d(s));
    if let Some(kind) = detect(INDICATORS) {
        return Some(kind);
    }
    if URL_SCHEMES.iter().any(|p| s.starts_with(p)) {
        return url(s);
    }
    if let Some(kind) = detect(SYNTAX) {
        return Some(kind);
    }
    if PATH_PREFIXES.iter().any(|p| s.starts_with(p)) {
        return path(s);
    }
    detect(ENCODINGS).or_else(|| env_var(s))
}

/// `Url` for a string that starts with a URL scheme, except Apple's
/// certificate authority URL, which is in every signed Mach-O.
fn url(s: &str) -> Option<StringKind> {
    (!s.starts_with("https://www.apple.com/appleca")).then_some(StringKind::Url)
}

/// A Tor onion service: a 16- (v2) or 56-character (v3) base32 label
/// before `.onion`, as a whole word. "Visit abcdef.onion" names no service.
fn tor_address(s: &str) -> Option<StringKind> {
    let b = s.as_bytes();
    let base32 = |c: u8| c.is_ascii_lowercase() || (b'2'..=b'7').contains(&c);
    memchr::memmem::find_iter(b, b".onion")
        .any(|at| {
            let label = b[..at].iter().rev().take_while(|&&c| base32(c)).count();
            let start = at - label;
            let end = at + ".onion".len();
            matches!(label, 16 | 56)
                && (start == 0 || !b[start - 1].is_ascii_alphanumeric())
                && b.get(end).is_none_or(|c| !c.is_ascii_alphanumeric())
        })
        .then_some(StringKind::TorAddress)
}

/// `CTF{...}`, `flag{...}`, `picoCTF{...}` and friends.
fn ctf_flag(s: &str) -> Option<StringKind> {
    let opens = ["CTF{", "flag{", "FLAG{", "picoCTF{", "HTB{"];
    (s.ends_with('}') && opens.iter().any(|p| s.starts_with(p))).then_some(StringKind::CtfFlag)
}

/// A braced registry GUID or a canonical 8-4-4-4-12 UUID (Mythic payload
/// UUIDs, systemd, COM). The garbage filter would otherwise drop these: hex
/// and dashes trip its character-class-transition check.
fn guid(s: &str) -> Option<StringKind> {
    let b = s.as_bytes();
    let hex = || s.bytes().filter(u8::is_ascii_hexdigit).count();
    let braced = s.starts_with('{')
        && s.ends_with('}')
        && (36..=38).contains(&s.len())
        && memchr::memchr_iter(b'-', b).count() == 4
        && (30..=32).contains(&hex());
    let canonical = s.len() == 36 && [8, 13, 18, 23].iter().all(|&i| b[i] == b'-') && hex() == 32;
    (braced || canonical).then_some(StringKind::Guid)
}

/// Three base64url segments. Every real JWT header encodes `{"...`, which is
/// `eyJ` in base64url; requiring it rules out `pkg/foo.Type.method` symbols.
fn jwt(s: &str) -> Option<StringKind> {
    let segment = |p: &str| {
        !p.is_empty()
            && p.bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'='))
    };
    (s.len() >= 50
        && s.starts_with("eyJ")
        && s.matches('.').count() == 2
        && s.split('.').all(segment))
    .then_some(StringKind::Jwt)
}

fn sql_injection(s: &str) -> Option<StringKind> {
    let union = s.contains("UNION");
    ((memchr::memchr2(b'\'', b'-', s.as_bytes()).is_some() || union)
        && (s.contains("' OR '")
            || s.contains("1'='1")
            || (union && s.contains("SELECT"))
            || s.contains("admin'--")))
    .then_some(StringKind::SqlInjection)
}

fn xss(s: &str) -> Option<StringKind> {
    ((s.starts_with('j') || memchr::memchr2(b'<', b'=', s.as_bytes()).is_some())
        && ((s.contains("<script>") && s.contains("</script>"))
            || (s.contains("onerror=") && s.contains("alert("))
            || s.starts_with("javascript:")))
    .then_some(StringKind::XssPayload)
}

/// A shouted ransom demand, or a well-known ransomware file extension or
/// note name.
fn ransom_note(s: &str) -> Option<StringKind> {
    let shouted = RANSOM_INDICATORS.is_match(s)
        && s.bytes().filter(u8::is_ascii_uppercase).count() * 100 / s.len() > 50;
    let extensions = [
        ".locked",
        ".encrypted",
        ".crypted",
        ".wannacry",
        ".ryuk",
        ".locky",
    ];
    (shouted
        || extensions.contains(&s)
        || s.ends_with("-DECRYPT-INSTRUCTIONS.txt")
        || s.ends_with("HOW-TO-DECRYPT.html"))
    .then_some(StringKind::RansomNote)
}

fn mining_pool(s: &str) -> Option<StringKind> {
    (s.contains("stratum+tcp://")
        || s.contains("stratum+ssl://")
        || ((s.contains("pool.") || s.contains("nanopool") || s.contains("minergate"))
            && (s.contains(".com") || s.contains(".org") || s.contains(':'))))
    .then_some(StringKind::MiningPool)
}

/// `; cat`, `| whoami`, or a `$(...)` or backtick substitution holding
/// something command-shaped rather than binary noise.
fn command_injection(s: &str) -> Option<StringKind> {
    let ascii_percent = |t: &str| t.bytes().filter(u8::is_ascii).count() * 100 / t.len();
    if memchr::memchr3(b';', b'|', b'$', s.as_bytes()).is_some() {
        // The command must follow the separator as a whole word: "valid |
        // hidden" is not `| id`.
        if command_follows(s, ';', &["cat", "wget", "curl"])
            || command_follows(s, '|', &["whoami", "id", "uname"])
        {
            return Some(StringKind::CommandInjection);
        }
        if code::substitution_runs_command(s) {
            return Some(StringKind::CommandInjection);
        }
    }
    if s.len() >= 5 && s.starts_with('`') && s.ends_with('`') {
        let inner = &s[1..s.len() - 1];
        let commands = [" ", "cat", "ls", "pwd", "echo", "wget", "curl"];
        if ascii_percent(inner) > 90 && commands.iter().any(|c| inner.contains(c)) {
            return Some(StringKind::CommandInjection);
        }
    }
    None
}

/// A path, unless it is a Go runtime metric name (`/gc/heap/allocs:bytes`)
/// or mostly punctuation.
fn path(s: &str) -> Option<StringKind> {
    if s.starts_with('/') && s.contains(':') && !s.contains("://") {
        return None;
    }
    let alnum = s.bytes().filter(u8::is_ascii_alphanumeric).count();
    let special = s
        .bytes()
        .filter(|b| !b.is_ascii_alphanumeric() && !b.is_ascii_whitespace())
        .count();
    if alnum == 0 || special * 100 / s.len() > 30 {
        return None;
    }
    Some(path_kind(s))
}

fn path_kind(s: &str) -> StringKind {
    if network::is_suspicious_path(s) {
        StringKind::SuspiciousPath
    } else {
        StringKind::Path
    }
}

/// An upper-case variable name, optionally with the `=` of an assignment
/// (`GOMEMLIMIT=`). Unknown names need an underscore or a `GO` prefix, which
/// keeps out x86 register-push noise like `AWAVAUATSH`.
fn env_var(s: &str) -> Option<StringKind> {
    let name = s.strip_suffix('=').unwrap_or(s);
    let shaped = name.len() >= 3
        && name.starts_with(|c: char| c.is_ascii_uppercase())
        && name
            .bytes()
            .all(|c| c.is_ascii_uppercase() || c == b'_' || c.is_ascii_digit());
    (shaped
        && (KNOWN_ENV_VARS.contains(&name)
            || name.contains('_')
            || (name.starts_with("GO") && name.len() >= 4)))
        .then_some(StringKind::EnvVar)
}

/// Recognize a Windows registry key path, including the root-relative subkey
/// form that is passed alongside a separate `hKey` argument to `RegOpenKeyExA`
/// & friends (e.g. `Software\Microsoft\Windows\CurrentVersion\Run`).
///
/// The all-caps variant `SOFTWARE\` / `SYSTEM\` is matched on its own because
/// it is overwhelmingly registry-specific in practice. The mixed-case
/// `Software\` / `System\` form requires a known second component to avoid
/// false positives on generic filesystem strings.
fn is_registry_path(s: &str) -> bool {
    // Standard HKEY-prefixed forms.
    if s.starts_with("HKEY_")
        || s.starts_with("HKLM\\")
        || s.starts_with("HKCU\\")
        || s.starts_with("HKCR\\")
        || s.starts_with("HKU\\")
        || s.starts_with("HKCC\\")
    {
        return true;
    }

    // All-caps hive-relative paths are almost exclusively registry keys.
    if s.starts_with("SOFTWARE\\") || s.starts_with("SYSTEM\\") {
        return true;
    }

    // Mixed-case hive-relative paths. Restrict to well-known second components
    // so we don't classify a literal Windows filesystem path like
    // `Software\Foo\bar.dll` (which a few games / installers do embed).
    const WELL_KNOWN_SOFTWARE_SUBKEYS: &[&str] = &[
        "Software\\Microsoft\\",
        "Software\\Wow6432Node\\",
        "Software\\Classes\\",
        "Software\\Policies\\",
        "Software\\JavaSoft\\",
        "Software\\Clients\\",
        "Software\\WOW6432Node\\",
        "Software\\Mozilla\\",
        "Software\\Google\\",
    ];
    if WELL_KNOWN_SOFTWARE_SUBKEYS.iter().any(|p| s.starts_with(p)) {
        return true;
    }

    s.starts_with("System\\CurrentControlSet\\")
        || s.starts_with("System\\Setup\\")
        || s.starts_with("SAM\\")
        || s.starts_with("SECURITY\\")
}

/// Classify a long string by its first 256 bytes: only the prefix-anchored
/// kinds and code markers.
fn classify_prefix(prefix: &str) -> Option<StringKind> {
    if URL_SCHEMES.iter().any(|p| prefix.starts_with(p)) {
        return url(prefix);
    }
    if PATH_PREFIXES.iter().any(|p| prefix.starts_with(p)) {
        return path(prefix);
    }
    if is_registry_path(prefix) {
        return Some(StringKind::Registry);
    }
    if prefix.starts_with("<?php") {
        return Some(StringKind::PhpCode);
    }
    // A shebang names the interpreter; the code detectors below judge it.
    if code::is_python_code(prefix) {
        return Some(StringKind::PythonCode);
    }
    if code::is_javascript_code(prefix) {
        return Some(StringKind::JavaScriptCode);
    }
    code::is_shell_command(prefix).then_some(StringKind::ShellCmd)
}

/// Whether some `separator` in `s` is followed, after spaces, by one of
/// `commands` as a whole word.
fn command_follows(s: &str, separator: char, commands: &[&str]) -> bool {
    s.match_indices(separator).any(|(i, _)| {
        let rest = s[i + 1..].trim_start_matches(' ');
        commands.iter().any(|command| {
            rest.strip_prefix(command)
                .is_some_and(|after| !after.starts_with(|c: char| c.is_ascii_alphanumeric()))
        })
    })
}

/// `Some(Email)` for a plausible email address. Every `None` here only means
/// "not an email"; the caller goes on to try other kinds.
fn classify_email(s: &str) -> Option<StringKind> {
    if s.len() < 6 || s.contains("..") {
        return None;
    }
    let (local, domain) = s.split_once('@')?;
    // Local part: RFC 5321 atext we care about, starting alphanumeric. Slashes
    // are refused: `pkg/sub@v1.0.0/file.go` is a Go module path.
    if !local.starts_with(|c: char| c.is_ascii_alphanumeric())
        || !local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+' | b'%'))
    {
        return None;
    }
    // Domain: hostname characters only, so `logr@v1.4.1/logr.go` is refused.
    if !domain
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
    {
        return None;
    }
    let (first, _) = domain.split_once('.')?;
    let (_, tld) = domain.rsplit_once('.')?;
    // The first label has a letter and two characters ("0.x" and "E.MM" are
    // not domains) and is not a Go module version such as "v1".
    let version = first.len() >= 2
        && first.starts_with('v')
        && first[1..].bytes().all(|b| b.is_ascii_digit());
    if first.len() < 2
        || !first.bytes().any(|b| b.is_ascii_alphabetic())
        || version
        || tld.len() < 2
        || !tld.bytes().all(|b| b.is_ascii_alphabetic())
    {
        return None;
    }
    // `%` is legal in the local part but rare in a real address.
    let percent = local.bytes().filter(|&b| b == b'%').count();
    ((s.len() - percent) * 100 / s.len() >= 85).then_some(StringKind::Email)
}

#[cfg(test)]
mod tests;
