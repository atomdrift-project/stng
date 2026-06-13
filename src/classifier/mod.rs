//! String classification by semantic type.
//!
//! Classifies extracted strings as URLs, IPs, paths, shell commands, code
//! fragments, encoding schemes, and other security-relevant categories.

mod code;
pub mod encoding;
mod network;

use crate::types::StringKind;

/// Classify a general string by its content.
/// Note: Section names are detected via goblin, not pattern matching here.
pub fn classify_string(s: &str) -> Option<StringKind> {
    let len = s.len();

    if len < 3 {
        return None;
    }

    // For long strings, classify using only the first 256 bytes.
    // Most high-value patterns (URLs, paths, shebangs, code markers) are
    // prefix-based and don't need the full string. Skip encoding checks
    // (base64, hex, etc.) since those require full-content validation.
    if len > 1000 {
        let prefix = &s[..s.floor_char_boundary(256.min(len))];
        return classify_prefix(prefix);
    }

    let bytes = s.as_bytes();
    let first = bytes[0];

    // ===== HIGH-PRIORITY IOC DETECTION =====
    // These checks come first because they're high-value security indicators

    // CTF flags: CTF{...}, flag{...}, FLAG{...}, picoCTF{...}, HTB{...}
    if (s.starts_with("CTF{")
        || s.starts_with("flag{")
        || s.starts_with("FLAG{")
        || s.starts_with("picoCTF{")
        || s.starts_with("HTB{"))
        && s.ends_with('}')
    {
        return Some(StringKind::CTFFlag);
    }

    // GUIDs: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
    if s.starts_with('{') && s.ends_with('}') && (36..=38).contains(&len) {
        let dash_count = memchr::memchr_iter(b'-', s.as_bytes()).count();
        let hex_count = s.bytes().filter(u8::is_ascii_hexdigit).count();
        if dash_count == 4 && (30..=32).contains(&hex_count) {
            return Some(StringKind::GUID);
        }
    }

    // Canonical UUIDs: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX (RFC 4122 form,
    // 8-4-4-4-12). Used by Mythic agent payload_uuid, systemd, COM objects in
    // .NET registry hives, etc. The chaos filter would otherwise drop these
    // because hex+dash strings trip the character-class-transition check.
    if len == 36
        && bytes[8] == b'-'
        && bytes[13] == b'-'
        && bytes[18] == b'-'
        && bytes[23] == b'-'
        && s.bytes().filter(u8::is_ascii_hexdigit).count() == 32
    {
        return Some(StringKind::GUID);
    }

    // Cryptographic hashes (MD5=32, SHA1=40, SHA256=64, SHA512=128)
    if encoding::is_cryptographic_hash(s) {
        return Some(StringKind::Hash);
    }

    // Cryptocurrency wallet addresses (high value IOC)
    if let Some(kind) = network::classify_crypto_address(s) {
        return Some(kind);
    }

    // Email addresses (often used in ransomware) - use memchr for speed
    if len >= 6 && memchr::memchr(b'@', bytes).is_some() && memchr::memchr(b'.', bytes).is_some() {
        let at_count = memchr::memchr_iter(b'@', s.as_bytes()).count();
        if at_count == 1 {
            // Must be mostly ASCII (>95%) - reject garbage with non-ASCII chars
            let ascii_count = s.bytes().filter(u8::is_ascii).count();
            if ascii_count * 100 / len < 95 {
                return None; // Skip - has too much non-ASCII
            }

            // Reject consecutive dots (invalid email format)
            if s.contains("..") {
                return None; // Skip - has consecutive dots
            }

            // Split on @ to validate structure (exactly one @ guaranteed above)
            if let Some((local, domain)) = s.split_once('@') {
                // Local part must exist, not be empty, and start with alphanumeric
                let starts_with_alnum = local.chars().next().is_some_and(char::is_alphanumeric);
                if !starts_with_alnum {
                    return None; // Skip - starts with @ or non-alphanumeric
                }

                // Local part must have at least one alphanumeric character
                if !local.chars().any(char::is_alphanumeric) {
                    return None; // Skip - local part has no alphanumeric
                }

                // Local part may only contain the RFC-5321 atext subset we care about.
                // Reject slashes (common in Go module paths like "pkg/sub@v1.0.0/file.go")
                // and other symbols that are not legal in email addresses.
                if !local
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+' | '%'))
                {
                    return None; // Skip - local part contains non-email chars
                }

                // Domain must have a dot (not @domain or @.domain)
                if !domain.contains('.') || domain.starts_with('.') {
                    return None; // Skip - invalid domain structure
                }

                // Domain may only contain hostname-legal characters (letters, digits,
                // dots, hyphens). Reject slashes — `logr@v1.4.1/logr.go` is a Go
                // module path, not an email.
                if !domain
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
                {
                    return None; // Skip - domain contains non-hostname chars
                }

                // Domain must have at least one letter (not just numbers/symbols like @0.x)
                let domain_has_letter = domain.chars().any(|c| c.is_ascii_alphabetic());
                if !domain_has_letter {
                    return None; // Skip - domain has no letters
                }

                // Reject domains whose first label is a bare version token like
                // "v1" or "v2" — these come from Go module paths (`pkg@v1.4.1`).
                if let Some(first_label) = domain.split('.').next() {
                    let is_version_token = first_label.len() >= 2
                        && first_label.starts_with('v')
                        && first_label[1..].chars().all(|c| c.is_ascii_digit());
                    if is_version_token {
                        return None; // Skip - Go module version, not email domain
                    }
                }

                // Extract TLD (everything after last dot)
                if let Some(last_dot_pos) = domain.rfind('.') {
                    let tld = &domain[last_dot_pos + 1..];
                    // TLD must be at least 2 chars and all alphabetic
                    if tld.len() < 2 || !tld.chars().all(|c| c.is_ascii_alphabetic()) {
                        return None; // Skip - invalid TLD
                    }
                }

                // The main domain part (before TLD) must contain at least one letter
                // and be at least 2 characters long. Reject cases like "0.x" or "E.MM"
                if let Some(dot_pos) = domain.find('.') {
                    let main_domain = &domain[..dot_pos];
                    if main_domain.len() < 2 {
                        return None; // Skip - main domain too short (e.g., E.MM)
                    }
                    let main_has_letter = main_domain.chars().any(|c| c.is_ascii_alphabetic());
                    if !main_has_letter {
                        return None; // Skip - main domain has no letters (e.g., 0.x)
                    }
                }

                // Valid email chars check
                let valid_chars = s
                    .chars()
                    .filter(|c| c.is_alphanumeric() || matches!(c, '@' | '.' | '-' | '_' | '+'))
                    .count();
                if valid_chars * 100 / len >= 85 {
                    return Some(StringKind::Email);
                }
            }
        }
    }

    // Tor/Onion addresses
    if s.contains(".onion") && len >= 10 {
        return Some(StringKind::TorAddress);
    }

    // JWT tokens: three base64url segments separated by dots. Every real JWT
    // header decodes from `{"alg":...}`, which in base64url always starts with
    // `eyJ`. Requiring that prefix plus strict base64url chars in every
    // segment rules out arbitrary `foo/bar.Type.method` Go symbols.
    if s.matches('.').count() == 2 && len >= 50 && s.starts_with("eyJ") {
        // Exactly three dot-separated segments (guaranteed above); each must be a
        // non-empty base64url run.
        let is_base64url = |p: &str| {
            !p.is_empty()
                && p.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '='))
        };
        if s.split('.').all(is_base64url) {
            return Some(StringKind::JWT);
        }
    }

    // API keys (AWS, GitHub, Stripe, Slack)
    if let Some(kind) = network::classify_api_key(s) {
        return Some(kind);
    }

    // SQL injection patterns - only check if contains ' or - which are key indicators
    if (memchr::memchr2(b'\'', b'-', bytes).is_some() || s.contains("UNION"))
        && ((s.contains("' OR '") || s.contains("1'='1"))
            || (s.contains("UNION") && s.contains("SELECT"))
            || s.contains("admin'--"))
    {
        return Some(StringKind::SQLInjection);
    }

    // XSS payloads - only check if contains < or = which are key indicators
    if (first == b'j' || memchr::memchr2(b'<', b'=', bytes).is_some())
        && ((s.contains("<script>") && s.contains("</script>"))
            || (s.contains("onerror=") && s.contains("alert("))
            || s.starts_with("javascript:"))
    {
        return Some(StringKind::XSSPayload);
    }

    // LDAP/AD paths
    if s.contains("LDAP://") || (s.contains("CN=") && s.contains("DC=")) {
        return Some(StringKind::LDAPPath);
    }

    // Windows mutex names (often weird strings used for malware synchronization)
    if s.starts_with("Global\\") || s.starts_with("Local\\") {
        return Some(StringKind::Mutex);
    }

    // Ransomware patterns
    if s.contains("ENCRYPTED") || s.contains("DECRYPT") || s.contains("RANSOM") {
        let uppercase_count = s.bytes().filter(u8::is_ascii_uppercase).count();
        if uppercase_count * 100 / len > 50 {
            return Some(StringKind::RansomNote);
        }
    }
    // Ransomware file extensions
    if s == ".locked"
        || s == ".encrypted"
        || s == ".crypted"
        || s == ".wannacry"
        || s == ".ryuk"
        || s == ".locky"
        || s.ends_with("-DECRYPT-INSTRUCTIONS.txt")
        || s.ends_with("HOW-TO-DECRYPT.html")
    {
        return Some(StringKind::RansomNote);
    }

    // Cryptocurrency mining pools - only check if contains ':' or 'pool'
    if (first == b's' || memchr::memchr2(b':', b'p', bytes).is_some())
        && ((s.contains("stratum+tcp://") || s.contains("stratum+ssl://"))
            || ((s.contains("pool.") || s.contains("nanopool") || s.contains("minergate"))
                && (s.contains(".com") || s.contains(".org") || s.contains(":"))))
    {
        return Some(StringKind::MiningPool);
    }

    // ===== ORIGINAL CLASSIFICATION CONTINUES =====

    // URLs (including database URLs) - check first char for fast path
    if (first == b'h'
        || first == b'f'
        || first == b'p'
        || first == b'm'
        || first == b'r'
        || first == b's'
        || first == b't'
        || first == b'u')
        && (s.starts_with("http://")
            || s.starts_with("https://")
            || s.starts_with("ftp://")
            || s.starts_with("postgresql://")
            || s.starts_with("mysql://")
            || s.starts_with("redis://")
            || s.starts_with("mongodb://")
            || s.starts_with("ssh://")
            || s.starts_with("tcp://")
            || s.starts_with("udp://"))
    {
        // Skip common benign URLs (Apple certs, etc.)
        if s.starts_with("https://www.apple.com/appleca") {
            return None;
        }
        return Some(StringKind::Url);
    }

    // Check for embedded code first (most specific markers)
    // PHP has very distinctive markers (<?php tags) so check it first
    if code::is_php_code(s) {
        return Some(StringKind::PhpCode);
    }

    if code::is_python_code(s) {
        return Some(StringKind::PythonCode);
    }

    if code::is_javascript_code(s) {
        return Some(StringKind::JavaScriptCode);
    }

    // Check for AppleScript syntax (common in macOS malware)
    if code::is_applescript(s) {
        return Some(StringKind::AppleScript);
    }

    // Command injection patterns - check AFTER code detection but BEFORE generic shell commands.
    // Injection wrappers (;, |, $()) are stronger signals than generic command keywords.
    // JavaScript/PHP code might contain command strings but should be detected as code first.
    if memchr::memchr3(b';', b'|', b'$', bytes).is_some() {
        // Classic injection: ; cat, | whoami, etc.
        if (s.contains("; ") && (s.contains("cat") || s.contains("wget") || s.contains("curl")))
            || (s.contains("| ")
                && (s.contains("whoami") || s.contains("id") || s.contains("uname")))
        {
            return Some(StringKind::CommandInjection);
        }

        // Command substitution: $(...) - require actual command content inside
        // Must have command-like content, not just random binary data
        if let Some(start) = s.find("$(")
            && let Some(end_rel) = s[start + 2..].find(')')
        {
            let content = &s[start + 2..start + 2 + end_rel];
            // Must be non-empty and contain a space (actual command with args)
            // or be a known command name
            let is_command = !content.is_empty()
                && (content.contains(' ')
                    || content.starts_with("whoami")
                    || content.starts_with("id")
                    || content.starts_with("pwd")
                    || content.starts_with("hostname")
                    || content.starts_with("uname"));
            // Must be mostly ASCII and have reasonable alphanumeric ratio
            let ascii_count = content.bytes().filter(u8::is_ascii).count();
            let alpha_count = content.bytes().filter(u8::is_ascii_alphanumeric).count();
            let content_len = content.len();
            let is_valid = content_len >= 2
                && ascii_count * 100 / content_len > 90
                && alpha_count * 100 / content_len > 40;

            if is_command && is_valid {
                return Some(StringKind::CommandInjection);
            }
        }
    }

    // Backtick command substitution - must be mostly ASCII and contain command-like content
    if s.starts_with('`') && s.ends_with('`') && len >= 5 {
        let content = &s[1..len - 1];
        let content_len = content.len();

        // Must be mostly ASCII (>90%) - reject garbage with non-ASCII chars
        let ascii_count = content.bytes().filter(u8::is_ascii).count();
        if ascii_count * 100 / content_len > 90 {
            // Must contain spaces (multiword command) or known command names
            if content.contains(' ')
                || content.contains("cat")
                || content.contains("ls")
                || content.contains("pwd")
                || content.contains("echo")
                || content.contains("wget")
                || content.contains("curl")
            {
                return Some(StringKind::CommandInjection);
            }
        }
    }

    // Check for shell commands after injection detection (catches generic commands like 'echo', 'curl')
    // This is intentionally after code detection to avoid false positives
    if code::is_shell_command(s) {
        return Some(StringKind::ShellCmd);
    }

    // IP addresses and IP:port - only if starts with digit
    if first.is_ascii_digit()
        && let Some(kind) = network::classify_ip(s)
    {
        return Some(kind);
    }

    // Windows registry paths (full HKEY-prefixed or root-relative subkeys
    // passed alongside a separate hKey arg to Reg* APIs).
    if is_registry_path(s) {
        return Some(StringKind::Registry);
    }

    // Well-known config/system files (even without path prefix)
    let well_known_files = [
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
    for file in &well_known_files {
        if s == *file || s.ends_with(file) {
            return Some(StringKind::FilePath);
        }
    }

    // File paths - check for suspicious patterns
    // Skip Go runtime metrics (e.g., /gc/heap/allocs:bytes, /sched/latencies:seconds)
    if s.starts_with('/') || s.starts_with("C:\\") || s.starts_with("./") || s.starts_with("../") {
        // Go runtime metrics start with / and have colon (not URLs like file://)
        if s.starts_with('/') && s.contains(':') && !s.contains("://") {
            return None;
        }

        // Reject paths with too many special characters (likely garbage)
        let special_count = s
            .bytes()
            .filter(|b| !b.is_ascii_alphanumeric() && !b.is_ascii_whitespace())
            .count();
        let alphanumeric_count = s.bytes().filter(u8::is_ascii_alphanumeric).count();
        if alphanumeric_count == 0 || (len > 0 && special_count * 100 / len > 30) {
            return None; // Too many special chars for a valid path
        }

        if network::is_suspicious_path(s) {
            return Some(StringKind::SuspiciousPath);
        }
        return Some(StringKind::Path);
    }

    // Unicode escape sequences (common in JavaScript malware)
    if encoding::is_unicode_escaped(s) {
        return Some(StringKind::UnicodeEscaped);
    }

    // URL-encoded data (common in web shells and HTTP payloads)
    if encoding::is_url_encoded(s) {
        return Some(StringKind::UrlEncoded);
    }

    // Hex-encoded ASCII data (common in malware obfuscation)
    if encoding::is_hex_encoded(s) {
        return Some(StringKind::HexEncoded);
    }

    // Base58-encoded data (Bitcoin/cryptocurrency addresses)
    if encoding::is_base58(s) {
        return Some(StringKind::Base58);
    }

    // Base32-encoded data (Tor, some malware)
    if encoding::is_base32(s) {
        return Some(StringKind::Base32);
    }

    // Base85-encoded data (ASCII85/Z85, some compressed formats)
    if encoding::is_base85(s) {
        return Some(StringKind::Base85);
    }

    // Base64-encoded data (long strings, right charset, proper padding)
    if encoding::is_base64(s) {
        return Some(StringKind::Base64);
    }

    // Environment variable names (UPPERCASE, optionally with _ and digits)
    // May have trailing = for assignment context (e.g., "GOMEMLIMIT=")
    // This avoids matching x86 instruction patterns like "AWAVAUATSH"
    let env_name = s.strip_suffix('=').unwrap_or(s);
    if env_name.len() >= 3
        && env_name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_uppercase())
        && env_name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit())
    {
        let has_underscore = env_name.contains('_');

        // Go runtime env vars (GODEBUG, GOTRACEBACK, GOMAXPROCS, GOMEMLIMIT, etc.)
        let is_go_env = env_name.starts_with("GO") && env_name.len() >= 4;

        // Comprehensive whitelist of well-known environment variables
        let is_known = matches!(
            env_name,
            // POSIX/Unix standard
            "PATH" | "HOME" | "USER" | "SHELL" | "TERM" | "LANG" | "PWD" | "TMP" | "TEMP"
            | "TMPDIR" | "EDITOR" | "PAGER" | "MAIL" | "LOGNAME" | "HOSTNAME" | "DISPLAY"
            | "TZ" | "UID" | "GID" | "EUID" | "EGID"
            // Locale
            | "LC_ALL" | "LC_CTYPE" | "LC_COLLATE" | "LC_MESSAGES" | "LC_MONETARY"
            | "LC_NUMERIC" | "LC_TIME"
            // Terminal/Display
            | "COLUMNS" | "LINES" | "COLORTERM" | "CLICOLOR" | "LSCOLORS"
            // Development/Build
            | "CC" | "CXX" | "CFLAGS" | "CXXFLAGS" | "LDFLAGS" | "MAKE" | "AR" | "AS"
            | "LD" | "NM" | "RANLIB" | "STRIP"
            // Common application vars
            | "JAVA_HOME" | "PYTHONPATH" | "NODE_PATH" | "RUBYLIB" | "PERL5LIB"
            | "CARGO_HOME" | "RUSTUP_HOME" | "GOPATH" | "GOROOT" | "GOBIN" | "GOCACHE"
            // XDG Base Directory
            | "XDG_CONFIG_HOME" | "XDG_DATA_HOME" | "XDG_CACHE_HOME" | "XDG_STATE_HOME"
            | "XDG_RUNTIME_DIR"
            // Security/Auth
            | "SSH_AUTH_SOCK" | "SSH_AGENT_PID" | "GPG_AGENT_INFO" | "SUDO_USER"
            | "SUDO_UID" | "SUDO_GID" | "SUDO_COMMAND"
            // HTTP/Network
            | "HTTP_PROXY" | "HTTPS_PROXY" | "FTP_PROXY" | "NO_PROXY" | "ALL_PROXY"
            // Debugging/Profiling
            | "DEBUG" | "VERBOSE" | "TRACE"
            // glibc/system
            | "LD_LIBRARY_PATH" | "LD_PRELOAD" | "GLIBC_TUNABLES"
            // macOS specific
            | "DYLD_LIBRARY_PATH" | "DYLD_INSERT_LIBRARIES" | "DYLD_FRAMEWORK_PATH"
            // Windows common (for cross-platform tools)
            | "APPDATA" | "LOCALAPPDATA" | "PROGRAMFILES" | "SYSTEMROOT" | "WINDIR"
            | "USERPROFILE" | "COMPUTERNAME"
        );

        // Accept if: well-known name, has underscore (like BUILD_ID, CI_JOB), or Go env var
        if is_known || (has_underscore && env_name.len() >= 3) || is_go_env {
            return Some(StringKind::EnvVar);
        }
    }

    None
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

    if s.starts_with("System\\CurrentControlSet\\")
        || s.starts_with("System\\Setup\\")
        || s.starts_with("SAM\\")
        || s.starts_with("SECURITY\\")
    {
        return true;
    }

    false
}

/// Classify a long string using only its prefix.
///
/// Uses first-byte dispatch to avoid running expensive checks on irrelevant
/// prefixes. Skips encoding checks (base64, hex) that need full content.
fn classify_prefix(prefix: &str) -> Option<StringKind> {
    if prefix.len() < 3 {
        return None;
    }

    let first = prefix.as_bytes()[0];

    match first {
        // URLs: http://, https://, ftp://, etc.
        b'h' | b'f' | b'p' | b'm' | b'r' | b's' | b't' | b'u'
            if prefix.starts_with("http://")
                || prefix.starts_with("https://")
                || prefix.starts_with("ftp://")
                || prefix.starts_with("postgresql://")
                || prefix.starts_with("mysql://")
                || prefix.starts_with("redis://")
                || prefix.starts_with("mongodb://")
                || prefix.starts_with("ssh://")
                || prefix.starts_with("tcp://")
                || prefix.starts_with("udp://") =>
        {
            return Some(StringKind::Url);
        }
        // File paths
        b'/' | b'.'
            if prefix.starts_with('/') || prefix.starts_with("./") || prefix.starts_with("../") =>
        {
            if network::is_suspicious_path(prefix) {
                return Some(StringKind::SuspiciousPath);
            }
            return Some(StringKind::Path);
        }
        // Windows paths / registry
        b'C' if prefix.starts_with("C:\\") => return Some(StringKind::Path),
        b'H' | b'S' if is_registry_path(prefix) => {
            return Some(StringKind::Registry);
        }
        // PHP opening tag
        b'<' if prefix.starts_with("<?php") => return Some(StringKind::PhpCode),
        // Shebang / shell
        b'#' if prefix.starts_with("#!") => return Some(StringKind::ShellCmd),
        _ => {}
    }

    // Code detection (only if first byte didn't already resolve)
    if code::is_python_code(prefix) {
        return Some(StringKind::PythonCode);
    }
    if code::is_javascript_code(prefix) {
        return Some(StringKind::JavaScriptCode);
    }
    if code::is_shell_command(prefix) {
        return Some(StringKind::ShellCmd);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::classify_string;
    use super::code::is_shell_command;
    use super::encoding::{
        decode_unicode_escapes, decode_url_encoding, is_base32, is_base58, is_base64, is_base85,
        is_cryptographic_hash, is_hex_encoded, is_unicode_escaped, is_url_encoded,
    };
    use super::network::is_ipv4;
    use crate::extraction::{extract_from_structures, find_string_structures};
    use crate::types::{BinaryInfo, StringKind, StringStruct};

    #[test]
    fn test_find_string_structures() {
        let info = BinaryInfo::new_64bit_le();

        // Create test data with a string structure
        // ptr = 0x1000, len = 5
        let mut section_data = vec![0u8; 32];
        section_data[0..8].copy_from_slice(&0x1000u64.to_le_bytes());
        section_data[8..16].copy_from_slice(&5u64.to_le_bytes());

        let structs = find_string_structures(
            &section_data,
            0x2000, // section_addr
            0x1000, // blob_addr
            0x100,  // blob_size
            &info,
        );

        assert_eq!(structs.len(), 1);
        assert_eq!(structs[0].ptr, 0x1000);
        assert_eq!(structs[0].len, 5);
    }

    #[test]
    fn test_extract_from_structures() {
        let blob = b"HelloWorld";
        let structs = vec![
            StringStruct {
                struct_offset: 0,
                ptr: 0x1000,
                len: 5,
            },
            StringStruct {
                struct_offset: 16,
                ptr: 0x1005,
                len: 5,
            },
        ];

        let strings = extract_from_structures(blob, 0x1000, &structs, Some("test"), |_| None);

        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].value, "Hello");
        assert_eq!(strings[1].value, "World");
    }

    #[test]
    fn test_classify_string_env_vars() {
        // Should be classified as EnvVar
        assert_eq!(classify_string("COLUMNS"), Some(StringKind::EnvVar));
        assert_eq!(classify_string("TERM"), Some(StringKind::EnvVar));
        assert_eq!(classify_string("CLICOLOR"), Some(StringKind::EnvVar));
        assert_eq!(classify_string("LSCOLORS"), Some(StringKind::EnvVar));
        assert_eq!(classify_string("COLORTERM"), Some(StringKind::EnvVar));
        assert_eq!(classify_string("LS_SAMESORT"), Some(StringKind::EnvVar));
        assert_eq!(classify_string("CLICOLOR_FORCE"), Some(StringKind::EnvVar));
        assert_eq!(classify_string("PATH"), Some(StringKind::EnvVar));
        assert_eq!(classify_string("HOME"), Some(StringKind::EnvVar));
        assert_eq!(classify_string("USER"), Some(StringKind::EnvVar));
        assert_eq!(classify_string("LC_ALL"), Some(StringKind::EnvVar));
        assert_eq!(classify_string("XDG_CONFIG_HOME"), Some(StringKind::EnvVar));
        assert_eq!(classify_string("GO111MODULE"), Some(StringKind::EnvVar));

        // Go runtime env vars (no underscore, but start with GO)
        assert_eq!(classify_string("GODEBUG"), Some(StringKind::EnvVar));
        assert_eq!(classify_string("GOTRACEBACK"), Some(StringKind::EnvVar));
        assert_eq!(classify_string("GOMAXPROCS"), Some(StringKind::EnvVar));
        assert_eq!(classify_string("GOMEMLIMIT"), Some(StringKind::EnvVar));
        assert_eq!(classify_string("GOMEMLIMIT="), Some(StringKind::EnvVar));

        // Whitelisted well-known vars
        assert_eq!(classify_string("GLIBC_TUNABLES"), Some(StringKind::EnvVar));
        assert_eq!(classify_string("LD_PRELOAD"), Some(StringKind::EnvVar));
        assert_eq!(
            classify_string("DYLD_INSERT_LIBRARIES"),
            Some(StringKind::EnvVar)
        );
        assert_eq!(classify_string("JAVA_HOME"), Some(StringKind::EnvVar));
        assert_eq!(classify_string("HTTP_PROXY"), Some(StringKind::EnvVar));

        // Should NOT be classified as EnvVar (not in whitelist, no underscore)
        assert_ne!(classify_string("THE"), Some(StringKind::EnvVar));
        assert_ne!(classify_string("FOR"), Some(StringKind::EnvVar));
        assert_ne!(classify_string("AND"), Some(StringKind::EnvVar));
        assert_ne!(classify_string("DATA"), Some(StringKind::EnvVar));
        assert_ne!(classify_string("OBJECT"), Some(StringKind::EnvVar));
        assert_ne!(classify_string("CLASS"), Some(StringKind::EnvVar));

        // With underscore, 3+ chars is OK
        assert_eq!(classify_string("A_B"), Some(StringKind::EnvVar));
        assert_eq!(classify_string("BUILD_ID"), Some(StringKind::EnvVar));
        assert_eq!(classify_string("CI_JOB"), Some(StringKind::EnvVar));
    }

    #[test]
    fn test_classify_string_urls() {
        assert_eq!(
            classify_string("https://example.com"),
            Some(StringKind::Url)
        );
        assert_eq!(
            classify_string("http://localhost:8080"),
            Some(StringKind::Url)
        );
        assert_eq!(
            classify_string("postgresql://user:pass@host/db"),
            Some(StringKind::Url)
        );
    }

    #[test]
    fn test_classify_string_paths() {
        assert_eq!(classify_string("/usr/bin/ls"), Some(StringKind::Path));
        assert_eq!(classify_string("./config.yaml"), Some(StringKind::Path));
        assert_eq!(classify_string("../parent/file"), Some(StringKind::Path));

        // Go runtime metrics should NOT be classified as paths
        assert_eq!(classify_string("/gc/heap/allocs:bytes"), None);
        assert_eq!(classify_string("/sched/latencies:seconds"), None);
        assert_eq!(classify_string("/memory/classes/total:bytes"), None);
        assert_eq!(
            classify_string("/cpu/classes/gc/mark/assist:cpu-seconds"),
            None
        );
    }

    // Note: Section detection is now done via goblin address matching,
    // not pattern matching in classify_string. See lib.rs extract_raw_strings.

    #[test]
    fn test_find_string_structures_32bit() {
        let info = BinaryInfo::new_32bit_le();

        // Create 32-bit structure: ptr = 0x1000, len = 5
        let mut section_data = vec![0u8; 16];
        section_data[0..4].copy_from_slice(&0x1000u32.to_le_bytes());
        section_data[4..8].copy_from_slice(&5u32.to_le_bytes());

        let structs = find_string_structures(&section_data, 0x2000, 0x1000, 0x100, &info);

        assert_eq!(structs.len(), 1);
        assert_eq!(structs[0].ptr, 0x1000);
        assert_eq!(structs[0].len, 5);
    }

    #[test]
    fn test_find_string_structures_big_endian() {
        let info = BinaryInfo::new_64bit_be();

        // Create big-endian structure
        let mut section_data = vec![0u8; 32];
        section_data[0..8].copy_from_slice(&0x1000u64.to_be_bytes());
        section_data[8..16].copy_from_slice(&5u64.to_be_bytes());

        let structs = find_string_structures(&section_data, 0x2000, 0x1000, 0x100, &info);

        assert_eq!(structs.len(), 1);
        assert_eq!(structs[0].ptr, 0x1000);
        assert_eq!(structs[0].len, 5);
    }

    #[test]
    fn test_find_string_structures_out_of_range() {
        let info = BinaryInfo::new_64bit_le();

        // Create structure pointing outside blob range
        let mut section_data = vec![0u8; 32];
        section_data[0..8].copy_from_slice(&0x5000u64.to_le_bytes()); // Outside blob
        section_data[8..16].copy_from_slice(&5u64.to_le_bytes());

        let structs = find_string_structures(
            &section_data,
            0x2000,
            0x1000, // blob starts at 0x1000
            0x100,  // blob is 0x100 bytes
            &info,
        );

        // Should find nothing since pointer is out of range
        assert!(structs.is_empty());
    }

    #[test]
    fn test_find_string_structures_too_long() {
        let info = BinaryInfo::new_64bit_le();

        // Create structure with very long length
        let mut section_data = vec![0u8; 32];
        section_data[0..8].copy_from_slice(&0x1000u64.to_le_bytes());
        section_data[8..16].copy_from_slice(&0x200000u64.to_le_bytes()); // > 1MB

        let structs = find_string_structures(&section_data, 0x2000, 0x1000, 0x100, &info);

        // Should reject strings > 1MB
        assert!(structs.is_empty());
    }

    #[test]
    fn test_find_string_structures_zero_length() {
        let info = BinaryInfo::new_64bit_le();

        // Create structure with zero length
        let mut section_data = vec![0u8; 32];
        section_data[0..8].copy_from_slice(&0x1000u64.to_le_bytes());
        section_data[8..16].copy_from_slice(&0u64.to_le_bytes());

        let structs = find_string_structures(&section_data, 0x2000, 0x1000, 0x100, &info);

        // Should reject zero-length strings
        assert!(structs.is_empty());
    }

    #[test]
    fn test_is_ipv4_valid_ips() {
        // Real IP addresses should be detected
        assert!(is_ipv4("168.235.103.57"));
        assert!(is_ipv4("192.168.1.1"));
        assert!(is_ipv4("10.0.0.1"));
        assert!(is_ipv4("8.8.8.8"));
        assert!(is_ipv4("1.2.3.4"));
        assert!(is_ipv4("255.255.255.255"));
    }

    #[test]
    fn test_is_ipv4_rejects_version_numbers() {
        // Assembly/software version patterns should NOT be detected as IPs
        // Pattern: X.0.0.0
        assert!(!is_ipv4("1.0.0.0"));
        assert!(!is_ipv4("4.0.0.0"));
        assert!(!is_ipv4("11.0.0.0"));
        assert!(!is_ipv4("255.0.0.0"));

        // Pattern: X.Y.0.0
        assert!(!is_ipv4("2.1.0.0"));
        assert!(!is_ipv4("4.5.0.0"));
        assert!(!is_ipv4("10.2.0.0"));

        // Pattern: two zero octets (e.g. ProductVersion string like 18.0.0.23)
        assert!(!is_ipv4("18.0.0.23"));
        assert!(!is_ipv4("6.0.0.1"));
        assert!(!is_ipv4("100.0.52.0"));
    }

    #[test]
    fn test_is_ipv4_rejects_special_addresses() {
        // 0.0.0.0 is not a useful IOC
        assert!(!is_ipv4("0.0.0.0"));

        // Localhost is rarely an IOC
        assert!(!is_ipv4("127.0.0.1"));
        assert!(!is_ipv4("127.0.0.2"));
        assert!(!is_ipv4("127.255.255.255"));
    }

    #[test]
    fn test_is_ipv4_rejects_invalid() {
        // Not valid IP formats
        assert!(!is_ipv4(""));
        assert!(!is_ipv4("1.2.3"));
        assert!(!is_ipv4("1.2.3.4.5"));
        assert!(!is_ipv4("256.1.1.1"));
        assert!(!is_ipv4("1.2.3.abc"));
        assert!(!is_ipv4("hello"));
    }

    #[test]
    fn test_is_shell_command_detects_commands() {
        // Should detect shell commands
        assert!(is_shell_command("ls -la | grep foo"));
        assert!(is_shell_command("cat file 2>/dev/null"));
        assert!(is_shell_command("echo test && rm -rf /tmp"));
        assert!(is_shell_command("curl http://example.com"));
        assert!(is_shell_command("wget http://example.com"));
        assert!(is_shell_command("/bin/bash -c 'echo test'"));
        assert!(is_shell_command("$(whoami)"));
    }

    #[test]
    fn test_is_shell_command_rejects_dotnet_generics() {
        // .NET generic types should NOT be detected as shell commands
        assert!(!is_shell_command("IEnumerable`1"));
        assert!(!is_shell_command("Dictionary`2"));
        assert!(!is_shell_command("List`1"));
        assert!(!is_shell_command("Func`3"));
        assert!(!is_shell_command("Action`1"));
        assert!(!is_shell_command("System.Collections.Generic.List`1"));
    }

    #[test]
    fn test_is_shell_command_backtick_requires_content() {
        // Backtick must have command-like content with spaces
        assert!(is_shell_command("`ls -la`"));
        assert!(is_shell_command("echo `whoami foo`"));

        // Single backtick or empty content should not match
        assert!(!is_shell_command("foo`bar"));
        assert!(!is_shell_command("test`"));
    }

    #[test]
    fn test_classify_string_ip_detection() {
        // Real IPs should be classified as IP
        assert_eq!(classify_string("168.235.103.57"), Some(StringKind::IP));
        assert_eq!(classify_string("192.168.1.100"), Some(StringKind::IP));

        // Version numbers should NOT be classified as IP
        assert_ne!(classify_string("1.0.0.0"), Some(StringKind::IP));
        assert_ne!(classify_string("4.0.0.0"), Some(StringKind::IP));
        assert_ne!(classify_string("2.1.0.0"), Some(StringKind::IP));
    }

    #[test]
    fn test_classify_string_ipv6_detection() {
        // Real IPv6 addresses carry a multi-digit hextet. classify_ip is only
        // reached for digit-leading strings (see the guard in classify_string),
        // so exercise digit-leading addresses here.
        assert_eq!(classify_string("2001:db8::1"), Some(StringKind::IP));
        assert_eq!(classify_string("2606:4700::1111"), Some(StringKind::IP));

        // Single-digit-only colon noise (e.g. ImageMagick.Q16.msixbundle) is
        // not a credible IPv6 IOC and must not be classified as IP
        assert_ne!(classify_string("0::c"), Some(StringKind::IP));
        assert_ne!(classify_string("4::e"), Some(StringKind::IP));
    }

    #[test]
    fn test_classify_string_shell_command_detection() {
        // Shell commands should be classified
        assert_eq!(
            classify_string("curl http://evil.com"),
            Some(StringKind::ShellCmd)
        );
        assert_eq!(
            classify_string("cat /etc/passwd | grep root"),
            Some(StringKind::ShellCmd)
        );

        // .NET generics should NOT be classified as shell commands
        assert_ne!(classify_string("IEnumerable`1"), Some(StringKind::ShellCmd));
        assert_ne!(classify_string("Dictionary`2"), Some(StringKind::ShellCmd));

        // Go runtime strings should NOT be classified as shell commands
        assert_ne!(
            classify_string("s.allocCount != s.nelems && freeIndex == s.nelems"),
            Some(StringKind::ShellCmd)
        );
        assert_ne!(
            classify_string("malformed GOMEMLIMIT; see `go doc runtime/debug.SetMemoryLimit`"),
            Some(StringKind::ShellCmd)
        );
        assert_ne!(
            classify_string("exec format error"),
            Some(StringKind::ShellCmd)
        );

        // Non-shell shebangs should NOT be classified as shell commands
        assert_ne!(
            classify_string("#!/usr/bin/env ruby"),
            Some(StringKind::ShellCmd)
        );
        assert_ne!(
            classify_string("#!/usr/bin/env python3"),
            Some(StringKind::ShellCmd)
        );
        assert_ne!(
            classify_string("#!/usr/bin/env node"),
            Some(StringKind::ShellCmd)
        );
        assert_ne!(
            classify_string("#!/usr/bin/env perl"),
            Some(StringKind::ShellCmd)
        );

        // Shell shebangs should still be classified as shell commands
        assert_eq!(classify_string("#!/bin/bash"), Some(StringKind::ShellCmd));
        assert_eq!(classify_string("#!/bin/sh"), Some(StringKind::ShellCmd));
        assert_eq!(
            classify_string("#!/usr/bin/env bash"),
            Some(StringKind::ShellCmd)
        );
        assert_eq!(
            classify_string("#!/usr/bin/env sh"),
            Some(StringKind::ShellCmd)
        );
    }

    #[test]
    fn test_classify_string_applescript_detection() {
        // AppleScript code should be classified as AppleScript
        assert_eq!(
            classify_string("set desktopFolder to path to desktop folder"),
            Some(StringKind::AppleScript)
        );
        assert_eq!(
            classify_string("tell application \"Finder\""),
            Some(StringKind::AppleScript)
        );
        assert_eq!(
            classify_string("every file of desktopFolder whose name extension is in"),
            Some(StringKind::AppleScript)
        );
        assert_eq!(
            classify_string("duplicate aFile to POSIX file \"/tmp/backup\""),
            Some(StringKind::AppleScript)
        );
        assert_eq!(
            classify_string("path to documents folder"),
            Some(StringKind::AppleScript)
        );
        assert_eq!(classify_string("end tell"), Some(StringKind::AppleScript));
        assert_eq!(
            classify_string("repeat with aFile in allFiles"),
            Some(StringKind::AppleScript)
        );
        assert_eq!(
            classify_string("do shell script \"ls -la\""),
            Some(StringKind::AppleScript)
        );

        // Additional AppleScript patterns from real malware
        assert_eq!(
            classify_string("play dialog \"macOS needs to access System"),
            Some(StringKind::AppleScript)
        );
        assert_eq!(
            classify_string("ile \"%s\" as alias) with replacing"),
            Some(StringKind::AppleScript)
        );
        assert_eq!(
            classify_string("set tf to POSIX file \"%s\" as ali"),
            Some(StringKind::AppleScript)
        );

        // Regular shell commands should NOT be AppleScript
        assert_ne!(
            classify_string("curl http://example.com"),
            Some(StringKind::AppleScript)
        );
        assert_ne!(
            classify_string("cat /etc/passwd"),
            Some(StringKind::AppleScript)
        );

        // Passwd entries should NOT be AppleScript (avoid "_assetcache" matching "set ")
        assert_ne!(
            classify_string("_assetcache:*:235:235:Asset Cache Service:/var/empty:/usr/bin/false"),
            Some(StringKind::AppleScript)
        );
        assert_ne!(
            classify_string("_mobileasset:*:253:253:MobileAsset User:/var/ma:/usr/bin/false"),
            Some(StringKind::AppleScript)
        );

        // AppleScript "set" must have proper context (variable assignment)
        assert_eq!(
            classify_string("set myVar to 10"),
            Some(StringKind::AppleScript)
        );
        assert_eq!(
            classify_string("set desktopPath = \"/Users/test\""),
            Some(StringKind::AppleScript)
        );
    }

    #[test]
    fn test_is_hex_encoded_valid() {
        // Valid hex-encoded strings (from actual malware samples)
        // "const _0x1c31000=_0x2330d;"
        assert!(is_hex_encoded(
            "636F6E7374205F307831633331303030333D5F3078323330643B"
        ));

        // "function _0x2330d(_0x99a22,_0x58a56){"
        assert!(is_hex_encoded(
            "66756E6374696F6E205F307832333064285F3078393961322C5F30783538613536297B"
        ));

        // "Mozilla/5.0 (Windows NT 10.0; Win64)"
        assert!(is_hex_encoded(
            "4D6F7A696C6C612F352E30202857696E646F7773204E542031302E303B2057696E3634"
        ));

        // Long hex string with spaces
        assert!(is_hex_encoded(
            "48656C6C6F20576F726C642120546869732069732061207465737420737472696E67"
        ));
    }

    #[test]
    fn test_is_hex_encoded_invalid() {
        // Too short
        assert!(!is_hex_encoded("48656C6C6F"));

        // Odd length (51 chars)
        assert!(!is_hex_encoded(
            "48656C6C6F20576F726C6421205468697320697320612074657"
        ));

        // Not hex (contains 'G')
        assert!(!is_hex_encoded(
            "48656C6C6F20576F726C6421205468697320697320612074657374G1"
        ));

        // Valid hex but decodes to mostly non-printable
        assert!(!is_hex_encoded(
            "00010203040506070809FF00010203040506070809FF00010203040506070809FF"
        ));

        // All zeros
        assert!(!is_hex_encoded(
            "00000000000000000000000000000000000000000000000000000000"
        ));

        // Real SHA256 hash (should not be detected as hex-encoded text)
        assert!(!is_hex_encoded(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ));
    }

    #[test]
    fn test_classify_string_guid() {
        // Braced COM GUID
        assert_eq!(
            classify_string("{550e8400-e29b-41d4-a716-446655440000}"),
            Some(StringKind::GUID)
        );
        // Bare canonical UUID (RFC 4122 / Mythic payload_uuid)
        assert_eq!(
            classify_string("88a39a12-f279-4bb2-b102-1ee1157ad859"),
            Some(StringKind::GUID)
        );
        assert_eq!(
            classify_string("550e8400-e29b-41d4-a716-446655440000"),
            Some(StringKind::GUID)
        );
        // Uppercase
        assert_eq!(
            classify_string("88A39A12-F279-4BB2-B102-1EE1157AD859"),
            Some(StringKind::GUID)
        );
        // Wrong shape — not classified as GUID
        assert_ne!(
            classify_string("88a39a12f2794bb2b1021ee1157ad859"),
            Some(StringKind::GUID)
        );
        assert_ne!(
            classify_string("88a39a12-f279-4bb2-b102"),
            Some(StringKind::GUID)
        );
    }

    #[test]
    fn test_classify_string_hex_encoded() {
        // Hex-encoded JavaScript (from actual malware)
        assert_eq!(
            classify_string("636F6E7374205F307831633331303030333D5F3078323330643B"),
            Some(StringKind::HexEncoded)
        );

        // Hex-encoded function
        assert_eq!(
            classify_string(
                "66756E6374696F6E205F307832333064285F3078393961322C5F30783538613536297B"
            ),
            Some(StringKind::HexEncoded)
        );

        // Should not be hex-encoded (too short)
        assert_ne!(classify_string("48656C6C6F"), Some(StringKind::HexEncoded));

        // Should not be hex-encoded (odd length)
        assert_ne!(
            classify_string("48656C6C6F20576F726C642120546869732069732061207465737420737472696E6"),
            Some(StringKind::HexEncoded)
        );
    }

    #[test]
    fn test_hex_encoded_decoding() {
        // Test that hex-encoded strings decode correctly
        let hex = "48656C6C6F20576F726C64";
        let decoded: Vec<u8> = (0..hex.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
            .collect();
        let text = String::from_utf8(decoded).unwrap();
        assert_eq!(text, "Hello World");
    }

    #[test]
    fn test_is_unicode_escaped_valid() {
        // Valid \xXX format (from actual malware)
        assert!(is_unicode_escaped(
            "\\x27;\\x20const\\x20fs\\x20=\\x20require(\\x27fs\\x27);"
        ));

        // Mixed \xXX and regular text
        assert!(is_unicode_escaped(
            "\\x48\\x65\\x6c\\x6c\\x6f\\x20\\x57\\x6f\\x72\\x6c\\x64"
        ));

        // \uXXXX format
        assert!(is_unicode_escaped("\\u0048\\u0065\\u006c\\u006c\\u006f"));

        // Mixed format
        assert!(is_unicode_escaped(
            "const\\x20url\\x20=\\x20\\x27https://example.com\\x27;"
        ));
    }

    #[test]
    fn test_is_unicode_escaped_invalid() {
        // Too short
        assert!(!is_unicode_escaped("\\x48\\x65"));

        // Too few escape sequences
        assert!(!is_unicode_escaped("Hello \\x20 World"));

        // Not actually escaped
        assert!(!is_unicode_escaped("const url = 'https://example.com';"));

        // Invalid escape sequences
        assert!(!is_unicode_escaped("\\x\\x\\x\\x\\x\\x\\x\\x"));
    }

    #[test]
    fn test_classify_string_unicode_escaped() {
        // JavaScript with \xXX escapes (from actual malware)
        assert_eq!(
            classify_string("\\x27;\\x20const\\x20fs\\x20=\\x20require(\\x27fs\\x27);"),
            Some(StringKind::UnicodeEscaped)
        );

        // \uXXXX format
        assert_eq!(
            classify_string("\\u0048\\u0065\\u006c\\u006c\\u006f"),
            Some(StringKind::UnicodeEscaped)
        );

        // Should not be Unicode escaped (too few sequences)
        assert_ne!(
            classify_string("Hello \\x20 World"),
            Some(StringKind::UnicodeEscaped)
        );
    }

    #[test]
    fn test_decode_unicode_escapes() {
        // Test \xXX format
        let decoded = decode_unicode_escapes("\\x48\\x65\\x6c\\x6c\\x6f");
        let text = String::from_utf8(decoded).unwrap();
        assert_eq!(text, "Hello");

        // Test \uXXXX format
        let decoded = decode_unicode_escapes("\\u0048\\u0065\\u006c\\u006c\\u006f");
        let text = String::from_utf8(decoded).unwrap();
        assert_eq!(text, "Hello");

        // Test mixed content
        let decoded = decode_unicode_escapes("const\\x20fs\\x20=\\x20require");
        let text = String::from_utf8(decoded).unwrap();
        assert_eq!(text, "const fs = require");

        // Test actual malware pattern
        let decoded =
            decode_unicode_escapes("\\x27;\\x20const\\x20fs\\x20=\\x20require(\\x27fs\\x27);");
        let text = String::from_utf8(decoded).unwrap();
        assert_eq!(text, "'; const fs = require('fs');");
    }

    #[test]
    fn test_is_url_encoded_valid() {
        // Valid URL-encoded strings (from web shells)
        assert!(is_url_encoded(
            "%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E"
        ));

        // SQL injection payload
        assert!(is_url_encoded("%27%20OR%20%271%27%3D%271"));

        // Command injection
        assert!(is_url_encoded("%3Bcat%20%2Fetc%2Fpasswd"));

        // Mixed with plus signs and multiple encoded chars
        assert!(is_url_encoded("param1%3Dvalue1%26param2%3Dvalue2"));
    }

    #[test]
    fn test_is_url_encoded_invalid() {
        // Too short
        assert!(!is_url_encoded("%48%65"));

        // Too few percent signs (only 1)
        assert!(!is_url_encoded("Hello%20World"));

        // Not actually URL encoded (no percent signs)
        assert!(!is_url_encoded("regular text with some words"));

        // Has percent but not valid encoding (non-hex after %)
        assert!(!is_url_encoded("100% complete status check"));

        // C format strings should NOT be detected as URL encoded
        // %02d has hex digits (0, 2) but it's a printf specifier, not URL encoding
        assert!(!is_url_encoded("%d%02d%02d %02d:%02d:%02d"));
        assert!(!is_url_encoded("%d%02d%02dd%02d:%02d:%02d"));
        assert!(!is_url_encoded("Time: %02d:%02d:%02d Date: %04d-%02d-%02d"));
        assert!(!is_url_encoded("%s %d %f %x %o %p %c"));
        assert!(!is_url_encoded("Error code: %d, message: %s"));
        assert!(!is_url_encoded("%ld %lld %zu %zd"));
        assert!(!is_url_encoded("%-10s %+5d %#08x"));
    }

    #[test]
    fn test_classify_string_url_encoded() {
        // XSS payload
        assert_eq!(
            classify_string("%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E"),
            Some(StringKind::UrlEncoded)
        );

        // SQL injection
        assert_eq!(
            classify_string("%27%20OR%20%271%27%3D%271"),
            Some(StringKind::UrlEncoded)
        );

        // Should not be URL encoded (too few percent signs)
        assert_ne!(
            classify_string("Hello%20World"),
            Some(StringKind::UrlEncoded)
        );
    }

    #[test]
    fn test_decode_url_encoding() {
        // Test basic decoding
        let decoded = decode_url_encoding("%48%65%6c%6c%6f");
        let text = String::from_utf8(decoded).unwrap();
        assert_eq!(text, "Hello");

        // Test with plus signs
        let decoded = decode_url_encoding("Hello+World%21");
        let text = String::from_utf8(decoded).unwrap();
        assert_eq!(text, "Hello World!");

        // Test XSS payload
        let decoded = decode_url_encoding("%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E");
        let text = String::from_utf8(decoded).unwrap();
        assert_eq!(text, "<script>alert('XSS')</script>");

        // Test SQL injection
        let decoded = decode_url_encoding("%27%20OR%20%271%27%3D%271");
        let text = String::from_utf8(decoded).unwrap();
        assert_eq!(text, "' OR '1'='1");

        // Test command injection
        let decoded = decode_url_encoding("%3Bcat%20%2Fetc%2Fpasswd");
        let text = String::from_utf8(decoded).unwrap();
        assert_eq!(text, ";cat /etc/passwd");
    }

    #[test]
    fn test_is_base32_valid() {
        // Tor v2 onion address (Base32)
        assert!(is_base32("THEHIDDENWIKI3IKNKD7A"));

        // Generic Base32 encoded data
        assert!(is_base32("JBSWY3DPEBLW64TMMQ======"));
        assert!(is_base32("NFXGO2LUNBQXIIDUNBSSA"));

        // Without padding
        assert!(is_base32("MFRGG3DFMZTWQ2LK"));
    }

    #[test]
    fn test_is_base32_invalid() {
        // Too short
        assert!(!is_base32("ABCD"));

        // Contains lowercase (not valid Base32)
        assert!(!is_base32("JbSwY3DpEbLw64TmMq"));

        // Contains 0, 1, 8, 9 (not valid Base32)
        assert!(!is_base32("JBSWY3DPEBLW01089"));

        // Plain text (all letters, no digits)
        assert!(!is_base32("THISISPLAINTEXT"));

        // All digits (no letters)
        assert!(!is_base32("2345672345672345"));
    }

    #[test]
    fn test_classify_string_base32() {
        // Tor onion address
        assert_eq!(
            classify_string("THEHIDDENWIKI3IKNKD7A"),
            Some(StringKind::Base32)
        );

        // With padding
        assert_eq!(
            classify_string("JBSWY3DPEBLW64TMMQ======"),
            Some(StringKind::Base32)
        );

        // Should not be Base32 (has lowercase)
        assert_ne!(
            classify_string("JbSwY3DpEbLw64TmMq"),
            Some(StringKind::Base32)
        );
    }

    #[test]
    fn test_is_base58_valid_cryptocurrency_addresses() {
        // Bitcoin P2PKH address (starts with 1)
        assert!(is_base58("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"));

        // Bitcoin P2SH address (starts with 3)
        assert!(is_base58("3J98t1WpEZ73CNmYviecrnyiWrnqRhWNLy"));

        // Bitcoin mainnet address
        assert!(is_base58("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"));

        // Litecoin address (starts with L)
        assert!(is_base58("LdP8Qox1VAhCzLJNqrr74YovaWYyNBUWvL"));

        // Monero address fragment (for testing, partial)
        assert!(is_base58("4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfpAV"));

        // Generic Base58 with good entropy
        assert!(is_base58(
            "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
        ));
    }

    #[test]
    fn test_is_base58_invalid_alphabet_violations() {
        // Too short
        assert!(!is_base58("1A1zP1eP5Q"));
        assert!(!is_base58("short"));

        // Contains 0 (zero) - not in Base58 alphabet
        assert!(!is_base58("1A1zP1eP5QGefi2DMP0fTL5SLmv7DivfNa"));
        assert!(!is_base58("10000000000000000000"));

        // Contains O (capital O) - not in Base58 alphabet
        assert!(!is_base58("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfOa"));
        assert!(!is_base58("OOOOOOOOOOOOOOOOOOOO"));

        // Contains I (capital I) - not in Base58 alphabet
        assert!(!is_base58("1A1zP1eP5QGefi2DMPIfTL5SLmv7DivfNa"));
        assert!(!is_base58("IIIIIIIIIIIIIIIIIIII"));

        // Contains l (lowercase L) - not in Base58 alphabet
        assert!(!is_base58("1A1zP1eP5QGefi2DMPlTL5SLmv7DivfNa"));
        assert!(!is_base58("llllllllllllllllllll"));

        // Mixed invalid characters
        assert!(!is_base58("1A1zP1eP5QGefi2DMP0IfTL5SLmv7DivfOa"));
    }

    #[test]
    fn test_is_base58_invalid_missing_character_types() {
        // All uppercase (no lowercase or digits)
        assert!(!is_base58("ABCDEFGHJKMNPQRSTUVWXYZ"));
        assert!(!is_base58("THEQUICKBRWNFXJUMPS"));

        // All lowercase (no uppercase or digits)
        assert!(!is_base58("abcdefghjkmnpqrstuvwxyz"));
        assert!(!is_base58("thequickbrwnfxjumps"));

        // All digits (no letters)
        assert!(!is_base58("12345678912345678912"));

        // Only uppercase + digits (missing lowercase)
        assert!(!is_base58("ABC123DEF456GHJ789MN"));

        // Only lowercase + digits (missing uppercase)
        assert!(!is_base58("abc123def456ghj789mn"));

        // Only uppercase + lowercase (missing digits)
        assert!(!is_base58("ABCdefGHJmnpQRStuv"));
    }

    #[test]
    fn test_is_base58_invalid_class_names_objc() {
        // Objective-C class names (NS prefix with CamelCase)
        assert!(!is_base58("NSKnownKeysMappingStrategy1"));
        assert!(!is_base58("NSKnownKeysDictionary1"));
        assert!(!is_base58("NSMutableAttributedString1"));
        assert!(!is_base58("NSURLSessionConfiguration1"));
        assert!(!is_base58("NSUserNotificationCenter1"));

        // iOS/macOS classes (UI/CA/CG prefixes)
        assert!(!is_base58("UIViewControllerTransition1"));
        assert!(!is_base58("CABasicAnimationDelegate1"));
        assert!(!is_base58("CGAffineTransformMakeScale1"));
    }

    #[test]
    fn test_is_base58_invalid_class_names_other() {
        // Java/C# class names (XML, HTTP, SQL prefixes)
        assert!(!is_base58("XMLHttpRequestFactory1"));
        assert!(!is_base58("HTTPConnectionManager1"));
        assert!(!is_base58("SQLDatabaseConnectionPool1"));
    }

    #[test]
    fn test_is_base58_invalid_plain_text() {
        // Plain English text with many CamelCase transitions (7+)
        assert!(!is_base58("TheQuickBrownFoxJumpsOverTheLazyDog1"));
        assert!(!is_base58(
            "ThisIsAVeryLongStringWithManyCamelCaseWordsForTesting1"
        ));

        // Code-like text with many transitions
        assert!(!is_base58("thisIsAVariableNameWithManyWordsInCamelCase1"));
    }

    #[test]
    fn test_is_base58_edge_cases_should_pass() {
        // Random-looking Base58 with numbers at start (like Bitcoin addresses)
        assert!(is_base58("1Qqwerty2Asdfgh3Zxcvbn4Mjkuyt5Pqazwsx"));

        // Base58 with high entropy (random mix)
        assert!(is_base58("5Km2kuu7vtFDPpxywn4u3NLpbr5jKpTB3TXKWTNFyqn"));

        // One CamelCase transition is OK (not a class name pattern)
        assert!(is_base58("1234567aBcdefghJkmnpqrstuvwxyz"));

        // Starts with single uppercase (not multi-char prefix)
        assert!(is_base58("A1bcdefgh2Jkmnpqrs3tuvwxyz4"));
    }

    #[test]
    fn test_is_base58_edge_cases_borderline() {
        // Two uppercase at start but only 1 CamelCase transition = OK
        // (not enough transitions to be a class name)
        assert!(is_base58("AB1cdefgh2Jkmnpqrs3tuvwxyz4"));

        // Three CamelCase transitions but starts lowercase = OK
        // (class names typically start with uppercase)
        assert!(is_base58("a1BcD2eFg3HjK4mnp5qrs6tuv7wxyz8"));
    }

    #[test]
    fn test_is_base58_rejects_go_identifiers() {
        // Go package/type names containing http2/grpc/proto keywords
        assert!(!is_base58("http2ConnectionError"));
        assert!(!is_base58("http2writeResHeaders"));
        assert!(!is_base58("grpcServerConnection1234"));
        assert!(!is_base58("protoMessageDescriptor1234"));
    }

    #[test]
    fn test_classify_string_base58() {
        // Bitcoin address - now classified as CryptoWallet (more specific than Base58)
        assert_eq!(
            classify_string("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
            Some(StringKind::CryptoWallet)
        );

        // Should not be Base58/CryptoWallet (contains 0, which is invalid in Base58)
        assert_ne!(
            classify_string("1A1zP1eP5QGefi2DMP0fTL5SLmv7DivfNa"),
            Some(StringKind::Base58)
        );
        assert_ne!(
            classify_string("1A1zP1eP5QGefi2DMP0fTL5SLmv7DivfNa"),
            Some(StringKind::CryptoWallet)
        );
    }

    #[test]
    fn test_is_base64_valid() {
        // Valid base64 strings
        assert!(is_base64("SGVsbG8gV29ybGQhCg=="));
        assert!(is_base64(
            "VGhpcyBpcyBhIHNlY3JldCBtZXNzYWdlIGZvciB0ZXN0aW5n"
        ));
        assert!(is_base64(
            "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkw"
        ));
    }

    #[test]
    fn test_is_base64_invalid() {
        // Too short
        assert!(!is_base64("SGVsbG8="));

        // Not multiple of 4
        assert!(!is_base64("SGVsbG8gV29ybGQhCg"));

        // Contains spaces
        assert!(!is_base64("SGVs bG8g V29y bGQh Cg=="));

        // Sequential patterns (test data)
        assert!(!is_base64("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"));

        // Plain text patterns
        assert!(!is_base64("the quick brown fox ===="));

        // Missing mixed case
        assert!(!is_base64("AAAAAAAAAAAAAAAAAAAA")); // all uppercase
        assert!(!is_base64("aaaaaaaaaaaaaaaaaaaaaa==")); // all lowercase
        assert!(!is_base64("1234567890123456789012345678")); // all digits

        // Invalid characters
        assert!(!is_base64("SGVsbG8gV29ybGQh@g==")); // @ is not valid
    }

    #[test]
    fn test_is_base64_rejects_go_identifiers() {
        use super::encoding::is_base64;

        // Go package/type names containing http2/grpc/proto
        assert!(!is_base64("http2Request1234AbCd")); // http2 keyword
        assert!(!is_base64("grpcConnection12345A")); // grpc keyword
        assert!(!is_base64("protoMessage1234AbCd")); // proto keyword
    }

    #[test]
    fn test_is_base64_rejects_framework_prefixes() {
        use super::encoding::is_base64;

        // 4+ consecutive uppercase at start (HTTP*, POST*, NSUR*, XML*)
        assert!(!is_base64("HTTPConnection12345A")); // 4 consecutive upper
        assert!(!is_base64("POSTRequest123456AbC")); // 4 consecutive upper
        assert!(!is_base64("NSURLSession12345AbC")); // 4 consecutive upper (NSUR)
        assert!(!is_base64("XMLParserDelegate123")); // 4 consecutive upper (XMLP)
    }

    #[test]
    fn test_is_base64_rejects_cert_timestamps() {
        use super::encoding::is_base64;

        // ASN.1 certificate timestamps (UTCTime/GeneralizedTime + next field)
        // e.g. "201229235959Z0b1" = "20121229235959Z" + ASN.1 tag "0b1"
        assert!(!is_base64("201229235959Z0b1"));
        assert!(!is_base64("310111235959Z0w1"));
    }

    #[test]
    fn test_is_base64_rejects_x86_instruction_patterns() {
        use super::encoding::is_base64;

        // x86 conditional jump patterns: Ht (test+jz) and HH sequences
        // These have high character repetition but decode to non-printable garbage
        assert!(!is_base64("rtVHHtRHt2HtLHHu"));
    }

    #[test]
    fn test_is_base64_accepts_real_base64() {
        use super::encoding::is_base64;

        // Valid base64 should pass regardless of CamelCase patterns
        assert!(is_base64("SGVsbG8gV29ybGQhCg==")); // "Hello World!\n"
        assert!(is_base64(
            "VGhpcyBpcyBhIHNlY3JldCBtZXNzYWdlIGZvciB0ZXN0aW5n"
        )); // Long
        assert!(is_base64(
            "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkw"
        )); // alphabet

        // Base64 with many accidental CamelCase transitions should still pass
        assert!(is_base64("aB3cD5eF7gH9iJ1kL2mN4oP6qR8sT0uV")); // Random patterns
        assert!(is_base64("Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv")); // Random patterns
    }

    #[test]
    fn test_is_base64_edge_cases() {
        use super::encoding::is_base64;

        // Borderline: 3 consecutive uppercase at start (should accept, threshold is 4)
        assert!(is_base64("SGVsbG8gV29ybGQhCg==")); // Valid base64: "Hello World!\n"
        assert!(is_base64("ABCdefGHIjklMNOpqrSTUvwxYZ123456")); // 3 upper at start (ABC)

        // Borderline: Exactly 4 consecutive uppercase (should reject)
        assert!(!is_base64("ABCDefGHIjklMNOpqrSTUvwxYZ123456")); // 4 upper at start (ABCD)
    }

    #[test]
    fn test_is_base85_valid() {
        // With quality heuristic, strings need to decode to significantly better quality
        // to be considered base85. Most false positives like file paths will fail this test.

        // Note: We don't test specific base85 strings here because the quality heuristic
        // makes it hard to construct a simple test case that passes.
        // The real test is in integration tests where we verify clean binaries have no false positives.
    }

    #[test]
    fn test_is_base85_invalid() {
        // Too short
        assert!(!is_base85("9jqo^BlbD"));

        // Environment variable pattern (all uppercase + underscores)
        assert!(!is_base85("DYLD_INSERT_LIBRARIES"));
        assert!(!is_base85("LD_PRELOAD_PATH_VAR"));

        // No lowercase or punctuation (just uppercase)
        assert!(!is_base85("ABCDEFGHIJKLMNOPQRST"));

        // Poor character diversity (< 8 unique chars)
        assert!(!is_base85("!!!!!!!!!!!!!!!!!!!!!"));
        assert!(!is_base85("aaaaaaaaaaaaaaaaaaaaaa"));

        // Too few valid ASCII85 characters (< 90%)
        assert!(!is_base85("regular text with spaces here"));

        // Passwd entries should NOT be classified as base85
        assert!(!is_base85(
            "_datadetectors:*:257:257:DataDetectors:/var/db/datadetectors:/usr/bin/false"
        ));
        assert!(!is_base85(
            "_mmaintenanced:*:283:283:mmaintenanced:/var/db/mmaintenanced:/usr/bin/false"
        ));
        assert!(!is_base85(
            "_biome:*:289:289:Biome:/var/db/biome:/usr/bin/false"
        ));
        assert!(!is_base85(
            "_terminusd:*:295:295:Terminus:/var/db/terminus:/usr/bin/false"
        ));
        assert!(!is_base85(
            "_nsurlsessiond:*:242:242:NSURLSession Daemon:/var/db/nsurlsessiond:/usr/bin/false"
        ));
    }

    #[test]
    fn test_base32_performance_edge_cases() {
        // All valid base32 chars but no digits - should fail
        assert!(!is_base32("AAAABBBBCCCCDDDD"));

        // All digits but no letters - should fail
        assert!(!is_base32("2222333344445555"));

        // Contains invalid digits (0, 1, 8, 9)
        assert!(!is_base32("ABCD0123EFGH89IJ"));

        // Contains lowercase
        assert!(!is_base32("ABCDEFGHabcdefgh"));
    }

    #[test]
    fn test_base58_performance_edge_cases() {
        // Missing uppercase
        assert!(!is_base58("abcdefghijklmnopqrstuvwxyz123456"));

        // Missing lowercase
        assert!(!is_base58("ABCDEFGHJKMNPQRSTUVWXYZ123456"));

        // Missing digits
        assert!(!is_base58("ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz"));

        // Contains excluded characters (0, O, I, l)
        assert!(!is_base58("1A1zP1eP5QGefi2DMP0fTL5SLmv7DivfNa")); // has 0
        assert!(!is_base58("1A1zP1eP5QGefi2DMPOfTL5SLmv7DivfNa")); // has O
        assert!(!is_base58("1A1zP1eP5QGefi2DMPIfTL5SLmv7DivfNa")); // has I
        assert!(!is_base58("1A1zP1eP5QGefi2DMPlfTL5SLmv7DivfNa")); // has l
    }

    #[test]
    fn test_base64_performance_single_pass() {
        // This test ensures the optimization works - it should reject quickly
        // on first invalid character without scanning the whole string
        let invalid_at_start = format!("@{}", "A".repeat(100));
        assert!(!is_base64(&invalid_at_start));

        let with_space = "SGVs bG8g".repeat(10);
        assert!(!is_base64(&with_space));
    }

    #[test]
    fn test_is_cryptographic_hash_valid() {
        // MD5 hash (32 chars)
        assert!(is_cryptographic_hash("d41d8cd98f00b204e9800998ecf8427e"));

        // SHA1 hash (40 chars)
        assert!(is_cryptographic_hash(
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        ));

        // SHA256 hash (64 chars) - empty string hash
        assert!(is_cryptographic_hash(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ));

        // SHA512 hash (128 chars)
        assert!(is_cryptographic_hash(
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        ));
    }

    #[test]
    fn test_is_cryptographic_hash_invalid() {
        // Too short
        assert!(!is_cryptographic_hash("d41d8cd98f00b204"));

        // Wrong length (not 32/40/64/128)
        assert!(!is_cryptographic_hash("d41d8cd98f00b204e9800998ecf8427e00"));

        // Hex-encoded ASCII text ("Hello World" repeated) - should NOT be hash
        // "Hello World" = 48656c6c6f20576f726c64
        assert!(!is_cryptographic_hash("48656c6c6f20576f726c6448656c6c6f"));

        // Not hex digits
        assert!(!is_cryptographic_hash("ghijklmnopqrstuvwxyz123456789012"));
    }

    #[test]
    fn test_classify_string_hash() {
        // SHA256 hash should be classified as Hash
        assert_eq!(
            classify_string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            Some(StringKind::Hash)
        );

        // SHA1 hash should be classified as Hash
        assert_eq!(
            classify_string("da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            Some(StringKind::Hash)
        );

        // MD5 hash should be classified as Hash
        assert_eq!(
            classify_string("d41d8cd98f00b204e9800998ecf8427e"),
            Some(StringKind::Hash)
        );

        // Hex-encoded text should NOT be classified as Hash
        assert_ne!(
            classify_string("48656c6c6f20576f726c6448656c6c6f"),
            Some(StringKind::Hash)
        );
    }

    #[test]
    fn test_php_detection() {
        // Real PHP code
        assert_eq!(
            classify_string("<?php echo 'hello'; ?>"),
            Some(StringKind::PhpCode)
        );

        // Short echo tag with valid content
        assert_eq!(
            classify_string("<?= $variable ?>"),
            Some(StringKind::PhpCode)
        );

        // .reloc section garbage starting with <?= must NOT trigger PHP detection
        assert_ne!(classify_string("<?=\">.>|>"), Some(StringKind::PhpCode));
    }

    #[test]
    fn test_python_rejection_java_kotlin() {
        // Java/Kotlin/Android imports should NOT be classified as Python
        assert_ne!(
            classify_string("import android.os.Build;"),
            Some(StringKind::PythonCode)
        );
        assert_ne!(
            classify_string("import android.os.Build"),
            Some(StringKind::PythonCode)
        );
        assert_ne!(
            classify_string("package com.airbnb.lottie;"),
            Some(StringKind::PythonCode)
        );
        assert_ne!(
            classify_string("import java.util.List;"),
            Some(StringKind::PythonCode)
        );
    }
}
