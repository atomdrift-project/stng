//! Code pattern detection for string classification.
//!
//! Detects Python, JavaScript, PHP, AppleScript, and shell command patterns.

use super::encoding::contains_ignore_ascii_case;
use aho_corasick::AhoCorasick;
use std::sync::LazyLock;

/// AppleScript source indicators (matched case-insensitively).
#[allow(clippy::expect_used)]
static APPLESCRIPT_PATTERNS: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build([
            "tell application",
            "path to desktop",
            "path to documents",
            "every file of",
            "whose name extension",
            "posix file",
            "end tell",
            "do shell script",
            " dialog",
            "choose file",
            "choose folder",
            "duplicate ",
            " to posix file",
            "repeat with",
            "end repeat",
            " as alias",
            " with replacing",
            "set volume",
        ])
        .expect("valid applescript patterns")
});

/// Error-message patterns used to reject format-string placeholders that look
/// like shell commands (e.g. "Error: could not {0} the {1}").
#[allow(clippy::expect_used)]
static SHELL_ERROR_PATTERNS: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::new([
        "Error",
        "error",
        "Failed",
        "Could not",
        "Unable to",
        "Cannot",
        "Invalid",
        "Unsupported",
        "not supported",
        "not found",
        "access",
        "service",
        "[Click",
        "prompt",
    ])
    .expect("valid error patterns")
});

/// Comparison operators that indicate programming expressions, not shell commands.
#[allow(clippy::expect_used)]
static SHELL_COMPARISON_OPS: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::new(["!=", "==", "<=", ">="]).expect("valid comparison patterns")
});

/// Shell redirection patterns that are strong shell indicators.
#[allow(clippy::expect_used)]
static SHELL_REDIRECTS: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::new([">/dev/null", "2>/dev/null", "2>&1"]).expect("valid redirect patterns")
});

/// Shell command keywords that confirm a pipe `|` is part of a real pipeline.
#[allow(clippy::expect_used)]
static SHELL_PIPE_COMMANDS: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::new([
        "grep", "awk", "sed", "sort", "uniq", "head", "tail", "cat ", "xargs", "wc ", "cut ", "tr ",
    ])
    .expect("valid pipe-command patterns")
});

/// Trigger substrings for Python detection. A positive `is_python_code` result
/// always requires at least two of the `matches += 1` checks below to fire, and
/// every one of those checks needs one of these substrings — so a string
/// containing none of them cannot be Python. A single Aho-Corasick scan rejects
/// such strings (the overwhelming majority, e.g. Go symbol-table entries) in
/// place of ~20 sequential `contains` probes.
#[allow(clippy::expect_used)]
static PYTHON_INDICATORS: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::new([
        "import ",
        "from ",
        "def ",
        "class ",
        "exec(",
        "eval(",
        "__import__",
        "subprocess",
        "getattr(",
        "lambda ",
        "sys.",
        "os.path",
        "os.system",
        "os.environ",
        "os.name",
        "os.getcwd",
        "__name__",
    ])
    .expect("valid python indicators")
});

/// Trigger substrings for JavaScript detection. As with [`PYTHON_INDICATORS`],
/// a match needs at least two of the keyword checks, each of which requires one
/// of these substrings, so a single scan can reject everything else.
#[allow(clippy::expect_used)]
static JAVASCRIPT_INDICATORS: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::new([
        "function ",
        "const ",
        "let ",
        "var ",
        "require(",
        "document.",
        "window.",
        "console.log",
        "=>",
    ])
    .expect("valid javascript indicators")
});

/// Check if a string looks like Python code
pub(super) fn is_python_code(s: &str) -> bool {
    let len = s.len();

    // Must have some length
    if len < 8 {
        return false;
    }

    // Quick rejection: reject any string lacking a Python trigger substring.
    // See [`PYTHON_INDICATORS`] for why this preserves every positive match.
    if !PYTHON_INDICATORS.is_match(s) {
        return false;
    }

    // Reject Go symbol-table strings up-front: Go's pclntab embeds type
    // metadata like `sync/atomic.(*Pointer[go.shape.struct { os.mu sync.Mutex;
    // os.class uint32 }]).Swap` which trips the `class ` + `os.` Python
    // heuristic below. Go's symbol syntax `.(*` (pointer method), `go.shape.`,
    // and `syscall.Handle` never appear in Python source.
    if s.contains(".(*") || s.contains("go.shape.") || s.contains("syscall.Handle") {
        return false;
    }

    // Reject Java/Kotlin/Android imports and package patterns
    if (s.contains("import ") || s.contains("package "))
        && (s.contains("android.")
            || s.contains("java.")
            || s.contains("javax.")
            || s.contains("kotlin.")
            || s.contains("com.google.")
            || s.contains("org.apache."))
    {
        return false;
    }

    // Java/Kotlin imports often end with semicolon
    if s.starts_with("import ") && s.ends_with(';') {
        return false;
    }

    // HTML/Svelte/Vue component markup can contain `class ` attributes and
    // method-like expressions such as `onclick(...)` or `rgba(...)`. Those are
    // not embedded Python payloads.
    if looks_like_component_markup(s) {
        return false;
    }

    let mut matches = 0;

    // Strong Python indicators (word boundaries matter)
    if s.contains("import ") || s.starts_with("import ") {
        matches += 1;
    }
    if s.contains("from ") && s.contains(" import") {
        matches += 1;
    }
    if s.contains("def ") {
        matches += 1;
    }
    if s.contains("class ") {
        matches += 1;
    }
    if s.contains("exec(") {
        matches += 1;
    }
    if s.contains("eval(") {
        matches += 1;
    }
    // `__import__(...)` is the dynamic-import builtin — unambiguously Python and
    // a staple of `python -c` obfuscation (`getattr(__import__('os'),'system')`).
    if s.contains("__import__") {
        matches += 2;
    }
    // Python stdlib execution modules / builtins that one-liner droppers lean on
    // even without an `import os; os.system` pair.
    if s.contains("subprocess") {
        matches += 1;
    }
    if s.contains("getattr(") {
        matches += 1;
    }
    if s.contains("lambda ") {
        matches += 1;
    }
    if s.contains("sys.") {
        matches += 1;
    }
    // Refine 'os.' to avoid matching 'android.os' or 'ios'
    if s.contains("os.path")
        || s.contains("os.system")
        || s.contains("os.environ")
        || s.contains("os.name")
        || s.contains("os.getcwd")
        || (s.contains("os.") && (s.contains("import os") || s.contains("from os")))
    {
        matches += 1;
    }
    if s.contains("__name__") && s.contains("__main__") {
        matches += 1;
    }

    // Require at least 2 matches to reduce false positives
    matches >= 2
}

fn looks_like_component_markup(s: &str) -> bool {
    let trimmed = s.trim_start();
    if !(trimmed.starts_with('<') && s.contains('>')) {
        return false;
    }

    let markup_markers = [
        "<script",
        "</script",
        "<style",
        "</style",
        "<template",
        "</template",
        "<svelte:",
        "<div",
        "</div",
        "<span",
        "</span",
        "<button",
        "</button",
        " class=",
        "class=\"",
        "class='",
    ];

    markup_markers.iter().any(|marker| s.contains(marker))
}

/// Check if a string looks like JavaScript code
pub(super) fn is_javascript_code(s: &str) -> bool {
    let len = s.len();

    // Must have some length
    if len < 8 {
        return false;
    }

    // Quick rejection: reject any string lacking a JavaScript trigger
    // substring. See [`JAVASCRIPT_INDICATORS`] for why this is loss-free.
    if !JAVASCRIPT_INDICATORS.is_match(s) {
        return false;
    }

    let mut matches = 0;

    // JavaScript-specific patterns
    if s.contains("function ") {
        matches += 1;
    }
    if s.contains("const ") && s.contains(" = ") {
        matches += 1;
    }
    if s.contains("let ") && s.contains(" = ") {
        matches += 1;
    }
    if s.contains("var ") && s.contains(" = ") {
        matches += 1;
    }
    if s.contains("require(") {
        matches += 1;
    }
    if s.contains("document.") {
        matches += 1;
    }
    if s.contains("window.") {
        matches += 1;
    }
    if s.contains("console.log") {
        matches += 1;
    }
    // Arrow functions: => {
    if s.contains("=>") && s.contains("{") {
        matches += 1;
    }

    // Require at least 2 matches to reduce false positives
    matches >= 2
}

/// Check if a string looks like PHP code
pub(super) fn is_php_code(s: &str) -> bool {
    let len = s.len();

    // Must have some length
    if len < 5 {
        return false;
    }

    // Strong PHP indicators - opening tags are very distinctive
    if s.contains("<?php") {
        return true;
    }

    // Short echo tag <?= requires plausible PHP content after it.
    // Random binary data in .reloc sections can produce <?= followed by garbage
    // (e.g. `<?=">.>|>`). Require a space, letter, or $ after the tag.
    if let Some(pos) = s.find("<?=") {
        let after = &s[pos + 3..];
        if after.starts_with(|c: char| c.is_ascii_alphanumeric() || c == ' ' || c == '$') {
            return true;
        }
    }

    // Fallback: look for PHP-specific patterns
    // PHP variables always start with $, so require multiple $ signs
    let dollar_count = memchr::memchr_iter(b'$', s.as_bytes()).count();
    if dollar_count < 2 {
        return false;
    }

    let mut matches = 0;

    // PHP variable assignment: $var =
    if s.contains("$") && s.contains(" = ") {
        matches += 1;
    }

    // Common PHP obfuscation: eval(base64_decode
    if s.contains("eval") && s.contains("base64_decode") {
        matches += 1;
    }

    // PHP function with $ variable in body
    if s.contains("function ") && s.contains("$") && s.contains("{") {
        matches += 1;
    }

    // Require at least 2 matches if no PHP tags
    matches >= 2
}

/// Check if a string looks like AppleScript code
pub(super) fn is_applescript(s: &str) -> bool {
    // Quick rejection: AppleScript needs spaces and reasonable length
    if s.len() < 8 || !s.contains(' ') {
        return false;
    }

    // Quick rejection: must contain at least one common AppleScript keyword fragment
    // This avoids lowercase conversion for most strings
    let bytes = s.as_bytes();
    let has_indicator = bytes.windows(4).any(|w| {
        // Check for "tell", "path", "file", "end ", "set ", "with", "shel", "dial", "alia" (case insensitive)
        matches!(
            w,
            b"tell"
                | b"Tell"
                | b"TELL"
                | b"path"
                | b"Path"
                | b"PATH"
                | b"file"
                | b"File"
                | b"FILE"
                | b"end "
                | b"End "
                | b"END "
                | b"set "
                | b"Set "
                | b"SET "
                | b"with"
                | b"With"
                | b"WITH"
                | b"shel"
                | b"Shel"
                | b"SHEL"
                | b"dial"
                | b"Dial"
                | b"DIAL"
                | b"alia"
                | b"Alia"
                | b"ALIA"
        )
    });
    if !has_indicator {
        return false;
    }

    if APPLESCRIPT_PATTERNS.is_match(s.as_bytes()) {
        return true;
    }

    // "set " only if it appears at word boundaries and is followed by assignment.
    let bytes = s.as_bytes();
    let has_set = bytes
        .get(..4)
        .is_some_and(|p| p.eq_ignore_ascii_case(b"set "))
        || contains_ignore_ascii_case(bytes, b"\nset ")
        || contains_ignore_ascii_case(bytes, b"\tset ")
        || contains_ignore_ascii_case(bytes, b" set ");
    if has_set && (contains_ignore_ascii_case(bytes, b" to ") || s.contains('=')) {
        return true;
    }

    false
}

/// Check if a string looks like a shell command
pub(super) fn is_shell_command(s: &str) -> bool {
    let len = s.len();

    // Must have some length
    if len < 4 {
        // Shell commands are predominantly ASCII. Long strings with many non-ASCII chars
        // (like localized UI text) are almost never shell commands.
        let ascii_count = s.bytes().filter(u8::is_ascii).count();
        if len > 100 && ascii_count * 100 / len < 95 {
            return false;
        }

        return false;
    }

    // Shebang for shell interpreters is a strong indicator.
    // Only match actual shell interpreters, not #!/usr/bin/env ruby, python, etc.
    if s.starts_with("#!/bin/bash")
        || s.starts_with("#!/bin/sh")
        || s.starts_with("#!/bin/zsh")
        || s.starts_with("#!/bin/dash")
        || s.starts_with("#!/bin/ksh")
    {
        return true;
    }
    if let Some(after_env) = s.strip_prefix("#!/usr/bin/env ") {
        let interpreter = after_env.split_whitespace().next().unwrap_or("");
        if matches!(interpreter, "bash" | "sh" | "zsh" | "dash" | "ksh") {
            return true;
        }
        return false;
    }

    // Quick byte-level check: shell commands typically contain key indicators
    // If none of these bytes are present, it's very unlikely to be a shell command
    let bytes = s.as_bytes();
    let has_shell_indicators = bytes
        .iter()
        .any(|&b| matches!(b, b' ' | b'/' | b'$' | b'|' | b'&' | b'>' | b';' | b'`'));
    if !has_shell_indicators {
        return false;
    }

    // Reject common error message patterns (not shell commands)
    // Format string placeholders, error codes, UI text markers
    if s.contains("{0}") || s.contains("{1}") || s.contains("%s") || s.contains("%d") {
        // Check if it looks like an error message or UI string
        let is_error_message = SHELL_ERROR_PATTERNS.is_match(s);
        if is_error_message {
            return false;
        }
    }

    // Skip strings with error code patterns like "ABC12345:" or "TTF24041:"
    // (uppercase letters followed by digits and colon at start)
    if len >= 6 {
        let chars: Vec<char> = s.chars().take(10).collect();
        let mut has_letters = false;
        let mut has_digits = false;
        let mut found_colon = false;
        for &c in &chars {
            if c == ':' {
                found_colon = true;
                break;
            }
            if c.is_ascii_uppercase() {
                has_letters = true;
            }
            if c.is_ascii_digit() {
                has_digits = true;
            }
        }
        if has_letters && has_digits && found_colon {
            return false;
        }
    }

    // Fast path: shell commands almost always contain a space
    // Exceptions: paths like /bin/sh, command substitution $(...)
    if memchr::memchr(b' ', bytes).is_none() && !s.starts_with("/bin/") && !s.starts_with("$(") {
        return false;
    }

    // Skip if it looks like a .NET generic type (contains backtick followed by digit)
    // e.g., IEnumerable`1, Dictionary`2, etc.
    if s.contains('`') {
        // Check if it's a .NET generic pattern: Name`N where N is a digit
        let has_generic_pattern = s
            .chars()
            .zip(s.chars().skip(1))
            .any(|(a, b)| a == '`' && b.is_ascii_digit());
        if has_generic_pattern {
            return false;
        }
    }

    // Skip strings that look like code/programming expressions
    // These contain comparison operators that wouldn't appear in shell commands
    if SHELL_COMPARISON_OPS.is_match(s) {
        return false;
    }

    // Shell operators and redirects
    // Note: " | " alone is not enough - UI strings often use | as a separator
    // e.g., "Click here | Don't show again" - must have actual shell context
    if SHELL_REDIRECTS.is_match(s) {
        return true;
    }

    // Pipe requires additional shell context (command-like words around it)
    if s.contains(" | ") {
        // Check if it looks like a shell pipeline (has command-like patterns)
        let has_shell_context = SHELL_PIPE_COMMANDS.is_match(s)
            || s.starts_with("ls ")
            || s.starts_with("find ")
            || s.starts_with("ps ");
        if has_shell_context {
            return true;
        }
    }

    // && requires shell context too - common in error messages
    if s.contains(" && ") {
        // Check for actual command patterns
        let has_shell_context = s.contains("cd ") || s.contains("mkdir ") || s.contains("rm ");
        if has_shell_context {
            return true;
        }
    }

    // Command substitution: $(...) - require actual command content inside
    if let Some(start) = s.find("$(")
        && let Some(end_rel) = s[start + 2..].find(')')
    {
        let content = &s[start + 2..start + 2 + end_rel];
        // Must contain a space (actual command with args) or be a known command name
        let is_command = !content.is_empty()
            && (content.contains(' ')
                || content.starts_with("whoami")
                || content.starts_with("id")
                || content.starts_with("pwd")
                || content.starts_with("hostname")
                || content.starts_with("uname"));
        // Must be mostly ASCII with reasonable alphanumeric ratio
        let ascii_count = content.bytes().filter(u8::is_ascii).count();
        let alpha_count = content.bytes().filter(u8::is_ascii_alphanumeric).count();
        let content_len = content.len();
        if content_len >= 2
            && ascii_count * 100 / content_len > 90
            && alpha_count * 100 / content_len > 40
            && is_command
        {
            return true;
        }
    }

    // Backtick command substitution - must start with backtick and look like actual command
    // Skip documentation references like "see `go doc ...`" or inline code in error messages
    // Skip strings with escaped backticks (complicated to parse correctly)
    if s.starts_with('`')
        && !s.contains("\\`")
        && let Some(rest) = s.strip_prefix('`')
        && let Some(end) = rest.find('`')
    {
        let content = &rest[..end];
        // Must have command-like content and not look like a doc reference
        if !content.is_empty()
            && content.contains(' ')
            && !content.starts_with("go ")
            && !content.contains(" doc ")
        {
            // Must be mostly ASCII (>90%) - reject garbage with non-ASCII chars
            let ascii_count = content.bytes().filter(u8::is_ascii).count();
            let content_len = content.len();
            if content_len > 0 && ascii_count * 100 / content_len > 90 {
                return true;
            }
        }
    }

    // Common command prefixes with arguments
    // Note: "exec " removed - too many false positives with "exec format error" etc.
    let cmd_prefixes = [
        "sed ",
        "rm ",
        "kill ",
        "chmod ",
        "chown ",
        "wget ",
        "curl ",
        "bash ",
        "sh ",
        "/bin/sh",
        "/bin/bash",
        "nc ",
        "ncat ",
        "python ",
        "perl ",
        "ruby ",
        "php ",
        "echo ",
        "cat ",
        "mkdir ",
        "cp ",
        "mv ",
        "touch ",
        "tar ",
        "gzip ",
        "gunzip ",
        "base64 ",
        "openssl ",
        "dd ",
        "mount ",
        "umount ",
        "iptables ",
        "systemctl ",
        "service ",
        "crontab ",
        "useradd ",
        "userdel ",
        "passwd ",
        "sudo ",
        "su ",
        "chroot ",
        "nohup ",
        "setsid ",
        "eval ",
    ];

    for prefix in cmd_prefixes {
        if s.starts_with(prefix) {
            // Special case: "service " at start should be followed by command words
            if prefix == "service "
                && let Some(after) = s.strip_prefix(prefix)
            {
                let is_command = after.starts_with("start")
                    || after.starts_with("stop")
                    || after.starts_with("restart")
                    || after.starts_with("status")
                    || after.starts_with("enable")
                    || after.starts_with("disable");
                if !is_command {
                    continue;
                }
            }
            return true;
        }
        // Check for " prefix" pattern without allocation
        if let Some(pos) = s.find(prefix)
            && pos > 0
            && s.as_bytes()[pos - 1] == b' '
        {
            // Special case: "service " should be followed by command words, not "provider" etc.
            if prefix == "service " {
                let after = &s[pos + prefix.len()..];
                let is_command = after.starts_with("start")
                    || after.starts_with("stop")
                    || after.starts_with("restart")
                    || after.starts_with("status")
                    || after.starts_with("enable")
                    || after.starts_with("disable");
                if !is_command {
                    continue;
                }
            }
            return true;
        }
    }

    false
}

#[cfg(test)]
mod python_oneliner_tests {
    use super::is_python_code;

    /// Obfuscated `python -c` one-liner bodies must classify as Python so the
    /// embedded-code detector re-analyzes them and Python rules run.
    #[test]
    fn obfuscated_python_oneliners_are_python() {
        for s in [
            "getattr(__import__('os'), 'sy'+'stem')('bun install bad-pkg')",
            "eval('__import__(\\'os\\').system(\\'bun install bad-pkg\\')')",
            "(o:=__import__('os')).system('bun install bad-pkg')",
            "(lambda o: o.system('bun install bad-pkg'))(__import__('os'))",
            "import subprocess; subprocess.run('bun install bad-pkg', shell=True)",
            "exec(__import__('base64').b64decode('aW1wb3J0IG9z'))",
            "import os; os.system('gkp-dab llatsni nub'[::-1])",
        ] {
            assert!(is_python_code(s), "should classify as Python: {s}");
        }
    }

    /// Guard against over-classifying non-Python strings.
    #[test]
    fn non_python_strings_are_not_python() {
        for s in [
            "the quick brown fox jumps over the lazy dog today",
            "https://example.com/path/to/resource?query=value",
            "SELECT * FROM users WHERE id = 1 AND name = 'bob'",
            "<script>\n  let count = 0;\n</script>\n<button class=\"primary\" onclick={() => count += 1}>Click</button>",
        ] {
            assert!(!is_python_code(s), "should NOT classify as Python: {s}");
        }
    }
}
