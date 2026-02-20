//! Code pattern detection for string classification.
//!
//! Detects Python, JavaScript, PHP, AppleScript, and shell command patterns.

/// Check if a string looks like Python code
pub(super) fn is_python_code(s: &str) -> bool {
    let len = s.len();

    // Must have some length
    if len < 8 {
        return false;
    }

    // Quick rejection: Python code must contain certain characters
    let bytes = s.as_bytes();
    let has_python_indicators = bytes.iter().any(|&b| matches!(b, b'(' | b':' | b'.'));
    if !has_python_indicators {
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
    if s.contains("sys.") {
        matches += 1;
    }
    if s.contains("os.") {
        matches += 1;
    }
    if s.contains("__name__") && s.contains("__main__") {
        matches += 1;
    }

    // Require at least 2 matches to reduce false positives
    matches >= 2
}

/// Check if a string looks like JavaScript code
pub(super) fn is_javascript_code(s: &str) -> bool {
    let len = s.len();

    // Must have some length
    if len < 8 {
        return false;
    }

    // Quick rejection: JavaScript code must contain certain characters
    let bytes = s.as_bytes();
    let has_js_indicators = bytes
        .iter()
        .any(|&b| matches!(b, b'(' | b'{' | b'=' | b'.'));
    if !has_js_indicators {
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
    if s.contains("<?php") || s.contains("<?=") {
        return true;
    }

    // Fallback: look for PHP-specific patterns
    // PHP variables always start with $, so require multiple $ signs
    let dollar_count = s.chars().filter(|&c| c == '$').count();
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
    let lower = s.to_ascii_lowercase();

    // AppleScript indicators - using word boundaries to avoid false positives
    // "set " must be followed by a variable assignment context, not just appear in a word
    let applescript_patterns = [
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
    ];

    for pattern in &applescript_patterns {
        if lower.contains(pattern) {
            return true;
        }
    }

    // "set " only if it appears at word boundaries (start of line, after space/tab)
    // and is followed by a variable name
    if (lower.starts_with("set ")
        || lower.contains("\nset ")
        || lower.contains("\tset ")
        || lower.contains(" set "))
        && (lower.contains(" to ") || lower.contains("="))
    {
        return true;
    }

    false
}

/// Check if a string looks like a shell command
pub(super) fn is_shell_command(s: &str) -> bool {
    let len = s.len();

    // Must have some length
    if len < 4 {
        return false;
    }

    // Shebang is a strong indicator
    if s.starts_with("#!/bin/bash") || s.starts_with("#!/bin/sh") || s.starts_with("#!/usr/bin/env")
    {
        return true;
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
    if s.contains("!=") || s.contains("==") || s.contains("<=") || s.contains(">=") {
        return false;
    }

    // Shell operators and redirects
    if s.contains(" | ")
        || s.contains(">/dev/null")
        || s.contains("2>/dev/null")
        || s.contains("2>&1")
        || s.contains(" && ")
        || s.contains("$(")
    {
        return true;
    }

    // Backtick command substitution - must start with backtick and look like actual command
    // Skip documentation references like "see `go doc ...`" or inline code in error messages
    // Skip strings with escaped backticks (complicated to parse correctly)
    if s.starts_with('`') && !s.contains("\\`") {
        if let Some(rest) = s.strip_prefix('`') {
            if let Some(end) = rest.find('`') {
                let content = &rest[..end];
                // Must have command-like content and not look like a doc reference
                if !content.is_empty()
                    && content.contains(' ')
                    && !content.starts_with("go ")
                    && !content.contains(" doc ")
                {
                    // Must be mostly ASCII (>90%) - reject garbage with non-ASCII chars
                    let ascii_count = content.chars().filter(char::is_ascii).count();
                    let content_len = content.chars().count();
                    if content_len > 0 && ascii_count * 100 / content_len > 90 {
                        return true;
                    }
                }
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
            return true;
        }
        // Check for " prefix" pattern without allocation
        if let Some(pos) = s.find(prefix) {
            if pos > 0 && s.as_bytes()[pos - 1] == b' ' {
                return true;
            }
        }
    }

    false
}
