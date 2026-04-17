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

    // Reject Go symbol-table strings up-front: Go's pclntab embeds type
    // metadata like `sync/atomic.(*Pointer[go.shape.struct { os.mu sync.Mutex;
    // os.class uint32 }]).Swap` which trips the `class ` + `os.` Python
    // heuristic below. Go's symbol syntax `.(*` (pointer method), `go.shape.`,
    // and `syscall.Handle` never appear in Python source.
    if s.contains(".(*") || s.contains("go.shape.") || s.contains("syscall.Handle") {
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

    let lower = s.to_ascii_lowercase();

    // AppleScript indicators
    let patterns = [
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

    for pattern in &patterns {
        if lower.contains(pattern) {
            return true;
        }
    }

    // "set " only if it appears at word boundaries and is followed by assignment
    if (lower.starts_with("set ")
        || lower.contains("\nset ")
        || lower.contains("\tset ")
        || lower.contains(" set "))
        && (lower.contains(" to ") || lower.contains('='))
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
        let is_error_message = s.contains("Error")
            || s.contains("error")
            || s.contains("Failed")
            || s.contains("Could not")
            || s.contains("Unable to")
            || s.contains("Cannot")
            || s.contains("Invalid")
            || s.contains("Unsupported")
            || s.contains("not supported")
            || s.contains("not found")
            || s.contains("access")
            || s.contains("service")
            || s.contains("[Click")
            || s.contains("prompt");
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
    if s.contains("!=") || s.contains("==") || s.contains("<=") || s.contains(">=") {
        return false;
    }

    // Shell operators and redirects
    // Note: " | " alone is not enough - UI strings often use | as a separator
    // e.g., "Click here | Don't show again" - must have actual shell context
    if s.contains(">/dev/null") || s.contains("2>/dev/null") || s.contains("2>&1") {
        return true;
    }

    // Pipe requires additional shell context (command-like words around it)
    if s.contains(" | ") {
        // Check if it looks like a shell pipeline (has command-like patterns)
        let has_shell_context = s.contains("grep")
            || s.contains("awk")
            || s.contains("sed")
            || s.contains("sort")
            || s.contains("uniq")
            || s.contains("head")
            || s.contains("tail")
            || s.contains("cat ")
            || s.contains("xargs")
            || s.contains("wc ")
            || s.contains("cut ")
            || s.contains("tr ")
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
    if let Some(start) = s.find("$(") {
        if let Some(end_rel) = s[start + 2..].find(')') {
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
                    let ascii_count = content.bytes().filter(u8::is_ascii).count();
                    let content_len = content.len();
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
            // Special case: "service " at start should be followed by command words
            if prefix == "service " {
                if let Some(after) = s.strip_prefix(prefix) {
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
            }
            return true;
        }
        // Check for " prefix" pattern without allocation
        if let Some(pos) = s.find(prefix) {
            if pos > 0 && s.as_bytes()[pos - 1] == b' ' {
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
    }

    false
}
