//! File paths as indicators: canonical form, and the system, build-source
//! and templated paths that are not.

/// Canonicalize an uncommon absolute path suitable for exact IOC matching.
///
/// This intentionally performs minimal normalization: only a Windows drive
/// letter is uppercased. Resolving `..`, separators, case, symlinks, or
/// environment variables without the target filesystem would merge distinct
/// paths and create false matches.
#[must_use]
pub fn canonicalize_ioc_path(input: &str) -> Option<String> {
    if input.is_empty()
        || input.len() > 4096
        || input.trim() != input
        || input.bytes().any(|b| b.is_ascii_control())
        || has_path_template(input)
        || input.contains("://")
    {
        return None;
    }

    let bytes = input.as_bytes();
    let windows_drive = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/');
    let windows_unc = input.starts_with(r"\\")
        && input[2..]
            .split(['\\', '/'])
            .filter(|part| !part.is_empty())
            .count()
            >= 3;
    let posix = input.starts_with('/') && !input.starts_with("//");
    if !posix && !windows_drive && !windows_unc {
        return None;
    }
    if posix && memchr::memchr_iter(b'/', bytes).count() < 2 {
        return None;
    }

    if input.ends_with(['/', '\\']) {
        return None;
    }
    let leaf = input.rsplit(['/', '\\']).next()?;
    if leaf.len() < 5
        || matches!(leaf, "." | "..")
        || looks_like_source_file(leaf)
        || looks_like_build_source_path(input, leaf)
    {
        return None;
    }

    if !posix {
        if input[usize::from(windows_drive) * 2..]
            .bytes()
            .any(|b| matches!(b, b'<' | b'>' | b'"' | b'|' | b'?' | b'*' | b':'))
        {
            return None;
        }
    } else if !input
        .chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '/' | '.' | '_' | '-' | '+' | '@' | ' '))
    {
        return None;
    }

    let comparison = if posix {
        input.to_string()
    } else {
        input.to_ascii_lowercase()
    };
    if is_common_system_path(&comparison) {
        return None;
    }

    let mut canonical = input.to_string();
    if windows_drive {
        canonical.replace_range(0..1, &input[..1].to_ascii_uppercase());
    }
    Some(canonical)
}

pub(super) fn has_path_template(path: &str) -> bool {
    if path.contains('$') || path.contains('{') || path.contains('}') {
        return true;
    }
    path.as_bytes().windows(2).any(|pair| {
        pair[0] == b'%'
            && matches!(
                pair[1],
                b's' | b'S' | b'd' | b'i' | b'u' | b'x' | b'X' | b'f' | b'@' | b'0'..=b'9'
            )
    })
}

pub(super) fn looks_like_source_file(leaf: &str) -> bool {
    let leaf = leaf.to_ascii_lowercase();
    [
        ".c", ".cc", ".cpp", ".cxx", ".go", ".h", ".hh", ".hpp", ".java", ".m", ".mm", ".rs",
        ".swift",
    ]
    .iter()
    .any(|extension| leaf.ends_with(extension))
}

pub(super) fn looks_like_build_source_path(path: &str, leaf: &str) -> bool {
    let normalized = path.replace('\\', "/").to_ascii_lowercase();
    let in_source_tree = normalized.contains("/src/")
        || normalized.contains("/include/")
        || normalized.contains("/node_modules/")
        || normalized.contains("/vendor/")
        || normalized.contains("/go/pkg/mod/")
        || normalized.contains("/rustc/");
    if !in_source_tree {
        return false;
    }
    let leaf = leaf.to_ascii_lowercase();
    [
        ".c", ".cc", ".cpp", ".cxx", ".go", ".h", ".hh", ".hpp", ".java", ".js", ".m", ".mm",
        ".py", ".rs", ".swift", ".ts",
    ]
    .iter()
    .any(|extension| leaf.ends_with(extension))
}

pub(super) fn is_common_system_path(path: &str) -> bool {
    const POSIX: &[&str] = &[
        "/bin/bash",
        "/bin/cat",
        "/bin/dash",
        "/bin/echo",
        "/bin/false",
        "/bin/ls",
        "/bin/sh",
        "/bin/true",
        "/bin/zsh",
        "/dev/egd-pool",
        "/dev/null",
        "/dev/random",
        "/dev/srandom",
        "/dev/stderr",
        "/dev/stdin",
        "/dev/stdout",
        "/dev/tty",
        "/dev/ubskey",
        "/dev/urandom",
        "/etc/egd-pool",
        "/etc/entropy",
        "/etc/apache/mime.types",
        "/etc/apache2/mime.types",
        "/etc/group",
        "/etc/hosts",
        "/etc/httpd/conf/mime.types",
        "/etc/mdns.allow",
        "/etc/mime.types",
        "/etc/nsswitch.conf",
        "/etc/passwd",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        "/etc/pki/tls/cacert.pem",
        "/etc/pki/tls/certs",
        "/etc/protocols",
        "/etc/resolv.conf",
        "/etc/services",
        "/etc/ssl/ca-bundle.pem",
        "/etc/ssl/cert.pem",
        "/etc/ssl/certs",
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/zoneinfo",
        "/lib/time/zoneinfo.zip",
        "/lib64/ld-linux-x86-64.so.2",
        "/proc/meminfo",
        "/proc/self/auxv",
        "/proc/sys/kernel/hostname",
        "/proc/sys/net/core/somaxconn",
        "/system/etc/security/cacerts",
        "/usr/bin/bash",
        "/usr/bin/curl",
        "/usr/bin/env",
        "/usr/bin/false",
        "/usr/bin/perl",
        "/usr/bin/python",
        "/usr/bin/python3",
        "/usr/bin/ruby",
        "/usr/bin/sh",
        "/usr/bin/true",
        "/usr/bin/wget",
        "/usr/bin/zsh",
        "/usr/bin/ntlm_auth",
        "/usr/lib/dyld",
        "/usr/local/share/mime/globs2",
        "/usr/share/mime/globs2",
        "/var/run/egd-pool",
    ];
    const WINDOWS_LOWERCASE: &[&str] = &[
        r"c:\windows\explorer.exe",
        r"c:\windows\notepad.exe",
        r"c:\windows\system32\cmd.exe",
        r"c:\windows\system32\powershell.exe",
        r"c:\windows\system32\rundll32.exe",
    ];
    POSIX.contains(&path)
        || WINDOWS_LOWERCASE.contains(&path)
        || path.eq_ignore_ascii_case("/drivers/etc/hosts")
        || path.starts_with("/dev/")
        || path.starts_with("/root/go/")
        || path.starts_with("/System/Library/Frameworks/")
        || path.starts_with("/root/openssl-prefix/")
        || path.starts_with("/sys/kernel/mm/")
        || path.contains("/.cargo/registry/src/")
        || path.contains("/lib/rustlib/src/")
        || (path.starts_with("/usr/lib/")
            && path.rsplit('/').next().is_some_and(|leaf| {
                (leaf.starts_with("lib") && (leaf.contains(".so") || leaf.ends_with(".dylib")))
                    || leaf == "dyld"
            }))
}
