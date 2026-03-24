//! Network, path, and cryptographic classification.
//!
//! Detects IP addresses, file paths, crypto wallet addresses, and API keys.

use crate::types::StringKind;

/// Check if a string is a suspicious/security-relevant path
pub(super) fn is_suspicious_path(s: &str) -> bool {
    // Hidden paths (contain /. component)
    if s.contains("/.") {
        return true;
    }

    // Known suspicious/rootkit locations
    let suspicious = [
        "/etc/ld.so.preload",
        "/etc/ld.so.conf",
        "/dev/shm",
        "/dev/mem",
        "/dev/kmem",
        "/proc/",
        "/sys/",
        "/.ssh/",
        "/etc/cron",
        "/etc/init.d",
        "/etc/systemd",
        "/etc/rc.local",
        "/var/spool/cron",
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
        "/.bash_profile",
        "/.bashrc",
        "/.profile",
        "/.bash_login",
        "/.zshrc",
        "/tmp/",
        "/var/tmp/",
    ];

    for path in suspicious {
        if s.contains(path) {
            return true;
        }
    }

    false
}

/// Classify IP addresses and IP:port combinations
pub(super) fn classify_ip(s: &str) -> Option<StringKind> {
    let s = s.trim();

    // Check for IP:port pattern first
    if let Some(colon_pos) = s.rfind(':') {
        let (ip_part, port_part) = s.split_at(colon_pos);
        let port_str = &port_part[1..];

        // Verify port is numeric and reasonable
        if let Ok(port) = port_str.parse::<u16>() {
            if port > 0 && is_ipv4(ip_part) {
                return Some(StringKind::IPPort);
            }
        }
    }

    // Plain IPv4
    if is_ipv4(s) {
        return Some(StringKind::IP);
    }

    // IPv6 (contains multiple colons, hex chars)
    if s.contains(':') && memchr::memchr_iter(b':', s.as_bytes()).count() >= 2 {
        // Reject trailing colons (invalid IPv6)
        if s.ends_with(':') && !s.ends_with("::") {
            return None;
        }
        // Reject leading colons (invalid unless it's ::)
        if s.starts_with(':') && !s.starts_with("::") {
            return None;
        }
        // Reject 3+ consecutive colons (only :: is valid)
        if s.contains(":::") {
            return None;
        }
        // Reject multiple :: occurrences (only one allowed)
        if s.matches("::").count() > 1 {
            return None;
        }
        let valid_ipv6 = s
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.');
        if valid_ipv6 && s.len() >= 3 {
            return Some(StringKind::IP);
        }
    }

    None
}

/// Check if a string is a valid IPv4 address (not a version number)
pub(super) fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }

    let mut octets = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        match part.parse::<u8>() {
            Ok(n) => octets[i] = n,
            Err(_) => return false,
        }
    }

    // Whitelist well-known public DNS and infrastructure IPs
    // These are legitimate IOCs even if they match version-like patterns
    let is_known_dns = matches!(
        octets,
        [8, 8, 8, 8]      // Google DNS
        | [8, 8, 4, 4]    // Google DNS secondary
        | [1, 1, 1, 1]    // Cloudflare DNS
        | [1, 0, 0, 1]    // Cloudflare DNS secondary
        | [9, 9, 9, 9]    // Quad9 DNS
        | [4, 2, 2, 1]    // Level3 DNS
        | [4, 2, 2, 2]    // Level3 DNS
        | [208, 67, 222, 222] // OpenDNS
        | [208, 67, 220, 220] // OpenDNS
    );
    if is_known_dns {
        return true;
    }

    // Filter out common version number patterns (false positives)
    // Pattern: X.0.0.0 (e.g., 1.0.0.0, 4.0.0.0, 11.0.0.0) - assembly versions
    if octets[1] == 0 && octets[2] == 0 && octets[3] == 0 {
        return false;
    }

    // Pattern: X.Y.0.0 (e.g., 2.1.0.0, 4.5.0.0) - also common versions
    if octets[2] == 0 && octets[3] == 0 {
        return false;
    }

    // Pattern: X.0.Y.Z where second octet is 0 and Y,Z are small (version-like)
    // e.g., 49.0.2.1, 8.0.14.0 - .NET assembly versions
    // But exclude private IP ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
    let is_private_range = octets[0] == 10
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 168);
    if !is_private_range && octets[1] == 0 && octets[2] < 20 && octets[3] < 20 {
        return false;
    }

    // 0.0.0.0 is not a useful IOC
    if octets == [0, 0, 0, 0] {
        return false;
    }

    // 127.x.x.x localhost is rarely an IOC
    if octets[0] == 127 {
        return false;
    }

    // Filter X.509/ASN.1 OIDs that look like IPs
    // 2.5.x.y = ISO X.500 arc (certificate attributes and extensions)
    // Common OIDs: 2.5.4.3 (CN), 2.5.29.17 (subjectAltName), 2.5.29.37 (extKeyUsage)
    if octets[0] == 2 && octets[1] == 5 {
        return false;
    }

    true
}

/// Classify cryptocurrency wallet addresses
pub(super) fn classify_crypto_address(s: &str) -> Option<StringKind> {
    let len = s.len();

    // Bitcoin (legacy): starts with 1 or 3, 26-35 chars, Base58 (excludes 0, O, I, l)
    if (s.starts_with('1') || s.starts_with('3')) && (26..=35).contains(&len) {
        // Must be valid Base58: no 0, O, I, or l characters
        if s.chars()
            .all(|c| c.is_ascii_alphanumeric() && c != '0' && c != 'O' && c != 'I' && c != 'l')
        {
            return Some(StringKind::CryptoWallet);
        }
    }

    // Bitcoin (bech32): starts with bc1, 42+ chars
    if s.starts_with("bc1") && len >= 42 {
        let alnum_count = s.bytes().filter(u8::is_ascii_alphanumeric).count();
        if alnum_count * 100 / len >= 95 {
            return Some(StringKind::CryptoWallet);
        }
    }

    // Ethereum: starts with 0x, 42 chars hex
    if s.starts_with("0x") && len == 42 {
        let hex_count = s[2..].bytes().filter(u8::is_ascii_hexdigit).count();
        if hex_count == 40 {
            return Some(StringKind::CryptoWallet);
        }
    }

    // Monero: starts with 4 or 8, 95-108 chars
    if (s.starts_with('4') || s.starts_with('8')) && (95..=108).contains(&len) {
        let alnum_count = s.bytes().filter(u8::is_ascii_alphanumeric).count();
        if alnum_count * 100 / len >= 95 {
            return Some(StringKind::CryptoWallet);
        }
    }

    // Litecoin: starts with L or M, 26-35 chars, Base58
    if (s.starts_with('L') || s.starts_with('M')) && (26..=35).contains(&len) {
        // Must be valid Base58: no 0, O, I, or l characters
        if !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() && c != '0' && c != 'O' && c != 'I' && c != 'l')
        {
            return None;
        }

        // Reject CamelCase identifiers (multiple lowercase-to-uppercase transitions)
        // Real Litecoin addresses have random-looking mixed case, not structured patterns
        let mut camel_case_transitions = 0;
        let mut prev_was_lower = false;

        for c in s.chars() {
            let is_lower = c.is_ascii_lowercase();
            let is_upper = c.is_ascii_uppercase();

            if prev_was_lower && is_upper {
                camel_case_transitions += 1;
            }

            prev_was_lower = is_lower;
        }

        // Reject if it has 3+ CamelCase transitions (structured identifiers)
        // Real crypto addresses may have 0-2 by chance, but 3+ indicates naming pattern
        if camel_case_transitions >= 3 {
            return None;
        }

        return Some(StringKind::CryptoWallet);
    }

    // Dogecoin: starts with D, 34 chars, Base58
    if s.starts_with('D')
        && len == 34
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() && c != '0' && c != 'O' && c != 'I' && c != 'l')
    {
        return Some(StringKind::CryptoWallet);
    }

    None
}

/// Classify API keys and secrets
pub(super) fn classify_api_key(s: &str) -> Option<StringKind> {
    let len = s.len();

    // AWS access key: starts with AKIA, 20+ chars
    if s.starts_with("AKIA") && len >= 20 {
        let alnum_count = s.bytes().filter(u8::is_ascii_alphanumeric).count();
        if alnum_count * 100 / len >= 90 {
            return Some(StringKind::APIKey);
        }
    }

    // GitHub token: starts with ghp_, 36+ chars
    if s.starts_with("ghp_") && len >= 36 {
        let alnum_count = s
            .bytes()
            .filter(|b| b.is_ascii_alphanumeric() || *b == b'_')
            .count();
        if alnum_count * 100 / len >= 90 {
            return Some(StringKind::APIKey);
        }
    }

    // Stripe keys: starts with sk_live_ or pk_live_
    if (s.starts_with("sk_live_") || s.starts_with("pk_live_")) && len >= 20 {
        let alnum_count = s
            .bytes()
            .filter(|b| b.is_ascii_alphanumeric() || *b == b'_')
            .count();
        if alnum_count * 100 / len >= 90 {
            return Some(StringKind::APIKey);
        }
    }

    // Slack tokens: starts with xox, 30+ chars
    if s.starts_with("xox") && len >= 30 {
        let alnum_count = s
            .bytes()
            .filter(|b| b.is_ascii_alphanumeric() || *b == b'-')
            .count();
        if alnum_count * 100 / len >= 90 {
            return Some(StringKind::APIKey);
        }
    }

    None
}
