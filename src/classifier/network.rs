//! Network, path, and cryptographic classification.
//!
//! Detects IP addresses, file paths, crypto wallet addresses, and API keys.

use crate::types::StringKind;
use aho_corasick::AhoCorasick;
use std::sync::LazyLock;

/// Locations stealers and rootkits go after: credential stores, keychains,
/// wallets, browser and messenger data, the loader's preload hook. Naming one makes a
/// string a suspicious path wherever it appears in it, `%s/` prefix and all.
static TARGETED_LOCATIONS: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::new([
        // Linux rootkits
        "/proc/net/",
        "ld.so.preload",
        // Credentials and keys
        "/Library/Ethereum/keystore",
        "/Library/Application Support/Ethereum",
        "/.ssh/",
        "/.aws/",
        "/.gnupg/",
        "/Keychain",
        "/wallet.dat",
        "/Library/Cookies",
        // Wallet directories
        "Wallets/",
        "Exodus/exodus.wallet",
        "Exodus/exodus.conf",
        ".electrum/wallets",
        ".electrum-ltc/wallets",
        ".electron-cash/wallets",
        ".sparrow/wallets",
        "Monero/wallets",
        ".walletwasabi/",
        "Neon/storage/userWallet",
        "Daedalus Mainnet/wallets",
        "Blockstream/Green/Wallets",
        "com.bitpay.wallet",
        "/trezor.txt",
        "/specter.txt",
        // Browser and messenger data
        "/Local Storage",
        "Login Data",
        "Web Data",
        "Cookies.binarycookies",
        "cookies.sqlite",
        "formhistory.sqlite",
        "key4.db",
        "logins.json",
        "History.db",
        "Bookmarks.plist",
        "/tdata",
        "Telegram Desktop",
        "org.telegram.desktop",
        "keepcoder.Telegram",
        // Shell history and game-store sessions
        "zsh_history",
        "bash_history",
        "loginusers.vdf",
    ])
    .unwrap_or_else(crate::invalid_pattern)
});

/// Whether `s` names a location in [`TARGETED_LOCATIONS`].
pub(crate) fn names_targeted_location(s: &str) -> bool {
    TARGETED_LOCATIONS.is_match(s)
}

/// Check if a string is a suspicious/security-relevant path
pub(super) fn is_suspicious_path(s: &str) -> bool {
    // Hidden paths: a `/.` component.
    if s.contains("/.") {
        return true;
    }
    if s.starts_with("/etc/") {
        return [
            "ld.so.preload",
            "ld.so.conf",
            "cron",
            "init.d",
            "systemd",
            "rc.local",
        ]
        .iter()
        .any(|name| s.contains(name));
    }
    if s.starts_with("/dev/") {
        // `mem` covers `kmem` too.
        return s.contains("shm") || s.contains("mem");
    }
    [
        "/proc/",
        "/sys/",
        "/tmp/",
        "/var/tmp/",
        "/var/spool/cron",
        "/Library/Launch",
    ]
    .iter()
    .any(|prefix| s.starts_with(prefix))
}

/// Classify IP addresses and IP:port combinations
pub(super) fn classify_ip(s: &str) -> Option<StringKind> {
    let s = s.trim();

    // Check for IP:port pattern first
    if let Some(colon_pos) = s.rfind(':') {
        let (ip_part, port_part) = s.split_at(colon_pos);
        let port_str = &port_part[1..];

        // Verify port is numeric and reasonable
        if let Ok(port) = port_str.parse::<u16>()
            && port > 0
            && is_ipv4(ip_part)
        {
            return Some(StringKind::IpPort);
        }
    }

    // Plain IPv4
    if is_ipv4(s) {
        return Some(StringKind::Ip);
    }

    // IPv6, as the standard library parses it, with at least one hextet of
    // two or more digits. Real addresses carry a multi-digit prefix (2001,
    // fe80, fc00) or interface identifier; "0::c" and "4::e" are noise.
    if s.parse::<std::net::Ipv6Addr>().is_ok()
        && s.split(':')
            .any(|group| group.len() >= 2 && group.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Some(StringKind::Ip);
    }

    None
}

/// Check if a string is a valid IPv4 address (not a version number)
pub(super) fn is_ipv4(s: &str) -> bool {
    let mut parts = s.split('.');
    let mut octets = [0u8; 4];
    for octet in &mut octets {
        match parts.next().map(str::parse) {
            Some(Ok(n)) => *octet = n,
            _ => return false,
        }
    }
    if parts.next().is_some() {
        return false;
    }

    // Whitelist well-known public DNS and infrastructure IPs
    // These are legitimate IOCs even if they match version-like patterns
    let is_known_dns = matches!(
        octets,
        [8, 8, 8, 8]
            | [8, 8, 4, 4]
            | [1, 1, 1, 1]
            | [1, 0, 0, 1]
            | [9, 9, 9, 9]
            | [4, 2, 2, 1 | 2]
            | [208, 67, 222, 222]
            | [208, 67, 220, 220] // OpenDNS
    );
    if is_known_dns {
        return true;
    }

    // Version numbers. IOC extraction applies a stricter rule to bare quads
    // (`ioc::looks_like_version`); this one must still accept a lone
    // `192.168.1.1`.
    // X.Y.0.0 (1.0.0.0, 2.1.0.0, 0.0.0.0) is an assembly or file version.
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

    // Two or more zero octets is almost always a version number (e.g. 18.0.0.23, ProductVersion)
    let zero_count = octets.iter().filter(|&&o| o == 0).count();
    if !is_private_range && zero_count >= 2 {
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
    let wallet = Some(StringKind::CryptoWallet);

    // Base58Check: Bitcoin (version 0x00 `1…`, 0x05 `3…`), Litecoin (0x30
    // `L…`, 0x32 `M…`) and Dogecoin (0x1e `D…`). The checksum separates an
    // address from an identifier that merely avoids `0OIl`.
    if (26..=35).contains(&len)
        && base58check_version(s).is_some_and(|v| matches!(v, 0x00 | 0x05 | 0x30 | 0x32 | 0x1e))
    {
        return wallet;
    }

    // Bitcoin SegWit (bech32 or bech32m), checksum verified.
    if (14..=90).contains(&len) && s.get(..3).is_some_and(|p| p.eq_ignore_ascii_case("bc1")) {
        return is_bech32(s).then_some(StringKind::CryptoWallet);
    }

    // Ethereum: 0x and 40 hex digits. Its mixed-case checksum (EIP-55) needs
    // Keccak, so the shape alone decides.
    if s.starts_with("0x") && len == 42 && s[2..].bytes().all(|b| b.is_ascii_hexdigit()) {
        return wallet;
    }

    // Monero: starts with 4 or 8, 95-108 chars
    if (s.starts_with('4') || s.starts_with('8')) && (95..=108).contains(&len) {
        let alnum_count = s.bytes().filter(u8::is_ascii_alphanumeric).count();
        if alnum_count * 100 / len >= 95 {
            return wallet;
        }
    }

    None
}

/// The version byte of a 25-byte Base58Check payload whose double-SHA-256
/// checksum matches, as in a legacy cryptocurrency address.
fn base58check_version(s: &str) -> Option<u8> {
    use sha2::{Digest, Sha256};
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    // Big-endian base-256 accumulator; a 35-digit address fits 26 bytes.
    let mut bytes = [0u8; 26];
    for c in s.bytes() {
        let mut carry = u32::try_from(ALPHABET.iter().position(|&a| a == c)?).ok()?;
        for byte in bytes.iter_mut().rev() {
            carry += u32::from(*byte) * 58;
            *byte = u8::try_from(carry & 0xff).ok()?;
            carry >>= 8;
        }
        if carry != 0 {
            return None;
        }
    }
    // Each leading `1` is a leading zero byte.
    let zeros = s.bytes().take_while(|&c| c == b'1').count();
    let significant = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    if zeros + (bytes.len() - significant) != 25 {
        return None;
    }
    let payload = &bytes[bytes.len() - 25..];
    let (body, checksum) = payload.split_at(21);
    let digest = Sha256::digest(Sha256::digest(body));
    (digest[..4] == *checksum).then_some(body[0])
}

/// A valid bech32 (BIP 173) or bech32m (BIP 350) string: one case, an
/// `hrp1data` split, and a checksum that verifies.
fn is_bech32(s: &str) -> bool {
    const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    if s.bytes().any(|b| b.is_ascii_lowercase()) && s.bytes().any(|b| b.is_ascii_uppercase()) {
        return false;
    }
    let s = s.to_ascii_lowercase();
    let Some((hrp, data)) = s.rsplit_once('1') else {
        return false;
    };
    if hrp.is_empty() || data.len() < 6 {
        return false;
    }
    let mut values = Vec::with_capacity(hrp.len() * 2 + 1 + data.len());
    values.extend(hrp.bytes().map(|b| b >> 5));
    values.push(0);
    values.extend(hrp.bytes().map(|b| b & 31));
    for c in data.bytes() {
        let Some(v) = CHARSET.iter().position(|&x| x == c) else {
            return false;
        };
        values.push(u8::try_from(v).unwrap_or(0));
    }
    let polymod = values.iter().fold(1u32, |chk, &v| {
        let top = chk >> 25;
        let mut chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(v);
        for (bit, generator) in [
            0x3b6a_57b2,
            0x2650_8e6d,
            0x1ea1_19fa,
            0x3d42_33dd,
            0x2a14_62b3,
        ]
        .into_iter()
        .enumerate()
        {
            if (top >> bit) & 1 == 1 {
                chk ^= generator;
            }
        }
        chk
    });
    matches!(polymod, 1 | 0x2bc8_30a3)
}

/// Classify API keys and secrets
pub(super) fn classify_api_key(s: &str) -> Option<StringKind> {
    let len = s.len();

    // AWS access key: starts with AKIA, 20+ chars
    if s.starts_with("AKIA") && len >= 20 {
        let alnum_count = s.bytes().filter(u8::is_ascii_alphanumeric).count();
        if alnum_count * 100 / len >= 90 {
            return Some(StringKind::ApiKey);
        }
    }

    // GitHub token: starts with ghp_, 36+ chars
    if s.starts_with("ghp_") && len >= 36 {
        let alnum_count = s
            .bytes()
            .filter(|b| b.is_ascii_alphanumeric() || *b == b'_')
            .count();
        if alnum_count * 100 / len >= 90 {
            return Some(StringKind::ApiKey);
        }
    }

    // Stripe keys: starts with sk_live_ or pk_live_
    if (s.starts_with("sk_live_") || s.starts_with("pk_live_")) && len >= 20 {
        let alnum_count = s
            .bytes()
            .filter(|b| b.is_ascii_alphanumeric() || *b == b'_')
            .count();
        if alnum_count * 100 / len >= 90 {
            return Some(StringKind::ApiKey);
        }
    }

    // Slack tokens: starts with xox, 30+ chars
    if s.starts_with("xox") && len >= 30 {
        let alnum_count = s
            .bytes()
            .filter(|b| b.is_ascii_alphanumeric() || *b == b'-')
            .count();
        if alnum_count * 100 / len >= 90 {
            return Some(StringKind::ApiKey);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::names_targeted_location;

    /// Specific stores count wherever they appear; the generic words the XOR
    /// scan also accepts decodes on ("key", "history", "cookies") do not.
    #[test]
    fn targeted_locations_are_specific_names() {
        for s in [
            "%s/Library/Application Support/discord/Local Storage",
            "Wallets/Exodus",
            "/Users/a/Library/Keychains/login.keychain-db",
            "Default/Login Data",
            "Telegram Desktop/tdata/",
        ] {
            assert!(names_targeted_location(s), "{s}");
        }
        for s in ["monkey", "history", "cookies", "Local Storage", "user_key"] {
            assert!(!names_targeted_location(s), "{s}");
        }
    }
}
