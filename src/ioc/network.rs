//! Hosts, IP addresses and ports parsed exactly from strings and URL
//! authorities, and metadata hostnames that are not indicators.

use super::{IocKind, NetworkMatch, canonicalize_hostname};
use crate::StringMethod;
use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr};

pub(super) fn is_common_metadata_hostname(hostname: &str) -> bool {
    if matches!(
        hostname,
        "curl.haxx.se"
            | "ns.adobe.com"
            | "schemas.microsoft.com"
            | "schemas.openxmlformats.org"
            | "www.apple.com"
            | "crl.microsoft.com"
            | "doc.rust-lang.org"
            | "docs.rs"
            | "github.com"
            | "go.dev"
            | "www.microsoft.com"
            | "www.openssl.org"
            | "www.w3.org"
    ) {
        return true;
    }

    let mut labels = hostname.rsplit('.');
    matches!(
        (labels.next(), labels.next()),
        (
            Some("com"),
            Some("digicert" | "symcb" | "symauth" | "verisign")
        )
    )
}

pub(super) fn should_suppress_metadata_hostname(method: StringMethod, hostname: &str) -> bool {
    // Compiler, runtime, and certificate metadata is surfaced by these direct
    // extraction paths. Decoded/stack-constructed values are much stronger
    // behavioral evidence and keep the overwhelmingly common IOC hot path
    // free of a metadata deny-list lookup.
    matches!(
        method,
        StringMethod::RawScan
            | StringMethod::Heuristic
            | StringMethod::InstructionPattern
            | StringMethod::Structure
            | StringMethod::RizinString
            | StringMethod::WideString
    ) && is_common_metadata_hostname(hostname)
}

pub(super) fn parse_exact_network(
    value: &str,
    typed_host: bool,
    typed_ip: bool,
) -> Option<NetworkMatch> {
    let trimmed = value.trim();
    let start = value.len().checked_sub(value.trim_start().len())?;
    if trimmed.is_empty() || trimmed.contains("://") {
        return None;
    }

    if let Some((kind, canonical, port, host_len)) = parse_authority(trimmed, false) {
        let is_endpoint = port.is_some();
        if is_endpoint
            || (kind == IocKind::Ip && typed_ip)
            || (kind == IocKind::Hostname && typed_host)
        {
            return Some(NetworkMatch {
                kind,
                value: canonical,
                port,
                start,
                len: host_len,
            });
        }
    }
    None
}

/// Parse a URL authority (`url`) or an exact network token.
///
/// A URL's host is read as a browser reads it, since that is where the
/// sample connects: percent-escapes decoded, IPv4 in any form `inet_aton`
/// takes (`0x2d.0x21.0x20.0x9c`, `45.33.8348`, `2130706436`), and an empty
/// port (`host:`) meaning the default. Reading these more strictly than the
/// runtime does hid the C2 behind them.
///
/// Returns `(kind, canonical host, port, host length in the input)`.
pub(super) fn parse_authority(
    authority: &str,
    url: bool,
) -> Option<(IocKind, String, Option<u16>, usize)> {
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    if authority.is_empty() {
        return None;
    }

    if let Some(rest) = authority.strip_prefix('[') {
        let close = rest.find(']')?;
        let host = &rest[..close];
        let ip: IpAddr = host.parse().ok()?;
        if !ip.is_ipv6() {
            return None;
        }
        let tail = &rest[close + 1..];
        let port = match tail.strip_prefix(':') {
            _ if tail.is_empty() => None,
            Some("") if url => None,
            port => Some(parse_port(port?)?),
        };
        return Some((IocKind::Ip, ip.to_string(), port, host.len()));
    }

    if let Ok(ip) = authority.parse::<IpAddr>() {
        return Some((IocKind::Ip, ip.to_string(), None, authority.len()));
    }

    let (host, port) = match authority.rsplit_once(':') {
        Some((host, "")) if url && !host.contains(':') => (host, None),
        Some((host, port)) if !host.contains(':') => (host, Some(parse_port(port)?)),
        _ => (authority, None),
    };
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some((IocKind::Ip, ip.to_string(), port, host.len()));
    }
    let decoded = if url {
        percent_decode(host)?
    } else {
        Cow::Borrowed(host)
    };
    if url && let Some(ip) = url_ipv4(&decoded) {
        return Some((IocKind::Ip, ip.to_string(), port, host.len()));
    }
    let hostname = canonicalize_hostname(&decoded)?;
    Some((IocKind::Hostname, hostname, port, host.len()))
}

/// `%XX` escapes in `host` decoded; other bytes, and malformed escapes, kept.
pub(super) fn percent_decode(host: &str) -> Option<Cow<'_, str>> {
    if !host.contains('%') {
        return Some(Cow::Borrowed(host));
    }
    let bytes = host.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let escape = bytes
            .get(i + 1..i + 3)
            .filter(|hex| hex.iter().all(u8::is_ascii_hexdigit))
            .and_then(|hex| u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok());
        match (bytes[i], escape) {
            (b'%', Some(byte)) => {
                out.push(byte);
                i += 3;
            }
            (byte, _) => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok().map(Cow::Owned)
}

/// The IPv4 address a URL host names under the WHATWG host parser: one to
/// four dot-separated numbers, each decimal, `0x` hex, or `0`-prefixed
/// octal, the last filling the remaining bytes.
pub(super) fn url_ipv4(host: &str) -> Option<Ipv4Addr> {
    let host = host.strip_suffix('.').unwrap_or(host);
    let parts = host
        .split('.')
        .map(|part| {
            let (digits, radix) =
                if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
                    (hex, 16)
                } else if part.len() > 1 && part.starts_with('0') {
                    (&part[1..], 8)
                } else {
                    (part, 10)
                };
            if part.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
                return None;
            }
            if digits.is_empty() {
                return Some(0);
            }
            u64::from_str_radix(digits, radix).ok()
        })
        .collect::<Option<Vec<u64>>>()?;
    let (&last, init) = parts.split_last()?;
    if init.len() > 3 || init.iter().any(|&n| n > 255) || last >> (8 * (4 - init.len())) != 0 {
        return None;
    }
    let value = init
        .iter()
        .enumerate()
        .fold(last, |acc, (i, &n)| acc | (n << (8 * (3 - i))));
    Some(Ipv4Addr::from(u32::try_from(value).ok()?))
}

/// Whether `value` holds a URL whose authority parses as a host or IP.
pub(crate) fn has_url_authority(value: &str) -> bool {
    let mut found = false;
    scan_url_authorities(value, |_| found = true);
    found
}

pub(super) fn parse_port(port: &str) -> Option<u16> {
    let parsed = port.parse::<u16>().ok()?;
    (parsed != 0).then_some(parsed)
}

/// Cheap necessary-condition gate before parsing an untyped endpoint.
///
/// This deliberately does not prove validity; `parse_authority` still performs
/// exact IP/hostname/port validation. Its job is to keep PSL and IDNA work out
/// of the ordinary-string path.
pub(super) fn has_endpoint_shape(value: &str) -> bool {
    let value = value.trim();
    let Some((host, port)) = value.rsplit_once(':') else {
        return false;
    };
    !host.is_empty()
        && !port.is_empty()
        && port.bytes().all(|b| b.is_ascii_digit())
        && (value.starts_with('[') || !host.contains(':'))
}

pub(super) fn scan_url_authorities(value: &str, mut emit: impl FnMut(NetworkMatch)) {
    let bytes = value.as_bytes();
    if memchr::memchr(b':', bytes).is_none() {
        return;
    }
    let mut search_from = 0usize;
    while search_from < bytes.len() {
        let Some(rel) = memchr::memmem::find(&bytes[search_from..], b"://") else {
            break;
        };
        let marker = search_from + rel;
        let Some(_scheme_start) = scheme_start(bytes, marker) else {
            search_from = marker + 3;
            continue;
        };
        let authority_start = marker + 3;
        let authority_end = bytes[authority_start..]
            .iter()
            .position(|b| {
                // Browsers end a URL's authority at `\` too, so
                // `http://c2.ru\@decoy.com/` connects to `c2.ru`.
                b.is_ascii_whitespace()
                    || matches!(*b, b'/' | b'\\' | b'?' | b'#' | b'"' | b'\'' | b'<' | b'>')
            })
            .map_or(bytes.len(), |end| authority_start + end);
        let authority = &value[authority_start..authority_end];
        // A document type definition URL names a schema, as in a plist's
        // `<!DOCTYPE … "http://www.apple.com/DTDs/PropertyList-1.0.dtd">`;
        // readers do not fetch it, so its host is not one the sample contacts.
        let url_end = bytes[authority_end..]
            .iter()
            .position(|b| b.is_ascii_whitespace() || matches!(*b, b'"' | b'\'' | b'<' | b'>'))
            .map_or(bytes.len(), |end| authority_end + end);
        if url_end >= authority_end + 4 && bytes[url_end - 4..url_end].eq_ignore_ascii_case(b".dtd")
        {
            search_from = url_end;
            continue;
        }
        if let Some((kind, canonical, port, host_len)) = parse_authority(authority, true) {
            let userinfo_len = authority.rfind('@').map_or(0, |at| at.saturating_add(1));
            let bracket_len = usize::from(authority[userinfo_len..].starts_with('['));
            emit(NetworkMatch {
                kind,
                value: canonical,
                port,
                start: authority_start + userinfo_len + bracket_len,
                len: host_len,
            });
        }
        search_from = authority_end.max(marker + 3);
    }
}

pub(super) fn scheme_start(bytes: &[u8], colon: usize) -> Option<usize> {
    if colon == 0 {
        return None;
    }
    let mut start = colon;
    while start > 0 {
        let b = bytes[start - 1];
        if b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.') {
            start -= 1;
        } else {
            break;
        }
    }
    let scheme = &bytes[start..colon];
    (!scheme.is_empty()
        && scheme[0].is_ascii_alphabetic()
        && scheme
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(*b, b'+' | b'-' | b'.')))
    .then_some(start)
}
