//! Conservative, deduplicated indicator extraction.
//!
//! This module intentionally does not scan every dotted token as a hostname.
//! A context-free value such as `foo.rs` is indistinguishable from a Rust
//! filename, even though `.rs` is a real public suffix. Hostnames are emitted
//! only when an upstream extractor already typed the value as a hostname, when
//! it is the host portion of a structurally valid endpoint, or when it is an
//! authority in a URL. This trades recall for the precision required by bulk
//! corpus analysis.

mod network;
mod path;

pub(crate) use network::has_url_authority;
pub use path::canonicalize_ioc_path;

use network::{
    has_endpoint_shape, parse_exact_network, scan_url_authorities,
    should_suppress_metadata_hostname,
};
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
    /// Repeating-key XOR.
    Xor,
    /// DES.
    Des,
    /// Triple DES.
    TripleDes,
    /// Fernet (AES-128-CBC with HMAC-SHA256).
    Fernet,
    /// AES.
    Aes,
    /// RC4.
    Rc4,
    /// ChaCha20.
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
    /// What sort of indicator this is.
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

        let is_path = matches!(
            extracted.kind,
            Some(StringKind::Path | StringKind::SuspiciousPath)
        );
        if is_path
            && extracted.method != StringMethod::PclntabSymbol
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

        if is_path && extracted.kind != Some(StringKind::SuspiciousPath) {
            continue;
        }

        // URL authorities are strong structural evidence even when a broader
        // classifier called the whole string a shell command or source code.
        // A suspicious path is scanned too: a stealer config naming
        // `Login Data` beside its C2 URL is typed as one, and the URL must
        // not go unreported. Plain paths keep their old handling.
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
        if is_path {
            continue;
        }

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

fn xor_key_material(extracted: &ExtractedString) -> Option<Vec<u8>> {
    if extracted.value.is_empty() || extracted.value.len() > 4096 {
        return None;
    }

    // ARM64 stack-XOR and repeating-XOR PE recovery render arbitrary key bytes
    // as `0x<hex>`. Restrict hex decoding to those producers: a user-supplied
    // ASCII XOR key beginning with "0x" must remain those literal bytes.
    if matches!(
        extracted.method,
        StringMethod::XorStackPair | StringMethod::XorRepeatingKey
    ) {
        let encoded = extracted.value.strip_prefix("0x")?;
        if encoded.is_empty() || encoded.len() % 2 != 0 {
            return None;
        }
        return crate::bytes::from_hex(encoded.as_bytes()).filter(|key| !key.is_empty());
    }

    Some(extracted.value.as_bytes().to_vec())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
