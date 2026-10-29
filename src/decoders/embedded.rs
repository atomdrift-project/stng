//! Encoded tokens embedded in longer strings: quoted or delimited base64
//! and hex runs, and string concatenation that hides them.

use super::base64_text::{MAX_INFLATED_PER_PASS, base64_payload_to_text, decode_base64_bytes};
use super::{MAX_DECODED_SIZE, MIN_BASE64_LENGTH, decoded_to_text};
use crate::{ExtractedString, StringMethod};
use rayon::prelude::*;
use regex::Regex;
use std::sync::LazyLock;
use std::sync::atomic::AtomicUsize;

#[allow(clippy::expect_used)]
pub(super) static QUOTED_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"['"]([^'"]+)['"]"#).expect("static regex"));

/// Matches base64-like substrings within larger strings (e.g. embedded in shell
/// commands). The `{8,}` run only *starts* a candidate — [`extract_embedded_base64`]
/// then decides whether a run this short is trustworthy. A 6-byte payload is 8
/// base64 chars, so this is the floor below which nothing meaningful decodes.
#[allow(clippy::expect_used)]
pub(super) static EMBEDDED_B64_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"([A-Za-z0-9+/]{8,}={0,2})").expect("static regex"));

/// The alphabet-char count above which an embedded run is trusted on its own —
/// long enough (9 decoded bytes) that a false positive is unlikely. Shorter
/// runs need a corroborating signal; see [`extract_embedded_base64`].
pub(super) const EMBEDDED_B64_TRUSTED_LEN: usize = 12;

/// Matches hex runs embedded in a larger string — the shape droppers use when
/// they hide a command as `echo <hex> | xxd -r -p | sh` rather than encoding
/// the whole string. [`decode_hex_strings`] only decodes a value that is hex
/// *in its entirety*, so without this the payload inside such a one-liner is
/// never decoded and every plaintext rule downstream is blind to it.
#[allow(clippy::expect_used)]
pub(super) static EMBEDDED_HEX_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"([0-9a-fA-F]{32,})").expect("static regex"));

/// The run length above which an embedded hex run is decoded on its own: 32
/// nibbles is 16 decoded bytes. The floor is deliberately double
/// [`MIN_HEX_LENGTH`] because an embedded run has no delimiters vouching for
/// it — it is simply a stretch of text that happens to be hex — and the corpus
/// is full of innocent long hex: digests, UUIDs with the dashes stripped, git
/// object ids, key material, colour tables. Those are rejected on output
/// rather than input: random bytes almost never survive [`decoded_to_text`],
/// which requires the result to be printable text end to end.
pub(super) const EMBEDDED_HEX_TRUSTED_LEN: usize = 32;

/// Deobfuscate strings that use concatenation patterns.
///
/// Many malware samples split encoded strings using concatenation to evade detection:
/// - JavaScript: `"ZnVu" + "Y3Rp" + "b24"`
/// - Python: `'ZnVu' + 'Y3Rp' + 'b24'`
/// - PHP: `'ZnVu' . 'Y3Rp' . 'b24'`
/// - Obfuscated: `"ZnVu" + 'A' + "Y3Rp"` (junk inserted between chunks)
///
/// This function detects these patterns, extracts the quoted segments,
/// and reassembles them into the original encoded string.
pub(crate) fn deobfuscate_concatenation(s: &str) -> Option<String> {
    // Check if the string contains common concatenation patterns
    if !s.contains(" + ") && !s.contains(" . ") && !s.contains(" .. ") {
        return None;
    }

    let mut segments = Vec::new();

    for cap in QUOTED_RE.captures_iter(s) {
        if let Some(content) = cap.get(1) {
            segments.push(content.as_str());
        }
    }

    // Need at least 2 segments to be concatenation
    if segments.len() < 2 {
        return None;
    }

    // Reassemble all segments
    let reassembled = segments.join("");

    // Only return if the result is different and potentially useful
    // (longer strings, higher chance of being encoded data)
    if reassembled.len() >= MIN_BASE64_LENGTH && reassembled != s {
        Some(reassembled)
    } else {
        None
    }
}

/// Extract and decode base64 embedded within larger strings.
///
/// This handles cases where base64 is embedded in code or commands:
/// - Python: `exec(base64.b64decode('YWJjZGVm'))`
/// - Shell: `echo YWJjZGVm | base64 -d`
/// - JavaScript: `atob('YWJjZGVm')`
///
/// Unlike `decode_base64_strings` which decodes entire strings that are base64,
/// this function extracts base64 substrings from within larger strings.
pub(crate) fn extract_embedded_base64(strings: &[ExtractedString]) -> Vec<ExtractedString> {
    let budget = AtomicUsize::new(MAX_INFLATED_PER_PASS);
    // Each input string can yield several embedded payloads; `flat_map_iter`
    // parallelises across strings while keeping each string's per-capture order.
    strings
        .par_iter()
        .with_min_len(crate::par::MIN_ITEMS_PER_JOB)
        .flat_map_iter(|s| {
            let mut local = Vec::new();
            // A base64 *decode* command — GNU `base64 -d`/`--decode`, BSD and
            // macOS `base64 -D` — takes base64 by construction, so a shorter
            // run is trustworthy there than it would be in free text.
            let has_command = ["base64 -d", "base64 --decode", "base64 -D"]
                .iter()
                .any(|m| s.value.contains(m));
            for cap in EMBEDDED_B64_RE.captures_iter(&s.value) {
                if let Some(b64_match) = cap.get(1) {
                    let b64_str = b64_match.as_str();

                    // Skip if it's the entire string (handled by decode_base64_strings)
                    if b64_str == s.value {
                        continue;
                    }

                    // A remainder of one cannot encode any final bytes.
                    // Remainders two and three are canonical unpadded Base64.
                    if b64_str.len() % 4 == 1 {
                        continue;
                    }

                    // A short run alone is indistinguishable from an ordinary
                    // identifier, so it is taken only when padding (base64's
                    // own tell, which almost never follows an identifier) or a
                    // decode command corroborates it. A run of
                    // EMBEDDED_B64_TRUSTED_LEN stands on its own.
                    let pad = b64_str.bytes().rev().take_while(|&b| b == b'=').count();
                    if b64_str.len() - pad < EMBEDDED_B64_TRUSTED_LEN && pad == 0 && !has_command {
                        continue;
                    }

                    // Try to decode it
                    if let Some(decoded) = decode_base64_bytes(b64_str) {
                        // Check size limit
                        if decoded.len() > MAX_DECODED_SIZE {
                            continue;
                        }

                        // Base64 can wrap binary zlib data. Inflate before asking
                        // for text, just as the sample's runtime decoder does.
                        if let Some((decoded_str, _)) = base64_payload_to_text(decoded, &budget) {
                            let trimmed = decoded_str.trim();

                            // Must be meaningful (at least 4 chars after trim)
                            if trimmed.len() >= 4 {
                                local.push(ExtractedString {
                                    value: trimmed.to_string(),
                                    // The base64 token sits at `b64_match.start()`
                                    // within the parent's bytes; its source extent
                                    // is the encoded token, not the decoded value.
                                    data_offset: s.data_offset + b64_match.start() as u64,
                                    data_len: u32::try_from(b64_str.len()).unwrap_or(u32::MAX),
                                    method: StringMethod::Base64Decode,
                                    kind: crate::classify_string(trimmed),
                                    ..Default::default()
                                });
                            }
                        }
                    }
                }
            }
            local
        })
        .collect()
}

/// Extract and decode hex runs embedded inside larger strings.
///
/// The counterpart to [`extract_embedded_base64`]. [`decode_hex_strings`]
/// decodes a string only when the *whole* value is hex, which misses the
/// common dropper shape where the blob is one argument of a shell one-liner
/// (`echo <hex> | xxd -r -p | sh`). Recovering it here puts the decoded
/// command in the encoded-string corpus, where the ordinary plaintext rules
/// can see it.
pub(crate) fn extract_embedded_hex(strings: &[ExtractedString]) -> Vec<ExtractedString> {
    // Each input string can yield several embedded payloads; `flat_map_iter`
    // parallelises across strings while keeping each string's per-capture order.
    strings
        .par_iter()
        .with_min_len(crate::par::MIN_ITEMS_PER_JOB)
        .flat_map_iter(|s| {
            let mut local = Vec::new();
            for cap in EMBEDDED_HEX_RE.captures_iter(&s.value) {
                let Some(hex_match) = cap.get(1) else {
                    continue;
                };
                let hex_str = hex_match.as_str();

                // The whole-string case is decode_hex_strings' job.
                if hex_str == s.value {
                    continue;
                }
                if hex_str.len() < EMBEDDED_HEX_TRUSTED_LEN || !hex_str.len().is_multiple_of(2) {
                    continue;
                }

                let Some(decoded) = crate::bytes::from_hex(hex_str.as_bytes()) else {
                    continue;
                };
                // Rejects the digests, ids, and key material that make up most
                // long hex: their bytes are not printable text.
                let Some(decoded_str) = decoded_to_text(decoded) else {
                    continue;
                };
                let trimmed = decoded_str.trim();
                if trimmed.len() < 4 {
                    continue;
                }

                local.push(ExtractedString {
                    value: trimmed.to_string(),
                    // The hex token sits at `hex_match.start()` within the
                    // parent's bytes; the source extent is the encoded token,
                    // not the decoded value.
                    data_offset: s.data_offset + hex_match.start() as u64,
                    data_len: u32::try_from(hex_str.len()).unwrap_or(u32::MAX),
                    method: StringMethod::HexDecode,
                    kind: crate::classify_string(trimmed),
                    ..Default::default()
                });
            }
            local
        })
        .collect()
}
