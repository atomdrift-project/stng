//! Encoded strings (base64, hex, URL, escapes, base32/85, ROT13) decoded
//! into the strings they hide.

use crate::{ExtractedString, StringMethod, classifier, decoders, fuzzy_base64, par};

/// Apply every string decoder (base64, embedded base64, fuzzy base64, base32,
/// base85, ROT13-base64, hex, URL, and unicode-escape) to already-extracted
/// strings and return
/// the newly decoded results.
///
/// Decoding runs on the *text* of each string, so it is filetype-agnostic: the
/// same pass that recovers base64-encoded PowerShell from a PE also recovers a
/// base64-over-UTF-16LE blob sitting in a plain `.txt` or `.json`. Both the
/// internal extraction pipeline and the CLI's line-based text path funnel through
/// here so coverage stays identical across inputs.
/// Base64 wrapping a zlib stream is inflated with a 10 MiB output bound before
/// text validation; decoded strings retain the encoded token's source extent.
#[must_use]
pub fn decode_encoded_strings(strings: &[ExtractedString]) -> Vec<ExtractedString> {
    decode(strings, Rot13::Yes)
}

/// Whether [`decode`] tries ROT13 under base64.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rot13 {
    /// Text: ROT13-then-base64 is a script obfuscation.
    Yes,
    /// Binaries: arbitrary symbols "decode" to noise that would outrank the
    /// real string at its offset.
    No,
}

/// Every decoder over `strings`, run concurrently; results in pass order.
pub(crate) fn decode(strings: &[ExtractedString], rot13: Rot13) -> Vec<ExtractedString> {
    let split = strings.len() >= par::MIN_ITEMS_PER_JOB;
    super::parallel(
        split,
        [
            &|| decoders::decode_base64_strings(strings),
            &|| decoders::extract_embedded_base64(strings),
            &|| fuzzy_base64::extract_fuzzy_base64(strings),
            &|| decoders::decode_base32_strings(strings),
            &|| decoders::decode_base85_strings(strings),
            &|| match rot13 {
                Rot13::Yes => decoders::decode_rot13_base64_strings(strings),
                Rot13::No => Vec::new(),
            },
            &|| decoders::decode_hex_strings(strings),
            &|| decoders::extract_embedded_hex(strings),
            &|| decoders::decode_url_strings(strings),
            &|| decoders::decode_unicode_escape_strings(strings),
        ],
    )
    .concat()
}

/// Decode spaced ASCII strings in place.
///
/// This handles strings like "V a r F i l e I n f o" -> "VarFileInfo"
/// which are common in PE resource sections and .NET metadata.
/// Strings that weren't already decoded during extraction are decoded here.
pub(crate) fn decode_spaced_strings(strings: &mut Vec<ExtractedString>, min_length: usize) {
    use std::collections::HashSet;
    let mut seen: HashSet<String> = HashSet::new();
    let mut new_strings = Vec::new();

    for s in strings.iter_mut() {
        // Skip strings already marked as SpacedAscii
        if s.method == StringMethod::SpacedAscii {
            seen.insert(s.value.clone());
            continue;
        }

        // Try to decode as spaced ASCII
        if let Some(decoded) = decoders::decode_spaced_ascii(&s.value)
            && decoded.len() >= min_length
            && !seen.contains(&decoded)
        {
            seen.insert(decoded.clone());

            // Create a new decoded string entry
            let kind = classifier::classify_string(&decoded);
            new_strings.push(ExtractedString {
                value: decoded,
                data_offset: s.data_offset,
                data_len: 0,
                method: StringMethod::SpacedAscii,
                kind,
                ..Default::default()
            });
        }
    }

    strings.extend(new_strings);
}
