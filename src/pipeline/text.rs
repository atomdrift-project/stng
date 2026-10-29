//! Text inputs: UTF-16 files, and script deobfuscation.

use super::deduplicate_by_offset;
use crate::raw::extract_raw_strings;
use crate::{
    ExtractOptions, ExtractedString, StringMethod, classifier, decode_encoded_strings,
    is_text_file, script,
};

/// Extract strings from a UTF-16 encoded file (detected by BOM).
///
/// When a UTF-16 BOM is detected at the start of a file, this function:
/// 1. Decodes the entire file from UTF-16 to UTF-8
/// 2. Extracts strings from the decoded UTF-8 content
/// 3. Marks all strings with the appropriate StringMethod (Utf16LeDecode or Utf16BeDecode)
///
/// This is common for JavaScript malware, PowerShell scripts, and other text files
/// saved in UTF-16 encoding on Windows systems.
pub(crate) fn extract_from_utf16_file(
    data: &[u8],
    opts: &ExtractOptions,
    is_little_endian: bool,
) -> Vec<ExtractedString> {
    let mut strings = Vec::new();

    // Skip the 2-byte BOM and decode the rest
    if data.len() < 2 {
        return strings;
    }

    let utf16_data = &data[2..];

    // Convert bytes to u16 code units
    if !utf16_data.len().is_multiple_of(2) {
        // Odd number of bytes - can't be valid UTF-16, truncate last byte
        tracing::warn!("UTF-16 file has odd byte count, truncating last byte");
    }

    // Decode UTF-16 to UTF-8, streaming code units straight from the byte
    // slice so the whole-file Vec<u16> intermediate is never materialized.
    let code_units = utf16_data.as_chunks::<2>().0.iter().map(|chunk| {
        if is_little_endian {
            u16::from_le_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], chunk[1]])
        }
    });
    let decoded: String = char::decode_utf16(code_units)
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect();
    let decoded_bytes = decoded.as_bytes();

    // Extract strings from the decoded UTF-8 content
    let mut raw_strings = extract_raw_strings(decoded_bytes, opts.min_length, &[], &[]);

    // Apply decoders (base64, hex, URL-encoding, etc.) to the extracted strings
    // This allows us to find base64-encoded PowerShell, hex-encoded URLs, etc.
    let decoded_strings = decode_encoded_strings(&raw_strings);

    // Update the method for all extracted strings to indicate they came from UTF-16 decoding
    // (but preserve the method for decoded strings - they should show Base64Decode, etc.)
    let method = if is_little_endian {
        StringMethod::Utf16LeDecode
    } else {
        StringMethod::Utf16BeDecode
    };

    for string in &mut raw_strings {
        string.method = method;
    }

    strings.extend(raw_strings);
    strings.extend(decoded_strings);

    deduplicate_by_offset(strings)
}

/// Recover a text file whose UTF-16 BOM was prepended to ordinary bytes.
///
/// Some malware builders use this malformed wrapper to confuse tools that
/// select a decoder solely from the first two bytes. A genuine UTF-16 source
/// containing ASCII necessarily has NUL bytes between its code units, so NULs
/// in at most one byte of eight mark the bytes as 8-bit text. The count is a
/// density, not "none at all": one planted NUL or invalid UTF-8 byte must not
/// turn an ASCII script into CJK and hide every string in it. The text then
/// gets the decoders and script deobfuscation any other text file gets.
pub(crate) fn extract_from_malformed_utf16_bom_file(
    data: &[u8],
    opts: &ExtractOptions,
) -> Option<Vec<ExtractedString>> {
    let payload = data.get(2..)?;
    if memchr::memchr_iter(0, payload).count().saturating_mul(8) > payload.len() {
        return None;
    }

    let mut strings = extract_raw_strings(payload, opts.min_length, &[], &[]);
    for string in &mut strings {
        // `payload` omits the BOM, but consumers expect file-relative offsets.
        string.data_offset = string.data_offset.saturating_add(2);
    }
    let decoded = decode_encoded_strings(&strings);
    strings.extend(decoded);
    // Not gated on `is_text_file`: the BOM already claims text, and one
    // planted byte must not switch deobfuscation off.
    append_script_deobfuscation(&mut strings, payload, opts);
    Some(strings)
}

/// Run script deobfuscation and append decoded strings.
///
/// Detects Python/JS/PHP/PowerShell obfuscation patterns in text data,
/// decodes hidden payloads, extracts strings from them, and appends
/// them to the existing string list with `ScriptDecode` method.
pub(crate) fn append_script_deobfuscation(
    strings: &mut Vec<ExtractedString>,
    data: &[u8],
    opts: &ExtractOptions,
) {
    let deob_results = script::deobfuscate_script(data);
    for result in deob_results {
        let payload_bytes = result.decoded.as_bytes();
        let mut payload_strings = extract_raw_strings(payload_bytes, opts.min_length, &[], &[]);

        let payload_decoded = decode_encoded_strings(&payload_strings);
        payload_strings.extend(payload_decoded);

        // Mark all strings as ScriptDecode with provenance.
        // Use a high base offset to avoid collisions with raw-scan strings from
        // the original file during deduplication.
        let base_offset = data.len() as u64 + 1 + result.offset as u64;
        for s in &mut payload_strings {
            s.method = StringMethod::ScriptDecode;
            s.kind = classifier::classify_string(&s.value);
            s.rebase(base_offset);
        }

        strings.extend(payload_strings);
    }
}

/// Script deobfuscation normally runs only for inputs identified as text. A
/// self-identifying VBScript.Encode marker is also sufficient evidence: its
/// encoded body can contain enough control/high bytes to classify an ASP page
/// as binary. Check strings already extracted by the normal scan so binary
/// inputs without the marker pay no additional full-file scan.
pub(crate) fn should_deobfuscate_script(data: &[u8], strings: &[ExtractedString]) -> bool {
    is_text_file(data) || strings.iter().any(|s| s.value.contains("#@~^"))
}
