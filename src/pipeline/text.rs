//! Text inputs: UTF-16 files, and script deobfuscation.

use super::deduplicate_by_offset;
use crate::raw::extract_raw_strings;
use crate::{
    ExtractOptions, ExtractedString, StringMethod, classifier, decode_encoded_strings, script,
};

/// Extract strings from a UTF-16 file (one with a byte-order mark).
///
/// The text is decoded to UTF-8 and scanned as text; every offset and length
/// is mapped back to the UTF-16 bytes it came from, so a string found at
/// character `n` is reported at file offset `2 + 2n` (BMP text). Raw strings
/// get `Utf16LeDecode` or `Utf16BeDecode`; decoded ones keep their method.
pub(crate) fn extract_from_utf16_file(
    data: &[u8],
    opts: &ExtractOptions,
    is_little_endian: bool,
) -> Vec<ExtractedString> {
    let Some(utf16) = data.get(2..) else {
        return Vec::new();
    };
    if !utf16.len().is_multiple_of(2) {
        tracing::debug!("UTF-16 file has an odd byte count; the last byte is ignored");
    }
    let units = utf16.as_chunks::<2>().0.iter().map(|&pair| {
        if is_little_endian {
            u16::from_le_bytes(pair)
        } else {
            u16::from_be_bytes(pair)
        }
    });

    // Decode, recording the file offset where each character starts.
    let mut text = String::with_capacity(utf16.len() / 2);
    let mut starts: Vec<(usize, u64)> = Vec::with_capacity(utf16.len() / 2);
    let mut at = 2u64;
    for unit in char::decode_utf16(units) {
        starts.push((text.len(), at));
        let (c, units) = match unit {
            Ok(c) => (c, c.len_utf16()),
            Err(_) => (char::REPLACEMENT_CHARACTER, 1),
        };
        at += 2 * units as u64;
        text.push(c);
    }
    let end = at;
    let locate = |offset: u64| -> u64 {
        let Ok(offset) = usize::try_from(offset) else {
            return end;
        };
        starts
            .binary_search_by_key(&offset, |&(decoded, _)| decoded)
            .map_or(end, |i| starts[i].1)
    };

    let mut strings = extract_raw_strings(text.as_bytes(), opts.min_length, &[], &[]);
    for s in &mut strings {
        let start = locate(s.data_offset);
        let stop = locate(s.data_offset.saturating_add(s.value.len() as u64));
        s.data_offset = start;
        s.data_len = u32::try_from(stop - start).unwrap_or(u32::MAX);
    }
    let method = if is_little_endian {
        StringMethod::Utf16LeDecode
    } else {
        StringMethod::Utf16BeDecode
    };
    finish_text(strings, text.as_bytes(), opts, &locate, Some(method))
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
    // `payload` omits the BOM; offsets are file offsets.
    let locate = |offset: u64| offset.saturating_add(2);
    for s in &mut strings {
        s.data_offset = locate(s.data_offset);
    }
    Some(finish_text(strings, payload, opts, &locate, None))
}

/// The passes a text file's strings share: the decoders, the garbage filter
/// and script deobfuscation of `text`, then offset deduplication. `locate`
/// maps an offset in `text` to one in the file; `method`, if given, relabels
/// the raw strings after the decoders have seen them.
fn finish_text(
    mut strings: Vec<ExtractedString>,
    text: &[u8],
    opts: &ExtractOptions,
    locate: &dyn Fn(u64) -> u64,
    method: Option<StringMethod>,
) -> Vec<ExtractedString> {
    let decoded = if opts.is_cancelled() {
        Vec::new()
    } else {
        decode_encoded_strings(&strings)
    };
    if let Some(method) = method {
        for s in &mut strings {
            s.method = method;
        }
    }
    strings.extend(decoded);
    if opts.filter_garbage {
        strings.retain(|s| super::passes_garbage_filter(s, &[]));
    }
    // Not gated on `is_text_file`: the BOM already claims text, and one
    // planted byte must not switch deobfuscation off.
    if !opts.is_cancelled() {
        let first = strings.len();
        append_script_deobfuscation(&mut strings, text, opts);
        for s in &mut strings[first..] {
            s.data_offset = locate(s.data_offset);
        }
    }
    deduplicate_by_offset(strings)
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

        // Each string is located at the encoded blob it was decoded from;
        // deduplication keys these derived strings on their value too.
        for s in &mut payload_strings {
            s.method = StringMethod::ScriptDecode;
            s.kind = classifier::classify_string(&s.value);
            s.data_offset = result.offset as u64;
            s.data_len = 0;
            s.fragments = None;
        }

        strings.extend(payload_strings);
    }
}
