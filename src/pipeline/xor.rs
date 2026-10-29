//! The XOR passes over a whole input: single-byte, auto-detected,
//! user-supplied, rolling, incremental and disassembler-located keys.

use crate::{
    ExtractOptions, ExtractedString, FormatHint, StringKind, StringMethod, XorMode, binary, detect,
    xor,
};

/// Whether the XOR scanners may run over `data`.
///
/// They hunt obfuscation in executable code and binary data. On text —
/// source, documents, hex dumps — they find only noise: no real-world sample
/// shows them recovering anything from text, and on source carrying a `^` they
/// cost about a tenth of extraction. So text is skipped, unless the caller
/// names the key and so knows better. Text carriers keep decoders shaped for
/// them: hex-then-XOR over decoded hex strings ([`decoders`]), and script
/// deobfuscation, which recovers the key from the code.
pub(crate) fn scans_for_xor(data: &[u8], opts: &ExtractOptions) -> bool {
    opts.xor_key().is_some() || (opts.format_hint != FormatHint::Text && detect::is_binary(data))
}

/// The single-byte XOR pattern scan. A key that decodes two or more strings
/// is in use throughout the file, so it gets a full extraction pass, which
/// also finds strings with no trigger pattern (syscall names, log paths) and
/// supersedes that key's pattern hits.
pub(crate) fn single_byte_xor_scan(
    strings: &mut Vec<ExtractedString>,
    data: &[u8],
    opts: &ExtractOptions,
    is_pe: bool,
) {
    let found = xor::extract_xor_strings(data, opts.xor_min_length, is_pe);
    // Each result is a single-byte decode, so `value[0] == data[offset] ^
    // key` (for UTF-16 too: the first character's low byte) recovers its key.
    let key_of = |r: &ExtractedString| -> Option<u8> {
        let off = usize::try_from(r.data_offset).ok()?;
        Some(data.get(off)? ^ r.value.as_bytes().first()?)
    };
    let mut counts = [0usize; 256];
    for key in found.iter().filter_map(key_of) {
        counts[usize::from(key)] += 1;
    }
    let mut full = [false; 256];
    for key in 0..=u8::MAX {
        if counts[usize::from(key)] >= 2 && !xor::SKIP_XOR_KEYS.contains(&key) {
            strings.extend(xor::extract_custom_xor_strings_with_hints(
                data,
                &[key],
                opts.xor_min_length,
                &opts.hints.boundaries,
                opts.filter_garbage,
                false,
            ));
            full[usize::from(key)] = true;
        }
    }
    strings.extend(
        found
            .into_iter()
            .filter(|r| key_of(r).is_none_or(|k| !full[usize::from(k)])),
    );
}

/// Run XOR scanning and extend `strings` with any decoded results.
///
/// `excluded_ranges` is a sorted list of `[start, end)` byte ranges the
/// scanner must skip. Callers with a parsed binary pass the file offsets of
/// executable sections — XOR-obfuscated strings don't live in `.text`, so
/// skipping those ranges cuts the scanned-byte count on a typical binary
/// by 60-80% with near-zero risk of missing legitimate hits.
pub(crate) fn apply_xor_scan(
    strings: &mut Vec<ExtractedString>,
    data: &[u8],
    opts: &ExtractOptions,
    is_pe: bool,
    excluded_ranges: &[(usize, usize)],
) {
    tracing::debug!(
        mode = ?opts.xor,
        key_offsets = opts.hints.xor_key_offsets.len(),
        "apply_xor_scan"
    );
    if data.is_empty() || opts.is_cancelled() {
        return;
    }
    // Every return below precedes the first string this scan adds.
    let first_added = strings.len();

    if !scans_for_xor(data, opts) {
        tracing::debug!("Skipping XOR scan: text input");
        return;
    }

    // Platform-signed binaries (Apple/Microsoft OS binaries) are vetted
    // upstream; malware-vs-legitimate single-byte XOR obfuscation never
    // survives platform signing. Skipping XOR on these is the single biggest
    // throughput win for typical system-binary corpora. Third-party
    // Developer ID signatures are NOT matched — those CAN be signed malware.
    // An explicit key or `XorMode::Scan` bypasses this.
    if !opts.xor_explicit() && binary::is_platform_signed(data) {
        tracing::debug!("Skipping XOR scan: platform-signed binary");
        return;
    }

    let t_xor = std::time::Instant::now();

    // For PE binaries, also try rolling XOR with known plaintext patterns
    // This catches .NET malware like Redline that uses short cycling keys
    if is_pe && data.len() <= xor::MAX_XOR_SCAN_SIZE {
        let rolling_results = xor::extract_rolling_xor_with_known_plaintext(
            data,
            opts.xor_min_length,
            excluded_ranges,
        );
        strings.extend(rolling_results);
    }

    let boundaries = &opts.hints.boundaries;

    if let Some(key) = opts.xor_key() {
        let key_str = String::from_utf8_lossy(key);
        if let Some(ks) = strings.iter_mut().find(|s| s.value == key_str.as_ref()) {
            ks.kind = Some(StringKind::XorKey);
        }
        strings.extend(xor::extract_custom_xor_strings_with_hints(
            data,
            key,
            opts.xor_min_length,
            boundaries,
            opts.filter_garbage,
            false, // User-provided key: disable early termination for complete extraction
        ));
    } else if opts.xor_scans() {
        let auto_key = if data.len() <= xor::MAX_AUTO_DETECT_SIZE {
            xor::auto_detect_xor_key(data, strings, opts.xor_min_length)
        } else {
            None
        };
        if let Some((key, key_str, key_offset)) = auto_key {
            // Mark ALL occurrences of the key string as XorKey. Fat binaries
            // contain the same string at multiple arch offsets; the value-dedup
            // in main.rs keeps whichever copy comes first, so every copy must
            // carry the XorKey kind to survive as the correct kind.
            let mut marked = false;
            for ks in strings.iter_mut().filter(|s| s.value == key_str) {
                ks.kind = Some(StringKind::XorKey);
                marked = true;
            }
            if !marked {
                tracing::warn!(
                    key = ?key_str,
                    "XOR key not found in extracted strings — injecting"
                );
                strings.push(ExtractedString {
                    value: key_str.clone(),
                    data_offset: key_offset,
                    data_len: 0,
                    method: StringMethod::XorDecode,
                    kind: Some(StringKind::XorKey),
                    fragments: None,
                });
            }
            strings.extend(xor::extract_custom_xor_strings_with_hints(
                data,
                &key,
                opts.xor_min_length,
                boundaries,
                opts.filter_garbage,
                false, // Even for auto-detected keys, extract completely for final results
            ));
        } else {
            single_byte_xor_scan(strings, data, opts, is_pe);
        }

        // Always run incremental XOR detection if enabled - it might complement regular XOR
        let inc_results =
            xor::extract_incremental_xor_strings(data, opts.xor_min_length, excluded_ranges);
        strings.extend(inc_results);
    }

    // Code an external disassembler found loading an XOR key: decode the
    // file with the key at each such offset.
    if opts.xor == XorMode::Scan && !opts.hints.xor_key_offsets.is_empty() {
        strings.extend(xor::extract_multikey_xor_strings(
            data,
            &opts.hints.xor_key_offsets,
            opts.xor_min_length,
        ));
    }

    xor::report_kinds(&mut strings[first_added..]);
    tracing::debug!("TIME: XOR key scanning took {:?}", t_xor.elapsed());
}
