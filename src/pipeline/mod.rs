//! The extraction pipeline for parsed binaries: one scan per format, then the
//! passes every format shares.

use crate::StringKind;
use crate::apply_xor_scan;
use crate::binary;
use crate::binary::SectionInfo;
use crate::decode_spaced_strings;
use crate::deduplicate_by_offset;
use crate::extract_raw_strings;
use crate::extract_stack_strings;
use crate::passes_garbage_filter;
use crate::scan_binary_ips;
use crate::{ExtractOptions, ExtractedString};
use goblin::Object;
use rayon::prelude::*;
use std::collections::HashMap;
use std::collections::HashSet;
mod elf;
pub(crate) mod macho;
mod pe;

use pe::suppress_version_info_ips;

/// Run independent passes on rayon's pool; their results, in task order.
pub(crate) fn parallel<const N: usize>(
    tasks: [&(dyn Fn() -> Vec<ExtractedString> + Sync); N],
) -> [Vec<ExtractedString>; N] {
    let mut results: Vec<Vec<ExtractedString>> = tasks.par_iter().map(|task| task()).collect();
    std::array::from_fn(|i| std::mem::take(&mut results[i]))
}

/// What a format's scan found.
pub(crate) struct Scan {
    pub(crate) strings: Vec<ExtractedString>,
    /// The file's sections, for code ranges.
    pub(crate) sections: Vec<SectionInfo>,
    /// A Go binary: its own passes cover it, so speculative XOR is skipped.
    pub(crate) is_go: bool,
}

/// Extract strings from a parsed binary.
pub(crate) fn extract(
    object: &Object<'_>,
    data: &[u8],
    opts: &ExtractOptions,
) -> Vec<ExtractedString> {
    let scan = match object {
        Object::Mach(goblin::mach::Mach::Binary(macho)) => macho::scan_thin(macho, data, opts),
        Object::Mach(goblin::mach::Mach::Fat(fat)) => macho::scan_fat(fat, data, opts),
        Object::Elf(elf) => elf::scan(elf, data, opts),
        Object::PE(pe) => pe::scan(pe, data, opts),
        _ => scan_other(data, opts),
    };
    finish(object, data, opts, scan)
}

/// Strings from an object goblin parsed but stng has no format pass for.
fn scan_other(data: &[u8], opts: &ExtractOptions) -> Scan {
    let min_length = opts.min_length;
    let mut strings = Vec::new();
    // Unknown format - use r2 if available, plus raw scan
    strings.extend(opts.r2_strings.iter().flatten().cloned());
    // Always do raw scan for unknown formats (r2 strings complement, not replace)
    if !data.is_empty() {
        strings.extend(extract_raw_strings(data, min_length, &[], &[]));
    }
    // Extract binary network data (IPs and ports in network byte order)
    // For unknown formats, use 0 (not M68000) to process normally
    strings.extend(scan_binary_ips(data, min_length, 0, None, None));
    strings.extend(extract_stack_strings(data, min_length));
    Scan {
        strings,
        sections: Vec::new(),
        is_go: false,
    }
}

/// The passes every format shares, over what its scan found: XOR decoding,
/// rizin's connect() addresses, code-signature reclassification, the
/// decoders, the garbage filter and offset deduplication.
fn finish(
    object: &Object<'_>,
    data: &[u8],
    opts: &ExtractOptions,
    scan: Scan,
) -> Vec<ExtractedString> {
    let min_length = opts.min_length;
    let Scan {
        mut strings,
        sections: section_info,
        is_go: is_go_binary,
    } = scan;
    // XOR string detection. `section_info` was populated by the format branch
    // above, so it doesn't need recomputing here.
    let is_pe = matches!(object, Object::PE(_));
    let excluded_ranges = binary::code_ranges_from_sections(&section_info);

    if !is_go_binary || opts.xor_key_offsets.is_some() || opts.xor_key.is_some() {
        apply_xor_scan(&mut strings, data, opts, is_pe, &excluded_ranges);
    }

    // IPs an external disassembler recovered from `connect()` call sites.
    if let Some(addrs) = &opts.rizin_connect_addrs {
        strings.extend(addrs.iter().cloned());
    }

    // Section names are no longer stored per-string (callers derive them from
    // the offset when needed). PE version-info IP suppression still applies.
    if let Object::PE(pe) = object {
        suppress_version_info_ips(&mut strings, pe);
    }

    macho::classify_code_signature(&mut strings, object);

    // Decode encoded strings (base64, hex, URL-encoding, unicode escapes).
    // Check cancellation between passes so a user-interrupted scan can bail
    // out without finishing every decoder on a multi-megabyte string set.
    let t_dec = std::time::Instant::now();
    if !opts.is_cancelled() {
        let decoded = crate::decode(&strings, crate::Rot13::No);
        strings.extend(decoded);
    }

    // Decode spaced ASCII strings (common in PE .rsrc, .NET metadata)
    decode_spaced_strings(&mut strings, min_length);
    tracing::debug!("TIME: Classification took {:?}", t_dec.elapsed());

    if opts.filter_garbage {
        // The garbage heuristic is the single most expensive post-extraction
        // pass (it runs `is_garbage_with_context` over every candidate). Each
        // verdict is independent, so evaluate them in parallel. `into_par_iter`
        // + `filter` + `collect` preserves the original order, matching the
        // sequential `retain` it replaces.
        let code_ranges = binary::code_ranges_from_sections(&section_info);
        strings = std::mem::take(&mut strings)
            .into_par_iter()
            .filter(|s| passes_garbage_filter(s, &code_ranges))
            .collect();
    }

    strip_go_varint_prefixes(&mut strings);

    deduplicate_by_offset(strings)
}

/// Merge a set of imports into the strings list.
/// Updates kind for strings already present, then appends new ones.
fn merge_imports(strings: &mut Vec<ExtractedString>, imports: Vec<ExtractedString>) {
    let import_map: HashMap<&str, Option<StringKind>> =
        imports.iter().map(|s| (s.value.as_str(), s.kind)).collect();
    for s in strings.iter_mut() {
        if let Some(&kind) = import_map.get(s.value.as_str()) {
            s.kind = kind;
        }
    }
    // Collect new imports first so that `seen` (which borrows `strings`) is
    // dropped before the mutable `strings.extend()` call below.
    let new_imports: Vec<_> = {
        let seen: HashSet<&str> = strings.iter().map(|s| s.value.as_str()).collect();
        imports
            .into_iter()
            .filter(|s| !seen.contains(s.value.as_str()))
            .collect()
    };
    strings.extend(new_imports);
}

/// Strip Go varint length-prefix bytes that bled into otherwise-clean strings.
///
/// Go's pclntab `pkgnamestab` packs entries as `<varint length byte><N bytes>`.
/// Raw printable scanners (including radare2's `izz`) capture the length byte
/// as the first character of the string. When the pattern is unambiguous —
/// the leading byte is a small printable value, equals the length of the
/// remainder, the remainder is all printable ASCII, and starts with a
/// module-path-like character — we strip the prefix in place.
fn strip_go_varint_prefixes(strings: &mut [ExtractedString]) {
    for s in strings.iter_mut() {
        let bytes = s.value.as_bytes();
        if bytes.len() < 6 {
            continue;
        }
        let prefix = bytes[0];
        // Only consider single-byte varint lengths (1..0x80) that are also
        // printable punctuation. Skip unambiguous separators like ' '.
        if !(0x21..0x7F).contains(&prefix) {
            continue;
        }
        let rest = &bytes[1..];
        if rest.len() != prefix as usize {
            continue;
        }
        // Tight predicate: rest must look like a Go package path or type name.
        // Starts with letter/underscore/* / [ / ( / .
        // Body: alnum + path/type punctuation only.
        let starts_ok = matches!(
            rest[0],
            b'a'..=b'z' | b'A'..=b'Z' | b'_' | b'*' | b'[' | b'(' | b'.'
        );
        if !starts_ok {
            continue;
        }
        let body_ok = rest.iter().all(|&b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'/' | b'.' | b'_' | b'-' | b'*' | b'[' | b']' | b'(' | b')' | b' '
                )
        });
        if !body_ok {
            continue;
        }
        // Module-path / Go-type heuristic: contains '/' or '.' (rules out
        // 33-letter random alphabet sequences).
        if !rest.iter().any(|&b| b == b'/' || b == b'.') {
            continue;
        }
        // Safe to strip in place: byte 0 is ASCII, so byte 1 is a char boundary.
        s.value.drain(..1);
        s.data_offset += 1;
    }
}
