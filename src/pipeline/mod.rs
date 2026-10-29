//! The extraction pipeline for parsed binaries: one scan per format, then the
//! passes every format shares.

use crate::binary;
use crate::binary::SectionInfo;
use crate::extract_raw_strings;
use crate::extract_stack_strings;
use crate::scan_binary_ips;
use crate::{ExtractOptions, ExtractedString};
use crate::{StringKind, StringMethod, classifier, par, validation};
use decode::decode_spaced_strings;
use goblin::Object;
use rayon::prelude::*;
use std::collections::HashMap;
use std::collections::HashSet;
use xor::apply_xor_scan;
pub(crate) mod decode;
mod elf;
pub(crate) mod java;
pub(crate) mod macho;
mod pe;
pub(crate) mod text;
pub(crate) mod xor;

use pe::suppress_version_info_ips;

/// Run independent passes, on rayon's pool when `split` (see [`crate::par`]);
/// their results, in task order.
pub(crate) fn parallel<const N: usize>(
    split: bool,
    tasks: [&(dyn Fn() -> Vec<ExtractedString> + Sync); N],
) -> [Vec<ExtractedString>; N] {
    if !split {
        return tasks.map(|task| task());
    }
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
    strings.extend(opts.hints.strings.iter().cloned());
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

    if !is_go_binary || opts.xor_explicit() {
        apply_xor_scan(&mut strings, data, opts, is_pe, &excluded_ranges);
    }

    // IPs an external disassembler recovered from `connect()` call sites.
    strings.extend(opts.hints.connect_addrs.iter().cloned());

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
        let decoded = decode::decode(&strings, decode::Rot13::No);
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
            .with_min_len(crate::par::MIN_ITEMS_PER_JOB)
            .filter(|s| passes_garbage_filter(s, &code_ranges))
            .collect();
    }

    strip_go_varint_prefixes(&mut strings);

    deduplicate_by_offset(strings)
}

/// Append the `candidates` whose values `strings` does not already hold.
fn extend_unclaimed(
    strings: &mut Vec<ExtractedString>,
    candidates: impl IntoIterator<Item = ExtractedString>,
) {
    let fresh: Vec<ExtractedString> = {
        let known: HashSet<&str> = strings.iter().map(|s| s.value.as_str()).collect();
        candidates
            .into_iter()
            .filter(|s| !known.contains(s.value.as_str()))
            .collect()
    };
    strings.extend(fresh);
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

/// Extract stack strings from every executable section whose byte range is
/// given by `exec_ranges`.  Section ranges are parsed by
/// `binary::collect_*_section_info` and filtered to the executable ones.
///
/// This avoids feeding the entire file to iced-x86 — for a typical PE or
/// Mach-O only a small fraction is code, and disassembling `.rdata` /
/// `__LINKEDIT` as x86 is pure waste.  ELF already did this filtering
/// inline; this helper generalises the pattern so PE and Mach-O get the
/// same win.
pub(crate) fn extract_stack_strings_from_ranges(
    data: &[u8],
    min_length: usize,
    exec_ranges: &[(usize, usize)],
) -> Vec<ExtractedString> {
    if exec_ranges.is_empty() {
        return Vec::new();
    }
    exec_ranges
        .par_iter()
        .with_min_len(par::job_len(exec_ranges.len(), data.len()))
        .filter_map(|&(start, end)| {
            let end = end.min(data.len());
            if start >= end {
                return None;
            }
            let section_data = data.get(start..end)?;
            let mut results = extract_stack_strings(section_data, min_length);
            for r in &mut results {
                r.rebase(start as u64);
            }
            Some(results)
        })
        .flatten()
        .collect()
}

/// Returns `true` if a string should be kept when garbage filtering is enabled.
/// Encoded strings and special kinds are always kept regardless of content.
///
/// Runs `is_garbage_with_context` so architecture- and section-aware
/// filters (notably the x86 push/pop save-sequence detector) can scope
/// themselves to the right inputs. Kind, section, and arch all come
/// from the `ExtractedString` itself when known.
pub(crate) fn passes_garbage_filter(s: &ExtractedString, code_ranges: &[(usize, usize)]) -> bool {
    // A referenced pointer/length can describe a complete multiline literal
    // (scripts, XML, configuration). Preserve clean ASCII text layout without
    // relaxing the control-character check for unstructured machine-code noise.
    if s.method == StringMethod::InstructionPattern
        && s.value.trim().contains(['\n', '\r', '\t'])
        && s.value
            .bytes()
            .all(|b| (b' '..=b'~').contains(&b) || matches!(b, b'\n' | b'\r' | b'\t'))
    {
        return true;
    }
    // Strings produced by our own decoders / deobfuscators are
    // *deliberately* surfaced — base64-decoded payloads, XOR-decrypted
    // C2 URLs, deobfuscated VBScript fragments, etc. The garbage
    // heuristic is meant to suppress raw-scan noise from binary
    // sections, not to second-guess the decoder pipeline. Without
    // this gate, decoded entries get reclassified by `classify_string`
    // on their *content* (e.g. obfuscated PowerShell with diacritic
    // letters), `kind` lands somewhere other than `Base64`, and the
    // `is_garbage_with_context` check below culls them — exactly the
    // payload bytes the caller asked us to decode.
    //
    // Limited to *deterministic transformation* methods (decode /
    // unobfuscate); raw scan variants like `RawScan` and `WideString` are
    // still subject to the garbage check.
    //
    // `StackString` is deliberately NOT exempt. Unlike the decoders above —
    // which reverse a known, reversible encoding and so produce trustworthy
    // output — stack-string extraction is a *heuristic* reconstruction of
    // bytes laid into a stack frame. It readily assembles junk (a block of
    // 0x3f stack fills becomes `????????`, register save patterns become
    // `wwwwwwww`). Exempting the whole method surfaced that noise whenever
    // the caller asked for filtering. Routing stack strings through
    // `is_garbage_with_context` (kind-aware: `StackString` is treated as
    // provenance, so real reconstructions still pass) drops the junk while
    // keeping genuine deobfuscated payloads. Raw mode (`filter_garbage`
    // off) never reaches this function, so it still surfaces every fragment.
    if matches!(
        s.method,
        StringMethod::Structure
            | StringMethod::Base64Decode
            | StringMethod::Base64ObfuscatedDecode
            | StringMethod::HexDecode
            | StringMethod::UrlDecode
            | StringMethod::UnicodeEscapeDecode
            | StringMethod::ScriptDecode
            | StringMethod::CfmlDecode
            | StringMethod::XorDecode
    ) {
        return true;
    }
    if matches!(
        s.kind,
        Some(
            StringKind::EntitlementsXml
                | StringKind::Section
                | StringKind::Base64
                | StringKind::Base32
                | StringKind::Base85
                | StringKind::HexEncoded
                | StringKind::UrlEncoded
                | StringKind::UnicodeEscaped
                | StringKind::XorKey
        )
    ) {
        return true;
    }
    // Derive the code-section flag from the offset: `code_ranges` are the
    // executable byte ranges (built once from section headers). Empty ranges
    // mean "no section info" → unknown. Replaces the per-string section name
    // that `ExtractedString` no longer carries.
    let in_code_section = if code_ranges.is_empty() {
        None
    } else {
        // The ranges are sorted and disjoint: find the last one starting at or
        // before the offset.
        let off = usize::try_from(s.data_offset).unwrap_or(usize::MAX);
        let i = code_ranges.partition_point(|&(start, _)| start <= off);
        Some(i > 0 && off < code_ranges[i - 1].1)
    };
    let ctx = crate::types::StringContext {
        kind: s.kind,
        in_code_section,
        // Arch hint was only ever stamped *after* this filter ran (or not at
        // all on the main path), so it was always `None` here in practice.
        arch: None,
    };
    !validation::is_garbage_with_context(&s.value, &ctx)
}

/// Raw-scan strings minus what the language passes in `claimed` already cover.
///
/// rustc packs `&str` literals back to back with no terminator, so one raw run
/// can span a literal the structure pass sliced out and bytes it never named:
/// `src/main.rshttps://host/x.png` when only `src/main.rs` is referenced.
/// Offset dedup keeps the higher-priority slice and would discard the whole run,
/// URL included. Instead each raw run is cut around the claimed byte spans and
/// only the unclaimed pieces of at least `min_length` bytes are returned. Runs
/// whose value a pass already produced are dropped outright.
pub(crate) fn unclaimed_raw_strings(
    raw: Vec<ExtractedString>,
    claimed: &[ExtractedString],
    min_length: usize,
) -> Vec<ExtractedString> {
    let known: HashSet<&str> = claimed.iter().map(|s| s.value.as_str()).collect();
    let mut spans: Vec<(u64, u64)> = claimed
        .iter()
        .map(|s| (s.data_offset, s.data_offset + s.value.len() as u64))
        .collect();
    spans.sort_unstable();
    let longest = spans.iter().map(|&(a, b)| b - a).max().unwrap_or(0);

    let mut out = Vec::with_capacity(raw.len());
    for s in raw {
        if known.contains(s.value.as_str()) {
            continue;
        }
        let start = s.data_offset;
        let end = start + s.value.len() as u64;
        // Spans sorted by start: those overlapping [start, end) begin before
        // `end` and no earlier than `start - longest`.
        let lo = spans.partition_point(|&(a, _)| a < start.saturating_sub(longest));
        let hi = spans.partition_point(|&(a, _)| a < end);
        let overlapping: Vec<(u64, u64)> = spans[lo..hi]
            .iter()
            .filter(|&&(_, b)| b > start)
            .copied()
            .collect();
        if overlapping.is_empty() {
            out.push(s);
            continue;
        }

        let mut cursor = start;
        let mut pieces = Vec::new();
        for (a, b) in overlapping {
            if a > cursor {
                pieces.push((cursor, a));
            }
            cursor = cursor.max(b);
        }
        if cursor < end {
            pieces.push((cursor, end));
        }
        for (a, b) in pieces {
            let (Ok(lo), Ok(hi)) = (usize::try_from(a - start), usize::try_from(b - start)) else {
                continue;
            };
            let Some(value) = s.value.get(lo..hi) else {
                continue;
            };
            if value.len() < min_length || known.contains(value) {
                continue;
            }
            out.push(ExtractedString {
                value: value.to_string(),
                data_offset: a,
                kind: classifier::classify_string(value),
                ..s.clone()
            });
        }
    }
    out
}

/// Deduplicate strings by keeping only the best string at each offset.
///
/// Uses a single in-place sort + `dedup_by_key` pass — no HashMap allocation.
/// The sort key is `(offset asc, priority desc, length desc)` so the first
/// entry at each offset is the best candidate and `dedup_by_key(data_offset)`
/// keeps it.  Best candidate = highest `StringMethod::dedup_priority`, tied
/// with longer `value`. Remaining ties prefer a classified kind and a recorded
/// (larger) extent, then break on method, value and fragments, so the survivor
/// never depends on the order passes produced candidates in.
pub(crate) fn deduplicate_by_offset(mut strings: Vec<ExtractedString>) -> Vec<ExtractedString> {
    if strings.len() < 2 {
        return strings;
    }

    strings.sort_unstable_by(|a, b| {
        a.data_offset
            .cmp(&b.data_offset)
            .then_with(|| {
                // Descending priority: higher priority first.
                b.method.dedup_priority().cmp(&a.method.dedup_priority())
            })
            .then_with(|| {
                // Descending length: longer first.
                b.value.len().cmp(&a.value.len())
            })
            .then_with(|| b.kind.cmp(&a.kind))
            .then_with(|| b.data_len.cmp(&a.data_len))
            .then_with(|| a.method.cmp(&b.method))
            .then_with(|| a.value.cmp(&b.value))
            .then_with(|| a.fragments.cmp(&b.fragments))
    });

    // Every offset is file-relative (Mach-O section/VA offsets are rebased at the
    // source), so a file offset names exactly one location: keying the dedup on
    // the offset alone collapses true duplicates. The exception is strings
    // decoded from a script blob, which all carry the blob's offset; they are
    // kept apart, one per value.
    let (mut derived, mut strings): (Vec<_>, Vec<_>) = strings
        .into_iter()
        .partition(|s| s.method == StringMethod::ScriptDecode);
    strings.dedup_by(|a, b| a.data_offset == b.data_offset);
    derived.sort_by(|a, b| (a.data_offset, &a.value).cmp(&(b.data_offset, &b.value)));
    derived.dedup_by(|a, b| a.data_offset == b.data_offset && a.value == b.value);
    strings.extend(derived);
    strings.sort_by_key(|s| s.data_offset);
    strings
}
