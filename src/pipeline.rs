//! The extraction pipeline for parsed binaries: one scan per format, then the
//! passes every format shares.

use crate::binary::{self, SectionInfo};
use crate::layouts::Layouts;
use crate::raw::{extract_raw_strings, extract_wide_strings};
use crate::sockaddr::scan_binary_ips;
use crate::stack_strings::extract_stack_strings;
use crate::{
    ExtractOptions, ExtractedString, StringKind, StringMethod, classifier, is_text_file, par,
    validation,
};
use decode::decode_spaced_strings;
use goblin::Object;
use pe::suppress_version_info_ips;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::ops::Range;
use xor::apply_xor_scan;

pub(crate) mod decode;
mod elf;
pub(crate) mod java;
pub(crate) mod macho;
mod pe;
pub(crate) mod text;
pub(crate) mod xor;

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
/// `layouts` holds, or reads on first use, binform's layouts of `data`.
pub(crate) fn extract<'d>(
    object: &Object<'_>,
    layouts: &Layouts<'_, 'd>,
    data: &'d [u8],
    opts: &ExtractOptions,
) -> Vec<ExtractedString> {
    let scan = match object {
        Object::Mach(goblin::mach::Mach::Binary(macho)) => {
            macho::scan_thin(macho, layouts, data, opts)
        }
        Object::Mach(goblin::mach::Mach::Fat(fat)) => macho::scan_fat(fat, layouts, data, opts),
        Object::Elf(elf) => elf::scan(elf, layouts, data, opts),
        Object::PE(pe) => pe::scan(pe, layouts, data, opts),
        _ => scan_unknown(data, opts),
    };
    finish(Some(object), data, opts, scan)
}

/// Extract strings from input goblin does not parse as a binary: text,
/// scripts, and binaries it cannot read.
pub(crate) fn extract_unknown(data: &[u8], opts: &ExtractOptions) -> Vec<ExtractedString> {
    finish(None, data, opts, scan_unknown(data, opts))
}

/// Strings from input with no format pass: a raw scan, and what an `MZ`
/// header, a ColdFusion template, `sockaddr_in` structures and stack-built
/// strings add.
fn scan_unknown(data: &[u8], opts: &ExtractOptions) -> Scan {
    let min_length = opts.min_length;
    let mut strings = Vec::new();
    // An `MZ` file goblin could not parse is still likely Windows, whose
    // strings are often UTF-16.
    if data.starts_with(b"MZ") {
        strings.extend(extract_wide_strings(data, min_length, &[], &[]));
    }
    strings.extend(extract_raw_strings(data, min_length, &[], &[]));
    // Legacy ColdFusion templates are DES-encrypted CFML behind a fixed
    // signature. The decrypted source is one string, so later passes see the
    // template body.
    if !opts.is_cancelled()
        && let Some(source) = crate::cfml::decode(data)
        && source.len() >= min_length
    {
        strings.push(ExtractedString {
            value: String::from_utf8_lossy(&source).into_owned(),
            data_offset: 0,
            data_len: u32::try_from(data.len()).unwrap_or(u32::MAX),
            method: StringMethod::CfmlDecode,
            kind: None,
            fragments: None,
        });
    }
    // Machine 0: no format, so no architecture to exclude.
    strings.extend(scan_binary_ips(data, min_length, 0, None, None));
    // No format, so no architecture: x86-64 is the likeliest code.
    strings.extend(extract_stack_strings(data, min_length, 64));
    Scan {
        strings,
        sections: Vec::new(),
        is_go: false,
    }
}

/// The passes every input shares, over what its scan found: XOR decoding,
/// the decoders, script deobfuscation, the garbage filter and offset
/// deduplication. `object` is `None` for input goblin did not parse.
fn finish(
    object: Option<&Object<'_>>,
    data: &[u8],
    opts: &ExtractOptions,
    scan: Scan,
) -> Vec<ExtractedString> {
    let min_length = opts.min_length;
    let Scan {
        mut strings,
        sections,
        is_go,
    } = scan;
    let code_ranges = binary::code_ranges_from_sections(&sections);
    let is_pe = object.map_or_else(|| data.starts_with(b"MZ"), |o| matches!(o, Object::PE(_)));
    tracing::debug!(
        strings = strings.len(),
        sections = sections.len(),
        is_go,
        is_pe,
        "format scan finished"
    );

    if !is_go || opts.xor_explicit() {
        apply_xor_scan(&mut strings, data, opts, is_pe, &code_ranges);
    }

    match object {
        Some(object) => {
            // Version numbers in PE version info look like IPs.
            if let Object::PE(pe) = object {
                suppress_version_info_ips(&mut strings, pe);
            }
            macho::classify_code_signature(&mut strings, object);
        }
        // A PE under a repeating XOR key is opaque to goblin, so it can only
        // land here. Recovery reads a fixed 128-byte header, so it needs no
        // size gate; text is skipped as `apply_xor_scan` skips it. Only the
        // key is surfaced; the decoded image is binary, for callers of
        // `recover_repeating_xor_pe`.
        None => {
            if opts.xor_scans()
                && xor::scans_for_xor(data, opts)
                && let Some(key) = crate::xor::recover_repeating_xor_pe(data)
            {
                strings.push(key.to_key_string());
            }
        }
    }

    // Base64, hex, URL encoding and escapes. Cancellation is checked before
    // the decoders, which are the slowest pass over a large string set.
    let t_dec = std::time::Instant::now();
    let before_decoding = strings.len();
    if !opts.is_cancelled() {
        let decoded = decode::decode(&strings, decode::Rot13::No);
        strings.extend(decoded);
    }
    // Spaced ASCII, common in PE .rsrc and .NET metadata.
    decode_spaced_strings(&mut strings, min_length);
    tracing::debug!(
        elapsed = ?t_dec.elapsed(),
        decoded = strings.len().saturating_sub(before_decoding),
        "decoding finished"
    );

    // Script deobfuscation normally runs only for text. A self-identifying
    // VBScript.Encode marker is also enough: its encoded body can hold
    // enough control and high bytes to make an ASP page look binary. The
    // marker is looked for in the strings already found, so binaries without
    // it pay for no extra scan of the file.
    let deobfuscate = is_text_file(data) || strings.iter().any(|s| s.value.contains("#@~^"));

    if opts.filter_garbage {
        let before_filter = strings.len();
        // The most expensive post-extraction pass; verdicts are independent,
        // and `into_par_iter` + `filter` + `collect` keeps the order.
        strings = std::mem::take(&mut strings)
            .into_par_iter()
            .with_min_len(crate::par::MIN_ITEMS_PER_JOB)
            .filter(|s| passes_garbage_filter(s, &code_ranges))
            .collect();
        tracing::debug!(
            kept = strings.len(),
            dropped = before_filter - strings.len(),
            "garbage filter finished"
        );
    }

    strip_go_varint_prefixes(&mut strings);

    // Script results are exempt from the garbage filter and deduplicated
    // apart from the rest, so they are added last.
    if deobfuscate {
        let before = strings.len();
        text::append_script_deobfuscation(&mut strings, data, opts);
        tracing::debug!(
            added = strings.len() - before,
            "script deobfuscation finished"
        );
    }

    let strings = deduplicate_by_offset(strings);
    tracing::debug!(strings = strings.len(), "strings after offset dedup");
    strings
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
/// Raw printable scanners capture the length byte
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
        // A `/` that happens to equal the length (47) is far likelier the root
        // of an absolute path (`/Users/…`, `/core/src/…`) than the length of a
        // module path, whose first element is a domain (`github.com/…`).
        let first = rest.split(|&b| b == b'/').next().unwrap_or_default();
        if prefix == b'/' && !first.contains(&b'.') {
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
/// Stack strings in `exec_ranges` of `data`, decoded as `bits`-bit x86;
/// none when the code is not x86 (`bits` is `None`).
pub(crate) fn extract_stack_strings_from_ranges(
    data: &[u8],
    min_length: usize,
    exec_ranges: &[Range<usize>],
    bits: Option<u32>,
) -> Vec<ExtractedString> {
    let Some(bits) = bits else {
        return Vec::new();
    };
    if exec_ranges.is_empty() {
        return Vec::new();
    }
    exec_ranges
        .par_iter()
        .with_min_len(par::job_len(exec_ranges.len(), data.len()))
        .filter_map(|range| {
            let start = range.start;
            let section_data = data.get(start..range.end.min(data.len()))?;
            let mut results = extract_stack_strings(section_data, min_length, bits);
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
pub(crate) fn passes_garbage_filter(s: &ExtractedString, code_ranges: &[Range<usize>]) -> bool {
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
    // mean "no section info" → unknown.
    let in_code_section = if code_ranges.is_empty() {
        None
    } else {
        // The ranges are sorted and disjoint: find the last one starting at or
        // before the offset.
        let off = usize::try_from(s.data_offset).unwrap_or(usize::MAX);
        let i = code_ranges.partition_point(|r| r.start <= off);
        Some(i > 0 && off < code_ranges[i - 1].end)
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
    let span =
        |s: &ExtractedString| s.data_offset..s.data_offset.saturating_add(s.value.len() as u64);
    let mut spans: Vec<Range<u64>> = claimed.iter().map(span).collect();
    spans.sort_unstable_by_key(|r| (r.start, r.end));
    let longest = spans.iter().map(|r| r.end - r.start).max().unwrap_or(0);

    let mut out = Vec::with_capacity(raw.len());
    for s in raw {
        if known.contains(s.value.as_str()) {
            continue;
        }
        let Range { start, end } = span(&s);
        // Spans sorted by start: those overlapping `start..end` begin before
        // `end` and no earlier than `start - longest`.
        let lo = spans.partition_point(|r| r.start < start.saturating_sub(longest));
        let hi = spans.partition_point(|r| r.start < end);
        let overlapping: Vec<&Range<u64>> =
            spans[lo..hi].iter().filter(|r| r.end > start).collect();
        if overlapping.is_empty() {
            out.push(s);
            continue;
        }

        let mut cursor = start;
        let mut pieces = Vec::new();
        for claimed in overlapping {
            if claimed.start > cursor {
                pieces.push(cursor..claimed.start);
            }
            cursor = cursor.max(claimed.end);
        }
        if cursor < end {
            pieces.push(cursor..end);
        }
        for Range { start: a, end: b } in pieces {
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
    // the offset alone collapses true duplicates. Text decoded from another
    // string (base64, hex, URL escapes) carries its source's offset, so it is
    // kept beside that source, which an analyst greps for: the best decoding
    // per offset survives. A script blob decodes to many strings, all at the
    // blob, so those are kept one per value.
    let (mut decoded, mut strings): (Vec<_>, Vec<_>) = strings
        .into_iter()
        .partition(|s| s.method.decodes_a_string());
    let (mut scripts, mut decoded): (Vec<_>, Vec<_>) = decoded
        .drain(..)
        .partition(|s| s.method == StringMethod::ScriptDecode);
    strings.dedup_by(|a, b| a.data_offset == b.data_offset);
    decoded.dedup_by(|a, b| a.data_offset == b.data_offset);
    scripts.sort_by(|a, b| (a.data_offset, &a.value).cmp(&(b.data_offset, &b.value)));
    scripts.dedup_by(|a, b| a.data_offset == b.data_offset && a.value == b.value);
    strings.extend(decoded);
    strings.extend(scripts);
    strings.sort_by_key(|s| s.data_offset);
    strings
}
