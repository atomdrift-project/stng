//! Go string extractor implementation.
//!
//! Extracts strings from Go binaries using structure analysis and instruction patterns.

// This codebase targets 64-bit hosts only: usize = u64, so u64-to-usize casts are lossless.
#![allow(clippy::cast_possible_truncation)]

use crate::extraction::pair_strings;
use crate::instr::inline_strings;
use crate::types::{Arch, BinaryInfo, ExtractedString, StringMethod};
use goblin::elf::Elf;
use goblin::mach::MachO;
use goblin::mach::cputype::{CPU_TYPE_ARM64, CPU_TYPE_X86_64};
use goblin::pe::PE;
use std::collections::HashSet;

use crate::classifier::classify_string;

/// Minimum length for structure-based extraction.
///
/// Structure-based strings have high confidence (backed by actual {ptr, len}
/// pairs in the binary), so we use a lower floor than the user-specified
/// min_length to avoid dropping short but real strings like "gh" or "sh".
const STRUCTURE_MIN_LENGTH: usize = 2;

/// Upper bound for targeted scans over Go's packed string pool.
const MAX_PACKED_RODATA_HEURISTIC_SIZE: usize = 4 * 1024 * 1024;

/// Extracts strings from Go binaries using structure analysis.
pub(crate) struct GoStringExtractor {
    min_length: usize,
}

impl GoStringExtractor {
    pub(crate) fn new(min_length: usize) -> Self {
        Self { min_length }
    }

    /// Extract strings from a Go Mach-O binary.
    ///
    /// Structure, inline-instruction, and packed-pool extraction all record the
    /// string's virtual address; a final pass converts each to a file offset so
    /// every emitted offset indexes the file. `file_base` rebases a fat slice's
    /// offsets onto the whole fat file (0 for a thin binary).
    #[must_use]
    pub(crate) fn extract_macho(&self, macho: &MachO<'_>, file_base: u64) -> Vec<ExtractedString> {
        let text_section = |name: &str| {
            crate::binary::macho_sections(macho)
                .filter(|(s, _)| s.segname().ok() == Some("__TEXT") && s.name().ok() == Some(name))
                .last()
                .map(|(s, data)| (s.addr, data))
        };
        let Some(rodata) = text_section("__rodata") else {
            return Vec::new();
        };
        let arch = match macho.header.cputype() {
            CPU_TYPE_ARM64 => Arch::Aarch64,
            CPU_TYPE_X86_64 => Arch::X86_64,
            _ => Arch::Other,
        };
        let sections = crate::binary::macho_sections(macho)
            .map(|(section, data)| (section.addr, section.offset as usize, data));
        let info = BinaryInfo::from_macho(macho.is_64);
        let mut strings =
            self.pointer_strings(sections, rodata, text_section("__text"), arch, &info);
        self.extend_packed_literals(&mut strings, rodata);
        strings.extend(super::struct_tags::extract(macho, self.min_length));

        for s in &mut strings {
            s.data_offset = file_base.saturating_add(crate::binary::macho_vaddr_to_file_offset(
                macho,
                s.data_offset,
            ));
        }
        strings
    }

    /// Extract strings from an ELF binary.
    #[must_use]
    pub(crate) fn extract_elf(&self, elf: &Elf<'_>, data: &[u8]) -> Vec<ExtractedString> {
        let Some(rodata) = crate::binary::elf_section(elf, data, ".rodata") else {
            return Vec::new();
        };
        let arch = match elf.header.e_machine {
            goblin::elf::header::EM_AARCH64 => Arch::Aarch64,
            goblin::elf::header::EM_X86_64 => Arch::X86_64,
            _ => Arch::Other,
        };
        let sections = elf.section_headers.iter().filter_map(|sh| {
            let bytes = crate::binary::file_range(data, sh.sh_offset, sh.sh_size)?;
            Some((sh.sh_addr, usize::try_from(sh.sh_offset).ok()?, bytes))
        });
        let text = crate::binary::elf_section(elf, data, ".text");
        let info = BinaryInfo::from_elf(elf.is_64, elf.little_endian);
        // No packed-literal pass: on ELF the generic scanners already report
        // the pool's URLs, and the pass only adds run-ons whose end it misses
        // (`…/payload.tsnet/http`).
        let mut strings = self.pointer_strings(sections, rodata, text, arch, &info);

        for s in &mut strings {
            s.data_offset = crate::binary::elf_vaddr_to_file_offset(elf, s.data_offset);
        }
        strings
    }

    /// Extract strings from a PE binary.
    #[must_use]
    pub(crate) fn extract_pe(&self, pe: &PE<'_>, data: &[u8]) -> Vec<ExtractedString> {
        // PE pointers are full virtual addresses (`ImageBase + section_va`),
        // so every address handed to the scanners includes ImageBase.
        let image_base = pe
            .header
            .optional_header
            .map_or(0u64, |opt| opt.windows_fields.image_base);
        // Section bytes as the file holds them: a truncated sample still
        // yields the strings in the part that survived.
        let raw = |section: &goblin::pe::section_table::SectionTable| {
            crate::binary::file_range_clamped(
                data,
                u64::from(section.pointer_to_raw_data),
                u64::from(section.size_of_raw_data),
            )
        };
        let Some((rodata_section, rodata_data)) = pe.sections.iter().find_map(|section| {
            let name = crate::binary::pe_section_name(&section.name);
            if !(name.contains("rodata") || name.contains(".rdata")) {
                return None;
            }
            Some((section, raw(section)?))
        }) else {
            return Vec::new();
        };
        let rodata_va = u64::from(rodata_section.virtual_address).wrapping_add(image_base);
        let rodata = (rodata_va, rodata_data);

        let sections = pe.sections.iter().filter_map(|section| {
            Some((
                u64::from(section.virtual_address).wrapping_add(image_base),
                section.pointer_to_raw_data as usize,
                raw(section)?,
            ))
        });
        // Go code points at packed `.rdata` literals with LEA + MOV-length,
        // which the structure scan misses: format strings such as
        // `dd if=/dev/zero of=%s bs=446 count=1` surface only this way.
        let text = pe.sections.iter().find_map(|section| {
            if crate::binary::pe_section_name(&section.name) != ".text" {
                return None;
            }
            Some((
                u64::from(section.virtual_address).wrapping_add(image_base),
                raw(section)?,
            ))
        });
        let arch = match pe.header.coff_header.machine {
            goblin::pe::header::COFF_MACHINE_ARM64 => Arch::Aarch64,
            goblin::pe::header::COFF_MACHINE_X86_64 => Arch::X86_64,
            _ => Arch::Other,
        };
        let info = BinaryInfo::from_pe(pe.is_64);
        let mut strings = self.pointer_strings(sections, rodata, text, arch, &info);
        self.extend_packed_literals(&mut strings, rodata);

        // The passes above work in virtual addresses, but `data_offset` is a
        // file offset that callers compare with PE raw-data ranges: map every
        // result in rodata back to its file position.
        let rodata_file = u64::from(rodata_section.pointer_to_raw_data);
        for s in &mut strings {
            if let Some(relative) = s.data_offset.checked_sub(rodata_va)
                && relative < rodata_data.len() as u64
            {
                s.data_offset = rodata_file + relative;
            }
        }
        strings
    }

    /// The strings `{ptr, len}` pairs in `sections` and `text`'s instructions
    /// point at in `rodata`, in virtual addresses. Both are high-confidence,
    /// so they use the structure floor rather than `min_length`.
    fn pointer_strings<'a>(
        &self,
        sections: impl IntoIterator<Item = (u64, usize, &'a [u8])>,
        rodata: (u64, &[u8]),
        text: Option<(u64, &[u8])>,
        arch: Arch,
        info: &BinaryInfo,
    ) -> Vec<ExtractedString> {
        let min = self.min_length.min(STRUCTURE_MIN_LENGTH);
        let mut strings = pair_strings(sections, rodata, info, min);
        if let Some(text) = text {
            strings.extend(inline_strings(arch, text, rodata, min));
        }
        strings
    }

    /// Bounded high-signal literals (URLs, find-command fragments) from Go's
    /// packed rodata pool. The raw scanner skips the pool to avoid one giant
    /// concatenated run, and pointer analysis misses constants assembled at
    /// run time.
    fn extend_packed_literals(
        &self,
        strings: &mut Vec<ExtractedString>,
        (addr, rodata): (u64, &[u8]),
    ) {
        if rodata.len() > MAX_PACKED_RODATA_HEURISTIC_SIZE {
            tracing::debug!(
                size = rodata.len(),
                "Go packed-literal scan skipped: rodata too large"
            );
            return;
        }
        let packed = extract_packed_rodata_literals(rodata, addr, self.min_length);
        let existing: HashSet<&str> = strings.iter().map(|s| s.value.as_str()).collect();
        let fresh: Vec<ExtractedString> = packed
            .into_iter()
            .filter(|s| !existing.contains(s.value.as_str()))
            .collect();
        drop(existing);
        let mut batch_seen: HashSet<String> = HashSet::new();
        for s in fresh {
            if batch_seen.insert(s.value.clone()) {
                strings.push(s);
            }
        }
    }
}

fn extract_packed_rodata_literals(
    data: &[u8],
    section_data_offset: u64,
    min_length: usize,
) -> Vec<ExtractedString> {
    let mut sink = PackedLiteralSink::new(section_data_offset, min_length);

    extract_url_literals(data, &mut sink);
    extract_find_command_fragments(data, &mut sink);

    sink.results
}

struct PackedLiteralSink {
    section_data_offset: u64,
    min_length: usize,
    seen: HashSet<String>,
    results: Vec<ExtractedString>,
}

impl PackedLiteralSink {
    fn new(section_data_offset: u64, min_length: usize) -> Self {
        Self {
            section_data_offset,
            min_length,
            seen: HashSet::new(),
            results: Vec::new(),
        }
    }

    fn add_candidate(&mut self, data: &[u8], start: usize, end: usize) {
        if start >= end || end > data.len() {
            return;
        }

        let Ok(value) = std::str::from_utf8(&data[start..end]) else {
            return;
        };
        let value =
            value.trim_matches(|c: char| c.is_ascii_whitespace() || matches!(c, '"' | '\''));
        if value.len() < self.min_length || value.len() > 512 {
            return;
        }
        if !self.seen.insert(value.to_string()) {
            return;
        }

        self.results.push(ExtractedString {
            value: value.to_string(),
            data_offset: self.section_data_offset.saturating_add(start as u64),
            method: StringMethod::Heuristic,
            kind: classify_string(value),
            ..Default::default()
        });
    }
}

fn extract_url_literals(data: &[u8], sink: &mut PackedLiteralSink) {
    const URL_SCHEMES: [&[u8]; 2] = [b"http://", b"https://"];

    for scheme in URL_SCHEMES {
        let mut cursor = 0;
        while let Some(relative) = memchr::memmem::find(&data[cursor..], scheme) {
            let start = cursor + relative;
            let end = trim_url_end(data, start, scheme.len());
            sink.add_candidate(data, start, end);
            cursor = start + scheme.len();
        }
    }
}

fn extract_find_command_fragments(data: &[u8], sink: &mut PackedLiteralSink) {
    const FIND_TRIGGER: &[u8] = b"-maxdepth";
    const MAX_COMMAND_FRAGMENT: usize = 256;

    let mut cursor = 0;
    while let Some(relative) = memchr::memmem::find(&data[cursor..], FIND_TRIGGER) {
        let start = cursor + relative;
        let hard_end = start.saturating_add(MAX_COMMAND_FRAGMENT).min(data.len());
        let mut raw_end = start;
        while raw_end < hard_end && is_command_fragment_byte(data[raw_end]) {
            raw_end += 1;
        }
        let Some(candidate) = std::str::from_utf8(&data[start..raw_end]).ok() else {
            cursor = start + FIND_TRIGGER.len();
            continue;
        };
        let candidate = trim_find_command_fragment(candidate);
        if candidate.contains("-iname")
            || candidate.contains("-name")
            || candidate.contains("-exec")
        {
            let end = start + candidate.len();
            sink.add_candidate(data, start, end);
        }
        cursor = start + FIND_TRIGGER.len();
    }
}

fn trim_url_end(data: &[u8], start: usize, scheme_len: usize) -> usize {
    let mut end = start;
    while end < data.len()
        && (data[end].is_ascii_alphanumeric()
            || matches!(
                data[end],
                b'.' | b'_' | b':' | b'/' | b'@' | b'-' | b'?' | b'=' | b'&' | b'%' | b'#' | b'+'
            ))
    {
        end += 1;
    }

    let search_start = start.saturating_add(scheme_len);
    if search_start < end
        && let Some(relative) = memchr::memmem::find(&data[search_start..end], b"http2:")
    {
        end = search_start + relative;
    }

    while end > start
        && matches!(
            data[end - 1],
            b'.' | b',' | b';' | b':' | b'?' | b'&' | b'='
        )
    {
        end -= 1;
    }

    end
}

fn is_command_fragment_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || byte.is_ascii_whitespace()
        || matches!(
            byte,
            b'_' | b'.'
                | b'-'
                | b'/'
                | b'*'
                | b'"'
                | b'\''
                | b'|'
                | b'>'
                | b'<'
                | b'&'
                | b'='
                | b'('
                | b')'
        )
}

fn trim_find_command_fragment(s: &str) -> &str {
    if let Some(end) = end_after_head_limit(s) {
        return &s[..end];
    }
    if let Some(pos) = s.find("2>/dev/null") {
        return &s[..pos + "2>/dev/null".len()];
    }
    if let Some(pos) = long_hex_run_start(s) {
        return s[..pos].trim_end();
    }
    s.trim_end()
}

fn end_after_head_limit(s: &str) -> Option<usize> {
    let (pos, marker_len) = match s.find("|head") {
        Some(pos) => (pos, "|head".len()),
        None => (s.find("| head")?, "| head".len()),
    };

    let mut end = pos + marker_len;
    let bytes = s.as_bytes();
    while end < bytes.len() && bytes[end].is_ascii_whitespace() {
        end += 1;
    }
    if end < bytes.len() && bytes[end] == b'-' {
        end += 1;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
    }
    Some(end)
}

fn long_hex_run_start(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut run_start = 0;
    let mut run_len = 0;
    for (i, byte) in bytes.iter().enumerate() {
        if byte.is_ascii_hexdigit() {
            if run_len == 0 {
                run_start = i;
            }
            run_len += 1;
            if run_len >= 32 {
                return Some(run_start);
            }
        } else {
            run_len = 0;
        }
    }
    None
}

/// Extract strings from a Go pclntab `pkgnamestab`-style table.
///
/// Go 1.18+ packs package paths and reflect type names in a table where
/// each entry is a single-byte varint length followed by that many printable
/// ASCII bytes, optionally separated by `0x00`. Stripped Go PEs fold this
/// table into `.rdata` so it isn't reachable via `{ptr,len}` structures.
///
/// We only emit a run of entries when at least three valid entries appear
/// back-to-back, which suppresses false positives in regular text.
/// Go's pclntab names in `table`, which starts at file `offset`: the
/// NUL-separated funcnametab and the varint-prefixed pkgnamestab, scanned
/// concurrently. Returns `(nul_separated, varint_prefixed)`.
pub(crate) fn pclntab_strings(
    table: &[u8],
    offset: u64,
    min_length: usize,
) -> (Vec<ExtractedString>, Vec<ExtractedString>) {
    crate::par::join(
        table.len(),
        || extract_null_separated_strings(table, offset, min_length),
        || extract_varint_prefixed_strings(table, offset, min_length),
    )
}

fn extract_varint_prefixed_strings(
    data: &[u8],
    section_data_offset: u64,
    min_length: usize,
) -> Vec<ExtractedString> {
    use crate::types::StringMethod;

    // Cap pkgnamestab entries at 64 bytes — the actual Go module paths and
    // reflect type names we care about (`github.com/.../sub`, `*[8]*pkg.Type`)
    // sit well under that. Bytes in the packed string-pool encoding overlap
    // with this range frequently enough that a higher cap lets multi-string
    // chunks slip through whenever an alphabetic byte aligns with a chunk
    // length.
    const MAX_VARINT_ENTRY: usize = 64;

    fn entry_at(data: &[u8], pos: usize) -> Option<(usize, &[u8])> {
        let len_byte = *data.get(pos)?;
        if !(1..0x80).contains(&len_byte) {
            return None;
        }
        let len = len_byte as usize;
        if len > MAX_VARINT_ENTRY {
            return None;
        }
        let start = pos + 1;
        let end = start.checked_add(len)?;
        if end > data.len() {
            return None;
        }
        let bytes = &data[start..end];
        let starts_ok = matches!(
            bytes[0],
            b'a'..=b'z' | b'A'..=b'Z' | b'_' | b'*' | b'[' | b'(' | b'.'
        );
        // Restrict to the alphabet that Go module paths and reflect type
        // names actually use. Spaces, angle brackets, and other punctuation
        // would let packed string pools masquerade as a varint-prefixed
        // table — regular sentences happen to encode as a believable run.
        let valid_body = bytes.iter().all(|&b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'_' | b'.' | b'/' | b'*' | b'[' | b']' | b'(' | b')' | b'-' | b',' | b' '
                )
        });
        if starts_ok && valid_body {
            Some((end, bytes))
        } else {
            None
        }
    }

    let mut results = Vec::new();
    let mut i = 0;
    while i < data.len() {
        // Skip bytes that can't possibly start a single-byte varint entry
        // (NULs and the high bit of multi-byte varints we don't decode).
        // Avoids per-byte entry_at calls across long zero-filled holes.
        let b = data[i];
        if b == 0 || b >= 0x80 {
            i += 1;
            continue;
        }
        let mut entries: Vec<(usize, &[u8])> = Vec::new();
        let mut cursor = i;
        while let Some((next, bytes)) = entry_at(data, cursor) {
            entries.push((cursor + 1, bytes));
            cursor = next;
            while cursor < data.len() && data[cursor] == 0 {
                cursor += 1;
            }
        }
        if entries.len() >= 3 {
            for (off, bytes) in &entries {
                if bytes.len() < min_length {
                    continue;
                }
                let Ok(value) = std::str::from_utf8(bytes) else {
                    continue;
                };
                let kind = classify_string(value);
                results.push(ExtractedString {
                    value: value.to_string(),
                    data_offset: section_data_offset + *off as u64,
                    method: StringMethod::PclntabSymbol,
                    kind,
                    ..Default::default()
                });
            }
            i = cursor.max(i + 1);
        } else {
            i += 1;
        }
    }
    results
}

/// Extract null-terminated printable strings from a `.rdata`-style region.
///
/// Go's `pclntab` funcnametab and filetab store entries as
/// `<bytes>\0<bytes>\0<bytes>\0...` — short printable identifiers separated
/// by single NUL bytes. The whole-section raw scan is skipped on Go PE
/// binaries to avoid concatenating string-pool data, so this targeted
/// extractor recovers the funcnametab entries that the structure scanner
/// can't reach (they are referenced by 4-byte offsets, not `{ptr,len}`).
///
/// To avoid false positives in user-data regions, an entry is only emitted
/// when at least three contiguous valid entries appear back-to-back.
fn extract_null_separated_strings(
    data: &[u8],
    section_data_offset: u64,
    min_length: usize,
) -> Vec<ExtractedString> {
    use crate::types::StringMethod;

    // Funcnametab entries are Go function or type names, and a full name
    // carries its module path: `github.com/org/repo/internal/pkg.Func` is
    // routinely past 80 characters, and a generic instantiation spells its
    // type shape in full. A rejected entry also breaks the 3-in-a-row run
    // around it, so too low a cap loses whole stretches of packages. 1,024
    // keeps all but a few dozen names of a 75 MB Go binary (longest 1,139);
    // the alphabet and 3-in-a-row gates, not the length, keep packed-pool
    // runs out.
    const MAX_ENTRY_LEN: usize = 1024;

    fn entry_at(data: &[u8], pos: usize) -> Option<(usize, &[u8])> {
        // An entry is at most MAX_ENTRY_LEN bytes before its NUL, so only scan
        // that far for the terminator. On NUL-sparse pclntab pc-tables the
        // terminator can be thousands of bytes away; scanning the whole gap
        // from every starting byte makes the outer loop O(n²). Capping the
        // probe is exact — a NUL beyond the window would yield an over-long
        // entry that the length check below rejects anyway.
        let window = data.get(pos..)?;
        let limit = (MAX_ENTRY_LEN + 1).min(window.len());
        let nul = pos + memchr::memchr(0, &window[..limit])?;
        let bytes = &data[pos..nul];
        if bytes.is_empty() || bytes.len() > MAX_ENTRY_LEN {
            return None;
        }
        // Reject anything that isn't strictly a Go-symbol-like token.
        // Spaces and punctuation outside the function-name alphabet break
        // packed-pool runs from masquerading as funcnametab entries.
        // `{ } ; :` appear in generic instantiations
        // (`pkg.F[go.shape.interface { Open([]uint8) error; Size() int }]`).
        let valid_body = bytes.iter().all(|&b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'_' | b'.'
                        | b'/'
                        | b'*'
                        | b'['
                        | b']'
                        | b'('
                        | b')'
                        | b'-'
                        | b','
                        | b' '
                        | b'{'
                        | b'}'
                        | b';'
                        | b':'
                )
        });
        let starts_ok = matches!(
            bytes[0],
            b'a'..=b'z' | b'A'..=b'Z' | b'_' | b'*' | b'[' | b'(' | b'.'
        );
        if valid_body && starts_ok {
            Some((nul + 1, bytes))
        } else {
            None
        }
    }

    let mut results = Vec::new();
    let mut i = 0;
    while i < data.len() {
        // Skip the NUL padding stretches that pad `.rdata` between tables —
        // entry_at can't start on a NUL anyway, so jump straight to the next
        // candidate byte.
        if data[i] == 0 {
            match data[i..].iter().position(|&b| b != 0) {
                Some(off) => i += off,
                None => break,
            }
        }
        let mut entries: Vec<(usize, &[u8])> = Vec::new();
        let mut cursor = i;
        while let Some((next, bytes)) = entry_at(data, cursor) {
            entries.push((cursor, bytes));
            cursor = next;
        }
        if entries.len() >= 3 {
            for (off, bytes) in &entries {
                if bytes.len() < min_length {
                    continue;
                }
                let Ok(value) = std::str::from_utf8(bytes) else {
                    continue;
                };
                let kind = classify_string(value);
                results.push(ExtractedString {
                    value: value.to_string(),
                    data_offset: section_data_offset + *off as u64,
                    method: StringMethod::PclntabSymbol,
                    kind,
                    ..Default::default()
                });
            }
            i = cursor.max(i + 1);
        } else if let Some((_, first)) = entries.first() {
            // A start inside the first entry reads a suffix of it followed by
            // these same entries, so it cannot reach three either. Stepping
            // one byte re-read up to 2 KiB per byte.
            i += first.len() + 1;
        } else {
            i += 1;
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::{
        extract_null_separated_strings, extract_packed_rodata_literals,
        extract_varint_prefixed_strings,
    };
    use crate::types::{StringKind, StringMethod};

    #[test]
    fn detects_three_consecutive_varint_entries() {
        // 5 entries: lengths 4, 5, 6, 7, 8 followed by content + a NUL between
        let mut buf = Vec::new();
        for word in ["alpha", "betas", "gammas", "deltaa1", "epsilonn"] {
            buf.push(word.len() as u8);
            buf.extend_from_slice(word.as_bytes());
        }
        let out = extract_varint_prefixed_strings(&buf, 0, 4);
        let values: Vec<&str> = out.iter().map(|s| s.value.as_str()).collect();
        assert!(values.contains(&"alpha"));
        assert!(values.contains(&"epsilonn"));
        assert!(!values.iter().any(|v| v.starts_with('\u{05}')));
    }

    #[test]
    fn rejects_isolated_match() {
        // Two scattered entries with garbage between — should not emit.
        let mut buf = vec![0x05, b'h', b'e', b'l', b'l', b'o'];
        buf.extend_from_slice(&[0xFF, 0xFE, 0x00, 0xC0]);
        buf.extend_from_slice(&[0x05, b'w', b'o', b'r', b'l', b'd']);
        let out = extract_varint_prefixed_strings(&buf, 0, 4);
        assert!(out.is_empty(), "isolated matches must not surface");
    }

    #[test]
    fn null_separated_picks_up_funcnames() {
        // Mimic a chunk of pclntab funcnametab.
        let mut buf = Vec::new();
        for w in ["debugCall32", "debugCall64", "debugCall128", "debugCall256"] {
            buf.extend_from_slice(w.as_bytes());
            buf.push(0);
        }
        let out = extract_null_separated_strings(&buf, 0, 4);
        let values: Vec<&str> = out.iter().map(|s| s.value.as_str()).collect();
        assert!(values.contains(&"debugCall32"));
        assert!(values.contains(&"debugCall128"));
    }

    /// Real funcnametab names carry the full module path and, for generics,
    /// the spelled-out type shape (`{ } ;` included). Each rejection would
    /// also break the 3-in-a-row run around it, losing the neighbours: here a
    /// hash-renamed backdoor helper in a trojanized Terraform provider.
    #[test]
    fn null_separated_keeps_long_module_paths_and_generic_shapes() {
        let names = [
            "github.com/gocommunity-io/terraform-provider-dockerd/internal/provider.normalizeGPUOption",
            "github.com/gocommunity-io/terraform-provider-dockerd/internal/provider._ad79680770be",
            "github.com/gocommunity-io/terraform-provider-dockerd/internal/provider._3701ded6d95a[go.shape.interface { NonceSize() int; Open([]uint8, []uint8, []uint8, []uint8) ([]uint8, error) }]",
            "github.com/gocommunity-io/terraform-provider-dockerd/internal/provider._7a15e4445f4b",
        ];
        let mut buf = Vec::new();
        for n in names {
            buf.extend_from_slice(n.as_bytes());
            buf.push(0);
        }
        let out = extract_null_separated_strings(&buf, 0, 4);
        let values: Vec<&str> = out.iter().map(|s| s.value.as_str()).collect();
        for n in names {
            assert!(values.contains(&n), "missing {n}");
        }
    }

    #[test]
    fn null_separated_skips_megastrings() {
        // A long unsegmented printable run should produce nothing.
        let mut buf = b"longstringwithoutanydelimitersjustabunchoflettersinarow".to_vec();
        buf.push(0);
        let out = extract_null_separated_strings(&buf, 0, 4);
        assert!(out.is_empty(), "a single long entry shouldn't qualify");
    }

    #[test]
    fn packed_rodata_recovers_bounded_url_from_concatenated_go_pool() {
        let buf =
            b"noisehttps://api.telegram.org/bot123456789:ABCDEF/sendMessagehttp2: server idle";

        let out = extract_packed_rodata_literals(buf, 0x1000, 4);

        let url = out
            .iter()
            .find(|s| s.value == "https://api.telegram.org/bot123456789:ABCDEF/sendMessage")
            .expect("telegram URL should be recovered without adjacent Go runtime text");
        assert_eq!(url.method, StringMethod::Heuristic);
        assert_eq!(url.kind, Some(StringKind::Url));
        assert!(!out.iter().any(|s| s.value.contains("http2:")));
    }

    #[test]
    fn packed_rodata_recovers_bounded_find_command_fragment() {
        let buf = b"crypto/rsa: insecure -maxdepth 6 -iname \"*wallet*\" -o -iname \"*keystore*\" -o -iname \"id.json\" 2>/dev/null|head -30b3312d04f441d4ca5ec8e6d8c3ce3de5 more";

        let out = extract_packed_rodata_literals(buf, 0x2000, 4);

        let command = "-maxdepth 6 -iname \"*wallet*\" -o -iname \"*keystore*\" -o -iname \"id.json\" 2>/dev/null|head -30";
        let found = out
            .iter()
            .find(|s| s.value == command)
            .expect("find command fragment should be recovered without trailing hex noise");
        assert_eq!(found.method, StringMethod::Heuristic);
        assert!(found.value.contains("id.json"));
        assert!(!found.value.contains("b3312d04f"));
    }
}
