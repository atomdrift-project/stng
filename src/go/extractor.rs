//! Go string extractor implementation.
//!
//! Extracts strings from Go binaries using structure analysis and instruction patterns.

// This codebase targets 64-bit hosts only: usize = u64, so u64-to-usize casts are lossless.
#![allow(clippy::cast_possible_truncation)]

use crate::extraction::{extract_from_structures, find_string_structures};
use crate::instr::{extract_inline_strings_amd64, extract_inline_strings_arm64};
use crate::types::{BinaryInfo, ExtractedString, StringMethod, StringStruct};
use goblin::elf::Elf;
use goblin::mach::MachO;
use goblin::mach::cputype::{CPU_TYPE_ARM64, CPU_TYPE_X86_64};
use goblin::pe::PE;
use rayon::prelude::*;
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

    /// Extract strings from a Mach-O binary.
    #[must_use]
    pub(crate) fn extract_macho(&self, macho: &MachO<'_>, _data: &[u8]) -> Vec<ExtractedString> {
        let mut strings = Vec::new();
        // Mach-O is always little-endian on modern systems (x86_64, ARM64)
        let info = BinaryInfo::from_macho(macho.is_64);

        // Find __rodata section in __TEXT segment (contains string data)
        let mut rodata_info: Option<(u64, &[u8])> = None;
        let mut text_info: Option<(u64, &[u8])> = None;

        for seg in &macho.segments {
            let seg_name = seg.name().unwrap_or("");
            if seg_name == "__TEXT"
                && let Ok(sections) = seg.sections()
            {
                for (section, section_data) in sections {
                    let name = section.name().unwrap_or("");
                    if name == "__rodata" {
                        rodata_info = Some((section.addr, section_data));
                    }
                    if name == "__text" {
                        text_info = Some((section.addr, section_data));
                    }
                }
            }
        }

        let Some((rodata_addr, rodata_data)) = rodata_info else {
            return strings;
        };

        // Collect all sections first for parallel processing
        let sections_info: Vec<(u64, &[u8])> = macho
            .segments
            .iter()
            .filter_map(|seg| seg.sections().ok())
            .flatten()
            .map(|(section, section_data)| (section.addr, section_data))
            .collect();

        // Search all sections for string structures in parallel
        let all_structs: Vec<StringStruct> = sections_info
            .par_iter()
            .flat_map(|(section_addr, section_data)| {
                find_string_structures(
                    section_data,
                    *section_addr,
                    rodata_addr,
                    rodata_data.len() as u64,
                    &info,
                )
            })
            .collect();

        // Extract strings using structure boundaries
        let structured = extract_from_structures(
            rodata_data,
            rodata_addr,
            &all_structs,
            Some("__rodata"),
            classify_string,
        );

        // Filter by minimum length — use lower floor for structure-based strings
        let struct_min = self.min_length.min(STRUCTURE_MIN_LENGTH);
        strings.extend(
            structured
                .into_iter()
                .filter(|s| s.value.len() >= struct_min),
        );

        // Extract inline strings from instructions (ARM64 or x86_64)
        // Use the same lower floor — instruction patterns (LEA+MOV with rodata
        // pointer and immediate length) are high confidence.
        if let Some((text_addr, text_data)) = text_info {
            let cpu_type = macho.header.cputype();
            if cpu_type == CPU_TYPE_ARM64 {
                let inline_strings = extract_inline_strings_arm64(
                    text_data,
                    text_addr,
                    rodata_data,
                    rodata_addr,
                    struct_min,
                );
                strings.extend(
                    inline_strings
                        .into_iter()
                        .filter(|s| s.value.len() >= struct_min),
                );
            } else if cpu_type == CPU_TYPE_X86_64 {
                let inline_strings = extract_inline_strings_amd64(
                    text_data,
                    text_addr,
                    rodata_data,
                    rodata_addr,
                    struct_min,
                );
                strings.extend(
                    inline_strings
                        .into_iter()
                        .filter(|s| s.value.len() >= struct_min),
                );
            }
        }

        // Go's Mach-O linker stores many literals in one packed printable
        // `__rodata` pool. The generic raw scanner skips that section to avoid
        // emitting giant concatenated runs, while pointer/length analysis can
        // miss constants that are assembled at runtime. Recover only bounded
        // high-signal substrings from the packed pool.
        if rodata_data.len() <= MAX_PACKED_RODATA_HEURISTIC_SIZE {
            let packed = extract_packed_rodata_literals(
                rodata_data,
                rodata_addr,
                Some("__rodata"),
                self.min_length,
            );
            // Borrow existing values (no per-string clone). Collect the genuinely new
            // literals first so the borrow on `strings` is released before we extend it.
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

        strings
    }

    /// Extract strings from an ELF binary.
    #[must_use]
    pub(crate) fn extract_elf(&self, elf: &Elf<'_>, data: &[u8]) -> Vec<ExtractedString> {
        let mut strings = Vec::new();
        let info = BinaryInfo::from_elf(elf.is_64, elf.little_endian);

        // Find .rodata section (contains string data)
        let rodata_info = self.find_rodata_elf(elf, data);
        let Some((rodata_addr, rodata_data)) = rodata_info else {
            return strings;
        };

        // Find .text section for inline string extraction
        let text_info = elf
            .section_headers
            .iter()
            .find(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(".text"))
            .and_then(|sh| {
                let start = sh.sh_offset as usize;
                let end = start.checked_add(sh.sh_size as usize)?;
                if end <= data.len() {
                    Some((sh.sh_addr, &data[start..end]))
                } else {
                    None
                }
            });

        // Search all data sections for string structures in parallel
        let sections_info: Vec<_> = elf
            .section_headers
            .iter()
            .filter_map(|sh| {
                let start = sh.sh_offset as usize;
                let end = start.checked_add(sh.sh_size as usize)?;
                if end <= data.len() && sh.sh_size > 0 {
                    Some((sh.sh_addr, &data[start..end]))
                } else {
                    None
                }
            })
            .collect();

        let all_structs: Vec<StringStruct> = sections_info
            .par_iter()
            .flat_map(|(section_addr, section_data)| {
                find_string_structures(
                    section_data,
                    *section_addr,
                    rodata_addr,
                    rodata_data.len() as u64,
                    &info,
                )
            })
            .collect();

        // Extract strings using structure boundaries
        let structured = extract_from_structures(
            rodata_data,
            rodata_addr,
            &all_structs,
            Some(".rodata"),
            classify_string,
        );

        // Filter by minimum length — use lower floor for structure-based strings
        let struct_min = self.min_length.min(STRUCTURE_MIN_LENGTH);
        strings.extend(
            structured
                .into_iter()
                .filter(|s| s.value.len() >= struct_min),
        );

        // Extract inline strings from .text section
        // Use the same lower floor for instruction patterns (high confidence)
        if let Some((text_addr, text_data)) = text_info {
            let inline_strings = match elf.header.e_machine {
                goblin::elf::header::EM_AARCH64 => extract_inline_strings_arm64(
                    text_data,
                    text_addr,
                    rodata_data,
                    rodata_addr,
                    struct_min,
                ),
                goblin::elf::header::EM_X86_64 => extract_inline_strings_amd64(
                    text_data,
                    text_addr,
                    rodata_data,
                    rodata_addr,
                    struct_min,
                ),
                _ => Vec::new(),
            };

            strings.extend(
                inline_strings
                    .into_iter()
                    .filter(|s| s.value.len() >= struct_min),
            );
        }

        strings
    }

    /// Extract strings from a PE binary.
    #[must_use]
    pub(crate) fn extract_pe(&self, pe: &PE<'_>, data: &[u8]) -> Vec<ExtractedString> {
        let mut strings = Vec::new();
        let info = BinaryInfo::from_pe(pe.is_64);

        // PE pointers are full virtual addresses (`ImageBase + section_va`).
        // Without folding ImageBase into the addresses we hand to
        // `find_string_structures`, every {ptr,len} pair stored in `.data`
        // misses its target by exactly ImageBase and the structure scanner
        // returns essentially zero hits.
        let image_base = pe
            .header
            .optional_header
            .map_or(0u64, |opt| opt.windows_fields.image_base);

        // Find .rodata or .rdata section
        let rodata_info = self.find_rodata_pe(pe, data);
        let Some((rodata_addr, rodata_data)) = rodata_info else {
            return strings;
        };
        let rodata_va = rodata_addr + image_base;

        // Search all sections for string structures
        let sections_info: Vec<_> = pe
            .sections
            .iter()
            .filter_map(|section| {
                let start = section.pointer_to_raw_data as usize;
                let size = section.size_of_raw_data as usize;
                let end = start.saturating_add(size);
                if end <= data.len() && size > 0 {
                    Some((
                        u64::from(section.virtual_address) + image_base,
                        &data[start..end],
                    ))
                } else {
                    None
                }
            })
            .collect();

        let all_structs: Vec<StringStruct> = sections_info
            .par_iter()
            .flat_map(|(section_addr, section_data)| {
                find_string_structures(
                    section_data,
                    *section_addr,
                    rodata_va,
                    rodata_data.len() as u64,
                    &info,
                )
            })
            .collect();

        // Extract strings
        let structured = extract_from_structures(
            rodata_data,
            rodata_va,
            &all_structs,
            Some(".rodata"),
            classify_string,
        );

        // Filter by minimum length — use lower floor for structure-based strings
        let struct_min = self.min_length.min(STRUCTURE_MIN_LENGTH);
        strings.extend(
            structured
                .into_iter()
                .filter(|s| s.value.len() >= struct_min),
        );

        // Extract inline strings referenced from `.text` (LEA + MOV-length).
        // Go x86-64/arm64 code points at packed `.rdata` literals this way, and
        // the {ptr,len} structure scan above misses them — which is why format
        // strings such as `dd if=/dev/zero of=%s bs=446 count=1` surface only
        // inside rizin's merged blobs. Mirrors the ELF and Mach-O paths.
        let text_info = pe.sections.iter().find_map(|section| {
            if crate::binary::pe_section_name(&section.name) != ".text" {
                return None;
            }
            let start = section.pointer_to_raw_data as usize;
            let end = start.checked_add(section.size_of_raw_data as usize)?;
            let text = data.get(start..end)?;
            Some((u64::from(section.virtual_address) + image_base, text))
        });
        if let Some((text_va, text_data)) = text_info {
            let inline_strings = match pe.header.coff_header.machine {
                goblin::pe::header::COFF_MACHINE_ARM64 => extract_inline_strings_arm64(
                    text_data,
                    text_va,
                    rodata_data,
                    rodata_va,
                    struct_min,
                ),
                goblin::pe::header::COFF_MACHINE_X86_64 => extract_inline_strings_amd64(
                    text_data,
                    text_va,
                    rodata_data,
                    rodata_va,
                    struct_min,
                ),
                _ => Vec::new(),
            };
            strings.extend(
                inline_strings
                    .into_iter()
                    .filter(|s| s.value.len() >= struct_min),
            );
        }

        // Recover bounded high-signal literals (URLs, find-command fragments)
        // from the packed `.rdata` pool, which the generic raw scanner skips to
        // avoid emitting one giant concatenated run.
        if rodata_data.len() <= MAX_PACKED_RODATA_HEURISTIC_SIZE {
            let packed = extract_packed_rodata_literals(
                rodata_data,
                rodata_va,
                Some(".rodata"),
                self.min_length,
            );
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

        strings
    }

    /// Find .rodata section in ELF
    fn find_rodata_elf<'a>(&self, elf: &Elf<'_>, data: &'a [u8]) -> Option<(u64, &'a [u8])> {
        // Try .rodata first
        let rodata_sh = elf
            .section_headers
            .iter()
            .find(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(".rodata"))?;

        let start = rodata_sh.sh_offset as usize;
        let end = start.checked_add(rodata_sh.sh_size as usize)?;

        if end <= data.len() {
            Some((rodata_sh.sh_addr, &data[start..end]))
        } else {
            None
        }
    }

    /// Find .rodata or .rdata section in PE
    fn find_rodata_pe<'a>(&self, pe: &PE<'_>, data: &'a [u8]) -> Option<(u64, &'a [u8])> {
        // Try .rodata or .rdata
        for section in &pe.sections {
            let name = crate::binary::pe_section_name(&section.name);
            if name.contains("rodata") || name.contains(".rdata") {
                let start = section.pointer_to_raw_data as usize;
                let size = section.size_of_raw_data as usize;
                let end = start.saturating_add(size);

                if end <= data.len() && size > 0 {
                    return Some((u64::from(section.virtual_address), &data[start..end]));
                }
            }
        }
        None
    }
}

fn extract_packed_rodata_literals(
    data: &[u8],
    section_data_offset: u64,
    section: Option<&str>,
    min_length: usize,
) -> Vec<ExtractedString> {
    let mut sink = PackedLiteralSink::new(section_data_offset, section, min_length);

    extract_url_literals(data, &mut sink);
    extract_find_command_fragments(data, &mut sink);

    sink.results
}

struct PackedLiteralSink<'a> {
    section_data_offset: u64,
    section: Option<&'a str>,
    min_length: usize,
    seen: HashSet<String>,
    results: Vec<ExtractedString>,
}

impl<'a> PackedLiteralSink<'a> {
    fn new(section_data_offset: u64, section: Option<&'a str>, min_length: usize) -> Self {
        Self {
            section_data_offset,
            section,
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
            data_offset: self.section_data_offset + start as u64,
            section: self.section.map(str::to_string),
            method: StringMethod::Heuristic,
            kind: classify_string(value),
            ..Default::default()
        });
    }
}

fn extract_url_literals(data: &[u8], sink: &mut PackedLiteralSink<'_>) {
    const URL_SCHEMES: [&[u8]; 2] = [b"http://", b"https://"];

    for scheme in URL_SCHEMES {
        let mut cursor = 0;
        while let Some(relative) = find_subslice(&data[cursor..], scheme) {
            let start = cursor + relative;
            let end = trim_url_end(data, start, scheme.len());
            sink.add_candidate(data, start, end);
            cursor = start + scheme.len();
        }
    }
}

fn extract_find_command_fragments(data: &[u8], sink: &mut PackedLiteralSink<'_>) {
    const FIND_TRIGGER: &[u8] = b"-maxdepth";
    const MAX_COMMAND_FRAGMENT: usize = 256;

    let mut cursor = 0;
    while let Some(relative) = find_subslice(&data[cursor..], FIND_TRIGGER) {
        let start = cursor + relative;
        let raw_end = command_fragment_end(data, start, MAX_COMMAND_FRAGMENT);
        let Some(candidate) = std::str::from_utf8(&data[start..raw_end]).ok() else {
            cursor = start + FIND_TRIGGER.len();
            continue;
        };
        let candidate = trim_find_command_fragment(candidate);
        if candidate_has_find_selector(candidate) {
            let end = start + candidate.len();
            sink.add_candidate(data, start, end);
        }
        cursor = start + FIND_TRIGGER.len();
    }
}

fn trim_url_end(data: &[u8], start: usize, scheme_len: usize) -> usize {
    let mut end = start;
    while end < data.len() && is_url_byte(data[end]) {
        end += 1;
    }

    let search_start = start.saturating_add(scheme_len);
    if search_start < end
        && let Some(relative) = find_subslice(&data[search_start..end], b"http2:")
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

fn is_url_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'.' | b'_' | b':' | b'/' | b'@' | b'-' | b'?' | b'=' | b'&' | b'%' | b'#' | b'+'
        )
}

fn command_fragment_end(data: &[u8], start: usize, max_len: usize) -> usize {
    let hard_end = start.saturating_add(max_len).min(data.len());
    let mut end = start;
    while end < hard_end && is_command_fragment_byte(data[end]) {
        end += 1;
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
    let marker = if let Some(pos) = s.find("|head") {
        (pos, "|head".len())
    } else if let Some(pos) = s.find("| head") {
        (pos, "| head".len())
    } else {
        return None;
    };

    let mut end = marker.0 + marker.1;
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

fn candidate_has_find_selector(s: &str) -> bool {
    s.contains("-iname") || s.contains("-name") || s.contains("-exec")
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    memchr::memmem::find(haystack, needle)
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
pub(crate) fn extract_varint_prefixed_strings(
    data: &[u8],
    section_data_offset: u64,
    section: Option<&str>,
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
                    section: section.map(str::to_string),
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
pub(crate) fn extract_null_separated_strings(
    data: &[u8],
    section_data_offset: u64,
    section: Option<&str>,
    min_length: usize,
) -> Vec<ExtractedString> {
    use crate::types::StringMethod;

    // Funcnametab entries are Go function or type names — no whitespace,
    // bounded length. Above ~80 chars we are almost certainly inside a
    // packed string pool whose entries have no NUL separators.
    const MAX_ENTRY_LEN: usize = 80;

    fn entry_at(data: &[u8], pos: usize) -> Option<(usize, &[u8])> {
        let nul = pos + memchr::memchr(0, data.get(pos..)?)?;
        let bytes = &data[pos..nul];
        if bytes.is_empty() || bytes.len() > MAX_ENTRY_LEN {
            return None;
        }
        // Reject anything that isn't strictly a Go-symbol-like token.
        // Spaces and punctuation outside the function-name alphabet break
        // packed-pool runs from masquerading as funcnametab entries.
        let valid_body = bytes.iter().all(|&b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'_' | b'.' | b'/' | b'*' | b'[' | b']' | b'(' | b')' | b'-' | b',' | b' '
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
                    section: section.map(str::to_string),
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
        let out = extract_varint_prefixed_strings(&buf, 0, None, 4);
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
        let out = extract_varint_prefixed_strings(&buf, 0, None, 4);
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
        let out = extract_null_separated_strings(&buf, 0, None, 4);
        let values: Vec<&str> = out.iter().map(|s| s.value.as_str()).collect();
        assert!(values.contains(&"debugCall32"));
        assert!(values.contains(&"debugCall128"));
    }

    #[test]
    fn null_separated_skips_megastrings() {
        // A long unsegmented printable run should produce nothing.
        let mut buf = b"longstringwithoutanydelimitersjustabunchoflettersinarow".to_vec();
        buf.push(0);
        let out = extract_null_separated_strings(&buf, 0, None, 4);
        assert!(out.is_empty(), "a single long entry shouldn't qualify");
    }

    #[test]
    fn packed_rodata_recovers_bounded_url_from_concatenated_go_pool() {
        let buf =
            b"noisehttps://api.telegram.org/bot123456789:ABCDEF/sendMessagehttp2: server idle";

        let out = extract_packed_rodata_literals(buf, 0x1000, Some("__rodata"), 4);

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

        let out = extract_packed_rodata_literals(buf, 0x2000, Some("__rodata"), 4);

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
