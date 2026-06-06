//! Rust string extraction.
//!
//! Rust strings use similar fat pointer representations:
//! - `&str`: `{ptr: *u8, len: usize}` (16 bytes on 64-bit)
//! - `String`: `{ptr: *u8, len: usize, cap: usize}` (24 bytes on 64-bit)
//!
//! Rust binaries are harder to analyze than Go because:
//! 1. No dedicated sections like .gopclntab
//! 2. More aggressive inlining and optimization
//! 3. String data may be in .rodata or .data.rel.ro

// This codebase targets 64-bit hosts only: usize = u64, so u64-to-usize casts are lossless.
#![allow(clippy::cast_possible_truncation)]
//!
//! For inline literals, we also perform instruction pattern analysis.

use super::classifier::classify_string;
use super::extraction::{extract_from_structures, find_string_structures};
use super::instr::{extract_inline_strings_amd64, extract_inline_strings_arm64};
use super::types::{BinaryInfo, ExtractedString, StringMethod, StringStruct};
use goblin::elf::Elf;
use goblin::mach::MachO;
use goblin::mach::cputype::{CPU_TYPE_ARM64, CPU_TYPE_X86_64};
use goblin::pe::PE;
use rayon::prelude::*;
use regex::Regex;
use std::collections::HashSet;
use std::sync::LazyLock;

// Static regex patterns are infallible - the patterns are compile-time constants
#[allow(clippy::expect_used)]
static RE_URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(https?|ftp|postgresql|mysql|redis|mongodb)://[a-zA-Z0-9._:/@\-?=&%]+")
        .expect("static regex")
});
#[allow(clippy::expect_used)]
static RE_PATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"/[a-zA-Z0-9_./\-]+").expect("static regex"));
#[allow(clippy::expect_used)]
static RE_ENV_VAR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Z][A-Z0-9_]{3,}").expect("static regex"));
#[allow(clippy::expect_used)]
static RE_SNAKE_CASE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)+").expect("static regex"));
#[allow(clippy::expect_used)]
static RE_DOMAIN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[a-z][a-z0-9]*\.[a-z][a-z0-9.]+").expect("static regex"));

/// Minimum length for structure-based extraction.
///
/// Structure-based strings have high confidence (backed by actual {ptr, len}
/// pairs in the binary), so we use a lower floor than the user-specified
/// min_length to avoid dropping short but real strings.
const STRUCTURE_MIN_LENGTH: usize = 2;

/// Extracts strings from Rust binaries using structure analysis.
pub(crate) struct RustStringExtractor {
    min_length: usize,
}

impl RustStringExtractor {
    pub(crate) fn new(min_length: usize) -> Self {
        Self { min_length }
    }

    /// Extract strings from a Mach-O binary.
    ///
    /// Rust Mach-O binaries typically store strings in:
    /// - `__cstring` in `__TEXT` segment (null-terminated C strings)
    /// - `__const` in `__TEXT` segment (constants, often packed)
    /// - `__const` in `__DATA_CONST` segment (ptr+len structures)
    ///
    /// Rust stores &str slice structures (ptr+len) in `__DATA_CONST`,
    /// while the actual string data is in `__TEXT,__const` or `__cstring`.
    pub(crate) fn extract_macho(&self, macho: &MachO<'_>, _data: &[u8]) -> Vec<ExtractedString> {
        let mut strings = Vec::new();
        let info = BinaryInfo::from_macho(macho.is_64);

        // Collect sections by type
        let mut cstring_info: Option<(u64, &[u8])> = None;
        let mut text_const_info: Option<(u64, &[u8])> = None;
        let mut data_const_info: Option<(u64, &[u8])> = None;
        let mut text_info: Option<(u64, &[u8])> = None;

        for seg in &macho.segments {
            let seg_name = seg.name().unwrap_or("");
            if let Ok(sections) = seg.sections() {
                for (section, section_data) in sections {
                    let name = section.name().unwrap_or("");
                    match (seg_name, name) {
                        ("__TEXT", "__cstring") => {
                            cstring_info = Some((section.addr, section_data));
                        }
                        ("__TEXT", "__const") => {
                            text_const_info = Some((section.addr, section_data));
                        }
                        ("__DATA_CONST", "__const") => {
                            data_const_info = Some((section.addr, section_data));
                        }
                        ("__TEXT", "__text") => text_info = Some((section.addr, section_data)),
                        _ => {}
                    }
                }
            }
        }

        // PHASE 1: Extract from __DATA_CONST structures pointing to string sections
        // This is the primary method for Rust - it stores &str slices here
        if let Some((data_const_addr, data_const_data)) = data_const_info {
            // Target sections to look for pointers to
            let targets: Vec<(u64, &[u8], &str)> = [
                cstring_info.map(|(a, d)| (a, d, "__cstring")),
                text_const_info.map(|(a, d)| (a, d, "__TEXT,__const")),
            ]
            .into_iter()
            .flatten()
            .collect();

            for (target_addr, target_data, section_name) in targets {
                let structs = find_string_structures(
                    data_const_data,
                    data_const_addr,
                    target_addr,
                    target_data.len() as u64,
                    &info,
                );

                let structured = extract_from_structures(
                    target_data,
                    target_addr,
                    &structs,
                    Some(section_name),
                    classify_string,
                );

                // Use lower floor for structure-based strings (high confidence)
                let struct_min = self.min_length.min(STRUCTURE_MIN_LENGTH);
                let existing: HashSet<&str> = strings
                    .iter()
                    .map(|s: &ExtractedString| s.value.as_str())
                    .collect();
                let new_strings: Vec<_> = structured
                    .into_iter()
                    .filter(|s| s.value.len() >= struct_min && !existing.contains(s.value.as_str()))
                    .collect();
                strings.extend(new_strings);
            }
        }

        // PHASE 2: Raw extraction from __cstring (null-terminated strings)
        if let Some((_, cstring_data)) = cstring_info {
            let raw = self.extract_raw_strings(cstring_data, Some("__cstring"));
            let existing: HashSet<&str> = strings.iter().map(|s| s.value.as_str()).collect();
            let new_strings: Vec<_> = raw
                .into_iter()
                .filter(|s| {
                    s.value.len() >= self.min_length && !existing.contains(s.value.as_str())
                })
                .collect();
            strings.extend(new_strings);
        }

        // PHASE 3: Heuristic extraction from __TEXT,__const for packed strings
        // Rust often packs format strings without structures
        // Skip for large sections (> 1MB) as regex scanning is expensive
        const MAX_HEURISTIC_SECTION_SIZE: usize = 1024 * 1024;
        if let Some((text_const_addr, text_const_data)) = text_const_info {
            let heuristic = if text_const_data.len() <= MAX_HEURISTIC_SECTION_SIZE {
                self.extract_packed_strings(text_const_data, Some("__TEXT,__const"))
            } else {
                Vec::new()
            };
            let new_heuristic: Vec<_> = {
                let existing: HashSet<&str> = strings.iter().map(|s| s.value.as_str()).collect();
                heuristic
                    .into_iter()
                    .filter(|s| {
                        s.value.len() >= self.min_length && !existing.contains(s.value.as_str())
                    })
                    .map(|s| ExtractedString {
                        value: s.value,
                        data_offset: text_const_addr + s.data_offset,
                        section: s.section,
                        method: StringMethod::Heuristic,
                        kind: s.kind,
                        ..Default::default()
                    })
                    .collect()
            };
            strings.extend(new_heuristic);
        }

        // PHASE 4: Instruction pattern analysis
        if let Some((text_addr, text_data)) = text_info {
            let targets: Vec<(u64, &[u8], &str)> = [
                cstring_info.map(|(a, d)| (a, d, "__cstring")),
                text_const_info.map(|(a, d)| (a, d, "__TEXT,__const")),
            ]
            .into_iter()
            .flatten()
            .collect();

            for (section_addr, section_data, section_name) in targets {
                let inline_strings = match macho.header.cputype() {
                    CPU_TYPE_ARM64 => extract_inline_strings_arm64(
                        text_data,
                        text_addr,
                        section_data,
                        section_addr,
                        self.min_length,
                    ),
                    CPU_TYPE_X86_64 => extract_inline_strings_amd64(
                        text_data,
                        text_addr,
                        section_data,
                        section_addr,
                        self.min_length,
                    ),
                    _ => Vec::new(),
                };

                let new_inline: Vec<_> = {
                    let existing: HashSet<&str> =
                        strings.iter().map(|s| s.value.as_str()).collect();
                    inline_strings
                        .into_iter()
                        .filter(|s| !existing.contains(s.value.as_str()))
                        .map(|mut s| {
                            s.section = Some(section_name.to_string());
                            s
                        })
                        .collect()
                };
                strings.extend(new_inline);
            }
        }

        strings
    }

    /// Extract strings from an ELF binary.
    pub(crate) fn extract_elf(&self, elf: &Elf<'_>, data: &[u8]) -> Vec<ExtractedString> {
        let mut strings = Vec::new();
        // Use actual endianness from ELF header
        let info = BinaryInfo::from_elf(elf.is_64, elf.little_endian);

        // Rust uses multiple sections for string data
        let string_sections = [".rodata", ".data.rel.ro", ".data.rel.ro.local"];

        for section_name in &string_sections {
            if let Some(extracted) = self.extract_from_section(elf, data, section_name, &info) {
                strings.extend(extracted);
            }
        }

        // Perform instruction pattern analysis for inline literals
        let text_info = self.find_section(elf, data, ".text");
        let rodata_info = self.find_section(elf, data, ".rodata");

        if let (Some((text_addr, text_data)), Some((rodata_addr, rodata_data))) =
            (text_info, rodata_info)
        {
            let inline_strings = match elf.header.e_machine {
                goblin::elf::header::EM_X86_64 => extract_inline_strings_amd64(
                    text_data,
                    text_addr,
                    rodata_data,
                    rodata_addr,
                    self.min_length,
                ),
                goblin::elf::header::EM_AARCH64 => extract_inline_strings_arm64(
                    text_data,
                    text_addr,
                    rodata_data,
                    rodata_addr,
                    self.min_length,
                ),
                _ => Vec::new(),
            };

            strings.extend(inline_strings);
        }

        // Deduplicate
        let mut seen: HashSet<String> = HashSet::new();
        strings.retain(|s| {
            if seen.contains(&s.value) {
                false
            } else {
                seen.insert(s.value.clone());
                true
            }
        });

        strings
    }

    /// Extract strings from a PE binary.
    ///
    /// Rust PE binaries pack `&'static str` data into `.rdata` and reference
    /// each substring through a `(ptr, len)` slice table that also lives in
    /// `.rdata` (or `.data` for `&'static [&str]` arrays). The pointers are
    /// absolute virtual addresses (`image_base + virtual_address`), so the
    /// structure scanner runs against image-base-relative VAs and the result
    /// is converted back to a file offset for downstream tooling.
    pub(crate) fn extract_pe(&self, pe: &PE<'_>, data: &[u8]) -> Vec<ExtractedString> {
        let info = BinaryInfo::from_pe(pe.is_64);
        let image_base = pe
            .header
            .optional_header
            .map_or(0u64, |opt| opt.windows_fields.image_base);

        let Some(rdata) = pe.sections.iter().find(|s| {
            let name = crate::binary::pe_section_name(&s.name);
            name == ".rdata" || name == ".rodata"
        }) else {
            return Vec::new();
        };

        let rdata_file_start = rdata.pointer_to_raw_data as usize;
        let rdata_size = rdata.size_of_raw_data as usize;
        let rdata_file_end = rdata_file_start.saturating_add(rdata_size).min(data.len());
        if rdata_file_start >= rdata_file_end {
            return Vec::new();
        }
        let rdata_bytes = &data[rdata_file_start..rdata_file_end];
        let rdata_va = image_base + u64::from(rdata.virtual_address);

        // Scan candidate sections for `(ptr, len)` pairs whose pointer falls
        // inside `.rdata`. `.rdata` itself is the dominant location; `.data`
        // also holds Rust slice tables for items that the linker chose not to
        // place in read-only memory.
        let candidate_names: &[&str] = &[".rdata", ".rodata", ".data"];
        let scan_sections: Vec<(u64, &[u8])> = pe
            .sections
            .iter()
            .filter_map(|sec| {
                let name = crate::binary::pe_section_name(&sec.name);
                if !candidate_names.contains(&name.as_str()) {
                    return None;
                }
                let start = usize::try_from(sec.pointer_to_raw_data).ok()?;
                let size = usize::try_from(sec.size_of_raw_data).ok()?;
                let end = start.checked_add(size)?.min(data.len());
                if start >= end {
                    return None;
                }
                Some((
                    image_base + u64::from(sec.virtual_address),
                    &data[start..end],
                ))
            })
            .collect();

        let all_structs: Vec<StringStruct> = scan_sections
            .par_iter()
            .flat_map(|(addr, bytes)| {
                find_string_structures(bytes, *addr, rdata_va, rdata_bytes.len() as u64, &info)
            })
            .collect();

        let mut structured = extract_from_structures(
            rdata_bytes,
            rdata_va,
            &all_structs,
            Some(".rdata"),
            classify_string,
        );

        // Convert the VA stored in `data_offset` back to a file offset so the
        // result lines up with the raw scanner's reporting convention.
        let rdata_file_start_u64 = rdata_file_start as u64;
        for s in &mut structured {
            s.data_offset = rdata_file_start_u64 + (s.data_offset - rdata_va);
        }

        let struct_min = self.min_length.min(STRUCTURE_MIN_LENGTH);
        let mut seen: HashSet<String> = HashSet::new();
        structured
            .into_iter()
            .filter(|s| s.value.len() >= struct_min && seen.insert(s.value.clone()))
            .collect()
    }

    /// Helper to find a section by name and return its address and data.
    fn find_section<'a>(
        &self,
        elf: &Elf<'_>,
        data: &'a [u8],
        section_name: &str,
    ) -> Option<(u64, &'a [u8])> {
        for sh in &elf.section_headers {
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
            if name == section_name {
                let offset = sh.sh_offset as usize;
                let size = sh.sh_size as usize;
                if let Some(end) = offset.checked_add(size)
                    && end <= data.len()
                {
                    return Some((sh.sh_addr, &data[offset..end]));
                }
            }
        }
        None
    }

    fn extract_from_section(
        &self,
        elf: &Elf<'_>,
        data: &[u8],
        target_section: &str,
        info: &BinaryInfo,
    ) -> Option<Vec<ExtractedString>> {
        // Find the target section
        let mut section_info: Option<(u64, usize, usize)> = None;

        for sh in &elf.section_headers {
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
            if name == target_section {
                section_info = Some((sh.sh_addr, sh.sh_offset as usize, sh.sh_size as usize));
                break;
            }
        }

        let (section_addr, section_offset, section_size) = section_info?;

        if section_offset + section_size > data.len() {
            return None;
        }

        let section_data = &data[section_offset..section_offset + section_size];

        // Search all sections for string structures pointing into this section
        let mut all_structs = Vec::new();

        for sh in &elf.section_headers {
            if sh.sh_type == goblin::elf::section_header::SHT_NOBITS || sh.sh_size == 0 {
                continue;
            }

            let offset = sh.sh_offset as usize;
            let size = sh.sh_size as usize;
            let Some(end) = offset.checked_add(size) else {
                continue;
            };

            if end > data.len() {
                continue;
            }

            let search_data = &data[offset..end];
            let structs = find_string_structures(
                search_data,
                sh.sh_addr,
                section_addr,
                section_size as u64,
                info,
            );
            all_structs.extend(structs);
        }

        if all_structs.is_empty() {
            return None;
        }

        // Extract strings using structure boundaries
        let mut extracted = extract_from_structures(
            section_data,
            section_addr,
            &all_structs,
            Some(target_section),
            classify_string,
        );

        // Use lower floor for structure-based strings (high confidence)
        let struct_min = self.min_length.min(STRUCTURE_MIN_LENGTH);
        extracted.retain(|s| s.value.len() >= struct_min);

        Some(extracted)
    }

    /// Extract raw strings as fallback.
    fn extract_raw_strings(&self, data: &[u8], section_name: Option<&str>) -> Vec<ExtractedString> {
        let mut strings = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        let mut current = Vec::new();
        let mut start_offset = 0usize;

        for (i, &byte) in data.iter().enumerate() {
            if byte == 0 {
                if current.len() >= self.min_length
                    && let Ok(s) = std::str::from_utf8(&current)
                {
                    let trimmed = s.trim();
                    if !trimmed.is_empty() && !seen.contains(trimmed) {
                        seen.insert(trimmed.to_string());
                        strings.push(ExtractedString {
                            value: trimmed.to_string(),
                            data_offset: start_offset as u64,
                            section: section_name.map(str::to_string),
                            method: StringMethod::RawScan,
                            kind: classify_string(trimmed),
                            ..Default::default()
                        });
                    }
                }
                current.clear();
            } else if byte.is_ascii_graphic() || byte.is_ascii_whitespace() {
                if current.is_empty() {
                    start_offset = i;
                }
                current.push(byte);
            } else {
                current.clear();
            }
        }

        strings
    }

    /// Extract strings from packed data using heuristic pattern matching.
    ///
    /// Rust often packs format strings and literals together without null
    /// terminators or pointer structures. This method uses pattern recognition
    /// to split and extract meaningful strings.
    fn extract_packed_strings(
        &self,
        data: &[u8],
        section_name: Option<&str>,
    ) -> Vec<ExtractedString> {
        // Collect segments with their byte offsets within `data`.
        //
        // A segment is a maximal run of printable ASCII (or newline, a real
        // delimiter Rust keeps inside packed literals); every other byte
        // splits. Such runs are pure ASCII, so they can be borrowed straight
        // from `data` as &str — no intermediate copy of the section needed.
        let is_segment_byte = |b: u8| b == b'\n' || (32..127).contains(&b);
        let mut segments: Vec<(&str, u64)> = Vec::new();
        let mut run_start: Option<usize> = None;
        for (i, &b) in data.iter().enumerate() {
            if is_segment_byte(b) {
                if run_start.is_none() {
                    run_start = Some(i);
                }
            } else if let Some(start) = run_start.take()
                && i - start >= self.min_length
                && let Ok(seg) = std::str::from_utf8(&data[start..i])
            {
                segments.push((seg, start as u64));
            }
        }
        if let Some(start) = run_start
            && data.len() - start >= self.min_length
            && let Ok(seg) = std::str::from_utf8(&data[start..])
        {
            segments.push((seg, start as u64));
        }

        // Process segments in parallel
        let all_strings: Vec<Vec<ExtractedString>> = segments
            .par_iter()
            .map(|(segment, segment_base)| {
                let mut strings = Vec::new();
                let mut seen = HashSet::new();
                self.extract_patterns_from_segment(
                    segment,
                    *segment_base,
                    section_name,
                    &mut strings,
                    &mut seen,
                );
                strings
            })
            .collect();

        // Flatten and deduplicate
        let mut seen: HashSet<String> = HashSet::new();
        all_strings
            .into_iter()
            .flatten()
            .filter(|s| seen.insert(s.value.clone()))
            .collect()
    }

    /// Extract recognizable patterns from a text segment.
    ///
    /// `segment_base` is the byte offset of this segment's start within the original data slice,
    /// used to compute accurate `data_offset` values for each extracted string.
    fn extract_patterns_from_segment(
        &self,
        segment: &str,
        segment_base: u64,
        section_name: Option<&str>,
        strings: &mut Vec<ExtractedString>,
        seen: &mut HashSet<String>,
    ) {
        // Pattern 1: URLs (highest priority, clear boundaries)
        for cap in RE_URL.find_iter(segment) {
            let url = cap.as_str().trim_end_matches(['.', ',', ';']);
            let offset = segment_base + cap.start() as u64;
            self.add_if_valid(url, offset, section_name, strings, seen);
        }

        // Pattern 2: Unix file paths
        for cap in RE_PATH.find_iter(segment) {
            let path = cap.as_str();
            if path.contains('/') && path.len() >= self.min_length {
                let offset = segment_base + cap.start() as u64;
                self.add_if_valid(path, offset, section_name, strings, seen);
            }
        }

        // Pattern 3: Environment variable names (UPPER_CASE_WITH_UNDERSCORES)
        for cap in RE_ENV_VAR.find_iter(segment) {
            let env_var = cap.as_str();
            if env_var.contains('_') && env_var.len() >= self.min_length {
                let offset = segment_base + cap.start() as u64;
                self.add_if_valid(env_var, offset, section_name, strings, seen);
            }
        }

        // Pattern 4: snake_case identifiers
        for cap in RE_SNAKE_CASE.find_iter(segment) {
            let ident = cap.as_str();
            if ident.len() >= self.min_length {
                let offset = segment_base + cap.start() as u64;
                self.add_if_valid(ident, offset, section_name, strings, seen);
            }
        }

        // Pattern 5: Domain names
        for cap in RE_DOMAIN.find_iter(segment) {
            let domain = cap.as_str();
            if domain.len() >= self.min_length {
                let offset = segment_base + cap.start() as u64;
                self.add_if_valid(domain, offset, section_name, strings, seen);
            }
        }

        // Pattern 6: Split on boundary patterns and extract remaining identifiers
        let seg_start = segment.as_ptr() as usize;
        for part in segment
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '.' && c != '-')
            .filter(|s| s.len() >= self.min_length)
        {
            let part_base = segment_base + (part.as_ptr() as usize - seg_start) as u64;

            // Split on case transitions: lowercase followed by 4+ uppercase.
            // All chars here are ASCII so byte index == char index.
            let mut last_byte = 0usize;
            let char_indices: Vec<(usize, char)> = part.char_indices().collect();
            for i in 1..char_indices.len().saturating_sub(3) {
                if char_indices[i - 1].1.is_ascii_lowercase()
                    && char_indices[i].1.is_ascii_uppercase()
                    && char_indices
                        .get(i + 1)
                        .is_some_and(|(_, c)| c.is_ascii_uppercase())
                    && char_indices
                        .get(i + 2)
                        .is_some_and(|(_, c)| c.is_ascii_uppercase())
                {
                    let byte_end = char_indices[i].0;
                    let sub = &part[last_byte..byte_end];
                    if sub.len() >= self.min_length {
                        self.add_if_valid(
                            sub,
                            part_base + last_byte as u64,
                            section_name,
                            strings,
                            seen,
                        );
                    }
                    last_byte = byte_end;
                }
            }
            // Add remaining part
            let sub = &part[last_byte..];
            if sub.len() >= self.min_length {
                self.add_if_valid(
                    sub,
                    part_base + last_byte as u64,
                    section_name,
                    strings,
                    seen,
                );
            }
        }
    }

    /// Add a string if it passes validation.
    fn add_if_valid(
        &self,
        s: &str,
        data_offset: u64,
        section_name: Option<&str>,
        strings: &mut Vec<ExtractedString>,
        seen: &mut HashSet<String>,
    ) {
        let trimmed = s.trim();
        if trimmed.len() < self.min_length {
            return;
        }
        if seen.contains(trimmed) {
            return;
        }
        // Skip if mostly digits
        let digit_count = trimmed.chars().filter(char::is_ascii_digit).count();
        if digit_count > trimmed.len() * 7 / 10 {
            return;
        }
        // Skip if looks like hex
        if trimmed.len() <= 16
            && trimmed
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == 'x' || c == 'X')
        {
            return;
        }

        seen.insert(trimmed.to_string());
        strings.push(ExtractedString {
            value: trimmed.to_string(),
            data_offset,
            section: section_name.map(str::to_string),
            method: StringMethod::Heuristic,
            kind: classify_string(trimmed),
            ..Default::default()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StringKind;
    use goblin::mach::MachO;

    #[test]
    fn test_rust_extractor_creation() {
        let extractor = RustStringExtractor::new(4);
        assert_eq!(extractor.min_length, 4);
    }

    #[test]
    fn test_rust_extractor_different_min_lengths() {
        let extractor1 = RustStringExtractor::new(0);
        assert_eq!(extractor1.min_length, 0);
        let extractor2 = RustStringExtractor::new(100);
        assert_eq!(extractor2.min_length, 100);
    }

    #[test]
    fn test_raw_string_extraction() {
        let extractor = RustStringExtractor::new(4);
        let data = b"Hello\0World\0foo\0";

        let strings = extractor.extract_raw_strings(data, Some(".rodata"));

        assert_eq!(strings.len(), 2); // "Hello" and "World", "foo" is < 4 chars
        assert!(strings.iter().any(|s| s.value == "Hello"));
        assert!(strings.iter().any(|s| s.value == "World"));
    }

    #[test]
    fn test_raw_string_deduplication() {
        let extractor = RustStringExtractor::new(4);
        let data = b"Hello\0Hello\0World\0";

        let strings = extractor.extract_raw_strings(data, None);

        // Should deduplicate
        assert_eq!(strings.iter().filter(|s| s.value == "Hello").count(), 1);
    }

    #[test]
    fn test_raw_string_min_length() {
        let extractor = RustStringExtractor::new(6);
        let data = b"Hello\0World\0";

        let strings = extractor.extract_raw_strings(data, None);

        // "Hello" is 5 chars, "World" is 5 chars - both < 6
        assert!(strings.is_empty());
    }

    #[test]
    fn test_raw_string_whitespace_trimming() {
        let extractor = RustStringExtractor::new(4);
        let data = b"  Hello  \0  World  \0";

        let strings = extractor.extract_raw_strings(data, None);

        assert!(strings.iter().any(|s| s.value == "Hello"));
        assert!(strings.iter().any(|s| s.value == "World"));
    }

    #[test]
    fn test_raw_string_non_printable_breaks() {
        let extractor = RustStringExtractor::new(4);
        // Non-printable byte should break the string
        let data = b"Hello\x01World\0";

        let strings = extractor.extract_raw_strings(data, None);

        // Should have World (5 chars), Hello was broken
        assert!(strings.iter().any(|s| s.value == "World"));
    }

    #[test]
    fn test_extract_packed_strings_urls() {
        let extractor = RustStringExtractor::new(4);
        let data = b"https://example.com/path?query=value";

        let strings = extractor.extract_packed_strings(data, Some("test"));

        assert!(strings.iter().any(|s| s.value.contains("example.com")));
    }

    #[test]
    fn test_extract_packed_strings_paths() {
        let extractor = RustStringExtractor::new(4);
        let data = b"/usr/local/bin/rustc";

        let strings = extractor.extract_packed_strings(data, None);

        assert!(strings.iter().any(|s| s.value.contains("/usr")));
    }

    #[test]
    fn test_extract_packed_strings_env_vars() {
        let extractor = RustStringExtractor::new(4);
        let data = b"RUST_BACKTRACE=full HOME_DIR=/home";

        let strings = extractor.extract_packed_strings(data, None);

        assert!(strings.iter().any(|s| s.value.contains("RUST_BACKTRACE")));
    }

    #[test]
    fn test_extract_packed_strings_snake_case() {
        let extractor = RustStringExtractor::new(4);
        let data = b"my_function_name some_other_var";

        let strings = extractor.extract_packed_strings(data, None);

        assert!(strings.iter().any(|s| s.value.contains("my_function_name")));
    }

    #[test]
    fn test_extract_packed_strings_domain_names() {
        let extractor = RustStringExtractor::new(4);
        let data = b"example.com api.github.com";

        let strings = extractor.extract_packed_strings(data, None);

        assert!(strings.iter().any(|s| s.value.contains("example.com")));
    }

    #[test]
    fn test_extract_packed_strings_null_separated() {
        let extractor = RustStringExtractor::new(4);
        let data = b"hello\0world\0test";

        let strings = extractor.extract_packed_strings(data, None);

        // Should split on nulls
        assert!(strings.iter().any(|s| s.value == "hello"));
        assert!(strings.iter().any(|s| s.value == "world"));
    }

    #[test]
    fn test_extract_packed_strings_newline_separated() {
        let extractor = RustStringExtractor::new(4);
        let data = b"line1\nline2\nline3";

        let strings = extractor.extract_packed_strings(data, None);

        // Should process newlines
        assert!(!strings.is_empty());
    }

    #[test]
    fn test_add_if_valid_too_short() {
        let extractor = RustStringExtractor::new(10);
        let mut strings = Vec::new();
        let mut seen = HashSet::new();

        extractor.add_if_valid("short", 0, None, &mut strings, &mut seen);

        assert!(strings.is_empty());
    }

    #[test]
    fn test_add_if_valid_duplicate() {
        let extractor = RustStringExtractor::new(4);
        let mut strings = Vec::new();
        let mut seen = HashSet::new();

        seen.insert("hello".to_string());
        extractor.add_if_valid("hello", 0, None, &mut strings, &mut seen);

        assert!(strings.is_empty());
    }

    #[test]
    fn test_add_if_valid_mostly_digits() {
        let extractor = RustStringExtractor::new(4);
        let mut strings = Vec::new();
        let mut seen = HashSet::new();

        // More than 70% digits should be rejected
        extractor.add_if_valid("12345678ab", 0, None, &mut strings, &mut seen);

        assert!(strings.is_empty());
    }

    #[test]
    fn test_add_if_valid_hex_pattern() {
        let extractor = RustStringExtractor::new(4);
        let mut strings = Vec::new();
        let mut seen = HashSet::new();

        // Short hex patterns should be rejected
        extractor.add_if_valid("deadbeef", 0, None, &mut strings, &mut seen);

        assert!(strings.is_empty());
    }

    #[test]
    fn test_add_if_valid_success() {
        let extractor = RustStringExtractor::new(4);
        let mut strings = Vec::new();
        let mut seen = HashSet::new();

        extractor.add_if_valid("hello_world", 0, Some(".rodata"), &mut strings, &mut seen);

        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value, "hello_world");
        assert_eq!(strings[0].method, StringMethod::Heuristic);
    }

    #[test]
    fn test_extract_patterns_from_segment_complex() {
        let extractor = RustStringExtractor::new(4);
        let segment = "https://example.com/path /usr/bin/test MY_ENV_VAR=value snake_case_ident";
        let mut strings = Vec::new();
        let mut seen = HashSet::new();

        extractor.extract_patterns_from_segment(
            segment,
            0,
            Some(".rodata"),
            &mut strings,
            &mut seen,
        );

        // Should extract URLs, paths, env vars, and identifiers
        assert!(!strings.is_empty());
    }

    #[test]
    fn test_extract_patterns_case_transition_split() {
        let extractor = RustStringExtractor::new(4);
        // lowercaseUPPERCASEFOLLOWS - should split on case transition
        let segment = "helloWORLDNOW";
        let mut strings = Vec::new();
        let mut seen = HashSet::new();

        extractor.extract_patterns_from_segment(segment, 0, None, &mut strings, &mut seen);

        // Should handle case transitions
        assert!(!strings.is_empty());
    }

    #[test]
    fn test_find_section_not_found() {
        let extractor = RustStringExtractor::new(4);

        // Create minimal ELF-like data
        let mut data = vec![0u8; 512];
        data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        data[4] = 2; // 64-bit
        data[5] = 1; // little endian

        // Parse as ELF and try to find a non-existent section
        if let Ok(goblin::Object::Elf(elf)) = goblin::Object::parse(&data) {
            let result = extractor.find_section(&elf, &data, ".nonexistent");
            assert!(result.is_none());
        }
    }

    #[test]
    fn test_raw_string_classification() {
        let extractor = RustStringExtractor::new(4);
        let data = b"https://example.com\0/usr/bin\0ERROR_CODE\0";

        let strings = extractor.extract_raw_strings(data, None);

        // Check classification
        let url = strings
            .iter()
            .find(|s| s.value.contains("example"))
            .unwrap();
        assert_eq!(url.kind, Some(StringKind::Url));

        let path = strings.iter().find(|s| s.value.contains("/usr")).unwrap();
        assert_eq!(path.kind, Some(StringKind::Path));
    }

    #[test]
    fn test_extractor_size() {
        let extractor = RustStringExtractor::new(4);
        assert_eq!(
            std::mem::size_of_val(&extractor),
            std::mem::size_of::<usize>()
        );
    }

    #[test]
    fn test_elf_extraction_empty_data() {
        let extractor = RustStringExtractor::new(4);
        let mut elf_data = vec![0u8; 64];
        elf_data[0..4].copy_from_slice(b"\x7fELF");
        elf_data[4] = 2;
        elf_data[5] = 1;
        elf_data[6] = 1;
        if let Ok(elf) = goblin::elf::Elf::parse(&elf_data) {
            let strings = extractor.extract_elf(&elf, &elf_data);
            assert!(strings.len() < 10);
        }
    }

    #[test]
    fn test_elf_extraction_with_rodata() {
        let extractor = RustStringExtractor::new(4);
        let mut elf_data = vec![0u8; 1024];
        elf_data[0..4].copy_from_slice(b"\x7fELF");
        elf_data[4] = 2;
        elf_data[5] = 1;
        elf_data[6] = 1;
        elf_data[16] = 3;
        elf_data[18] = 0x3e;
        let test_strings = b"test_string\0another_test\0hello_world\0";
        elf_data[512..512 + test_strings.len()].copy_from_slice(test_strings);
        if let Ok(elf) = goblin::elf::Elf::parse(&elf_data) {
            let strings = extractor.extract_elf(&elf, &elf_data);
            assert!(strings.len() < 100);
        }
    }

    #[test]
    fn test_macho_extraction_minimal() {
        let extractor = RustStringExtractor::new(4);
        let mut macho_data = vec![0u8; 4096];
        macho_data[0..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        if let Ok(macho) = MachO::parse(&macho_data, 0) {
            let strings = extractor.extract_macho(&macho, &macho_data);
            assert!(strings.len() < 10);
        }
    }

    #[test]
    fn test_elf_multiple_sections() {
        let extractor = RustStringExtractor::new(4);
        let test_paths = ["/bin/true", "/usr/bin/true", "/bin/echo"];
        for path in &test_paths {
            if let Ok(data) = std::fs::read(path)
                && let Ok(elf) = goblin::elf::Elf::parse(&data)
            {
                let strings = extractor.extract_elf(&elf, &data);
                assert!(!strings.is_empty(), "Should find strings in {}", path);
                for s in &strings {
                    assert!(s.value.len() >= 4, "String too short: '{}'", s.value);
                }
                let has_any_method = strings.iter().any(|s| {
                    matches!(
                        s.method,
                        crate::StringMethod::Structure
                            | crate::StringMethod::InstructionPattern
                            | crate::StringMethod::RawScan
                    )
                });
                assert!(has_any_method, "Should use at least one extraction method");
                break;
            }
        }
    }

    #[test]
    fn test_min_length_filtering_elf() {
        let extractor_short = RustStringExtractor::new(4);
        let extractor_long = RustStringExtractor::new(20);
        if let Ok(data) = std::fs::read("/bin/ls")
            && let Ok(elf) = goblin::elf::Elf::parse(&data)
        {
            let strings_short = extractor_short.extract_elf(&elf, &data);
            let strings_long = extractor_long.extract_elf(&elf, &data);
            assert!(strings_long.len() <= strings_short.len());
            for s in &strings_long {
                // Structure-based strings can be shorter than min_length (down to 2)
                assert!(s.value.len() >= 2, "String '{}' too short", s.value);
            }
            for s in &strings_short {
                assert!(s.value.len() >= 2, "String too short: '{}'", s.value);
            }
        }
    }

    #[test]
    fn test_elf_string_deduplication() {
        let extractor = RustStringExtractor::new(4);
        if let Ok(data) = std::fs::read("/bin/ls")
            && let Ok(elf) = goblin::elf::Elf::parse(&data)
        {
            let strings = extractor.extract_elf(&elf, &data);
            let mut seen = std::collections::HashSet::new();
            let mut duplicates = Vec::new();
            for s in &strings {
                if !seen.insert(&s.value) {
                    duplicates.push(&s.value);
                }
            }
            assert!(
                duplicates.len() < strings.len() / 10,
                "Too many duplicates: {} out of {}",
                duplicates.len(),
                strings.len()
            );
        }
    }

    #[test]
    fn test_macho_text_const() {
        let extractor = RustStringExtractor::new(4);
        for path in &["/bin/ls", "/usr/bin/true", "/bin/cat"] {
            if let Ok(data) = std::fs::read(path)
                && data.len() > 4
                && data[0..4] == [0xcf, 0xfa, 0xed, 0xfe]
                && let Ok(macho) = MachO::parse(&data, 0)
            {
                let strings = extractor.extract_macho(&macho, &data);
                if !strings.is_empty() {
                    for s in &strings {
                        assert!(s.value.len() >= 4);
                    }
                    break;
                }
            }
        }
    }

    #[test]
    fn test_corrupted_binary_handling() {
        let extractor = RustStringExtractor::new(4);
        let garbage_data = vec![0xAA; 1024];
        if let Ok(elf) = goblin::elf::Elf::parse(&garbage_data) {
            let strings = extractor.extract_elf(&elf, &garbage_data);
            assert!(strings.len() < 500);
        }
    }

    #[test]
    fn test_empty_binary() {
        let extractor = RustStringExtractor::new(4);
        if let Ok(elf) = goblin::elf::Elf::parse(&[]) {
            assert!(extractor.extract_elf(&elf, &[]).is_empty());
        }
    }

    #[test]
    fn test_very_large_min_length() {
        let extractor = RustStringExtractor::new(1000);
        if let Ok(data) = std::fs::read("/bin/ls")
            && let Ok(elf) = goblin::elf::Elf::parse(&data)
        {
            let strings = extractor.extract_elf(&elf, &data);
            for s in &strings {
                // Even with 1000 min_length, structure-based strings can be as short as 2
                assert!(
                    s.value.len() >= 2,
                    "String shorter than STRUCTURE_MIN_LENGTH"
                );
            }
            assert!(strings.len() < 50);
        }
    }

    #[test]
    fn test_section_metadata() {
        let extractor = RustStringExtractor::new(4);
        if let Ok(data) = std::fs::read("/bin/ls")
            && let Ok(elf) = goblin::elf::Elf::parse(&data)
        {
            let strings = extractor.extract_elf(&elf, &data);
            if !strings.is_empty() {
                let with_sections = strings.iter().filter(|s| s.section.is_some()).count();
                assert!(
                    with_sections > 0,
                    "At least some strings should have section metadata"
                );
                for s in &strings {
                    if let Some(section) = &s.section {
                        assert!(!section.is_empty());
                        assert!(
                            section.starts_with('.')
                                || section.starts_with("__")
                                || section == "rodata"
                                || section == "text",
                            "Unexpected section name: {}",
                            section
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_offset_validity() {
        let extractor = RustStringExtractor::new(4);
        if let Ok(data) = std::fs::read("/bin/ls") {
            let file_size = data.len() as u64;
            if let Ok(elf) = goblin::elf::Elf::parse(&data) {
                let strings = extractor.extract_elf(&elf, &data);
                for s in &strings {
                    assert!(
                        s.data_offset < file_size,
                        "Offset {} exceeds file size {}",
                        s.data_offset,
                        file_size
                    );
                }
            }
        }
    }
}
