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
//!
//! For inline literals, we also perform instruction pattern analysis.

// This codebase targets 64-bit hosts only: usize = u64, so u64-to-usize casts are lossless.
#![allow(clippy::cast_possible_truncation)]

use super::classifier::classify_string;
use super::extraction::pair_strings;
use super::instr::{inline_strings, is_valid_utf8_string};
use super::types::{Arch, BinaryInfo, ExtractedString, StringMethod};
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
    /// - `__const` in `__DATA_CONST` or `__DATA` (ptr+len structures)
    ///
    /// Rust stores &str slice structures (ptr+len) in either data segment,
    /// while the actual string data is in `__TEXT,__const` or `__cstring`.
    ///
    /// Each phase below records the string's *virtual address* (PHASE 1/4 from a
    /// pointer or instruction operand, PHASE 3 from the section base, PHASE 2
    /// lifted onto the section's VA). A final pass converts every VA to a file
    /// offset, because every offset stng reports indexes the file. `file_base`
    /// rebases a fat slice's offsets onto the whole fat file; it is 0 for a thin
    /// binary, where `macho`'s load commands already carry file-relative offsets.
    pub(crate) fn extract_macho(&self, macho: &MachO<'_>, file_base: u64) -> Vec<ExtractedString> {
        let mut strings: Vec<ExtractedString> = Vec::new();
        let info = BinaryInfo::from_macho(macho.is_64);

        // Collect sections by type
        let mut cstring_info: Option<(u64, &[u8])> = None;
        let mut text_const_info: Option<(u64, &[u8])> = None;
        let mut data_const_sections = [None; 2];
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
                            data_const_sections[0] = Some((section.addr, section_data));
                        }
                        ("__DATA", "__const") => {
                            data_const_sections[1] = Some((section.addr, section_data));
                        }
                        ("__TEXT", "__text") => text_info = Some((section.addr, section_data)),
                        _ => {}
                    }
                }
            }
        }

        // PHASE 1: Extract data-segment structures pointing to string sections.
        // Older linkers place these in __DATA,__const rather than __DATA_CONST.
        // This is the primary method for Rust - it stores &str slices here
        for (data_const_addr, data_const_data) in data_const_sections.into_iter().flatten() {
            // Target sections to look for pointers to
            for target in [cstring_info, text_const_info].into_iter().flatten() {
                // Use lower floor for structure-based strings (high confidence)
                let structured = pair_strings(
                    [(data_const_addr, 0, data_const_data)],
                    target,
                    &info,
                    self.min_length.min(STRUCTURE_MIN_LENGTH),
                );
                let existing: HashSet<&str> = strings.iter().map(|s| s.value.as_str()).collect();
                let new_strings: Vec<_> = structured
                    .into_iter()
                    .filter(|s| !existing.contains(s.value.as_str()))
                    .collect();
                strings.extend(new_strings);
            }
        }

        // PHASE 2: Raw extraction from __cstring (null-terminated strings)
        if let Some((cstring_addr, cstring_data)) = cstring_info {
            let raw = self.extract_raw_strings(cstring_data);
            let existing: HashSet<&str> = strings.iter().map(|s| s.value.as_str()).collect();
            let new_strings: Vec<_> = raw
                .into_iter()
                .filter(|s| {
                    s.value.len() >= self.min_length && !existing.contains(s.value.as_str())
                })
                .map(|mut s| {
                    // extract_raw_strings offsets are relative to the __cstring
                    // slice; lift onto the section's VA so the VA->file pass below
                    // resolves them like every other phase.
                    s.rebase(cstring_addr);
                    s
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
                self.extract_packed_strings(text_const_data)
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
                        data_offset: text_const_addr.saturating_add(s.data_offset),
                        method: StringMethod::Heuristic,
                        kind: s.kind,
                        ..Default::default()
                    })
                    .collect()
            };
            strings.extend(new_heuristic);
        }

        // PHASE 4: Instruction pattern analysis
        if let Some(text) = text_info {
            let arch = match macho.header.cputype() {
                CPU_TYPE_ARM64 => Arch::Aarch64,
                CPU_TYPE_X86_64 => Arch::X86_64,
                _ => Arch::Other,
            };
            for target in [cstring_info, text_const_info].into_iter().flatten() {
                let inline = inline_strings(arch, text, target, self.min_length);
                let existing: HashSet<&str> = strings.iter().map(|s| s.value.as_str()).collect();
                let new_inline: Vec<_> = inline
                    .into_iter()
                    .filter(|s| !existing.contains(s.value.as_str()))
                    .collect();
                strings.extend(new_inline);
            }
        }

        // Every phase recorded a virtual address; resolve each to a file offset.
        // `macho_vaddr_to_file_offset` walks the slice's own load commands, and
        // `file_base` rebases a fat slice's result onto the whole file (0 thin).
        for s in &mut strings {
            s.data_offset = file_base.saturating_add(crate::binary::macho_vaddr_to_file_offset(
                macho,
                s.data_offset,
            ));
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

        let sections = || {
            elf.section_headers.iter().filter_map(|sh| {
                if sh.sh_type == goblin::elf::section_header::SHT_NOBITS || sh.sh_size == 0 {
                    return None;
                }
                let offset = sh.sh_offset as usize;
                let end = offset.checked_add(sh.sh_size as usize)?;
                Some((sh.sh_addr, offset, data.get(offset..end)?))
            })
        };
        let struct_min = self.min_length.min(STRUCTURE_MIN_LENGTH);
        for name in string_sections {
            if let Some(target) = crate::binary::elf_section(elf, data, name) {
                strings.extend(pair_strings(sections(), target, &info, struct_min));
            }
        }

        // Position-independent builds -- rustc's default -- leave every pointer
        // in .data.rel.ro zero on disk; the loader fills it from a RELATIVE
        // relocation. The structure scan above reads the bytes, sees (0, len),
        // and recovers nothing, so read the pointers from the relocations.
        if let Some((rodata_addr, rodata_data)) = crate::binary::elf_section(elf, data, ".rodata") {
            strings.extend(relative_reloc_strings(
                elf,
                data,
                rodata_addr,
                rodata_data,
                self.min_length,
            ));
        }

        // Perform instruction pattern analysis for inline literals
        let text_info = crate::binary::elf_section(elf, data, ".text");
        let rodata_info = crate::binary::elf_section(elf, data, ".rodata");

        if let (Some(text), Some(rodata)) = (text_info, rodata_info) {
            let arch = match elf.header.e_machine {
                goblin::elf::header::EM_X86_64 => Arch::X86_64,
                goblin::elf::header::EM_AARCH64 => Arch::Aarch64,
                _ => Arch::Other,
            };
            strings.extend(inline_strings(arch, text, rodata, self.min_length));
        }

        // Both phases decoded pointers, so every offset so far is a virtual
        // address; resolve each to a file offset, as the Mach-O path does.
        for s in &mut strings {
            s.data_offset = crate::binary::elf_vaddr_to_file_offset(elf, s.data_offset);
        }

        // Deduplicate by value: insert() is false on a repeat, dropping it.
        let mut seen: HashSet<String> = HashSet::new();
        strings.retain(|s| seen.insert(s.value.clone()));

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

        let Some(rdata_bytes) = crate::binary::file_range_clamped(
            data,
            u64::from(rdata.pointer_to_raw_data),
            u64::from(rdata.size_of_raw_data),
        ) else {
            return Vec::new();
        };
        let rdata_file_start = rdata.pointer_to_raw_data as usize;
        let rdata_va = image_base.wrapping_add(u64::from(rdata.virtual_address));

        // Scan candidate sections for `(ptr, len)` pairs whose pointer falls
        // inside `.rdata`. `.rdata` itself is the dominant location; `.data`
        // also holds Rust slice tables for items that the linker chose not to
        // place in read-only memory.
        let candidate_names: &[&str] = &[".rdata", ".rodata", ".data"];
        let scan_sections = pe.sections.iter().filter_map(|sec| {
            let name = crate::binary::pe_section_name(&sec.name);
            if !candidate_names.contains(&&*name) {
                return None;
            }
            let bytes = crate::binary::file_range_clamped(
                data,
                u64::from(sec.pointer_to_raw_data),
                u64::from(sec.size_of_raw_data),
            )?;
            Some((
                image_base.wrapping_add(u64::from(sec.virtual_address)),
                sec.pointer_to_raw_data as usize,
                bytes,
            ))
        });

        let struct_min = self.min_length.min(STRUCTURE_MIN_LENGTH);
        let structured = pair_strings(scan_sections, (rdata_va, rdata_bytes), &info, struct_min);

        // Convert the VA stored in `data_offset` back to a file offset so the
        // result lines up with the raw scanner's reporting convention.
        let rdata_file_start = rdata_file_start as u64;
        let mut seen: HashSet<String> = HashSet::new();
        structured
            .into_iter()
            .filter(|s| seen.insert(s.value.clone()))
            .map(|mut s| {
                s.data_offset = rdata_file_start.wrapping_add(s.data_offset.wrapping_sub(rdata_va));
                s
            })
            .collect()
    }
    /// Extract raw strings as fallback.
    fn extract_raw_strings(&self, data: &[u8]) -> Vec<ExtractedString> {
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
    fn extract_packed_strings(&self, data: &[u8]) -> Vec<ExtractedString> {
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
        let bytes = segments.iter().map(|(segment, _)| segment.len()).sum();
        let all_strings: Vec<Vec<ExtractedString>> = segments
            .par_iter()
            .with_min_len(crate::par::job_len(segments.len(), bytes))
            .map(|(segment, segment_base)| {
                let mut strings = Vec::new();
                let mut seen = HashSet::new();
                self.extract_patterns_from_segment(segment, *segment_base, &mut strings, &mut seen);
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
        strings: &mut Vec<ExtractedString>,
        seen: &mut HashSet<String>,
    ) {
        // Pattern 1: URLs (highest priority, clear boundaries)
        for cap in RE_URL.find_iter(segment) {
            let url = cap.as_str().trim_end_matches(['.', ',', ';']);
            let offset = segment_base + cap.start() as u64;
            self.add_if_valid(url, offset, strings, seen);
        }

        // Pattern 2: Unix file paths
        for cap in RE_PATH.find_iter(segment) {
            let path = cap.as_str();
            if path.contains('/') && path.len() >= self.min_length {
                let offset = segment_base + cap.start() as u64;
                self.add_if_valid(path, offset, strings, seen);
            }
        }

        // Pattern 3: Environment variable names (UPPER_CASE_WITH_UNDERSCORES)
        for cap in RE_ENV_VAR.find_iter(segment) {
            let env_var = cap.as_str();
            if env_var.contains('_') && env_var.len() >= self.min_length {
                let offset = segment_base + cap.start() as u64;
                self.add_if_valid(env_var, offset, strings, seen);
            }
        }

        // Pattern 4: snake_case identifiers
        for cap in RE_SNAKE_CASE.find_iter(segment) {
            let ident = cap.as_str();
            if ident.len() >= self.min_length {
                let offset = segment_base + cap.start() as u64;
                self.add_if_valid(ident, offset, strings, seen);
            }
        }

        // Pattern 5: Domain names
        for cap in RE_DOMAIN.find_iter(segment) {
            let domain = cap.as_str();
            if domain.len() >= self.min_length {
                let offset = segment_base + cap.start() as u64;
                self.add_if_valid(domain, offset, strings, seen);
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
                        self.add_if_valid(sub, part_base + last_byte as u64, strings, seen);
                    }
                    last_byte = byte_end;
                }
            }
            // Add remaining part
            let sub = &part[last_byte..];
            if sub.len() >= self.min_length {
                self.add_if_valid(sub, part_base + last_byte as u64, strings, seen);
            }
        }
    }

    /// Add a string if it passes validation.
    fn add_if_valid(
        &self,
        s: &str,
        data_offset: u64,
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
            method: StringMethod::Heuristic,
            kind: classify_string(trimmed),
            ..Default::default()
        });
    }
}

/// Longest `&str` a relocation-derived header may describe; a longer length
/// word next to a rodata pointer is some other field, not a slice length.
const RELOC_STRING_MAX_LEN: u64 = 4096;

/// `&str` / `&[u8]` headers whose pointer half is a RELATIVE relocation.
///
/// In a PIE the `(ptr, len)` pairs rustc emits for string constants, panic
/// locations and literal tables sit in `.data.rel.ro` with the pointer slot
/// zeroed; the loader writes `base + addend` there. Each relocation's addend
/// is therefore the string's address and its offset names the slot, so the
/// length is the word after it. One pass over the relocations -- no scan of
/// the section bytes -- and only pairs whose target lies in `.rodata` and
/// decodes to printable text are kept. Addresses are virtual; the caller
/// resolves them to file offsets with the rest of the ELF strings.
fn relative_reloc_strings(
    elf: &Elf<'_>,
    data: &[u8],
    rodata_addr: u64,
    rodata: &[u8],
    min_length: usize,
) -> Vec<ExtractedString> {
    let relative = match elf.header.e_machine {
        goblin::elf::header::EM_X86_64 => goblin::elf::reloc::R_X86_64_RELATIVE,
        goblin::elf::header::EM_AARCH64 => goblin::elf::reloc::R_AARCH64_RELATIVE,
        _ => return Vec::new(),
    };
    if !elf.is_64 || !elf.little_endian {
        return Vec::new();
    }
    let rodata_end = rodata_addr.saturating_add(rodata.len() as u64);
    let mut seen: HashSet<(u64, u64)> = HashSet::new();
    let mut out = Vec::new();
    for rel in &elf.dynrelas {
        if rel.r_type != relative {
            continue;
        }
        let Some(target) = rel.r_addend.and_then(|a| u64::try_from(a).ok()) else {
            continue;
        };
        if !(rodata_addr..rodata_end).contains(&target) {
            continue;
        }
        let Ok(len_at) = usize::try_from(crate::binary::elf_vaddr_to_file_offset(
            elf,
            rel.r_offset.wrapping_add(8),
        )) else {
            continue;
        };
        let Some(len) = data
            .get(len_at..len_at.saturating_add(8))
            .and_then(|b| <[u8; 8]>::try_from(b).ok())
            .map(u64::from_le_bytes)
        else {
            continue;
        };
        if len < min_length as u64 || len > RELOC_STRING_MAX_LEN || !seen.insert((target, len)) {
            continue;
        }
        let start = (target - rodata_addr) as usize;
        let Some(bytes) = rodata.get(start..start + len as usize) else {
            continue;
        };
        let Ok(s) = std::str::from_utf8(bytes) else {
            continue;
        };
        if !is_valid_utf8_string(s) {
            continue;
        }
        out.push(ExtractedString {
            value: s.to_string(),
            data_offset: target,
            method: StringMethod::Structure,
            kind: classify_string(s),
            ..Default::default()
        });
    }
    out
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod triage_tests;
