//! Go string extractor implementation.
//!
//! Extracts strings from Go binaries using structure analysis and instruction patterns.

// This codebase targets 64-bit hosts only: usize = u64, so u64-to-usize casts are lossless.
#![allow(clippy::cast_possible_truncation)]

use crate::extraction::{extract_from_structures, find_string_structures};
use crate::instr::{extract_inline_strings_amd64, extract_inline_strings_arm64};
use crate::types::{BinaryInfo, ExtractedString, StringStruct};
use goblin::elf::Elf;
use goblin::mach::cputype::{CPU_TYPE_ARM64, CPU_TYPE_X86_64};
use goblin::mach::MachO;
use goblin::pe::PE;
use rayon::prelude::*;

use crate::classifier::classify_string;

/// Minimum length for structure-based extraction.
///
/// Structure-based strings have high confidence (backed by actual {ptr, len}
/// pairs in the binary), so we use a lower floor than the user-specified
/// min_length to avoid dropping short but real strings like "gh" or "sh".
const STRUCTURE_MIN_LENGTH: usize = 2;

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
            if seg_name == "__TEXT" {
                if let Ok(sections) = seg.sections() {
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
        for s in structured {
            if s.value.len() >= struct_min {
                strings.push(s);
            }
        }

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
                for s in inline_strings {
                    if s.value.len() >= struct_min {
                        strings.push(s);
                    }
                }
            } else if cpu_type == CPU_TYPE_X86_64 {
                let inline_strings = extract_inline_strings_amd64(
                    text_data,
                    text_addr,
                    rodata_data,
                    rodata_addr,
                    struct_min,
                );
                for s in inline_strings {
                    if s.value.len() >= struct_min {
                        strings.push(s);
                    }
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
        for s in structured {
            if s.value.len() >= struct_min {
                strings.push(s);
            }
        }

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

            for s in inline_strings {
                if s.value.len() >= struct_min {
                    strings.push(s);
                }
            }
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
        for s in structured {
            if s.value.len() >= struct_min {
                strings.push(s);
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
    use super::{extract_null_separated_strings, extract_varint_prefixed_strings};

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
}
