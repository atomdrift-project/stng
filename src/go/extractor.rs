//! Go string extractor implementation.
//!
//! Extracts strings from Go binaries using structure analysis and instruction patterns.

use crate::extraction::{extract_from_structures, find_string_structures};
use crate::instr::{extract_inline_strings_amd64, extract_inline_strings_arm64};
use crate::types::{BinaryInfo, ExtractedString, StringStruct};
use goblin::elf::Elf;
use goblin::mach::cputype::{CPU_TYPE_ARM64, CPU_TYPE_X86_64};
use goblin::mach::MachO;
use goblin::pe::PE;
use rayon::prelude::*;

use super::classifier::classify_string;

/// Extracts strings from Go binaries using structure analysis.
pub struct GoStringExtractor {
    min_length: usize,
}

impl GoStringExtractor {
    pub fn new(min_length: usize) -> Self {
        Self { min_length }
    }

    /// Extract strings from a Mach-O binary.
    pub fn extract_macho(&self, macho: &MachO<'_>, _data: &[u8]) -> Vec<ExtractedString> {
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

        // Filter by minimum length
        for s in structured {
            if s.value.len() >= self.min_length {
                strings.push(s);
            }
        }

        // Extract inline strings from instructions (ARM64 or x86_64)
        if let Some((text_addr, text_data)) = text_info {
            let cpu_type = macho.header.cputype();
            if cpu_type == CPU_TYPE_ARM64 {
                let inline_strings = extract_inline_strings_arm64(
                    text_data,
                    text_addr,
                    rodata_data,
                    rodata_addr,
                    self.min_length,
                );
                for s in inline_strings {
                    if s.value.len() >= self.min_length {
                        strings.push(s);
                    }
                }
            } else if cpu_type == CPU_TYPE_X86_64 {
                let inline_strings = extract_inline_strings_amd64(
                    text_data,
                    text_addr,
                    rodata_data,
                    rodata_addr,
                    self.min_length,
                );
                for s in inline_strings {
                    if s.value.len() >= self.min_length {
                        strings.push(s);
                    }
                }
            }
        }

        strings
    }

    /// Extract strings from an ELF binary.
    pub fn extract_elf(&self, elf: &Elf<'_>, data: &[u8]) -> Vec<ExtractedString> {
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
                let end = start + sh.sh_size as usize;
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
                let end = start + sh.sh_size as usize;
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

        for s in structured {
            if s.value.len() >= self.min_length {
                strings.push(s);
            }
        }

        // Extract inline strings from .text section
        if let Some((text_addr, text_data)) = text_info {
            // Detect architecture from ELF machine type
            let inline_strings = match elf.header.e_machine {
                goblin::elf::header::EM_AARCH64 => extract_inline_strings_arm64(
                    text_data,
                    text_addr,
                    rodata_data,
                    rodata_addr,
                    self.min_length,
                ),
                goblin::elf::header::EM_X86_64 => extract_inline_strings_amd64(
                    text_data,
                    text_addr,
                    rodata_data,
                    rodata_addr,
                    self.min_length,
                ),
                _ => Vec::new(),
            };

            for s in inline_strings {
                if s.value.len() >= self.min_length {
                    strings.push(s);
                }
            }
        }

        strings
    }

    /// Extract strings from a PE binary.
    pub fn extract_pe(&self, pe: &PE<'_>, data: &[u8]) -> Vec<ExtractedString> {
        let mut strings = Vec::new();
        let info = BinaryInfo::from_pe(pe.is_64);

        // Find .rodata or .rdata section
        let rodata_info = self.find_rodata_pe(pe, data);
        let Some((rodata_addr, rodata_data)) = rodata_info else {
            return strings;
        };

        // Search all sections for string structures
        let sections_info: Vec<_> = pe
            .sections
            .iter()
            .filter_map(|section| {
                let start = section.pointer_to_raw_data as usize;
                let size = section.size_of_raw_data as usize;
                let end = start.saturating_add(size);
                if end <= data.len() && size > 0 {
                    Some((u64::from(section.virtual_address), &data[start..end]))
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

        // Extract strings
        let structured = extract_from_structures(
            rodata_data,
            rodata_addr,
            &all_structs,
            Some(".rodata"),
            classify_string,
        );

        for s in structured {
            if s.value.len() >= self.min_length {
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
        let end = start + rodata_sh.sh_size as usize;

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
            let name = String::from_utf8_lossy(&section.name);
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
