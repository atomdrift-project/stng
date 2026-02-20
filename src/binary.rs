//! Binary format helpers and type detection.

use goblin::mach::MachO;

/// Section metadata including name, size, and type.
#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub size: u64,
    pub is_executable: bool,
    pub is_writable: bool,
}

/// Collect segment and section names from a Mach-O binary.
pub fn collect_macho_segments(macho: &MachO<'_>) -> Vec<String> {
    let mut segments = Vec::new();
    for seg in &macho.segments {
        if let Ok(name) = seg.name() {
            segments.push(name.to_string());
        }
        if let Ok(sections) = seg.sections() {
            for (sec, _) in sections {
                if let Ok(name) = sec.name() {
                    segments.push(name.to_string());
                }
            }
        }
    }
    segments
}

/// Collect section metadata from a Mach-O binary.
pub fn collect_macho_section_info(
    macho: &MachO<'_>,
) -> std::collections::HashMap<String, SectionInfo> {
    use goblin::mach::constants::S_ATTR_SOME_INSTRUCTIONS;
    let mut sections = std::collections::HashMap::new();

    for seg in &macho.segments {
        if let Ok(secs) = seg.sections() {
            for (sec, _) in secs {
                if let Ok(name) = sec.name() {
                    let is_executable = (sec.flags & S_ATTR_SOME_INSTRUCTIONS) != 0;
                    let is_writable = seg.initprot & 0x2 != 0; // VM_PROT_WRITE

                    sections.insert(
                        name.to_string(),
                        SectionInfo {
                            name: name.to_string(),
                            size: sec.size,
                            is_executable,
                            is_writable,
                        },
                    );
                }
            }
        }
    }
    sections
}

/// Collect section names from an ELF binary.
pub fn collect_elf_segments(elf: &goblin::elf::Elf<'_>) -> Vec<String> {
    elf.section_headers
        .iter()
        .filter_map(|sh| {
            elf.shdr_strtab
                .get_at(sh.sh_name)
                .map(std::string::ToString::to_string)
        })
        .collect()
}

/// Collect section metadata from an ELF binary.
pub fn collect_elf_section_info(
    elf: &goblin::elf::Elf<'_>,
) -> std::collections::HashMap<String, SectionInfo> {
    use goblin::elf::section_header::{SHF_EXECINSTR, SHF_WRITE};
    let mut sections = std::collections::HashMap::new();

    for sh in &elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
            let is_executable = (sh.sh_flags & u64::from(SHF_EXECINSTR)) != 0;
            let is_writable = (sh.sh_flags & u64::from(SHF_WRITE)) != 0;

            sections.insert(
                name.to_string(),
                SectionInfo {
                    name: name.to_string(),
                    size: sh.sh_size,
                    is_executable,
                    is_writable,
                },
            );
        }
    }
    sections
}

/// Collect section metadata from a PE binary.
pub fn collect_pe_section_info(
    pe: &goblin::pe::PE<'_>,
) -> std::collections::HashMap<String, SectionInfo> {
    use goblin::pe::section_table::{IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE};
    let mut sections = std::collections::HashMap::new();

    for sec in &pe.sections {
        let name = String::from_utf8_lossy(&sec.name)
            .trim_end_matches('\0')
            .to_string();

        let is_executable = (sec.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        let is_writable = (sec.characteristics & IMAGE_SCN_MEM_WRITE) != 0;

        sections.insert(
            name.clone(),
            SectionInfo {
                name,
                size: u64::from(sec.size_of_raw_data),
                is_executable,
                is_writable,
            },
        );
    }
    sections
}

/// Helper to check if a Mach-O binary has Go sections.
pub fn macho_has_go_sections(macho: &MachO<'_>) -> bool {
    macho.segments.iter().any(|seg| {
        seg.sections().is_ok_and(|secs| {
            secs.iter().any(|(sec, _)| {
                let name = sec.name().unwrap_or("");
                name == "__gopclntab" || name == "__go_buildinfo"
            })
        })
    })
}

/// Check if a binary is a Go binary by looking for Go-specific sections.
pub fn is_go_binary(data: &[u8]) -> bool {
    use goblin::Object;
    match Object::parse(data) {
        Ok(Object::Mach(goblin::mach::Mach::Binary(macho))) => macho_has_go_sections(&macho),
        Ok(Object::Elf(elf)) => elf.section_headers.iter().any(|sh| {
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
            name == ".gopclntab" || name == ".go.buildinfo"
        }),
        Ok(Object::PE(_pe)) => false,
        _ => false,
    }
}

/// Check if a binary is a Rust binary.
pub fn is_rust_binary(data: &[u8]) -> bool {
    use goblin::Object;
    match Object::parse(data) {
        Ok(Object::Mach(goblin::mach::Mach::Binary(macho))) => macho_is_rust(&macho),
        Ok(Object::Elf(elf)) => elf.section_headers.iter().any(|sh| {
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
            name.contains("rust") || name == ".rustc"
        }),
        _ => false,
    }
}

/// Check if a Mach-O binary appears to be a Rust binary.
pub fn macho_is_rust(macho: &MachO<'_>) -> bool {
    macho.segments.iter().any(|seg| {
        seg.sections().is_ok_and(|secs| {
            secs.iter().any(|(sec, _)| {
                let name = sec.name().unwrap_or("");
                name.contains("rust")
            })
        })
    })
}

/// Find the section name containing an address in a Mach-O binary.
pub fn find_macho_section(macho: &MachO<'_>, addr: u64) -> Option<String> {
    for seg in &macho.segments {
        for (sec, _) in &seg.sections().ok()? {
            let start = sec.addr;
            let end = start + sec.size;
            if addr >= start && addr < end {
                return Some(sec.name().ok()?.to_string());
            }
        }
    }
    None
}

/// Convert virtual address to file offset for Mach-O binaries.
pub fn macho_vaddr_to_file_offset(macho: &MachO<'_>, vaddr: u64) -> u64 {
    for seg in &macho.segments {
        let vm_start = seg.vmaddr;
        let vm_end = vm_start + seg.vmsize;

        if vaddr >= vm_start && vaddr < vm_end {
            // file_offset = (virtual_address - segment_vmaddr) + segment_fileoff
            return (vaddr - vm_start) + seg.fileoff;
        }
    }

    // If not found in any segment, return the vaddr as-is
    vaddr
}
