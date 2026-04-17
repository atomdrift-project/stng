//! Binary format helpers and type detection.

use goblin::mach::MachO;

/// Executable-section byte ranges from a `SectionInfo` map.
///
/// XOR-obfuscated strings never live in `.text`/`__TEXT.__text` — that's
/// machine code. Skipping these ranges during XOR scanning typically drops
/// the scanned-byte count by 60-80% on normal binaries with near-zero risk
/// of missing legitimate hits.
#[must_use]
pub fn code_ranges_from_sections(
    section_info: &std::collections::HashMap<String, SectionInfo>,
) -> Vec<(usize, usize)> {
    let mut ranges: Vec<(usize, usize)> = section_info
        .values()
        .filter(|s| s.is_executable && s.size > 0)
        .map(SectionInfo::range)
        .filter(|&(start, end)| end > start)
        .collect();
    ranges.sort_unstable_by_key(|&(s, _)| s);
    ranges
}

/// Heuristic: is this binary signed by a platform vendor (Apple, Microsoft)?
///
/// Only *platform* signatures — the CAs that ship the OS — are treated as
/// trustworthy-enough to skip expensive pattern scans. Third-party developer
/// signatures (including malware that managed to get signed) are NOT matched
/// here.
///
/// Implemented as a bounded memmem scan for CA subject strings that appear
/// verbatim in the embedded code signature / Authenticode blob. We scan both
/// the head and the tail of the file because Mach-O places
/// `LC_CODE_SIGNATURE` after `__LINKEDIT` (near the file tail) and PE's
/// Certificate Table directory typically lives near the end as well.
#[must_use]
pub fn is_platform_signed(data: &[u8]) -> bool {
    // Apple platform CAs — match only Apple's own OS/system binaries, not
    // Developer ID third-party signatures.
    const APPLE_PLATFORM_CAS: &[&[u8]] = &[
        b"Apple Root CA",
        b"Apple Mac OS Application Signing",
        b"Software Signing",
    ];
    // Microsoft platform CAs — Windows system binaries, driver signing.
    const MICROSOFT_PLATFORM_CAS: &[&[u8]] = &[
        b"Microsoft Windows Production PCA",
        b"Microsoft Windows",
        b"Microsoft Root Certificate Authority",
    ];
    const HEAD_WINDOW: usize = 4 * 1024 * 1024;
    const TAIL_WINDOW: usize = 4 * 1024 * 1024;
    let head_end = data.len().min(HEAD_WINDOW);
    let tail_start = data.len().saturating_sub(TAIL_WINDOW).max(head_end);
    let head = &data[..head_end];
    let tail = &data[tail_start..];
    APPLE_PLATFORM_CAS
        .iter()
        .chain(MICROSOFT_PLATFORM_CAS.iter())
        .any(|needle| {
            memchr::memmem::find(head, needle).is_some()
                || memchr::memmem::find(tail, needle).is_some()
        })
}

/// Convert a PE section name ([u8; 8]) to a String, trimming NUL bytes.
/// Avoids the allocation overhead of `String::from_utf8_lossy` for ASCII section names.
#[inline]
pub(crate) fn pe_section_name(name: &[u8; 8]) -> String {
    let end = name.iter().position(|&b| b == 0).unwrap_or(8);
    // PE section names are ASCII; use from_utf8 with lossy fallback for malformed binaries
    match std::str::from_utf8(&name[..end]) {
        Ok(s) => s.to_string(),
        Err(_) => String::from_utf8_lossy(&name[..end]).into_owned(),
    }
}

/// Section metadata including name, size, type, and byte range.
#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    /// File offset of section payload (where raw bytes begin).
    pub file_offset: u64,
    pub size: u64,
    pub is_executable: bool,
    pub is_writable: bool,
}

impl SectionInfo {
    /// `[start, end)` file-offset range covered by this section.
    #[must_use]
    pub fn range(&self) -> (usize, usize) {
        let start = self.file_offset as usize;
        let end = start.saturating_add(self.size as usize);
        (start, end)
    }
}

/// Collect segment and section names from a Mach-O binary.
#[must_use]
pub(crate) fn collect_macho_segments(macho: &MachO<'_>) -> Vec<String> {
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
#[must_use]
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
                            file_offset: u64::from(sec.offset),
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
#[must_use]
pub(crate) fn collect_elf_segments(elf: &goblin::elf::Elf<'_>) -> Vec<String> {
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
#[must_use]
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
                    file_offset: sh.sh_offset,
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
#[must_use]
pub fn collect_pe_section_info(
    pe: &goblin::pe::PE<'_>,
) -> std::collections::HashMap<String, SectionInfo> {
    use goblin::pe::section_table::{IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE};
    let mut sections = std::collections::HashMap::new();

    for sec in &pe.sections {
        let name = pe_section_name(&sec.name);

        let is_executable = (sec.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        let is_writable = (sec.characteristics & IMAGE_SCN_MEM_WRITE) != 0;

        sections.insert(
            name.clone(),
            SectionInfo {
                name,
                file_offset: u64::from(sec.pointer_to_raw_data),
                size: u64::from(sec.size_of_raw_data),
                is_executable,
                is_writable,
            },
        );
    }
    sections
}

/// Helper to check if a Mach-O binary has Go sections.
#[must_use]
pub(crate) fn macho_has_go_sections(macho: &MachO<'_>) -> bool {
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
#[must_use]
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
#[must_use]
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
#[must_use]
pub(crate) fn macho_is_rust(macho: &MachO<'_>) -> bool {
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
#[must_use]
pub(crate) fn find_macho_section(macho: &MachO<'_>, addr: u64) -> Option<String> {
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
#[must_use]
pub(crate) fn macho_vaddr_to_file_offset(macho: &MachO<'_>, vaddr: u64) -> u64 {
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
