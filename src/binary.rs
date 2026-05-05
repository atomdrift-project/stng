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
    ///
    /// On 32-bit targets, a file offset or size beyond `usize::MAX` is
    /// saturated — this can only happen for inputs larger than 4 GiB, which
    /// we don't support for loading into memory.
    #[must_use]
    pub fn range(&self) -> (usize, usize) {
        let start = usize::try_from(self.file_offset).unwrap_or(usize::MAX);
        let size = usize::try_from(self.size).unwrap_or(usize::MAX);
        let end = start.saturating_add(size);
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

/// File-offset ranges in a Go ELF that hold packed string blobs the raw
/// scanner must skip.
///
/// Go's compiler concatenates string contents back-to-back without null
/// terminators, relying on `{ptr, len}` headers for boundaries. A naive
/// printable-byte run scanner thus emits the entire blob as one merged
/// garbage string. The structure-based and inline-pattern extractors already
/// extract these strings with correct boundaries, so the raw scanner should
/// stay out of these regions.
#[must_use]
pub(crate) fn elf_go_skip_ranges(
    elf: &goblin::elf::Elf<'_>,
    data_len: usize,
) -> Vec<std::ops::Range<usize>> {
    elf.section_headers
        .iter()
        .filter_map(|sh| {
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
            if !matches!(name, ".rodata" | ".gopclntab") {
                return None;
            }
            let start = usize::try_from(sh.sh_offset).ok()?;
            let size = usize::try_from(sh.sh_size).ok()?;
            let end = start.checked_add(size)?.min(data_len);
            if start >= end {
                return None;
            }
            Some(start..end)
        })
        .collect()
}

/// File-offset ranges in a Go Mach-O binary the raw scanner must skip.
/// See [`elf_go_skip_ranges`] for the rationale.
#[must_use]
pub(crate) fn macho_go_skip_ranges(macho: &MachO<'_>) -> Vec<std::ops::Range<usize>> {
    let mut ranges = Vec::new();
    for seg in &macho.segments {
        let Ok(sections) = seg.sections() else {
            continue;
        };
        for (sec, _) in &sections {
            let name = sec.name().unwrap_or("");
            if !matches!(name, "__rodata" | "__gopclntab") {
                continue;
            }
            let Ok(start) = usize::try_from(sec.offset) else {
                continue;
            };
            let Ok(size) = usize::try_from(sec.size) else {
                continue;
            };
            let Some(end) = start.checked_add(size) else {
                continue;
            };
            if start < end {
                ranges.push(start..end);
            }
        }
    }
    ranges
}

/// File-offset ranges in a Go PE binary the raw scanner must skip.
/// See [`elf_go_skip_ranges`] for the rationale.
#[must_use]
pub(crate) fn pe_go_skip_ranges(
    pe: &goblin::pe::PE<'_>,
    data_len: usize,
) -> Vec<std::ops::Range<usize>> {
    pe.sections
        .iter()
        .filter_map(|sec| {
            let name = pe_section_name(&sec.name);
            // Stripped Go PE builds fold gopclntab and the string blob into
            // .rdata; cover both names for robustness. `.text` is included so
            // raw printable scans don't surface x86 instruction-byte fragments
            // (`H9A8`, `KYKZ`) or mid-string slices of pclntab funcnames
            // that the cmp-immediate dispatch code happens to embed.
            // Stack-constructed strings in `.text` are still recovered by
            // the stack-string extractor.
            if !matches!(name.as_str(), ".rodata" | ".rdata" | ".gopclntab" | ".text") {
                return None;
            }
            let start = usize::try_from(sec.pointer_to_raw_data).ok()?;
            let size = usize::try_from(sec.size_of_raw_data).ok()?;
            let end = start.checked_add(size)?.min(data_len);
            if start >= end {
                return None;
            }
            Some(start..end)
        })
        .collect()
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
        Ok(Object::PE(pe)) => pe_is_rust(&pe, data),
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

/// Check if a PE binary appears to be a Rust binary.
///
/// Unlike ELF/Mach-O, PE doesn't preserve a `.rustc` section name; the rustc
/// frontend strips toolchain metadata sections. We instead look for path
/// fragments rustc embeds verbatim in panic messages: `index.crates.io` (the
/// crates.io registry root used in dependency paths) and `/rustc/<sha>`
/// (libstd path prefix). Both are present in any non-trivial Rust PE build.
#[must_use]
pub(crate) fn pe_is_rust(pe: &goblin::pe::PE<'_>, data: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[b"index.crates.io", b"/rustc/"];
    for section in &pe.sections {
        let name = pe_section_name(&section.name);
        if !matches!(name.as_str(), ".rdata" | ".rodata") {
            continue;
        }
        let Ok(start) = usize::try_from(section.pointer_to_raw_data) else {
            continue;
        };
        let Ok(size) = usize::try_from(section.size_of_raw_data) else {
            continue;
        };
        let end = start.saturating_add(size).min(data.len());
        if start >= end {
            continue;
        }
        let bytes = &data[start..end];
        if NEEDLES
            .iter()
            .any(|n| memchr::memmem::find(bytes, n).is_some())
        {
            return true;
        }
    }
    false
}

/// File-offset ranges in a Rust PE binary the raw scanner must skip.
///
/// Rust's PE backend packs `&'static str` slices into one back-to-back blob in
/// `.rdata` (no NUL terminators), then references each substring through a
/// separate `(ptr, len)` table. Without skipping, the raw scanner sees the
/// entire blob as one long printable run and emits it as a single garbage
/// string. The structure-based extractor recovers the correctly-sliced
/// substrings.
#[must_use]
pub(crate) fn pe_rust_skip_ranges(
    pe: &goblin::pe::PE<'_>,
    data_len: usize,
) -> Vec<std::ops::Range<usize>> {
    pe.sections
        .iter()
        .filter_map(|sec| {
            let name = pe_section_name(&sec.name);
            if !matches!(name.as_str(), ".rdata" | ".rodata") {
                return None;
            }
            let start = usize::try_from(sec.pointer_to_raw_data).ok()?;
            let size = usize::try_from(sec.size_of_raw_data).ok()?;
            let end = start.checked_add(size)?.min(data_len);
            if start >= end {
                return None;
            }
            Some(start..end)
        })
        .collect()
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
