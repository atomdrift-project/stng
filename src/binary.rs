//! Binary format helpers and type detection.

mod bind;
mod language;
mod signature;

pub(crate) use bind::macho_imports;
pub(crate) use language::{
    elf_go_skip_ranges, elf_is_rust, macho_go_skip_ranges, macho_has_go_sections, macho_is_rust,
    pe_go_skip_ranges, pe_is_rust, pe_rust_skip_ranges,
};
pub use language::{is_go_binary, is_rust_binary};
pub(crate) use signature::is_platform_signed;

use goblin::mach::MachO;

/// Executable-section byte ranges, sorted, with overlapping ranges merged.
///
/// XOR-obfuscated strings never live in `.text`/`__TEXT.__text` — that's
/// machine code. Skipping these ranges during XOR scanning typically drops
/// the scanned-byte count by 60-80% on normal binaries with near-zero risk
/// of missing legitimate hits.
#[must_use]
pub(crate) fn code_ranges_from_sections(sections: &[SectionInfo]) -> Vec<(usize, usize)> {
    merge_overlapping(
        sections
            .iter()
            .filter(|s| s.is_executable && s.size > 0)
            .map(SectionInfo::range)
            .collect(),
    )
}

/// `ranges` sorted, with any that overlap merged into one; adjacent ranges
/// stay apart. Section headers can declare the same code thousands of times,
/// and each scan of a copy decoded it all again.
pub(crate) fn merge_overlapping(mut ranges: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    ranges.retain(|&(start, end)| end > start);
    ranges.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if start < last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}

/// `data[offset..offset + size]` when that range lies wholly in `data`.
/// Offsets and sizes come from file headers; this and [`file_range_clamped`]
/// are where they become slices.
pub(crate) fn file_range(data: &[u8], offset: u64, size: u64) -> Option<&[u8]> {
    let start = usize::try_from(offset).ok()?;
    data.get(start..start.checked_add(usize::try_from(size).ok()?)?)
}

/// The part of `data[offset..offset + size]` the file actually holds, cut at
/// the end of `data` as in a truncated sample. `None` when nothing remains.
pub(crate) fn file_range_clamped(data: &[u8], offset: u64, size: u64) -> Option<&[u8]> {
    let start = usize::try_from(offset).ok()?;
    let size = usize::try_from(size).unwrap_or(usize::MAX);
    let end = start.saturating_add(size).min(data.len());
    (start < end).then(|| &data[start..end])
}

/// The first ELF section named `name`: its virtual address and bytes, when
/// they lie wholly in `data`.
pub(crate) fn elf_section<'a>(
    elf: &goblin::elf::Elf<'_>,
    data: &'a [u8],
    name: &str,
) -> Option<(u64, &'a [u8])> {
    let sh = elf
        .section_headers
        .iter()
        .find(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(name))?;
    Some((sh.sh_addr, file_range(data, sh.sh_offset, sh.sh_size)?))
}

/// A PE section name, up to its first NUL. Borrowed unless the name is not
/// UTF-8, which only a malformed binary has.
pub(crate) fn pe_section_name(name: &[u8; 8]) -> std::borrow::Cow<'_, str> {
    let end = name.iter().position(|&b| b == 0).unwrap_or(8);
    String::from_utf8_lossy(&name[..end])
}

/// Section metadata including name, size, type, and byte range.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct SectionInfo {
    /// Section name as the header gives it (`.text`, `__cstring`, …).
    pub name: String,
    /// File offset of section payload (where raw bytes begin).
    pub file_offset: u64,
    /// Size in bytes, as the section header records it.
    pub size: u64,
    /// Holds machine code.
    pub is_executable: bool,
    /// Writable at run time.
    pub is_writable: bool,
}

impl SectionInfo {
    /// `[start, end)` file-offset range covered by this section.
    ///
    /// On 32-bit targets, a file offset or size beyond `usize::MAX` is
    /// saturated — this can only happen for inputs larger than 4 GiB, which
    /// we don't support for loading into memory.
    #[must_use]
    pub(crate) fn range(&self) -> (usize, usize) {
        let start = usize::try_from(self.file_offset).unwrap_or(usize::MAX);
        let size = usize::try_from(self.size).unwrap_or(usize::MAX);
        let end = start.saturating_add(size);
        (start, end)
    }
}

/// Run one of goblin's lazy walks, treating a panic as a parse failure.
///
/// goblin's Mach-O bind-opcode interpreter (`MachO::imports`, goblin 0.10
/// `mach/imports.rs`) indexes the segment and dylib tables with ordinals read
/// from the file, so a crafted binary panics it. A hostile file should cost
/// its imports, not the whole extraction. This is stng's only `catch_unwind`:
/// confine it to third-party walks we cannot bound ourselves.
pub(crate) fn contain<T, E>(walk: impl FnOnce() -> Result<T, E>) -> Option<T> {
    let Ok(result) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(walk)) else {
        tracing::warn!("goblin panicked on a malformed table; skipping it");
        return None;
    };
    result.ok()
}

/// Every section of `macho` with its bytes, across all segments. Segments
/// whose section table does not parse contribute nothing.
pub(crate) fn macho_sections<'m, 'a>(
    macho: &'m MachO<'a>,
) -> impl Iterator<Item = (goblin::mach::segment::Section, &'a [u8])> + 'm {
    macho
        .segments
        .iter()
        .filter_map(|segment| segment.sections().ok())
        .flatten()
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

/// Section metadata of a Mach-O binary, in load-command order. Names repeat
/// across segments (`__TEXT,__const` and `__DATA_CONST,__const`), so this is a
/// list, not a map keyed by name.
#[must_use]
pub(crate) fn collect_macho_section_info(macho: &MachO<'_>) -> Vec<SectionInfo> {
    use goblin::mach::constants::S_ATTR_SOME_INSTRUCTIONS;
    let mut sections = Vec::new();

    for seg in &macho.segments {
        if let Ok(secs) = seg.sections() {
            for (sec, _) in secs {
                if let Ok(name) = sec.name() {
                    let is_executable = (sec.flags & S_ATTR_SOME_INSTRUCTIONS) != 0;
                    let is_writable = seg.initprot & 0x2 != 0; // VM_PROT_WRITE

                    sections.push(SectionInfo {
                        name: name.to_string(),
                        file_offset: u64::from(sec.offset),
                        size: sec.size,
                        is_executable,
                        is_writable,
                    });
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

/// Section metadata of an ELF binary, in section-header order.
#[must_use]
pub(crate) fn collect_elf_section_info(elf: &goblin::elf::Elf<'_>) -> Vec<SectionInfo> {
    use goblin::elf::section_header::{SHF_EXECINSTR, SHF_WRITE};
    let mut sections = Vec::new();

    for sh in &elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
            let is_executable = (sh.sh_flags & u64::from(SHF_EXECINSTR)) != 0;
            let is_writable = (sh.sh_flags & u64::from(SHF_WRITE)) != 0;

            sections.push(SectionInfo {
                name: name.to_string(),
                file_offset: sh.sh_offset,
                size: sh.sh_size,
                is_executable,
                is_writable,
            });
        }
    }
    sections
}

/// Section metadata of a PE binary, in section-table order.
#[must_use]
pub(crate) fn collect_pe_section_info(pe: &goblin::pe::PE<'_>) -> Vec<SectionInfo> {
    use goblin::pe::section_table::{IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE};
    let mut sections = Vec::new();

    for sec in &pe.sections {
        let name = pe_section_name(&sec.name).into_owned();

        let is_executable = (sec.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        let is_writable = (sec.characteristics & IMAGE_SCN_MEM_WRITE) != 0;

        sections.push(SectionInfo {
            name,
            file_offset: u64::from(sec.pointer_to_raw_data),
            size: u64::from(sec.size_of_raw_data),
            is_executable,
            is_writable,
        });
    }
    sections
}

/// Convert a virtual address to a file offset for ELF binaries.
///
/// The ELF counterpart of [`macho_vaddr_to_file_offset`]: finds the `PT_LOAD`
/// segment whose file-backed range holds `vaddr` and rebases it. Extractors
/// that decode pointers — Go string headers, `ADRP`/`LEA` targets — work in
/// virtual addresses; left unconverted they report a string at an address that
/// is off by the load bias (0x400000 for a non-PIE amd64 Go binary, 0x10000
/// for arm64), pointing at unrelated bytes or past the end of the file.
/// Addresses in no segment's file image (`.bss`, or no program headers at
/// all) are returned unchanged, as the Mach-O helper does.
#[must_use]
pub(crate) fn elf_vaddr_to_file_offset(elf: &goblin::elf::Elf<'_>, vaddr: u64) -> u64 {
    elf.program_headers
        .iter()
        .filter(|ph| ph.p_type == goblin::elf::program_header::PT_LOAD)
        .find(|ph| vaddr >= ph.p_vaddr && vaddr - ph.p_vaddr < ph.p_filesz)
        .map_or(vaddr, |ph| (vaddr - ph.p_vaddr).saturating_add(ph.p_offset))
}

/// Convert virtual address to file offset for Mach-O binaries.
#[must_use]
pub(crate) fn macho_vaddr_to_file_offset(macho: &MachO<'_>, vaddr: u64) -> u64 {
    // Segment fields are the file's to choose, so no sum of them is trusted
    // not to wrap.
    for seg in &macho.segments {
        if let Some(delta) = vaddr.checked_sub(seg.vmaddr)
            && delta < seg.vmsize
        {
            // file_offset = (virtual_address - segment_vmaddr) + segment_fileoff
            return delta.saturating_add(seg.fileoff);
        }
    }

    // If not found in any segment, return the vaddr as-is
    vaddr
}
