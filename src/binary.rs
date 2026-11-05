//! Binary format helpers and type detection.

mod language;
mod signature;

pub(crate) use language::{
    elf_go_skip_ranges, elf_has_go_sections, elf_is_rust, macho_go_skip_ranges,
    macho_has_go_sections, macho_is_rust, pe_go_skip_ranges, pe_is_rust, pe_rust_skip_ranges,
};
pub use language::{is_go_binary, is_rust_binary};
pub(crate) use signature::is_platform_signed;

use goblin::mach::MachO;
use std::ops::Range;

/// Executable-section byte ranges, sorted, with overlapping ranges merged.
///
/// XOR-obfuscated strings live in data, not in `.text`/`__TEXT.__text`, which
/// is machine code, so XOR scanning skips these ranges: on most binaries the
/// bulk of the file.
#[must_use]
pub(crate) fn code_ranges_from_sections(sections: &[SectionInfo]) -> Vec<Range<usize>> {
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
pub(crate) fn merge_overlapping(mut ranges: Vec<Range<usize>>) -> Vec<Range<usize>> {
    ranges.retain(|r| !r.is_empty());
    ranges.sort_unstable_by_key(|r| (r.start, r.end));
    let mut merged: Vec<Range<usize>> = Vec::with_capacity(ranges.len());
    for range in ranges {
        match merged.last_mut() {
            Some(last) if range.start < last.end => last.end = last.end.max(range.end),
            _ => merged.push(range),
        }
    }
    merged
}

/// Byte ranges, sorted and disjoint, for membership tests. Built in
/// `O(n log n)`; a lookup is a binary search, since a binary can declare
/// tens of thousands of ranges.
#[derive(Debug, Default)]
pub(crate) struct RangeSet(Vec<Range<usize>>);

impl RangeSet {
    /// The union of `[start, end)` ranges; empty ones are dropped.
    pub(crate) fn new(ranges: impl IntoIterator<Item = Range<usize>>) -> Self {
        Self(merge_overlapping(ranges.into_iter().collect()))
    }

    pub(crate) fn contains(&self, offset: usize) -> bool {
        let i = self.0.partition_point(|r| r.start <= offset);
        i > 0 && offset < self.0[i - 1].end
    }
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
    clamped_range(data.len(), offset, size).map(|r| &data[r])
}

/// The part of `offset..offset + size` a file of `len` bytes holds; `None`
/// when nothing remains. See [`file_range_clamped`].
pub(crate) fn clamped_range(len: usize, offset: u64, size: u64) -> Option<Range<usize>> {
    let start = usize::try_from(offset).ok()?;
    let size = usize::try_from(size).unwrap_or(usize::MAX);
    let end = start.saturating_add(size).min(len);
    (start < end).then_some(start..end)
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
    /// File-offset range covered by this section, saturated
    /// at `usize::MAX` for header values past the end of any loadable file.
    #[must_use]
    pub(crate) fn range(&self) -> Range<usize> {
        let start = usize::try_from(self.file_offset).unwrap_or(usize::MAX);
        let size = usize::try_from(self.size).unwrap_or(usize::MAX);
        start..start.saturating_add(size)
    }
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

/// Segment and section names of a Mach-O binary: each segment's name, then
/// its sections'.
#[must_use]
pub(crate) fn macho_section_names(macho: &MachO<'_>) -> Vec<String> {
    let mut names = Vec::new();
    for seg in &macho.segments {
        names.extend(seg.name().ok().map(str::to_string));
        if let Ok(sections) = seg.sections() {
            names.extend(
                sections
                    .iter()
                    .filter_map(|(sec, _)| sec.name().ok().map(str::to_string)),
            );
        }
    }
    names
}

/// Section metadata of a Mach-O binary, in load-command order. Names repeat
/// across segments (`__TEXT,__const` and `__DATA_CONST,__const`), so this is a
/// list, not a map keyed by name.
#[must_use]
pub(crate) fn collect_macho_section_info(macho: &MachO<'_>) -> Vec<SectionInfo> {
    use goblin::mach::constants::S_ATTR_SOME_INSTRUCTIONS;
    const VM_PROT_WRITE: u32 = 0x2;
    macho
        .segments
        .iter()
        .flat_map(|seg| {
            let is_writable = seg.initprot & VM_PROT_WRITE != 0;
            seg.sections()
                .into_iter()
                .flatten()
                .filter_map(move |(sec, _)| {
                    Some(SectionInfo {
                        name: sec.name().ok()?.to_string(),
                        file_offset: u64::from(sec.offset),
                        size: sec.size,
                        is_executable: sec.flags & S_ATTR_SOME_INSTRUCTIONS != 0,
                        is_writable,
                    })
                })
        })
        .collect()
}

/// Section names of an ELF binary, in section-header order.
#[must_use]
pub(crate) fn elf_section_names(elf: &goblin::elf::Elf<'_>) -> Vec<String> {
    elf.section_headers
        .iter()
        .filter_map(|sh| elf.shdr_strtab.get_at(sh.sh_name).map(str::to_string))
        .collect()
}

/// Section metadata of an ELF binary, in section-header order.
#[must_use]
pub(crate) fn collect_elf_section_info(elf: &goblin::elf::Elf<'_>) -> Vec<SectionInfo> {
    use goblin::elf::section_header::{SHF_EXECINSTR, SHF_WRITE};
    elf.section_headers
        .iter()
        .filter_map(|sh| {
            Some(SectionInfo {
                name: elf.shdr_strtab.get_at(sh.sh_name)?.to_string(),
                file_offset: sh.sh_offset,
                size: sh.sh_size,
                is_executable: sh.sh_flags & u64::from(SHF_EXECINSTR) != 0,
                is_writable: sh.sh_flags & u64::from(SHF_WRITE) != 0,
            })
        })
        .collect()
}

/// Section metadata of a PE binary, in section-table order.
#[must_use]
pub(crate) fn collect_pe_section_info(pe: &goblin::pe::PE<'_>) -> Vec<SectionInfo> {
    use goblin::pe::section_table::{IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE};
    pe.sections
        .iter()
        .map(|sec| SectionInfo {
            name: pe_section_name(&sec.name).into_owned(),
            file_offset: u64::from(sec.pointer_to_raw_data),
            size: u64::from(sec.size_of_raw_data),
            is_executable: sec.characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
            is_writable: sec.characteristics & IMAGE_SCN_MEM_WRITE != 0,
        })
        .collect()
}

/// Convert a virtual address to a file offset for ELF binaries.
///
/// The ELF counterpart of [`macho_vaddr_to_file_offset`]: finds the `PT_LOAD`
/// segment whose file-backed range holds `vaddr` and rebases it. Extractors
/// that decode pointers — Go string headers, `ADRP`/`LEA` targets — work in
/// virtual addresses; left unconverted they report a string at an address that
/// is off by the load bias (0x400000 for a non-PIE amd64 Go binary, 0x10000
/// for arm64), pointing at unrelated bytes or past the end of the file.
/// `None` for an address in no segment's file image (`.bss`, or no program
/// headers at all): there are no bytes in the file to point at.
#[must_use]
pub(crate) fn elf_vaddr_to_file_offset(elf: &goblin::elf::Elf<'_>, vaddr: u64) -> Option<u64> {
    elf.program_headers
        .iter()
        .filter(|ph| ph.p_type == goblin::elf::program_header::PT_LOAD)
        .find(|ph| vaddr >= ph.p_vaddr && vaddr - ph.p_vaddr < ph.p_filesz)
        .map(|ph| (vaddr - ph.p_vaddr).saturating_add(ph.p_offset))
}

/// The file offset of virtual address `vaddr` in a Mach-O, or `None` when
/// no segment's file-backed part (`filesize`, not `vmsize`) holds it.
#[must_use]
pub(crate) fn macho_vaddr_to_file_offset(macho: &MachO<'_>, vaddr: u64) -> Option<u64> {
    // Segment fields are the file's to choose, so no sum of them is trusted
    // not to wrap.
    macho.segments.iter().find_map(|seg| {
        let delta = vaddr.checked_sub(seg.vmaddr)?;
        (delta < seg.filesize).then(|| delta.saturating_add(seg.fileoff))
    })
}
