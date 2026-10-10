//! Binary format helpers and type detection.

use goblin::mach::MachO;

/// Executable-section byte ranges, sorted, with overlapping ranges merged.
///
/// XOR-obfuscated strings never live in `.text`/`__TEXT.__text` — that's
/// machine code. Skipping these ranges during XOR scanning typically drops
/// the scanned-byte count by 60-80% on normal binaries with near-zero risk
/// of missing legitimate hits.
#[must_use]
pub fn code_ranges_from_sections(sections: &[SectionInfo]) -> Vec<(usize, usize)> {
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

/// Heuristic: is this binary signed by a platform vendor (Apple, Microsoft)?
///
/// Only *platform* signatures — the chains that sign the OS itself — are
/// treated as trustworthy-enough to skip expensive pattern scans. Third-party
/// signatures (including malware that managed to get signed) are NOT matched:
///
/// - Apple: the "Software Signing" leaf issued by Apple's platform CA. Every
///   Apple chain, Developer ID included, ends in "Apple Root CA", so that name
///   proves nothing (3CX's trojanized libffmpeg carries it).
/// - Microsoft: the Windows Production PCA, which issues only Windows
///   components. Microsoft's timestamp countersignatures (rooted in "Microsoft
///   Root Certificate Authority") and WHQL-attested third-party drivers
///   ("Microsoft Windows Hardware Compatibility Publisher") do not chain to it.
///
/// Names are looked for only inside the embedded signature
/// (`signature_blobs`); anywhere else they are just bytes a sample can carry
/// to opt out of scanning. Signatures are not verified, so a binary carrying a
/// copied platform signature blob still passes.
#[must_use]
pub fn is_platform_signed(data: &[u8]) -> bool {
    signature_blobs(data).iter().any(|blob| {
        let has = |name: &[u8]| memchr::memmem::find(blob, name).is_some();
        let apple = has(b"Apple Code Signing Certification Authority")
            && has(b"Software Signing")
            && !has(b"Developer ID");
        let microsoft = has(b"Microsoft Windows Production PCA");
        apple || microsoft
    })
}

/// The code-signature data embedded in a binary: a PE's Authenticode
/// certificate table, or the `LC_CODE_SIGNATURE` blob of a Mach-O (of each
/// slice, for a universal binary). Headers are read with bounds checks, so a
/// malformed one yields fewer blobs, never a panic.
fn signature_blobs(data: &[u8]) -> Vec<&[u8]> {
    let span = |start: u64, len: u64| {
        let start = usize::try_from(start).ok()?;
        data.get(start..start.checked_add(usize::try_from(len).ok()?)?)
    };
    let bytes = |at: usize, n: usize| data.get(at..at.checked_add(n)?);
    let u16_le = |at| Some(u16::from_le_bytes(bytes(at, 2)?.try_into().ok()?));
    let u32_le = |at| Some(u32::from_le_bytes(bytes(at, 4)?.try_into().ok()?));
    let u32_be = |at| Some(u32::from_be_bytes(bytes(at, 4)?.try_into().ok()?));
    let u64_be = |at| Some(u64::from_be_bytes(bytes(at, 8)?.try_into().ok()?));

    // LC_CODE_SIGNATURE of the thin Mach-O at `base`.
    let macho = |base: usize| -> Option<&[u8]> {
        const LC_CODE_SIGNATURE: u32 = 0x1d;
        // Inside the file, so the small offsets added below cannot overflow.
        data.get(base..)?;
        let header_len = match u32_le(base)? {
            0xfeed_face => 28,
            0xfeed_facf => 32,
            _ => return None,
        };
        let ncmds = u32_le(base + 16)?;
        let mut at = base.checked_add(header_len)?;
        for _ in 0..ncmds.min(4096) {
            let (cmd, size) = (u32_le(at)?, u32_le(at + 4)?);
            if cmd == LC_CODE_SIGNATURE {
                let (offset, len) = (u32_le(at + 8)?, u32_le(at + 12)?);
                return span(base as u64 + u64::from(offset), u64::from(len));
            }
            if size < 8 {
                return None;
            }
            at = at.checked_add(usize::try_from(size).ok()?)?;
        }
        None
    };

    match data.get(..4) {
        Some([b'M', b'Z', ..]) => {
            // Authenticode: data directory 4, whose "address" is a file offset.
            let pe = usize::try_from(u32_le(0x3c).unwrap_or(0)).unwrap_or(0);
            let optional = pe + 24;
            let directories = match (data.get(pe..pe + 4), u16_le(optional)) {
                (Some(b"PE\0\0"), Some(0x10b)) => optional + 96,
                (Some(b"PE\0\0"), Some(0x20b)) => optional + 112,
                _ => return Vec::new(),
            };
            let count = u32_le(directories - 4).unwrap_or(0);
            let entry = directories + 4 * 8;
            if count <= 4 {
                return Vec::new();
            }
            match (u32_le(entry), u32_le(entry + 4)) {
                (Some(offset), Some(len)) => span(u64::from(offset), u64::from(len))
                    .into_iter()
                    .collect(),
                _ => Vec::new(),
            }
        }
        Some([0xca, 0xfe, 0xba, 0xbe | 0xbf]) => {
            // Universal binary: big-endian slice table (64-bit offsets for 0xcafebabf).
            let wide = data[3] == 0xbf;
            let entry_len = if wide { 32 } else { 20 };
            let slices = u32_be(4).unwrap_or(0).min(64) as usize;
            (0..slices)
                .filter_map(|i| {
                    let entry = 8 + i * entry_len;
                    let offset = if wide {
                        u64_be(entry + 8)?
                    } else {
                        u64::from(u32_be(entry + 8)?)
                    };
                    macho(usize::try_from(offset).ok()?)
                })
                .collect()
        }
        _ => macho(0).into_iter().collect(),
    }
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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SectionInfo {
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
    pub fn range(&self) -> (usize, usize) {
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
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(walk))
        .ok()?
        .ok()
}

/// The most imports a Mach-O's bind streams may declare before
/// [`macho_imports`] declines to hand them to goblin.
const MAX_MACHO_BIND_IMPORTS: u64 = 256 * 1024;

/// `macho.imports()`, contained like [`contain`] -- unless the bind streams
/// in `slice`, the bytes `macho` was parsed from, would have goblin build more
/// than [`MAX_MACHO_BIND_IMPORTS`] imports. goblin builds one `Import` per
/// binding, and a single `DO_BIND_ULEB_TIMES_SKIPPING_ULEB` with a forged
/// repeat count asks for billions: gigabytes in seconds, which no panic guard
/// stops.
pub(crate) fn macho_imports<'m>(
    macho: &'m MachO<'_>,
    slice: &[u8],
) -> Option<Vec<goblin::mach::imports::Import<'m>>> {
    if macho_bind_count(macho, slice) > MAX_MACHO_BIND_IMPORTS {
        return None;
    }
    contain(|| macho.imports())
}

/// The bindings `macho`'s bind and lazy-bind streams declare, as goblin's
/// interpreter would count them, up to just past [`MAX_MACHO_BIND_IMPORTS`].
fn macho_bind_count(macho: &MachO<'_>, slice: &[u8]) -> u64 {
    use goblin::mach::load_command::CommandVariant;

    let mut count = 0u64;
    for lc in &macho.load_commands {
        let (CommandVariant::DyldInfo(info) | CommandVariant::DyldInfoOnly(info)) = &lc.command
        else {
            continue;
        };
        let streams = [
            (info.bind_off, info.bind_size),
            (info.lazy_bind_off, info.lazy_bind_size),
        ];
        for (off, size) in streams {
            let stream = file_range_clamped(slice, off.into(), size.into()).unwrap_or_default();
            count = bind_stream_count(stream, count);
            if count > MAX_MACHO_BIND_IMPORTS {
                return count;
            }
        }
    }
    count
}

/// `count` plus the bindings one bind-opcode `stream` declares, stopping
/// once the total passes [`MAX_MACHO_BIND_IMPORTS`].
fn bind_stream_count(stream: &[u8], mut count: u64) -> u64 {
    use goblin::mach::bind_opcodes::{
        BIND_OPCODE_ADD_ADDR_ULEB, BIND_OPCODE_DO_BIND, BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED,
        BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB, BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB,
        BIND_OPCODE_MASK, BIND_OPCODE_SET_ADDEND_SLEB, BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB,
        BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB, BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM,
    };
    let mut at = 0;
    while let Some(&opcode) = stream.get(at) {
        at += 1;
        let read = match opcode & BIND_OPCODE_MASK {
            BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB
            | BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB
            | BIND_OPCODE_ADD_ADDR_ULEB
            | BIND_OPCODE_SET_ADDEND_SLEB => leb128(stream, &mut at).map(|_| ()),
            BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM => stream
                .get(at..)
                .and_then(|rest| rest.iter().position(|&b| b == 0))
                .map(|len| at += len + 1),
            BIND_OPCODE_DO_BIND | BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED => {
                count += 1;
                Some(())
            }
            BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB => {
                count += 1;
                leb128(stream, &mut at).map(|_| ())
            }
            BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB => {
                leb128(stream, &mut at).and_then(|times| {
                    leb128(stream, &mut at)?;
                    count = count.saturating_add(times);
                    Some(())
                })
            }
            _ => Some(()),
        };
        // A truncated operand ends goblin's walk too.
        if read.is_none() || count > MAX_MACHO_BIND_IMPORTS {
            break;
        }
    }
    count
}

/// A LEB128 value at `*at`, advancing past it. Signed and unsigned values
/// share the framing; bits past 64 are dropped, as goblin's reader drops them.
fn leb128(bytes: &[u8], at: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *bytes.get(*at)?;
        *at += 1;
        if shift < 64 {
            value |= u64::from(byte & 0x7f) << shift;
        }
        shift = shift.saturating_add(7);
        if byte & 0x80 == 0 {
            return Some(value);
        }
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

/// Section metadata of a Mach-O binary, in load-command order. Names repeat
/// across segments (`__TEXT,__const` and `__DATA_CONST,__const`), so this is a
/// list, not a map keyed by name.
#[must_use]
pub fn collect_macho_section_info(macho: &MachO<'_>) -> Vec<SectionInfo> {
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
pub fn collect_elf_section_info(elf: &goblin::elf::Elf<'_>) -> Vec<SectionInfo> {
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
pub fn collect_pe_section_info(pe: &goblin::pe::PE<'_>) -> Vec<SectionInfo> {
    use goblin::pe::section_table::{IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE};
    let mut sections = Vec::new();

    for sec in &pe.sections {
        let name = pe_section_name(&sec.name);

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
        Ok(Object::Elf(elf)) => elf_is_rust(&elf, data),
        Ok(Object::PE(pe)) => pe_is_rust(&pe, data),
        _ => false,
    }
}

/// Path fragments rustc embeds verbatim in panic locations, stripped or not:
/// the crates.io registry root in dependency paths, the `/rustc/<sha>` libstd
/// prefix of rustup toolchains, and the standard library's own source paths.
/// The last matter for distro toolchains, which remap the prefix away (Arch
/// ships `library/std/src/...` bare, or under `/usr/src/debug/rust/rustc-*`),
/// so a dependency-free program from one carries neither of the first two.
const RUST_CONTENT_NEEDLES: &[&[u8]] = &[
    b"index.crates.io",
    b"/rustc/",
    b"library/std/src/",
    b"library/core/src/",
];

/// Whether `bytes` carries one of [`RUST_CONTENT_NEEDLES`].
fn has_rust_content(bytes: &[u8]) -> bool {
    RUST_CONTENT_NEEDLES
        .iter()
        .any(|n| memchr::memmem::find(bytes, n).is_some())
}

/// Check if a Mach-O binary appears to be a Rust binary.
///
/// A `rust`-named section marks a dylib or proc-macro that carries rustc
/// metadata; an ordinary executable has none. Those are recognised by the
/// panic-location paths in `__TEXT` read-only data instead, as on PE.
#[must_use]
pub(crate) fn macho_is_rust(macho: &MachO<'_>) -> bool {
    let mut rodata = Vec::new();
    for seg in &macho.segments {
        let Ok(secs) = seg.sections() else { continue };
        for (sec, bytes) in secs {
            let name = sec.name().unwrap_or("");
            if name.contains("rust") {
                return true;
            }
            if matches!(name, "__const" | "__cstring") && seg.name().ok() == Some("__TEXT") {
                rodata.push(bytes);
            }
        }
    }
    rodata.into_iter().any(has_rust_content)
}

/// Check if an ELF binary appears to be a Rust binary.
///
/// As for Mach-O: a `rust`-named section (`.rustc`) only exists in dylibs and
/// proc-macros, so an ordinary Rust executable -- stripped or not -- is
/// recognised by the panic-location paths in `.rodata`. Section-name-only
/// detection sent every Rust executable down the unknown-ELF path, so its
/// `&str` literals were never sliced out of rustc's packed string blob.
#[must_use]
pub(crate) fn elf_is_rust(elf: &goblin::elf::Elf<'_>, data: &[u8]) -> bool {
    let mut rodata = None;
    for sh in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
        if name.contains("rust") {
            return true;
        }
        if name == ".rodata" {
            rodata = Some(sh);
        }
    }
    rodata.is_some_and(|sh| {
        let (Ok(start), Ok(size)) = (usize::try_from(sh.sh_offset), usize::try_from(sh.sh_size))
        else {
            return false;
        };
        data.get(start..start.saturating_add(size).min(data.len()))
            .is_some_and(has_rust_content)
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
        if has_rust_content(&data[start..end]) {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A forged repeat count is counted, not replayed: symbol `_a`, then
    /// `DO_BIND_ULEB_TIMES_SKIPPING_ULEB` with a count of 2^32 - 1, which
    /// goblin's interpreter would turn into that many `Import`s.
    #[test]
    fn a_forged_bind_repeat_count_passes_the_cap() {
        let stream = [
            0x11, 0x40, b'_', b'a', 0x00, 0x70, 0x00, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F, 0x00,
            0x00,
        ];
        assert!(bind_stream_count(&stream, 0) > MAX_MACHO_BIND_IMPORTS);
    }

    /// Ordinary binds are counted one by one, across operand-bearing opcodes.
    #[test]
    fn ordinary_binds_are_counted() {
        let stream = [
            0x11, // SET_DYLIB_ORDINAL_IMM 1
            0x40, b'_', b'a', 0x00, // SET_SYMBOL_TRAILING_FLAGS_IMM "_a"
            0x72, 0x10, // SET_SEGMENT_AND_OFFSET_ULEB seg 2, offset 16
            0x90, // DO_BIND
            0xA0, 0x08, // DO_BIND_ADD_ADDR_ULEB 8
            0xB1, // DO_BIND_ADD_ADDR_IMM_SCALED
            0xC0, 0x03, 0x08, // DO_BIND_ULEB_TIMES_SKIPPING_ULEB 3, skip 8
            0x00, // DONE
        ];
        assert_eq!(bind_stream_count(&stream, 0), 6);
        // A truncated operand ends the walk, as it ends goblin's.
        assert_eq!(bind_stream_count(&stream[..9], 0), 2);
    }

    const CA: &[u8] = b"Microsoft Windows Production PCA 2011";

    fn put(data: &mut [u8], at: usize, bytes: &[u8]) {
        data[at..at + bytes.len()].copy_from_slice(bytes);
    }

    /// A PE32+ header whose certificate table covers `[0x300, 0x400)`.
    fn pe() -> Vec<u8> {
        let mut data = vec![0u8; 0x400];
        put(&mut data, 0, b"MZ");
        put(&mut data, 0x3c, &0x80u32.to_le_bytes());
        put(&mut data, 0x80, b"PE\0\0");
        let optional = 0x80 + 24;
        put(&mut data, optional, &0x20bu16.to_le_bytes());
        put(&mut data, optional + 108, &16u32.to_le_bytes());
        put(&mut data, optional + 112 + 32, &0x300u32.to_le_bytes());
        put(&mut data, optional + 112 + 36, &0x100u32.to_le_bytes());
        data
    }

    /// A 64-bit Mach-O whose LC_CODE_SIGNATURE covers `[0x200, 0x300)`.
    fn macho() -> Vec<u8> {
        let mut data = vec![0u8; 0x300];
        put(&mut data, 0, &0xfeed_facfu32.to_le_bytes());
        put(&mut data, 16, &1u32.to_le_bytes());
        for (i, word) in [0x1du32, 16, 0x200, 0x100].iter().enumerate() {
            put(&mut data, 32 + 4 * i, &word.to_le_bytes());
        }
        data
    }

    #[test]
    fn platform_ca_counts_only_inside_the_signature() {
        let mut signed = pe();
        put(&mut signed, 0x320, CA);
        assert!(is_platform_signed(&signed));
        let mut planted = pe();
        put(&mut planted, 0x200, CA);
        assert!(
            !is_platform_signed(&planted),
            "CA name outside the certificate table"
        );

        let mut signed = macho();
        put(&mut signed, 0x210, CA);
        assert!(is_platform_signed(&signed));
        let mut planted = macho();
        put(&mut planted, 0x100, CA);
        assert!(
            !is_platform_signed(&planted),
            "CA name outside LC_CODE_SIGNATURE"
        );

        // Universal binary: one slice at 0x1000, its blob relative to the slice.
        let mut fat = vec![0u8; 0x1000];
        put(&mut fat, 0, &0xcafe_babeu32.to_be_bytes());
        put(&mut fat, 4, &1u32.to_be_bytes());
        put(&mut fat, 8 + 8, &0x1000u32.to_be_bytes());
        put(&mut fat, 8 + 12, &0x300u32.to_be_bytes());
        fat.extend(signed);
        assert!(is_platform_signed(&fat));
        assert!(!is_platform_signed(CA));
    }

    #[test]
    fn third_party_chains_are_not_platform() {
        let signed_with = |names: &[&[u8]]| {
            let mut data = macho();
            let mut at = 0x200;
            for name in names {
                put(&mut data, at, name);
                at += name.len() + 1;
            }
            is_platform_signed(&data)
        };
        let platform: &[&[u8]] = &[
            b"Software Signing",
            b"Apple Code Signing Certification Authority",
            b"Apple Root CA",
        ];
        assert!(signed_with(platform));
        // 3CX's trojanized libffmpeg: a Developer ID chain to the same root.
        assert!(!signed_with(&[
            b"Developer ID Application: 3CX (33CF4654HL)",
            b"Developer ID Certification Authority",
            b"Apple Root CA",
        ]));

        let authenticode_with = |names: &[&[u8]]| {
            let mut data = pe();
            let mut at = 0x300;
            for name in names {
                put(&mut data, at, name);
                at += name.len() + 1;
            }
            is_platform_signed(&data)
        };
        // A vendor signature with a Microsoft timestamp countersignature.
        assert!(!authenticode_with(&[
            b"Microsoft Time-Stamp PCA 2010",
            b"Microsoft Root Certificate Authority 2010",
        ]));
        // A WHQL-attested third-party driver.
        assert!(!authenticode_with(&[
            b"Microsoft Windows Hardware Compatibility Publisher",
            b"Microsoft Windows Third Party Component CA 2014",
        ]));
    }

    #[test]
    fn signature_walk_survives_hostile_headers() {
        let mut data = macho();
        put(&mut data, 16, &u32::MAX.to_le_bytes()); // ncmds
        put(&mut data, 32 + 4, &0u32.to_le_bytes()); // cmdsize 0
        put(&mut data, 32, &0x19u32.to_le_bytes());
        assert!(!is_platform_signed(&data));
        let mut data = pe();
        put(&mut data, 0x3c, &u32::MAX.to_le_bytes());
        assert!(!is_platform_signed(&data));
        let mut fat = vec![0u8; 64];
        put(&mut fat, 0, &0xcafe_babfu32.to_be_bytes());
        put(&mut fat, 4, &u32::MAX.to_be_bytes());
        put(&mut fat, 8 + 8, &u64::MAX.to_be_bytes());
        assert!(!is_platform_signed(&fat));
    }
}
