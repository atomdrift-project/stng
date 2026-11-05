//! Go and Rust detection by section names and content, and the packed
//! string sections a raw scan must skip.

use super::{clamped_range, file_range_clamped, macho_sections, pe_section_name};
use goblin::mach::MachO;
use std::ops::Range;

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
pub(crate) fn elf_go_skip_ranges(elf: &goblin::elf::Elf<'_>, data_len: usize) -> Vec<Range<usize>> {
    elf.section_headers
        .iter()
        .filter(|sh| {
            matches!(
                elf.shdr_strtab.get_at(sh.sh_name),
                Some(".rodata" | ".gopclntab")
            )
        })
        .filter_map(|sh| clamped_range(data_len, sh.sh_offset, sh.sh_size))
        .collect()
}

/// File-offset ranges in a Go Mach-O binary the raw scanner must skip.
/// See [`elf_go_skip_ranges`] for the rationale.
#[must_use]
pub(crate) fn macho_go_skip_ranges(macho: &MachO<'_>) -> Vec<Range<usize>> {
    macho_sections(macho)
        .filter(|(sec, _)| matches!(sec.name(), Ok("__rodata" | "__gopclntab")))
        .filter_map(|(sec, _)| clamped_range(usize::MAX, u64::from(sec.offset), sec.size))
        .collect()
}

/// File-offset ranges in a Go PE binary the raw scanner must skip.
/// See [`elf_go_skip_ranges`] for the rationale.
///
/// Stripped Go PE builds fold gopclntab and the string blob into `.rdata`;
/// both names are covered for robustness. `.text` is included so raw
/// printable scans don't surface x86 instruction-byte fragments (`H9A8`,
/// `KYKZ`) or mid-string slices of pclntab funcnames that the cmp-immediate
/// dispatch code happens to embed. Stack-constructed strings in `.text` are
/// still recovered by the stack-string extractor.
#[must_use]
pub(crate) fn pe_go_skip_ranges(pe: &goblin::pe::PE<'_>, data_len: usize) -> Vec<Range<usize>> {
    pe_section_ranges(pe, data_len, &[".rodata", ".rdata", ".gopclntab", ".text"]).collect()
}

/// File-offset ranges of `pe`'s sections named in `names`, cut at `data_len`.
fn pe_section_ranges<'p>(
    pe: &'p goblin::pe::PE<'_>,
    data_len: usize,
    names: &'p [&str],
) -> impl Iterator<Item = Range<usize>> + 'p {
    pe.sections
        .iter()
        .filter(|sec| names.contains(&&*pe_section_name(&sec.name)))
        .filter_map(move |sec| {
            clamped_range(
                data_len,
                u64::from(sec.pointer_to_raw_data),
                u64::from(sec.size_of_raw_data),
            )
        })
}

/// Whether an ELF binary has Go's `.gopclntab` or `.go.buildinfo` section.
#[must_use]
pub(crate) fn elf_has_go_sections(elf: &goblin::elf::Elf<'_>) -> bool {
    elf.section_headers.iter().any(|sh| {
        matches!(
            elf.shdr_strtab.get_at(sh.sh_name),
            Some(".gopclntab" | ".go.buildinfo")
        )
    })
}

/// Whether a PE carries Go's build information header, 16-byte aligned in a
/// section, where Go's own `debug/buildinfo` looks for it. Section names are
/// optional (a stripped build folds `.gopclntab` into `.rdata`); the header
/// is not, and a pointer size of 4 or 8 must follow its magic.
fn pe_has_go_buildinfo(pe: &goblin::pe::PE<'_>, data: &[u8]) -> bool {
    const MAGIC: &[u8] = b"\xff Go buildinf:";
    pe.sections
        .iter()
        .filter_map(|sec| {
            file_range_clamped(
                data,
                u64::from(sec.pointer_to_raw_data),
                u64::from(sec.size_of_raw_data),
            )
        })
        .any(|bytes| {
            // 16 bytes: the magic, the pointer size, then flags.
            bytes
                .as_chunks::<16>()
                .0
                .iter()
                .any(|header| header.starts_with(MAGIC) && matches!(header[14], 4 | 8))
        })
}

/// Whether a Mach-O binary has Go's `__gopclntab` or `__go_buildinfo` section.
#[must_use]
pub(crate) fn macho_has_go_sections(macho: &MachO<'_>) -> bool {
    macho_sections(macho).any(|(sec, _)| matches!(sec.name(), Ok("__gopclntab" | "__go_buildinfo")))
}

/// Check if a binary is a Go binary by looking for Go-specific sections.
#[must_use]
pub fn is_go_binary(data: &[u8]) -> bool {
    use goblin::Object;
    match Object::parse(data) {
        Ok(Object::Mach(goblin::mach::Mach::Binary(macho))) => macho_has_go_sections(&macho),
        Ok(Object::Elf(elf)) => elf_has_go_sections(&elf),
        Ok(Object::PE(pe)) => pe_has_go_buildinfo(&pe, data),
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
pub(super) const RUST_CONTENT_NEEDLES: &[&[u8]] = &[
    b"index.crates.io",
    b"/rustc/",
    b"library/std/src/",
    b"library/core/src/",
];

/// Whether `bytes` carries one of [`RUST_CONTENT_NEEDLES`].
pub(super) fn has_rust_content(bytes: &[u8]) -> bool {
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
        file_range_clamped(data, sh.sh_offset, sh.sh_size).is_some_and(has_rust_content)
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
    pe_section_ranges(pe, data.len(), PE_RODATA).any(|r| has_rust_content(&data[r]))
}

/// The PE sections that hold read-only data.
const PE_RODATA: &[&str] = &[".rdata", ".rodata"];

/// File-offset ranges in a Rust PE binary the raw scanner must skip.
///
/// Rust's PE backend packs `&'static str` slices into one back-to-back blob in
/// `.rdata` (no NUL terminators), then references each substring through a
/// separate `(ptr, len)` table. Without skipping, the raw scanner sees the
/// entire blob as one long printable run and emits it as a single garbage
/// string. The structure-based extractor recovers the correctly-sliced
/// substrings.
#[must_use]
pub(crate) fn pe_rust_skip_ranges(pe: &goblin::pe::PE<'_>, data_len: usize) -> Vec<Range<usize>> {
    pe_section_ranges(pe, data_len, PE_RODATA).collect()
}
