//! PE binaries.

use super::{Scan, extract_stack_strings_from_ranges, merge_imports, parallel};
use crate::binary::{
    self, collect_pe_section_info, pe_go_skip_ranges, pe_is_rust, pe_rust_skip_ranges,
};
use crate::go::{GoStringExtractor, pclntab_strings};
use crate::imports::extract_layout_imports;
use crate::layouts::Layouts;
use crate::raw::{extract_raw_strings, extract_wide_strings};
use crate::rust::RustStringExtractor;
use crate::sockaddr::scan_binary_ips;
use crate::{ExtractOptions, ExtractedString, StringKind, StringMethod, dotnet, xor};
use goblin::pe::PE;

/// Strings from a PE binary.
pub(super) fn scan<'d>(
    pe: &PE<'_>,
    layouts: &Layouts<'_, 'd>,
    data: &'d [u8],
    opts: &ExtractOptions,
) -> Scan {
    let min_length = opts.min_length;
    let mut strings = Vec::new();
    let mut is_go_binary = false;
    // Collect PE section names and metadata
    let segments: Vec<String> = pe
        .sections
        .iter()
        .map(|sec| binary::pe_section_name(&sec.name).into_owned())
        .collect();
    let section_info = collect_pe_section_info(pe);

    // Check for Go. Stripped Go PE builds merge `go.buildinfo` /
    // `gopclntab` into `.rdata`, so also accept `.symtab` — Go is the
    // only common PE toolchain that retains that exact section name
    // (MSVC/GCC/Clang PEs don't emit a section literally named `.symtab`).
    // Without this, stripped Go PEs skip the Go-aware code path and
    // hit the speculative XOR scanner, which decodes random pclntab
    // bytes into garbled "payloads".
    let has_go = pe.sections.iter().any(|sec| {
        let name = binary::pe_section_name(&sec.name);
        name.contains("go.buildinfo") || name.contains("gopclntab") || name == ".symtab"
    });

    // A section name is only the file's claim. Go handling skips raw and XOR
    // scanning of `.rdata`, so it needs Go structures behind it: a non-Go
    // binary carrying one Go-named section otherwise hid every string there.
    let t_struct = std::time::Instant::now();
    let go_strings = if has_go {
        GoStringExtractor::new(min_length).extract_pe(pe, data)
    } else {
        Vec::new()
    };
    if has_go && go_strings.is_empty() {
        tracing::debug!("PE has Go section names but no Go string structures; scanning as non-Go");
    }
    if !go_strings.is_empty() {
        is_go_binary = true;
        strings.extend(go_strings);
        tracing::debug!(elapsed = ?t_struct.elapsed(), "Go PE structure extraction finished");

        let t_pcln = std::time::Instant::now();
        strings.extend(rdata_pclntab_strings(pe, data, min_length));
        tracing::debug!(elapsed = ?t_pcln.elapsed(), "Go PE pclntab scan finished");
    }

    // Rust PE binaries pack `&'static str` data into `.rdata` the
    // same way Go does; structure-based slicing recovers individual
    // entries that the raw scanner would otherwise glue into one
    // megastring (`thumbs.dbnetuser.dat...`).
    let is_rust = !is_go_binary && pe_is_rust(pe, data);
    if is_rust {
        let t_struct = std::time::Instant::now();
        let extractor = RustStringExtractor::new(min_length);
        strings.extend(extractor.extract_pe(pe, data));
        tracing::debug!(elapsed = ?t_struct.elapsed(), "Rust PE structure extraction finished");
    }

    // Skip raw-scanning Go's or Rust's packed string sections to
    // avoid emitting the entire blob as one merged garbage string.
    let pe_skip: Vec<std::ops::Range<usize>> = if is_go_binary {
        pe_go_skip_ranges(pe, data.len())
    } else if is_rust {
        pe_rust_skip_ranges(pe, data.len())
    } else {
        Vec::new()
    };

    let wide_skip: &[std::ops::Range<usize>] = if is_rust { &[] } else { &pe_skip };

    // Only executable sections are disassembled for stack strings. Go PE
    // binaries need this too: dynamically resolved Win32 API names are
    // written by successive `mov reg, imm64; mov [rsp+N], reg` and only
    // emerge as full names when those writes are merged.
    let exec_ranges = binary::code_ranges_from_sections(&section_info);
    let split = crate::par::splits(data.len());
    let [
        us_strings,
        wide_strings,
        net_strings,
        raw_strings,
        stack_strings,
    ] = parallel(
        split,
        [
            &|| dotnet::extract_us_heap_strings(pe, data, min_length),
            // UTF-16 literals are NUL-terminated, never packed like `&str`
            // data, so the wide scan covers Rust's `.rdata` too. Go's skipped
            // sections hold pclntab tables that only decode to UTF-16 noise.
            &|| extract_wide_strings(data, min_length, &segments, wide_skip),
            &|| {
                // No ELF machine: the M68000 skip is ELF's.
                scan_binary_ips(data, min_length, 0, None, Some(pe))
            },
            &|| extract_raw_strings(data, min_length, &segments, &pe_skip),
            &|| {
                extract_stack_strings_from_ranges(
                    data,
                    min_length,
                    &exec_ranges,
                    crate::x86::bits_pe(pe.header.coff_header.machine),
                )
            },
        ],
    );

    strings.extend(us_strings);
    strings.extend(wide_strings);
    strings.extend(net_strings);
    strings.extend(raw_strings);
    strings.extend(stack_strings);
    if opts.xor_scans() && !is_go_binary && !opts.is_cancelled() {
        strings.extend(xor::pe_decoder::extract(pe, data, min_length));
    }

    // Recover imports/exports from the PE directories — names behind RVA
    // tables that a raw byte scan can't reach.
    if !opts.caller_provides_symbols {
        let imports = layouts.with(0, data, |layout| extract_layout_imports(layout, min_length));
        merge_imports(&mut strings, imports);
    }

    strings.extend(pdb_path(pe, min_length));

    // Data appended after the image: installers, droppers and crypters put
    // payloads and configuration there.
    if let Some(overlay) = crate::overlay::pe_overlay(pe, data) {
        strings.retain(|s| s.data_offset < overlay.start_offset);
        strings.extend(crate::overlay::overlay_strings(data, &overlay, min_length));
    }
    Scan {
        strings,
        sections: section_info,
        is_go: is_go_binary,
    }
}

/// Go's pclntab `pkgnamestab`, which stripped Windows builds keep inside
/// `.rdata`: varint-prefixed module paths and reflect type names that no
/// `{ptr, len}` structure reaches.
fn rdata_pclntab_strings(pe: &PE<'_>, data: &[u8], min_length: usize) -> Vec<ExtractedString> {
    let mut strings = Vec::new();
    for sec in &pe.sections {
        let name = binary::pe_section_name(&sec.name);
        if !matches!(&*name, ".rdata" | ".rodata") {
            continue;
        }
        let start = u64::from(sec.pointer_to_raw_data);
        let Some(section_bytes) =
            binary::file_range_clamped(data, start, u64::from(sec.size_of_raw_data))
        else {
            continue;
        };
        let (nulls, varints) = pclntab_strings(section_bytes, start, min_length);
        strings.extend(varints);
        strings.extend(nulls);
    }
    strings
}

/// The PDB path from the CodeView (RSDS) debug record. It sits in `.rdata`,
/// which is skip-scanned for Go and Rust binaries, and names the build
/// machine's project — often the most attributable string in a sample.
fn pdb_path(pe: &PE<'_>, min_length: usize) -> Option<ExtractedString> {
    let debug = pe.debug_data.as_ref()?;
    let info = debug.codeview_pdb70_debug_info.as_ref()?;
    let dir = debug.find_type(goblin::pe::debug::IMAGE_DEBUG_TYPE_CODEVIEW)?;
    let name = info.filename.split(|&b| b == 0).next()?;
    let value = std::str::from_utf8(name).ok()?;
    if value.len() < min_length {
        return None;
    }
    // RSDS record: 4-byte signature, 16-byte GUID, 4-byte age, then the path.
    Some(ExtractedString {
        value: value.to_owned(),
        data_offset: u64::from(dir.pointer_to_raw_data) + 24,
        method: StringMethod::Structure,
        kind: crate::classifier::classify_string(value),
        ..Default::default()
    })
}

/// Clear IP/host classifications for strings that are VS_VERSION_INFO values.
///
/// FileVersion and ProductVersion commonly look like IP addresses (e.g. "18.0.0.23").
/// Goblin parses these fields directly, so we can suppress them precisely.
pub(crate) fn suppress_version_info_ips(strings: &mut [ExtractedString], pe: &goblin::pe::PE<'_>) {
    let version_strings: Vec<String> = pe
        .resource_data
        .as_ref()
        .and_then(|r| r.version_info.as_ref())
        .map(|vi| {
            [
                vi.string_info.file_version(),
                vi.string_info.product_version(),
            ]
            .into_iter()
            .flatten()
            .collect()
        })
        .unwrap_or_default();

    if version_strings.is_empty() {
        return;
    }

    for s in strings.iter_mut() {
        if matches!(s.kind, Some(StringKind::Ip | StringKind::IpPort))
            && version_strings.iter().any(|v| v == &s.value)
        {
            tracing::debug!(ip = ?s.value, "Suppressing version-info false positive IP");
            s.kind = None;
        }
    }
}
