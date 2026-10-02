//! PE binaries.

use super::merge_imports;
use super::{Scan, parallel};
use crate::GoStringExtractor;
use crate::RustStringExtractor;
use crate::StringKind;
use crate::StringMethod;
use crate::binary;
use crate::collect_pe_section_info;
use crate::dotnet;
use crate::extract_null_separated_strings;
use crate::extract_overlay_strings;
use crate::extract_pe_imports;
use crate::extract_raw_strings;
use crate::extract_stack_strings_from_ranges;
use crate::extract_varint_prefixed_strings;
use crate::extract_wide_strings;
use crate::pe_go_skip_ranges;
use crate::pe_is_rust;
use crate::pe_rust_skip_ranges;
use crate::pe_xor;
use crate::scan_binary_ips;
use crate::{ExtractOptions, ExtractedString};
use goblin::pe::PE;

/// Strings from a PE binary.
pub(super) fn scan(pe: &PE<'_>, data: &[u8], opts: &ExtractOptions) -> Scan {
    let min_length = opts.min_length;
    let mut strings = Vec::new();
    let mut is_go_binary = false;
    // Collect PE section names and metadata
    let segments: Vec<String> = pe
        .sections
        .iter()
        .map(|sec| binary::pe_section_name(&sec.name))
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

    if has_go {
        is_go_binary = true;
        let t_struct = std::time::Instant::now();
        let extractor = GoStringExtractor::new(min_length);
        strings.extend(extractor.extract_pe(pe, data));
        tracing::debug!(
            "TIME: Go PE structure extraction took {:?}",
            t_struct.elapsed()
        );

        // Recover the Go pclntab `pkgnamestab` table that lives inside
        // .rdata on stripped Windows builds — varint-length-prefixed
        // module paths and reflect type names that are not reachable
        // via {ptr,len} structures.
        let t_pcln = std::time::Instant::now();
        for sec in &pe.sections {
            let name = binary::pe_section_name(&sec.name);
            if !matches!(name.as_str(), ".rdata" | ".rodata") {
                continue;
            }
            let start = u64::from(sec.pointer_to_raw_data);
            let Some(section_bytes) =
                binary::file_range_clamped(data, start, u64::from(sec.size_of_raw_data))
            else {
                continue;
            };
            let (varints, nulls) = crate::par::join(
                section_bytes.len(),
                || {
                    extract_varint_prefixed_strings(
                        section_bytes,
                        start,
                        Some(name.as_str()),
                        min_length,
                    )
                },
                || {
                    extract_null_separated_strings(
                        section_bytes,
                        start,
                        Some(name.as_str()),
                        min_length,
                    )
                },
            );
            strings.extend(varints);
            strings.extend(nulls);
        }
        tracing::debug!("TIME: Go PE pclntab scan took {:?}", t_pcln.elapsed());
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
        tracing::debug!(
            "TIME: Rust PE structure extraction took {:?}",
            t_struct.elapsed()
        );
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
        r2_strings,
        wide_strings,
        net_strings,
        raw_strings,
        stack_strings,
    ] = parallel(
        split,
        [
            &|| dotnet::extract_us_heap_strings(pe, data, min_length),
            &|| opts.r2_strings.clone().unwrap_or_default(),
            // UTF-16 literals are NUL-terminated, never packed like `&str`
            // data, so the wide scan covers Rust's `.rdata` too. Go's skipped
            // sections hold pclntab tables that only decode to UTF-16 noise.
            &|| extract_wide_strings(data, min_length, &segments, wide_skip),
            &|| {
                scan_binary_ips(
                    data,
                    min_length,
                    pe.header.coff_header.machine,
                    None,
                    Some(pe),
                )
            },
            &|| extract_raw_strings(data, min_length, &segments, &pe_skip),
            &|| extract_stack_strings_from_ranges(data, min_length, &exec_ranges),
        ],
    );

    strings.extend(us_strings);
    strings.extend(r2_strings);
    strings.extend(wide_strings);
    strings.extend(net_strings);
    strings.extend(raw_strings);
    strings.extend(stack_strings);
    if opts.xor_scan && opts.xor_key.is_none() && !is_go_binary && !opts.is_cancelled() {
        strings.extend(pe_xor::extract(pe, data, min_length));
    }

    // Recover imports/exports from the PE directories — names behind RVA
    // tables that a raw byte scan can't reach (the radare2-only gap).
    if !opts.caller_provides_symbols {
        merge_imports(&mut strings, extract_pe_imports(pe, min_length));
    }

    strings.extend(pdb_path(pe, min_length));

    // Extract overlay/appended data (common malware technique)
    strings.extend(extract_overlay_strings(data, min_length));
    Scan {
        strings,
        sections: section_info,
        is_go: is_go_binary,
    }
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
        if matches!(s.kind, Some(StringKind::IP | StringKind::IPPort))
            && version_strings.iter().any(|v| v == &s.value)
        {
            tracing::debug!("Suppressing version-info false positive IP: {}", s.value);
            s.kind = None;
        }
    }
}
