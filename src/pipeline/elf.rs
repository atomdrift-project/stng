//! ELF binaries.

use super::merge_imports;
use super::{Scan, parallel};
use crate::GoStringExtractor;
use crate::RustStringExtractor;
use crate::StringMethod;
use crate::binary;
use crate::collect_elf_section_info;
use crate::collect_elf_segments;
use crate::detect_elf_overlay_from_elf;
use crate::elf_go_skip_ranges;
use crate::extract_elf_imports;
use crate::extract_null_separated_strings;
use crate::extract_overlay_strings;
use crate::extract_raw_strings;
use crate::extract_stack_strings;
use crate::extract_stack_strings_with_context;
use crate::extract_varint_prefixed_strings;
use crate::extract_wide_strings;
use crate::scan_binary_ips;
use crate::unclaimed_raw_strings;
use crate::{ExtractOptions, ExtractedString};
use goblin::elf::Elf;
use rayon::prelude::*;
use std::collections::HashSet;

/// Strings from an ELF binary.
pub(super) fn scan(elf: &Elf<'_>, data: &[u8], opts: &ExtractOptions) -> Scan {
    let min_length = opts.min_length;
    let mut strings = Vec::new();
    let mut is_go_binary = false;
    let segments = collect_elf_segments(elf);
    let section_info = collect_elf_section_info(elf);

    // Detect overlay first to avoid scanning it during normal extraction.
    // Reuse the already-parsed ELF — detect_elf_overlay(data) would re-parse.
    let overlay_info = detect_elf_overlay_from_elf(elf, data);
    let scan_data = if let Some(ref overlay) = overlay_info {
        // Only scan up to overlay start (safe cast: min with data.len())
        let end = usize::try_from(overlay.start_offset)
            .unwrap_or(data.len())
            .min(data.len());
        &data[..end]
    } else {
        data
    };

    // Check for Go sections
    let has_go = elf.section_headers.iter().any(|sh| {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
        name == ".gopclntab" || name == ".go.buildinfo"
    });

    // Check for Rust (rustc metadata sections or panic-location paths).
    // Only asked of non-Go binaries: the content probe scans .rodata.
    let has_rust = !has_go && binary::elf_is_rust(elf, scan_data);

    if has_go {
        is_go_binary = true;

        // Go ELF extraction is six independent passes over `scan_data`:
        //   1. structure-based Go string extraction (.rodata)
        //   2. pclntab symbol recovery (funcnametab/pkgnamestab in
        //      .gopclntab) — names the structure and raw passes can't
        //      reach because the section is skip-scanned below.
        //   3. raw-string fallback for cgo strings the structure pass
        //      misses (.noptrdata, .strtab, .symtab, …). Skip-scanning
        //      .rodata/.gopclntab avoids emitting Go's null-less packed
        //      blobs as one giant garbage string.
        //   4. UTF-16 wide-string scan
        //   5. network-IP scan
        //   6. .text XOR-pair extraction
        // None of them depend on another's output, so run all six
        // concurrently. The raw fallback is normally pruned of strings
        // the structure pass already found; that `known`-set filter is a
        // value comparison applied *after* the join, so it no longer
        // forces the structure pass to complete first. Results are
        // appended in the original sequential order, leaving downstream
        // deduplication unaffected.
        let skip = elf_go_skip_ranges(elf, scan_data.len());
        let split = crate::par::splits(scan_data.len());
        let [go_strings, pcln_res, raw_all, wide_res, ip_res, stack_res] = parallel(
            split,
            [
                &|| GoStringExtractor::new(min_length).extract_elf(elf, scan_data),
                &|| extract_elf_pclntab_strings(elf, scan_data, min_length),
                &|| extract_raw_strings(scan_data, min_length, &segments, &skip),
                &|| extract_wide_strings(scan_data, min_length, &segments, &skip),
                &|| scan_binary_ips(scan_data, min_length, elf.header.e_machine, Some(elf), None),
                &|| extract_go_text_xor_strings(elf, scan_data, min_length),
            ],
        );
        // A section name is only the file's claim. Without Go structures
        // behind it, scan as an unknown ELF below: the skipped `.rodata` and
        // the XOR and IP passes Go turns off would otherwise hide a non-Go
        // binary's strings behind one Go-named section.
        if go_strings.is_empty() {
            tracing::warn!(
                "ELF has Go section names but no Go string structures; scanning as non-Go"
            );
            is_go_binary = false;
            strings.extend(opts.r2_strings.iter().flatten().cloned());
            strings.extend(extract_raw_strings(scan_data, min_length, &segments, &[]));
        }
        let known: HashSet<&str> = go_strings.iter().map(|s| s.value.as_str()).collect();
        let fresh: Vec<ExtractedString> = raw_all
            .into_iter()
            .filter(|s| !known.contains(s.value.as_str()))
            .collect();
        drop(known);
        strings.extend(go_strings);
        strings.extend(pcln_res);
        strings.extend(fresh);
        strings.extend(wide_res);
        strings.extend(ip_res);
        strings.extend(stack_res);
    } else if has_rust {
        let extractor = RustStringExtractor::new(min_length);
        strings.extend(extractor.extract_elf(elf, scan_data));
        // The structure and instruction passes slice rustc's packed
        // `&str` blob; everything else -- libc strings, C dependencies,
        // data the Rust code never names -- still needs the raw scan an
        // unknown ELF gets. Before content detection this branch only
        // saw dylibs; now it sees every Rust executable, and dropping
        // the raw scan would have lost strings they used to report.
        strings.extend(opts.r2_strings.iter().flatten().cloned());
        let raw = extract_raw_strings(scan_data, min_length, &segments, &[]);
        let fresh = unclaimed_raw_strings(raw, &strings, min_length);
        strings.extend(fresh);
    } else {
        // Unknown ELF (C, C++, assembly, etc.) - use r2 if available + raw scan.
        strings.extend(opts.r2_strings.iter().flatten().cloned());
        strings.extend(extract_raw_strings(scan_data, min_length, &segments, &[]));
    }

    // Wide strings, network IPs, and stack strings for non-Go ELF.
    // Go ELF runs these concurrently with its raw-string fallback above.
    if !is_go_binary {
        // Extract UTF-16LE wide strings (less common in ELF but can
        // occur, especially in malware).
        strings.extend(extract_wide_strings(scan_data, min_length, &segments, &[]));

        // Extract binary network data (IPs and ports in network byte order)
        strings.extend(scan_binary_ips(
            scan_data,
            min_length,
            elf.header.e_machine,
            Some(elf),
            None,
        ));

        // Only scan executable sections for stack strings to avoid wasting time on data
        // Parallelize section scanning using Rayon
        let code = crate::binary::merge_overlapping(
            elf.section_headers
                .iter()
                .filter(|sh| {
                    sh.sh_flags & u64::from(goblin::elf::section_header::SHF_EXECINSTR) != 0
                })
                .filter_map(|sh| {
                    // u64→usize: lossless on 64-bit hosts (this tool targets 64-bit only)
                    #[allow(clippy::cast_possible_truncation)]
                    let start = sh.sh_offset as usize;
                    #[allow(clippy::cast_possible_truncation)]
                    let end = start.saturating_add(sh.sh_size as usize);
                    scan_data.get(start..end).map(|_| (start, end))
                })
                .collect(),
        );
        let results: Vec<ExtractedString> = code
            .par_iter()
            .with_min_len(crate::par::job_len(code.len(), scan_data.len()))
            .flat_map_iter(|&(start, end)| {
                let mut results = extract_stack_strings(&scan_data[start..end], min_length);
                for r in &mut results {
                    r.rebase(start as u64);
                }
                results
            })
            .collect();

        strings.extend(results);
    }

    if !opts.caller_provides_symbols {
        merge_imports(&mut strings, extract_elf_imports(elf, min_length));
    }

    // Filter out any strings that fall within the overlay region
    // (they'll be re-extracted with proper section="overlay" marking)
    if let Some(ref overlay) = overlay_info {
        strings.retain(|s| s.data_offset < overlay.start_offset);
    }

    // Extract overlay/appended data (common malware technique)
    strings.extend(extract_overlay_strings(data, min_length));
    Scan {
        strings,
        sections: section_info,
        is_go: is_go_binary,
    }
}

/// Extract XOR-obfuscated stack-pair strings from a Go ELF binary's `.text`
/// section, returning only `XorStackPair` matches with file-relative offsets.
///
/// Pulled out of the Go ELF branch so it can run as one lane of the parallel
/// scan join alongside the raw-string, wide-string, and network-IP passes.
fn extract_go_text_xor_strings(
    elf: &goblin::elf::Elf<'_>,
    scan_data: &[u8],
    min_length: usize,
) -> Vec<ExtractedString> {
    // Compute image base from the first PT_LOAD segment for VA translation.
    let image_base = elf
        .program_headers
        .iter()
        .find(|ph| ph.p_type == goblin::elf::program_header::PT_LOAD)
        .map(|ph| ph.p_vaddr.saturating_sub(ph.p_offset))
        .unwrap_or(0);

    let Some((text_start, text_vma, text)) = elf
        .section_headers
        .iter()
        .find(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(".text"))
        .and_then(|sh| {
            let text = binary::file_range(scan_data, sh.sh_offset, sh.sh_size)?;
            Some((usize::try_from(sh.sh_offset).ok()?, sh.sh_addr, text))
        })
    else {
        return Vec::new();
    };

    // Use the context-aware version to resolve RIP-relative XMM loads.
    let mut xor_results =
        extract_stack_strings_with_context(text, min_length, scan_data, text_vma, image_base);
    // Adjust data_offset to file-relative position.
    for r in &mut xor_results {
        r.rebase(text_start as u64);
    }
    xor_results
        .into_iter()
        .filter(|s| s.method == StringMethod::XorStackPair)
        .collect()
}

/// Recover Go symbol names from an ELF `.gopclntab` section.
///
/// `.gopclntab` holds the funcnametab (NUL-separated function names like
/// `main.Size2Bytes`) and pkgnamestab (varint-length-prefixed package paths).
/// Those entries are referenced by 4-byte offsets, not `{ptr,len}` headers, so
/// the structure scanner can't reach them, and [`elf_go_skip_ranges`] keeps the
/// raw scanner out of the section to avoid emitting its packed pcdata/funcdata
/// tables as garbage runs. This targeted pass (3+ consecutive valid entries)
/// recovers the names without the noise — mirroring the Go PE path.
fn extract_elf_pclntab_strings(
    elf: &goblin::elf::Elf<'_>,
    scan_data: &[u8],
    min_length: usize,
) -> Vec<ExtractedString> {
    let Some(sh) = elf
        .section_headers
        .iter()
        .find(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(".gopclntab"))
    else {
        return Vec::new();
    };

    let Some(section_bytes) = binary::file_range_clamped(scan_data, sh.sh_offset, sh.sh_size)
    else {
        return Vec::new();
    };
    let Ok(start) = usize::try_from(sh.sh_offset) else {
        return Vec::new();
    };

    let t_pcln = std::time::Instant::now();
    // funcnametab is NUL-separated; pkgnamestab is varint-length-prefixed.
    // Scan for both concurrently — the varint pass is fully hidden behind the
    // larger funcname pass and recovers package paths the latter can't.
    let (varints, mut nulls) = crate::par::join(
        section_bytes.len(),
        || {
            extract_varint_prefixed_strings(
                section_bytes,
                start as u64,
                Some(".gopclntab"),
                min_length,
            )
        },
        || {
            extract_null_separated_strings(
                section_bytes,
                start as u64,
                Some(".gopclntab"),
                min_length,
            )
        },
    );
    nulls.extend(varints);
    tracing::debug!(
        "TIME: Go ELF .gopclntab scan took {:?} ({} symbols)",
        t_pcln.elapsed(),
        nulls.len()
    );
    nulls
}
