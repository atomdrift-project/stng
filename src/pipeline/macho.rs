//! Mach-O: thin and universal binaries.

use super::Scan;
use super::merge_imports;
use crate::GoStringExtractor;
use crate::RustStringExtractor;
use crate::StringKind;
use crate::StringMethod;
use crate::arm64_stack_xor;
use crate::binary;
use crate::collect_macho_section_info;
use crate::collect_macho_segments;
use crate::entitlements;
use crate::extract_macho_imports;
use crate::extract_null_separated_strings;
use crate::extract_raw_strings;
use crate::extract_stack_strings_from_ranges;
use crate::extract_varint_prefixed_strings;
use crate::fmix_xor;
use crate::get_r2_strings;
use crate::heap_xor;
use crate::lcg_xor;
use crate::macho_go_skip_ranges;
use crate::macho_has_go_sections;
use crate::pointer_xor;
use crate::swift_small_strings;
use crate::{ExtractOptions, ExtractedString};
use goblin::Object;
use goblin::mach::{MachO, MultiArch};
use std::collections::HashSet;

/// Decoders that read one slice's own sections, given the slice's offset in
/// the file. Every slice of a universal binary gets them: an x86-first file
/// may carry ARM-only encodings.
fn slice_decoders(
    macho: &MachO<'_>,
    data: &[u8],
    slice_base: u64,
    min_length: usize,
) -> Vec<ExtractedString> {
    let mut strings = heap_xor::extract_macho(macho, slice_base, min_length);
    strings.extend(pointer_xor::extract_macho(macho, slice_base, min_length));
    strings.extend(swift_small_strings::extract_macho(
        macho, slice_base, min_length,
    ));
    strings.extend(fmix_xor::extract_macho(macho, slice_base, min_length));
    strings.extend(lcg_xor::extract_macho_lcg_xor(
        macho, data, slice_base, min_length,
    ));
    strings.extend(lcg_xor::extract_macho_xor_macho_strings(
        macho, data, slice_base, min_length,
    ));
    strings
}

/// Strings from a thin (single-architecture) Mach-O.
pub(super) fn scan_thin(macho: &MachO<'_>, data: &[u8], opts: &ExtractOptions) -> Scan {
    let min_length = opts.min_length;
    let mut strings = Vec::new();
    let mut is_go_binary = false;
    let segments = collect_macho_segments(macho);
    let section_info = collect_macho_section_info(macho);
    // Thin binary: the slice is the whole file, so no slice base.
    strings.extend(slice_decoders(macho, data, 0, min_length));
    if macho_has_go_sections(macho) {
        is_go_binary = true;
        let extractor = GoStringExtractor::new(min_length);
        // Thin binary: the slice is the whole file, so no slice base.
        strings.extend(extractor.extract_macho(macho, 0));
        strings.extend(extract_macho_pclntab_strings(macho, data, 0, min_length));

        // Raw scan fallback for Go shared libraries / cgo binaries.
        // Skip raw-scanning the Go string-blob sections — strings there
        // are packed back-to-back without null terminators, so a raw
        // scan emits the entire blob as one merged garbage string. The
        // structure-based + inline-pattern extractors already cover
        // these regions with correct boundaries.
        let skip = macho_go_skip_ranges(macho);
        let new_raw: Vec<_> = {
            let known: HashSet<&str> = strings.iter().map(|s| s.value.as_str()).collect();
            extract_raw_strings(data, min_length, &segments, &skip)
                .into_iter()
                .filter(|s| !known.contains(s.value.as_str()))
                .collect()
        };
        strings.extend(new_raw);
    } else if binary::macho_is_rust(macho) {
        let extractor = RustStringExtractor::new(min_length);
        // Thin binary: the slice is the whole file, so no slice base.
        strings.extend(extractor.extract_macho(macho, 0));
        // Same fallback an unknown Mach-O gets (see below): the Rust
        // passes only cover the literals Rust code names.
        if let Some(r2_strings) = get_r2_strings(opts) {
            strings.extend(r2_strings);
        }
        let extra: Vec<ExtractedString> = {
            let known: HashSet<&str> = strings.iter().map(|s| s.value.as_str()).collect();
            let mut seen: HashSet<String> = HashSet::new();
            scan_macho_sections(data, min_length, &segments, &section_info)
                .into_iter()
                .chain(extract_raw_strings(data, min_length, &segments, &[]))
                .filter(|s| !known.contains(s.value.as_str()) && seen.insert(s.value.clone()))
                .collect()
        };
        strings.extend(extra);
    } else {
        // Unknown Mach-O (C/C++/Objective-C/asm). Use r2 if available,
        // then the targeted extractor, then an unconditional per-section
        // scan. The targeted extractor only covers __cstring/__const/
        // __text and silently skips other string-literal sections
        // (notably __objc_methname); without the section scan those
        // strings — and any IOC fragments split across literals — are
        // lost whenever r2 is unavailable. ELF and Go already always run
        // a raw scan for the same reason.
        if let Some(r2_strings) = get_r2_strings(opts) {
            strings.extend(r2_strings);
        }
        let extractor = RustStringExtractor::new(min_length);
        // Thin binary: the slice is the whole file, so no slice base.
        strings.extend(extractor.extract_macho(macho, 0));
        // Per-section scan first (section-tagged, file-relative offsets)
        // so __objc_methname and the like are correlatable by their
        // section; whole-file scan second as a backstop for bytes
        // outside any enumerated section (__LINKEDIT, padding, minimal
        // layouts). Merge by value: the section-tagged copy wins and
        // nothing already held by r2/the targeted extractor is duped.
        let extra: Vec<ExtractedString> = {
            let known: HashSet<&str> = strings.iter().map(|s| s.value.as_str()).collect();
            let mut seen: HashSet<String> = HashSet::new();
            scan_macho_sections(data, min_length, &segments, &section_info)
                .into_iter()
                .chain(extract_raw_strings(data, min_length, &segments, &[]))
                .filter(|s| !known.contains(s.value.as_str()) && seen.insert(s.value.clone()))
                .collect()
        };
        strings.extend(extra);
    }
    if !is_go_binary {
        // Capture opacity before adding instruction-derived stack
        // strings; the admission signal should describe what the
        // ordinary string pass could see in the file.
        let profile = arm64_stack_xor_profile(data.len(), &strings);
        // Only disassemble executable sections — feeding the whole
        // Mach-O to iced-x86 wastes cycles on __LINKEDIT and
        // non-code segments.
        let exec_ranges = binary::code_ranges_from_sections(&section_info);
        strings.extend(extract_stack_strings_from_ranges(
            data,
            min_length,
            &exec_ranges,
        ));
        let xor_strings =
            arm64_stack_xor::extract_arm64_stack_xor_strings(macho, data, 0, profile, min_length);
        strings.extend(xor_strings);
    }
    if !opts.caller_provides_symbols {
        merge_imports(&mut strings, extract_macho_imports(macho, min_length));
    }
    apply_entitlements(&mut strings, macho, data, min_length);
    Scan {
        strings,
        sections: section_info,
        is_go: is_go_binary,
    }
}

/// Strings from a universal (fat) Mach-O: every slice's own decoders, and
/// one pass over the file.
pub(super) fn scan_fat(fat: &MultiArch<'_>, data: &[u8], opts: &ExtractOptions) -> Scan {
    let min_length = opts.min_length;
    let mut strings = Vec::new();
    let mut is_go_binary = false;
    let mut section_info = Vec::new();
    // Fat binary - check for Go/Rust first
    let mut is_go = false;
    let mut is_rust = false;
    let mut segments = Vec::new();
    let mut first_macho: Option<MachO<'_>> = None;
    // Fat-header offsets of each slice within the whole file, so a slice's
    // strings can be rebased onto the file (a slice's own load commands are
    // slice-relative). Indexed in lockstep with the iteration below.
    let arch_offsets: Vec<u64> = fat
        .arches()
        .map(|a| a.iter().map(|x| u64::from(x.offset)).collect())
        .unwrap_or_default();
    for (idx, arch_result) in fat.into_iter().enumerate() {
        if let Ok(goblin::mach::SingleArch::MachO(macho)) = arch_result {
            let Some(&slice_base) = arch_offsets.get(idx) else {
                continue;
            };
            // Instruction decoders must visit every architecture: an
            // x86-first universal file may carry ARM-only encodings.
            // Keep whole-file raw scanning below to one pass.
            strings.extend(slice_decoders(&macho, data, slice_base, min_length));
            if first_macho.is_some() {
                if macho_has_go_sections(&macho) {
                    let extractor = GoStringExtractor::new(min_length);
                    strings.extend(extractor.extract_macho(&macho, slice_base));
                    strings.extend(extract_macho_pclntab_strings(
                        &macho, data, slice_base, min_length,
                    ));
                } else if binary::macho_is_rust(&macho) {
                    let extractor = RustStringExtractor::new(min_length);
                    strings.extend(extractor.extract_macho(&macho, slice_base));
                }
                continue;
            }
            segments = collect_macho_segments(&macho);
            // A slice's load commands are slice-relative; the
            // whole-file passes here and after the match need file
            // offsets.
            section_info = collect_macho_section_info(&macho);
            for info in &mut section_info {
                info.file_offset += slice_base;
            }
            if macho_has_go_sections(&macho) {
                is_go = true;
                is_go_binary = true;
                let extractor = GoStringExtractor::new(min_length);
                strings.extend(extractor.extract_macho(&macho, slice_base));
                strings.extend(extract_macho_pclntab_strings(
                    &macho, data, slice_base, min_length,
                ));

                // See macho_has_go_sections branch above for why we
                // skip-scan the Go string-blob sections.
                let base = usize::try_from(slice_base).unwrap_or(usize::MAX);
                let skip: Vec<_> = macho_go_skip_ranges(&macho)
                    .into_iter()
                    .map(|r| r.start.saturating_add(base)..r.end.saturating_add(base))
                    .collect();
                let new_raw: Vec<_> = {
                    let known: HashSet<&str> = strings.iter().map(|s| s.value.as_str()).collect();
                    extract_raw_strings(data, min_length, &segments, &skip)
                        .into_iter()
                        .filter(|s| !known.contains(s.value.as_str()))
                        .collect()
                };
                strings.extend(new_raw);
            } else if binary::macho_is_rust(&macho) {
                is_rust = true;
                let extractor = RustStringExtractor::new(min_length);
                strings.extend(extractor.extract_macho(&macho, slice_base));
            }
            first_macho = Some(macho);
        }
    }
    // For non-Go fat binaries, use r2 if available + raw scan. Rust
    // slices get it too, after their structure pass: that pass only
    // covers the literals Rust code names (see the thin branch).
    if !is_go {
        if let Some(r2_strings) = get_r2_strings(opts) {
            strings.extend(r2_strings);
        }
        // Also do raw scan to catch anything r2 missed
        let raw = extract_raw_strings(data, min_length, &segments, &[]);
        if is_rust {
            let known: HashSet<&str> = strings.iter().map(|s| s.value.as_str()).collect();
            let fresh: Vec<_> = raw
                .into_iter()
                .filter(|s| !known.contains(s.value.as_str()))
                .collect();
            drop(known);
            strings.extend(fresh);
        } else {
            strings.extend(raw);
        }
    }
    if !is_go_binary {
        // See the thin Mach-O branch: measure opacity before adding
        // instruction-derived stack strings.
        let profile = arm64_stack_xor_profile(data.len(), &strings);
        let exec_ranges = binary::code_ranges_from_sections(&section_info);
        strings.extend(extract_stack_strings_from_ranges(
            data,
            min_length,
            &exec_ranges,
        ));
        if let Ok(arches) = fat.arches() {
            for (idx, arch) in arches.iter().enumerate() {
                let Ok(goblin::mach::SingleArch::MachO(macho)) = fat.get(idx) else {
                    continue;
                };
                let arch_start = arch.offset as usize;
                let arch_size = arch.size as usize;
                let Some(arch_end) = arch_start.checked_add(arch_size) else {
                    continue;
                };
                let Some(arch_data) = data.get(arch_start..arch_end) else {
                    continue;
                };
                let profile = arm64_stack_xor::AdmissionProfile {
                    input_size: arch_data.len(),
                    ..profile
                };
                let xor_strings = arm64_stack_xor::extract_arm64_stack_xor_strings(
                    &macho,
                    arch_data,
                    u64::from(arch.offset),
                    profile,
                    min_length,
                );
                strings.extend(xor_strings);
            }
        }
    }
    if let Some(ref macho) = first_macho {
        if !opts.caller_provides_symbols {
            merge_imports(&mut strings, extract_macho_imports(macho, min_length));
        }
        apply_entitlements(&mut strings, macho, data, min_length);
    }
    Scan {
        strings,
        sections: section_info,
        is_go: is_go_binary,
    }
}

/// Raw-scan every non-executable Mach-O section so string-literal sections the
/// targeted extractor skips — notably `__objc_methname` — and the leading entry
/// of each section still surface when radare2 is unavailable. Each section is
/// scanned as a slice, so the raw scanner yields section-relative offsets; they
/// are rebased to the section's file offset before being emitted, because every
/// offset stng reports indexes the file, never a section. The section name is
/// tagged so callers can still correlate fragments by location. Executable
/// sections are covered by the stack-string / disassembly passes, so raw-scanning
/// their instruction bytes here would only add noise. Results are de-duplicated
/// by value within this pass; callers merge them against what they already hold.
fn scan_macho_sections(
    data: &[u8],
    min_length: usize,
    segments: &[String],
    section_info: &[binary::SectionInfo],
) -> Vec<ExtractedString> {
    let mut out = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    // The first section to yield a value claims it, so walk sections in file
    // order.
    let mut sections: Vec<&binary::SectionInfo> = section_info.iter().collect();
    sections.sort_by(|a, b| (a.file_offset, &a.name).cmp(&(b.file_offset, &b.name)));
    for info in sections {
        if info.is_executable || info.size == 0 {
            continue;
        }
        // u64→usize: lossless on 64-bit hosts (this tool targets 64-bit only).
        #[allow(clippy::cast_possible_truncation)]
        let start = info.file_offset as usize;
        #[allow(clippy::cast_possible_truncation)]
        let end = start.saturating_add(info.size as usize);
        let Some(section_bytes) = data.get(start..end) else {
            continue;
        };
        for mut s in extract_raw_strings(section_bytes, min_length, segments, &[]) {
            // The raw scanner offsets are relative to `section_bytes`; lift them
            // to the file by adding the section's file offset.
            s.rebase(start as u64);
            if seen.insert(s.value.clone()) {
                out.push(s);
            }
        }
    }
    out
}

/// Apply Mach-O entitlements: remove overlapping strings, then append entitlement XML.
fn apply_entitlements(
    strings: &mut Vec<ExtractedString>,
    macho: &MachO<'_>,
    data: &[u8],
    min_length: usize,
) {
    let entitlements = entitlements::extract_macho_entitlements(macho, data, min_length);
    for ent in &entitlements {
        if ent.kind == Some(StringKind::EntitlementsXml) {
            let ent_start = ent.data_offset;
            let ent_end = ent_start.saturating_add(ent.value.len() as u64);
            strings.retain(|s| {
                s.data_offset.saturating_add(s.value.len() as u64) <= ent_start
                    || s.data_offset >= ent_end
            });
        }
    }
    strings.extend(entitlements);
}

/// Go function and package names from a Mach-O `__gopclntab` section.
///
/// The Mach-O counterpart of [`extract_elf_pclntab_strings`]. The raw scan
/// skips `__gopclntab` (see `binary::macho_go_skip_ranges`) because its
/// strings are packed without terminators the raw scanner understands, and the
/// structure-based Go extractor recovers string literals rather than function
/// names — so without this pass a Mach-O Go binary exposed none of the
/// `pkg.Function` names its ELF and PE builds do, and every rule keyed on them
/// went blind on macOS. `slice_base` rebases a fat slice's section offsets onto
/// the whole file.
fn extract_macho_pclntab_strings(
    macho: &MachO<'_>,
    data: &[u8],
    slice_base: u64,
    min_length: usize,
) -> Vec<ExtractedString> {
    let Some(sec) = macho
        .segments
        .iter()
        .filter_map(|seg| seg.sections().ok())
        .flatten()
        .map(|(sec, _)| sec)
        .find(|sec| sec.name().is_ok_and(|n| n == "__gopclntab"))
    else {
        return Vec::new();
    };
    let Some(start) = slice_base.checked_add(u64::from(sec.offset)) else {
        return Vec::new();
    };
    let (Ok(start), Ok(size)) = (usize::try_from(start), usize::try_from(sec.size)) else {
        return Vec::new();
    };
    let end = start.saturating_add(size).min(data.len());
    let Some(section_bytes) = data.get(start..end) else {
        return Vec::new();
    };

    let t_pcln = std::time::Instant::now();
    // Same two encodings as the ELF pass: NUL-separated funcnametab and
    // varint-prefixed pkgnamestab.
    let (varints, mut nulls) = rayon::join(
        || {
            extract_varint_prefixed_strings(
                section_bytes,
                start as u64,
                Some("__gopclntab"),
                min_length,
            )
        },
        || {
            extract_null_separated_strings(
                section_bytes,
                start as u64,
                Some("__gopclntab"),
                min_length,
            )
        },
    );
    nulls.extend(varints);
    tracing::debug!(
        "TIME: Go Mach-O __gopclntab scan took {:?} ({} symbols)",
        t_pcln.elapsed(),
        nulls.len()
    );
    nulls
}

/// File-offset range(s) of the Mach-O `__LINKEDIT` segment (which holds the
/// code-signature blob). Returns one range for a thin binary and one per slice
/// for a fat binary; empty for non-Mach-O. Used to scope code-signature
/// reclassification by offset now that strings no longer carry a section name.
pub(crate) fn macho_linkedit_ranges(object: &Object<'_>) -> Vec<(u64, u64)> {
    fn from_macho(macho: &MachO<'_>, base: u64) -> Option<(u64, u64)> {
        macho.segments.iter().find_map(|seg| {
            (seg.name().ok() == Some("__LINKEDIT")).then(|| {
                let start = base + seg.fileoff;
                (start, start + seg.filesize)
            })
        })
    }
    let mut ranges = Vec::new();
    match object {
        Object::Mach(goblin::mach::Mach::Binary(macho)) => ranges.extend(from_macho(macho, 0)),
        Object::Mach(goblin::mach::Mach::Fat(fat)) => {
            // `iter_arches` runs to the header's `nfat_arch` (up to u32::MAX)
            // without checking it against the buffer; entries are contiguous,
            // so the first unreadable one ends the table.
            let offsets: Vec<u64> = fat
                .iter_arches()
                .map_while(std::result::Result::ok)
                .map(|a| u64::from(a.offset))
                .collect();
            for (arch, base) in fat.into_iter().zip(offsets) {
                if let Ok(goblin::mach::SingleArch::MachO(macho)) = arch {
                    ranges.extend(from_macho(&macho, base));
                }
            }
        }
        _ => {}
    }
    ranges
}

/// Check if a string looks like a bundle ID (reverse domain notation).
/// Examples: com.apple.ls, org.example.app, net.something.tool
fn is_bundle_id(s: &str) -> bool {
    if !s.starts_with("com.")
        && !s.starts_with("org.")
        && !s.starts_with("net.")
        && !s.starts_with("io.")
        && !s.starts_with("app.")
        && !s.starts_with("dev.")
    {
        return false;
    }
    let mut count = 0;
    for part in s.split('.') {
        if part.is_empty() {
            return false;
        }
        if !part
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            return false;
        }
        count += 1;
    }
    count >= 3
}

/// Check if a string looks like it's part of an X.509 certificate.
/// Certificates are embedded in the code signature blob and contain:
/// - Distinguished Names (DN): "Apple Inc.1", "Apple Certification Authority1"
/// - ASN.1 dates: "111024173941Z", "261024173941Z0"
/// - CRL URLs: `"http://crl.apple.com/codesigning.crl0"`
/// - Policy text: "This certificate is to be used exclusively for..."
fn is_certificate_string(s: &str) -> bool {
    // Certificate Authority names
    if s.contains("Certification Authority")
        || s.contains("Certificate Authority")
        || s.contains("Root CA")
    {
        return true;
    }

    // Code signing related
    if s.contains("Code Signing") || s.contains("Software Signing") {
        return true;
    }

    // CRL (Certificate Revocation List) URLs
    if s.contains("crl.apple.com")
        || s.contains("appleca")
        || (s.contains(".crl") && s.contains("http"))
    {
        return true;
    }

    // ASN.1 date format: YYMMDDHHMMSSZ or YYYYMMDDHHMMSSZ
    // Examples: "111024173941Z", "261024173941Z0", "201029183238Z"
    if s.len() >= 13 && s.ends_with('Z') {
        let without_z = &s[..s.len() - 1];
        if without_z.chars().all(|c| c.is_ascii_digit())
            && (without_z.len() == 12 || without_z.len() == 14)
        {
            return true;
        }
    }
    // Sometimes has trailing digits/chars after Z
    if s.len() >= 14
        && s.contains('Z')
        && let Some(z_pos) = s.find('Z')
        && z_pos >= 12
    {
        let before_z = &s[..z_pos];
        if before_z.chars().rev().take(12).all(|c| c.is_ascii_digit()) {
            return true;
        }
    }

    // Certificate policy text
    if s.contains("certificate is to be used")
        || s.contains("Reliance on this certificate")
        || s.contains("terms and conditions")
    {
        return true;
    }

    // Apple Inc. and related organizational units (but not just "Apple")
    if (s.contains("Apple Inc.") || s.contains("Apple Software")) && s.len() < 50 {
        // Keep it short to avoid false positives
        return true;
    }

    false
}

fn arm64_stack_xor_profile(
    input_size: usize,
    strings: &[ExtractedString],
) -> arm64_stack_xor::AdmissionProfile {
    let mut string_count = 0_usize;
    let mut string_bytes = 0_usize;
    for string in strings {
        if string.method == StringMethod::XorStackPair {
            continue;
        }
        string_count = string_count.saturating_add(1);
        string_bytes = string_bytes.saturating_add(string.value.len());
    }
    arm64_stack_xor::AdmissionProfile {
        input_size,
        content_size: input_size,
        string_count,
        string_bytes,
    }
}

/// Upgrade strings in the Mach-O __LINKEDIT segment related to code
/// signatures. Section names are no longer stored per-string, so gate on
/// the segment's file-offset range(s) instead (thin: one; fat: per slice).
pub(super) fn classify_code_signature(strings: &mut [ExtractedString], object: &Object<'_>) {
    let linkedit_ranges = macho_linkedit_ranges(object);
    for s in strings.iter_mut() {
        if linkedit_ranges
            .iter()
            .any(|&(start, end)| s.data_offset >= start && s.data_offset < end)
        {
            // Base64 strings in __LINKEDIT that decode to SHA-1 (20 bytes) or
            // SHA-256 (32 bytes) are CD hashes. Other base64 content (certificate
            // data, etc.) decodes to different sizes and must not be promoted.
            if s.kind == Some(StringKind::Base64) {
                let decoded_len = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    s.value.trim(),
                )
                .map(|b| b.len())
                .unwrap_or(0);
                if decoded_len == 20 || decoded_len == 32 {
                    s.kind = Some(StringKind::CodeSignatureHash);
                    s.method = StringMethod::CodeSignature;
                }
            }

            // XML/plist strings in __LINKEDIT are part of code signature
            if s.kind.is_none()
                && (s.value.starts_with("<?xml")
                    || s.value.starts_with("<!DOCTYPE plist")
                    || s.value.starts_with("<plist")
                    || s.value.starts_with("<dict")
                    || s.value.starts_with("</dict>")
                    || s.value.starts_with("</plist>")
                    || s.value.starts_with("<key>")
                    || s.value.starts_with("<array>")
                    || s.value.starts_with("</array>")
                    || s.value.starts_with("<data>")
                    || s.value.starts_with("</data>"))
            {
                s.method = StringMethod::CodeSignature;
            }

            // Certificate-related strings in __LINKEDIT (X.509 certificate chain)
            if (s.kind.is_none() || s.kind == Some(StringKind::Base64))
                && is_certificate_string(&s.value)
            {
                s.method = StringMethod::CodeSignature;
            }

            // Bundle IDs (reverse domain notation) in __LINKEDIT are often app identifiers
            if s.kind.is_none() && is_bundle_id(&s.value) {
                s.kind = Some(StringKind::AppId);
            }
        }
    }
}
