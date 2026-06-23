// Allow unwrap/expect/panic in test code — panicking on failure is idiomatic in tests.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

//! # stng - Language-aware string extraction
//!
//! This library provides language-aware string extraction for Go and Rust binaries.
//! Unlike traditional `strings(1)`, it understands how these languages store strings
//! internally (pointer + length pairs, NOT null-terminated) and can properly extract
//! individual strings from packed string data.
//!
//! ## Background
//!
//! Both Go and Rust use "fat pointer" representations for strings:
//! - Go: `string` is `{ptr: *byte, len: int}` (16 bytes on 64-bit)
//! - Rust: `&str` is `{ptr: *u8, len: usize}` (16 bytes on 64-bit)
//! - Rust: `String` is `{ptr: *u8, len: usize, cap: usize}` (24 bytes on 64-bit)
//!
//! Because strings aren't null-terminated, they're often packed together
//! in the binary without separators. Traditional string extraction tools
//! concatenate them into garbage blobs.
//!
//! This module finds the pointer+length structures and uses them to
//! extract strings with precise boundaries.
//!
//! ## Usage
//!
//! ```no_run
//! use stng::extract_strings;
//!
//! let data = std::fs::read("my_binary").unwrap();
//! let strings = extract_strings(&data, 4);
//!
//! for s in strings {
//!     println!("{}: {}", s.data_offset, s.value);
//! }
//! ```

// Core modules
mod extraction;
mod types;
mod validation;
mod validation_thresholds;

// Binary format modules
mod arm64_stack_xor;
pub mod binary;
mod binary_net;
mod detect;
mod dotnet;
mod entitlements;
mod imports;
mod overlay;
mod raw;
mod stack_strings;

// Script deobfuscation
pub mod script;

// String classifier
pub mod classifier;

// Language-specific extractors
mod go;
pub(crate) mod instr;
pub mod r2;
mod rust;
pub mod string_cache;
pub(crate) mod xor;

// Decoders for encoded strings
pub(crate) mod decoders;
mod fuzzy_base64;

// Public API
pub use binary::{is_go_binary, is_rust_binary};
pub use classifier::classify_string;
pub use detect::{detect_language, is_text_file};
pub use overlay::{detect_elf_overlay, detect_elf_overlay_from_elf};
pub use string_cache::{
    cache_key_for, cached_strings_by_key, cached_strings_from_object, cached_strings_with_options,
};
pub use types::{
    Arch, BinaryInfo, ExtractedString, OverlayInfo, Severity, StringContext, StringFragment,
    StringKind, StringMethod, StringStruct,
};

pub use xor::{MAX_XOR_SCAN_SIZE, extract_incremental_xor_strings};

// Internal — not part of the stable public API
pub(crate) use go::{
    GoStringExtractor, extract_null_separated_strings, extract_varint_prefixed_strings,
};
pub use overlay::extract_overlay_strings;
pub(crate) use rust::RustStringExtractor;
pub(crate) use stack_strings::{extract_stack_strings, extract_stack_strings_with_context};
pub use validation::{is_garbage, is_garbage_with_context, is_garbage_with_kind};

// Re-export goblin so library clients can parse binaries themselves
pub use goblin;
use goblin::Object;
use goblin::mach::MachO;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

// Import internal modules for use in this file
use binary::{
    collect_elf_section_info, collect_elf_segments, collect_macho_section_info,
    collect_macho_segments, collect_pe_section_info, elf_go_skip_ranges, macho_go_skip_ranges,
    macho_has_go_sections, pe_go_skip_ranges, pe_is_rust, pe_rust_skip_ranges,
};
use binary_net::scan_binary_ips;
use imports::{extract_elf_imports, extract_macho_imports, extract_pe_imports};
use raw::{extract_raw_strings, extract_wide_strings};

/// Extract stack strings from every executable section whose byte range is
/// given by `exec_ranges`.  Section ranges are parsed by
/// `binary::collect_*_section_info` and filtered to the executable ones.
///
/// This avoids feeding the entire file to iced-x86 — for a typical PE or
/// Mach-O only a small fraction is code, and disassembling `.rdata` /
/// `__LINKEDIT` as x86 is pure waste.  ELF already did this filtering
/// inline; this helper generalises the pattern so PE and Mach-O get the
/// same win.
fn extract_stack_strings_from_ranges(
    data: &[u8],
    min_length: usize,
    exec_ranges: &[(usize, usize)],
) -> Vec<ExtractedString> {
    if exec_ranges.is_empty() {
        return Vec::new();
    }
    exec_ranges
        .par_iter()
        .filter_map(|&(start, end)| {
            let end = end.min(data.len());
            if start >= end {
                return None;
            }
            let section_data = data.get(start..end)?;
            let mut results = extract_stack_strings(section_data, min_length);
            for r in &mut results {
                r.data_offset += start as u64;
            }
            Some(results)
        })
        .flatten()
        .collect()
}

/// Strip Go varint length-prefix bytes that bled into otherwise-clean strings.
///
/// Go's pclntab `pkgnamestab` packs entries as `<varint length byte><N bytes>`.
/// Raw printable scanners (including radare2's `izz`) capture the length byte
/// as the first character of the string. When the pattern is unambiguous —
/// the leading byte is a small printable value, equals the length of the
/// remainder, the remainder is all printable ASCII, and starts with a
/// module-path-like character — we strip the prefix in place.
fn strip_go_varint_prefixes(strings: &mut [ExtractedString]) {
    for s in strings.iter_mut() {
        let bytes = s.value.as_bytes();
        if bytes.len() < 6 {
            continue;
        }
        let prefix = bytes[0];
        // Only consider single-byte varint lengths (1..0x80) that are also
        // printable punctuation. Skip unambiguous separators like ' '.
        if !(0x21..0x7F).contains(&prefix) {
            continue;
        }
        let rest = &bytes[1..];
        if rest.len() != prefix as usize {
            continue;
        }
        // Tight predicate: rest must look like a Go package path or type name.
        // Starts with letter/underscore/* / [ / ( / .
        // Body: alnum + path/type punctuation only.
        let starts_ok = matches!(
            rest[0],
            b'a'..=b'z' | b'A'..=b'Z' | b'_' | b'*' | b'[' | b'(' | b'.'
        );
        if !starts_ok {
            continue;
        }
        let body_ok = rest.iter().all(|&b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'/' | b'.' | b'_' | b'-' | b'*' | b'[' | b']' | b'(' | b')' | b' '
                )
        });
        if !body_ok {
            continue;
        }
        // Module-path / Go-type heuristic: contains '/' or '.' (rules out
        // 33-letter random alphabet sequences).
        if !rest.iter().any(|&b| b == b'/' || b == b'.') {
            continue;
        }
        // Safe to strip in place: byte 0 is ASCII, so byte 1 is a char boundary.
        s.value.drain(..1);
        s.data_offset += 1;
    }
}

/// Returns `true` if a string should be kept when garbage filtering is enabled.
/// Encoded strings and special kinds are always kept regardless of content.
///
/// Runs `is_garbage_with_context` so architecture- and section-aware
/// filters (notably the x86 push/pop save-sequence detector) can scope
/// themselves to the right inputs. Kind, section, and arch all come
/// from the `ExtractedString` itself when known.
fn passes_garbage_filter(s: &ExtractedString, code_ranges: &[(usize, usize)]) -> bool {
    // Strings produced by our own decoders / deobfuscators are
    // *deliberately* surfaced — base64-decoded payloads, XOR-decrypted
    // C2 URLs, deobfuscated VBScript fragments, etc. The garbage
    // heuristic is meant to suppress raw-scan noise from binary
    // sections, not to second-guess the decoder pipeline. Without
    // this gate, decoded entries get reclassified by `classify_string`
    // on their *content* (e.g. obfuscated PowerShell with diacritic
    // letters), `kind` lands somewhere other than `Base64`, and the
    // `is_garbage_with_context` check below culls them — exactly the
    // payload bytes the caller asked us to decode.
    //
    // Limited to *deterministic transformation* methods (decode /
    // unobfuscate); raw scan variants like `RawScan` and `WideString` are
    // still subject to the garbage check.
    //
    // `StackString` is deliberately NOT exempt. Unlike the decoders above —
    // which reverse a known, reversible encoding and so produce trustworthy
    // output — stack-string extraction is a *heuristic* reconstruction of
    // bytes laid into a stack frame. It readily assembles junk (a block of
    // 0x3f stack fills becomes `????????`, register save patterns become
    // `wwwwwwww`). Exempting the whole method surfaced that noise whenever
    // the caller asked for filtering. Routing stack strings through
    // `is_garbage_with_context` (kind-aware: `StackString` is treated as
    // provenance, so real reconstructions still pass) drops the junk while
    // keeping genuine deobfuscated payloads. Raw mode (`filter_garbage`
    // off) never reaches this function, so it still surfaces every fragment.
    if matches!(
        s.method,
        StringMethod::Base64Decode
            | StringMethod::Base64ObfuscatedDecode
            | StringMethod::HexDecode
            | StringMethod::UrlDecode
            | StringMethod::UnicodeEscapeDecode
            | StringMethod::ScriptDecode
            | StringMethod::XorDecode
    ) {
        return true;
    }
    if matches!(
        s.kind,
        Some(StringKind::EntitlementsXml)
            | Some(StringKind::Section)
            | Some(StringKind::Base64)
            | Some(StringKind::Base32)
            | Some(StringKind::Base85)
            | Some(StringKind::HexEncoded)
            | Some(StringKind::UrlEncoded)
            | Some(StringKind::UnicodeEscaped)
            | Some(StringKind::XorKey)
    ) {
        return true;
    }
    // Derive the code-section flag from the offset: `code_ranges` are the
    // executable byte ranges (built once from section headers). Empty ranges
    // mean "no section info" → unknown. Replaces the per-string section name
    // that `ExtractedString` no longer carries.
    let in_code_section = if code_ranges.is_empty() {
        None
    } else {
        let off = usize::try_from(s.data_offset).unwrap_or(usize::MAX);
        Some(offset_in_ranges(off, code_ranges))
    };
    let ctx = crate::types::StringContext {
        kind: s.kind,
        in_code_section,
        // Arch hint was only ever stamped *after* this filter ran (or not at
        // all on the main path), so it was always `None` here in practice.
        arch: None,
    };
    !validation::is_garbage_with_context(&s.value, &ctx)
}

/// True if `offset` falls in any of the sorted, non-overlapping `ranges`.
fn offset_in_ranges(offset: usize, ranges: &[(usize, usize)]) -> bool {
    let i = ranges.partition_point(|&(start, _)| start <= offset);
    i > 0 && offset < ranges[i - 1].1
}

/// Merge a set of imports into the strings list.
/// Updates kind for strings already present, then appends new ones.
fn merge_imports(strings: &mut Vec<ExtractedString>, imports: Vec<ExtractedString>) {
    let import_map: HashMap<&str, Option<StringKind>> =
        imports.iter().map(|s| (s.value.as_str(), s.kind)).collect();
    for s in strings.iter_mut() {
        if let Some(&kind) = import_map.get(s.value.as_str()) {
            s.kind = kind;
        }
    }
    // Collect new imports first so that `seen` (which borrows `strings`) is
    // dropped before the mutable `strings.extend()` call below.
    let new_imports: Vec<_> = {
        let seen: HashSet<&str> = strings.iter().map(|s| s.value.as_str()).collect();
        imports
            .into_iter()
            .filter(|s| !seen.contains(s.value.as_str()))
            .collect()
    };
    strings.extend(new_imports);
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
    section_info: &HashMap<String, binary::SectionInfo>,
) -> Vec<ExtractedString> {
    let mut out = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for info in section_info.values() {
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
        for mut s in extract_raw_strings(
            section_bytes,
            min_length,
            Some(info.name.as_str()),
            segments,
            section_info,
            &[],
        ) {
            // The raw scanner offsets are relative to `section_bytes`; lift them
            // to the file by adding the section's file offset.
            s.data_offset += start as u64;
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

/// Run XOR scanning and extend `strings` with any decoded results.
///
/// `excluded_ranges` is a sorted list of `[start, end)` byte ranges the
/// scanner must skip. Callers with a parsed binary pass the file offsets of
/// executable sections — XOR-obfuscated strings don't live in `.text`, so
/// skipping those ranges cuts the scanned-byte count on a typical binary
/// by 60-80% with near-zero risk of missing legitimate hits.
fn apply_xor_scan(
    strings: &mut Vec<ExtractedString>,
    data: &[u8],
    opts: &ExtractOptions,
    is_pe: bool,
    excluded_ranges: &[(usize, usize)],
) {
    tracing::debug!(
        "apply_xor_scan: called (xor_scan: {}, xor_scan_multi: {})",
        opts.xor_scan,
        opts.xor_scan_multi
    );
    if data.is_empty() || opts.is_cancelled() {
        return;
    }

    // Text / script input: XOR obfuscation in source code is vanishingly rare,
    // and the scanner produces noise on long runs of printable bytes.  Only
    // skip on an *explicit* `FormatHint::Text` — auto-detection via
    // `is_text_file` would false-positive on mostly-printable XOR payloads
    // and regress test fixtures that use such shapes.  Callers with an
    // explicit xor_key bypass this — they know better.
    if opts.xor_key.is_none() && opts.format_hint == FormatHint::Text {
        tracing::debug!("Skipping XOR scan: text/script input (explicit hint)");
        return;
    }

    // Platform-signed binaries (Apple/Microsoft OS binaries) are vetted
    // upstream; malware-vs-legitimate single-byte XOR obfuscation never
    // survives platform signing. Skipping XOR on these is the single biggest
    // throughput win for typical system-binary corpora. Third-party
    // Developer ID signatures are NOT matched — those CAN be signed malware.
    // Users who passed an explicit xor_key or requested xorscan bypass this.
    if opts.xor_key.is_none() && !opts.xor_scan_multi && binary::is_platform_signed(data) {
        tracing::debug!("Skipping XOR scan: platform-signed binary");
        return;
    }

    let t_xor = std::time::Instant::now();

    // For PE binaries, also try rolling XOR with known plaintext patterns
    // This catches .NET malware like Redline that uses short cycling keys
    if is_pe && (opts.xor_scan || opts.xor_key.is_some()) && data.len() <= xor::MAX_XOR_SCAN_SIZE {
        let rolling_results = xor::extract_rolling_xor_with_known_plaintext(
            data,
            opts.xor_min_length,
            excluded_ranges,
        );
        strings.extend(rolling_results);
    }

    // Rizin string boundaries. Two sources, in preference order:
    //   1. Caller pre-populated via `ExtractOptions::with_rizin_boundaries`
    //      — set by expose when it ran rizin upstream. Skip the spawn.
    //   2. Standalone stng with `use_r2` on and an available path —
    //      spawn rizin in-process. This keeps stng usable as an
    //      independent CLI tool.
    let r2_boundaries = opts.rizin_boundaries.clone().or_else(|| {
        if opts.use_r2 {
            opts.path.as_deref().and_then(r2::extract_string_boundaries)
        } else {
            None
        }
    });

    if let Some(ref key) = opts.xor_key {
        let key_str = String::from_utf8_lossy(key);
        if let Some(ks) = strings.iter_mut().find(|s| s.value == key_str.as_ref()) {
            ks.kind = Some(StringKind::XorKey);
        }
        strings.extend(xor::extract_custom_xor_strings_with_hints(
            data,
            key,
            opts.xor_min_length,
            r2_boundaries.as_deref(),
            opts.filter_garbage,
            false, // User-provided key: disable early termination for complete extraction
        ));
    } else if opts.xor_scan {
        let auto_key = if data.len() <= xor::MAX_AUTO_DETECT_SIZE {
            xor::auto_detect_xor_key(data, strings, opts.xor_min_length)
        } else {
            None
        };
        if let Some((key, key_str, _)) = auto_key {
            // Mark ALL occurrences of the key string as XorKey. Fat binaries
            // contain the same string at multiple arch offsets; the value-dedup
            // in main.rs keeps whichever copy comes first, so every copy must
            // carry the XorKey kind to survive as the correct kind.
            let mut marked = false;
            for ks in strings.iter_mut().filter(|s| s.value == key_str) {
                ks.kind = Some(StringKind::XorKey);
                marked = true;
            }
            if !marked {
                tracing::warn!(
                    "XOR key '{}' not found in extracted strings — injecting",
                    key_str
                );
                strings.push(ExtractedString {
                    value: key_str.clone(),
                    data_offset: 0,
                    data_len: 0,
                    method: StringMethod::XorDecode,
                    kind: Some(StringKind::XorKey),
                    fragments: None,
                });
            }
            strings.extend(xor::extract_custom_xor_strings_with_hints(
                data,
                &key,
                opts.xor_min_length,
                r2_boundaries.as_deref(),
                opts.filter_garbage,
                false, // Even for auto-detected keys, extract completely for final results
            ));
        } else {
            let xor_results = xor::extract_xor_strings(data, opts.xor_min_length, is_pe);

            // Every `extract_xor_strings` result is a single-byte XOR decode, so
            // its key is recoverable from the data without a stored tag:
            // `value[0] == data[offset] ^ key`, hence `key = data[offset] ^ value[0]`
            // (holds for the wide/16LE path too — the first char's low byte).
            let xor_key_of = |r: &ExtractedString| -> Option<u8> {
                let off = usize::try_from(r.data_offset).ok()?;
                Some(data.get(off)? ^ r.value.as_bytes().first()?)
            };

            // If the pattern scan found 2+ strings encoded with the same single-byte key,
            // that key is in use throughout the binary. Do a full extraction pass so we
            // don't miss strings that lack a trigger pattern (e.g. syscall names, log paths).
            let mut key_counts: HashMap<u8, usize> = HashMap::new();
            for r in &xor_results {
                if let Some(k) = xor_key_of(r) {
                    *key_counts.entry(k).or_insert(0) += 1;
                }
            }
            // Track keys that received a full extraction pass — their AC scan results
            // are a strict subset and can be dropped to avoid redundant deduplication work.
            let mut fully_extracted_keys: HashSet<u8> = HashSet::new();
            for (key, count) in key_counts {
                if count >= 2 && !xor::SKIP_XOR_KEYS.contains(&key) {
                    let full = xor::extract_custom_xor_strings_with_hints(
                        data,
                        &[key],
                        opts.xor_min_length,
                        r2_boundaries.as_deref(),
                        opts.filter_garbage,
                        false,
                    );
                    strings.extend(full);
                    fully_extracted_keys.insert(key);
                }
            }

            // Skip AC-scan results for keys already covered by full extraction above.
            strings.extend(
                xor_results
                    .into_iter()
                    .filter(|r| xor_key_of(r).is_none_or(|k| !fully_extracted_keys.contains(&k))),
            );
        }

        // Always run incremental XOR detection if enabled - it might complement regular XOR
        let inc_results =
            xor::extract_incremental_xor_strings(data, opts.xor_min_length, excluded_ranges);
        strings.extend(inc_results);
    }

    if opts.xor_scan_multi {
        // Multikey XOR candidate harvesting. Caller-pre-populated
        // candidates (from expose's upstream rizin pass) win;
        // otherwise stng spawns rizin itself when `use_r2` is set
        // and a path is available — standalone CLI behaviour.
        let (candidates, path_for_verify) = if let Some(ref pre) = opts.rizin_xor_candidates {
            if pre.is_empty() {
                (None, opts.path.as_deref())
            } else {
                let mut c = strings.clone();
                c.extend(pre.clone());
                (Some(c), opts.path.as_deref())
            }
        } else if opts.use_r2 {
            if let Some(path) = opts.path.as_deref() {
                let mut c = strings.clone();
                c.extend(r2::extract_binary_xor_candidates(path, data));
                (Some(c), Some(path))
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };
        if let Some(candidates) = candidates {
            let verify_path = path_for_verify.unwrap_or("");
            let xor_keys = r2::verify_xor_keys(verify_path, data, &candidates);
            if !xor_keys.is_empty() {
                let decoded =
                    xor::extract_multikey_xor_strings(data, &xor_keys, opts.xor_min_length);
                strings.extend(decoded);
            }
        }
    }

    tracing::debug!("TIME: XOR key scanning took {:?}", t_xor.elapsed());
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
/// - CRL URLs: "http://crl.apple.com/codesigning.crl0"
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
        .find(|sh| elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("") == ".text")
        .and_then(|sh| {
            // u64→usize: lossless on 64-bit hosts (this tool targets 64-bit only)
            #[allow(clippy::cast_possible_truncation)]
            let start = sh.sh_offset as usize;
            #[allow(clippy::cast_possible_truncation)]
            let end = start.saturating_add(sh.sh_size as usize);
            let text = scan_data.get(start..end)?;
            Some((start, sh.sh_addr, text))
        })
    else {
        return Vec::new();
    };

    // Use the context-aware version to resolve RIP-relative XMM loads.
    let mut xor_results =
        extract_stack_strings_with_context(text, min_length, scan_data, text_vma, image_base);
    // Adjust data_offset to file-relative position.
    for r in &mut xor_results {
        r.data_offset += text_start as u64;
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

    let Ok(start) = usize::try_from(sh.sh_offset) else {
        return Vec::new();
    };
    let Ok(size) = usize::try_from(sh.sh_size) else {
        return Vec::new();
    };
    let end = start.saturating_add(size).min(scan_data.len());
    let Some(section_bytes) = scan_data.get(start..end) else {
        return Vec::new();
    };

    let t_pcln = std::time::Instant::now();
    // funcnametab is NUL-separated; pkgnamestab is varint-length-prefixed.
    // Scan for both concurrently — the varint pass is fully hidden behind the
    // larger funcname pass and recovers package paths the latter can't.
    let (varints, mut nulls) = rayon::join(
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

/// File-offset range(s) of the Mach-O `__LINKEDIT` segment (which holds the
/// code-signature blob). Returns one range for a thin binary and one per slice
/// for a fat binary; empty for non-Mach-O. Used to scope code-signature
/// reclassification by offset now that strings no longer carry a section name.
fn macho_linkedit_ranges(object: &Object<'_>) -> Vec<(u64, u64)> {
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
            let offsets: Vec<u64> = fat
                .iter_arches()
                .filter_map(std::result::Result::ok)
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

/// Clear IP/host classifications for strings that are VS_VERSION_INFO values.
///
/// FileVersion and ProductVersion commonly look like IP addresses (e.g. "18.0.0.23").
/// Goblin parses these fields directly, so we can suppress them precisely.
fn suppress_version_info_ips(strings: &mut [ExtractedString], pe: &goblin::pe::PE<'_>) {
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
        if matches!(s.kind, Some(StringKind::IP) | Some(StringKind::IPPort))
            && version_strings.iter().any(|v| v == &s.value)
        {
            tracing::debug!("Suppressing version-info false positive IP: {}", s.value);
            s.kind = None;
        }
    }
}
/// Hint about the input shape so stng can skip pointless work.
///
/// `Auto` (default) lets stng decide from the bytes. A caller that already knows
/// the input is text can pass `Text` to suppress expensive binary-only analyses
/// (XOR scan, stack strings) that produce nothing on text input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FormatHint {
    /// Let stng detect.
    #[default]
    Auto,
    /// Text / script — skip XOR scan and binary-only analyses.
    Text,
}

#[derive(Debug, Clone)]
pub struct ExtractOptions {
    /// Minimum string length to extract
    pub min_length: usize,
    /// Use radare2 for extraction (if available). Default: false for library use.
    pub use_r2: bool,
    /// Path to the binary file (required if `use_r2` is true)
    pub path: Option<String>,
    /// Pre-extracted strings from radare2 (allows clients to run r2 themselves)
    pub r2_strings: Option<Vec<ExtractedString>>,
    /// Filter out garbage strings (default: false for library, true for CLI)
    pub filter_garbage: bool,
    /// Enable XOR string detection (single-byte keys). Default: false.
    pub xor_scan: bool,
    /// Custom XOR key for decoding (overrides auto-detection if set).
    pub xor_key: Option<Vec<u8>>,
    /// Minimum length for XOR-decoded strings (default: 10).
    pub xor_min_length: usize,
    /// Enable advanced multi-byte XOR scanning with radare2/rizin (slow). Default: false.
    pub xor_scan_multi: bool,
    /// Use r2 result caching (default: true). Disable with --no-cache flag.
    pub use_cache: bool,
    /// Skip stng's native import/export/symbol extraction. Default: false.
    ///
    /// Set this when the caller already parses the binary's symbol tables
    /// itself (e.g. filefacts' `extract_symbols`) so the work isn't done
    /// twice. stng emits no value back here because it only *produces*
    /// symbol names — it doesn't consume them for string extraction — so the
    /// efficient hint is suppression, not a data feed (unlike the rizin
    /// fields below, whose data stng actually uses). Symbol names still
    /// surface as raw `__LINKEDIT` / `.rdata` scan hits; only the structured,
    /// typed import/export pass is skipped.
    pub caller_provides_symbols: bool,
    /// Cancellation flag checked at phase boundaries (start of extraction,
    /// before XOR scan, between decoder passes).  When the flag becomes
    /// `true`, extraction returns whatever it has so far.
    pub cancel: Option<Arc<AtomicBool>>,
    /// Hint about the input so stng can skip analyses that will produce
    /// nothing on that shape of input.  See `FormatHint` for the semantics.
    pub format_hint: FormatHint,
    /// Pre-extracted rizin string boundaries. When set, stng uses these
    /// to constrain the XOR scan instead of spawning rizin to run
    /// `izj`. Part of the Wave A cleave→expose rizin migration: lets
    /// the caller (expose) own the rizin invocation and feed the
    /// resulting metadata down into stng without a second subprocess.
    pub rizin_boundaries: Option<Vec<r2::StringBoundary>>,
    /// Pre-extracted connect-address strings (sockaddr_in literals
    /// resolved through rizin's disassembly walker). When set, stng
    /// merges these into the output instead of spawning rizin to
    /// reproduce the walk.
    pub rizin_connect_addrs: Option<Vec<ExtractedString>>,
    /// Pre-extracted XOR key candidates from rizin's instruction-
    /// pattern walker. When set, stng skips the
    /// `extract_binary_xor_candidates` spawn.
    pub rizin_xor_candidates: Option<Vec<ExtractedString>>,
}

impl Default for ExtractOptions {
    fn default() -> Self {
        Self::new(4)
    }
}

impl ExtractOptions {
    #[must_use]
    pub fn new(min_length: usize) -> Self {
        Self {
            min_length,
            use_r2: false,
            path: None,
            r2_strings: None,
            filter_garbage: false,
            xor_scan: false,
            xor_key: None,
            xor_min_length: xor::DEFAULT_XOR_MIN_LENGTH,
            xor_scan_multi: false,
            use_cache: true,
            caller_provides_symbols: false,
            cancel: None,
            format_hint: FormatHint::Auto,
            rizin_boundaries: None,
            rizin_connect_addrs: None,
            rizin_xor_candidates: None,
        }
    }

    /// Supply pre-extracted rizin string boundaries. Wave A of the
    /// cleave→expose rizin migration: callers (notably expose) run
    /// rizin once and feed the resulting metadata down into stng so
    /// stng doesn't have to re-spawn for the same binary. Setting
    /// this disables stng's internal `extract_string_boundaries`
    /// spawn.
    #[must_use]
    pub fn with_rizin_boundaries(mut self, b: Vec<r2::StringBoundary>) -> Self {
        self.rizin_boundaries = Some(b);
        self
    }

    /// Supply pre-extracted connect-address strings (sockaddr_in
    /// literals recovered from rizin's disassembly walker). Replaces
    /// stng's internal `extract_connect_addrs` spawn.
    #[must_use]
    pub fn with_rizin_connect_addrs(mut self, c: Vec<ExtractedString>) -> Self {
        self.rizin_connect_addrs = Some(c);
        self
    }

    /// Supply pre-extracted XOR key candidates from rizin's
    /// instruction-pattern walker. Replaces stng's internal
    /// `extract_binary_xor_candidates` spawn.
    #[must_use]
    pub fn with_rizin_xor_candidates(mut self, x: Vec<ExtractedString>) -> Self {
        self.rizin_xor_candidates = Some(x);
        self
    }

    /// Set the binary path and enable radare2-assisted extraction.
    #[must_use]
    pub fn with_r2(mut self, path: &str) -> Self {
        self.use_r2 = true;
        self.path = Some(path.to_string());
        self
    }

    /// Provide pre-extracted r2 strings instead of running r2 internally.
    /// This allows library clients to run r2 themselves and pass the results.
    #[must_use]
    pub fn with_r2_strings(mut self, strings: Vec<ExtractedString>) -> Self {
        self.r2_strings = Some(strings);
        self
    }

    /// Enable garbage filtering to remove noise strings.
    /// Default is false for library use to give clients full control.
    #[must_use]
    pub fn with_garbage_filter(mut self, enable: bool) -> Self {
        self.filter_garbage = enable;
        self
    }

    /// Enable XOR string detection with optional custom minimum length.
    /// This scans for strings obfuscated with single-byte XOR keys (0x01-0xFF).
    /// Default minimum length is 10 characters.
    #[must_use]
    pub fn with_xor(mut self, min_length: Option<usize>) -> Self {
        self.xor_scan = true;
        if let Some(len) = min_length {
            self.xor_min_length = len;
        }
        self
    }

    /// Specify a custom XOR key for decoding.
    /// The key can be single-byte or multi-byte and will be applied to all byte streams.
    /// This overrides automatic XOR detection when set.
    #[must_use]
    pub fn with_xor_key(mut self, key: Vec<u8>) -> Self {
        self.xor_key = Some(key);
        self
    }

    /// Enable advanced multi-byte XOR scanning with radare2/rizin.
    /// This is slower but can detect complex multi-byte XOR obfuscation.
    /// Requires radare2 or rizin to be installed.
    #[must_use]
    pub fn with_xorscan(mut self, enable: bool) -> Self {
        self.xor_scan_multi = enable;
        self
    }

    /// Control r2/rizin result caching.
    /// Default is true. Disable with --no-cache flag.
    #[must_use]
    pub fn with_cache(mut self, use_cache: bool) -> Self {
        self.use_cache = use_cache;
        self
    }

    /// Skip native import/export/symbol extraction because the caller already
    /// parses the symbol tables itself. See [`ExtractOptions::caller_provides_symbols`].
    #[must_use]
    pub fn with_caller_provides_symbols(mut self, provided: bool) -> Self {
        self.caller_provides_symbols = provided;
        self
    }

    /// Install a cancellation flag.
    ///
    /// stng checks the flag at phase boundaries (start of extraction, before
    /// XOR scan, between decoder passes).  When the flag flips to `true`,
    /// extraction returns whatever has been produced so far.
    #[must_use]
    pub fn with_cancellation(mut self, cancel: Arc<AtomicBool>) -> Self {
        self.cancel = Some(cancel);
        self
    }

    /// Supply a hint about the input shape.
    ///
    /// `FormatHint::Text` skips the XOR scan and other binary-only analyses,
    /// which is a large win for callers that run stng over directories of
    /// scripts / minified JS / office documents.
    #[must_use]
    pub fn with_format_hint(mut self, hint: FormatHint) -> Self {
        self.format_hint = hint;
        self
    }

    /// Returns true if a cancellation flag was installed and has flipped.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancel
            .as_ref()
            .is_some_and(|c| c.load(Ordering::Relaxed))
    }
}

/// Extract strings from binary data using multiple techniques.
///
/// This is the primary entry point for language-aware string extraction from
/// compiled binaries. It automatically detects the binary format and language,
/// then applies appropriate extraction techniques.
///
/// # Arguments
///
/// * `data` - The raw binary data to analyze
/// * `min_length` - Minimum string length to extract (typically 4-8)
///
/// # Returns
///
/// A vector of extracted strings with metadata about where they were found,
/// how they were extracted, and semantic classification.
///
/// # Examples
///
/// ```no_run
/// use stng::extract_strings;
///
/// let data = std::fs::read("/bin/ls").unwrap();
/// let strings = extract_strings(&data, 4);
///
/// for s in strings.iter().take(10) {
///     println!("{:?}: {}", s.kind, s.value);
/// }
/// ```
#[must_use]
pub fn extract_strings(data: &[u8], min_length: usize) -> Vec<ExtractedString> {
    extract_strings_with_options(data, &ExtractOptions::new(min_length))
}

/// Apply every string decoder (base64, embedded base64, fuzzy base64, base32,
/// base85, hex, URL, and unicode-escape) to already-extracted strings and return
/// the newly decoded results.
///
/// Decoding runs on the *text* of each string, so it is filetype-agnostic: the
/// same pass that recovers base64-encoded PowerShell from a PE also recovers a
/// base64-over-UTF-16LE blob sitting in a plain `.txt` or `.json`. Both the
/// internal extraction pipeline and the CLI's line-based text path funnel through
/// here so coverage stays identical across inputs.
#[must_use]
pub fn decode_encoded_strings(strings: &[ExtractedString]) -> Vec<ExtractedString> {
    let mut decoded = Vec::new();
    decoded.extend(decoders::decode_base64_strings(strings));
    decoded.extend(decoders::extract_embedded_base64(strings));
    decoded.extend(fuzzy_base64::extract_fuzzy_base64(strings));
    decoded.extend(decoders::decode_base32_strings(strings));
    decoded.extend(decoders::decode_base85_strings(strings));
    decoded.extend(decoders::decode_hex_strings(strings));
    decoded.extend(decoders::decode_url_strings(strings));
    decoded.extend(decoders::decode_unicode_escape_strings(strings));
    decoded
}

/// Decode spaced ASCII strings in place.
///
/// This handles strings like "V a r F i l e I n f o" -> "VarFileInfo"
/// which are common in PE resource sections and .NET metadata.
/// Strings that weren't already decoded during extraction are decoded here.
fn decode_spaced_strings(strings: &mut Vec<ExtractedString>, min_length: usize) {
    use std::collections::HashSet;
    let mut seen: HashSet<String> = HashSet::new();
    let mut new_strings = Vec::new();

    for s in strings.iter_mut() {
        // Skip strings already marked as SpacedAscii
        if s.method == StringMethod::SpacedAscii {
            seen.insert(s.value.clone());
            continue;
        }

        // Try to decode as spaced ASCII
        if let Some(decoded) = r2::decode_spaced_ascii(&s.value)
            && decoded.len() >= min_length
            && !seen.contains(&decoded)
        {
            seen.insert(decoded.clone());

            // Create a new decoded string entry
            let kind = classifier::classify_string(&decoded);
            new_strings.push(ExtractedString {
                value: decoded,
                data_offset: s.data_offset,
                data_len: 0,
                method: StringMethod::SpacedAscii,
                kind,
                ..Default::default()
            });
        }
    }

    strings.extend(new_strings);
}

/// Deduplicate strings by keeping only the best string at each offset.
///
/// Uses a single in-place sort + `dedup_by_key` pass — no HashMap allocation.
/// The sort key is `(offset asc, priority desc, length desc)` so the first
/// entry at each offset is the best candidate and `dedup_by_key(data_offset)`
/// keeps it.  Best candidate = highest `StringMethod::dedup_priority`, tied
/// with longer `value`.
fn deduplicate_by_offset(mut strings: Vec<ExtractedString>) -> Vec<ExtractedString> {
    if strings.len() < 2 {
        return strings;
    }

    strings.sort_unstable_by(|a, b| {
        a.data_offset
            .cmp(&b.data_offset)
            .then_with(|| {
                // Descending priority: higher priority first.
                b.method.dedup_priority().cmp(&a.method.dedup_priority())
            })
            .then_with(|| {
                // Descending length: longer first.
                b.value.len().cmp(&a.value.len())
            })
    });

    // Every offset is file-relative (Mach-O section/VA offsets are rebased at the
    // source), so a file offset names exactly one location: keying the dedup on
    // the offset alone collapses true duplicates without the section tag that a
    // section-relative layout once needed to avoid cross-section `:0` collisions.
    strings.dedup_by(|a, b| a.data_offset == b.data_offset);
    strings
}

/// Extract strings from a UTF-16 encoded file (detected by BOM).
///
/// When a UTF-16 BOM is detected at the start of a file, this function:
/// 1. Decodes the entire file from UTF-16 to UTF-8
/// 2. Extracts strings from the decoded UTF-8 content
/// 3. Marks all strings with the appropriate StringMethod (Utf16LeDecode or Utf16BeDecode)
///
/// This is common for JavaScript malware, PowerShell scripts, and other text files
/// saved in UTF-16 encoding on Windows systems.
fn extract_from_utf16_file(
    data: &[u8],
    opts: &ExtractOptions,
    is_little_endian: bool,
) -> Vec<ExtractedString> {
    let mut strings = Vec::new();

    // Skip the 2-byte BOM and decode the rest
    if data.len() < 2 {
        return strings;
    }

    let utf16_data = &data[2..];

    // Convert bytes to u16 code units
    if !utf16_data.len().is_multiple_of(2) {
        // Odd number of bytes - can't be valid UTF-16, truncate last byte
        tracing::warn!("UTF-16 file has odd byte count, truncating last byte");
    }

    // Decode UTF-16 to UTF-8, streaming code units straight from the byte
    // slice so the whole-file Vec<u16> intermediate is never materialized.
    let code_units = utf16_data.chunks_exact(2).map(|chunk| {
        if is_little_endian {
            u16::from_le_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], chunk[1]])
        }
    });
    let decoded: String = char::decode_utf16(code_units)
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect();
    let decoded_bytes = decoded.as_bytes();

    // Extract strings from the decoded UTF-8 content
    let mut raw_strings = extract_raw_strings(
        decoded_bytes,
        opts.min_length,
        None,
        &[],
        &HashMap::new(),
        &[],
    );

    // Apply decoders (base64, hex, URL-encoding, etc.) to the extracted strings
    // This allows us to find base64-encoded PowerShell, hex-encoded URLs, etc.
    let decoded_strings = decode_encoded_strings(&raw_strings);

    // Update the method for all extracted strings to indicate they came from UTF-16 decoding
    // (but preserve the method for decoded strings - they should show Base64Decode, etc.)
    let method = if is_little_endian {
        StringMethod::Utf16LeDecode
    } else {
        StringMethod::Utf16BeDecode
    };

    for string in &mut raw_strings {
        string.method = method;
    }

    strings.extend(raw_strings);
    strings.extend(decoded_strings);

    deduplicate_by_offset(strings)
}

/// Run script deobfuscation and append decoded strings.
///
/// Detects Python/JS/PHP/PowerShell obfuscation patterns in text data,
/// decodes hidden payloads, extracts strings from them, and appends
/// them to the existing string list with `ScriptDecode` method.
fn append_script_deobfuscation(
    strings: &mut Vec<ExtractedString>,
    data: &[u8],
    opts: &ExtractOptions,
) {
    let deob_results = script::deobfuscate_script(data);
    for result in deob_results {
        let payload_bytes = result.decoded.as_bytes();
        let mut payload_strings = extract_raw_strings(
            payload_bytes,
            opts.min_length,
            None,
            &[],
            &HashMap::new(),
            &[],
        );

        // Run decoders on the extracted payload strings
        let mut payload_decoded = Vec::new();
        payload_decoded.extend(decoders::decode_base64_strings(&payload_strings));
        payload_decoded.extend(decoders::extract_embedded_base64(&payload_strings));
        payload_decoded.extend(decoders::decode_hex_strings(&payload_strings));
        payload_decoded.extend(decoders::decode_url_strings(&payload_strings));
        payload_decoded.extend(decoders::decode_unicode_escape_strings(&payload_strings));
        payload_strings.extend(payload_decoded);

        // Mark all strings as ScriptDecode with provenance.
        // Use a high base offset to avoid collisions with raw-scan strings from
        // the original file during deduplication.
        let base_offset = data.len() as u64 + 1 + result.offset as u64;
        for s in &mut payload_strings {
            s.method = StringMethod::ScriptDecode;
            s.kind = classifier::classify_string(&s.value);
            s.data_offset += base_offset;
        }

        strings.extend(payload_strings);
    }
}

/// Extract strings with additional options.
///
/// Provides fine-grained control over the extraction process through the
/// `ExtractOptions` builder pattern.
///
/// # Arguments
///
/// * `data` - The raw binary data to analyze
/// * `opts` - Extraction options (min length, filters, external tool integration)
///
/// # Examples
///
/// ```
/// use stng::{extract_strings_with_options, ExtractOptions};
///
/// let data = std::fs::read("/bin/ls").unwrap();
/// let opts = ExtractOptions::new(4)
///     .with_garbage_filter(true);
/// let strings = extract_strings_with_options(&data, &opts);
/// ```
#[must_use]
pub fn extract_strings_with_options(data: &[u8], opts: &ExtractOptions) -> Vec<ExtractedString> {
    extract_strings_inner(data, opts)
}

fn extract_strings_inner(data: &[u8], opts: &ExtractOptions) -> Vec<ExtractedString> {
    // Fast-fail on already-cancelled callers.
    if opts.is_cancelled() {
        return Vec::new();
    }

    // Check for UTF-16 BOM first, before trying to parse as a binary format
    // This ensures text files with UTF-16 encoding are handled correctly
    if data.len() >= 2 {
        let has_utf16le_bom = data[0] == 0xFF && data[1] == 0xFE;
        let has_utf16be_bom = data[0] == 0xFE && data[1] == 0xFF;

        if has_utf16le_bom || has_utf16be_bom {
            return extract_from_utf16_file(data, opts, has_utf16le_bom);
        }
    }

    // Route binary objects we actually understand through the goblin
    // path; treat everything else (parse error *or* `Object::Unknown` —
    // goblin's "this magic isn't a binary I recognise" catchall) as a
    // raw / text input.
    //
    // Without this, ZIP-prefixed scripts, polyglots, and any
    // text-with-trailing-binary file land on the goblin branch (which
    // gates encoded-string decoding behind `is_text_file`) and the
    // base64 / hex / url decoders never run on the script payload.
    // Goblin's binary extractors have nothing useful to say about an
    // `Object::Unknown` anyway, so the only thing the goblin branch
    // contributes there is the gate that breaks decoding.
    let parsed_binary = match Object::parse(data) {
        Ok(obj) if !matches!(obj, Object::Unknown(_)) => Some(obj),
        _ => None,
    };

    if let Some(object) = parsed_binary {
        let t0 = std::time::Instant::now();
        let mut strings = extract_from_object(&object, data, opts);
        tracing::debug!("TIME: Extraction took {:?}", t0.elapsed());

        // For text files parsed by goblin (e.g. as Unknown), also run script deobfuscation
        if is_text_file(data) {
            append_script_deobfuscation(&mut strings, data, opts);
        }

        deduplicate_by_offset(strings)
    } else {
        // Unknown format - use r2 if available, plus raw scan
        let mut strings = Vec::new();
        if let Some(r2_strings) = get_r2_strings(opts) {
            strings.extend(r2_strings);
        }

        // Check if this looks like a PE (MZ header) even if goblin failed to parse
        let is_pe = data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A;

        // Extract wide strings for PE-like files (common in Windows binaries)
        if is_pe && !data.is_empty() {
            strings.extend(extract_wide_strings(
                data,
                opts.min_length,
                None,
                &[],
                &HashMap::new(),
                &[],
            ));
        }

        // Raw scan for all unknown formats (r2 strings complement, not replace)
        if !data.is_empty() {
            strings.extend(extract_raw_strings(
                data,
                opts.min_length,
                None,
                &[],
                &HashMap::new(),
                &[],
            ));
        }

        // Extract binary network data (IPs and ports in network byte order)
        // For unknown formats, use 0 (not M68000) to process normally
        strings.extend(scan_binary_ips(data, opts.min_length, 0, None, None));
        strings.extend(extract_stack_strings(data, opts.min_length));

        // Trigger XOR scan even for unknown formats if requested
        if opts.xor_scan || opts.xor_scan_multi || opts.xor_key.is_some() {
            apply_xor_scan(&mut strings, data, opts, is_pe, &[]);
        }

        // Decode encoded strings (base64, hex, URL-encoding, unicode escapes).
        // Check cancellation between passes so a large script/unknown blob
        // can be interrupted without running every decoder to completion.
        let mut decoded = Vec::new();
        if !opts.is_cancelled() {
            decoded.extend(decoders::decode_base64_strings(&strings));
            decoded.extend(decoders::extract_embedded_base64(&strings));
            decoded.extend(fuzzy_base64::extract_fuzzy_base64(&strings));
        }
        if !opts.is_cancelled() {
            decoded.extend(decoders::decode_base32_strings(&strings));
            decoded.extend(decoders::decode_base85_strings(&strings));
            decoded.extend(decoders::decode_hex_strings(&strings));
        }
        if !opts.is_cancelled() {
            decoded.extend(decoders::decode_url_strings(&strings));
            decoded.extend(decoders::decode_unicode_escape_strings(&strings));
        }
        strings.extend(decoded);

        // Decode spaced ASCII strings (common in PE .rsrc, .NET metadata)
        decode_spaced_strings(&mut strings, opts.min_length);

        // Script deobfuscation for text files that didn't parse as a known binary format
        if is_text_file(data) {
            append_script_deobfuscation(&mut strings, data, opts);
        }

        // Unknown format — no section info; full-file scan is acceptable
        // because we couldn't identify code regions to skip.
        if opts.xor_scan || opts.xor_scan_multi || opts.xor_key.is_some() {
            apply_xor_scan(&mut strings, data, opts, is_pe, &[]);
        }
        if opts.filter_garbage {
            strings.retain(|s| passes_garbage_filter(s, &[]));
        }

        deduplicate_by_offset(strings)
    }
}

/// Extract strings from binary data using a caller-supplied parsed goblin object.
///
/// Library callers (e.g. cleave) that have already called `goblin::Object::parse`
/// for their own analysis can pass the result here to avoid stng re-parsing.
///
/// The function routes through the same internal pipeline as
/// `extract_strings_with_options`, honouring cancellation and format-hint
/// options.  For text / unknown inputs callers should use
/// `extract_strings_with_options` instead — this entry point assumes the
/// caller has a valid `Object`.
#[must_use]
pub fn extract_strings_from_object(
    object: &Object<'_>,
    data: &[u8],
    opts: &ExtractOptions,
) -> Vec<ExtractedString> {
    if opts.is_cancelled() {
        return Vec::new();
    }
    // `Object::Unknown` means goblin saw no recognised binary magic —
    // the caller passed in a non-binary (text, polyglot, unfamiliar
    // container). The goblin branch has nothing to extract from such
    // inputs, and skipping the raw / decoder pipeline here would mean
    // base64-encoded payloads in the body never get decoded. Defer to
    // the main entry point's unknown-format branch instead. The extra
    // `Object::parse` call inside is one header read; the alternative
    // (duplicating ~80 lines of decoder pipeline here) is the kind of
    // drift that creates exactly the bug we're fixing.
    if matches!(object, Object::Unknown(_)) {
        return extract_strings_inner(data, opts);
    }
    let mut strings = extract_from_object(object, data, opts);
    if is_text_file(data) {
        append_script_deobfuscation(&mut strings, data, opts);
    }
    deduplicate_by_offset(strings)
}

/// Extract strings from a pre-parsed binary object.
///
/// Dispatches to the appropriate language-aware extractor based on the binary format
/// (Mach-O, ELF, PE) and detected language (Go, Rust, unknown). Runs XOR scanning,
/// stack string extraction, import enrichment, and section enrichment after the
/// primary extraction pass.
fn extract_from_object(
    object: &Object<'_>,
    data: &[u8],
    opts: &ExtractOptions,
) -> Vec<ExtractedString> {
    let min_length = opts.min_length;
    let mut strings = Vec::new();
    // Track if this is a Go binary - skip XOR scanning for Go (rarely obfuscated)
    let mut is_go_binary = false;
    // Section metadata: computed once by whichever format branch runs below and
    // reused for the XOR exclusion ranges at the end (was recomputed there).
    let mut section_info = std::collections::HashMap::new();

    match object {
        Object::Mach(goblin::mach::Mach::Binary(macho)) => {
            let segments = collect_macho_segments(macho);
            section_info = collect_macho_section_info(macho);
            if macho_has_go_sections(macho) {
                is_go_binary = true;
                let extractor = GoStringExtractor::new(min_length);
                // Thin binary: the slice is the whole file, so no slice base.
                strings.extend(extractor.extract_macho(macho, 0));

                // Raw scan fallback for Go shared libraries / cgo binaries.
                // Skip raw-scanning the Go string-blob sections — strings there
                // are packed back-to-back without null terminators, so a raw
                // scan emits the entire blob as one merged garbage string. The
                // structure-based + inline-pattern extractors already cover
                // these regions with correct boundaries.
                let skip = macho_go_skip_ranges(macho);
                let new_raw: Vec<_> = {
                    let known: HashSet<&str> = strings.iter().map(|s| s.value.as_str()).collect();
                    extract_raw_strings(data, min_length, None, &segments, &section_info, &skip)
                        .into_iter()
                        .filter(|s| !known.contains(s.value.as_str()))
                        .collect()
                };
                strings.extend(new_raw);
            } else if binary::macho_is_rust(macho) {
                let extractor = RustStringExtractor::new(min_length);
                // Thin binary: the slice is the whole file, so no slice base.
                strings.extend(extractor.extract_macho(macho, 0));
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
                        .chain(extract_raw_strings(
                            data,
                            min_length,
                            None,
                            &segments,
                            &section_info,
                            &[],
                        ))
                        .filter(|s| {
                            !known.contains(s.value.as_str()) && seen.insert(s.value.clone())
                        })
                        .collect()
                };
                strings.extend(extra);
            }
            if !is_go_binary {
                // Only disassemble executable sections — feeding the whole
                // Mach-O to iced-x86 wastes cycles on __LINKEDIT and
                // non-code segments.
                let exec_ranges = binary::code_ranges_from_sections(&section_info);
                strings.extend(extract_stack_strings_from_ranges(
                    data,
                    min_length,
                    &exec_ranges,
                ));
                strings.extend(arm64_stack_xor::extract_arm64_stack_xor_strings(
                    macho, data, 0, min_length,
                ));
            }
            if !opts.caller_provides_symbols {
                merge_imports(&mut strings, extract_macho_imports(macho, min_length));
            }
            apply_entitlements(&mut strings, macho, data, min_length);
        }
        Object::Mach(goblin::mach::Mach::Fat(fat)) => {
            // Fat binary - check for Go/Rust first
            let mut is_go = false;
            let mut is_rust = false;
            let mut segments = Vec::new();
            let mut section_info = std::collections::HashMap::new();
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
                    let slice_base = arch_offsets.get(idx).copied().unwrap_or(0);
                    segments = collect_macho_segments(&macho);
                    section_info = collect_macho_section_info(&macho);
                    if macho_has_go_sections(&macho) {
                        is_go = true;
                        is_go_binary = true;
                        let extractor = GoStringExtractor::new(min_length);
                        strings.extend(extractor.extract_macho(&macho, slice_base));

                        // See macho_has_go_sections branch above for why we
                        // skip-scan the Go string-blob sections.
                        let skip = macho_go_skip_ranges(&macho);
                        let new_raw: Vec<_> = {
                            let known: HashSet<&str> =
                                strings.iter().map(|s| s.value.as_str()).collect();
                            extract_raw_strings(
                                data,
                                min_length,
                                None,
                                &segments,
                                &section_info,
                                &skip,
                            )
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
                    break;
                }
            }
            // For non-Go/non-Rust fat binaries, use r2 if available + raw scan
            if !is_go && !is_rust {
                if let Some(r2_strings) = get_r2_strings(opts) {
                    strings.extend(r2_strings);
                }
                // Also do raw scan to catch anything r2 missed
                strings.extend(extract_raw_strings(
                    data,
                    min_length,
                    None,
                    &segments,
                    &section_info,
                    &[],
                ));
            }
            if !is_go_binary {
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
                        strings.extend(arm64_stack_xor::extract_arm64_stack_xor_strings(
                            &macho,
                            arch_data,
                            u64::from(arch.offset),
                            min_length,
                        ));
                    }
                }
            }
            if let Some(ref macho) = first_macho {
                if !opts.caller_provides_symbols {
                    merge_imports(&mut strings, extract_macho_imports(macho, min_length));
                }
                apply_entitlements(&mut strings, macho, data, min_length);
            }
        }
        Object::Elf(elf) => {
            let segments = collect_elf_segments(elf);
            section_info = collect_elf_section_info(elf);

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

            // Check for Rust (presence of rust metadata or panic strings)
            let has_rust = elf.section_headers.iter().any(|sh| {
                let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
                name.contains("rust") || name == ".rustc"
            });

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
                let (go_strings, (pcln_res, (raw_all, (wide_res, (ip_res, stack_res))))) =
                    rayon::join(
                        || GoStringExtractor::new(min_length).extract_elf(elf, scan_data),
                        || {
                            rayon::join(
                                || extract_elf_pclntab_strings(elf, scan_data, min_length),
                                || {
                                    rayon::join(
                                        || {
                                            extract_raw_strings(
                                                scan_data,
                                                min_length,
                                                None,
                                                &segments,
                                                &section_info,
                                                &skip,
                                            )
                                        },
                                        || {
                                            rayon::join(
                                                || {
                                                    extract_wide_strings(
                                                        scan_data,
                                                        min_length,
                                                        None,
                                                        &segments,
                                                        &section_info,
                                                        &skip,
                                                    )
                                                },
                                                || {
                                                    rayon::join(
                                                        || {
                                                            scan_binary_ips(
                                                                scan_data,
                                                                min_length,
                                                                elf.header.e_machine,
                                                                Some(elf),
                                                                None,
                                                            )
                                                        },
                                                        || {
                                                            extract_go_text_xor_strings(
                                                                elf, scan_data, min_length,
                                                            )
                                                        },
                                                    )
                                                },
                                            )
                                        },
                                    )
                                },
                            )
                        },
                    );
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
            } else {
                // Unknown ELF (C, C++, assembly, etc.) - use r2 if available + raw scan.
                if let Some(r2_strings) = get_r2_strings(opts) {
                    strings.extend(r2_strings);
                }
                strings.extend(extract_raw_strings(
                    scan_data,
                    min_length,
                    None,
                    &segments,
                    &section_info,
                    &[],
                ));
            }

            // Wide strings, network IPs, and stack strings for non-Go ELF.
            // Go ELF runs these concurrently with its raw-string fallback above.
            if !is_go_binary {
                // Extract UTF-16LE wide strings (less common in ELF but can
                // occur, especially in malware).
                strings.extend(extract_wide_strings(
                    scan_data,
                    min_length,
                    None,
                    &segments,
                    &section_info,
                    &[],
                ));

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
                let results: Vec<ExtractedString> = elf
                    .section_headers
                    .par_iter()
                    .filter(|sh| {
                        sh.sh_flags & u64::from(goblin::elf::section_header::SHF_EXECINSTR) != 0
                    })
                    .filter_map(|sh| {
                        // u64→usize: lossless on 64-bit hosts (this tool targets 64-bit only)
                        #[allow(clippy::cast_possible_truncation)]
                        let start = sh.sh_offset as usize;
                        #[allow(clippy::cast_possible_truncation)]
                        let end = start.saturating_add(sh.sh_size as usize);
                        scan_data.get(start..end).map(|text| {
                            let mut results = extract_stack_strings(text, min_length);
                            for r in &mut results {
                                r.data_offset += start as u64;
                            }
                            results
                        })
                    })
                    .flatten()
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
        }
        Object::PE(pe) => {
            // Collect PE section names and metadata
            let segments: Vec<String> = pe
                .sections
                .iter()
                .map(|sec| binary::pe_section_name(&sec.name))
                .collect();
            section_info = collect_pe_section_info(pe);

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
                    let Some(start) = usize::try_from(sec.pointer_to_raw_data).ok() else {
                        continue;
                    };
                    let Some(size) = usize::try_from(sec.size_of_raw_data).ok() else {
                        continue;
                    };
                    let end = start.saturating_add(size).min(data.len());
                    if start >= end {
                        continue;
                    }
                    let section_bytes = &data[start..end];
                    let (varints, nulls) = rayon::join(
                        || {
                            extract_varint_prefixed_strings(
                                section_bytes,
                                start as u64,
                                Some(name.as_str()),
                                min_length,
                            )
                        },
                        || {
                            extract_null_separated_strings(
                                section_bytes,
                                start as u64,
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

            let (
                (us_strings, r2_strings),
                (wide_strings, (net_strings, (raw_strings, stack_strings))),
            ) = rayon::join(
                || {
                    rayon::join(
                        || dotnet::extract_us_heap_strings(pe, data, min_length),
                        || get_r2_strings(opts).unwrap_or_default(),
                    )
                },
                || {
                    rayon::join(
                        || {
                            extract_wide_strings(
                                data,
                                min_length,
                                None,
                                &segments,
                                &section_info,
                                &pe_skip,
                            )
                        },
                        || {
                            rayon::join(
                                || {
                                    scan_binary_ips(
                                        data,
                                        min_length,
                                        pe.header.coff_header.machine,
                                        None,
                                        Some(pe),
                                    )
                                },
                                || {
                                    rayon::join(
                                        || {
                                            extract_raw_strings(
                                                data,
                                                min_length,
                                                None,
                                                &segments,
                                                &section_info,
                                                &pe_skip,
                                            )
                                        },
                                        || {
                                            // Only disassemble executable
                                            // sections — `.rdata` / `.rsrc`
                                            // / other non-code PE sections
                                            // would waste iced-x86 cycles.
                                            // Go PE binaries also need this:
                                            // dynamically-resolved Win32 APIs
                                            // are written via successive
                                            // `mov reg, imm64; mov [rsp+N], reg`
                                            // and only emerge as full names
                                            // when those writes are merged.
                                            let exec_ranges =
                                                binary::code_ranges_from_sections(&section_info);
                                            extract_stack_strings_from_ranges(
                                                data,
                                                min_length,
                                                &exec_ranges,
                                            )
                                        },
                                    )
                                },
                            )
                        },
                    )
                },
            );

            strings.extend(us_strings);
            strings.extend(r2_strings);
            strings.extend(wide_strings);
            strings.extend(net_strings);
            strings.extend(raw_strings);
            strings.extend(stack_strings);

            // Recover imports/exports from the PE directories — names behind RVA
            // tables that a raw byte scan can't reach (the radare2-only gap).
            if !opts.caller_provides_symbols {
                merge_imports(&mut strings, extract_pe_imports(pe, min_length));
            }

            // Extract overlay/appended data (common malware technique)
            strings.extend(extract_overlay_strings(data, min_length));
        }
        _ => {
            // Unknown format - use r2 if available, plus raw scan
            if let Some(r2_strings) = get_r2_strings(opts) {
                strings.extend(r2_strings);
            }
            // Always do raw scan for unknown formats (r2 strings complement, not replace)
            if !data.is_empty() {
                strings.extend(extract_raw_strings(
                    data,
                    min_length,
                    None,
                    &[],
                    &HashMap::new(),
                    &[],
                ));
            }
            // Extract binary network data (IPs and ports in network byte order)
            // For unknown formats, use 0 (not M68000) to process normally
            strings.extend(scan_binary_ips(data, min_length, 0, None, None));
            strings.extend(extract_stack_strings(data, min_length));
        }
    }

    // XOR string detection. `section_info` was populated by the format branch
    // above, so it doesn't need recomputing here.
    let is_pe = matches!(object, Object::PE(_));
    let excluded_ranges = binary::code_ranges_from_sections(&section_info);

    if !is_go_binary || opts.xor_scan_multi || opts.xor_key.is_some() {
        apply_xor_scan(&mut strings, data, opts, is_pe, &excluded_ranges);
    }

    // IPs recovered from `connect()` syscalls. Pre-populated wins
    // (expose's upstream rizin pass already harvested them);
    // otherwise stng spawns rizin itself when `use_r2` is on and we
    // have a path — standalone CLI behaviour. Skip on large files
    // (>10 MB) where the binary scan has diminishing returns.
    if let Some(ref pre) = opts.rizin_connect_addrs {
        if !pre.is_empty() {
            strings.extend(pre.clone());
        }
    } else if opts.use_r2
        && data.len() <= 10 * 1024 * 1024
        && let Some(ref path) = opts.path
    {
        let connect_addrs = r2::extract_connect_addrs(path, data);
        if !connect_addrs.is_empty() {
            strings.extend(connect_addrs);
        }
    }

    // Section names are no longer stored per-string (callers derive them from
    // the offset when needed). PE version-info IP suppression still applies.
    if let Object::PE(pe) = object {
        suppress_version_info_ips(&mut strings, pe);
    }

    // Upgrade strings in the Mach-O __LINKEDIT segment related to code
    // signatures. Section names are no longer stored per-string, so gate on
    // the segment's file-offset range(s) instead (thin: one; fat: per slice).
    let linkedit_ranges = macho_linkedit_ranges(object);
    for s in &mut strings {
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

    // Decode encoded strings (base64, hex, URL-encoding, unicode escapes).
    // Check cancellation between passes so a user-interrupted scan can bail
    // out without finishing every decoder on a multi-megabyte string set.
    let t_dec = std::time::Instant::now();
    let mut decoded = Vec::new();
    if !opts.is_cancelled() {
        // The eight decoders are independent passes over `strings`; run them
        // concurrently. Results are concatenated in the original pass order so
        // downstream offset/value deduplication is unaffected.
        let (g1, (g2, g3)) = rayon::join(
            || {
                let mut v = decoders::decode_base64_strings(&strings);
                v.extend(decoders::extract_embedded_base64(&strings));
                v.extend(fuzzy_base64::extract_fuzzy_base64(&strings));
                v
            },
            || {
                rayon::join(
                    || {
                        let mut v = decoders::decode_base32_strings(&strings);
                        v.extend(decoders::decode_base85_strings(&strings));
                        v.extend(decoders::decode_hex_strings(&strings));
                        v
                    },
                    || {
                        let mut v = decoders::decode_url_strings(&strings);
                        v.extend(decoders::decode_unicode_escape_strings(&strings));
                        v
                    },
                )
            },
        );
        decoded.extend(g1);
        decoded.extend(g2);
        decoded.extend(g3);
    }

    // Add decoded strings to the main list
    strings.extend(decoded);

    // Decode spaced ASCII strings (common in PE .rsrc, .NET metadata)
    decode_spaced_strings(&mut strings, min_length);
    tracing::debug!("TIME: Classification took {:?}", t_dec.elapsed());

    if opts.filter_garbage {
        // The garbage heuristic is the single most expensive post-extraction
        // pass (it runs `is_garbage_with_context` over every candidate). Each
        // verdict is independent, so evaluate them in parallel. `into_par_iter`
        // + `filter` + `collect` preserves the original order, matching the
        // sequential `retain` it replaces.
        let code_ranges = binary::code_ranges_from_sections(&section_info);
        strings = std::mem::take(&mut strings)
            .into_par_iter()
            .filter(|s| passes_garbage_filter(s, &code_ranges))
            .collect();
    }

    strip_go_varint_prefixes(&mut strings);

    deduplicate_by_offset(strings)
}

/// Rizin string set. Two sources, in preference order:
///   1. Caller-provided via `ExtractOptions::with_r2_strings` — set
///      by expose when it ran rizin upstream.
///   2. Standalone stng with `use_r2` on and an available path —
///      spawn rizin in-process. Keeps stng usable as an independent
///      CLI tool.
fn get_r2_strings(opts: &ExtractOptions) -> Option<Vec<ExtractedString>> {
    if let Some(ref pre) = opts.r2_strings {
        return Some(pre.clone());
    }
    if opts.use_r2
        && let Some(ref path) = opts.path
    {
        return r2::extract_strings(path, opts.min_length, opts.use_cache);
    }
    None
}
