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

// Offsets and sizes from headers are u64, and the code converts them to usize
// freely: on a 32-bit target that would truncate them silently.
#[cfg(not(target_pointer_width = "64"))]
compile_error!("stng requires a 64-bit target");

// Core: options, the pipeline, and the types and checks every pass shares
mod extraction;
mod ioc;
mod options;
mod par;
mod pipeline;
mod types;
mod validation;

// Binary formats and their building blocks
mod arm64;
mod binary;
mod bytes;
mod cfml;
mod detect;
mod dotnet;
mod entitlements;
mod imports;
mod overlay;
mod raw;
mod sockaddr;
mod stack_strings;
mod swift_small_strings;
mod text;
mod x86;

// Script deobfuscation
pub mod script;

// String classifier
pub mod classifier;

// Extractors: Go and Rust structures, instruction patterns, XOR
mod go;
pub(crate) mod instr;
mod rust;
pub(crate) mod xor;

// Decoders for encoded strings
pub(crate) mod decoders;
mod fuzzy_base64;

// Public API
pub use binary::{is_go_binary, is_rust_binary};
pub use classifier::classify_string;
pub use decoders::decode_spaced_ascii;
pub use detect::{Language, detect_language, is_text_file};
pub use ioc::{
    Ioc, IocKind, IocOccurrence, IpEvidence, KeyAlgorithm, KeyMetadata, MAX_IOC_OCCURRENCES,
    canonicalize_hostname, canonicalize_ioc_path, decode_key_material, encode_key_material,
    extract_iocs, is_external_ip,
};
pub use overlay::detect_elf_overlay;
pub use types::{
    Arch, ExtractedString, OverlayInfo, Severity, StringBoundary, StringContext, StringFragment,
    StringKind, StringMethod,
};
pub use xor::lcg::{Lcg, decode_lcg_xor, decode_xor_fat_macho, extract_macho_lcg_xor};

pub use xor::{MAX_XOR_SCAN_SIZE, RepeatingXorKey, recover_repeating_xor_pe};

// Internal — not part of the stable public API
pub(crate) use go::{GoStringExtractor, pclntab_strings};
pub use overlay::extract_overlay_strings;
pub(crate) use rust::RustStringExtractor;
pub(crate) use stack_strings::{extract_stack_strings, extract_stack_strings_with_context};
pub use validation::{is_garbage, is_garbage_with_context};

/// The goblin stng parses with, so a caller can parse once and hand the
/// object to [`extract_strings_from_object`]. Its version is part of stng's
/// API: a goblin release that breaks its API is a stng major release.
pub use goblin;
use goblin::Object;
pub use options::{ExternalHints, ExtractOptions, FormatHint, XorMode};
pub use pipeline::decode::decode_encoded_strings;

// Import internal modules for use in this file
use binary::{
    collect_elf_section_info, collect_elf_segments, collect_macho_section_info,
    collect_macho_segments, collect_pe_section_info, elf_go_skip_ranges, macho_go_skip_ranges,
    macho_has_go_sections, pe_go_skip_ranges, pe_is_rust, pe_rust_skip_ranges,
};
use imports::{extract_elf_imports, extract_macho_imports, extract_pe_imports};
use pipeline::decode::{Rot13, decode, decode_spaced_strings};
use pipeline::java::extract_java_class_strings;
use pipeline::text::{
    append_script_deobfuscation, extract_from_malformed_utf16_bom_file, extract_from_utf16_file,
    should_deobfuscate_script,
};
use pipeline::xor::{apply_xor_scan, scans_for_xor};
use pipeline::{deduplicate_by_offset, passes_garbage_filter};
use raw::{extract_raw_strings, extract_wide_strings};
use sockaddr::scan_binary_ips;

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
/// ```no_run
/// use stng::{extract_strings_with_options, ExtractOptions};
///
/// let data = std::fs::read("/bin/ls").unwrap();
/// let opts = ExtractOptions::new(4)
///     .with_garbage_filter(true);
/// let strings = extract_strings_with_options(&data, &opts);
/// ```
#[must_use]
pub fn extract_strings_with_options(data: &[u8], opts: &ExtractOptions) -> Vec<ExtractedString> {
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
            if let Some(strings) = extract_from_malformed_utf16_bom_file(data, opts) {
                return strings;
            }
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
    // A JVM class and a big-endian fat Mach-O share the same CAFEBABE magic.
    // Goblin therefore accepts a class as `Mach::Fat`, interprets the JVM
    // minor/major version words as an architecture count, warns once per
    // bogus FatArch, and returns no useful strings.  A real fat Mach-O keeps
    // its architecture count in bytes 4..8 (normally a small integer), while
    // a class stores a plausible JVM major version in bytes 6..8 followed by
    // a constant-pool count and tag. Walk that pool directly: it is both
    // cheaper and more exact than treating Java as an unknown binary.
    // filefacts uses the same bound, which also keeps malformed CAFEBABE input
    // out of Goblin's fat-architecture loop.
    if let Some(&[0xCA, 0xFE, 0xBA, 0xBE, a, b, c, d]) = data.get(..8)
        && u32::from_be_bytes([a, b, c, d]) > 16
    {
        return extract_java_class_strings(data, opts);
    }

    let parsed_binary = match Object::parse(data) {
        Ok(obj) if !matches!(obj, Object::Unknown(_)) => Some(obj),
        _ => None,
    };

    if let Some(object) = parsed_binary {
        let t0 = std::time::Instant::now();
        let mut strings = pipeline::extract(&object, data, opts);
        tracing::debug!("TIME: Extraction took {:?}", t0.elapsed());

        // For text files parsed by goblin (e.g. as Unknown), also run script deobfuscation
        if should_deobfuscate_script(data, &strings) {
            append_script_deobfuscation(&mut strings, data, opts);
        }

        deduplicate_by_offset(strings)
    } else {
        // Unknown format - use r2 if available, plus raw scan
        let mut strings = Vec::new();
        strings.extend(opts.hints.strings.iter().cloned());

        // Check if this looks like a PE (MZ header) even if goblin failed to parse
        let is_pe = data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A;

        // Extract wide strings for PE-like files (common in Windows binaries)
        if is_pe && !data.is_empty() {
            strings.extend(extract_wide_strings(data, opts.min_length, &[], &[]));
        }

        // Raw scan for all unknown formats (r2 strings complement, not replace)
        if !data.is_empty() {
            strings.extend(extract_raw_strings(data, opts.min_length, &[], &[]));
        }

        // Legacy ColdFusion templates use a fixed signature followed by
        // DES-encrypted CFML. Recover the source as one decoded string so
        // language and behavior traits can inspect the actual template body.
        if !opts.is_cancelled()
            && let Some(source) = cfml::decode(data)
            && source.len() >= opts.min_length
        {
            strings.push(ExtractedString {
                value: String::from_utf8_lossy(&source).into_owned(),
                data_offset: 0,
                data_len: u32::try_from(data.len()).unwrap_or(u32::MAX),
                method: StringMethod::CfmlDecode,
                kind: None,
                fragments: None,
            });
        }

        // Extract binary network data (IPs and ports in network byte order)
        // For unknown formats, use 0 (not M68000) to process normally
        strings.extend(scan_binary_ips(data, opts.min_length, 0, None, None));
        strings.extend(extract_stack_strings(data, opts.min_length));

        // Trigger XOR scan even for unknown formats if requested
        if opts.xor != XorMode::Off {
            apply_xor_scan(&mut strings, data, opts, is_pe, &[]);
        }

        // A PE under a repeating XOR key is opaque to goblin, so this branch is
        // the only place one can land. Recovery reads a fixed 128-byte header
        // whatever the input size, so it needs no size gate; text is skipped
        // as `apply_xor_scan` skips it. Only the key is surfaced; the decoded
        // image is binary, for callers of `recover_repeating_xor_pe`.
        if opts.xor_scans()
            && scans_for_xor(data, opts)
            && let Some(key) = xor::recover_repeating_xor_pe(data)
        {
            strings.push(key.to_key_string());
        }

        if !opts.is_cancelled() {
            let decoded = decode(&strings, Rot13::No);
            strings.extend(decoded);
        }

        // Decode spaced ASCII strings (common in PE .rsrc, .NET metadata)
        decode_spaced_strings(&mut strings, opts.min_length);

        // Script deobfuscation for text files that didn't parse as a known binary format
        if should_deobfuscate_script(data, &strings) {
            append_script_deobfuscation(&mut strings, data, opts);
        }

        // XOR already ran once above, before the decoder suite, so XOR
        // plaintext still feeds base64/hex. A second full-file scan here
        // is the same bytes (unknown format has no new section map).
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
        return extract_strings_with_options(data, opts);
    }
    let mut strings = pipeline::extract(object, data, opts);
    if should_deobfuscate_script(data, &strings) {
        append_script_deobfuscation(&mut strings, data, opts);
    }
    deduplicate_by_offset(strings)
}

/// Reads the sample at `path` (relative to the crate root) at run time.
/// Samples live in git gzip-compressed as `<path>.gz` and are never embedded
/// with `include_bytes!`: no binary, test or otherwise, should carry malware.
/// Mirrors `tests/common`, which unit tests cannot import.
#[cfg(test)]
pub(crate) fn test_fixture(path: &str) -> &'static [u8] {
    use std::io::Read;
    let full = format!("{}/{path}.gz", env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    std::fs::File::open(&full)
        .and_then(|f| flate2::read::GzDecoder::new(f).read_to_end(&mut out))
        .unwrap_or_else(|e| panic!("{full}: {e}"));
    out.leak()
}

#[cfg(test)]
mod tests;
