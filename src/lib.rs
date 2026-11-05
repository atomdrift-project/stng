// Tests panic on failure and build their inputs with plain casts.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::cast_possible_truncation
    )
)]

//! # stng: strings(1) for malware analysis
//!
//! stng extracts the strings in a binary or script and says what each one
//! is (a URL, an IP, a shell command, a path, an API key, …) and how it was
//! found. Beyond a byte scan it:
//!
//! - reads Go and Rust string data by its `{ptr, len}` structures, which a
//!   byte scan merges into blobs because the strings have no terminators;
//! - follows the instructions that load string addresses and lengths, and
//!   rebuilds strings assembled on the stack;
//! - decodes base64, hex, URL and Unicode escapes, base32/base85, and
//!   obfuscated scripts (JavaScript, PowerShell, Python, PHP, VBScript,
//!   batch, Lua);
//! - recovers XOR-encoded strings: single-byte and repeating keys found in
//!   the file, a key the caller gives, and several compiler- and
//!   loader-specific encodings.
//!
//! Every string carries its file offset and the extent of the bytes it came
//! from ([`ExtractedString::source_spans`]); [`extract_iocs`] turns a set of
//! strings into canonical network, path and key indicators.
//!
//! ## Usage
//!
//! ```no_run
//! let data = std::fs::read("sample.bin").expect("read sample");
//! let opts = stng::ExtractOptions::new(4)
//!     .with_garbage_filter(true)
//!     .with_xor(stng::XorMode::Auto);
//! for s in stng::extract_strings_with_options(&data, &opts) {
//!     println!("{:#x} {:?} {}", s.data_offset, s.kind, s.value);
//! }
//! ```
//!
//! [`ExtractOptions::new`] turns every optional pass off: no garbage filter
//! and no XOR. The `stng` command turns both on. [`extract_strings`] is
//! `extract_strings_with_options` with those defaults.
//!
//! ## Hostile input
//!
//! Inputs are assumed to be malicious. Offsets and sizes from headers are
//! bounds-checked before use, every decoder and scanner has a work or size
//! budget, and stng never executes, loads or writes what it scans. A pass
//! that runs out of budget logs it at `debug` and returns what it has.
//!
//! ## Threads and cancellation
//!
//! stng runs its passes on rayon's global pool and never builds or
//! configures one; bound it with [`rayon::ThreadPool::install`] around the
//! call. [`ExtractOptions::with_cancellation`] is checked between passes;
//! a cancelled call returns the strings found so far, so treat its result
//! as partial.
//!
//! ## Depending on stng
//!
//! stng depends on a tree-sitter fork through `[patch.crates-io]`, and Cargo
//! applies patches only from the top-level manifest. A crate that depends on
//! stng must copy that `[patch.crates-io]` block from stng's `Cargo.toml`;
//! without it, Lua deobfuscation parses hostile input with upstream
//! tree-sitter, which lacks the fork's bounds.

/// The `unwrap_or_else` arm for building a matcher from a pattern fixed in
/// the source: failing is a bug in that pattern, never a property of the
/// input, so it panics. Clippy's `invalid_regex` checks literal patterns at
/// compile time, and every matcher is built by some test.
#[expect(
    clippy::panic,
    reason = "only reached for a pattern written in this crate"
)]
pub(crate) fn invalid_pattern<T>(e: impl std::fmt::Display) -> T {
    panic!("invalid static pattern: {e}")
}

// The README's examples compile as doctests.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

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
mod layouts;
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
mod classifier;

// Extractors: Go and Rust structures, instruction patterns, XOR
mod go;
pub(crate) mod instr;
mod rust;
pub(crate) mod xor;

// Decoders for encoded strings
pub(crate) mod decoders;
mod fuzzy_base64;

// Public API
pub use classifier::classify_string;
pub use detect::{Language, detect_language};
pub use ioc::{
    Ioc, IocKind, IocOccurrence, IpEvidence, KeyAlgorithm, KeyMetadata, MAX_IOC_OCCURRENCES,
    canonicalize_hostname, canonicalize_ioc_path, decode_key_material, encode_key_material,
    extract_iocs, is_external_ip,
};
pub use overlay::{detect_elf_overlay, detect_overlay};
pub use types::{ExtractedString, OverlayInfo, Severity, StringFragment, StringKind, StringMethod};
pub use xor::lcg::{Lcg, LcgError, decode_lcg_xor, decode_xor_fat_macho};

pub use validation::is_garbage;
pub use xor::{RepeatingXorKey, recover_repeating_xor_pe};

/// Single-purpose detectors and passes that the integration tests exercise
/// directly. Not part of the stable API: they may change in any release.
#[doc(hidden)]
pub use binary::{is_go_binary, is_rust_binary};
#[doc(hidden)]
pub use detect::is_text_file;
#[doc(hidden)]
pub use overlay::extract_overlay_strings;
#[doc(hidden)]
pub use xor::lcg::extract_macho_lcg_xor;

/// binform, whose layouts [`extract_strings_from_parsed`] accepts so a
/// caller reads a binary's tables once. Its version is part of stng's API.
pub use binform;
/// goblin, whose parsed [`Object`] [`extract_strings_from_parsed`]
/// accepts so a caller parses once. Its version is part of stng's API, and
/// goblin is pre-1.0, so a goblin minor release that breaks its API is a
/// stng major release.
pub use goblin;
use goblin::Object;
pub use layouts::Layout;
pub use options::{ExtractOptions, FormatHint, XorMode};
pub use pipeline::decode::decode_encoded_strings;

use pipeline::java::extract_java_class_strings;
use pipeline::text::{extract_from_malformed_utf16_bom_file, extract_from_utf16_file};

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
    route(data, None, &[], opts)
}

/// The one router behind every entry point: `parsed` is the caller's goblin
/// object, if any, which saves a parse but never changes the route.
fn route<'d>(
    data: &'d [u8],
    parsed: Option<&Object<'_>>,
    layouts: &[Layout<'_, 'd>],
    opts: &ExtractOptions,
) -> Vec<ExtractedString> {
    if opts.is_cancelled() {
        return Vec::new();
    }

    // A UTF-16 byte-order mark makes the file text, whatever goblin would
    // make of the bytes after it.
    if let Some(&[a, b]) = data.get(..2) {
        let le = [a, b] == [0xFF, 0xFE];
        if le || [a, b] == [0xFE, 0xFF] {
            tracing::debug!(
                little_endian = le,
                "UTF-16 byte-order mark; scanning as text"
            );
            if let Some(strings) = extract_from_malformed_utf16_bom_file(data, opts) {
                return strings;
            }
            return extract_from_utf16_file(data, opts, le);
        }
    }

    // A JVM class and a big-endian fat Mach-O share the CAFEBABE magic, so
    // goblin reads a class as `Mach::Fat` with its version words as an
    // architecture count, and finds nothing. A fat Mach-O's count (bytes
    // 4..8) is a small integer; a class's major version there is above 16.
    // Walking the constant pool is cheaper and exact, and keeps malformed
    // CAFEBABE input out of goblin's fat-architecture loop.
    if let Some(&[0xCA, 0xFE, 0xBA, 0xBE, a, b, c, d]) = data.get(..8)
        && u32::from_be_bytes([a, b, c, d]) > 16
    {
        tracing::debug!("JVM class file");
        return extract_java_class_strings(data, opts);
    }

    // `Object::Unknown` (no magic goblin recognises) and a parse error both
    // mean the input is not a binary stng has a format pass for: text,
    // scripts, ZIP-prefixed polyglots, damaged binaries.
    let parsed_here;
    let object = match parsed {
        Some(object) => Some(object),
        None => {
            parsed_here = Object::parse(data);
            if let Err(e) = &parsed_here {
                tracing::debug!(error = %e, "not a binary goblin parses; scanning as raw input");
            }
            parsed_here.as_ref().ok()
        }
    };
    match object {
        Some(object) if !matches!(object, Object::Unknown(_)) => {
            let format = match object {
                Object::Elf(_) => "elf",
                Object::PE(_) => "pe",
                Object::Mach(goblin::mach::Mach::Binary(_)) => "macho",
                Object::Mach(goblin::mach::Mach::Fat(_)) => "macho-fat",
                _ => "other",
            };
            tracing::debug!(format, bytes = data.len(), "parsed binary");
            let t0 = std::time::Instant::now();
            let strings = pipeline::extract(object, &layouts::Layouts::new(layouts), data, opts);
            tracing::debug!(elapsed = ?t0.elapsed(), "extraction finished");
            strings
        }
        _ => pipeline::extract_unknown(data, opts),
    }
}

/// [`extract_strings_with_options`] for a binary the caller already parsed:
/// the goblin `object` for `data`, and any binform layouts already read
/// from it, each with the file offset of the bytes it was read from (zero
/// for a whole binary, a slice's offset for one architecture of a universal
/// binary). The result is the same as from the bytes alone.
///
/// stng reads a binary's import, export and symbol tables through binform,
/// and only when it needs them: unless [`ExtractOptions`] says the caller
/// provides symbols, and for an ARM64 Mach-O's stack-XOR pass. A layout
/// passed here is used instead of reading the bytes again; any layout stng
/// needs and was not given, it reads once per call.
#[must_use]
pub fn extract_strings_from_parsed<'d>(
    object: &Object<'_>,
    layouts: &[Layout<'_, 'd>],
    data: &'d [u8],
    opts: &ExtractOptions,
) -> Vec<ExtractedString> {
    route(data, Some(object), layouts, opts)
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
