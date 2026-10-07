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
mod ioc;
mod types;
mod validation;
mod validation_thresholds;

// Binary format modules
mod arm64;
mod arm64_effects;
mod arm64_frame;
mod arm64_stack_xor;
pub mod binary;
mod binary_net;
mod bytes;
mod cfml;
mod detect;
mod dotnet;
mod entitlements;
mod fmix_xor;
mod heap_xor;
mod imports;
mod lcg_xor;
mod overlay;
mod pe_xor;
mod pointer_xor;
mod raw;
mod stack_strings;
mod swift_small_strings;

// Script deobfuscation
pub mod script;

// String classifier
pub mod classifier;

// Language-specific extractors
mod go;
pub(crate) mod instr;
mod rust;
pub(crate) mod xor;

// Decoders for encoded strings
pub(crate) mod decoders;
mod fuzzy_base64;
mod par;
mod pipeline;

// Public API
pub use binary::{is_go_binary, is_rust_binary};
pub use classifier::classify_string;
pub use decoders::decode_spaced_ascii;
pub use detect::{detect_language, is_text_file};
pub use ioc::{
    Ioc, IocKind, IocOccurrence, IpEvidence, KeyAlgorithm, KeyMetadata, MAX_IOC_OCCURRENCES,
    canonicalize_hostname, canonicalize_ioc_path, decode_key_material, encode_key_material,
    extract_iocs, is_external_ip,
};
pub use lcg_xor::{
    decode_lcg_xor, decode_xor_fat_macho, extract_macho_lcg_xor, extract_macho_xor_macho_strings,
};
pub use overlay::{detect_elf_overlay, detect_elf_overlay_from_elf};
pub use types::{
    Arch, BinaryInfo, ExtractedString, OverlayInfo, Severity, StringBoundary, StringContext,
    StringFragment, StringKind, StringMethod, StringStruct,
};

pub use xor::{
    MAX_XOR_SCAN_SIZE, RepeatingXorKey, extract_incremental_xor_strings, recover_repeating_xor_pe,
};

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
        .with_min_len(par::job_len(exec_ranges.len(), data.len()))
        .filter_map(|&(start, end)| {
            let end = end.min(data.len());
            if start >= end {
                return None;
            }
            let section_data = data.get(start..end)?;
            let mut results = extract_stack_strings(section_data, min_length);
            for r in &mut results {
                r.rebase(start as u64);
            }
            Some(results)
        })
        .flatten()
        .collect()
}

/// Returns `true` if a string should be kept when garbage filtering is enabled.
/// Encoded strings and special kinds are always kept regardless of content.
///
/// Runs `is_garbage_with_context` so architecture- and section-aware
/// filters (notably the x86 push/pop save-sequence detector) can scope
/// themselves to the right inputs. Kind, section, and arch all come
/// from the `ExtractedString` itself when known.
fn passes_garbage_filter(s: &ExtractedString, code_ranges: &[(usize, usize)]) -> bool {
    // A referenced pointer/length can describe a complete multiline literal
    // (scripts, XML, configuration). Preserve clean ASCII text layout without
    // relaxing the control-character check for unstructured machine-code noise.
    if s.method == StringMethod::InstructionPattern
        && s.value.trim().contains(['\n', '\r', '\t'])
        && s.value
            .bytes()
            .all(|b| (b' '..=b'~').contains(&b) || matches!(b, b'\n' | b'\r' | b'\t'))
    {
        return true;
    }
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
        StringMethod::Structure
            | StringMethod::Base64Decode
            | StringMethod::Base64ObfuscatedDecode
            | StringMethod::HexDecode
            | StringMethod::UrlDecode
            | StringMethod::UnicodeEscapeDecode
            | StringMethod::ScriptDecode
            | StringMethod::CfmlDecode
            | StringMethod::XorDecode
    ) {
        return true;
    }
    if matches!(
        s.kind,
        Some(
            StringKind::EntitlementsXml
                | StringKind::Section
                | StringKind::Base64
                | StringKind::Base32
                | StringKind::Base85
                | StringKind::HexEncoded
                | StringKind::UrlEncoded
                | StringKind::UnicodeEscaped
                | StringKind::XorKey
        )
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
        // The ranges are sorted and disjoint: find the last one starting at or
        // before the offset.
        let off = usize::try_from(s.data_offset).unwrap_or(usize::MAX);
        let i = code_ranges.partition_point(|&(start, _)| start <= off);
        Some(i > 0 && off < code_ranges[i - 1].1)
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

/// Whether the XOR scanners may run over `data`.
///
/// They hunt obfuscation in executable code and binary data. On text —
/// source, documents, hex dumps — they find only noise: no real-world sample
/// shows them recovering anything from text, and on source carrying a `^` they
/// cost about a tenth of extraction. So text is skipped, unless the caller
/// names the key and so knows better. Text carriers keep decoders shaped for
/// them: hex-then-XOR over decoded hex strings ([`decoders`]), and script
/// deobfuscation, which recovers the key from the code.
fn scans_for_xor(data: &[u8], opts: &ExtractOptions) -> bool {
    opts.xor_key.is_some() || (opts.format_hint != FormatHint::Text && detect::is_binary(data))
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
        "apply_xor_scan: called (xor_scan: {}, key offsets: {})",
        opts.xor_scan,
        opts.xor_key_offsets.is_some()
    );
    if data.is_empty() || opts.is_cancelled() {
        return;
    }
    // Every return below precedes the first string this scan adds.
    let first_added = strings.len();

    if !scans_for_xor(data, opts) {
        tracing::debug!("Skipping XOR scan: text input");
        return;
    }

    // Platform-signed binaries (Apple/Microsoft OS binaries) are vetted
    // upstream; malware-vs-legitimate single-byte XOR obfuscation never
    // survives platform signing. Skipping XOR on these is the single biggest
    // throughput win for typical system-binary corpora. Third-party
    // Developer ID signatures are NOT matched — those CAN be signed malware.
    // Users who passed an explicit xor_key or requested xorscan bypass this.
    if opts.xor_key.is_none() && opts.xor_key_offsets.is_none() && binary::is_platform_signed(data)
    {
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

    let r2_boundaries = opts.rizin_boundaries.as_deref();

    if let Some(ref key) = opts.xor_key {
        let key_str = String::from_utf8_lossy(key);
        if let Some(ks) = strings.iter_mut().find(|s| s.value == key_str.as_ref()) {
            ks.kind = Some(StringKind::XorKey);
        }
        strings.extend(xor::extract_custom_xor_strings_with_hints(
            data,
            key,
            opts.xor_min_length,
            r2_boundaries,
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
                r2_boundaries,
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
                        r2_boundaries,
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

    // Code an external disassembler found loading an XOR key: decode the
    // file with the key at each such offset.
    if let Some(offsets) = &opts.xor_key_offsets {
        strings.extend(xor::extract_multikey_xor_strings(
            data,
            offsets,
            opts.xor_min_length,
        ));
    }

    xor::report_kinds(&mut strings[first_added..]);
    tracing::debug!("TIME: XOR key scanning took {:?}", t_xor.elapsed());
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

/// How to extract strings. Start from [`ExtractOptions::new`] and adjust with
/// the `with_*` builders.
#[derive(Debug, Clone)]
pub struct ExtractOptions {
    /// Minimum string length to extract
    pub min_length: usize,
    /// Filter out garbage strings (default: false for library, true for CLI)
    pub filter_garbage: bool,
    /// Enable XOR strings (single-byte scanning and bounded x86 PE decoder recovery). Default: false.
    pub xor_scan: bool,
    /// Custom XOR key for decoding (overrides auto-detection if set).
    pub xor_key: Option<Vec<u8>>,
    /// Minimum length for XOR-decoded strings (default: 10).
    pub xor_min_length: usize,
    /// Skip stng's native import/export/symbol extraction. Default: false.
    ///
    /// Set this when the caller already parses the binary's symbol tables
    /// itself (e.g. filefacts' `extract_symbols`) so the work isn't done
    /// twice. Symbol names still surface as raw `__LINKEDIT` / `.rdata` scan
    /// hits; only the structured, typed import/export pass is skipped.
    pub caller_provides_symbols: bool,
    /// Cancellation flag checked at phase boundaries (start of extraction,
    /// before XOR scan, between decoder passes).  When the flag becomes
    /// `true`, extraction returns whatever it has so far.
    pub cancel: Option<Arc<AtomicBool>>,
    /// Hint about the input so stng can skip analyses that will produce
    /// nothing on that shape of input.  See `FormatHint` for the semantics.
    pub format_hint: FormatHint,
    /// Strings an external disassembler (rizin/radare2) found, merged into
    /// the output. stng runs no subprocesses; the stng CLI runs rizin and
    /// passes its results through these `rizin_*` / `r2_*` fields.
    pub r2_strings: Option<Vec<ExtractedString>>,
    /// String extents from an external disassembler, used to aim XOR
    /// decoding.
    pub rizin_boundaries: Option<Vec<StringBoundary>>,
    /// `sockaddr_in` addresses an external disassembler recovered from
    /// `connect()` call sites, merged into the output.
    pub rizin_connect_addrs: Option<Vec<ExtractedString>>,
    /// File offsets where an external disassembler found code loading an XOR
    /// key. Each is tried as a 16-, 32- and 8-byte repeating key.
    pub xor_key_offsets: Option<Vec<u64>>,
}

impl Default for ExtractOptions {
    fn default() -> Self {
        Self::new(4)
    }
}

impl ExtractOptions {
    /// Options for strings of at least `min_length` bytes, with every optional
    /// pass (garbage filter, XOR scan) off.
    #[must_use]
    pub fn new(min_length: usize) -> Self {
        Self {
            min_length,
            filter_garbage: false,
            xor_scan: false,
            xor_key: None,
            xor_min_length: xor::DEFAULT_XOR_MIN_LENGTH,
            caller_provides_symbols: false,
            cancel: None,
            format_hint: FormatHint::Auto,
            r2_strings: None,
            rizin_boundaries: None,
            rizin_connect_addrs: None,
            xor_key_offsets: None,
        }
    }

    /// Supply strings an external rizin/radare2 run found.
    #[must_use]
    pub fn with_r2_strings(mut self, strings: Vec<ExtractedString>) -> Self {
        self.r2_strings = Some(strings);
        self
    }

    /// Supply string extents from an external rizin run (`izzj`).
    #[must_use]
    pub fn with_rizin_boundaries(mut self, b: Vec<StringBoundary>) -> Self {
        self.rizin_boundaries = Some(b);
        self
    }

    /// Supply connect-address strings from an external rizin run.
    #[must_use]
    pub fn with_rizin_connect_addrs(mut self, c: Vec<ExtractedString>) -> Self {
        self.rizin_connect_addrs = Some(c);
        self
    }

    /// Supply file offsets of XOR keys found by an external disassembler.
    #[must_use]
    pub fn with_xor_key_offsets(mut self, offsets: Vec<u64>) -> Self {
        self.xor_key_offsets = Some(offsets);
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
    /// Scans single-byte XOR keys and recovers bounded, instruction-proven
    /// repeating-key XOR buffers in x86 PEs without a subprocess.
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
/// base85, ROT13-base64, hex, URL, and unicode-escape) to already-extracted
/// strings and return
/// the newly decoded results.
///
/// Decoding runs on the *text* of each string, so it is filetype-agnostic: the
/// same pass that recovers base64-encoded PowerShell from a PE also recovers a
/// base64-over-UTF-16LE blob sitting in a plain `.txt` or `.json`. Both the
/// internal extraction pipeline and the CLI's line-based text path funnel through
/// here so coverage stays identical across inputs.
/// Base64 wrapping a zlib stream is inflated with a 10 MiB output bound before
/// text validation; decoded strings retain the encoded token's source extent.
#[must_use]
pub fn decode_encoded_strings(strings: &[ExtractedString]) -> Vec<ExtractedString> {
    decode(strings, Rot13::Yes)
}

/// Whether [`decode`] tries ROT13 under base64.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Rot13 {
    /// Text: ROT13-then-base64 is a script obfuscation.
    Yes,
    /// Binaries: arbitrary symbols "decode" to noise that would outrank the
    /// real string at its offset.
    No,
}

/// Every decoder over `strings`, run concurrently; results in pass order.
fn decode(strings: &[ExtractedString], rot13: Rot13) -> Vec<ExtractedString> {
    let split = strings.len() >= par::MIN_ITEMS_PER_JOB;
    pipeline::parallel(
        split,
        [
            &|| decoders::decode_base64_strings(strings),
            &|| decoders::extract_embedded_base64(strings),
            &|| fuzzy_base64::extract_fuzzy_base64(strings),
            &|| decoders::decode_base32_strings(strings),
            &|| decoders::decode_base85_strings(strings),
            &|| match rot13 {
                Rot13::Yes => decoders::decode_rot13_base64_strings(strings),
                Rot13::No => Vec::new(),
            },
            &|| decoders::decode_hex_strings(strings),
            &|| decoders::extract_embedded_hex(strings),
            &|| decoders::decode_url_strings(strings),
            &|| decoders::decode_unicode_escape_strings(strings),
        ],
    )
    .concat()
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
        if let Some(decoded) = decoders::decode_spaced_ascii(&s.value)
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

/// Raw-scan strings minus what the language passes in `claimed` already cover.
///
/// rustc packs `&str` literals back to back with no terminator, so one raw run
/// can span a literal the structure pass sliced out and bytes it never named:
/// `src/main.rshttps://host/x.png` when only `src/main.rs` is referenced.
/// Offset dedup keeps the higher-priority slice and would discard the whole run,
/// URL included. Instead each raw run is cut around the claimed byte spans and
/// only the unclaimed pieces of at least `min_length` bytes are returned. Runs
/// whose value a pass already produced are dropped outright.
fn unclaimed_raw_strings(
    raw: Vec<ExtractedString>,
    claimed: &[ExtractedString],
    min_length: usize,
) -> Vec<ExtractedString> {
    let known: HashSet<&str> = claimed.iter().map(|s| s.value.as_str()).collect();
    let mut spans: Vec<(u64, u64)> = claimed
        .iter()
        .map(|s| (s.data_offset, s.data_offset + s.value.len() as u64))
        .collect();
    spans.sort_unstable();
    let longest = spans.iter().map(|&(a, b)| b - a).max().unwrap_or(0);

    let mut out = Vec::with_capacity(raw.len());
    for s in raw {
        if known.contains(s.value.as_str()) {
            continue;
        }
        let start = s.data_offset;
        let end = start + s.value.len() as u64;
        // Spans sorted by start: those overlapping [start, end) begin before
        // `end` and no earlier than `start - longest`.
        let lo = spans.partition_point(|&(a, _)| a < start.saturating_sub(longest));
        let hi = spans.partition_point(|&(a, _)| a < end);
        let overlapping: Vec<(u64, u64)> = spans[lo..hi]
            .iter()
            .filter(|&&(_, b)| b > start)
            .copied()
            .collect();
        if overlapping.is_empty() {
            out.push(s);
            continue;
        }

        let mut cursor = start;
        let mut pieces = Vec::new();
        for (a, b) in overlapping {
            if a > cursor {
                pieces.push((cursor, a));
            }
            cursor = cursor.max(b);
        }
        if cursor < end {
            pieces.push((cursor, end));
        }
        for (a, b) in pieces {
            let (Ok(lo), Ok(hi)) = (usize::try_from(a - start), usize::try_from(b - start)) else {
                continue;
            };
            let Some(value) = s.value.get(lo..hi) else {
                continue;
            };
            if value.len() < min_length || known.contains(value) {
                continue;
            }
            out.push(ExtractedString {
                value: value.to_string(),
                data_offset: a,
                kind: classifier::classify_string(value),
                ..s.clone()
            });
        }
    }
    out
}

/// Deduplicate strings by keeping only the best string at each offset.
///
/// Uses a single in-place sort + `dedup_by_key` pass — no HashMap allocation.
/// The sort key is `(offset asc, priority desc, length desc)` so the first
/// entry at each offset is the best candidate and `dedup_by_key(data_offset)`
/// keeps it.  Best candidate = highest `StringMethod::dedup_priority`, tied
/// with longer `value`. Remaining ties prefer a classified kind and a recorded
/// (larger) extent, then break on method, value and fragments, so the survivor
/// never depends on the order passes produced candidates in.
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
            .then_with(|| b.kind.cmp(&a.kind))
            .then_with(|| b.data_len.cmp(&a.data_len))
            .then_with(|| a.method.cmp(&b.method))
            .then_with(|| a.value.cmp(&b.value))
            .then_with(|| a.fragments.cmp(&b.fragments))
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
    let code_units = utf16_data.as_chunks::<2>().0.iter().map(|chunk| {
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
    let mut raw_strings = extract_raw_strings(decoded_bytes, opts.min_length, &[], &[]);

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

/// Recover a text file whose UTF-16 BOM was prepended to ordinary UTF-8 bytes.
///
/// Some malware builders use this malformed wrapper to confuse tools that
/// select a decoder solely from the first two bytes.  A genuine UTF-16 source
/// containing ASCII necessarily has NUL bytes between its code units, whereas
/// this form is valid UTF-8 with no embedded NULs after the BOM. Keep the check
/// narrow: a trailing NUL is tolerated as a text terminator; any embedded NUL
/// (or invalid UTF-8) remains on the normal UTF-16 path.
fn extract_from_malformed_utf16_bom_file(
    data: &[u8],
    opts: &ExtractOptions,
) -> Option<Vec<ExtractedString>> {
    let payload = data.get(2..)?;
    let text_end = payload
        .iter()
        .rposition(|&byte| byte != 0)
        .map_or(0, |i| i + 1);
    let text = &payload[..text_end];
    if text.contains(&0) || std::str::from_utf8(text).is_err() {
        return None;
    }

    let mut strings = extract_raw_strings(payload, opts.min_length, &[], &[]);
    for string in &mut strings {
        // `payload` omits the BOM, but consumers expect file-relative offsets.
        string.data_offset = string.data_offset.saturating_add(2);
    }
    Some(strings)
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
        let mut payload_strings = extract_raw_strings(payload_bytes, opts.min_length, &[], &[]);

        let payload_decoded = decode_encoded_strings(&payload_strings);
        payload_strings.extend(payload_decoded);

        // Mark all strings as ScriptDecode with provenance.
        // Use a high base offset to avoid collisions with raw-scan strings from
        // the original file during deduplication.
        let base_offset = data.len() as u64 + 1 + result.offset as u64;
        for s in &mut payload_strings {
            s.method = StringMethod::ScriptDecode;
            s.kind = classifier::classify_string(&s.value);
            s.rebase(base_offset);
        }

        strings.extend(payload_strings);
    }
}

/// Script deobfuscation normally runs only for inputs identified as text. A
/// self-identifying VBScript.Encode marker is also sufficient evidence: its
/// encoded body can contain enough control/high bytes to classify an ASP page
/// as binary. Check strings already extracted by the normal scan so binary
/// inputs without the marker pay no additional full-file scan.
fn should_deobfuscate_script(data: &[u8], strings: &[ExtractedString]) -> bool {
    is_text_file(data) || strings.iter().any(|s| s.value.contains("#@~^"))
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
        strings.extend(opts.r2_strings.iter().flatten().cloned());

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
        if opts.xor_scan || opts.xor_key.is_some() || opts.xor_key_offsets.is_some() {
            apply_xor_scan(&mut strings, data, opts, is_pe, &[]);
        }

        // A PE under a repeating XOR key is opaque to goblin, so this branch is
        // the only place one can land. Recovery reads a fixed 128-byte header
        // whatever the input size, so it needs no size gate; text is skipped
        // as `apply_xor_scan` skips it. Only the key is surfaced; the decoded
        // image is binary, for callers of `recover_repeating_xor_pe`.
        if opts.xor_scan
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

/// Extract the JVM constant-pool UTF-8 entries directly. Besides being one
/// linear pass, this preserves exact string boundaries: a raw byte scan can
/// accidentally prepend a printable low byte from the preceding `u2 length`.
fn extract_java_class_strings(data: &[u8], opts: &ExtractOptions) -> Vec<ExtractedString> {
    let Some(&[count_hi, count_lo]) = data.get(8..10) else {
        return Vec::new();
    };
    let count = u16::from_be_bytes([count_hi, count_lo]) as usize;
    let mut strings = Vec::new();
    let mut pos = 10usize;
    let mut index = 1usize;

    while index < count {
        let Some(&tag) = data.get(pos) else {
            break;
        };
        pos += 1;
        let size = match tag {
            1 => {
                let Some(&[hi, lo]) = data.get(pos..pos + 2) else {
                    break;
                };
                pos += 2;
                let len = u16::from_be_bytes([hi, lo]);
                let len_usize = usize::from(len);
                let Some(bytes) = data.get(pos..pos.saturating_add(len_usize)) else {
                    break;
                };
                let value = String::from_utf8_lossy(bytes).into_owned();
                if value.len() >= opts.min_length {
                    strings.push(ExtractedString {
                        kind: classifier::classify_string(&value),
                        value,
                        data_offset: pos as u64,
                        data_len: u32::from(len),
                        method: StringMethod::RawScan,
                        fragments: None,
                    });
                }
                len_usize
            }
            3 | 4 | 9 | 10 | 11 | 12 | 17 | 18 => 4,
            5 | 6 => {
                index += 1;
                8
            }
            7 | 8 | 16 | 19 | 20 => 2,
            15 => 3,
            _ => break,
        };
        let Some(next) = pos.checked_add(size).filter(|&next| next <= data.len()) else {
            break;
        };
        pos = next;
        index += 1;
    }

    if opts.xor_scan || opts.xor_key.is_some() || opts.xor_key_offsets.is_some() {
        apply_xor_scan(&mut strings, data, opts, false, &[]);
    }
    let decoded = decode_encoded_strings(&strings);
    strings.extend(decoded);
    if opts.filter_garbage {
        strings.retain(|s| passes_garbage_filter(s, &[]));
    }
    deduplicate_by_offset(strings)
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
mod tests {
    use super::*;

    #[test]
    fn fat_linkedit_walk_is_bounded_by_the_buffer() {
        // nfat_arch = u32::MAX over 1 KiB: a walk that trusts the count
        // visits about four billion entries.
        let mut data = vec![0xCA, 0xFE, 0xBA, 0xBE, 0xFF, 0xFF, 0xFF, 0xFF];
        data.resize(1024, 0);
        let fat = goblin::mach::MultiArch::new(&data).expect("fat header parses");
        let object = Object::Mach(goblin::mach::Mach::Fat(fat));
        assert!(pipeline::macho::macho_linkedit_ranges(&object).is_empty());
    }

    #[test]
    fn stack_string_spans_are_file_offsets() {
        // mov dword [rbp-0x10], "hell"; mov dword [rbp-0xc], "o wo";
        // mov dword [rbp-8], "rld\0"; ret — 4 KB into the file.
        let code = [
            0xC7, 0x45, 0xF0, b'h', b'e', b'l', b'l', 0xC7, 0x45, 0xF4, b'o', b' ', b'w', b'o',
            0xC7, 0x45, 0xF8, b'r', b'l', b'd', 0, 0xC3,
        ];
        let mut data = vec![0u8; 4096];
        data.extend_from_slice(&code);
        let found = extract_stack_strings_from_ranges(&data, 4, &[(4096, data.len())]);
        let s = found
            .iter()
            .find(|s| s.value.starts_with("hello"))
            .unwrap_or_else(|| panic!("no stack string in {found:?}"));
        assert!(s.fragments.is_some(), "{s:?}");
        for (offset, len) in s.source_spans() {
            assert!(
                offset >= 4096 && offset + len <= data.len() as u64,
                "span {offset}+{len} outside the code: {s:?}"
            );
        }
    }

    #[test]
    fn instruction_referenced_text_preserves_layout_without_exempting_raw_noise() {
        let text = "a\nb\tc\rd";
        assert!(passes_garbage_filter(
            &at(text, 0, StringMethod::InstructionPattern),
            &[]
        ));
        assert!(!passes_garbage_filter(
            &at(text, 0, StringMethod::RawScan),
            &[]
        ));
        for control in ['\0', '\u{1}', '\u{1b}', '\u{7f}'] {
            let value = format!("a\nb{control}c");
            assert!(!passes_garbage_filter(
                &at(&value, 0, StringMethod::InstructionPattern),
                &[]
            ));
        }
        assert!(!passes_garbage_filter(
            &at(" \n\t\r ", 0, StringMethod::InstructionPattern),
            &[]
        ));
    }

    fn at(value: &str, offset: u64, method: StringMethod) -> ExtractedString {
        ExtractedString {
            value: value.to_string(),
            data_offset: offset,
            method,
            ..Default::default()
        }
    }

    #[test]
    fn unclaimed_raw_strings_keeps_bytes_around_claimed_literals() {
        // rustc packs `src/main.rs` and an unreferenced URL back to back.
        let raw = vec![
            at(
                "src/main.rshttps://example.org/x.png",
                0x100,
                StringMethod::RawScan,
            ),
            at("untouched run", 0x200, StringMethod::RawScan),
            at("already known", 0x300, StringMethod::RawScan),
        ];
        let claimed = vec![
            at("src/main.rs", 0x100, StringMethod::Structure),
            at("already known", 0x400, StringMethod::Structure),
        ];

        let got: Vec<_> = unclaimed_raw_strings(raw, &claimed, 4)
            .into_iter()
            .map(|s| (s.value, s.data_offset))
            .collect();
        assert_eq!(
            got,
            [
                ("https://example.org/x.png".to_string(), 0x10b),
                ("untouched run".to_string(), 0x200),
            ]
        );
    }

    #[test]
    fn unclaimed_raw_strings_drops_short_gaps_between_literals() {
        let raw = vec![at("alphaXYbravo", 0, StringMethod::RawScan)];
        let claimed = vec![
            at("alpha", 0, StringMethod::Structure),
            at("bravo", 7, StringMethod::Structure),
        ];
        assert!(unclaimed_raw_strings(raw, &claimed, 4).is_empty());
    }
}
