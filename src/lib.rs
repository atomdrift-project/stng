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
mod error;
mod extraction;
mod types;
mod validation;
mod validation_thresholds;

// Binary format modules
pub mod binary;
mod binary_net;
mod detect;
mod entitlements;
mod imports;
mod overlay;
mod raw;
mod stack_strings;

// Language-specific extractors
mod go;
pub(crate) mod instr;
pub mod r2;
mod rust;
pub(crate) mod xor;

// Decoders for encoded strings
pub(crate) mod decoders;
mod fuzzy_base64;

// Public API
pub use binary::{is_go_binary, is_rust_binary};
pub use detect::{detect_language, is_text_file};
pub use error::{Result, StngError};
pub use go::classify_string;
pub use overlay::detect_elf_overlay;
pub use types::{
    BinaryInfo, ExtractedString, FunctionMetadata, OverlayInfo, Severity, StringKind, StringMethod,
    StringStruct,
};

pub use xor::MAX_XOR_SCAN_SIZE;

// Internal — not part of the stable public API
pub(crate) use go::GoStringExtractor;
pub use overlay::extract_overlay_strings;
pub(crate) use rust::RustStringExtractor;
pub(crate) use stack_strings::extract_stack_strings;
pub use validation::is_garbage;

// Re-export goblin so library clients can parse binaries themselves
pub use goblin;
use goblin::mach::cputype::{
    CPU_TYPE_ARM, CPU_TYPE_ARM64, CPU_TYPE_POWERPC, CPU_TYPE_POWERPC64, CPU_TYPE_X86,
    CPU_TYPE_X86_64,
};
use goblin::mach::MachO;
use goblin::Object;
use std::collections::{HashMap, HashSet};

// Import internal modules for use in this file
use binary::{
    collect_elf_section_info, collect_elf_segments, collect_macho_section_info,
    collect_macho_segments, collect_pe_section_info, macho_has_go_sections,
};
use binary_net::scan_binary_ips;
use imports::{extract_elf_imports, extract_macho_imports};
use raw::{extract_raw_strings, extract_wide_strings};

/// Returns `true` if a string should be kept when garbage filtering is enabled.
/// Encoded strings and special kinds are always kept regardless of content.
fn passes_garbage_filter(s: &ExtractedString) -> bool {
    matches!(
        s.kind,
        StringKind::EntitlementsXml
            | StringKind::Section
            | StringKind::Base64
            | StringKind::Base32
            | StringKind::Base85
            | StringKind::HexEncoded
            | StringKind::UrlEncoded
            | StringKind::UnicodeEscaped
    ) || !validation::is_garbage(&s.value)
}

/// Merge a set of imports into the strings list.
/// Updates kind/library for strings already present, then appends new ones.
fn merge_imports(strings: &mut Vec<ExtractedString>, imports: Vec<ExtractedString>) {
    let import_map: HashMap<&str, (StringKind, Option<&str>)> = imports
        .iter()
        .map(|s| (s.value.as_str(), (s.kind, s.library.as_deref())))
        .collect();
    for s in strings.iter_mut() {
        if let Some(&(kind, lib)) = import_map.get(s.value.as_str()) {
            s.kind = kind;
            s.library = lib.map(ToString::to_string);
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

/// Apply Mach-O entitlements: remove overlapping strings, then append entitlement XML.
fn apply_entitlements(
    strings: &mut Vec<ExtractedString>,
    macho: &MachO<'_>,
    data: &[u8],
    min_length: usize,
) {
    let entitlements = entitlements::extract_macho_entitlements(macho, data, min_length);
    for ent in &entitlements {
        if ent.kind == StringKind::EntitlementsXml {
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
fn apply_xor_scan(
    strings: &mut Vec<ExtractedString>,
    data: &[u8],
    opts: &ExtractOptions,
    is_pe: bool,
) {
    if data.is_empty() {
        return;
    }
    let r2_boundaries = if opts.use_r2 {
        opts.path.as_deref().and_then(r2::extract_string_boundaries)
    } else {
        None
    };

    if let Some(ref key) = opts.xor_key {
        tracing::debug!("Custom XOR: using {} byte key", key.len());
        let key_str = String::from_utf8_lossy(key);
        if let Some(ks) = strings.iter_mut().find(|s| s.value == key_str.as_ref()) {
            ks.kind = StringKind::XorKey;
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
            tracing::info!("Auto-detected XOR key: '{}'", key_str);
            if let Some(ks) = strings.iter_mut().find(|s| s.value == key_str) {
                ks.kind = StringKind::XorKey;
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
            strings.extend(xor::extract_xor_strings(data, opts.xor_min_length, is_pe));
            if opts.xor_scan_multi {
                if let Some(ref path) = opts.path {
                    let xor_keys = r2::verify_xor_keys(path, strings);
                    tracing::debug!("Multi-byte XOR: found {} potential keys", xor_keys.len());
                    if !xor_keys.is_empty() {
                        let decoded =
                            xor::extract_multikey_xor_strings(data, &xor_keys, opts.xor_min_length);
                        tracing::debug!("Multi-byte XOR: decoded {} strings", decoded.len());
                        strings.extend(decoded);
                    }
                } else {
                    tracing::debug!("Multi-byte XOR: path not provided, skipping");
                }
            }
        }
    }
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
    if s.len() >= 14 && s.contains('Z') {
        if let Some(z_pos) = s.find('Z') {
            if z_pos >= 12 {
                let before_z = &s[..z_pos];
                if before_z.chars().rev().take(12).all(|c| c.is_ascii_digit()) {
                    return true;
                }
            }
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

/// Enrich strings with section information based on their file offsets (ELF)
fn enrich_elf_sections(strings: &mut [ExtractedString], elf: &goblin::elf::Elf<'_>) {
    for s in strings {
        if s.section.is_none() {
            // Find which section this offset belongs to
            for sh in &elf.section_headers {
                if s.data_offset >= sh.sh_offset && s.data_offset < sh.sh_offset + sh.sh_size {
                    if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
                        if !name.is_empty() {
                            s.section = Some(name.to_string());
                            break;
                        }
                    }
                }
            }
        }
    }
}

/// Convert Mach-O cputype to architecture string
fn cputype_to_arch_string(cputype: u32) -> &'static str {
    match cputype {
        CPU_TYPE_X86_64 => "x86_64",
        CPU_TYPE_ARM64 => "arm64",
        CPU_TYPE_X86 => "x86",
        CPU_TYPE_ARM => "arm",
        CPU_TYPE_POWERPC => "ppc",
        CPU_TYPE_POWERPC64 => "ppc64",
        _ => "unknown",
    }
}

/// Enrich strings with section information based on their file offsets (Mach-O)
///
/// `base_offset` is the file offset where this architecture starts (0 for regular binaries,
/// arch.offset for fat binaries).
fn enrich_macho_sections(
    strings: &mut [ExtractedString],
    macho: &goblin::mach::MachO<'_>,
    base_offset: u64,
) {
    let arch_name = cputype_to_arch_string(macho.header.cputype);
    // Calculate Mach-O header regions (relative to architecture start)
    // Header is 32 bytes for 64-bit, 28 bytes for 32-bit
    let header_size: u64 = if macho.is_64 { 32 } else { 28 };
    let load_cmds_end = base_offset + header_size + u64::from(macho.header.sizeofcmds);

    // Find LINKEDIT segment range (contains symbol/string tables)
    // Segment fileoff is relative to architecture, so add base_offset
    let mut linkedit_range: Option<(u64, u64)> = None;
    for segment in &macho.segments {
        if let Ok(name) = segment.name() {
            if name == "__LINKEDIT" {
                let start = base_offset + segment.fileoff;
                let end = start + segment.filesize;
                linkedit_range = Some((start, end));
                break;
            }
        }
    }

    for s in strings {
        // Check if section needs enrichment (None or empty string)
        let needs_section = s.section.as_ref().is_none_or(std::string::String::is_empty);
        if needs_section {
            // First check actual sections
            // Try both absolute and architecture-relative comparisons
            // (radare2 on fat binaries returns architecture-relative offsets)
            let mut found = false;
            for segment in &macho.segments {
                for (section, _data) in segment.into_iter().flatten() {
                    // Skip BSS/uninitialized sections (offset 0, no file content)
                    if section.offset == 0 {
                        continue;
                    }

                    // Try absolute file offset comparison first
                    let section_start_abs = base_offset + u64::from(section.offset);
                    let section_end_abs = section_start_abs + section.size;

                    // Try architecture-relative offset comparison second
                    let section_start_rel = u64::from(section.offset);
                    let section_end_rel = section_start_rel + section.size;

                    let matches_absolute =
                        s.data_offset >= section_start_abs && s.data_offset < section_end_abs;
                    let matches_relative =
                        s.data_offset >= section_start_rel && s.data_offset < section_end_rel;

                    if matches_absolute || matches_relative {
                        s.section = Some(section.name().unwrap_or("(unknown)").to_string());
                        s.architecture = Some(arch_name.to_string());
                        found = true;
                        break;
                    }
                }
                if found {
                    break;
                }
            }

            // If not in a section, check Mach-O specific regions
            if !found {
                if s.data_offset >= base_offset && s.data_offset < load_cmds_end {
                    // In header or load commands area
                    s.section = Some("load_commands".to_string());
                    s.architecture = Some(arch_name.to_string());
                } else if let Some((start, end)) = linkedit_range {
                    if s.data_offset >= start && s.data_offset < end {
                        // In LINKEDIT but not in a specific section (symbol/string tables)
                        s.section = Some("__LINKEDIT".to_string());
                        s.architecture = Some(arch_name.to_string());
                    }
                }
            }
        }
    }
}

/// Enrich strings with section information based on their file offsets (PE)
fn enrich_pe_sections(strings: &mut [ExtractedString], pe: &goblin::pe::PE<'_>) {
    for s in strings {
        if s.section.is_none() {
            // Find which section this offset belongs to
            for section in &pe.sections {
                let section_start = u64::from(section.pointer_to_raw_data);
                let section_end = section_start + u64::from(section.size_of_raw_data);
                if s.data_offset >= section_start && s.data_offset < section_end {
                    let name = String::from_utf8_lossy(&section.name)
                        .trim_end_matches('\0')
                        .to_string();
                    if !name.is_empty() {
                        s.section = Some(name);
                        break;
                    }
                }
            }
        }
    }
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
}

impl Default for ExtractOptions {
    fn default() -> Self {
        Self::new(4)
    }
}

impl ExtractOptions {
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
        }
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

fn method_priority(m: StringMethod) -> u8 {
    match m {
        // Highest priority: language-aware extraction and obfuscated decoded content
        StringMethod::Structure
        | StringMethod::StackString
        | StringMethod::XorStackPair
        | StringMethod::InstructionPattern
        | StringMethod::Base64ObfuscatedDecode => 3,

        // High priority: decoded/extracted content
        StringMethod::R2String
        | StringMethod::R2Symbol
        | StringMethod::WideString
        | StringMethod::XorDecode
        | StringMethod::Base64Decode
        | StringMethod::Base32Decode
        | StringMethod::Base85Decode
        | StringMethod::HexDecode
        | StringMethod::UrlDecode
        | StringMethod::UnicodeEscapeDecode
        | StringMethod::CodeSignature
        | StringMethod::Utf16LeDecode
        | StringMethod::Utf16BeDecode => 2,

        // Medium priority: heuristics
        StringMethod::Heuristic => 1,

        // Lowest priority: raw scanning
        StringMethod::RawScan => 0,
    }
}

/// Deduplicate strings by keeping only the best string at each offset.
/// Uses in-place sort-based deduplication to avoid allocating a large HashMap.
/// When multiple strings exist at the same offset, keeps the one with:
/// 1. Highest method priority (decoded > raw scan)
/// 2. Longest value (if same priority)
fn deduplicate_by_offset(mut strings: Vec<ExtractedString>) -> Vec<ExtractedString> {
    if strings.is_empty() {
        return strings;
    }

    // Sort by offset first, then by priority (best first), then by length (longest first)
    strings.sort_by(|a, b| {
        a.data_offset
            .cmp(&b.data_offset)
            .then_with(|| {
                // Higher priority first (reverse comparison)
                let pa = method_priority(a.method);
                let pb = method_priority(b.method);
                pb.cmp(&pa)
            })
            .then_with(|| {
                // Longer strings first (reverse comparison)
                b.value.len().cmp(&a.value.len())
            })
    });

    // Remove duplicates at the same offset (keep first, which is best due to sort)
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

    let code_units: Vec<u16> = utf16_data
        .chunks_exact(2)
        .map(|chunk| {
            if is_little_endian {
                u16::from_le_bytes([chunk[0], chunk[1]])
            } else {
                u16::from_be_bytes([chunk[0], chunk[1]])
            }
        })
        .collect();

    // Decode UTF-16 to UTF-8
    let decoded = String::from_utf16_lossy(&code_units);
    let decoded_bytes = decoded.as_bytes();

    // Extract strings from the decoded UTF-8 content
    let mut raw_strings =
        extract_raw_strings(decoded_bytes, opts.min_length, None, &[], &HashMap::new());

    // Apply decoders (base64, hex, URL-encoding, etc.) to the extracted strings
    // This allows us to find base64-encoded PowerShell, hex-encoded URLs, etc.
    let mut decoded_strings = Vec::new();
    decoded_strings.extend(decoders::decode_base64_strings(&raw_strings));
    decoded_strings.extend(fuzzy_base64::extract_fuzzy_base64(&raw_strings));
    decoded_strings.extend(decoders::decode_base32_strings(&raw_strings));
    decoded_strings.extend(decoders::decode_base85_strings(&raw_strings));
    decoded_strings.extend(decoders::decode_hex_strings(&raw_strings));
    decoded_strings.extend(decoders::decode_url_strings(&raw_strings));
    decoded_strings.extend(decoders::decode_unicode_escape_strings(&raw_strings));

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
    // Check for UTF-16 BOM first, before trying to parse as a binary format
    // This ensures text files with UTF-16 encoding are handled correctly
    if data.len() >= 2 {
        let has_utf16le_bom = data[0] == 0xFF && data[1] == 0xFE;
        let has_utf16be_bom = data[0] == 0xFE && data[1] == 0xFF;

        if has_utf16le_bom || has_utf16be_bom {
            tracing::debug!(
                "Detected UTF-16{} BOM, decoding entire file",
                if has_utf16le_bom { "LE" } else { "BE" }
            );
            return extract_from_utf16_file(data, opts, has_utf16le_bom);
        }
    }

    if let Ok(object) = Object::parse(data) {
        deduplicate_by_offset(extract_from_object(&object, data, opts))
    } else {
        // Unknown format - use r2 if available, otherwise raw scan
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
            ));
        }

        // Raw scan for all unknown formats
        if !data.is_empty() {
            strings.extend(extract_raw_strings(
                data,
                opts.min_length,
                None,
                &[],
                &HashMap::new(),
            ));
        }

        // XOR string detection
        apply_xor_scan(&mut strings, data, opts, is_pe);

        // Decode encoded strings (base64, hex, URL-encoding, unicode escapes)
        let mut decoded = Vec::new();
        decoded.extend(decoders::decode_base64_strings(&strings));
        decoded.extend(fuzzy_base64::extract_fuzzy_base64(&strings));
        decoded.extend(decoders::decode_base32_strings(&strings));
        decoded.extend(decoders::decode_base85_strings(&strings));
        decoded.extend(decoders::decode_hex_strings(&strings));
        decoded.extend(decoders::decode_url_strings(&strings));
        decoded.extend(decoders::decode_unicode_escape_strings(&strings));
        strings.extend(decoded);

        if opts.filter_garbage {
            strings.retain(passes_garbage_filter);
        }

        deduplicate_by_offset(strings)
    }
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

    match object {
        Object::Mach(goblin::mach::Mach::Binary(macho)) => {
            let segments = collect_macho_segments(macho);
            let section_info = collect_macho_section_info(macho);
            if macho_has_go_sections(macho) {
                is_go_binary = true;
                let extractor = GoStringExtractor::new(min_length);
                strings.extend(extractor.extract_macho(macho, data));
            } else if binary::macho_is_rust(macho) {
                let extractor = RustStringExtractor::new(min_length);
                strings.extend(extractor.extract_macho(macho, data));
            } else {
                // Unknown Mach-O - use r2 if available
                if let Some(r2_strings) = get_r2_strings(opts) {
                    strings.extend(r2_strings);
                }
                // Also do raw scan to catch anything r2 missed
                let extractor = RustStringExtractor::new(min_length);
                let rust_strings = extractor.extract_macho(macho, data);
                if rust_strings.is_empty() {
                    strings.extend(extract_raw_strings(
                        data,
                        min_length,
                        None,
                        &segments,
                        &section_info,
                    ));
                } else {
                    strings.extend(rust_strings);
                }
            }
            // Skip stack string extraction for Go binaries
            if !is_go_binary {
                strings.extend(extract_stack_strings(data, min_length));
            }
            merge_imports(&mut strings, extract_macho_imports(macho, min_length));
            apply_entitlements(&mut strings, macho, data, min_length);
        }
        Object::Mach(goblin::mach::Mach::Fat(fat)) => {
            // Fat binary - check for Go/Rust first
            let mut is_go = false;
            let mut is_rust = false;
            let mut segments = Vec::new();
            let mut section_info = std::collections::HashMap::new();
            let mut first_macho: Option<MachO<'_>> = None;
            for arch_result in fat {
                if let Ok(goblin::mach::SingleArch::MachO(macho)) = arch_result {
                    segments = collect_macho_segments(&macho);
                    section_info = collect_macho_section_info(&macho);
                    if macho_has_go_sections(&macho) {
                        is_go = true;
                        is_go_binary = true;
                        let extractor = GoStringExtractor::new(min_length);
                        strings.extend(extractor.extract_macho(&macho, data));
                    } else if binary::macho_is_rust(&macho) {
                        is_rust = true;
                        let extractor = RustStringExtractor::new(min_length);
                        strings.extend(extractor.extract_macho(&macho, data));
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
                ));
            }
            // Skip stack string extraction for Go binaries
            if !is_go_binary {
                strings.extend(extract_stack_strings(data, min_length));
            }
            if let Some(ref macho) = first_macho {
                merge_imports(&mut strings, extract_macho_imports(macho, min_length));
                apply_entitlements(&mut strings, macho, data, min_length);
            }
        }
        Object::Elf(elf) => {
            let segments = collect_elf_segments(elf);
            let section_info = collect_elf_section_info(elf);

            // Detect overlay first to avoid scanning it during normal extraction
            let overlay_info = detect_elf_overlay(data);
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
                let extractor = GoStringExtractor::new(min_length);
                strings.extend(extractor.extract_elf(elf, scan_data));
            } else if has_rust {
                let extractor = RustStringExtractor::new(min_length);
                strings.extend(extractor.extract_elf(elf, scan_data));
            } else {
                // Unknown ELF - use r2 if available + raw scan
                if let Some(r2_strings) = get_r2_strings(opts) {
                    strings.extend(r2_strings);
                }
                // Also do raw scan to catch anything r2 missed
                let extractor = RustStringExtractor::new(min_length);
                let rust_strings = extractor.extract_elf(elf, scan_data);
                if rust_strings.is_empty() {
                    strings.extend(extract_raw_strings(
                        scan_data,
                        min_length,
                        None,
                        &segments,
                        &section_info,
                    ));
                } else {
                    strings.extend(rust_strings);
                }
            }
            // Extract UTF-16LE wide strings (less common in ELF but can occur, especially in malware)
            strings.extend(extract_wide_strings(
                scan_data,
                min_length,
                None,
                &segments,
                &section_info,
            ));

            // Extract binary network data (IPs and ports in network byte order)
            strings.extend(scan_binary_ips(
                scan_data,
                min_length,
                elf.header.e_machine,
                Some(elf),
                None,
            ));

            if is_go_binary {
                // For Go binaries, run XOR-pair extraction on the .text section only.
                // garble-obfuscated Go malware (e.g. BrickStorm) stores sensitive strings
                // as two non-printable immediate constants on the stack and XORs them at
                // runtime — the Go string extractor misses these entirely.
                // We restrict to .text to avoid noise from data sections and only keep
                // XorStackPair results (regular stack string detection is too noisy in Go).
                let text_data = elf
                    .section_headers
                    .iter()
                    .find(|sh| elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("") == ".text")
                    .and_then(|sh| {
                        let start = sh.sh_offset as usize;
                        let end = start.saturating_add(sh.sh_size as usize);
                        let text = scan_data.get(start..end)?;
                        Some((start, text))
                    });
                if let Some((text_start, text)) = text_data {
                    let mut xor_results = extract_stack_strings(text, min_length);
                    // Adjust data_offset to file-relative position.
                    for r in &mut xor_results {
                        r.data_offset += text_start as u64;
                    }
                    strings.extend(
                        xor_results
                            .into_iter()
                            .filter(|s| s.method == StringMethod::XorStackPair),
                    );
                }
            } else {
                strings.extend(extract_stack_strings(scan_data, min_length));
            }
            merge_imports(&mut strings, extract_elf_imports(elf, min_length));

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
                .map(|sec| {
                    String::from_utf8_lossy(&sec.name)
                        .trim_end_matches('\0')
                        .to_string()
                })
                .collect();
            let section_info = collect_pe_section_info(pe);

            // Check for Go by looking for go.buildinfo section specifically
            let has_go = pe.sections.iter().any(|sec| {
                let name = String::from_utf8_lossy(&sec.name);
                name.contains("go.buildinfo") || name.contains("gopclntab")
            });

            if has_go {
                is_go_binary = true;
                let extractor = GoStringExtractor::new(min_length);
                strings.extend(extractor.extract_pe(pe, data));
            }

            // Use r2 if available
            if let Some(r2_strings) = get_r2_strings(opts) {
                strings.extend(r2_strings);
            }

            // Extract UTF-16LE wide strings (common in Windows binaries)
            strings.extend(extract_wide_strings(
                data,
                min_length,
                None,
                &segments,
                &section_info,
            ));

            // Extract binary network data (IPs and ports in network byte order)
            strings.extend(scan_binary_ips(
                data,
                min_length,
                pe.header.coff_header.machine,
                None,
                Some(pe),
            ));

            // Raw scan for PE (catches strings missed by structure extraction)
            strings.extend(extract_raw_strings(
                data,
                min_length,
                None,
                &segments,
                &section_info,
            ));

            // Skip stack string extraction for Go binaries
            if !is_go_binary {
                strings.extend(extract_stack_strings(data, min_length));
            }

            // Extract overlay/appended data (common malware technique)
            strings.extend(extract_overlay_strings(data, min_length));
        }
        _ => {
            // Unknown format - use r2 if available, otherwise raw scan
            if let Some(r2_strings) = get_r2_strings(opts) {
                strings.extend(r2_strings);
            }
            if strings.is_empty() && !data.is_empty() {
                strings.extend(extract_raw_strings(
                    data,
                    min_length,
                    None,
                    &[],
                    &HashMap::new(),
                ));
            }
            // Extract binary network data (IPs and ports in network byte order)
            // For unknown formats, use 0 (not M68000) to process normally
            strings.extend(scan_binary_ips(data, min_length, 0, None, None));
            strings.extend(extract_stack_strings(data, min_length));
        }
    }

    // XOR string detection - skip for Go binaries (they don't use XOR obfuscation)
    if !is_go_binary {
        let is_pe = matches!(object, Object::PE(_));
        apply_xor_scan(&mut strings, data, opts, is_pe);
    }

    // Extract IP addresses from connect() syscalls using radare2 (if enabled)
    // Skip for large files (>10MB) as even binary scan has diminishing returns
    if opts.use_r2 && data.len() <= 10 * 1024 * 1024 {
        if let Some(ref path) = opts.path {
            let connect_addrs = r2::extract_connect_addrs(path, data);
            if !connect_addrs.is_empty() {
                tracing::debug!(
                    "Found {} IP addresses from connect() calls",
                    connect_addrs.len()
                );
                strings.extend(connect_addrs);
            }
        }
    }

    // Enrich all strings with section information based on file offsets
    // This happens AFTER all extraction (including XOR) is complete
    match object {
        Object::Elf(elf) => enrich_elf_sections(&mut strings, elf),
        Object::Mach(goblin::mach::Mach::Binary(macho)) => {
            enrich_macho_sections(&mut strings, macho, 0)
        }
        Object::Mach(goblin::mach::Mach::Fat(fat)) => {
            // Collect architecture offsets first
            let arch_offsets: Vec<u64> = fat
                .iter_arches()
                .filter_map(std::result::Result::ok)
                .map(|a| u64::from(a.offset))
                .collect();

            // Enrich strings against each architecture
            for (macho_result, base_offset) in fat.into_iter().zip(arch_offsets) {
                if let Ok(goblin::mach::SingleArch::MachO(macho)) = macho_result {
                    enrich_macho_sections(&mut strings, &macho, base_offset);
                }
            }
        }
        Object::PE(pe) => enrich_pe_sections(&mut strings, pe),
        _ => {}
    }

    // Upgrade strings in __LINKEDIT section related to code signatures
    // __LINKEDIT contains symbol tables AND the code signature blob
    // This must happen AFTER section enrichment so section names are populated
    for s in &mut strings {
        if let Some(ref section) = s.section {
            if section == "__LINKEDIT" {
                // Base64 strings in __LINKEDIT that decode to SHA-1 (20 bytes) or
                // SHA-256 (32 bytes) are CD hashes. Other base64 content (certificate
                // data, etc.) decodes to different sizes and must not be promoted.
                if s.kind == StringKind::Base64 {
                    let decoded_len = base64::Engine::decode(
                        &base64::engine::general_purpose::STANDARD,
                        s.value.trim(),
                    )
                    .map(|b| b.len())
                    .unwrap_or(0);
                    if decoded_len == 20 || decoded_len == 32 {
                        s.kind = StringKind::CodeSignatureHash;
                        s.method = StringMethod::CodeSignature;
                    }
                }

                // XML/plist strings in __LINKEDIT are part of code signature
                // (entitlements or code signature metadata like cdhashes)
                if s.kind == StringKind::Const
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
                // These are Distinguished Names, dates, CRL URLs, and policy text.
                // Also covers Base64-classified strings that are actually ASN.1 date
                // fragments (e.g. "350209214036Z0b1") which are not CD hashes.
                if (s.kind == StringKind::Const || s.kind == StringKind::Base64)
                    && is_certificate_string(&s.value)
                {
                    s.method = StringMethod::CodeSignature;
                }

                // Bundle IDs (reverse domain notation) in __LINKEDIT are often app identifiers
                if s.kind == StringKind::Const && is_bundle_id(&s.value) {
                    s.kind = StringKind::AppId;
                }
            }
        }
    }

    // Decode encoded strings (base64, hex, URL-encoding, unicode escapes)
    // This happens BEFORE garbage filtering so we can decode potentially-garbage-looking encodings
    let mut decoded = Vec::new();
    decoded.extend(decoders::decode_base64_strings(&strings));
    decoded.extend(fuzzy_base64::extract_fuzzy_base64(&strings));
    decoded.extend(decoders::decode_base32_strings(&strings));
    decoded.extend(decoders::decode_base85_strings(&strings));
    decoded.extend(decoders::decode_hex_strings(&strings));
    decoded.extend(decoders::decode_url_strings(&strings));
    decoded.extend(decoders::decode_unicode_escape_strings(&strings));

    // Add decoded strings to the main list
    strings.extend(decoded);

    if opts.filter_garbage {
        strings.retain(passes_garbage_filter);
    }

    deduplicate_by_offset(strings)
}

/// Helper to get r2 strings from options (pre-extracted or by running r2)
fn get_r2_strings(opts: &ExtractOptions) -> Option<Vec<ExtractedString>> {
    // Use pre-extracted r2 strings if provided
    if let Some(ref r2_strings) = opts.r2_strings {
        return Some(r2_strings.clone());
    }
    // Otherwise run r2 if enabled
    if opts.use_r2 {
        if let Some(ref path) = opts.path {
            return r2::extract_strings(path, opts.min_length, opts.use_cache);
        }
    }
    None
}
