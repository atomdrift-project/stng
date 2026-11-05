//! Core types for string extraction.
//!
//! This module defines the fundamental data structures used throughout
//! the string extraction process.

use serde::{Deserialize, Serialize};

/// Represents a string structure found in binary (pointer + length pair).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct StringStruct {
    /// Offset in the section where this structure was found
    pub struct_offset: u64,
    /// Virtual address of the string data
    pub ptr: u64,
    /// Length of the string
    pub len: u64,
}

/// Where a string lies in the file: the NUL-bounded extents around strings
/// the raw scan found, used to aim XOR decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct StringBoundary {
    /// File offset of the string's first byte.
    pub offset: u64,
    /// Length in bytes.
    pub length: usize,
}

impl StringBoundary {
    /// A string of `length` bytes at file offset `offset`.
    #[must_use]
    pub(crate) fn new(offset: u64, length: usize) -> Self {
        Self { offset, length }
    }
}

/// Represents a fragment of a multi-part string (e.g., stack strings from multiple instructions)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[non_exhaustive]
pub struct StringFragment {
    /// File offset where this fragment's data is located
    pub offset: u64,
    /// Length of this fragment in bytes
    pub length: usize,
}

impl StringFragment {
    /// The `length` bytes at file offset `offset`.
    #[must_use]
    pub fn new(offset: u64, length: usize) -> Self {
        Self { offset, length }
    }
}

/// An extracted string with metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ExtractedString {
    /// The string value
    pub value: String,
    /// Offset in the binary where the string data is located
    pub data_offset: u64,
    /// Source byte length of the string's contiguous extent, starting at
    /// `data_offset` — i.e. the location is the span `[data_offset,
    /// data_offset + data_len)`.
    ///
    /// This is the **source (encoded) length**, recorded by the extractor that
    /// consumed the bytes: 2×code-units for UTF-16LE, the base64 token length
    /// for a decoded payload — NOT the decoded `value` length. `0` means the
    /// extractor didn't record it, which is only the case for byte-identical
    /// scans (plain ASCII/UTF-8) where `value.len()` *is* the source length.
    /// Ignored when `fragments` is set (the source is then those scattered
    /// spans). Use [`source_spans`](Self::source_spans), never `value.len()`,
    /// to locate the string. `u32` because a single string never spans 4 GiB,
    /// keeping the per-string cost to 4 bytes — the doc on `fragments` records
    /// why a heavier inline representation was rejected.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub data_len: u32,
    /// How the string was found
    pub method: StringMethod,
    /// Semantic kind of the string (None means no specific classification)
    pub kind: Option<StringKind>,
    /// Source fragments for multi-part (`StackString`) values — boxed because
    /// it is set on well under 1% of strings, and an extraction holds ~100k+
    /// transient `ExtractedString`s at peak, so an inline `Option<Vec<_>>`
    /// (24 B on every string) dominated peak RSS. Behind `Option<Box<_>>` the
    /// common case is 8 bytes and the rare case pays one allocation.
    /// Read with [`fragments`](Self::fragments).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[expect(
        clippy::box_collection,
        reason = "8 bytes per string, not 24; see above"
    )]
    pub(crate) fragments: Option<Box<Vec<StringFragment>>>,
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's skip_serializing_if passes a reference"
)]
fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}

/// Drop each string whose value an earlier one has, keeping their order.
/// Borrows the values rather than copying each into the set.
pub(crate) fn dedup_by_value(strings: &mut Vec<ExtractedString>) {
    let mut seen = std::collections::HashSet::with_capacity(strings.len());
    let keep: Vec<bool> = strings
        .iter()
        .map(|s| seen.insert(s.value.as_str()))
        .collect();
    let mut keep = keep.into_iter();
    strings.retain(|_| keep.next().unwrap_or(true));
}

impl ExtractedString {
    /// The scattered source spans of a multi-part (stack-built) value, in
    /// order; empty for a contiguous string.
    #[must_use]
    pub fn fragments(&self) -> &[StringFragment] {
        self.fragments.as_deref().map_or(&[], Vec::as_slice)
    }

    /// `value`, found at file offset `data_offset` by `method`, with no kind
    /// and a source as long as `value`. Adjust with the `with_*` methods.
    #[must_use]
    pub fn new(value: impl Into<String>, data_offset: u64, method: StringMethod) -> Self {
        Self {
            value: value.into(),
            data_offset,
            method,
            ..Self::default()
        }
    }

    /// The same string, classified as `kind` (a kind, or `None` to clear it).
    #[must_use]
    pub fn with_kind(mut self, kind: impl Into<Option<StringKind>>) -> Self {
        self.kind = kind.into();
        self
    }

    /// The same string, whose source is `len` bytes (when that differs from
    /// `value`'s length: an encoded token, UTF-16).
    #[must_use]
    pub fn with_data_len(mut self, len: u32) -> Self {
        self.data_len = len;
        self
    }

    /// The same string, assembled from the source `fragments`.
    #[must_use]
    pub fn with_fragments(mut self, fragments: Vec<StringFragment>) -> Self {
        self.fragments = Some(Box::new(fragments));
        self
    }

    /// The source byte spans this string was recovered from, as `(offset,
    /// len)` pairs: the scattered `fragments` for a `StackString`, otherwise
    /// its single contiguous extent. `len` is `data_len` when the extractor
    /// recorded it, else the byte-identical `value` length.
    ///
    /// This is the one correct way to locate a string in the source, for any
    /// encoding — consumers must use it rather than deriving a span from
    /// `value.len()`, which is the decoded length and undercounts UTF-16LE /
    /// base64 / other re-encoded strings.
    pub fn source_spans(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        let single = self
            .fragments
            .is_none()
            .then(|| (self.data_offset, u64::from(self.contiguous_source_len())));
        self.fragments
            .iter()
            .flat_map(|fragments| fragments.iter().map(|f| (f.offset, f.length as u64)))
            .chain(single)
    }

    /// Move this string's source location by `delta` bytes: its offset and
    /// every fragment. Extractors report offsets relative to the bytes they
    /// were given; callers lift them into the file with this.
    pub(crate) fn rebase(&mut self, delta: u64) {
        // Saturating: offsets derive from hostile headers.
        self.data_offset = self.data_offset.saturating_add(delta);
        for fragment in self.fragments.iter_mut().flat_map(|f| f.iter_mut()) {
            fragment.offset = fragment.offset.saturating_add(delta);
        }
    }

    /// Source byte length of this string's single contiguous extent: the
    /// recorded `data_len`, or the value's byte length when unrecorded (only
    /// the byte-identical scans leave it unrecorded). A string decoded from
    /// this one occupies the same source bytes, so it inherits this extent.
    /// Not meaningful for a `StackString` (use [`source_spans`](Self::source_spans)).
    #[must_use]
    pub(crate) fn contiguous_source_len(&self) -> u32 {
        if self.data_len > 0 {
            self.data_len
        } else {
            u32::try_from(self.value.len()).unwrap_or(u32::MAX)
        }
    }
}

impl Default for ExtractedString {
    fn default() -> Self {
        Self {
            value: String::new(),
            data_offset: 0,
            data_len: 0,
            method: StringMethod::RawScan,
            kind: None,
            fragments: None,
        }
    }
}

/// CPU architecture of the binary the string was extracted from.
///
/// Used by validation rules that depend on architecture-specific byte
/// patterns (notably `is_x86_save_sequence_fragment`, which detects
/// REX-prefix + push/pop opcode sequences that only x86-64 emits).
/// `None` on a `StringContext::arch` means "unknown" and rules treat
/// that as "may be x86, apply heuristics" — so callers that omit the
/// hint get current behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub(crate) enum Arch {
    /// 32-bit x86.
    X86,
    /// x86-64.
    X86_64,
    /// 32-bit ARM.
    Arm,
    /// 64-bit ARM.
    Aarch64,
    /// 32-bit MIPS.
    Mips,
    /// 64-bit MIPS.
    Mips64,
    /// 32-bit PowerPC.
    PowerPc,
    /// 64-bit PowerPC.
    PowerPc64,
    /// 32-bit RISC-V.
    RiscV,
    /// 64-bit RISC-V.
    RiscV64,
    /// SPARC.
    Sparc,
    /// WebAssembly.
    Wasm,
    /// Any other architecture.
    Other,
}

impl Arch {
    /// `true` for x86-family architectures (x86 and x86-64).  Used by
    /// rules that decode bytes assuming x86 instruction encoding.
    #[must_use]
    pub(crate) fn is_x86_family(self) -> bool {
        matches!(self, Self::X86 | Self::X86_64)
    }
}

/// Context passed to the validation rules so architecture- and
/// section-aware filters can scope themselves correctly.
///
/// All fields are optional with `None`-as-"unknown" semantics — every
/// existing caller of `is_garbage` keeps its
/// behavior because the empty context is treated as "no info, apply
/// the heuristics globally".  Callers that DO know the arch or
/// section can construct a richer context to suppress filters that
/// don't apply to their input (e.g. an ARM binary skips the x86
/// save-sequence filter; a `.rodata` string skips it too).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub(crate) struct StringContext {
    /// Semantic kind from the extractor (URL, Path, Section, …).
    /// What the extractor already recognised the string as, if anything.
    pub(crate) kind: Option<StringKind>,
    /// Whether the string lives in an executable (code) section, when
    /// known. `Some(false)` lets code-only rules (the x86 save-sequence
    /// detector) opt out; `None` means "unknown — apply the rule".
    pub(crate) in_code_section: Option<bool>,
    /// CPU architecture, when known.  `None` means "no info — assume
    /// any rule may apply"; `Some(non-x86)` switches off x86-only
    /// rules without the caller having to know which they are.
    pub(crate) arch: Option<Arch>,
}

impl StringContext {
    /// A context that assumes nothing: what [`is_garbage`](crate::is_garbage)
    /// uses.
    #[must_use]
    pub(crate) fn empty() -> Self {
        Self::default()
    }
}

/// Method used to extract the string.
///
/// Indicates the extraction technique, which affects confidence and context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum StringMethod {
    /// Found via language string layout (pointer+length or tagged inline bytes)
    Structure,
    /// Found via instruction pattern analysis (inline literals)
    InstructionPattern,
    /// Found via traditional null-terminated/ASCII scan (fallback)
    RawScan,
    /// Found via heuristic pattern matching (Rust packed strings)
    Heuristic,
    /// Found via UTF-16LE wide string scan (Windows)
    WideString,
    /// Found via space-padded ASCII decoding (.NET metadata format)
    SpacedAscii,
    /// Found via XOR decoding (single-byte or recovered repeating key)
    XorDecode,
    /// Found via base64 decoding, including zlib-compressed text payloads
    Base64Decode,
    /// Found via obfuscated base64 decoding (string concatenation, char substitution)
    Base64ObfuscatedDecode,
    /// Found via hex decoding
    HexDecode,
    /// Found via URL decoding
    UrlDecode,
    /// Found via unicode escape decoding (\xHH, \uHHHH, \UHHHHHHHH)
    UnicodeEscapeDecode,
    /// Found via base32 decoding
    Base32Decode,
    /// Found via base85 decoding (ASCII85/Z85)
    Base85Decode,
    /// Found via rot13 of a string that is base64 only after rotation
    Rot13Base64Decode,
    /// Found via stack string construction analysis (immediate values)
    StackString,
    /// Found in Mach-O code signature (entitlements)
    CodeSignature,
    /// Found via UTF-16LE whole-file decoding (BOM detected)
    Utf16LeDecode,
    /// Found via UTF-16BE whole-file decoding (BOM detected)
    Utf16BeDecode,
    /// Found via XOR of two stack-placed non-printable immediate constants (e.g. BrickStorm/garble style)
    XorStackPair,
    /// The repeating XOR key of a whole file that decodes to a PE image,
    /// rendered `0x<hex>` (see [`recover_repeating_xor_pe`](crate::recover_repeating_xor_pe))
    XorRepeatingKey,
    /// Found via script deobfuscation (decoded payload from obfuscated Python/JS/PHP/PowerShell)
    ScriptDecode,
    /// Found by decrypting a legacy Allaire/Adobe ColdFusion template
    CfmlDecode,
    /// Found via Go pclntab (program counter line table) symbol extraction
    PclntabSymbol,
}

impl StringMethod {
    /// Priority for deduplication: when two strings share an offset, the higher-priority
    /// method wins. Decoded and language-aware results beat raw scanning.
    #[must_use]
    pub fn dedup_priority(self) -> u8 {
        match self {
            // Highest: language-aware and decoded content — most trustworthy
            Self::Structure
            | Self::StackString
            | Self::XorStackPair
            | Self::XorRepeatingKey
            | Self::InstructionPattern
            | Self::XorDecode
            | Self::Base64Decode
            | Self::Base32Decode
            | Self::Base85Decode
            | Self::Rot13Base64Decode
            | Self::HexDecode
            | Self::UrlDecode
            | Self::UnicodeEscapeDecode
            | Self::Utf16LeDecode
            | Self::Utf16BeDecode
            | Self::ScriptDecode
            | Self::CfmlDecode => 3,

            // High: rich metadata sources
            Self::WideString | Self::SpacedAscii | Self::CodeSignature | Self::PclntabSymbol => 2,

            Self::Heuristic => 1,
            Self::RawScan | Self::Base64ObfuscatedDecode => 0,
        }
    }

    /// Whether the string is another extracted string's text decoded in
    /// place, and so shares that string's offset.
    pub(crate) fn decodes_a_string(self) -> bool {
        matches!(
            self,
            Self::Base64Decode
                | Self::Base64ObfuscatedDecode
                | Self::Base32Decode
                | Self::Base85Decode
                | Self::Rot13Base64Decode
                | Self::HexDecode
                | Self::UrlDecode
                | Self::UnicodeEscapeDecode
                | Self::ScriptDecode
        )
    }

    /// A short label for the method's column in the `stng` listing: what
    /// was decoded (`xor`, `b64`, `script`), or empty for plain extraction.
    #[must_use]
    pub fn short_name(self) -> &'static str {
        match self {
            Self::XorDecode | Self::XorStackPair | Self::XorRepeatingKey => "xor",
            Self::Base64ObfuscatedDecode => "b64+obf",
            Self::Base64Decode => "b64",
            Self::HexDecode => "hex",
            Self::UrlDecode => "url",
            Self::UnicodeEscapeDecode => "unicode",
            Self::Base32Decode => "b32",
            Self::Base85Decode => "b85",
            Self::CodeSignature => "codesig",
            Self::WideString => "wide",
            Self::SpacedAscii => "spaced",
            Self::ScriptDecode => "script",
            Self::Rot13Base64Decode => "rot13",
            Self::Utf16LeDecode | Self::Utf16BeDecode => "utf16",
            Self::CfmlDecode => "cfml",
            Self::StackString => "stack",
            // Plain extraction: no decoding to call out.
            Self::Structure
            | Self::InstructionPattern
            | Self::RawScan
            | Self::Heuristic
            | Self::PclntabSymbol => "",
        }
    }
}

/// Semantic kind of the extracted string.
///
/// Classifies strings by their purpose and security relevance.
/// None means the string has no specific classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum StringKind {
    /// Function or method name
    FuncName,
    /// Source file path
    FilePath,
    /// Map/dictionary key
    MapKey,
    /// Error message
    Error,
    /// Environment variable name
    EnvVar,
    /// URL or URI
    Url,
    /// File system path
    Path,
    /// Function argument (inline literal)
    Arg,
    /// Identifier (variable, type name, etc.)
    Ident,
    /// Low-value garbage string (misaligned reads, noise)
    Garbage,
    /// Binary segment/section name (__TEXT, .rodata, etc.)
    Section,
    /// Imported symbol from external library
    Import,
    /// Exported symbol
    Export,
    // Security-focused classifications
    /// IP address (v4 or v6)
    Ip,
    /// IP:port or host:port combination
    IpPort,
    /// Hostname (domain name like evil.com)
    Hostname,
    /// Shell command (pipes, redirects, common commands)
    ShellCmd,
    /// `AppleScript` code (common in macOS malware)
    AppleScript,
    /// Python code (import statements, def/class keywords, python-specific calls)
    PythonCode,
    /// JavaScript code (function declarations, const/let/var, require, arrow functions)
    JavaScriptCode,
    /// PHP code (<?php tags, $ variables, `eval(base64_decode)`)
    PhpCode,
    /// PowerShell code (-EncodedCommand, Invoke-Expression, iex, etc.)
    PowerShellCode,
    /// Suspicious path (hidden dirs, rootkit locations, persistence)
    SuspiciousPath,
    /// Windows registry path
    Registry,
    /// Base64-encoded data
    Base64,
    /// Code signature hash (CD hash in Mach-O __LINKEDIT section)
    CodeSignatureHash,
    /// Hex-encoded ASCII data (each byte as two hex chars)
    HexEncoded,
    /// Unicode escape sequences (\xXX, \uXXXX format)
    UnicodeEscaped,
    /// URL-encoded data (%XX format)
    UrlEncoded,
    /// Base32-encoded data
    Base32,
    /// Base58-encoded data (Bitcoin/cryptocurrency)
    Base58,
    /// Base85-encoded data (ASCII85/Z85)
    Base85,
    /// Overlay/appended data after ELF/PE boundary (ASCII/UTF-8)
    Overlay,
    // Cryptocurrency and ransomware IOCs
    /// Cryptocurrency wallet address (Bitcoin, Ethereum, Monero, etc.)
    CryptoWallet,
    /// Cryptocurrency mining pool URL or stratum address
    MiningPool,
    /// Email address (often used in ransomware contact info)
    Email,
    /// Tor/Onion address (.onion domain)
    TorAddress,
    /// CTF competition flag (CTF{...}, flag{...}, etc.)
    CtfFlag,
    /// SQL injection payload
    SqlInjection,
    /// XSS (Cross-Site Scripting) payload
    XssPayload,
    /// Command injection pattern
    CommandInjection,
    /// JWT (JSON Web Token)
    Jwt,
    /// API key or secret (AWS, GitHub, Stripe, etc.)
    ApiKey,
    /// Windows mutex or synchronization object name
    Mutex,
    /// GUID (Globally Unique Identifier)
    Guid,
    /// Cryptographic hash (MD5, SHA1, SHA256, SHA512)
    Hash,
    /// Ransomware-related string (ransom note, file extension, etc.)
    RansomNote,
    /// LDAP/Active Directory distinguished name
    LdapPath,
    /// Overlay data in UTF-16LE encoding (common in malware configs)
    OverlayWide,
    /// Stack-constructed string (common in malware)
    StackString,
    /// macOS entitlement from code signature
    Entitlement,
    /// Application/service identifier from entitlements
    AppId,
    /// Raw entitlements XML plist from Mach-O code signature
    EntitlementsXml,
    /// XOR encryption key (detected or provided)
    XorKey,
}

/// Severity level for security-focused output.
///
/// Used to prioritize and highlight critical findings in security analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Severity {
    /// Default: constants, identifiers
    Info,
    /// Supporting info: function names, exports
    Low,
    /// Important context: paths, env vars, imports
    Medium,
    /// Critical IOCs: IPs, URLs, shell commands, suspicious paths
    High,
}

impl StringKind {
    /// Returns `true` if this kind is produced by `classifier::classify_string`
    /// (content-pattern recognition), as opposed to an extractor-assigned label
    /// like `Overlay`, `Section`, `Import`, or `StackString`.
    ///
    /// Used by the garbage-filter fast path to skip a redundant
    /// `classify_string` call: if the extractor already labelled a string with
    /// one of these kinds, the classifier would also label it — so
    /// re-validation is pure waste.  Extractor-only labels fall through to
    /// the classifier because the filter uses its recognition to decide
    /// "meaningful".
    #[must_use]
    pub fn is_classifier_output(self) -> bool {
        matches!(
            self,
            Self::Url
                | Self::Path
                | Self::FilePath
                | Self::Email
                | Self::Ip
                | Self::IpPort
                | Self::Hash
                | Self::Guid
                | Self::Jwt
                | Self::ApiKey
                | Self::Registry
                | Self::CryptoWallet
                | Self::MiningPool
                | Self::TorAddress
                | Self::ShellCmd
                | Self::SuspiciousPath
                | Self::CtfFlag
                | Self::Mutex
                | Self::LdapPath
                | Self::HexEncoded
                | Self::UnicodeEscaped
                | Self::UrlEncoded
                | Self::AppleScript
                | Self::PythonCode
                | Self::JavaScriptCode
                | Self::PhpCode
                | Self::SqlInjection
                | Self::XssPayload
                | Self::CommandInjection
                | Self::RansomNote
                | Self::EnvVar
        )
    }

    /// Get the severity level for this kind
    #[must_use]
    pub fn severity(self) -> Severity {
        match self {
            Self::Ip
            | Self::IpPort
            | Self::Hostname
            | Self::Url
            | Self::ShellCmd
            | Self::SuspiciousPath
            | Self::Base64
            | Self::HexEncoded
            | Self::UnicodeEscaped
            | Self::UrlEncoded
            | Self::Base32
            | Self::Base58
            | Self::Base85
            | Self::Overlay
            | Self::OverlayWide
            | Self::StackString
            | Self::Entitlement
            | Self::AppId
            | Self::XorKey
            | Self::CryptoWallet
            | Self::MiningPool
            | Self::Email
            | Self::TorAddress
            | Self::CtfFlag
            | Self::SqlInjection
            | Self::XssPayload
            | Self::CommandInjection
            | Self::Jwt
            | Self::ApiKey
            | Self::Mutex
            | Self::Guid
            | Self::Hash
            | Self::RansomNote
            | Self::LdapPath => Severity::High,

            Self::Path
            | Self::FilePath
            | Self::Import
            | Self::EnvVar
            | Self::Registry
            | Self::Error
            | Self::Section
            | Self::EntitlementsXml => Severity::Medium,

            Self::FuncName | Self::Export => Severity::Low,

            // Explicit (not `_`) so a newly added StringKind must choose a severity.
            Self::MapKey
            | Self::Arg
            | Self::Ident
            | Self::Garbage
            | Self::CodeSignatureHash
            | Self::AppleScript
            | Self::PythonCode
            | Self::JavaScriptCode
            | Self::PhpCode
            | Self::PowerShellCode => Severity::Info,
        }
    }

    /// Get short display name for the kind
    #[must_use]
    pub fn short_name(self) -> &'static str {
        match self {
            Self::FuncName => "func",
            Self::FilePath => "file",
            Self::MapKey => "key",
            Self::Error => "error",
            Self::EnvVar => "env",
            Self::Url => "url",
            Self::Path => "path",
            Self::Arg => "arg",
            Self::Ident => "ident",
            Self::Garbage => "garbage",
            Self::Section => "section",
            Self::Import => "import",
            Self::Export => "export",
            Self::Ip => "ip",
            Self::IpPort => "ip:port",
            Self::Hostname => "host",
            Self::ShellCmd => "shell",
            Self::SuspiciousPath => "sus",
            Self::Registry => "registry",
            Self::Base64 => "base64",
            Self::CodeSignatureHash | Self::Hash => "hash",
            Self::HexEncoded => "hex",
            Self::UnicodeEscaped => "unicode",
            Self::UrlEncoded => "urlenc",
            Self::Base32 => "base32",
            Self::Base58 => "base58",
            Self::Base85 => "base85",
            Self::Overlay => "overlay",
            Self::OverlayWide => "overlay:16LE",
            Self::StackString => "stack",
            Self::Entitlement => "entitlement",
            Self::AppId => "appid",
            Self::EntitlementsXml => "entitlements",
            Self::XorKey => "xor_key",
            Self::CryptoWallet => "crypto",
            Self::MiningPool => "miner",
            Self::Email => "email",
            Self::TorAddress => "tor",
            Self::CtfFlag => "ctf_flag",
            Self::SqlInjection => "sqli",
            Self::XssPayload => "xss",
            Self::CommandInjection => "cmdi",
            Self::Jwt => "jwt",
            Self::ApiKey => "api_key",
            Self::Mutex => "mutex",
            Self::Guid => "guid",
            Self::RansomNote => "ransom",
            Self::LdapPath => "ldap",
            Self::AppleScript => "applescript",
            Self::PythonCode => "python",
            Self::JavaScriptCode => "javascript",
            Self::PhpCode => "php",
            Self::PowerShellCode => "powershell",
        }
    }
}

/// Binary information needed for string extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct BinaryInfo {
    /// A 64-bit binary.
    pub is_64bit: bool,
    /// Little-endian byte order.
    pub is_little_endian: bool,
    /// Pointer size in bytes: 8 for 64-bit binaries, 4 otherwise.
    pub ptr_size: usize,
}

impl BinaryInfo {
    /// Create `BinaryInfo` from ELF header information
    #[must_use]
    pub(crate) fn from_elf(is_64bit: bool, is_little_endian: bool) -> Self {
        Self {
            is_64bit,
            is_little_endian,
            ptr_size: if is_64bit { 8 } else { 4 },
        }
    }

    /// Create `BinaryInfo` from Mach-O (always little-endian on modern systems)
    #[must_use]
    pub(crate) fn from_macho(is_64bit: bool) -> Self {
        Self {
            is_64bit,
            is_little_endian: true, // All modern Mach-O is LE
            ptr_size: if is_64bit { 8 } else { 4 },
        }
    }

    /// Create `BinaryInfo` from PE (always little-endian)
    #[must_use]
    pub(crate) fn from_pe(is_64bit: bool) -> Self {
        Self {
            is_64bit,
            is_little_endian: true, // PE is always LE
            ptr_size: if is_64bit { 8 } else { 4 },
        }
    }
}

/// Information about trailing/overlay data appended after the binary structure.
///
/// Overlay data is commonly used by malware to hide payloads or configuration.
/// This struct identifies data appended beyond the normal ELF/PE structure boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct OverlayInfo {
    /// Offset where the overlay data begins
    pub start_offset: u64,
    /// Size of the overlay data in bytes
    pub size: u64,
}

#[cfg(test)]
mod tests;
