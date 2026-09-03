//! Core types for string extraction.
//!
//! This module defines the fundamental data structures used throughout
//! the string extraction process.

use serde::{Deserialize, Serialize};

/// Represents a string structure found in binary (pointer + length pair).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StringStruct {
    /// Offset in the section where this structure was found
    pub struct_offset: u64,
    /// Virtual address of the string data
    pub ptr: u64,
    /// Length of the string
    pub len: u64,
}

/// Represents a fragment of a multi-part string (e.g., stack strings from multiple instructions)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringFragment {
    /// File offset where this fragment's data is located
    pub offset: u64,
    /// Length of this fragment in bytes
    pub length: usize,
}

/// An extracted string with metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fragments: Option<Box<Vec<StringFragment>>>,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde skip_serializing_if signature
fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}

/// Iterator over a string's source byte spans — see
/// [`ExtractedString::source_spans`].
pub enum SourceSpans<'a> {
    /// The single contiguous extent of a normal string.
    Single(std::iter::Once<(u64, u64)>),
    /// The scattered fragments of a `StackString`.
    Fragments(std::slice::Iter<'a, StringFragment>),
}

impl Iterator for SourceSpans<'_> {
    type Item = (u64, u64);
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            SourceSpans::Single(it) => it.next(),
            SourceSpans::Fragments(it) => it.next().map(|f| (f.offset, f.length as u64)),
        }
    }
}

impl ExtractedString {
    /// The source byte spans this string was recovered from, as `(offset,
    /// len)` pairs: the scattered `fragments` for a `StackString`, otherwise
    /// its single contiguous extent. `len` is `data_len` when the extractor
    /// recorded it, else the byte-identical `value` length.
    ///
    /// This is the one correct way to locate a string in the source, for any
    /// encoding — consumers must use it rather than deriving a span from
    /// `value.len()`, which is the decoded length and undercounts UTF-16LE /
    /// base64 / other re-encoded strings.
    #[must_use]
    pub fn source_spans(&self) -> SourceSpans<'_> {
        match self.fragments.as_deref() {
            Some(frags) => SourceSpans::Fragments(frags.iter()),
            None => SourceSpans::Single(std::iter::once((
                self.data_offset,
                u64::from(self.contiguous_source_len()),
            ))),
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
pub enum Arch {
    X86,
    X86_64,
    Arm,
    Aarch64,
    Mips,
    Mips64,
    PowerPc,
    PowerPc64,
    RiscV,
    RiscV64,
    Sparc,
    Wasm,
    Other,
}

impl Arch {
    /// `true` for x86-family architectures (x86 and x86-64).  Used by
    /// rules that decode bytes assuming x86 instruction encoding.
    #[must_use]
    pub fn is_x86_family(self) -> bool {
        matches!(self, Self::X86 | Self::X86_64)
    }

    /// Parse the architecture name strings stng uses elsewhere
    /// (Mach-O fat slice labels, ELF e_machine names) into a typed
    /// `Arch`.  Returns `None` for unrecognised inputs so callers can
    /// fall back to the no-arch-info default.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "x86_64" | "x64" | "amd64" => Some(Self::X86_64),
            "x86" | "i386" | "i686" => Some(Self::X86),
            "arm64" | "aarch64" => Some(Self::Aarch64),
            "arm" | "armv7" | "armv6" => Some(Self::Arm),
            "mips" => Some(Self::Mips),
            "mips64" => Some(Self::Mips64),
            "ppc" | "powerpc" => Some(Self::PowerPc),
            "ppc64" | "powerpc64" => Some(Self::PowerPc64),
            "riscv" | "riscv32" => Some(Self::RiscV),
            "riscv64" => Some(Self::RiscV64),
            "sparc" => Some(Self::Sparc),
            "wasm" | "wasm32" | "wasm64" => Some(Self::Wasm),
            _ => None,
        }
    }

    /// Map an ELF `e_machine` value to a typed `Arch`. Returns `None`
    /// for machines stng has no rule for. Constants per the ELF
    /// specification.
    #[must_use]
    pub fn from_elf_machine(em: u16) -> Option<Self> {
        match em {
            2 | 18 | 43 => Some(Self::Sparc), // EM_SPARC, EM_SPARC32PLUS, EM_SPARCV9
            3 => Some(Self::X86),             // EM_386
            8 => Some(Self::Mips),            // EM_MIPS
            20 => Some(Self::PowerPc),        // EM_PPC
            21 => Some(Self::PowerPc64),      // EM_PPC64
            40 => Some(Self::Arm),            // EM_ARM
            62 => Some(Self::X86_64),         // EM_X86_64
            183 => Some(Self::Aarch64),       // EM_AARCH64
            243 => Some(Self::RiscV64),       // EM_RISCV — 32/64 distinguished by EI_CLASS
            _ => None,
        }
    }

    /// Map a PE `IMAGE_FILE_MACHINE_*` value to a typed `Arch`.
    /// Constants per the PE/COFF specification.
    #[must_use]
    pub fn from_pe_machine(machine: u16) -> Option<Self> {
        match machine {
            0x014c => Some(Self::X86),          // IMAGE_FILE_MACHINE_I386
            0x8664 => Some(Self::X86_64),       // IMAGE_FILE_MACHINE_AMD64
            0x01c0 | 0x01c4 => Some(Self::Arm), // ARM, ARMNT
            0xaa64 => Some(Self::Aarch64),      // ARM64
            0x5032 => Some(Self::RiscV),        // IMAGE_FILE_MACHINE_RISCV32
            0x5064 => Some(Self::RiscV64),      // IMAGE_FILE_MACHINE_RISCV64
            _ => None,
        }
    }

    /// Map a Mach-O `cputype` value to a typed `Arch`.
    /// `CPU_ARCH_ABI64 = 0x01000000` flag distinguishes 64-bit variants.
    #[must_use]
    pub fn from_macho_cputype(cputype: u32) -> Option<Self> {
        const CPU_ARCH_ABI64: u32 = 0x0100_0000;
        let base = cputype & !CPU_ARCH_ABI64;
        let is_64 = (cputype & CPU_ARCH_ABI64) != 0;
        match (base, is_64) {
            (7, false) => Some(Self::X86),
            (7, true) => Some(Self::X86_64),
            (12, false) => Some(Self::Arm),
            (12, true) => Some(Self::Aarch64),
            (18, false) => Some(Self::PowerPc),
            (18, true) => Some(Self::PowerPc64),
            _ => None,
        }
    }
}

/// Context passed to the validation rules so architecture- and
/// section-aware filters can scope themselves correctly.
///
/// All fields are optional with `None`-as-"unknown" semantics — every
/// existing caller of `is_garbage` / `is_garbage_with_kind` keeps its
/// behavior because the empty context is treated as "no info, apply
/// the heuristics globally".  Callers that DO know the arch or
/// section can construct a richer context to suppress filters that
/// don't apply to their input (e.g. an ARM binary skips the x86
/// save-sequence filter; a `.rodata` string skips it too).
///
/// Lifetime `'a` borrows the section name; pass `None` if you don't
/// have one.
#[derive(Debug, Clone, Default)]
pub struct StringContext {
    /// Semantic kind from the extractor (URL, Path, Section, …).
    /// Same role as the `kind` parameter on `is_garbage_with_kind`.
    pub kind: Option<StringKind>,
    /// Whether the string lives in an executable (code) section, when
    /// known. `Some(false)` lets code-only rules (the x86 save-sequence
    /// detector) opt out; `None` means "unknown — apply the rule".
    pub in_code_section: Option<bool>,
    /// CPU architecture, when known.  `None` means "no info — assume
    /// any rule may apply"; `Some(non-x86)` switches off x86-only
    /// rules without the caller having to know which they are.
    pub arch: Option<Arch>,
}

impl StringContext {
    /// Empty context — no kind, no section, no arch.  Equivalent to
    /// the legacy `is_garbage(s)` call.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Convenience: build a context carrying only a kind hint.
    /// Equivalent to the legacy `is_garbage_with_kind(s, kind)` call.
    #[must_use]
    pub fn with_kind(kind: Option<StringKind>) -> Self {
        Self {
            kind,
            ..Self::default()
        }
    }
}

/// Method used to extract the string.
///
/// Indicates the extraction technique, which affects confidence and context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum StringMethod {
    /// Found via pointer+length structure analysis
    Structure,
    /// Found via instruction pattern analysis (inline literals)
    InstructionPattern,
    /// Found via traditional null-terminated/ASCII scan (fallback)
    RawScan,
    /// Found via heuristic pattern matching (Rust packed strings)
    Heuristic,
    /// Found via radare2 string analysis (iz command)
    R2String,
    /// Found via radare2 symbol analysis (is command)
    R2Symbol,
    /// Found via UTF-16LE wide string scan (Windows)
    WideString,
    /// Found via space-padded ASCII decoding (.NET metadata format)
    SpacedAscii,
    /// Found via XOR decoding (single-byte key)
    XorDecode,
    /// Found via base64 decoding
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
    /// Found via script deobfuscation (decoded payload from obfuscated Python/JS/PHP/PowerShell)
    ScriptDecode,
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
            | Self::ScriptDecode => 3,

            // High: rich metadata sources
            Self::R2String
            | Self::R2Symbol
            | Self::WideString
            | Self::SpacedAscii
            | Self::CodeSignature
            | Self::PclntabSymbol => 2,

            Self::Heuristic => 1,
            Self::RawScan | Self::Base64ObfuscatedDecode => 0,
        }
    }

    /// Priority for display ordering: higher-value findings appear first.
    /// Differs from dedup_priority: structure/stack strings beat decoded payloads
    /// since they carry richer metadata.
    #[must_use]
    #[allow(clippy::match_same_arms)]
    pub fn display_priority(self) -> u8 {
        match self {
            // Highest: language-aware extraction and obfuscated decoding
            Self::Structure
            | Self::StackString
            | Self::XorStackPair
            | Self::InstructionPattern
            | Self::Base64ObfuscatedDecode => 3,

            // High: decoded content and rich sources
            Self::R2String
            | Self::R2Symbol
            | Self::WideString
            | Self::XorDecode
            | Self::Base64Decode
            | Self::Base32Decode
            | Self::Base85Decode
            | Self::Rot13Base64Decode
            | Self::HexDecode
            | Self::UrlDecode
            | Self::UnicodeEscapeDecode
            | Self::CodeSignature
            | Self::Utf16LeDecode
            | Self::Utf16BeDecode
            | Self::ScriptDecode
            | Self::PclntabSymbol => 2,

            Self::Heuristic => 1,
            Self::RawScan | Self::SpacedAscii => 0,
        }
    }
}

/// Semantic kind of the extracted string.
///
/// Classifies strings by their purpose and security relevance.
/// None means the string has no specific classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    IP,
    /// IP:port or host:port combination
    IPPort,
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
    CTFFlag,
    /// SQL injection payload
    SQLInjection,
    /// XSS (Cross-Site Scripting) payload
    XSSPayload,
    /// Command injection pattern
    CommandInjection,
    /// JWT (JSON Web Token)
    JWT,
    /// API key or secret (AWS, GitHub, Stripe, etc.)
    APIKey,
    /// Windows mutex or synchronization object name
    Mutex,
    /// GUID (Globally Unique Identifier)
    GUID,
    /// Cryptographic hash (MD5, SHA1, SHA256, SHA512)
    Hash,
    /// Ransomware-related string (ransom note, file extension, etc.)
    RansomNote,
    /// LDAP/Active Directory distinguished name
    LDAPPath,
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
pub enum Severity {
    /// Critical IOCs: IPs, URLs, shell commands, suspicious paths
    High = 0,
    /// Important context: paths, env vars, imports
    Medium = 1,
    /// Supporting info: function names, exports
    Low = 2,
    /// Default: constants, identifiers
    Info = 3,
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
    /// the original classifier check because the filter uses classifier
    /// recognition to decide "meaningful".
    #[must_use]
    pub fn is_classifier_output(self) -> bool {
        matches!(
            self,
            Self::Url
                | Self::Path
                | Self::FilePath
                | Self::Email
                | Self::IP
                | Self::IPPort
                | Self::Hash
                | Self::GUID
                | Self::JWT
                | Self::APIKey
                | Self::Registry
                | Self::CryptoWallet
                | Self::MiningPool
                | Self::TorAddress
                | Self::ShellCmd
                | Self::SuspiciousPath
                | Self::CTFFlag
                | Self::Mutex
                | Self::LDAPPath
                | Self::HexEncoded
                | Self::UnicodeEscaped
                | Self::UrlEncoded
                | Self::AppleScript
                | Self::PythonCode
                | Self::JavaScriptCode
                | Self::PhpCode
                | Self::SQLInjection
                | Self::XSSPayload
                | Self::CommandInjection
                | Self::RansomNote
                | Self::EnvVar
        )
    }

    /// Get the severity level for this kind
    #[must_use]
    pub fn severity(self) -> Severity {
        match self {
            Self::IP
            | Self::IPPort
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
            | Self::CTFFlag
            | Self::SQLInjection
            | Self::XSSPayload
            | Self::CommandInjection
            | Self::JWT
            | Self::APIKey
            | Self::Mutex
            | Self::GUID
            | Self::Hash
            | Self::RansomNote
            | Self::LDAPPath => Severity::High,

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
            Self::IP => "ip",
            Self::IPPort => "ip:port",
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
            Self::CTFFlag => "ctf_flag",
            Self::SQLInjection => "sqli",
            Self::XSSPayload => "xss",
            Self::CommandInjection => "cmdi",
            Self::JWT => "jwt",
            Self::APIKey => "api_key",
            Self::Mutex => "mutex",
            Self::GUID => "guid",
            Self::RansomNote => "ransom",
            Self::LDAPPath => "ldap",
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
pub struct BinaryInfo {
    pub is_64bit: bool,
    pub is_little_endian: bool,
    pub ptr_size: usize,
}

impl BinaryInfo {
    /// Create `BinaryInfo` from ELF header information
    #[must_use]
    pub fn from_elf(is_64bit: bool, is_little_endian: bool) -> Self {
        Self {
            is_64bit,
            is_little_endian,
            ptr_size: if is_64bit { 8 } else { 4 },
        }
    }

    /// Create `BinaryInfo` from Mach-O (always little-endian on modern systems)
    #[must_use]
    pub fn from_macho(is_64bit: bool) -> Self {
        Self {
            is_64bit,
            is_little_endian: true, // All modern Mach-O is LE
            ptr_size: if is_64bit { 8 } else { 4 },
        }
    }

    /// Create `BinaryInfo` from PE (always little-endian)
    #[must_use]
    pub fn from_pe(is_64bit: bool) -> Self {
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
pub struct OverlayInfo {
    /// Offset where the overlay data begins
    pub start_offset: u64,
    /// Size of the overlay data in bytes
    pub size: u64,
}

#[cfg(test)]
impl BinaryInfo {
    #[must_use]
    pub fn new_64bit_le() -> Self {
        Self {
            is_64bit: true,
            is_little_endian: true,
            ptr_size: 8,
        }
    }
    #[must_use]
    pub fn new_32bit_le() -> Self {
        Self {
            is_64bit: false,
            is_little_endian: true,
            ptr_size: 4,
        }
    }
    #[must_use]
    pub fn new_64bit_be() -> Self {
        Self {
            is_64bit: true,
            is_little_endian: false,
            ptr_size: 8,
        }
    }
    #[must_use]
    pub fn new_32bit_be() -> Self {
        Self {
            is_64bit: false,
            is_little_endian: false,
            ptr_size: 4,
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn source_spans_use_recorded_extent_then_fall_back_then_fragments() {
        // Recorded extent (e.g. a UTF-16LE string: source is 2× the value).
        let wide = ExtractedString {
            value: "Hi".into(),
            data_offset: 0x40,
            data_len: 4,
            method: StringMethod::WideString,
            ..Default::default()
        };
        assert_eq!(wide.source_spans().collect::<Vec<_>>(), vec![(0x40, 4)]);

        // No recorded extent → byte-identical fallback to the value length.
        let ascii = ExtractedString {
            value: "abcd".into(),
            data_offset: 0x10,
            method: StringMethod::RawScan,
            ..Default::default()
        };
        assert_eq!(ascii.source_spans().collect::<Vec<_>>(), vec![(0x10, 4)]);

        // Scattered stack string → the fragments, not the (bogus) single extent.
        let stack = ExtractedString {
            value: "STACK".into(),
            data_offset: 9999,
            data_len: 0,
            method: StringMethod::StackString,
            fragments: Some(Box::new(vec![
                StringFragment {
                    offset: 0x100,
                    length: 4,
                },
                StringFragment {
                    offset: 0x200,
                    length: 1,
                },
            ])),
            ..Default::default()
        };
        assert_eq!(
            stack.source_spans().collect::<Vec<_>>(),
            vec![(0x100, 4), (0x200, 1)]
        );
    }

    #[test]
    fn test_binary_info_64bit_le() {
        let info = BinaryInfo::new_64bit_le();
        assert!(info.is_64bit);
        assert!(info.is_little_endian);
        assert_eq!(info.ptr_size, 8);
    }

    #[test]
    fn test_binary_info_32bit_le() {
        let info = BinaryInfo::new_32bit_le();
        assert!(!info.is_64bit);
        assert!(info.is_little_endian);
        assert_eq!(info.ptr_size, 4);
    }

    #[test]
    fn test_binary_info_64bit_be() {
        let info = BinaryInfo::new_64bit_be();
        assert!(info.is_64bit);
        assert!(!info.is_little_endian);
        assert_eq!(info.ptr_size, 8);
    }

    #[test]
    fn test_binary_info_32bit_be() {
        let info = BinaryInfo::new_32bit_be();
        assert!(!info.is_64bit);
        assert!(!info.is_little_endian);
        assert_eq!(info.ptr_size, 4);
    }

    #[test]
    fn test_binary_info_from_elf() {
        let info64 = BinaryInfo::from_elf(true, true);
        assert!(info64.is_64bit);
        assert!(info64.is_little_endian);
        assert_eq!(info64.ptr_size, 8);

        let info32 = BinaryInfo::from_elf(false, false);
        assert!(!info32.is_64bit);
        assert!(!info32.is_little_endian);
        assert_eq!(info32.ptr_size, 4);
    }

    #[test]
    fn test_binary_info_from_macho() {
        let info64 = BinaryInfo::from_macho(true);
        assert!(info64.is_64bit);
        assert!(info64.is_little_endian); // Mach-O always LE
        assert_eq!(info64.ptr_size, 8);

        let info32 = BinaryInfo::from_macho(false);
        assert!(!info32.is_64bit);
        assert!(info32.is_little_endian);
        assert_eq!(info32.ptr_size, 4);
    }

    #[test]
    fn test_binary_info_from_pe() {
        let info64 = BinaryInfo::from_pe(true);
        assert!(info64.is_64bit);
        assert!(info64.is_little_endian); // PE always LE
        assert_eq!(info64.ptr_size, 8);

        let info32 = BinaryInfo::from_pe(false);
        assert!(!info32.is_64bit);
        assert!(info32.is_little_endian);
        assert_eq!(info32.ptr_size, 4);
    }

    #[test]
    fn test_string_kind_equality() {
        let none: Option<StringKind> = None;
        assert_eq!(none, None);
        assert_ne!(Some(StringKind::Import), None);
        assert_ne!(Some(StringKind::Import), Some(StringKind::Export));
    }

    #[test]
    fn test_string_method_equality() {
        assert_eq!(StringMethod::Structure, StringMethod::Structure);
        assert_ne!(StringMethod::Structure, StringMethod::RawScan);
    }

    #[test]
    fn test_extracted_string_clone() {
        let s = ExtractedString {
            value: "test".to_string(),
            data_offset: 100,
            method: StringMethod::Structure,
            kind: None,
            ..Default::default()
        };

        let cloned = s.clone();
        assert_eq!(s.value, cloned.value);
        assert_eq!(s.data_offset, cloned.data_offset);
        assert_eq!(s.method, cloned.method);
    }

    #[test]
    fn test_string_struct_clone() {
        let s = StringStruct {
            struct_offset: 100,
            ptr: 200,
            len: 10,
        };

        let cloned = s.clone();
        assert_eq!(s.struct_offset, cloned.struct_offset);
        assert_eq!(s.ptr, cloned.ptr);
        assert_eq!(s.len, cloned.len);
    }
}
