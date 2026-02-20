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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StringFragment {
    /// File offset where this fragment's data is located
    pub offset: u64,
    /// Length of this fragment in bytes
    pub length: usize,
    /// The specific instruction flavor (e.g., "movabs", "`stack_array`")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flavor: Option<String>,
}

/// An extracted string with metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExtractedString {
    /// The string value
    pub value: String,
    /// Offset in the binary where the string data is located
    pub data_offset: u64,
    /// Section name where the string was found
    pub section: Option<String>,
    /// How the string was found
    pub method: StringMethod,
    /// Semantic kind of the string
    pub kind: StringKind,
    /// Source library for imports (e.g., "libSystem.B.dylib")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub library: Option<String>,
    /// For multi-part strings (`StackString`), tracks all source fragments
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub fragments: Option<Vec<StringFragment>>,
    /// For Section strings, stores size and type metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub section_size: Option<u64>,
    /// For Section strings, whether the section is executable
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub section_executable: Option<bool>,
    /// For Section strings, whether the section is writable
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub section_writable: Option<bool>,
    /// Architecture (for Mach-O fat binaries: `x86_64`, `arm64`, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub architecture: Option<String>,
    /// Function metadata (for `FuncName` kind)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub function_meta: Option<FunctionMetadata>,
}

/// Metadata about a function (from binary analysis)
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FunctionMetadata {
    /// Function size in bytes
    pub size: u64,
    /// Number of basic blocks
    pub basic_blocks: u64,
    /// Number of branches/edges
    pub branches: u64,
    /// Number of instructions
    pub instructions: u64,
    /// Function signature (with args)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Whether function returns
    #[serde(skip_serializing_if = "Option::is_none")]
    pub noreturn: Option<bool>,
}

impl Default for ExtractedString {
    fn default() -> Self {
        Self {
            value: String::new(),
            data_offset: 0,
            section: None,
            method: StringMethod::RawScan,
            kind: StringKind::Const,
            library: None,
            fragments: None,
            section_size: None,
            section_executable: None,
            section_writable: None,
            architecture: None,
            function_meta: None,
        }
    }
}

impl ExtractedString {
    /// Get formatted section metadata if this is a section string
    pub fn section_metadata_str(&self) -> Option<String> {
        if self.kind != StringKind::Section {
            return None;
        }

        let size = self.section_size?;
        let is_exec = self.section_executable.unwrap_or(false);
        let is_write = self.section_writable.unwrap_or(false);

        // Format size
        #[allow(clippy::cast_precision_loss)]
        let size_str = if size < 1024 {
            format!("{size}b")
        } else if size < 1024 * 1024 {
            format!("{:.1}kb", size as f64 / 1024.0)
        } else {
            format!("{:.1}mb", size as f64 / (1024.0 * 1024.0))
        };

        // Format type
        let type_str = match (is_exec, is_write) {
            (true, true) => "TEXT+DATA",
            (true, false) => "TEXT",
            (false, _) => "DATA",
        };

        Some(format!("({size_str}, {type_str})"))
    }
}

/// Method used to extract the string.
///
/// Indicates the extraction technique, which affects confidence and context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
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
}

/// Semantic kind of the extracted string.
///
/// Classifies strings by their purpose and security relevance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[non_exhaustive]
pub enum StringKind {
    /// Generic string constant
    #[default]
    Const,
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
    /// Get the severity level for this kind
    pub fn severity(&self) -> Severity {
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

            _ => Severity::Info,
        }
    }

    /// Get short display name for the kind
    pub fn short_name(&self) -> &'static str {
        match self {
            Self::Const => "-",
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
            Self::CodeSignatureHash => "hash",
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
    pub fn from_elf(is_64bit: bool, is_little_endian: bool) -> Self {
        Self {
            is_64bit,
            is_little_endian,
            ptr_size: if is_64bit { 8 } else { 4 },
        }
    }

    /// Create `BinaryInfo` from Mach-O (always little-endian on modern systems)
    pub fn from_macho(is_64bit: bool) -> Self {
        Self {
            is_64bit,
            is_little_endian: true, // All modern Mach-O is LE
            ptr_size: if is_64bit { 8 } else { 4 },
        }
    }

    /// Create `BinaryInfo` from PE (always little-endian)
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
    pub fn new_64bit_le() -> Self {
        Self {
            is_64bit: true,
            is_little_endian: true,
            ptr_size: 8,
        }
    }
    pub fn new_32bit_le() -> Self {
        Self {
            is_64bit: false,
            is_little_endian: true,
            ptr_size: 4,
        }
    }
    pub fn new_64bit_be() -> Self {
        Self {
            is_64bit: true,
            is_little_endian: false,
            ptr_size: 8,
        }
    }
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
        assert_eq!(StringKind::Const, StringKind::Const);
        assert_ne!(StringKind::Const, StringKind::Import);
        assert_ne!(StringKind::Import, StringKind::Export);
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
            section: Some("section".to_string()),
            method: StringMethod::Structure,
            kind: StringKind::Const,
            library: Some("lib".to_string()),
            ..Default::default()
        };

        let cloned = s.clone();
        assert_eq!(s.value, cloned.value);
        assert_eq!(s.data_offset, cloned.data_offset);
        assert_eq!(s.section, cloned.section);
        assert_eq!(s.library, cloned.library);
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
