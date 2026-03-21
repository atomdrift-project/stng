//! Go pclntab (Program Counter Line Table) parser.
//!
//! Parses the `.gopclntab` section to find function names and addresses.
//! Used to locate garble's `*.Decrypt` functions for emulation.
//!
//! # Pclntab Format History
//!
//! The format has evolved across Go versions:
//! - Go 1.2-1.15: Legacy 1.2 format
//! - Go 1.16-1.17: Intermediate format
//! - Go 1.18+: Current format with modified header
//!
//! This implementation supports Go 1.16+ formats.

use std::collections::HashMap;

/// Magic bytes for different pclntab versions.
const MAGIC_GO12: u32 = 0xFFFFFFFB; // Go 1.2 - 1.15
const MAGIC_GO116: u32 = 0xFFFFFFFA; // Go 1.16, 1.17
const MAGIC_GO118: u32 = 0xFFFFFFF0; // Go 1.18, 1.19
const MAGIC_GO120: u32 = 0xFFFFFFF1; // Go 1.20+

/// Parsed function entry from pclntab.
#[derive(Debug, Clone)]
pub struct FuncEntry {
    /// Function name (e.g., "main.(*Foo).Decrypt")
    pub name: String,
    /// Entry point PC (virtual address)
    pub entry_pc: u64,
}

/// Parsed gopclntab information.
#[derive(Debug)]
pub struct Pclntab {
    /// Go version detected from magic
    pub go_version: GoVersion,
    /// Pointer size (4 or 8)
    pub ptr_size: u8,
    /// Text section start address
    pub text_start: u64,
    /// All functions found via functab entries
    pub functions: Vec<FuncEntry>,
    /// Map from function name to entry
    pub by_name: HashMap<String, FuncEntry>,
    /// All function names from the funcname table (includes inlined/wrapper functions
    /// not referenced by the functab). Empty for Go < 1.18.
    pub all_func_names: Vec<String>,
}

/// Detected Go version from pclntab magic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoVersion {
    Go12,  // 1.2 - 1.15
    Go116, // 1.16, 1.17
    Go118, // 1.18, 1.19
    Go120, // 1.20+
    Unknown, // Unrecognized magic (possibly garble-modified)
}

impl Pclntab {
    /// Parse a gopclntab section.
    ///
    /// # Parameters
    /// - `data`: Contents of .gopclntab section
    /// - `section_va`: Virtual address where section is loaded
    pub fn parse(data: &[u8], section_va: u64) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }

        // Read magic (little-endian)
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

        let go_version = match magic {
            MAGIC_GO12 => GoVersion::Go12,
            MAGIC_GO116 => GoVersion::Go116,
            MAGIC_GO118 => GoVersion::Go118,
            MAGIC_GO120 => GoVersion::Go120,
            _ => GoVersion::Unknown,
        };

        // Bytes 4-5: zeros
        // Byte 6: quantum (instruction alignment, usually 1 for x86)
        // Byte 7: pointer size (4 or 8)
        let ptr_size = data[7];
        if ptr_size != 4 && ptr_size != 8 {
            return None;
        }

        // Parse based on version
        match go_version {
            GoVersion::Go12 | GoVersion::Go116 => Self::parse_go116(data, section_va, ptr_size),
            GoVersion::Go118 | GoVersion::Go120 => {
                Self::parse_go118(data, section_va, ptr_size, go_version)
            }
            GoVersion::Unknown => {
                // For unknown formats, try scanning for function names directly
                Self::parse_by_scanning(data, section_va, ptr_size)
            }
        }
    }

    /// Fallback parser that scans for function names directly.
    ///
    /// Used when the pclntab magic is unrecognized (e.g., garble-modified binaries).
    fn parse_by_scanning(data: &[u8], _section_va: u64, ptr_size: u8) -> Option<Self> {
        let mut functions = Vec::new();
        let mut by_name = HashMap::new();

        // Scan for function name patterns like "package.(*Type).Method"
        // Look for null-terminated strings that look like Go function names
        let mut i = 0;
        while i < data.len() {
            // Skip non-printable bytes
            if !data[i].is_ascii_graphic() && data[i] != b'.' && data[i] != b'*' && data[i] != b'(' && data[i] != b')' {
                i += 1;
                continue;
            }

            // Try to read a function name
            let start = i;
            while i < data.len() && (data[i].is_ascii_alphanumeric() || matches!(data[i], b'.' | b'*' | b'(' | b')' | b'_' | b'/' | b'[' | b']')) {
                i += 1;
            }

            // Check if we hit a null terminator
            if i < data.len() && data[i] == 0 && i - start >= 8 {
                let name_bytes = &data[start..i];
                if let Ok(name) = std::str::from_utf8(name_bytes) {
                    // Check if it looks like a Go function name (has at least one dot)
                    if name.contains('.') && !name.starts_with('.') && !name.ends_with('.') {
                        let entry = FuncEntry {
                            name: name.to_string(),
                            entry_pc: 0, // Unknown - would need to correlate with code
                        };
                        if !by_name.contains_key(name) {
                            by_name.insert(name.to_string(), entry.clone());
                            functions.push(entry);
                        }
                    }
                }
            }

            i += 1;
        }

        if functions.is_empty() {
            return None;
        }

        Some(Self {
            go_version: GoVersion::Unknown,
            ptr_size,
            text_start: 0,
            all_func_names: Vec::new(),
            functions,
            by_name,
        })
    }

    /// Parse Go 1.16/1.17 format.
    fn parse_go116(data: &[u8], _section_va: u64, ptr_size: u8) -> Option<Self> {
        // Header layout for Go 1.16:
        // [0:4]   magic
        // [4:6]   zeros
        // [6]     quantum
        // [7]     ptrsize
        // [8:8+ptrsize] nfunc
        // [8+ptrsize:8+2*ptrsize] nfiles
        // [8+2*ptrsize:8+3*ptrsize] funcnameOffset
        // [8+3*ptrsize:8+4*ptrsize] cuOffset
        // [8+4*ptrsize:8+5*ptrsize] filetabOffset
        // [8+5*ptrsize:8+6*ptrsize] pctabOffset
        // [8+6*ptrsize:8+7*ptrsize] pclineOffset
        // ... (function table follows)

        let ps = ptr_size as usize;
        let header_size = 8 + 7 * ps;

        if data.len() < header_size {
            return None;
        }

        let nfunc = read_uint(data, 8, ptr_size)?;
        let funcname_off = read_uint(data, 8 + 2 * ps, ptr_size)? as usize;

        // Function table starts after header
        let functab_off = header_size;

        let mut functions = Vec::new();
        let mut by_name = HashMap::new();

        // Each functab entry is: (pc, funcoff) where both are ptr_size
        let entry_size = 2 * ps;

        for i in 0..nfunc as usize {
            let entry_off = functab_off + i * entry_size;
            if entry_off + entry_size > data.len() {
                break;
            }

            let entry_pc = read_uint(data, entry_off, ptr_size)?;
            let func_off = read_uint(data, entry_off + ps, ptr_size)? as usize;

            // Read function data
            if func_off + ps > data.len() {
                continue;
            }

            // Function data layout:
            // [0:ptrsize] entry (redundant with table)
            // [ptrsize:ptrsize+4] nameoff

            let nameoff = u32::from_le_bytes([
                data.get(func_off + ps)?.to_owned(),
                data.get(func_off + ps + 1)?.to_owned(),
                data.get(func_off + ps + 2)?.to_owned(),
                data.get(func_off + ps + 3)?.to_owned(),
            ]) as usize;

            let name = read_cstring(data, funcname_off + nameoff)?;

            let entry = FuncEntry {
                name: name.clone(),
                entry_pc,
            };
            by_name.insert(name, entry.clone());
            functions.push(entry);
        }

        Some(Self {
            go_version: GoVersion::Go116,
            ptr_size,
            text_start: 0, // Not available in this format
            all_func_names: Vec::new(),
            functions,
            by_name,
        })
    }

    /// Parse Go 1.18+ format.
    fn parse_go118(data: &[u8], _section_va: u64, ptr_size: u8, version: GoVersion) -> Option<Self> {
        // Header layout for Go 1.18+ (pcHeader struct):
        // [0:4]   magic (uint32)
        // [4:5]   pad1 (uint8)
        // [5:6]   pad2 (uint8)
        // [6]     quantum/minLC (uint8)
        // [7]     ptrSize (uint8)
        // [8:8+P] nfunc (int, P bytes where P=ptrSize)
        // [8+P:8+2P] nfiles (uint)
        // [8+2P:8+3P] textStart (uintptr)
        // [8+3P:8+4P] funcnameOffset (uintptr)
        // [8+4P:8+5P] cuOffset (uintptr)
        // [8+5P:8+6P] filetabOffset (uintptr)
        // [8+6P:8+7P] pctabOffset (uintptr)
        // [8+7P:8+8P] pclnOffset (uintptr)
        //
        // The functab immediately follows the header (no offset field for it).
        // Header size = 8 + 8*ptrSize (72 for 64-bit, 40 for 32-bit).

        let header_size = 8 + 8 * ptr_size as usize;
        if data.len() < header_size {
            return None;
        }

        // All header fields after the fixed 8-byte prefix use native pointer size.
        // For simplicity and because Go 1.18+ always stores nfunc/nfiles as
        // ptr-sized values, use read_uint for all of them.
        let nfunc = read_uint(data, 8, ptr_size)?;

        let text_start = read_uint(data, 8 + 2 * ptr_size as usize, ptr_size)?;

        let funcname_off = read_uint(data, 8 + 3 * ptr_size as usize, ptr_size)? as usize;
        let cu_off = read_uint(data, 8 + 4 * ptr_size as usize, ptr_size)? as usize;

        // In Go 1.18-1.19, the functab is right after the header.
        // In Go 1.20+, the functab is at pclnOffset (the last header field).
        // The pclnOffset points to where both the functab entries AND the
        // _func data are stored. func_off values in functab entries are
        // relative to pclnOffset.
        let pcln_off = read_uint(data, 8 + 7 * ptr_size as usize, ptr_size)? as usize;

        let functab_off = match version {
            GoVersion::Go118 => header_size, // functab right after header
            _ => pcln_off,                   // Go 1.20+: functab at pclnOffset
        };

        let mut functions = Vec::new();
        let mut by_name = HashMap::new();

        // In Go 1.18+, functab entries are (uint32 pc_offset, uint32 funcoff)
        // PC is relative to textStart
        let entry_size = 8;

        for i in 0..nfunc as usize {
            let entry_off = functab_off + i * entry_size;
            if entry_off + entry_size > data.len() {
                break;
            }

            let pc_off = u32::from_le_bytes([
                data[entry_off],
                data[entry_off + 1],
                data[entry_off + 2],
                data[entry_off + 3],
            ]);

            let func_off_raw = u32::from_le_bytes([
                data[entry_off + 4],
                data[entry_off + 5],
                data[entry_off + 6],
                data[entry_off + 7],
            ]) as usize;

            let entry_pc = text_start.wrapping_add(pc_off as u64);

            // In Go 1.20+, func_off is relative to pclnOffset (functab_off).
            // In Go 1.18, func_off is an absolute offset within pclntab.
            let func_off = match version {
                GoVersion::Go118 => func_off_raw,
                _ => functab_off + func_off_raw,
            };

            // Read function data
            // Function data layout in 1.18+:
            // [0:4] entryoff (uint32, relative to textStart)
            // [4:8] nameoff (int32, offset into funcname table)

            if func_off + 8 > data.len() {
                continue;
            }

            let nameoff = u32::from_le_bytes([
                data[func_off + 4],
                data[func_off + 5],
                data[func_off + 6],
                data[func_off + 7],
            ]) as usize;

            let Some(name) = read_cstring(data, funcname_off + nameoff) else {
                continue;
            };

            let entry = FuncEntry {
                name: name.clone(),
                entry_pc,
            };
            by_name.insert(name, entry.clone());
            functions.push(entry);
        }

        // Scan the funcname table for ALL function names (including inlined
        // functions, compiler-generated wrappers, and closures that don't have
        // functab entries). The funcname table runs from funcname_off to cu_off
        // and contains null-terminated strings.
        let all_func_names = scan_funcname_table(data, funcname_off, cu_off);

        Some(Self {
            go_version: version,
            ptr_size,
            text_start,
            all_func_names,
            functions,
            by_name,
        })
    }

    /// Find all functions whose names end with ".Decrypt".
    ///
    /// These are garble's string decryption wrapper functions.
    pub fn find_decrypt_functions(&self) -> Vec<&FuncEntry> {
        self.functions
            .iter()
            .filter(|f| f.name.ends_with(".Decrypt"))
            .collect()
    }

    /// Find a function by exact name.
    pub fn find_function(&self, name: &str) -> Option<&FuncEntry> {
        self.by_name.get(name)
    }

    /// Find functions matching a pattern (e.g., "runtime.slicebytetostring").
    pub fn find_functions_containing(&self, pattern: &str) -> Vec<&FuncEntry> {
        self.functions
            .iter()
            .filter(|f| f.name.contains(pattern))
            .collect()
    }

    /// Extract non-standard-library function names as strings.
    ///
    /// Uses the full funcname table when available (Go 1.18+), which includes
    /// inlined functions, closures, and compiler-generated wrappers that don't
    /// have functab entries. Falls back to functab-derived names for older formats.
    ///
    /// Returns function names that don't belong to the Go standard library,
    /// common runtime packages, or well-known third-party libraries. These
    /// custom function names are valuable for malware analysis as they reveal
    /// the binary's internal module structure and capabilities.
    pub fn extract_custom_func_names(&self, min_length: usize) -> Vec<String> {
        // Prefer the full funcname table scan (covers inlined/wrapper functions)
        let source: Box<dyn Iterator<Item = &str>> = if !self.all_func_names.is_empty() {
            Box::new(self.all_func_names.iter().map(String::as_str))
        } else {
            Box::new(self.functions.iter().map(|f| f.name.as_str()))
        };

        source
            .filter(|name| {
                if name.len() < min_length {
                    return false;
                }
                if is_stdlib_func(name) {
                    return false;
                }
                if looks_garbled(name) {
                    return false;
                }
                true
            })
            .map(String::from)
            .collect()
    }
}

/// Check if a function name belongs to the Go standard library or runtime.
fn is_stdlib_func(name: &str) -> bool {
    // Go runtime and internal packages
    let stdlib_prefixes = [
        "runtime.",
        "runtime/",
        "internal/",
        "type:.",
        "type:..func",
        "go:",
        "go.",
        // Standard library packages
        "bufio.",
        "bytes.",
        "compress/",
        "container/",
        "context.",
        "crypto.",
        "crypto/",
        "database/",
        "debug/",
        "embed.",
        "encoding.",
        "encoding/",
        "errors.",
        "expvar.",
        "flag.",
        "fmt.",
        "go/",
        "hash.",
        "hash/",
        "html.",
        "html/",
        "image.",
        "image/",
        "index/",
        "io.",
        "io/",
        "log.",
        "log/",
        "math.",
        "math/",
        "mime.",
        "mime/",
        "net.",
        "net/",
        "os.",
        "os/",
        "path.",
        "path/",
        "plugin.",
        "reflect.",
        "regexp.",
        "regexp/",
        "slices.",
        "sort.",
        "strconv.",
        "strings.",
        "sync.",
        "sync/",
        "syscall.",
        "syscall/",
        "testing.",
        "testing/",
        "text/",
        "time.",
        "time/",
        "unicode.",
        "unicode/",
        "unsafe.",
        "vendor/",
        "maps.",
        "iter.",
        "cmp.",
        "unique.",
        // Linker-generated
        "type:.eq.",
        "type:.hash.",
        // Well-known third-party (too common to be interesting)
        "golang.org/x/",
    ];
    for prefix in &stdlib_prefixes {
        if name.starts_with(prefix) {
            return true;
        }
    }
    false
}

/// Check if a function name looks like it was garble-obfuscated.
///
/// Garble replaces meaningful names with random-looking identifiers.
fn looks_garbled(name: &str) -> bool {
    // Get the last component after the last '.'
    let last_part = name.rsplit('.').next().unwrap_or(name);
    // Skip method receivers like "(*Foo).Bar"
    let check = if let Some(stripped) = last_part.strip_prefix("(*") {
        stripped.split(')').next().unwrap_or(last_part)
    } else {
        last_part
    };

    if check.is_empty() || check.len() < 4 {
        return false;
    }

    // Garble names are typically single-case alphanumeric with no meaningful patterns.
    // Real function names have mixed case, underscores, or recognizable words.
    let all_lower = check.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    let all_upper = check.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit());
    let has_vowel = check.chars().any(|c| matches!(c, 'a' | 'e' | 'i' | 'o' | 'u' | 'A' | 'E' | 'I' | 'O' | 'U'));

    // Single-case with no vowels is very likely garbled
    (all_lower || all_upper) && !has_vowel
}

/// Scan the funcname table for all null-terminated function names.
///
/// The funcname table in Go 1.18+ pclntab contains null-terminated strings
/// for ALL functions, including those not in the functab (inlined functions,
/// compiler-generated wrappers, closures). This gives complete coverage.
fn scan_funcname_table(data: &[u8], start: usize, end: usize) -> Vec<String> {
    let end = end.min(data.len());
    if start >= end {
        return Vec::new();
    }

    let table = &data[start..end];
    let mut names = Vec::new();
    let mut i = 0;

    while i < table.len() {
        // Find end of null-terminated string
        let str_end = match table[i..].iter().position(|&b| b == 0) {
            Some(pos) => i + pos,
            None => break,
        };

        if str_end > i {
            if let Ok(name) = std::str::from_utf8(&table[i..str_end]) {
                // Only keep names that look like Go function names
                // (contain a dot separating package from function)
                if name.len() >= 4 && name.contains('.') {
                    names.push(name.to_string());
                }
            }
        }

        i = str_end + 1;
    }

    names
}

/// Read a variable-size unsigned integer (4 or 8 bytes).
fn read_uint(data: &[u8], offset: usize, ptr_size: u8) -> Option<u64> {
    if ptr_size == 4 {
        if offset + 4 > data.len() {
            return None;
        }
        Some(u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as u64)
    } else {
        if offset + 8 > data.len() {
            return None;
        }
        Some(u64::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]))
    }
}

/// Read a null-terminated C string.
fn read_cstring(data: &[u8], offset: usize) -> Option<String> {
    if offset >= data.len() {
        return None;
    }

    let slice = &data[offset..];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());

    // Limit to reasonable function name length
    if end > 512 {
        return None;
    }

    String::from_utf8(slice[..end].to_vec()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_cstring() {
        let data = b"hello\0world\0";
        assert_eq!(read_cstring(data, 0), Some("hello".to_string()));
        assert_eq!(read_cstring(data, 6), Some("world".to_string()));
        assert_eq!(read_cstring(data, 100), None);
    }

    #[test]
    fn test_read_uint_32() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(read_uint(&data, 0, 4), Some(0x04030201));
    }

    #[test]
    fn test_read_uint_64() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(read_uint(&data, 0, 8), Some(0x0807060504030201));
    }

    #[test]
    fn test_magic_detection() {
        // Go 1.18 magic
        let mut data = vec![0; 80];
        data[0..4].copy_from_slice(&MAGIC_GO118.to_le_bytes());
        data[7] = 8; // ptr_size

        let pclntab = Pclntab::parse(&data, 0);
        assert!(pclntab.is_some());
        assert_eq!(pclntab.as_ref().map(|p| p.go_version), Some(GoVersion::Go118));
    }
}
