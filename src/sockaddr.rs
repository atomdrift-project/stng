//! Hard-coded IPv4 addresses in `sockaddr_in` structures.
//!
//! Scans binary data for hardcoded IP addresses in socket structures.
//! Only detects IPs in contextual patterns (sockaddr_in) to avoid false positives
//! from random 4-byte sequences.

use crate::types::{ExtractedString, StringKind, StringMethod};
use std::collections::HashSet;

/// Machine type constant for M68000 (Motorola 68000)
/// M68000 instructions contain 0x0002 patterns naturally, causing false positives
const EM_68K: u16 = 4;

/// Checks if a section name indicates a data section (writable or relocatable)
/// Real hardcoded C2 IPs should be in data sections, not code sections
fn is_data_section_elf(section: &str) -> bool {
    matches!(
        section,
        ".data"
            | ".data.rel.ro"
            | ".rodata"
            | ".rodata.cst"
            | ".bss"
            | ".fini_array"
            | ".init_array"
    )
}

/// Check if this is a Go binary by examining section names or embedded strings.
/// Go binaries have .gopclntab/.go.buildinfo (ELF) or gopclntab/go.buildinfo (PE).
/// Also checks for "Go build ID:" string which is present even in stripped binaries.
fn is_go_binary_from_sections(
    elf_opt: Option<&crate::goblin::elf::Elf<'_>>,
    pe_opt: Option<&crate::goblin::pe::PE<'_>>,
    data: &[u8],
) -> bool {
    // Check ELF for Go sections
    if let Some(elf) = elf_opt
        && elf.section_headers.iter().any(|sh| {
            if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
                name == ".gopclntab" || name == ".go.buildinfo"
            } else {
                false
            }
        })
    {
        return true;
    }

    // Check PE for Go sections
    if let Some(pe) = pe_opt
        && pe.sections.iter().any(|section| {
            let name = crate::binary::pe_section_name(&section.name).to_lowercase();
            name.contains("gopclntab") || name.contains("go.buildinfo")
        })
    {
        return true;
    }

    // Fallback: check for "Go build ID:" string in first 4KB of binary
    // This catches Go binaries that lack standard section names
    let search_len = data.len().min(4096);
    if data[..search_len].windows(12).any(|w| w == b"Go build ID:") {
        return true;
    }

    false
}

/// Check if this is a .NET binary by examining the CLR header directory.
/// .NET binaries have a COM descriptor (CLR header) and don't use C-style sockaddr_in.
fn is_dotnet_binary(pe_opt: Option<&crate::goblin::pe::PE<'_>>, data: &[u8]) -> bool {
    if let Some(pe) = pe_opt {
        // Check if PE has CLR runtime header (index 14 = COM_DESCRIPTOR / CLR header)
        if let Some(optional_header) = pe.header.optional_header {
            let data_directories = &optional_header.data_directories.data_directories;
            // Index 14 is IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR (CLR header)
            if data_directories.len() > 14
                && let Some((_, clr_dir)) = &data_directories[14]
                && clr_dir.virtual_address != 0
                && clr_dir.size != 0
            {
                return true;
            }
        }

        // Also check for BSJB signature in data (indicates CLI metadata header)
        // This is a backup check for native images (.ni.dll) which may not have CLR header
        if data.len() > 4 {
            // Search in first 1MB for "BSJB" (CLI metadata signature)
            let search_len = data.len().min(1024 * 1024);
            if data[..search_len].windows(4).any(|w| w == b"BSJB") {
                return true;
            }
        }
    }

    false
}

/// Returns true if the bytes surrounding `offset` look like a densely-packed
/// `u16` table (UNWIND_CODE arrays, C++ EH funcinfo / ip2state maps, jump
/// tables) rather than ad-hoc data that happens to contain a sockaddr_in.
///
/// MSVC-compiled PE files embed compiler-emitted exception-handling metadata
/// directly in `.rdata`. Some of it is reachable from `.pdata` UNWIND_INFO,
/// but the language-specific scope tables and FUNCINFO records are only
/// reachable indirectly through handler pointers and live at arbitrary
/// offsets. A robust signal that does not depend on chasing those pointers:
/// such tables are packed sequences of `XX 00` / `XX 01` u16 values
/// (CodeOffset + UnwindOp:UWOP_*, where UnwindOp ∈ 0..=10), so the local
/// density of u16 LE values below 0x0200 is far higher than in heterogeneous
/// data sections that hold real sockaddr_in structures.
fn looks_like_packed_u16_table(data: &[u8], offset: usize) -> bool {
    // ±32 bytes around the 8-byte candidate, even-aligned to the candidate.
    let parity = offset & 1;
    let start = (offset.saturating_sub(32) + parity) & !1 | parity;
    let end = offset.saturating_add(40).min(data.len());

    let mut small_nonzero = 0usize;
    let mut nonzero = 0usize;
    let mut p = start;
    while p + 1 < end {
        let v = u16::from_le_bytes([data[p], data[p + 1]]);
        if v != 0 {
            nonzero += 1;
            if v < 0x0200 {
                small_nonzero += 1;
            }
        }
        p += 2;
    }
    // UNWIND_CODE arrays have many distinct small-but-non-zero u16 entries
    // (variants of CodeOffset + UnwindOp). The ≥ 8 floor avoids tripping on
    // sparse sockaddr_in surrounded by zero padding, where the only small
    // non-zero u16 is the AF_INET marker itself. The 60% ratio of non-zero
    // u16s that are small matches the unicodedata.pyd UWOP region (~69%)
    // while leaving room for real sockaddr_in in mixed data (typically <40%).
    small_nonzero >= 8 && small_nonzero * 100 / nonzero.max(1) >= 60
}

/// Returns true if the bytes surrounding `offset` form a region with strong
/// period-2 byte structure — a packed lookup/metadata table (Delphi/VCL RTTI,
/// resource maps, encoded relocation tables) rather than heterogeneous data
/// that happens to hold a real sockaddr_in.
///
/// Such tables are sequences of repeating 2-byte cells (`64 02 64 02 …`,
/// `f0 02 f0 02 …`, `XX 10 XX 10 …`), so a high fraction of bytes equal the
/// byte two positions earlier. Real sockaddr_in structures live among
/// function pointers, zero padding, and unrelated constants, where non-zero
/// period-2 self-similarity is essentially nil (measured 0% across
/// heterogeneous, zero-padded, and pointer-mix layouts; the packed tables that
/// produced false positives measured 38–56%). Zero bytes are excluded so that
/// a zero-padded struct in `.bss`/`.data` is not mistaken for a periodic table.
fn sits_in_periodic_table(data: &[u8], offset: usize) -> bool {
    let start = offset.saturating_sub(32);
    let end = offset.saturating_add(32).min(data.len());
    if end < start + 3 {
        return false;
    }
    let window = &data[start..end];

    let mut matches = 0usize;
    for i in 0..window.len() - 2 {
        if window[i] != 0 && window[i] == window[i + 2] {
            matches += 1;
        }
    }
    let comparisons = window.len() - 2;

    // 25% leaves a wide margin above the 0% seen in real data sections while
    // sitting well below the 38% floor of the packed tables it targets.
    matches * 100 / comparisons >= 25
}

/// Endianness of the binary being scanned, used to restrict the AF_INET marker
/// check in [`scan_sockaddr_in`]. On a little-endian platform, sin_family is
/// stored as `02 00`; on a big-endian platform, `00 02`. Accepting both produces
/// false positives from byte sequences in code/data (e.g. COM GUIDs in PE
/// .rdata or small-integer lookup tables).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Endianness {
    Little,
    Big,
    /// Format gave no endianness hint (Mach-O, unknown or unparsed input):
    /// accept either marker.
    Unknown,
}

/// Scans binary data for hardcoded IP addresses in socket structures.
///
/// Only detects IPs in contextual patterns:
/// - sockaddr_in structures (with AF_INET marker = 0x0002)
///
/// Skips M68000 binaries entirely due to high false positive rate (0x0002 appears naturally in code).
///
/// For other architectures, restricts results to data sections to avoid code section false positives.
///
/// Does NOT scan for random 4-byte sequences to avoid false positives.
pub(crate) fn scan_binary_ips(
    data: &[u8],
    min_length: usize,
    e_machine: u16,
    elf_opt: Option<&crate::goblin::elf::Elf<'_>>,
    pe_opt: Option<&crate::goblin::pe::PE<'_>>,
) -> Vec<ExtractedString> {
    // Skip M68000 binaries - their instruction stream naturally contains 0x0002 patterns
    if e_machine == EM_68K {
        return Vec::new();
    }

    // Skip Go binaries - they don't use C-style sockaddr_in structures
    // Go has its own network abstractions and stores addresses differently
    // Scanning for sockaddr_in in Go binaries produces false positives from runtime metadata
    if is_go_binary_from_sections(elf_opt, pe_opt, data) {
        return Vec::new();
    }

    // Skip .NET binaries - they don't use C-style sockaddr_in structures
    // .NET has managed networking APIs and doesn't embed raw socket addresses
    // Native images (.ni.dll) contain compiled IL/JIT code that produces many false positives
    if is_dotnet_binary(pe_opt, data) {
        return Vec::new();
    }

    let endianness = match (elf_opt, pe_opt) {
        // ELF carries the runtime endianness explicitly.
        (Some(elf), _) => {
            if elf.little_endian {
                Endianness::Little
            } else {
                Endianness::Big
            }
        }
        // PE/COFF is always loaded little-endian on every shipping Windows
        // target (x86, x86_64, ARM, ARM64).
        (_, Some(_)) => Endianness::Little,
        _ => Endianness::Unknown,
    };

    let mut results = Vec::new();

    // Only scan for sockaddr_in structures - these have the AF_INET marker
    // which provides context that this is actually a socket structure
    results.extend(scan_sockaddr_in(data, min_length, endianness));

    // For ELF binaries with section info, filter to only accept data sections
    // Real hardcoded C2 IPs are in .data, .rodata, etc., not in .text (code)
    if let Some(elf) = elf_opt {
        results.retain(|s| {
            // Find which section this offset belongs to
            for sh in &elf.section_headers {
                if s.data_offset >= sh.sh_offset
                    && s.data_offset < sh.sh_offset.saturating_add(sh.sh_size)
                    && let Some(name) = elf.shdr_strtab.get_at(sh.sh_name)
                {
                    // Accept if in a data section, reject if in code section
                    return is_data_section_elf(name);
                }
            }
            // If section can't be determined, reject to be safe
            false
        });
    }

    // For PE binaries with section info, filter to only accept data sections
    // Real hardcoded C2 IPs are in .data, .rdata, etc., not in .text (code)
    if let Some(pe) = pe_opt {
        results.retain(|s| {
            // Drop candidates sitting inside compiler-emitted u16 tables
            // (UNWIND_INFO / C++ EH metadata / jump tables) that mimic
            // sockaddr_in byte sequences.
            if let Ok(off) = usize::try_from(s.data_offset)
                && (looks_like_packed_u16_table(data, off) || sits_in_periodic_table(data, off))
            {
                return false;
            }
            // Find which section this offset belongs to
            for section in &pe.sections {
                let section_start = u64::from(section.pointer_to_raw_data);
                let section_end = section_start + u64::from(section.size_of_raw_data);
                if s.data_offset >= section_start && s.data_offset < section_end {
                    let name = crate::binary::pe_section_name(&section.name);
                    return matches!(
                        &*name,
                        ".data" | ".rdata" | ".bss" | ".idata" | ".edata" | ".rsrc"
                    );
                }
            }
            // If section can't be determined, reject to be safe
            false
        });
    }

    // Deduplicate by offset to avoid reporting same location multiple times
    let mut seen = HashSet::new();
    results.retain(|s| seen.insert((s.data_offset, s.value.clone())));

    // Cap results: if more than 4 unique IPs detected, it's likely noise
    // Real malware rarely has more than a handful of hardcoded C2 addresses
    if results.len() > 4 {
        return Vec::new();
    }

    results
}

/// Whether `octets` is a plausible hard-coded server address.
fn is_valid_ip(octets: [u8; 4]) -> bool {
    // Reject if any octet is 0 (including first, last, or middle)
    // Real IPs don't have 0 octets, 0.x.x.x is invalid, x.x.x.0 is network address
    if octets.contains(&0) {
        return false;
    }

    // Reject multicast (224.0.0.0 and above)
    if octets[0] >= 224 {
        return false;
    }

    // Reject IPs with very low first octet (1-9 are often patterns in malformed structs)
    // 10.x.x.x is valid (private), so allow >= 10
    if octets[0] < 10 {
        return false;
    }

    // Reject IPs ending in .255 (broadcast addresses)
    if octets[3] == 255 {
        return false;
    }

    // Reject IPs with last octet >= 250 (often artifacts/broadcast-like patterns)
    if octets[3] >= 250 {
        return false;
    }

    // Reject IPs with any octet == 255 (broadcast patterns)
    if octets.contains(&255) {
        return false;
    }

    // Reject linearly incrementing sequences (e.g., 0x0D 0x0E 0x0F 0x10) — common in
    // data tables and unwind info, not real addresses.
    let is_linear = octets[1] == octets[0].wrapping_add(1)
        && octets[2] == octets[0].wrapping_add(2)
        && octets[3] == octets[0].wrapping_add(3);
    if is_linear {
        return false;
    }

    // Last octets 1–4 are gateway/infrastructure addresses, not C2 hosts.
    if octets[3] < 5 {
        return false;
    }

    // Repeated low-value octets (< 16) are a hallmark of binary data tables and
    // counter sequences (e.g., 21.3.12.12 where 12 repeats), not real IP allocations.
    for val in octets {
        if val < 16 && octets.iter().filter(|&&b| b == val).count() > 1 {
            return false;
        }
    }

    true
}

/// Scan for sockaddr_in structures (AF_INET + port + IP).
///
/// sockaddr_in structure layout:
/// - Byte 0-1: sin_family (AF_INET = 2, stored in host byte order)
/// - Byte 2-3: sin_port (network byte order / big-endian)
/// - Byte 4-7: sin_addr (4 bytes IPv4, network byte order / big-endian)
fn scan_sockaddr_in(
    data: &[u8],
    min_length: usize,
    endianness: Endianness,
) -> Vec<ExtractedString> {
    let mut results = Vec::new();

    // Skip file headers (ELF, PE, Mach-O) which often contain similar byte patterns
    // Use 1024 byte skip to cover headers and metadata sections that often contain
    // false positive patterns. Real sockaddr_in structs are in data sections further in.
    let start = if data.len() > 1024 { 1024 } else { 0 };

    let accept_le = matches!(endianness, Endianness::Little | Endianness::Unknown);
    let accept_be = matches!(endianness, Endianness::Big | Endianness::Unknown);

    for i in start..data.len().saturating_sub(7) {
        // Check for AF_INET marker (value 2) in the binary's native order.
        // Accepting the wrong byte order produces false positives because
        // unrelated structures (COM GUIDs in PE .rdata, small-int tables) often
        // contain `00 02` or `02 00` runs.
        let af_inet_le = accept_le && data[i] == 0x02 && data[i + 1] == 0x00;
        let af_inet_be = accept_be && data[i] == 0x00 && data[i + 1] == 0x02;

        if !af_inet_le && !af_inet_be {
            continue;
        }

        let port = u16::from_be_bytes([data[i + 2], data[i + 3]]);

        // Skip port 0 (invalid)
        if port == 0 {
            continue;
        }

        // Skip very high ports (>= 61000) - unlikely to be real C2, often artifacts
        if port >= 61000 {
            continue;
        }

        let octets = [data[i + 4], data[i + 5], data[i + 6], data[i + 7]];

        // Skip if IP is invalid
        if !is_valid_ip(octets) {
            continue;
        }

        // Skip if IP octets look like text (3+ ASCII printable characters)
        let ascii_count = octets.iter().filter(|&&b| (32..=126).contains(&b)).count();
        if ascii_count >= 3 {
            continue;
        }

        // A real sockaddr_in is a 16-byte struct whose trailing sin_zero[8]
        // padding is virtually always zeroed — either by C zero-initialization
        // of a partially-initialized struct, or by an explicit memset before
        // sin_family/sin_port/sin_addr are filled in. High-entropy data (icons,
        // version resources, compressed blobs) that happens to start with
        // `02 00` + a plausible port + a valid IP almost never carries the eight
        // trailing zero bytes. Requiring most of sin_zero to be zero removes
        // those coincidental matches without rejecting genuine socket literals.
        // If the struct is truncated by end-of-data the padding cannot be
        // confirmed, so reject to be safe (consistent with the section filter).
        let Some(sin_zero) = data.get(i + 8..i + 16) else {
            continue;
        };
        if sin_zero.iter().filter(|&&b| b == 0).count() < 6 {
            continue;
        }

        let ip_str = format!(
            "{}.{}.{}.{}:{}",
            octets[0], octets[1], octets[2], octets[3], port
        );

        // Respect min_length parameter
        if ip_str.len() < min_length {
            continue;
        }

        results.push(ExtractedString {
            value: ip_str,
            data_offset: i as u64,
            method: StringMethod::RawScan,
            kind: Some(StringKind::IpPort),
            ..Default::default()
        });
    }

    results
}

#[cfg(test)]
mod tests;
