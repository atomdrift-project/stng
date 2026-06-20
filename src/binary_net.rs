//! Binary network data detection.
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
    /// Format gave no endianness hint — accept either marker (legacy behavior
    /// for Mach-O / unknown / fully-unparsed inputs).
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
                        name.as_str(),
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

/// Scan for sockaddr_in structures (AF_INET + port + IP).
///
/// sockaddr_in structure layout:
/// - Byte 0-1: sin_family (AF_INET = 2, stored in host byte order)
/// - Byte 2-3: sin_port (network byte order / big-endian)
/// - Byte 4-7: sin_addr (4 bytes IPv4, network byte order / big-endian)
///
/// Skips the first 256 bytes to avoid false positives from ELF/PE/Mach-O file headers
/// that happen to contain sockaddr_in-like byte sequences.
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
            section: None,
            method: StringMethod::RawScan,
            kind: Some(StringKind::IPPort),
            ..Default::default()
        });
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lay down a realistic 16-byte `sockaddr_in` at `off`: the AF_INET marker,
    /// a big-endian port, the big-endian IPv4 address, and a zeroed 8-byte
    /// `sin_zero` tail — the layout `scan_sockaddr_in` now requires. `le_marker`
    /// selects the marker byte order (`02 00` little-endian vs `00 02` big-endian).
    fn put_sockaddr_in(data: &mut [u8], off: usize, le_marker: bool, port: u16, ip: [u8; 4]) {
        let marker = if le_marker {
            [0x02, 0x00]
        } else {
            [0x00, 0x02]
        };
        data[off..off + 2].copy_from_slice(&marker);
        data[off + 2..off + 4].copy_from_slice(&port.to_be_bytes());
        data[off + 4..off + 8].copy_from_slice(&ip);
        data[off + 8..off + 16].fill(0); // sin_zero
    }

    #[test]
    fn test_sockaddr_in_little_endian() {
        // sockaddr_in with AF_INET (0x0002) in little-endian
        let mut data = vec![0xAA; 300]; // Larger buffer to bypass 256-byte skip
        put_sockaddr_in(&mut data, 270, true, 8080, [192, 168, 1, 50]);

        let results = scan_sockaddr_in(&data, 4, Endianness::Unknown);

        // Should find our target
        let found = results.iter().find(|s| s.value == "192.168.1.50:8080");
        assert!(
            found.is_some(),
            "Should find 192.168.1.50:8080 in sockaddr_in"
        );
        assert_eq!(found.unwrap().data_offset, 270);
        assert_eq!(found.unwrap().kind, Some(StringKind::IPPort));
    }

    #[test]
    fn test_sockaddr_in_big_endian() {
        // sockaddr_in with AF_INET (0x0200) in big-endian
        let mut data = vec![0xAA; 300]; // Larger buffer to bypass 256-byte skip
        put_sockaddr_in(&mut data, 270, false, 8080, [192, 168, 1, 50]);

        let results = scan_sockaddr_in(&data, 4, Endianness::Unknown);

        let found = results.iter().find(|s| s.value == "192.168.1.50:8080");
        assert!(
            found.is_some(),
            "Should find 192.168.1.50:8080 with AF_INET BE"
        );
    }

    #[test]
    fn test_sockaddr_in_min_length_filter() {
        // sockaddr_in but with min_length that's too high
        let mut data = vec![0xAA; 300]; // Larger buffer to bypass 256-byte skip
        put_sockaddr_in(&mut data, 270, true, 80, [198, 51, 100, 80]);

        // Request results with min_length = 100
        let results = scan_sockaddr_in(&data, 100, Endianness::Unknown);

        // Should not find it (198.51.100.80:80 is only 16 chars)
        assert!(results.is_empty(), "Should filter by min_length");
    }

    #[test]
    fn test_sockaddr_in_no_false_positives_from_text() {
        // Data that looks like sockaddr_in but has text-like octets in the IP
        let mut data = vec![0xAA; 300]; // Larger buffer to bypass 256-byte skip
        // IP with 3+ ASCII chars (E=0x45, L=0x4C, F=0x46)
        put_sockaddr_in(&mut data, 270, true, 8080, [0x7F, 0x45, 0x4C, 0x46]);

        let results = scan_sockaddr_in(&data, 4, Endianness::Unknown);

        // Should filter out because IP looks like "ELF" text
        assert!(
            results.is_empty(),
            "Should filter sockaddr_in with text-like IP"
        );
    }

    #[test]
    fn test_multiple_sockaddr_in_structures() {
        let mut data = vec![0xAA; 100];

        // First sockaddr_in at offset 5
        put_sockaddr_in(&mut data, 5, true, 8080, [172, 16, 20, 50]);

        // Second sockaddr_in at offset 50 (well-separated to avoid overlaps)
        // IP 10.20.30.40 avoids accidental AF_INET patterns.
        put_sockaddr_in(&mut data, 50, false, 80, [10, 20, 30, 40]);

        let elf_arm = 40; // EM_ARM from ELF header
        let results = scan_binary_ips(&data, 4, elf_arm, None, None);

        // Should find at least the two main structures (deduplication may occur)
        assert!(results.len() >= 2);
        let ips: std::collections::HashSet<&str> =
            results.iter().map(|s| s.value.as_str()).collect();
        assert!(ips.contains("172.16.20.50:8080"));
        assert!(ips.contains("10.20.30.40:80"));
    }

    #[test]
    fn test_sockaddr_in_rejects_invalid_ips() {
        // Test that invalid IPs are filtered out
        let mut data = vec![0xAA; 400];

        // Invalid: 5.20.30.65 (first octet 5 is too low, artifact pattern)
        data[270] = 0x02;
        data[271] = 0x00;
        data[272..274].copy_from_slice(&[0x1F, 0x90]); // Port 8080
        data[274..278].copy_from_slice(&[0x05, 0x14, 0x1E, 0x41]); // 5.20.30.65

        // Invalid: 103.214.143.0 (last octet is 0)
        data[280] = 0x02;
        data[281] = 0x00;
        data[282..284].copy_from_slice(&[0x1F, 0x91]); // Port 8081
        data[284..288].copy_from_slice(&[0x67, 0xD6, 0x8F, 0x00]); // 103.214.143.0

        // Invalid: 234.0.1.112 (multicast range >= 224 and has zero octet)
        data[290] = 0x02;
        data[291] = 0x00;
        data[292..294].copy_from_slice(&[0x1F, 0x92]); // Port 8082
        data[294..298].copy_from_slice(&[0xEA, 0x00, 0x01, 0x70]); // 234.0.1.112

        // Invalid: 51.0.100.80 (has zero octet in middle)
        data[300] = 0x02;
        data[301] = 0x00;
        data[302..304].copy_from_slice(&[0x1F, 0x93]); // Port 8083
        data[304..308].copy_from_slice(&[0x33, 0x00, 0x64, 0x50]); // 51.0.100.80

        // Invalid: 123.45.0.67 (has zero octet)
        data[310] = 0x02;
        data[311] = 0x00;
        data[312..314].copy_from_slice(&[0x1F, 0x94]); // Port 8084
        data[314..318].copy_from_slice(&[0x7B, 0x2D, 0x00, 0x43]); // 123.45.0.67

        // Valid: 103.214.143.214 (realistic struct with zeroed sin_zero)
        put_sockaddr_in(&mut data, 320, true, 8085, [103, 214, 143, 214]);

        let results = scan_sockaddr_in(&data, 4, Endianness::Unknown);

        let ips: std::collections::HashSet<&str> =
            results.iter().map(|s| s.value.as_str()).collect();

        // Should NOT find the invalid IPs
        assert!(
            !ips.iter().any(|ip| ip.contains("5.20.30.65")),
            "Should reject 5.20.30.65 (low first octet)"
        );
        assert!(
            !ips.iter().any(|ip| ip.contains("103.214.143.0")),
            "Should reject 103.214.143.0 (zero octet)"
        );
        assert!(
            !ips.iter().any(|ip| ip.contains("234.0.1.112")),
            "Should reject 234.0.1.112 (multicast)"
        );
        assert!(
            !ips.iter().any(|ip| ip.contains("51.0.100.80")),
            "Should reject 51.0.100.80 (zero octet)"
        );
        assert!(
            !ips.iter().any(|ip| ip.contains("123.45.0.67")),
            "Should reject 123.45.0.67 (zero octet)"
        );

        // Should find the valid IP
        assert!(
            ips.contains("103.214.143.214:8085"),
            "Should find 103.214.143.214:8085"
        );
    }

    #[test]
    fn test_sockaddr_in_rejects_linear_ip() {
        // Linear sequences like 0x0D 0x0E 0x0F 0x10 are common in data tables,
        // not real addresses (matches the tscfgwmi.dll false positive pattern).
        let mut data = vec![0xAA; 320];

        // 13.14.15.16 — perfectly sequential, should be rejected
        data[270] = 0x02;
        data[271] = 0x00;
        data[272..274].copy_from_slice(&[0x01, 0x02]); // Port 258
        data[274..278].copy_from_slice(&[0x0D, 0x0E, 0x0F, 0x10]); // 13.14.15.16

        // 21.22.23.24 — also linear
        data[280] = 0x02;
        data[281] = 0x00;
        data[282..284].copy_from_slice(&[0x1F, 0x90]); // Port 8080
        data[284..288].copy_from_slice(&[0x15, 0x16, 0x17, 0x18]); // 21.22.23.24

        // 192.168.1.50 — not linear, should be found
        put_sockaddr_in(&mut data, 290, true, 8081, [192, 168, 1, 50]);

        let results = scan_sockaddr_in(&data, 4, Endianness::Unknown);
        let ips: std::collections::HashSet<&str> =
            results.iter().map(|s| s.value.as_str()).collect();

        assert!(
            !ips.contains("13.14.15.16:258"),
            "Should reject linear IP 13.14.15.16"
        );
        assert!(
            !ips.contains("21.22.23.24:8080"),
            "Should reject linear IP 21.22.23.24"
        );
        assert!(
            ips.contains("192.168.1.50:8081"),
            "Should find non-linear IP 192.168.1.50"
        );
    }

    #[test]
    fn test_sockaddr_in_rejects_low_last_octet() {
        // Last octets 1–4 are gateway/infrastructure, not C2 hosts.
        // Mirrors the 128.92.202.4 false positive from tscfgwmi.dll.
        let mut data = vec![0xAA; 320];

        // 128.92.202.4 — last octet 4, should be rejected
        data[270] = 0x00;
        data[271] = 0x02;
        data[272..274].copy_from_slice(&[0x80, 0x02]); // Port 32770
        data[274..278].copy_from_slice(&[0x80, 0x5C, 0xCA, 0x04]); // 128.92.202.4

        // 12.2.120.2 — last octet 2, should be rejected
        data[280] = 0x00;
        data[281] = 0x02;
        data[282..284].copy_from_slice(&[0x1A, 0x04]); // Port 6660
        data[284..288].copy_from_slice(&[0x0C, 0x02, 0x78, 0x02]); // 12.2.120.2

        // 128.92.202.6 — last octet 6, should be found
        put_sockaddr_in(&mut data, 290, false, 32770, [128, 92, 202, 6]);

        let results = scan_sockaddr_in(&data, 4, Endianness::Unknown);
        let ips: std::collections::HashSet<&str> =
            results.iter().map(|s| s.value.as_str()).collect();

        assert!(
            !ips.contains("128.92.202.4:32770"),
            "Should reject last octet 4"
        );
        assert!(
            !ips.contains("12.2.120.2:6660"),
            "Should reject last octet 2"
        );
        assert!(
            ips.contains("128.92.202.6:32770"),
            "Should find last octet 6"
        );
    }

    #[test]
    fn test_sockaddr_in_rejects_repeated_low_octets() {
        // Repeated low-value octets are common in binary data tables, not real IPs.
        // Mirrors the 21.3.12.12 false positive from tscfgwmi.dll.
        let mut data = vec![0xAA; 340];

        // 21.3.12.12 — value 12 repeats and is < 16, should be rejected
        data[270] = 0x00;
        data[271] = 0x02;
        data[272..274].copy_from_slice(&[0x05, 0x5B]); // Port 1371
        data[274..278].copy_from_slice(&[0x15, 0x03, 0x0C, 0x0C]); // 21.3.12.12

        // 185.220.100.240 — no repeated low values, should be found
        put_sockaddr_in(&mut data, 290, false, 8080, [185, 220, 100, 240]);

        // 104.21.25.21 — 21 repeats but 21 >= 16, should be found
        put_sockaddr_in(&mut data, 310, false, 443, [104, 21, 25, 21]);

        let results = scan_sockaddr_in(&data, 4, Endianness::Unknown);
        let ips: std::collections::HashSet<&str> =
            results.iter().map(|s| s.value.as_str()).collect();

        assert!(
            !ips.contains("21.3.12.12:1371"),
            "Should reject repeated low octet 12"
        );
        assert!(
            ips.contains("185.220.100.240:8080"),
            "Should find IP with no repeated low octets"
        );
        assert!(
            ips.contains("104.21.25.21:443"),
            "Should find IP where repeated value >= 16"
        );
    }

    #[test]
    fn test_m68000_skip() {
        // M68000 binaries should return empty results to avoid false positives
        // Their instruction stream naturally contains 0x0002 patterns
        let mut data = vec![0xAA; 300];

        // Create a valid sockaddr_in structure
        data[270] = 0x02;
        data[271] = 0x00;
        data[272..274].copy_from_slice(&[0x1F, 0x90]); // Port 8080
        data[274..278].copy_from_slice(&[0xC0, 0xA8, 0x01, 0x32]); // IP 192.168.1.50

        let elf_m68k = 4; // EM_68K from ELF header
        let results = scan_binary_ips(&data, 4, elf_m68k, None, None);

        // Should return empty for M68000 binaries
        assert!(
            results.is_empty(),
            "Should skip all results for M68000 binaries"
        );
    }

    #[test]
    fn test_non_m68000_architectures_processed() {
        // Non-M68000 architectures should be processed normally
        let mut data = vec![0xAA; 300];

        // Create a valid sockaddr_in structure
        put_sockaddr_in(&mut data, 270, true, 8080, [192, 168, 1, 50]);

        // Test with various non-M68000 architectures
        let arch_samples = vec![
            (40, "ARM"),    // EM_ARM
            (183, "ARM64"), // EM_AARCH64
            (62, "x86_64"), // EM_X86_64
            (3, "x86"),     // EM_386
        ];

        for (e_machine, arch_name) in arch_samples {
            let results = scan_binary_ips(&data, 4, e_machine, None, None);
            assert!(
                !results.is_empty(),
                "Should process {} architecture",
                arch_name
            );
            assert!(
                results
                    .iter()
                    .any(|r| r.value.contains("192.168.1.50:8080")),
                "Should find IP for {} architecture",
                arch_name
            );
        }
    }

    #[test]
    fn test_sockaddr_endianness_le_rejects_be_marker() {
        // On a little-endian binary, only `02 00` is a real sockaddr_in.
        // A `00 02 ...` sequence (e.g. middle of a COM GUID) must NOT match.
        let mut data = vec![0xAA; 300];
        // BE-marker bytes that decode to a plausible-looking 155.241.239.26:48379
        put_sockaddr_in(&mut data, 270, false, 48379, [155, 241, 239, 26]);

        let results = scan_sockaddr_in(&data, 4, Endianness::Little);
        assert!(
            results.is_empty(),
            "LE binary should not accept BE AF_INET marker; got {results:?}"
        );

        // Sanity: the same buffer with Unknown endianness *would* match.
        let results_unknown = scan_sockaddr_in(&data, 4, Endianness::Unknown);
        assert!(
            !results_unknown.is_empty(),
            "Unknown endianness should accept either marker"
        );
    }

    #[test]
    fn test_sockaddr_endianness_be_rejects_le_marker() {
        // Inverse: on a big-endian binary, only `00 02` is real.
        let mut data = vec![0xAA; 300];
        data[270] = 0x02;
        data[271] = 0x00;
        data[272..274].copy_from_slice(&[0x1F, 0x90]); // Port 8080
        data[274..278].copy_from_slice(&[0xC0, 0xA8, 0x01, 0x32]); // 192.168.1.50

        let results = scan_sockaddr_in(&data, 4, Endianness::Big);
        assert!(
            results.is_empty(),
            "BE binary should not accept LE AF_INET marker; got {results:?}"
        );
    }

    #[test]
    fn test_sockaddr_endianness_le_still_finds_native_marker() {
        // Regression guard: real LE sockaddr_in still extracts.
        let mut data = vec![0xAA; 300];
        put_sockaddr_in(&mut data, 270, true, 8080, [192, 168, 1, 50]);

        let results = scan_sockaddr_in(&data, 4, Endianness::Little);
        assert!(results.iter().any(|s| s.value == "192.168.1.50:8080"));
    }

    #[test]
    fn test_non_go_binaries_still_processed() {
        // Create a C-style binary with sockaddr_in that should be detected
        let mut data = vec![0xAA; 300];

        put_sockaddr_in(&mut data, 270, true, 8080, [192, 168, 1, 50]);

        // Test with ARM architecture (not M68000, not Go)
        let elf_arm = 40; // EM_ARM
        let results = scan_binary_ips(&data, 4, elf_arm, None, None);

        // Should still find the sockaddr_in structure
        assert!(
            !results.is_empty(),
            "Non-Go binaries should still be scanned"
        );
        assert!(
            results
                .iter()
                .any(|r| r.value.contains("192.168.1.50:8080")),
            "Should find IP in non-Go binary"
        );
    }

    /// Verbatim 64-byte slice from CPython 3.10 `unicodedata.pyd` (Windows) at
    /// file offset 0x4f80 — densely-packed UNWIND_CODE-style data that the
    /// raw scanner previously surfaced as `19.1.2.170:5632` and `19.1.5.170:6912`.
    /// `02 00 16 00 13 01 02 aa` sits at relative offset 26 of this slice.
    const UWOP_FIXTURE: &[u8] = &[
        0x0a, 0x00, 0x05, 0x00, 0x1b, 0x00, 0x0b, 0x00, 0x05, 0x00, 0x1b, 0x00, 0x13, 0x01, 0x04,
        0x88, 0x1b, 0x00, 0x13, 0x01, 0x04, 0x0a, 0x1e, 0x00, 0x13, 0x00, 0x02, 0x00, 0x16, 0x00,
        0x13, 0x01, 0x02, 0xaa, 0x17, 0x00, 0x13, 0x01, 0x02, 0xaa, 0x1e, 0x00, 0x01, 0x00, 0x04,
        0x88, 0x09, 0x00, 0x13, 0x00, 0x04, 0x00, 0x1b, 0x00, 0x13, 0x00, 0x02, 0x00, 0x1b, 0x00,
        0x13, 0x01, 0x05, 0xaa,
    ];

    /// Verbatim 64-byte slices from the Inno Setup installer
    /// `6fcd77d331dd9e9699a0f5ac623e2ac0.exe` at file offsets 0x1677f and
    /// 0x16abd, centered on the AF_INET marker (relative offset 32). These are
    /// Delphi/VCL packed metadata tables (`64 02 64 02`, `f0 02 f0 02`,
    /// `XX 10 XX 10`) that the raw scanner surfaced as `11.16.15.16:3856` and
    /// `19.89.9.89:784` — neither IP exists as ASCII anywhere in the file.
    const PERIODIC_FIXTURE_A: &[u8] = &[
        0x0e, 0x10, 0x0b, 0x10, 0x0b, 0x10, 0x0b, 0x10, 0x0b, 0x10, 0x0b, 0x10, 0x0b, 0x0f, 0x0e,
        0x10, 0x0b, 0x10, 0x0b, 0xe0, 0x0e, 0x10, 0x0b, 0xf0, 0x0e, 0x64, 0x02, 0x64, 0x02, 0x64,
        0x02, 0x64, 0x02, 0x00, 0x0f, 0x10, 0x0b, 0x10, 0x0f, 0x10, 0x0b, 0x20, 0x0f, 0x30, 0x0f,
        0x40, 0x0f, 0x50, 0x0f, 0x59, 0x09, 0x60, 0x0f, 0x10, 0x0b, 0x70, 0x0f, 0x80, 0x0f, 0x34,
        0x0e, 0x90, 0x0f, 0x34,
    ];
    const PERIODIC_FIXTURE_B: &[u8] = &[
        0x12, 0x00, 0x13, 0x8d, 0x04, 0xf0, 0x02, 0x1b, 0x07, 0x56, 0x05, 0xfd, 0x02, 0xfd, 0x02,
        0x64, 0x02, 0x64, 0x02, 0xf0, 0x02, 0xf0, 0x02, 0xf0, 0x02, 0xf0, 0x02, 0xf0, 0x02, 0xf0,
        0x02, 0xf0, 0x02, 0x00, 0x03, 0x10, 0x13, 0x59, 0x09, 0x59, 0x09, 0x69, 0x09, 0xd0, 0x0d,
        0xd0, 0x0d, 0xd0, 0x0d, 0x20, 0x13, 0x30, 0x13, 0x64, 0x02, 0x64, 0x02, 0x64, 0x02, 0x64,
        0x02, 0x64, 0x02, 0x64,
    ];

    #[test]
    fn test_sits_in_periodic_table_flags_real_false_positives() {
        // AF_INET marker sits at relative offset 32 in both fixtures.
        assert!(
            sits_in_periodic_table(PERIODIC_FIXTURE_A, 32),
            "11.16.15.16:3856 packed-table region must be flagged"
        );
        assert!(
            sits_in_periodic_table(PERIODIC_FIXTURE_B, 32),
            "19.89.9.89:784 packed-table region must be flagged"
        );
    }

    #[test]
    fn test_sits_in_periodic_table_passes_real_layouts() {
        // Heterogeneous .data around a real sockaddr_in.
        let mut hetero: Vec<u8> = (0u8..128)
            .map(|i| i.wrapping_mul(37).wrapping_add(0x33))
            .collect();
        hetero[64..72].copy_from_slice(&[0x02, 0x00, 0x1f, 0x90, 192, 168, 1, 50]);
        assert!(
            !sits_in_periodic_table(&hetero, 64),
            "heterogeneous sockaddr_in must not be flagged"
        );

        // Zero-padded struct in a BSS-like region — zeros must not count as
        // periodicity.
        let mut zeroed = vec![0u8; 128];
        zeroed[64..72].copy_from_slice(&[0x02, 0x00, 0x1f, 0x90, 192, 168, 1, 50]);
        assert!(
            !sits_in_periodic_table(&zeroed, 64),
            "zero-padded sockaddr_in must not be flagged"
        );
    }

    #[test]
    fn test_sin_zero_guard_rejects_periodic_fixture_at_raw_scan() {
        // The Delphi/VCL packed-table false positive (11.16.15.16:3856) is now
        // caught by the sin_zero guard directly in scan_sockaddr_in, without
        // needing a PE handle or the periodicity guard: the eight bytes after
        // the candidate IP are packed-table data, not a zeroed sin_zero tail.
        let mut data = vec![0u8; 2048];
        let embed = 1200;
        data[embed..embed + PERIODIC_FIXTURE_A.len()].copy_from_slice(PERIODIC_FIXTURE_A);
        let raw = scan_sockaddr_in(&data, 4, Endianness::Little);
        assert!(
            !raw.iter().any(|s| s.value == "11.16.15.16:3856"),
            "sin_zero guard must reject the packed-table false positive at raw scan; got {raw:?}"
        );
    }

    #[test]
    fn test_looks_like_packed_u16_table_flags_unwind_code_region() {
        // Both AF_INET-marker offsets in the real fixture must be flagged.
        assert!(looks_like_packed_u16_table(UWOP_FIXTURE, 26));
        assert!(looks_like_packed_u16_table(UWOP_FIXTURE, 56));
    }

    #[test]
    fn test_looks_like_packed_u16_table_passes_isolated_sockaddr() {
        // 192.168.1.50:8080 embedded among heterogeneous bytes (function
        // pointers, padding, unrelated constants) — what a real sockaddr_in
        // in `.data` looks like. Must NOT be flagged.
        // Pseudo-random spread covering the high byte space so u16 LE
        // values are >= 0x0200 most of the time. Length 128 fits in u8.
        let data_init: Vec<u8> = (0u8..128)
            .map(|i| i.wrapping_mul(37).wrapping_add(0x33))
            .collect();
        let mut data = data_init;
        let off = 64;
        data[off] = 0x02;
        data[off + 1] = 0x00;
        data[off + 2] = 0x1f;
        data[off + 3] = 0x90; // port 8080
        data[off + 4] = 192;
        data[off + 5] = 168;
        data[off + 6] = 1;
        data[off + 7] = 50;

        assert!(
            !looks_like_packed_u16_table(&data, off),
            "Isolated sockaddr_in in heterogeneous data must not be filtered"
        );
    }

    #[test]
    fn test_sin_zero_guard_rejects_unwind_fixture_at_raw_scan() {
        // Embed the UWOP fixture deep enough to clear the 1024-byte header skip
        // used by scan_sockaddr_in.
        let mut data = vec![0u8; 2048];
        let embed = 1200;
        data[embed..embed + UWOP_FIXTURE.len()].copy_from_slice(UWOP_FIXTURE);

        // The UNWIND_CODE false positive (19.1.2.170:5632) is now rejected by
        // the sin_zero guard directly in scan_sockaddr_in: the bytes following
        // the candidate IP are further unwind data, not a zeroed sin_zero tail.
        // This catches the false positive without a PE handle, ahead of the
        // looks_like_packed_u16_table guard the PE retain path still applies.
        let raw = scan_sockaddr_in(&data, 4, Endianness::Little);
        assert!(
            !raw.iter().any(|s| s.value == "19.1.2.170:5632"),
            "sin_zero guard must reject the UNWIND_CODE false positive at raw scan; got {raw:?}"
        );
    }
}
