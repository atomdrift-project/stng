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

/// Checks if a PE section name indicates a data section
/// Real hardcoded C2 IPs should be in data sections like .data or .rdata, not .text (code)
fn is_data_section_pe(section: &str) -> bool {
    matches!(
        section,
        ".data" | ".rdata" | ".bss" | ".idata" | ".edata" | ".rsrc"
    )
}

/// Check if this is a Go binary by examining section names.
/// Go binaries have .gopclntab/.go.buildinfo (ELF) or gopclntab/go.buildinfo (PE).
fn is_go_binary_from_sections(
    elf_opt: Option<&crate::goblin::elf::Elf<'_>>,
    pe_opt: Option<&crate::goblin::pe::PE<'_>>,
) -> bool {
    // Check ELF for Go sections
    if let Some(elf) = elf_opt {
        return elf.section_headers.iter().any(|sh| {
            if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
                name == ".gopclntab" || name == ".go.buildinfo"
            } else {
                false
            }
        });
    }

    // Check PE for Go sections
    if let Some(pe) = pe_opt {
        return pe.sections.iter().any(|section| {
            let name = String::from_utf8_lossy(&section.name)
                .trim_end_matches('\0')
                .to_lowercase();
            name.contains("gopclntab") || name.contains("go.buildinfo")
        });
    }

    false
}

/// Check if this is a .NET binary by examining the CLR header directory.
/// .NET binaries have a COM descriptor (CLR header) and don't use C-style sockaddr_in.
fn is_dotnet_binary(
    pe_opt: Option<&crate::goblin::pe::PE<'_>>,
    data: &[u8],
) -> bool {
    if let Some(pe) = pe_opt {
        // Check if PE has CLR runtime header (index 14 = COM_DESCRIPTOR / CLR header)
        if let Some(optional_header) = pe.header.optional_header {
            let data_directories = &optional_header.data_directories.data_directories;
            // Index 14 is IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR (CLR header)
            if data_directories.len() > 14 {
                if let Some((_, clr_dir)) = &data_directories[14] {
                    if clr_dir.virtual_address != 0 && clr_dir.size != 0 {
                        return true;
                    }
                }
            }
        }

        // Also check for BSJB signature in data (indicates CLI metadata header)
        // This is a backup check for native images (.ni.dll) which may not have CLR header
        if data.len() > 4 {
            // Search in first 1MB for "BSJB" (CLI metadata signature)
            let search_len = data.len().min(1024 * 1024);
            if data[..search_len]
                .windows(4)
                .any(|w| w == b"BSJB")
            {
                return true;
            }
        }
    }

    false
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
pub fn scan_binary_ips(
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
    if is_go_binary_from_sections(elf_opt, pe_opt) {
        return Vec::new();
    }

    // Skip .NET binaries - they don't use C-style sockaddr_in structures
    // .NET has managed networking APIs and doesn't embed raw socket addresses
    // Native images (.ni.dll) contain compiled IL/JIT code that produces many false positives
    if is_dotnet_binary(pe_opt, data) {
        return Vec::new();
    }

    let mut results = Vec::new();

    // Only scan for sockaddr_in structures - these have the AF_INET marker
    // which provides context that this is actually a socket structure
    results.extend(scan_sockaddr_in(data, min_length));

    // For ELF binaries with section info, filter to only accept data sections
    // Real hardcoded C2 IPs are in .data, .rodata, etc., not in .text (code)
    if let Some(elf) = elf_opt {
        results.retain(|s| {
            // Find which section this offset belongs to
            for sh in &elf.section_headers {
                if s.data_offset >= sh.sh_offset && s.data_offset < sh.sh_offset + sh.sh_size {
                    if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
                        // Accept if in a data section, reject if in code section
                        return is_data_section_elf(name);
                    }
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
            // Find which section this offset belongs to
            for section in &pe.sections {
                let section_start = u64::from(section.pointer_to_raw_data);
                let section_end = section_start + u64::from(section.size_of_raw_data);
                if s.data_offset >= section_start && s.data_offset < section_end {
                    let name = String::from_utf8_lossy(&section.name)
                        .trim_end_matches('\0')
                        .to_string();
                    // Accept if in a data section, reject if in code section
                    return is_data_section_pe(&name);
                }
            }
            // If section can't be determined, reject to be safe
            false
        });
    }

    // Deduplicate by offset to avoid reporting same location multiple times
    let mut seen = HashSet::new();
    results.retain(|s| seen.insert((s.data_offset, s.value.clone())));

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

    true
}

fn scan_sockaddr_in(data: &[u8], min_length: usize) -> Vec<ExtractedString> {
    let mut results = Vec::new();

    // Skip file headers (ELF, PE, Mach-O) which often contain similar byte patterns
    // Use 1024 byte skip to cover headers and metadata sections that often contain
    // false positive patterns. Real sockaddr_in structs are in data sections further in.
    let start = if data.len() > 1024 { 1024 } else { 0 };

    for i in start..data.len().saturating_sub(7) {
        // Check for AF_INET marker (value 2) in either endianness
        // Little-endian: 0x02 0x00
        // Big-endian: 0x00 0x02
        let af_inet_le = data[i] == 0x02 && data[i + 1] == 0x00;
        let af_inet_be = data[i] == 0x00 && data[i + 1] == 0x02;

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
            kind: StringKind::IPPort,
            source: Some("sockaddr_in".to_string()),
            ..Default::default()
        });
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sockaddr_in_little_endian() {
        // sockaddr_in with AF_INET (0x0002) in little-endian
        let mut data = vec![0xAA; 300]; // Larger buffer to bypass 256-byte skip
        data[270] = 0x02; // AF_INET LE first byte
        data[271] = 0x00; // AF_INET LE second byte
        data[272..274].copy_from_slice(&[0x1F, 0x90]); // Port 8080 BE
        data[274..278].copy_from_slice(&[0xC0, 0xA8, 0x01, 0x01]); // IP 192.168.1.1 BE

        let results = scan_sockaddr_in(&data, 4);

        // Should find our target
        let found = results.iter().find(|s| s.value == "192.168.1.1:8080");
        assert!(
            found.is_some(),
            "Should find 192.168.1.1:8080 in sockaddr_in"
        );
        assert_eq!(found.unwrap().data_offset, 270);
        assert_eq!(found.unwrap().kind, StringKind::IPPort);
        assert_eq!(found.unwrap().source, Some("sockaddr_in".to_string()));
    }

    #[test]
    fn test_sockaddr_in_big_endian() {
        // sockaddr_in with AF_INET (0x0200) in big-endian
        let mut data = vec![0xAA; 300]; // Larger buffer to bypass 256-byte skip
        data[270] = 0x00; // AF_INET BE first byte
        data[271] = 0x02; // AF_INET BE second byte
        data[272..274].copy_from_slice(&[0x1F, 0x90]); // Port 8080 BE
        data[274..278].copy_from_slice(&[0xC0, 0xA8, 0x01, 0x01]); // IP 192.168.1.1 BE

        let results = scan_sockaddr_in(&data, 4);

        let found = results.iter().find(|s| s.value == "192.168.1.1:8080");
        assert!(
            found.is_some(),
            "Should find 192.168.1.1:8080 with AF_INET BE"
        );
    }

    #[test]
    fn test_sockaddr_in_min_length_filter() {
        // sockaddr_in but with min_length that's too high
        let mut data = vec![0xAA; 300]; // Larger buffer to bypass 256-byte skip
        data[270] = 0x02; // AF_INET LE
        data[271] = 0x00;
        data[272..274].copy_from_slice(&[0x00, 0x50]); // Port 80
        data[274..278].copy_from_slice(&[0xC0, 0x00, 0x02, 0x01]);

        // Request results with min_length = 100
        let results = scan_sockaddr_in(&data, 100);

        // Should not find it (192.0.2.1:80 is only 15 chars)
        assert!(results.is_empty(), "Should filter by min_length");
    }

    #[test]
    fn test_sockaddr_in_no_false_positives_from_text() {
        // Data that looks like sockaddr_in but has text-like octets in the IP
        let mut data = vec![0xAA; 300]; // Larger buffer to bypass 256-byte skip
        data[270] = 0x02; // AF_INET LE
        data[271] = 0x00;
        data[272..274].copy_from_slice(&[0x1F, 0x90]); // Port 8080
                                                       // IP with 3+ ASCII chars (E=0x45, L=0x4C, F=0x46)
        data[274..278].copy_from_slice(&[0x7F, 0x45, 0x4C, 0x46]);

        let results = scan_sockaddr_in(&data, 4);

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
        data[5] = 0x02;
        data[6] = 0x00;
        data[7..9].copy_from_slice(&[0x1F, 0x90]); // Port 8080
                                                   // Use IP 172.16.1.1 (0xAC 0x10 0x01 0x01) to avoid accidental AF_INET patterns
        data[9..13].copy_from_slice(&[0xAC, 0x10, 0x01, 0x01]); // 172.16.1.1

        // Second sockaddr_in at offset 50 (well-separated to avoid overlaps)
        data[50] = 0x00;
        data[51] = 0x02;
        data[52..54].copy_from_slice(&[0x00, 0x50]); // Port 80
                                                     // Use IP 10.20.30.40 (0x0A 0x14 0x1E 0x28) to avoid accidental AF_INET patterns
        data[54..58].copy_from_slice(&[0x0A, 0x14, 0x1E, 0x28]); // 10.20.30.40

        let elf_arm = 40; // EM_ARM from ELF header
        let results = scan_binary_ips(&data, 4, elf_arm, None, None);

        // Should find at least the two main structures (deduplication may occur)
        assert!(results.len() >= 2);
        let ips: std::collections::HashSet<&str> =
            results.iter().map(|s| s.value.as_str()).collect();
        assert!(ips.contains("172.16.1.1:8080"));
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

        // Valid: 103.214.143.214
        data[320] = 0x02;
        data[321] = 0x00;
        data[322..324].copy_from_slice(&[0x1F, 0x95]); // Port 8085
        data[324..328].copy_from_slice(&[0x67, 0xD6, 0x8F, 0xD6]); // 103.214.143.214

        let results = scan_sockaddr_in(&data, 4);

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
    fn test_m68000_skip() {
        // M68000 binaries should return empty results to avoid false positives
        // Their instruction stream naturally contains 0x0002 patterns
        let mut data = vec![0xAA; 300];

        // Create a valid sockaddr_in structure
        data[270] = 0x02;
        data[271] = 0x00;
        data[272..274].copy_from_slice(&[0x1F, 0x90]); // Port 8080
        data[274..278].copy_from_slice(&[0xC0, 0xA8, 0x01, 0x01]); // IP 192.168.1.1

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
        data[270] = 0x02;
        data[271] = 0x00;
        data[272..274].copy_from_slice(&[0x1F, 0x90]); // Port 8080
        data[274..278].copy_from_slice(&[0xC0, 0xA8, 0x01, 0x01]); // IP 192.168.1.1

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
                results.iter().any(|r| r.value.contains("192.168.1.1:8080")),
                "Should find IP for {} architecture",
                arch_name
            );
        }
    }

    #[test]
    fn test_non_go_binaries_still_processed() {
        // Create a C-style binary with sockaddr_in that should be detected
        let mut data = vec![0xAA; 300];

        data[270] = 0x02;
        data[271] = 0x00;
        data[272..274].copy_from_slice(&[0x1F, 0x90]); // Port 8080
        data[274..278].copy_from_slice(&[0xC0, 0xA8, 0x01, 0x01]); // IP 192.168.1.1

        // Test with ARM architecture (not M68000, not Go)
        let elf_arm = 40; // EM_ARM
        let results = scan_binary_ips(&data, 4, elf_arm, None, None);

        // Should still find the sockaddr_in structure
        assert!(!results.is_empty(), "Non-Go binaries should still be scanned");
        assert!(
            results.iter().any(|r| r.value.contains("192.168.1.1:8080")),
            "Should find IP in non-Go binary"
        );
    }
}
