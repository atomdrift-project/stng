//! Hard-coded IPv4 addresses in `sockaddr_in` structures.
//!
//! Scans binary data for hardcoded IP addresses in socket structures.
//! Only detects IPs in contextual patterns (sockaddr_in) to avoid false positives
//! from random 4-byte sequences.

use crate::types::{ExtractedString, StringKind, StringMethod};
use std::ops::Range;

/// Machine type constant for M68000 (Motorola 68000)
/// M68000 instructions contain 0x0002 patterns naturally, causing false positives
const EM_68K: u16 = 4;

/// Addresses reported per file. Real samples hard-code a handful of C2
/// endpoints; more candidates than this are mostly lookalike data.
const MAX_ADDRESSES: usize = 4;
/// Candidates ranked when choosing them, bounding the work and memory a
/// file of lookalike records costs.
const MAX_CANDIDATES: usize = 1024;

/// The verdict of the first section, in header order, that covers each
/// offset. Section headers are attacker-controlled, so they may overlap and
/// number in the tens of thousands; a lookup per candidate is a binary search
/// rather than a walk over every header.
struct SectionMap {
    /// Sorted, distinct range boundaries; segment `k` is `bounds[k]..bounds[k + 1]`.
    bounds: Vec<u64>,
    verdict: Vec<Option<bool>>,
}

impl SectionMap {
    /// `sections` yields each section's file range and verdict, in header
    /// order.
    fn new(sections: impl Iterator<Item = (Range<u64>, bool)>) -> Self {
        let sections: Vec<_> = sections.filter(|(range, _)| !range.is_empty()).collect();
        let mut bounds: Vec<u64> = sections
            .iter()
            .flat_map(|(range, _)| [range.start, range.end])
            .collect();
        bounds.sort_unstable();
        bounds.dedup();
        let segments = bounds.len().saturating_sub(1);
        let mut verdict = vec![None; segments];
        // `next[k]` leads to the first unclaimed segment at or after `k`, so each
        // segment is claimed once, by the earliest section that covers it.
        let mut next: Vec<usize> = (0..=segments).collect();
        let find = |next: &mut [usize], mut k: usize| {
            while next[k] != k {
                next[k] = next[next[k]];
                k = next[k];
            }
            k
        };
        for (range, accept) in sections {
            let mut k = find(&mut next, bounds.partition_point(|&b| b < range.start));
            while k < segments && bounds[k] < range.end {
                verdict[k] = Some(accept);
                next[k] = k + 1;
                k = find(&mut next, k + 1);
            }
        }
        Self { bounds, verdict }
    }

    fn verdict(&self, offset: u64) -> Option<bool> {
        let k = self
            .bounds
            .partition_point(|&b| b <= offset)
            .checked_sub(1)?;
        *self.verdict.get(k)?
    }
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
    // ±32 bytes around the 8-byte candidate, in u16 cells aligned to it.
    let start = offset.saturating_sub(32);
    let start = start + ((start ^ offset) & 1);
    let end = offset.saturating_add(40).min(data.len());

    let window = data.get(start..end).unwrap_or_default();
    let (mut nonzero, mut small_nonzero) = (0usize, 0usize);
    for &cell in window.as_chunks::<2>().0 {
        let v = u16::from_le_bytes(cell);
        nonzero += usize::from(v != 0);
        small_nonzero += usize::from(v != 0 && v < 0x0200);
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

    let matches = window
        .windows(3)
        .filter(|w| w[0] != 0 && w[0] == w[2])
        .count();
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
    elf_machine: u16,
    elf_opt: Option<&crate::goblin::elf::Elf<'_>>,
    pe_opt: Option<&crate::goblin::pe::PE<'_>>,
) -> Vec<ExtractedString> {
    // Skip M68000 binaries - their instruction stream naturally contains 0x0002 patterns
    if elf_machine == EM_68K {
        tracing::debug!("skipping sockaddr scan: M68000 code");
        return Vec::new();
    }

    // Go and .NET binaries don't use C-style sockaddr_in structures: Go has
    // its own network abstractions, and scanning its runtime metadata finds
    // false positives; .NET has managed networking APIs, and native images
    // (.ni.dll) hold compiled IL/JIT code that finds many. Only structure
    // decides: a "Go build ID:" string is bytes any sample can carry to
    // switch the scan off.
    let is_go = elf_opt.is_some_and(crate::binary::elf_has_go_sections)
        || pe_opt.is_some_and(|pe| {
            pe.sections.iter().any(|section| {
                let name = crate::binary::pe_section_name(&section.name).to_lowercase();
                name.contains("gopclntab") || name.contains("go.buildinfo")
            })
        });
    let is_dotnet = pe_opt
        .and_then(|pe| pe.header.optional_header)
        .and_then(|h| h.data_directories.get_clr_runtime_header().copied())
        .is_some_and(|clr| clr.virtual_address != 0 && clr.size != 0);
    if is_go || is_dotnet {
        tracing::debug!(
            is_go,
            is_dotnet,
            "skipping sockaddr scan: Go or .NET binary"
        );
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

    // Real hard-coded C2 addresses live in data sections (.data, .rodata, …),
    // not in code. An offset no section covers is rejected.
    let sections = if let Some(elf) = elf_opt {
        Some(SectionMap::new(elf.section_headers.iter().filter_map(
            |sh| {
                // `.bss` and other NOBITS sections occupy no file bytes;
                // their header range would claim whatever follows them.
                if sh.sh_type == goblin::elf::section_header::SHT_NOBITS {
                    return None;
                }
                let name = elf.shdr_strtab.get_at(sh.sh_name)?;
                Some((
                    sh.sh_offset..sh.sh_offset.saturating_add(sh.sh_size),
                    matches!(
                        name,
                        ".data" | ".data.rel.ro" | ".rodata" | ".fini_array" | ".init_array"
                    ) || name.starts_with(".rodata."),
                ))
            },
        )))
    } else {
        pe_opt.map(|pe| {
            SectionMap::new(pe.sections.iter().map(|section| {
                let start = u64::from(section.pointer_to_raw_data);
                let name = crate::binary::pe_section_name(&section.name);
                (
                    start..start + u64::from(section.size_of_raw_data),
                    matches!(
                        &*name,
                        ".data" | ".rdata" | ".bss" | ".idata" | ".edata" | ".rsrc"
                    ),
                )
            }))
        })
    };

    // Only sockaddr_in structures are scanned: the AF_INET marker gives the
    // context that four bytes really are an address.
    let mut results: Vec<ExtractedString> = scan_sockaddr_in(data, min_length, endianness)
        .filter(|s| {
            // Drop PE candidates inside compiler-emitted u16 tables (UNWIND_INFO,
            // C++ EH metadata, jump tables) that mimic sockaddr_in bytes.
            if pe_opt.is_some()
                && let Ok(off) = usize::try_from(s.data_offset)
                && (looks_like_packed_u16_table(data, off) || sits_in_periodic_table(data, off))
            {
                return false;
            }
            sections
                .as_ref()
                .is_none_or(|map| map.verdict(s.data_offset) == Some(true))
        })
        .take(MAX_CANDIDATES)
        .collect();

    // Past a handful, keep the best-evidenced: a `sin_zero` that is all
    // zero, then file order. Dropping every candidate instead would let a
    // sample hide its real address behind a few decoys.
    if results.len() > MAX_ADDRESSES {
        tracing::debug!(
            candidates = results.len(),
            kept = MAX_ADDRESSES,
            "sockaddr: more candidates than a sample hard-codes; keeping the best padded"
        );
        let padding = |s: &ExtractedString| {
            usize::try_from(s.data_offset)
                .ok()
                .and_then(|at| data.get(at + 8..at + 16))
                .map_or(0, |zero| zero.iter().filter(|&&b| b == 0).count())
        };
        results.sort_by_key(|s| (std::cmp::Reverse(padding(s)), s.data_offset));
        results.truncate(MAX_ADDRESSES);
        results.sort_by_key(|s| s.data_offset);
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

    // A last octet of 250 or more is broadcast-like, and a 255 anywhere is a
    // mask or broadcast pattern.
    if octets[3] >= 250 || octets.contains(&255) {
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
) -> impl Iterator<Item = ExtractedString> + '_ {
    // Skip file headers (ELF, PE, Mach-O) which often contain similar byte patterns
    // Use 1024 byte skip to cover headers and metadata sections that often contain
    // false positive patterns. Real sockaddr_in structs are in data sections further in.
    let start = if data.len() > 1024 { 1024 } else { 0 };

    let accept_le = matches!(endianness, Endianness::Little | Endianness::Unknown);
    let accept_be = matches!(endianness, Endianness::Big | Endianness::Unknown);

    (start..data.len().saturating_sub(7)).filter_map(move |i| {
        // Check for AF_INET marker (value 2) in the binary's native order.
        // Accepting the wrong byte order produces false positives because
        // unrelated structures (COM GUIDs in PE .rdata, small-int tables) often
        // contain `00 02` or `02 00` runs.
        let af_inet_le = accept_le && data[i] == 0x02 && data[i + 1] == 0x00;
        let af_inet_be = accept_be && data[i] == 0x00 && data[i + 1] == 0x02;

        if !af_inet_le && !af_inet_be {
            return None;
        }

        let port = u16::from_be_bytes([data[i + 2], data[i + 3]]);

        // Skip port 0 (invalid)
        if port == 0 {
            return None;
        }

        // Skip very high ports (>= 61000) - unlikely to be real C2, often artifacts
        if port >= 61000 {
            return None;
        }

        let octets = [data[i + 4], data[i + 5], data[i + 6], data[i + 7]];

        // Skip if IP is invalid
        if !is_valid_ip(octets) {
            return None;
        }

        // Skip if IP octets look like text (3+ ASCII printable characters)
        let ascii_count = octets.iter().filter(|&&b| (32..=126).contains(&b)).count();
        if ascii_count >= 3 {
            return None;
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
        let sin_zero = data.get(i + 8..i + 16)?;
        if sin_zero.iter().filter(|&&b| b == 0).count() < 6 {
            return None;
        }

        let ip_str = format!(
            "{}.{}.{}.{}:{}",
            octets[0], octets[1], octets[2], octets[3], port
        );

        // Respect min_length parameter
        if ip_str.len() < min_length {
            return None;
        }

        Some(ExtractedString {
            value: ip_str,
            data_offset: i as u64,
            method: StringMethod::RawScan,
            kind: Some(StringKind::IpPort),
            ..Default::default()
        })
    })
}

#[cfg(test)]
mod tests;
