//! .NET metadata parsing for extracting User Strings (#US heap).
//!
//! .NET binaries store literal strings in the #US (User Strings) heap within
//! the CLI metadata. This module parses the metadata structure to extract
//! these strings, which are common targets for malware analysis.
//!
//! # .NET Metadata Structure
//!
//! ```text
//! PE Header
//!   -> Data Directories[14] (CLR Header)
//!     -> CLI Header (Metadata RVA/Size)
//!       -> Metadata Root (BSJB signature)
//!         -> Stream Headers (#~, #Strings, #US, #GUID, #Blob)
//!           -> #US Heap: compressed-length UTF-16LE strings
//! ```

use crate::{ExtractedString, StringMethod};
use goblin::pe::PE;
use std::collections::HashSet;

/// Magic signature for .NET metadata root ("BSJB")
const METADATA_SIGNATURE: &[u8] = b"BSJB";

/// Extract strings from the .NET User String (#US) heap.
///
/// Returns extracted strings from the #US heap if this is a .NET assembly.
/// Returns empty vector for native PE or if parsing fails.
pub fn extract_us_heap_strings(
    pe: &PE<'_>,
    data: &[u8],
    min_length: usize,
) -> Vec<ExtractedString> {
    let mut results = Vec::new();

    // Get CLR runtime header from data directory 14
    let clr_dir = match pe.header.optional_header {
        Some(ref opt) => opt.data_directories.get_clr_runtime_header(),
        None => return results,
    };

    let (clr_rva, clr_size) = match clr_dir {
        Some(dir) => (dir.virtual_address, dir.size),
        None => return results, // Not a .NET binary
    };

    if clr_size < 72 {
        return results; // CLR header too small
    }

    // Convert RVA to file offset
    let Some(clr_offset) = rva_to_offset(pe, clr_rva) else {
        return results;
    };

    // Read CLR header to get metadata RVA
    // CLR header structure: https://docs.microsoft.com/en-us/dotnet/standard/metadata-and-self-describing-components
    // Offset 8: MetaData RVA (4 bytes)
    // Offset 12: MetaData Size (4 bytes)
    if clr_offset + 16 > data.len() {
        return results;
    }

    let metadata_rva = u32::from_le_bytes([
        data[clr_offset + 8],
        data[clr_offset + 9],
        data[clr_offset + 10],
        data[clr_offset + 11],
    ]);

    let metadata_size = u32::from_le_bytes([
        data[clr_offset + 12],
        data[clr_offset + 13],
        data[clr_offset + 14],
        data[clr_offset + 15],
    ]) as usize;

    if metadata_size == 0 || metadata_size > 100 * 1024 * 1024 {
        return results; // Invalid metadata size
    }

    // Convert metadata RVA to file offset
    let Some(metadata_offset) = rva_to_offset(pe, metadata_rva) else {
        return results;
    };

    if metadata_offset + metadata_size > data.len() {
        return results;
    }

    let metadata = &data[metadata_offset..metadata_offset + metadata_size];

    // Parse metadata root to find #US stream
    if let Some((us_offset, us_size)) = find_us_stream(metadata) {
        let us_data = &metadata[us_offset..us_offset + us_size];
        let file_base_offset = (metadata_offset + us_offset) as u64;

        results.extend(parse_us_heap(us_data, file_base_offset, min_length));
    }

    results
}

/// Convert RVA to file offset using PE section mapping.
fn rva_to_offset(pe: &PE<'_>, rva: u32) -> Option<usize> {
    for section in &pe.sections {
        let section_rva = section.virtual_address;
        let section_size = section.virtual_size.max(section.size_of_raw_data);
        let section_offset = section.pointer_to_raw_data as usize;

        if rva >= section_rva && rva < section_rva.saturating_add(section_size) {
            let offset_in_section = (rva - section_rva) as usize;
            return section_offset.checked_add(offset_in_section);
        }
    }
    None
}

/// Find the #US (User Strings) stream in the metadata.
/// Returns (offset, size) relative to metadata start.
fn find_us_stream(metadata: &[u8]) -> Option<(usize, usize)> {
    // Check for BSJB signature at offset 0
    if metadata.len() < 16 || &metadata[0..4] != METADATA_SIGNATURE {
        return None;
    }

    // Metadata root structure:
    // 0-4: Signature ("BSJB")
    // 4-6: Major version
    // 6-8: Minor version
    // 8-12: Reserved
    // 12-16: Version string length (rounded up to 4-byte boundary)

    let version_len =
        u32::from_le_bytes([metadata[12], metadata[13], metadata[14], metadata[15]]) as usize;

    // Version length must be reasonable
    if version_len > 256 || 16 + version_len > metadata.len() {
        return None;
    }

    // Round version_len up to 4-byte boundary
    let version_len_padded = (version_len + 3) & !3;

    // After version string: 2 bytes flags, 2 bytes stream count
    let streams_offset = 16 + version_len_padded;
    if streams_offset + 4 > metadata.len() {
        return None;
    }

    // Skip flags (2 bytes)
    let stream_count =
        u16::from_le_bytes([metadata[streams_offset + 2], metadata[streams_offset + 3]]) as usize;

    if stream_count > 10 {
        return None; // Too many streams, likely corrupt
    }

    // Parse stream headers
    let mut pos = streams_offset + 4;

    for _ in 0..stream_count {
        if pos + 8 > metadata.len() {
            return None;
        }

        // Stream header: offset (4), size (4), name (null-terminated, 4-byte aligned)
        let stream_offset = u32::from_le_bytes([
            metadata[pos],
            metadata[pos + 1],
            metadata[pos + 2],
            metadata[pos + 3],
        ]) as usize;

        let stream_size = u32::from_le_bytes([
            metadata[pos + 4],
            metadata[pos + 5],
            metadata[pos + 6],
            metadata[pos + 7],
        ]) as usize;

        pos += 8;

        // Read stream name (null-terminated, 4-byte aligned)
        let name_start = pos;
        while pos < metadata.len() && metadata[pos] != 0 {
            pos += 1;
        }

        if pos >= metadata.len() {
            return None;
        }

        let name = std::str::from_utf8(&metadata[name_start..pos]).unwrap_or("");

        // Skip null terminator and align to 4 bytes
        pos += 1;
        pos = (pos + 3) & !3;

        // Check if this is the #US stream
        if name == "#US" && stream_offset + stream_size <= metadata.len() {
            return Some((stream_offset, stream_size));
        }
    }

    None
}

/// Parse the #US heap and extract strings.
///
/// The #US heap contains UTF-16LE encoded strings with a compressed length prefix.
/// Each entry starts with a compressed unsigned integer (1-4 bytes) specifying
/// the byte count, followed by the UTF-16LE data and a trailing byte.
fn parse_us_heap(heap: &[u8], file_base_offset: u64, min_length: usize) -> Vec<ExtractedString> {
    let mut results = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut pos = 0;

    // First byte of #US is always 0 (null string)
    if !heap.is_empty() && heap[0] == 0 {
        pos = 1;
    }

    while pos < heap.len() {
        // Read compressed length
        let Some((byte_len, len_bytes)) = read_compressed_uint(&heap[pos..]) else {
            break;
        };

        if byte_len == 0 {
            pos += len_bytes;
            continue;
        }

        let string_start = pos + len_bytes;
        let string_end = string_start + byte_len;

        if string_end > heap.len() {
            break;
        }

        // The byte_len includes the trailing byte, so actual UTF-16 data is byte_len - 1
        // But we need at least 2 bytes for one character
        if byte_len >= 2 {
            let utf16_len = byte_len - 1; // Exclude trailing byte

            // UTF-16LE: each character is 2 bytes
            if utf16_len >= 2 && utf16_len % 2 == 0 {
                let utf16_data = &heap[string_start..string_start + utf16_len];

                // Convert to u16 code units
                let code_units: Vec<u16> = utf16_data
                    .chunks_exact(2)
                    .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                    .collect();

                // Decode to string
                let decoded = String::from_utf16_lossy(&code_units);

                // Check minimum length and uniqueness
                if decoded.chars().count() >= min_length && !seen.contains(&decoded) {
                    seen.insert(decoded.clone());

                    let kind = crate::classifier::classify_string(&decoded);

                    results.push(ExtractedString {
                        value: decoded,
                        data_offset: file_base_offset + string_start as u64,
                        section: Some("#US".to_string()),
                        method: StringMethod::Structure,
                        kind,
                        source: Some("dotnet:#US".to_string()),
                        ..Default::default()
                    });
                }
            }
        }

        pos = string_end;
    }

    results
}

/// Read a compressed unsigned integer from the stream.
///
/// .NET uses a variable-length encoding:
/// - If high bit of first byte is 0: 1-byte value (0x00-0x7F)
/// - If high 2 bits are 10: 2-byte value (0x80-0x3FFF)
/// - If high 3 bits are 110: 4-byte value (0x00-0x1FFFFFFF)
///
/// Returns (value, bytes_consumed) or None if invalid.
fn read_compressed_uint(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }

    let first = data[0];

    if first & 0x80 == 0 {
        // 1-byte: 0xxxxxxx
        Some((first as usize, 1))
    } else if first & 0xC0 == 0x80 {
        // 2-byte: 10xxxxxx xxxxxxxx
        if data.len() < 2 {
            return None;
        }
        let value = (((first & 0x3F) as usize) << 8) | (data[1] as usize);
        Some((value, 2))
    } else if first & 0xE0 == 0xC0 {
        // 4-byte: 110xxxxx xxxxxxxx xxxxxxxx xxxxxxxx
        if data.len() < 4 {
            return None;
        }
        let value = (((first & 0x1F) as usize) << 24)
            | ((data[1] as usize) << 16)
            | ((data[2] as usize) << 8)
            | (data[3] as usize);
        Some((value, 4))
    } else {
        // Invalid encoding
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_compressed_uint_1byte() {
        // 1-byte values: 0x00-0x7F
        assert_eq!(read_compressed_uint(&[0x00]), Some((0, 1)));
        assert_eq!(read_compressed_uint(&[0x7F]), Some((0x7F, 1)));
        assert_eq!(read_compressed_uint(&[0x42]), Some((0x42, 1)));
    }

    #[test]
    fn test_read_compressed_uint_2byte() {
        // 2-byte values: 0x80-0x3FFF
        // Format: 10xxxxxx xxxxxxxx
        assert_eq!(read_compressed_uint(&[0x80, 0x80]), Some((0x80, 2)));
        assert_eq!(read_compressed_uint(&[0xBF, 0xFF]), Some((0x3FFF, 2)));
        assert_eq!(read_compressed_uint(&[0x81, 0x00]), Some((0x100, 2)));
    }

    #[test]
    fn test_read_compressed_uint_4byte() {
        // 4-byte values
        // Format: 110xxxxx xxxxxxxx xxxxxxxx xxxxxxxx
        assert_eq!(
            read_compressed_uint(&[0xC0, 0x00, 0x40, 0x00]),
            Some((0x4000, 4))
        );
    }

    #[test]
    fn test_read_compressed_uint_empty() {
        assert_eq!(read_compressed_uint(&[]), None);
    }

    #[test]
    fn test_read_compressed_uint_truncated() {
        // 2-byte marker but only 1 byte of data
        assert_eq!(read_compressed_uint(&[0x80]), None);

        // 4-byte marker but only 2 bytes of data
        assert_eq!(read_compressed_uint(&[0xC0, 0x00]), None);
    }

    #[test]
    fn test_find_us_stream_invalid() {
        // Empty data
        assert_eq!(find_us_stream(&[]), None);

        // Too short
        assert_eq!(find_us_stream(&[0x42, 0x53, 0x4A, 0x42]), None);

        // Wrong signature
        assert_eq!(find_us_stream(&[0x00; 100]), None);
    }

    #[test]
    fn test_parse_us_heap_empty() {
        // Empty heap
        let results = parse_us_heap(&[], 0, 4);
        assert!(results.is_empty());

        // Heap with only null byte
        let results = parse_us_heap(&[0x00], 0, 4);
        assert!(results.is_empty());
    }

    #[test]
    fn test_parse_us_heap_simple_string() {
        // Construct a simple #US heap entry
        // Format: [null byte] [length] [UTF-16LE data] [trailing byte]

        // "Test" in UTF-16LE: T=0x54, e=0x65, s=0x73, t=0x74
        // With null high bytes: 54 00 65 00 73 00 74 00
        // Length = 8 bytes + 1 trailing byte = 9
        // Compressed length for 9 = 0x09

        let mut heap = vec![0x00]; // Initial null byte
        heap.push(0x09); // Length = 9 (8 UTF-16 bytes + 1 trailing)
        heap.extend_from_slice(&[0x54, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00]); // "Test"
        heap.push(0x00); // Trailing byte

        let results = parse_us_heap(&heap, 0, 4);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].value, "Test");
        assert_eq!(results[0].source, Some("dotnet:#US".to_string()));
    }

    #[test]
    fn test_parse_us_heap_min_length() {
        // "Hi" is too short (min_length = 4)
        let mut heap = vec![0x00];
        heap.push(0x05); // Length = 5 (4 UTF-16 bytes + 1 trailing)
        heap.extend_from_slice(&[0x48, 0x00, 0x69, 0x00]); // "Hi"
        heap.push(0x00);

        let results = parse_us_heap(&heap, 0, 4);
        assert!(results.is_empty(), "Short string should be filtered out");
    }
}
