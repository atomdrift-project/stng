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

use crate::bytes::{u16_le, u32_le};
use crate::{ExtractedString, StringMethod};
use goblin::pe::PE;
use std::collections::HashSet;

/// Magic signature for .NET metadata root ("BSJB")
const METADATA_SIGNATURE: &[u8] = b"BSJB";

/// Extract strings from the .NET User String (#US) heap: none for a native
/// PE, or one whose metadata does not parse.
pub(crate) fn extract_us_heap_strings(
    pe: &PE<'_>,
    data: &[u8],
    min_length: usize,
) -> Vec<ExtractedString> {
    us_heap(pe, data)
        .map(|(heap, offset)| parse_us_heap(heap, offset, min_length))
        .unwrap_or_default()
}

/// The #US heap of a .NET assembly, and its file offset.
fn us_heap<'d>(pe: &PE<'_>, data: &'d [u8]) -> Option<(&'d [u8], u64)> {
    let clr = *pe
        .header
        .optional_header?
        .data_directories
        .get_clr_runtime_header()?;
    // A CLR header is 72 bytes.
    if clr.size < 72 {
        return None;
    }
    let clr_offset = rva_to_offset(pe, clr.virtual_address)?;
    // CLR header: metadata RVA at offset 8, metadata size at 12.
    // https://docs.microsoft.com/en-us/dotnet/standard/metadata-and-self-describing-components
    let metadata_rva = u32_le(data, clr_offset.saturating_add(8))?;
    let metadata_size = usize::try_from(u32_le(data, clr_offset.saturating_add(12))?).ok()?;
    if metadata_size == 0 || metadata_size > 100 * 1024 * 1024 {
        tracing::debug!(metadata_size, ".NET metadata size out of range");
        return None;
    }
    let metadata_offset = rva_to_offset(pe, metadata_rva)?;
    let metadata = data.get(metadata_offset..metadata_offset.checked_add(metadata_size)?)?;
    let us = find_us_stream(metadata)?;
    let offset = u64::try_from(metadata_offset + us.start).ok()?;
    Some((&metadata[us], offset))
}

/// The file offset of `rva`, through the section that maps it.
fn rva_to_offset(pe: &PE<'_>, rva: u32) -> Option<usize> {
    let section = pe.sections.iter().find(|s| {
        rva.checked_sub(s.virtual_address)
            .is_some_and(|delta| delta < s.virtual_size.max(s.size_of_raw_data))
    })?;
    usize::try_from(
        u64::from(section.pointer_to_raw_data) + u64::from(rva - section.virtual_address),
    )
    .ok()
}

/// Find the #US (User Strings) stream in the metadata.
/// Its byte range within `metadata`.
fn find_us_stream(metadata: &[u8]) -> Option<std::ops::Range<usize>> {
    if metadata.len() < 16 || &metadata[0..4] != METADATA_SIGNATURE {
        return None;
    }

    // Metadata root structure:
    // 0-4: Signature ("BSJB")
    // 4-6: Major version
    // 6-8: Minor version
    // 8-12: Reserved
    // 12-16: Version string length (rounded up to 4-byte boundary)

    let version_len = u32_le(metadata, 12)? as usize;

    // Version length must be reasonable
    if version_len > 256 || 16 + version_len > metadata.len() {
        return None;
    }

    // Round version_len up to 4-byte boundary
    let version_len_padded = (version_len + 3) & !3;

    // After version string: 2 bytes flags, 2 bytes stream count
    let streams_offset = 16 + version_len_padded;
    let stream_count = u16_le(metadata, streams_offset + 2)? as usize;

    if stream_count > 10 {
        return None; // Too many streams, likely corrupt
    }

    // Parse stream headers
    let mut pos = streams_offset + 4;

    for _ in 0..stream_count {
        // Stream header: offset (4), size (4), then a NUL-terminated name
        // padded to 4 bytes.
        let stream_offset = u32_le(metadata, pos)? as usize;
        let stream_size = u32_le(metadata, pos + 4)? as usize;
        let name_start = pos + 8;
        let name_end = name_start + memchr::memchr(0, metadata.get(name_start..)?)?;
        pos = (name_end + 1 + 3) & !3;

        if &metadata[name_start..name_end] == b"#US"
            && let Some(end) = stream_offset
                .checked_add(stream_size)
                .filter(|&end| end <= metadata.len())
        {
            return Some(stream_offset..end);
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

                let code_units: Vec<u16> = utf16_data
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|&chunk| u16::from_le_bytes(chunk))
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
                        method: StringMethod::Structure,
                        kind,
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
    fn reads_1byte_compressed_uint() {
        // 1-byte values: 0x00-0x7F
        assert_eq!(read_compressed_uint(&[0x00]), Some((0, 1)));
        assert_eq!(read_compressed_uint(&[0x7F]), Some((0x7F, 1)));
        assert_eq!(read_compressed_uint(&[0x42]), Some((0x42, 1)));
    }

    #[test]
    fn reads_2byte_compressed_uint() {
        // 2-byte values: 0x80-0x3FFF
        // Format: 10xxxxxx xxxxxxxx
        assert_eq!(read_compressed_uint(&[0x80, 0x80]), Some((0x80, 2)));
        assert_eq!(read_compressed_uint(&[0xBF, 0xFF]), Some((0x3FFF, 2)));
        assert_eq!(read_compressed_uint(&[0x81, 0x00]), Some((0x100, 2)));
    }

    #[test]
    fn reads_4byte_compressed_uint() {
        // 4-byte values
        // Format: 110xxxxx xxxxxxxx xxxxxxxx xxxxxxxx
        assert_eq!(
            read_compressed_uint(&[0xC0, 0x00, 0x40, 0x00]),
            Some((0x4000, 4))
        );
    }

    #[test]
    fn rejects_empty_compressed_uint() {
        assert_eq!(read_compressed_uint(&[]), None);
    }

    #[test]
    fn rejects_truncated_compressed_uint() {
        // 2-byte marker but only 1 byte of data
        assert_eq!(read_compressed_uint(&[0x80]), None);

        // 4-byte marker but only 2 bytes of data
        assert_eq!(read_compressed_uint(&[0xC0, 0x00]), None);
    }

    #[test]
    fn finds_no_us_stream_without_metadata() {
        // Empty data
        assert_eq!(find_us_stream(&[]), None);

        // Too short
        assert_eq!(find_us_stream(&[0x42, 0x53, 0x4A, 0x42]), None);

        // Wrong signature
        assert_eq!(find_us_stream(&[0x00; 100]), None);
    }

    #[test]
    fn empty_us_heap_yields_nothing() {
        // Empty heap
        let results = parse_us_heap(&[], 0, 4);
        assert!(results.is_empty());

        // Heap with only null byte
        let results = parse_us_heap(&[0x00], 0, 4);
        assert!(results.is_empty());
    }

    #[test]
    fn parses_utf16_us_heap_entry() {
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
    }

    #[test]
    fn drops_us_strings_below_min_length() {
        // "Hi" is too short (min_length = 4)
        let mut heap = vec![0x00];
        heap.push(0x05); // Length = 5 (4 UTF-16 bytes + 1 trailing)
        heap.extend_from_slice(&[0x48, 0x00, 0x69, 0x00]); // "Hi"
        heap.push(0x00);

        let results = parse_us_heap(&heap, 0, 4);
        assert!(results.is_empty(), "Short string should be filtered out");
    }
}
