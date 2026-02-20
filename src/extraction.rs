//! String extraction utilities.
//!
//! Functions for finding and extracting strings from binary data using
//! pointer+length structures.

use crate::types::{BinaryInfo, ExtractedString, StringKind, StringMethod, StringStruct};
use rayon::prelude::*;

/// Find pointer+length structures that point into a data blob.
///
/// This scans section data looking for consecutive pointer+length pairs
/// where the pointer falls within the target blob's address range.
///
/// # Arguments
///
/// * `section_data` - Raw bytes of the section to scan
/// * `section_addr` - Virtual address of the section
/// * `blob_addr` - Virtual address of the target data blob
/// * `blob_size` - Size of the target data blob in bytes
/// * `info` - Binary architecture information
///
/// # Returns
///
/// A vector of string structures found, each representing a potential string reference.
pub fn find_string_structures(
    section_data: &[u8],
    section_addr: u64,
    blob_addr: u64,
    blob_size: u64,
    info: &BinaryInfo,
) -> Vec<StringStruct> {
    // Fast path for 64-bit little-endian (most common case)
    if info.is_64bit && info.is_little_endian {
        return find_string_structures_64le(section_data, section_addr, blob_addr, blob_size);
    }

    // Generic path for other architectures
    find_string_structures_generic(section_data, section_addr, blob_addr, blob_size, info)
}

/// Specialized fast path for 64-bit little-endian (no runtime checks in loop)
#[inline]
fn find_string_structures_64le(
    section_data: &[u8],
    section_addr: u64,
    blob_addr: u64,
    blob_size: u64,
) -> Vec<StringStruct> {
    let mut structs = Vec::new();
    let blob_end = blob_addr + blob_size;

    if section_data.len() < 16 {
        return structs;
    }

    let mut i = 0;
    let end = section_data.len() - 15;

    while i < end {
        // Direct LE reads without runtime endianness checks
        // Loop ensures we have 16 bytes available (end = len - 15)
        let Some(ptr) = section_data
            .get(i..i + 8)
            .and_then(|s| s.try_into().ok())
            .map(u64::from_le_bytes)
        else {
            i += 8;
            continue;
        };
        let Some(len) = section_data
            .get(i + 8..i + 16)
            .and_then(|s| s.try_into().ok())
            .map(u64::from_le_bytes)
        else {
            i += 8;
            continue;
        };

        if ptr >= blob_addr
            && ptr < blob_end
            && len > 0
            && len < 1024 * 1024
            && ptr + len <= blob_end
        {
            structs.push(StringStruct {
                struct_offset: section_addr + i as u64,
                ptr,
                len,
            });
        }
        i += 8;
    }

    structs
}

/// Generic path for non-64-bit-LE architectures
fn find_string_structures_generic(
    section_data: &[u8],
    section_addr: u64,
    blob_addr: u64,
    blob_size: u64,
    info: &BinaryInfo,
) -> Vec<StringStruct> {
    let mut structs = Vec::new();
    let struct_size = info.ptr_size * 2;

    if section_data.len() < struct_size {
        return structs;
    }

    for i in (0..=section_data.len() - struct_size).step_by(info.ptr_size) {
        // Loop ensures we have struct_size bytes available at position i
        let (ptr, len) = if info.is_64bit {
            let Some(ptr) = section_data
                .get(i..i + 8)
                .and_then(|s| s.try_into().ok())
                .map(u64::from_be_bytes)
            else {
                continue;
            };
            let Some(len) = section_data
                .get(i + 8..i + 16)
                .and_then(|s| s.try_into().ok())
                .map(u64::from_be_bytes)
            else {
                continue;
            };
            (ptr, len)
        } else if info.is_little_endian {
            let Some(ptr) = section_data
                .get(i..i + 4)
                .and_then(|s| s.try_into().ok())
                .map(u32::from_le_bytes)
                .map(u64::from)
            else {
                continue;
            };
            let Some(len) = section_data
                .get(i + 4..i + 8)
                .and_then(|s| s.try_into().ok())
                .map(u32::from_le_bytes)
                .map(u64::from)
            else {
                continue;
            };
            (ptr, len)
        } else {
            let Some(ptr) = section_data
                .get(i..i + 4)
                .and_then(|s| s.try_into().ok())
                .map(u32::from_be_bytes)
                .map(u64::from)
            else {
                continue;
            };
            let Some(len) = section_data
                .get(i + 4..i + 8)
                .and_then(|s| s.try_into().ok())
                .map(u32::from_be_bytes)
                .map(u64::from)
            else {
                continue;
            };
            (ptr, len)
        };

        // Check if this looks like a valid string structure
        if ptr >= blob_addr
            && ptr < blob_addr + blob_size
            && len > 0
            && len < 1024 * 1024 // Max 1MB string
            && ptr + len <= blob_addr + blob_size
        {
            structs.push(StringStruct {
                struct_offset: section_addr + i as u64,
                ptr,
                len,
            });
        }
    }

    structs
}

/// Extract strings from a data blob using string structures as boundaries.
///
/// Uses the pointer and length information from string structures to precisely
/// extract string data, avoiding concatenation issues common in packed string sections.
///
/// # Arguments
///
/// * `blob` - Raw bytes of the data blob containing string data
/// * `blob_addr` - Virtual address of the blob
/// * `structs` - String structures pointing into the blob
/// * `section_name` - Optional section name for metadata
/// * `classify_fn` - Function to classify each extracted string
///
/// # Type Parameters
///
/// * `F` - Closure that takes a string slice and returns its `StringKind`
///
/// # Returns
///
/// A vector of extracted strings with metadata.
pub fn extract_from_structures<F>(
    blob: &[u8],
    blob_addr: u64,
    structs: &[StringStruct],
    section_name: Option<&str>,
    classify_fn: F,
) -> Vec<ExtractedString>
where
    F: Fn(&str) -> StringKind + Sync,
{
    structs
        .par_iter()
        .filter_map(|s| {
            if s.ptr < blob_addr {
                return None;
            }

            let offset = usize::try_from(s.ptr - blob_addr).ok()?;
            let end = offset + usize::try_from(s.len).ok()?;

            if end > blob.len() {
                return None;
            }

            let bytes = &blob[offset..end];

            // Fast ASCII printability check before UTF-8 validation
            let printable_count = bytes
                .iter()
                .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
                .count();

            if printable_count * 2 < bytes.len() {
                return None;
            }

            // Validate UTF-8
            if let Ok(string) = std::str::from_utf8(bytes) {
                let trimmed = string.trim();
                if trimmed.is_empty() {
                    return None;
                }
                Some(ExtractedString {
                    value: trimmed.to_string(),
                    data_offset: s.ptr,
                    section: section_name.map(str::to_string),
                    method: StringMethod::Structure,
                    kind: classify_fn(trimmed),
                    ..Default::default()
                })
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_string_structures_64bit_le() {
        let info = BinaryInfo::new_64bit_le();

        // Create section with one valid string structure
        // ptr = 0x1000, len = 5
        let mut section_data = vec![0u8; 32];
        section_data[0..8].copy_from_slice(&0x1000u64.to_le_bytes());
        section_data[8..16].copy_from_slice(&5u64.to_le_bytes());

        let structs = find_string_structures(
            &section_data,
            0x2000, // section_addr
            0x1000, // blob_addr
            0x100,  // blob_size
            &info,
        );

        assert_eq!(structs.len(), 1);
        assert_eq!(structs[0].ptr, 0x1000);
        assert_eq!(structs[0].len, 5);
        assert_eq!(structs[0].struct_offset, 0x2000);
    }

    #[test]
    fn test_find_string_structures_empty() {
        let info = BinaryInfo::new_64bit_le();
        let structs = find_string_structures(&[], 0x2000, 0x1000, 0x100, &info);
        assert!(structs.is_empty());
    }

    #[test]
    fn test_find_string_structures_too_short() {
        let info = BinaryInfo::new_64bit_le();
        let section_data = vec![0u8; 8]; // Only 8 bytes, need 16 for struct
        let structs = find_string_structures(&section_data, 0x2000, 0x1000, 0x100, &info);
        assert!(structs.is_empty());
    }

    #[test]
    fn test_find_string_structures_32bit() {
        let info = BinaryInfo::new_32bit_le();

        let mut section_data = vec![0u8; 16];
        section_data[0..4].copy_from_slice(&0x1000u32.to_le_bytes());
        section_data[4..8].copy_from_slice(&5u32.to_le_bytes());

        let structs = find_string_structures(&section_data, 0x2000, 0x1000, 0x100, &info);

        assert_eq!(structs.len(), 1);
        assert_eq!(structs[0].ptr, 0x1000);
        assert_eq!(structs[0].len, 5);
    }

    #[test]
    fn test_find_string_structures_big_endian() {
        let info = BinaryInfo::new_64bit_be();

        let mut section_data = vec![0u8; 32];
        section_data[0..8].copy_from_slice(&0x1000u64.to_be_bytes());
        section_data[8..16].copy_from_slice(&5u64.to_be_bytes());

        let structs = find_string_structures(&section_data, 0x2000, 0x1000, 0x100, &info);

        assert_eq!(structs.len(), 1);
        assert_eq!(structs[0].ptr, 0x1000);
        assert_eq!(structs[0].len, 5);
    }

    #[test]
    fn test_find_string_structures_32bit_be() {
        let info = BinaryInfo::new_32bit_be();

        let mut section_data = vec![0u8; 16];
        section_data[0..4].copy_from_slice(&0x1000u32.to_be_bytes());
        section_data[4..8].copy_from_slice(&5u32.to_be_bytes());

        let structs = find_string_structures(&section_data, 0x2000, 0x1000, 0x100, &info);

        assert_eq!(structs.len(), 1);
    }

    #[test]
    fn test_extract_from_structures_basic() {
        let blob = b"HelloWorld";
        let structs = vec![
            StringStruct {
                struct_offset: 0,
                ptr: 0x1000,
                len: 5,
            },
            StringStruct {
                struct_offset: 16,
                ptr: 0x1005,
                len: 5,
            },
        ];

        let strings =
            extract_from_structures(blob, 0x1000, &structs, Some("test"), |_| StringKind::Const);

        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].value, "Hello");
        assert_eq!(strings[1].value, "World");
        assert_eq!(strings[0].method, StringMethod::Structure);
    }

    #[test]
    fn test_extract_from_structures_invalid_utf8() {
        let blob = &[0xFF, 0xFE, 0xFD, 0xFC, 0xFB];
        let structs = vec![StringStruct {
            struct_offset: 0,
            ptr: 0x1000,
            len: 5,
        }];

        let strings = extract_from_structures(blob, 0x1000, &structs, None, |_| StringKind::Const);

        // Invalid UTF-8 should be skipped
        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_from_structures_mostly_non_printable() {
        let blob = b"\x01\x02\x03\x04\x05";
        let structs = vec![StringStruct {
            struct_offset: 0,
            ptr: 0x1000,
            len: 5,
        }];

        let strings = extract_from_structures(blob, 0x1000, &structs, None, |_| StringKind::Const);

        // Mostly non-printable should be skipped
        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_from_structures_ptr_out_of_range() {
        let blob = b"Hello";
        let structs = vec![StringStruct {
            struct_offset: 0,
            ptr: 0x5000, // Out of range
            len: 5,
        }];

        let strings = extract_from_structures(blob, 0x1000, &structs, None, |_| StringKind::Const);

        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_from_structures_len_overflow() {
        let blob = b"Hello";
        let structs = vec![StringStruct {
            struct_offset: 0,
            ptr: 0x1000,
            len: 100, // Longer than blob
        }];

        let strings = extract_from_structures(blob, 0x1000, &structs, None, |_| StringKind::Const);

        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_from_structures_with_section_name() {
        let blob = b"Hello";
        let structs = vec![StringStruct {
            struct_offset: 0,
            ptr: 0x1000,
            len: 5,
        }];

        let strings = extract_from_structures(blob, 0x1000, &structs, Some(".rodata"), |_| {
            StringKind::Const
        });

        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].section, Some(".rodata".to_string()));
    }

    #[test]
    fn test_extract_from_structures_classification() {
        let blob = b"/usr/bin";
        let structs = vec![StringStruct {
            struct_offset: 0,
            ptr: 0x1000,
            len: 8,
        }];

        let strings = extract_from_structures(blob, 0x1000, &structs, None, |s| {
            if s.starts_with('/') {
                StringKind::Path
            } else {
                StringKind::Const
            }
        });

        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].kind, StringKind::Path);
    }
}
