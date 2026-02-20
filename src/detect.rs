//! Language and text file detection.

use crate::binary::{is_go_binary, is_rust_binary};

pub fn detect_language(data: &[u8]) -> &'static str {
    if is_go_binary(data) {
        "go"
    } else if is_rust_binary(data) {
        "rust"
    } else if is_text_file(data) {
        "text"
    } else {
        "unknown"
    }
}

/// Check if data appears to be a text file rather than a binary.
///
/// Uses heuristics:
/// - Must be valid UTF-8 (or mostly ASCII)
/// - High ratio of printable characters
/// - No binary magic numbers at the start
pub fn is_text_file(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }

    // Check for common binary magic numbers
    if data.len() >= 4 {
        let magic = &data[0..4];
        // ELF
        if magic == [0x7f, b'E', b'L', b'F'] {
            return false;
        }
        // Mach-O (32-bit and 64-bit, both endiannesses)
        if magic == [0xfe, 0xed, 0xfa, 0xce]
            || magic == [0xce, 0xfa, 0xed, 0xfe]
            || magic == [0xfe, 0xed, 0xfa, 0xcf]
            || magic == [0xcf, 0xfa, 0xed, 0xfe]
        {
            return false;
        }
        // Fat Mach-O
        if magic == [0xca, 0xfe, 0xba, 0xbe] || magic == [0xbe, 0xba, 0xfe, 0xca] {
            return false;
        }
    }
    if data.len() >= 2 {
        // PE (MZ header)
        if data[0..2] == [b'M', b'Z'] {
            return false;
        }
    }

    // Sample up to 8KB for performance
    let sample_size = data.len().min(8192);
    let sample = &data[..sample_size];

    // Count printable vs non-printable bytes
    let mut printable = 0usize;
    let mut null_bytes = 0usize;

    for &b in sample {
        if b == 0 {
            null_bytes += 1;
        } else if b.is_ascii_graphic() || b.is_ascii_whitespace() {
            printable += 1;
        }
    }

    // Text files should have very few null bytes (allow a couple for edge cases)
    if null_bytes > 2 {
        return false;
    }

    // At least 85% should be printable ASCII for it to be considered text
    printable * 100 / sample_size >= 85
}
