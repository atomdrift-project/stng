//! Language and text file detection.

use crate::binary::{is_go_binary, is_rust_binary};

/// The language `data` was written in, as far as strings are concerned:
/// `"go"`, `"rust"`, `"text"` for text files, or `"unknown"`.
#[must_use]
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
#[must_use]
pub fn is_text_file(data: &[u8]) -> bool {
    if data.is_empty() || has_executable_magic(data) {
        return false;
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

/// Whether `data` begins with an executable's magic: ELF, Mach-O (thin or
/// fat, either endianness; a JVM class shares the fat magic), or PE's `MZ`.
fn has_executable_magic(data: &[u8]) -> bool {
    const MAGICS: [[u8; 4]; 7] = [
        [0x7f, b'E', b'L', b'F'],
        [0xfe, 0xed, 0xfa, 0xce],
        [0xce, 0xfa, 0xed, 0xfe],
        [0xfe, 0xed, 0xfa, 0xcf],
        [0xcf, 0xfa, 0xed, 0xfe],
        [0xca, 0xfe, 0xba, 0xbe],
        [0xbe, 0xba, 0xfe, 0xca],
    ];
    data.starts_with(b"MZ") || MAGICS.iter().any(|magic| data.starts_with(magic))
}

/// Whether `data` is binary rather than text, judged over all of it: an
/// executable's magic, more than two NUL bytes, or control characters in at
/// least a tenth of the bytes.
///
/// Unlike [`is_text_file`], which samples a prefix, a script with a binary
/// payload appended is binary here. Bytes above 0x7F count as text (UTF-8, or
/// a legacy code page), so a CJK document or a CP-1252 batch file is not
/// mistaken for binary. Among stng's fixtures the two never come close: text
/// stays under 3% control bytes with no NULs, and every binary that carries
/// XOR-obfuscated strings is over 25%, with tens of thousands of NULs.
pub(crate) fn is_binary(data: &[u8]) -> bool {
    if has_executable_magic(data) {
        return true;
    }
    let is_control =
        |b: u8| (b < 0x20 && !matches!(b, b'\t' | b'\n' | b'\r' | 0x0c | 0x1b)) || b == 0x7f;
    let (mut nuls, mut controls) = (0usize, 0usize);
    for chunk in data.chunks(4096) {
        nuls += chunk.iter().filter(|&&b| b == 0).count();
        if nuls > 2 {
            return true;
        }
        controls += chunk.iter().filter(|&&b| is_control(b)).count();
    }
    !data.is_empty() && controls * 10 >= data.len()
}
