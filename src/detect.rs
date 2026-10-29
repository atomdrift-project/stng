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

/// Whether `data` is text: non-empty, no executable magic, at most two NUL
/// bytes, and control characters in under a tenth of it. Bytes above 0x7F
/// count as text, so UTF-8 and legacy code pages (GBK, CP-1252) both qualify.
#[must_use]
pub fn is_text_file(data: &[u8]) -> bool {
    !data.is_empty() && !is_binary(data)
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
/// The whole input counts, so a script with a binary payload appended is
/// binary. Bytes above 0x7F count as text (UTF-8, or a legacy code page), so a
/// CJK document or a CP-1252 batch file is not mistaken for binary. Among stng's fixtures the two never come close: text
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
