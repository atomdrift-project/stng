//! Java class files: the constant pool's UTF-8 entries.

use super::deduplicate_by_offset;
use super::passes_garbage_filter;
use super::xor::apply_xor_scan;
use crate::raw::extract_raw_strings;
use crate::{ExtractOptions, ExtractedString, StringMethod, classifier, decode_encoded_strings};

/// Extract the JVM constant-pool UTF-8 entries directly. Besides being one
/// linear pass, this preserves exact string boundaries: a raw byte scan can
/// accidentally prepend a printable low byte from the preceding `u2 length`.
pub(crate) fn extract_java_class_strings(
    data: &[u8],
    opts: &ExtractOptions,
) -> Vec<ExtractedString> {
    let Some(&[count_hi, count_lo]) = data.get(8..10) else {
        return Vec::new();
    };
    let count = u16::from_be_bytes([count_hi, count_lo]) as usize;
    let mut strings = Vec::new();
    let mut pos = 10usize;
    let mut index = 1usize;

    while index < count {
        let Some(&tag) = data.get(pos) else {
            break;
        };
        pos += 1;
        let size = match tag {
            1 => {
                let Some(&[hi, lo]) = data.get(pos..pos + 2) else {
                    break;
                };
                pos += 2;
                let len = u16::from_be_bytes([hi, lo]);
                let len_usize = usize::from(len);
                let Some(bytes) = data.get(pos..pos.saturating_add(len_usize)) else {
                    break;
                };
                let value = String::from_utf8_lossy(bytes).into_owned();
                if value.len() >= opts.min_length {
                    strings.push(ExtractedString {
                        kind: classifier::classify_string(&value),
                        value,
                        data_offset: pos as u64,
                        data_len: u32::from(len),
                        method: StringMethod::RawScan,
                        fragments: None,
                    });
                }
                len_usize
            }
            3 | 4 | 9 | 10 | 11 | 12 | 17 | 18 => 4,
            5 | 6 => {
                index += 1;
                8
            }
            7 | 8 | 16 | 19 | 20 => 2,
            15 => 3,
            _ => break,
        };
        let Some(next) = pos.checked_add(size).filter(|&next| next <= data.len()) else {
            break;
        };
        pos = next;
        index += 1;
    }

    // Everything past the pool is scanned raw. The magic is shared with fat
    // Mach-O, so the header alone cannot prove this is a class: a fat binary
    // with more than 16 slices (XNU runs one) reads as a class with an empty
    // pool, and without this its every string would vanish. The same goes for
    // a payload appended to a genuine class.
    let mut rest = extract_raw_strings(&data[pos..], opts.min_length, &[], &[]);
    for string in &mut rest {
        string.data_offset = string.data_offset.saturating_add(pos as u64);
    }
    strings.extend(rest);

    if *opts.xor() != crate::XorMode::Off {
        apply_xor_scan(&mut strings, data, opts, false, &[]);
    }
    let decoded = decode_encoded_strings(&strings);
    strings.extend(decoded);
    if opts.filter_garbage {
        strings.retain(|s| passes_garbage_filter(s, &[]));
    }
    deduplicate_by_offset(strings)
}
