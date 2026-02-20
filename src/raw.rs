//! Raw string scanning for binaries without structure information.

use crate::go;
use crate::types::{ExtractedString, StringKind, StringMethod};
use memchr::memchr_iter;
use std::collections::HashMap;
use std::collections::HashSet;

pub fn extract_raw_strings(
    data: &[u8],
    min_length: usize,
    section: Option<String>,
    segment_names: &[String],
    section_info: &HashMap<String, crate::binary::SectionInfo>,
) -> Vec<ExtractedString> {
    // Build a set of known segment/section names for quick lookup
    let segment_names_set: HashSet<&str> = segment_names.iter().map(String::as_str).collect();

    let mut strings = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    // Strategy 1: Null-terminated strings
    let mut prev_end = 0usize;
    for null_pos in memchr_iter(0, data) {
        let chunk = &data[prev_end..null_pos];
        let chunk_start = prev_end;
        prev_end = null_pos + 1;

        if chunk.len() < min_length {
            continue;
        }

        // Find the last contiguous printable run that ends at the chunk boundary
        let mut run_start = None;
        for (i, &b) in chunk.iter().enumerate() {
            if b.is_ascii_graphic() || b.is_ascii_whitespace() {
                if run_start.is_none() {
                    run_start = Some(i);
                }
            } else {
                run_start = None;
            }
        }

        let Some(start) = run_start else { continue };
        let candidate = &chunk[start..];

        if candidate.len() < min_length {
            continue;
        }

        if let Ok(s) = std::str::from_utf8(candidate) {
            let trimmed = s.trim();
            if trimmed.len() >= min_length && !trimmed.is_empty() && !seen.contains(trimmed) {
                let kind = if segment_names_set.contains(trimmed) {
                    StringKind::Section
                } else {
                    go::classify_string(trimmed)
                };

                // Get section metadata if this is a section
                let (sec_size, sec_exec, sec_write) = if kind == StringKind::Section {
                    section_info
                        .get(trimmed)
                        .map_or((None, None, None), |info| {
                            (
                                Some(info.size),
                                Some(info.is_executable),
                                Some(info.is_writable),
                            )
                        })
                } else {
                    (None, None, None)
                };

                seen.insert(trimmed.to_string());
                strings.push(ExtractedString {
                    value: trimmed.to_string(),
                    data_offset: (chunk_start + start) as u64,
                    section: section.clone(),
                    method: StringMethod::RawScan,
                    kind,
                    library: None,
                    fragments: None,
                    section_size: sec_size,
                    section_executable: sec_exec,
                    section_writable: sec_write,
                    ..Default::default()
                });
            }
        }
    }

    // Strategy 2: Printable character runs (like traditional `strings`)
    // This catches strings that aren't null-terminated (common in JPEG, PDF, etc.)
    extract_printable_runs(
        data,
        min_length,
        section.as_ref(),
        &segment_names_set,
        section_info,
        &mut strings,
        &mut seen,
    );

    strings
}

/// Extract strings by scanning for runs of printable ASCII characters.
/// This mimics the behavior of the traditional `strings` command.
pub fn extract_printable_runs(
    data: &[u8],
    min_length: usize,
    section: Option<&String>,
    segment_names_set: &HashSet<&str>,
    section_info: &HashMap<String, crate::binary::SectionInfo>,
    strings: &mut Vec<ExtractedString>,
    seen: &mut HashSet<String>,
) {
    let mut run_start: Option<usize> = None;

    for (i, &b) in data.iter().enumerate() {
        let is_printable = b.is_ascii_graphic() || matches!(b, b' ' | b'\t');

        if is_printable {
            if run_start.is_none() {
                run_start = Some(i);
            }
        } else if let Some(start) = run_start {
            // End of a printable run
            let run = &data[start..i];
            if run.len() >= min_length {
                if let Ok(s) = std::str::from_utf8(run) {
                    let trimmed = s.trim();
                    if trimmed.len() >= min_length && !seen.contains(trimmed) {
                        let kind = if segment_names_set.contains(trimmed) {
                            StringKind::Section
                        } else {
                            go::classify_string(trimmed)
                        };

                        // Get section metadata if this is a section
                        let (sec_size, sec_exec, sec_write) = if kind == StringKind::Section {
                            section_info
                                .get(trimmed)
                                .map_or((None, None, None), |info| {
                                    (
                                        Some(info.size),
                                        Some(info.is_executable),
                                        Some(info.is_writable),
                                    )
                                })
                        } else {
                            (None, None, None)
                        };

                        seen.insert(trimmed.to_string());
                        strings.push(ExtractedString {
                            value: trimmed.to_string(),
                            data_offset: start as u64,
                            section: section.cloned(),
                            method: StringMethod::RawScan,
                            kind,
                            library: None,
                            fragments: None,
                            section_size: sec_size,
                            section_executable: sec_exec,
                            section_writable: sec_write,
                            ..Default::default()
                        });
                    }
                }
            }
            run_start = None;
        }
    }

    // Handle run at end of data
    if let Some(start) = run_start {
        let run = &data[start..];
        if run.len() >= min_length {
            if let Ok(s) = std::str::from_utf8(run) {
                let trimmed = s.trim();
                if trimmed.len() >= min_length && !seen.contains(trimmed) {
                    let kind = if segment_names_set.contains(trimmed) {
                        StringKind::Section
                    } else {
                        go::classify_string(trimmed)
                    };

                    // Get section metadata if this is a section
                    let (sec_size, sec_exec, sec_write) = if kind == StringKind::Section {
                        section_info
                            .get(trimmed)
                            .map_or((None, None, None), |info| {
                                (
                                    Some(info.size),
                                    Some(info.is_executable),
                                    Some(info.is_writable),
                                )
                            })
                    } else {
                        (None, None, None)
                    };

                    seen.insert(trimmed.to_string());
                    strings.push(ExtractedString {
                        value: trimmed.to_string(),
                        data_offset: start as u64,
                        section: section.cloned(),
                        method: StringMethod::RawScan,
                        kind,
                        library: None,
                        fragments: None,
                        section_size: sec_size,
                        section_executable: sec_exec,
                        section_writable: sec_write,
                        ..Default::default()
                    });
                }
            }
        }
    }
}

/// Extract UTF-16LE wide strings from binary data.
///
/// Windows binaries commonly use UTF-16LE for strings (file paths, registry keys,
/// .NET strings, resource data). This scans for the characteristic pattern of
/// ASCII bytes alternating with null bytes.
pub fn extract_wide_strings(
    data: &[u8],
    min_length: usize,
    section: Option<String>,
    segment_names: &[String],
    section_info: &HashMap<String, crate::binary::SectionInfo>,
) -> Vec<ExtractedString> {
    let segment_names_set: HashSet<&str> = segment_names.iter().map(String::as_str).collect();
    let mut strings = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    // Need at least 4 bytes for a 2-char wide string
    if data.len() < 4 {
        return strings;
    }

    let mut i = 0;
    while i + 1 < data.len() {
        // Look for start of UTF-16LE sequence: printable ASCII followed by 0x00
        let lo = data[i];
        let hi = data[i + 1];

        if (lo.is_ascii_graphic() || matches!(lo, b' ' | b'\t' | b'\n' | b'\r')) && hi == 0 {
            // Found potential start of wide string
            let start = i;
            let mut code_units: Vec<u16> = Vec::new();

            // Collect UTF-16LE code units
            while i + 1 < data.len() {
                let lo = data[i];
                let hi = data[i + 1];
                let code_unit = u16::from_le_bytes([lo, hi]);

                // Check for null terminator
                if code_unit == 0 {
                    break;
                }

                // For BMP characters, check if it's a printable character
                // Allow ASCII printable range and common Unicode ranges
                if is_valid_wide_char(code_unit) {
                    code_units.push(code_unit);
                    i += 2;
                } else {
                    break;
                }
            }

            // Decode and validate the string
            if code_units.len() >= min_length {
                let decoded = String::from_utf16_lossy(&code_units);
                let trimmed = decoded.trim();

                if trimmed.len() >= min_length && !trimmed.is_empty() && !seen.contains(trimmed) {
                    let kind = if segment_names_set.contains(trimmed) {
                        StringKind::Section
                    } else {
                        go::classify_string(trimmed)
                    };

                    // Get section metadata if this is a section
                    let (sec_size, sec_exec, sec_write) = if kind == StringKind::Section {
                        section_info
                            .get(trimmed)
                            .map_or((None, None, None), |info| {
                                (
                                    Some(info.size),
                                    Some(info.is_executable),
                                    Some(info.is_writable),
                                )
                            })
                    } else {
                        (None, None, None)
                    };

                    seen.insert(trimmed.to_string());
                    strings.push(ExtractedString {
                        value: trimmed.to_string(),
                        data_offset: start as u64,
                        section: section.clone(),
                        method: StringMethod::WideString,
                        kind,
                        library: None,
                        fragments: None,
                        section_size: sec_size,
                        section_executable: sec_exec,
                        section_writable: sec_write,
                        ..Default::default()
                    });
                }
            }

            // Skip the null terminator if present
            if i + 1 < data.len() && data[i] == 0 && data[i + 1] == 0 {
                i += 2;
            }
        } else {
            i += 1;
        }
    }

    strings
}

/// Check if a UTF-16 code unit represents a valid printable character.
#[inline]
#[allow(clippy::match_same_arms)] // Arms are grouped by Unicode block for readability
fn is_valid_wide_char(code_unit: u16) -> bool {
    match code_unit {
        // ASCII printable range (space through tilde) plus tab, newline, carriage return
        0x0009 | 0x000A | 0x000D | 0x0020..=0x007E => true,
        // Latin-1 Supplement (common accented characters)
        0x00A0..=0x00FF => true,
        // Latin Extended-A and B (European languages)
        0x0100..=0x024F => true,
        // Greek and Coptic
        0x0370..=0x03FF => true,
        // Cyrillic
        0x0400..=0x04FF => true,
        // CJK ranges would add too much noise, skip them
        // General punctuation
        0x2000..=0x206F => true,
        // Currency symbols
        0x20A0..=0x20CF => true,
        // Arrows, math operators, etc. - skip as they add noise
        _ => false,
    }
}
