//! Raw string scanning for binaries without structure information.

use crate::classifier;
use crate::types::{ExtractedString, StringKind, StringMethod};
use memchr::memchr_iter;
use std::collections::HashMap;
use std::collections::HashSet;
use std::ops::Range;

/// Returns true if `offset` falls inside any skip range.
///
/// Used to suppress raw scanning over regions whose strings are extracted by a
/// higher-fidelity method (Go's structure-based + inline-pattern extractors
/// cover .rodata; raw scanning that region produces merged garbage because
/// Go packs strings back-to-back without null terminators).
#[inline]
fn in_skip_range(offset: usize, skip_ranges: &[Range<usize>]) -> bool {
    skip_ranges.iter().any(|r| r.contains(&offset))
}

pub(crate) fn extract_raw_strings(
    data: &[u8],
    min_length: usize,
    section: Option<&str>,
    segment_names: &[String],
    section_info: &HashMap<String, crate::binary::SectionInfo>,
    skip_ranges: &[Range<usize>],
) -> Vec<ExtractedString> {
    // Build a set of known segment/section names for quick lookup
    let segment_names_set: HashSet<&str> = segment_names.iter().map(String::as_str).collect();

    let mut strings = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    // Strategy 1: Null-terminated strings
    let mut prev_end = 0usize;
    let mut strat1_runs = Vec::new();
    for null_pos in memchr_iter(0, data) {
        let chunk = &data[prev_end..null_pos];
        let chunk_start = prev_end;
        prev_end = null_pos + 1;

        if chunk.len() < min_length {
            continue;
        }

        // Find the last contiguous printable run that ends at the chunk boundary
        // Scan backwards from the end to stop early.
        let mut run_len = 0;
        for &b in chunk.iter().rev() {
            if b.is_ascii_graphic() || b.is_ascii_whitespace() {
                run_len += 1;
            } else {
                break;
            }
        }

        if run_len >= min_length {
            let start = chunk.len() - run_len;
            let abs_start = chunk_start + start;
            if in_skip_range(abs_start, skip_ranges) {
                continue;
            }
            strat1_runs.push((abs_start, &chunk[start..]));
        }
    }

    use rayon::prelude::*;
    let strat1_extracted: Vec<ExtractedString> = strat1_runs
        .into_par_iter()
        .filter_map(|(start, candidate)| {
            if let Ok(s) = std::str::from_utf8(candidate) {
                let trimmed = s.trim();
                if trimmed.len() >= min_length {
                    let kind = if segment_names_set.contains(trimmed) {
                        Some(StringKind::Section)
                    } else {
                        classifier::classify_string(trimmed)
                    };

                    // Get section metadata if this is a section
                    let (sec_size, sec_exec, sec_write) = if kind == Some(StringKind::Section) {
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

                    return Some(ExtractedString {
                        value: trimmed.to_string(),
                        data_offset: start as u64,
                        section: section.map(str::to_string),
                        method: StringMethod::RawScan,
                        kind,
                        fragments: None,
                        section_size: sec_size,
                        section_executable: sec_exec,
                        section_writable: sec_write,
                        ..Default::default()
                    });
                }
            }
            None
        })
        .collect();

    for s in strat1_extracted {
        if seen.insert(s.value.clone()) {
            strings.push(s);
        }
    }

    // Strategy 2: Printable character runs (like traditional `strings`)
    // This catches strings that aren't null-terminated (common in JPEG, PDF, etc.)
    extract_printable_runs(
        data,
        PrintableRunContext {
            min_length,
            section,
            segment_names_set: &segment_names_set,
            section_info,
            skip_ranges,
        },
        &mut strings,
        &mut seen,
    );

    strings
}

/// Extract strings by scanning for runs of printable ASCII characters.
/// This mimics the behavior of the traditional `strings` command.
#[derive(Clone, Copy)]
pub(crate) struct PrintableRunContext<'a> {
    pub(crate) min_length: usize,
    pub(crate) section: Option<&'a str>,
    pub(crate) segment_names_set: &'a HashSet<&'a str>,
    pub(crate) section_info: &'a HashMap<String, crate::binary::SectionInfo>,
    pub(crate) skip_ranges: &'a [Range<usize>],
}

pub(crate) fn extract_printable_runs(
    data: &[u8],
    context: PrintableRunContext<'_>,
    strings: &mut Vec<ExtractedString>,
    seen: &mut HashSet<String>,
) {
    let mut runs = Vec::new();
    let mut run_start: Option<usize> = None;

    for (i, &b) in data.iter().enumerate() {
        let is_printable = b.is_ascii_graphic() || matches!(b, b' ' | b'\t');

        if is_printable {
            if run_start.is_none() {
                run_start = Some(i);
            }
        } else if let Some(start) = run_start {
            if i - start >= context.min_length && !in_skip_range(start, context.skip_ranges) {
                runs.push((start, &data[start..i]));
            }
            run_start = None;
        }
    }

    if let Some(start) = run_start
        && data.len() - start >= context.min_length
        && !in_skip_range(start, context.skip_ranges)
    {
        runs.push((start, &data[start..]));
    }

    use rayon::prelude::*;
    let extracted: Vec<ExtractedString> = runs
        .into_par_iter()
        .filter_map(|(start, run)| {
            if let Ok(s) = std::str::from_utf8(run) {
                let trimmed = s.trim();
                if trimmed.len() >= context.min_length {
                    let mut kind = if context.segment_names_set.contains(trimmed) {
                        Some(StringKind::Section)
                    } else {
                        classifier::classify_string(trimmed)
                    };

                    // Shebangs at offset 0 are the file's interpreter declaration,
                    // not embedded shell commands.
                    if start == 0 && kind == Some(StringKind::ShellCmd) && trimmed.starts_with("#!")
                    {
                        kind = None;
                    }

                    // Get section metadata if this is a section
                    let (sec_size, sec_exec, sec_write) = if kind == Some(StringKind::Section) {
                        context
                            .section_info
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

                    return Some(ExtractedString {
                        value: trimmed.to_string(),
                        data_offset: start as u64,
                        section: context.section.map(str::to_string),
                        method: StringMethod::RawScan,
                        kind,
                        fragments: None,
                        section_size: sec_size,
                        section_executable: sec_exec,
                        section_writable: sec_write,
                        ..Default::default()
                    });
                }
            }
            None
        })
        .collect();

    for s in extracted {
        if seen.insert(s.value.clone()) {
            strings.push(s);
        }
    }
}

/// Extract UTF-16LE wide strings from binary data.
///
/// Windows binaries commonly use UTF-16LE for strings (file paths, registry keys,
/// .NET strings, resource data). This scans for the characteristic pattern of
/// ASCII bytes alternating with null bytes.
pub(crate) fn extract_wide_strings(
    data: &[u8],
    min_length: usize,
    section: Option<&str>,
    segment_names: &[String],
    section_info: &HashMap<String, crate::binary::SectionInfo>,
    skip_ranges: &[Range<usize>],
) -> Vec<ExtractedString> {
    let segment_names_set: HashSet<&str> = segment_names.iter().map(String::as_str).collect();
    let mut strings = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    // Need at least 4 bytes for a 2-char wide string
    if data.len() < 4 {
        return strings;
    }

    // Reusable buffer to avoid per-string allocation
    let mut code_units: Vec<u16> = Vec::with_capacity(256);

    // Use memchr to jump to zero bytes — UTF-16LE ASCII is [char, 0x00],
    // so every valid wide char has a zero at an odd offset.  Scanning for
    // zeros and checking the preceding byte is much faster than inspecting
    // every byte pair sequentially.
    let mut i = 0;
    for zero_pos in memchr_iter(0, data) {
        // We need the zero at an odd offset (hi byte of a UTF-16LE pair)
        if zero_pos == 0 || zero_pos % 2 == 0 {
            continue;
        }
        // Skip positions we've already consumed
        if zero_pos < i + 1 {
            continue;
        }

        let lo = data[zero_pos - 1];
        if !(lo.is_ascii_graphic() || matches!(lo, b' ' | b'\t' | b'\n' | b'\r')) {
            continue;
        }

        // Walk backward to find the true start of this wide string run,
        // but never before the last consumed position.
        let mut start = zero_pos - 1;
        let floor = if i > 0 { i } else { 0 };
        while start >= floor + 2 {
            let prev_lo = data[start - 2];
            let prev_hi = data[start - 1];
            if prev_hi == 0 && is_valid_wide_char(u16::from(prev_lo)) {
                start -= 2;
            } else {
                break;
            }
        }

        if in_skip_range(start, skip_ranges) {
            continue;
        }

        // Collect UTF-16LE code units from start
        code_units.clear();
        let mut j = start;
        while j + 1 < data.len() {
            let code_unit = u16::from_le_bytes([data[j], data[j + 1]]);
            if code_unit == 0 {
                break;
            }
            if is_valid_wide_char(code_unit) {
                code_units.push(code_unit);
                j += 2;
            } else {
                break;
            }
        }
        // Advance past this run (and null terminator if present)
        i = j;
        if j + 1 < data.len() && data[j] == 0 && data[j + 1] == 0 {
            i = j + 2;
        }

        if code_units.len() < min_length {
            continue;
        }

        let decoded = String::from_utf16_lossy(&code_units);
        let trimmed = decoded.trim();

        if trimmed.len() < min_length || trimmed.is_empty() || seen.contains(trimmed) {
            continue;
        }

        let kind = if segment_names_set.contains(trimmed) {
            Some(StringKind::Section)
        } else {
            classifier::classify_string(trimmed)
        };

        let (sec_size, sec_exec, sec_write) = if kind == Some(StringKind::Section) {
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
            section: section.map(str::to_string),
            method: StringMethod::WideString,
            kind,
            fragments: None,
            section_size: sec_size,
            section_executable: sec_exec,
            section_writable: sec_write,
            ..Default::default()
        });
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
