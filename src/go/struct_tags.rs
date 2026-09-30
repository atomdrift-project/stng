//! Read Go 1.18+ 64-bit Mach-O struct tags through reflection type links.
//! No byte search: only referenced types, fields, and length-prefixed names.

use crate::types::{ExtractedString, StringMethod};
use goblin::mach::MachO;
use std::collections::HashSet;

pub(super) fn extract(macho: &MachO<'_>, min_length: usize) -> Vec<ExtractedString> {
    if !macho.is_64 || !macho.little_endian {
        return Vec::new();
    }
    let mut types = None;
    let mut links = None;
    let mut modern = false;
    for seg in &macho.segments {
        let Ok(sections) = seg.sections() else {
            continue;
        };
        for (sec, data) in sections {
            match sec.name().unwrap_or("") {
                "__rodata" if seg.name().unwrap_or("") == "__DATA_CONST" => {
                    types = Some((sec.addr, data));
                }
                "__typelink" => links = Some(data),
                "__gopclntab" => {
                    modern = matches!(data.get(..4), Some([0xf0 | 0xf1, 0xff, 0xff, 0xff]));
                }
                _ => {}
            }
        }
    }
    let (Some((base, data)), Some(links)) = (types, links) else {
        return Vec::new();
    };
    if !modern || links.len() > 1024 * 1024 || data.len() > 64 * 1024 * 1024 {
        return Vec::new();
    }
    let offset = |va: u64| {
        usize::try_from(va.checked_sub(base)?)
            .ok()
            .filter(|&n| n < data.len())
    };
    let word = |at: usize| -> Option<u64> {
        Some(u64::from_le_bytes(
            data.get(at..at.checked_add(8)?)?.try_into().ok()?,
        ))
    };
    let mut seen_types = HashSet::new();
    let mut seen_tags = HashSet::new();
    let mut remaining_fields = 65536usize;
    let mut remaining_bytes = 1024 * 1024usize;
    let mut out = Vec::new();
    for link in links.as_chunks::<4>().0 {
        let relative = i32::from_le_bytes(*link);
        let Ok(mut ty) = usize::try_from(relative) else {
            continue;
        };
        // typelinks commonly lists *T. Follow one pointer, never recurse.
        if data.get(ty + 23).is_some_and(|k| k & 31 == 22) {
            let Some(elem) = word(ty + 48).and_then(offset) else {
                continue;
            };
            ty = elem;
        }
        if ty >= data.len()
            || !data.get(ty + 23).is_some_and(|k| k & 31 == 25)
            || !seen_types.insert(ty)
        {
            continue;
        }
        let Some(fields) = word(ty + 56).and_then(offset) else {
            continue;
        };
        let Some(count) = word(ty + 64).and_then(|n| usize::try_from(n).ok()) else {
            continue;
        };
        if count > 4096 || count > remaining_fields {
            break;
        }
        let Some(end) = count.checked_mul(24).and_then(|n| fields.checked_add(n)) else {
            continue;
        };
        let Some(fields) = data.get(fields..end) else {
            continue;
        };
        remaining_fields -= count;
        for field in fields.as_chunks::<24>().0 {
            let (qwords, _) = field.as_chunks::<8>();
            let va = u64::from_le_bytes(qwords[0]);
            let Some(name) = offset(va) else {
                continue;
            };
            let flags = data[name];
            if flags & 2 == 0 || flags & !15 != 0 {
                continue;
            }
            let Some((start, len)) = entry(data, name + 1) else {
                continue;
            };
            if len == 0 {
                continue;
            }
            let Some((tag, len)) = entry(data, start + len) else {
                continue;
            };
            if len < min_length || !seen_tags.insert(tag) {
                continue;
            }
            if len > remaining_bytes {
                return out;
            }
            let bytes = &data[tag..tag + len];
            let Ok(value) = std::str::from_utf8(bytes) else {
                continue;
            };
            if value.chars().any(char::is_control) {
                continue;
            }
            let Some(data_offset) = base.checked_add(tag as u64) else {
                continue;
            };
            let Ok(data_len) = u32::try_from(len) else {
                continue;
            };
            remaining_bytes -= len;
            out.push(ExtractedString {
                value: value.to_owned(),
                data_offset,
                data_len,
                method: StringMethod::Structure,
                ..Default::default()
            });
        }
    }
    out
}

/// A bounded Go Name varint and its bytes; reject truncated/oversized entries.
fn entry(data: &[u8], mut pos: usize) -> Option<(usize, usize)> {
    let mut len = 0usize;
    for shift in [0, 7] {
        let byte = *data.get(pos)?;
        pos += 1;
        len |= usize::from(byte & 127) << shift;
        if byte & 128 == 0 {
            return (len <= 4096 && pos.checked_add(len)? <= data.len()).then_some((pos, len));
        }
    }
    None
}

#[cfg(test)]
mod tests;
