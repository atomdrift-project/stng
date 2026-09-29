//! ARM64 shuffled xorshift tables. Only verified instruction sequences qualify;
//! addresses, seeds and lengths come from those instructions, never a key search.
use super::{decode_custom_base64, decode_hex, decode_shuffled_slices, has_unique_bytes};
use crate::{ExtractedString, StringMethod};
use goblin::mach::MachO;

const SMALL: [u32; 19] = [
    0xca483108, 0xca086508, 0xca486d08, 0x1b0a7d0e, 0x4b09092f, 0xd37ff930, 0x38706971, 0x0b1101ef,
    0x51001def, 0x787069b0, 0x4a0f01ce, 0x38c003af, 0xf84003b1, 0x710001ff, 0x9a8cb22f, 0x383069ee,
    0x91000529, 0xf100013f, 0x54fffdc1,
];
const LARGE: [u32; 19] = [
    0xca483108, 0xca086508, 0xca486d08, 0x1b0a7d0f, 0x4b090930, 0xd37ff931, 0x38716960, 0x0b000210,
    0x51001e10, 0x787169d1, 0x4a1001ef, 0x39c05ff0, 0xf94003e0, 0x7100021f, 0x9a8cb010, 0x38316a0f,
    0x91000529, 0xeb0d013f, 0x54fffdc1,
];
const SHORT: [u32; 19] = [
    0xca493129, 0xca096529, 0xca496d29, 0x1b0a7d2e, 0x4b08090f, 0xd37ff910, 0x38706971, 0x0b1101ef,
    0x51001def, 0x78706990, 0x4a0f01ce, 0x39c07fef, 0xf94007f1, 0x710001ff, 0x9a8db22f, 0x383069ee,
    0x91000508, 0xf100011f, 0x54fffdc1,
];
fn word(code: &[u8], pos: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        code.get(pos..pos.checked_add(4)?)?.try_into().ok()?,
    ))
}
fn immediate(w: u32, opcode: u32) -> Option<u64> {
    (w & !0x001f_ffe0 == opcode).then_some(u64::from((w >> 5) & 0xffff))
}
fn address(code: &[u8], pc: u64, pos: usize, reg: u32) -> Option<u64> {
    let a = word(code, pos)?;
    let b = word(code, pos + 4)?;
    if a & 0x9f00_001f != 0x9000_0000 | reg || b & 0xffc0_03ff != 0x9100_0000 | reg << 5 | reg {
        return None;
    }
    let delta = i64::from(((a >> 5) & 0x7ffff) << 2 | ((a >> 29) & 3));
    (pc.checked_add(pos as u64)? & !4095)
        .checked_add_signed((delta << 43 >> 43) << 12)?
        .checked_add(u64::from((b >> 10) & 0xfff))
}

struct Table {
    source: u64,
    indexes: u64,
    count: usize,
    seed: u64,
    skip: usize,
}
fn table(code: &[u8], pc: u64, pos: usize) -> Option<Table> {
    let first = word(code, pos)?;
    let short = first == SHORT[0];
    let large = !short && word(code, pos + 12)? == LARGE[3];
    let shape = if short {
        &SHORT
    } else if large {
        &LARGE
    } else {
        &SMALL
    };
    for (i, &expected) in shape.iter().enumerate() {
        let mask = match (short, large, i) {
            (false, false, 11 | 12) => !0x001f_f000, // signed stack displacement
            (_, false, 17) => !0x003f_fc00,          // CMP immediate, no shift
            _ => u32::MAX,
        };
        if word(code, pos + i * 4)? & mask != expected {
            return None;
        }
    }
    let setup = pos.checked_sub(if large { 28 } else { 24 })?;
    if word(code, setup)? != 0x528003aa {
        return None;
    } // MOV W10,29
    let source = address(code, pc, setup + 4, 11)?;
    let (indexes, count) = if large {
        if word(code, setup + 12)? != 0x910003ec {
            return None;
        } // MOV X12,SP
        (
            address(code, pc, setup + 20, 14)?,
            immediate(word(code, setup + 16)?, 0x5280000d)? as usize,
        )
    } else if short {
        if word(code, setup + 20)? != 0x910023ed {
            return None;
        } // ADD X13,SP,8
        (
            address(code, pc, setup + 12, 12)?,
            ((word(code, pos + 68)? >> 10) & 0xfff) as usize,
        )
    } else {
        // SUB X12,X29,#object_offset; the two loads address the same C++ string.
        let object = word(code, setup + 12)?;
        if object & 0xffc0_03ff != 0xd10003ac {
            return None;
        }
        let off = ((object >> 10) & 0xfff) as i32;
        let displacement = |w: u32| ((w >> 12) as i32 & 511) << 23 >> 23;
        if displacement(word(code, pos + 48)?) != -off
            || displacement(word(code, pos + 44)?) != 23 - off
        {
            return None;
        }
        (
            address(code, pc, setup + 16, 13)?,
            ((word(code, pos + 68)? >> 10) & 0xfff) as usize,
        )
    };
    if !(2..=65536).contains(&count) || count % 2 != 0 {
        return None;
    }
    let (seed_pos, reg, skip) = if short {
        // Counter zeroing and intervening allocation metadata stores. None writes X8.
        let pre = pos.checked_sub(19 * 4)?;
        let expected = [
            0xd2800008, 0xf90007e0, 0x90000009, 0x3dc00120, 0x3c8103e0, 0x6f00e400, 0xad000000,
            0x3d800800, 0x3c82d000,
        ];
        for (i, &w) in expected.iter().enumerate() {
            let mask = match i {
                2 => 0x9f00_001f,
                3 => 0xffc0_03ff,
                _ => u32::MAX,
            };
            if word(code, pre + i * 4)? & mask != w {
                return None;
            }
        }
        (setup.checked_sub(16)?, 9, 0)
    } else {
        let warm = setup.checked_sub(20)?;
        let expected = [0xca483108, 0xca086508, 0xca486d08, 0xf1000529, 0x54ffff81];
        for (i, &w) in expected.iter().enumerate() {
            if word(code, warm + i * 4)? != w {
                return None;
            }
        }
        let mut before = warm.checked_sub(4)?;
        // Alphabet construction interposes STUR Q0,[X19,8].
        if word(code, before)? == 0x3c808260 {
            before = before.checked_sub(4)?;
        }
        let skip = immediate(word(code, before)?, 0x52800009)? as usize;
        if skip + 1 != count {
            return None;
        }
        (before.checked_sub(16)?, 8, skip)
    };
    let mut seed = 0;
    for (i, opcode) in [0xd2800000, 0xf2a00000, 0xf2c00000, 0xf2e00000]
        .iter()
        .enumerate()
    {
        seed |= immediate(word(code, seed_pos + i * 4)?, opcode | reg)? << (16 * i);
    }
    Some(Table {
        source,
        indexes,
        count,
        seed,
        skip,
    })
}

pub(super) fn extract(
    macho: &MachO<'_>,
    slice_base: u64,
    min_length: usize,
) -> Vec<ExtractedString> {
    let (mut text, mut constant, mut wide_strings) = (None, None, None);
    for segment in &macho.segments {
        let Ok(sections) = segment.sections() else {
            continue;
        };
        for (section, bytes) in sections {
            if section.segname().ok() != Some("__TEXT") {
                continue;
            }
            match section.name().ok() {
                Some("__text") => text = Some((section.addr, bytes)),
                Some("__const") => constant = Some((section.addr, section.offset, bytes)),
                Some("__ustring") => wide_strings = Some((section.addr, bytes)),
                _ => {}
            }
        }
    }
    let (Some((pc, code)), Some((base, file_offset, bytes))) = (text, constant) else {
        return Vec::new();
    };
    // Reject large unrelated binaries before inspecting a single instruction.
    let wide_size = wide_strings.map_or(0, |(_, data)| data.len());
    if code.len() > 32768
        || !(512..=512 * 1024).contains(&bytes.len())
        || wide_size > 512 * 1024 - bytes.len()
    {
        return Vec::new();
    }
    let mut decoded = Vec::new();
    let mut candidates = 0;
    for pos in (0..code.len().saturating_sub(75)).step_by(4) {
        if !matches!(word(code, pos), Some(0xca483108 | 0xca493129)) {
            continue;
        }
        let Some(t) = table(code, pc, pos) else {
            continue;
        };
        if candidates == 8 {
            break;
        }
        candidates += 1;
        let Some(source) = t.source.checked_sub(base) else {
            continue;
        };
        let Ok(source) = usize::try_from(source) else {
            continue;
        };
        let Some(source_bytes) = source
            .checked_add(t.count * 2)
            .and_then(|end| bytes.get(source..end))
        else {
            continue;
        };
        // Linkers can place the u16 permutation in __ustring. Resolve only the
        // instruction's address; do not scan either section for candidate data.
        let index_slice = |address: u64, data: &[u8]| {
            let start = usize::try_from(t.indexes.checked_sub(address)?).ok()?;
            Some(start..start.checked_add(t.count * 2)?).filter(|r| r.end <= data.len())
        };
        let index_bytes = index_slice(base, bytes)
            .map(|range| &bytes[range])
            .or_else(|| {
                let (address, data) = wide_strings?;
                index_slice(address, data).map(|range| &data[range])
            });
        let Some(index_bytes) = index_bytes else {
            continue;
        };
        // A full permutation ensures no omitted or overwritten output positions.
        let mut seen = vec![false; t.count];
        if !index_bytes.chunks_exact(2).all(|b| {
            let i = usize::from(u16::from_le_bytes([b[0], b[1]]));
            if i >= seen.len() || seen[i] {
                false
            } else {
                seen[i] = true;
                true
            }
        }) {
            continue;
        }
        let Some(hex) =
            decode_shuffled_slices(source_bytes, index_bytes, t.seed, t.skip, t.count)
        else {
            continue;
        };
        let Some(value) = decode_hex(&hex) else {
            continue;
        };
        let Some(offset) = slice_base
            .checked_add(u64::from(file_offset))
            .and_then(|o| o.checked_add(source as u64))
        else {
            continue;
        };
        decoded.push((value, offset, (t.count * 2) as u32));
    }
    let Some((alphabet, _, _)) = decoded
        .iter()
        .find(|(v, _, _)| v.len() == 64 && has_unique_bytes(v))
    else {
        return Vec::new();
    };
    decoded
        .iter()
        .filter_map(|(encoded, offset, length)| {
            if encoded.len() == 64 && encoded == alphabet {
                return None;
            }
            let value = String::from_utf8(decode_custom_base64(encoded, alphabet)?).ok()?;
            if value.len() < min_length
                || value
                    .bytes()
                    .any(|b| b < 32 && !matches!(b, b'\n' | b'\r' | b'\t'))
            {
                return None;
            }
            Some(ExtractedString {
                value,
                data_offset: *offset,
                data_len: *length,
                method: StringMethod::Base64ObfuscatedDecode,
                kind: None,
                ..Default::default()
            })
        })
        .collect()
}
