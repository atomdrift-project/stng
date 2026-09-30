//! ARM64 Swift small ASCII strings assembled with move-wide instructions.
//! Only adjacent constant register pairs with the explicit 0xE0|length tag
//! qualify. No emulation, control-flow following, or speculative key search.

use crate::{ExtractedString, StringMethod, classify_string};
use goblin::mach::MachO;

const MAX_CODE: usize = 1024 * 1024;
const MAX_STRINGS: usize = 4096;
const MAX_DISTANCE: usize = 16;

#[derive(Clone, Copy, Default)]
struct Constant {
    value: u64,
    start: usize,
    epoch: usize,
}

pub(crate) fn extract_macho(
    macho: &MachO<'_>,
    slice_base: u64,
    min: usize,
) -> Vec<ExtractedString> {
    if min > 15 || macho.header.cputype != goblin::mach::constants::cputype::CPU_TYPE_ARM64 {
        return Vec::new();
    }
    let mut code = None;
    let mut swift = false;
    for seg in &macho.segments {
        if seg.name().ok() != Some("__TEXT") {
            continue;
        }
        let Ok(sections) = seg.sections() else {
            continue;
        };
        for (section, bytes) in sections {
            match section.name().ok() {
                Some("__swift5_types") if !bytes.is_empty() => swift = true,
                Some("__text") if bytes.len() <= MAX_CODE => {
                    code = Some((u64::from(section.offset), bytes));
                }
                _ => {}
            }
        }
    }
    let Some((offset, code)) = code.filter(|_| swift) else {
        return Vec::new();
    };
    let Some(base) = slice_base.checked_add(offset) else {
        return Vec::new();
    };
    if base.checked_add(code.len() as u64).is_none() {
        return Vec::new();
    }
    let mut regs = [Constant::default(); 31];
    let mut epoch = 1;
    let mut results = Vec::new();
    let (words, _) = code.as_chunks::<4>();
    for (index, bytes) in words.iter().enumerate() {
        let w = u32::from_le_bytes(*bytes);
        let rd = (w & 31) as usize;
        let op = w & 0x7f80_0000;
        if rd < 31 && (op == 0x5280_0000 || op == 0x7280_0000) {
            // MOVZ/MOVK, including W-register zero extension. Reject reserved
            // W-register shifts; a MOVK without a known MOVZ cannot qualify.
            let shift = ((w >> 21) & 3) * 16;
            let wide = w >> 31 != 0;
            if !wide && shift >= 32 {
                epoch += 1;
                continue;
            }
            let imm = u64::from((w >> 5) & 0xffff) << shift;
            if op == 0x5280_0000 {
                regs[rd] = Constant {
                    value: imm,
                    start: index,
                    epoch,
                };
            } else if regs[rd].epoch == epoch && index - regs[rd].start < MAX_DISTANCE {
                regs[rd].value = (regs[rd].value & !(0xffff_u64 << shift)) | imm;
                if !wide {
                    regs[rd].value &= 0xffff_ffff;
                }
            } else {
                regs[rd].epoch = 0;
            }
            // The changed register can be either word of a Swift string.
            for first in [rd.checked_sub(1), (rd < 30).then_some(rd)]
                .into_iter()
                .flatten()
            {
                let lo = regs[first];
                let hi = regs[first + 1];
                let start = lo.start.min(hi.start);
                if lo.epoch != epoch || hi.epoch != epoch || index - start >= MAX_DISTANCE {
                    continue;
                }
                let tag = (hi.value >> 56) as u8;
                let len = usize::from(tag & 15);
                if tag & 0xf0 != 0xe0 || len < min.max(1) {
                    continue;
                }
                let mut raw = [0_u8; 16];
                raw[..8].copy_from_slice(&lo.value.to_le_bytes());
                raw[8..].copy_from_slice(&hi.value.to_le_bytes());
                // Require the declared ASCII payload and canonical zero padding.
                if raw[..len]
                    .iter()
                    .all(|b| b.is_ascii_graphic() || *b == b' ')
                    && raw[len..15].iter().all(|b| *b == 0)
                {
                    let Ok(value) = String::from_utf8(raw[..len].to_vec()) else {
                        continue;
                    };
                    let Ok(data_len) = u32::try_from((index + 1 - start) * 4) else {
                        continue;
                    };
                    results.push(ExtractedString {
                        kind: classify_string(&value),
                        value,
                        data_offset: base + (start * 4) as u64,
                        data_len,
                        method: StringMethod::Structure,
                        ..Default::default()
                    });
                    // Do not emit partial successive versions of the same pair.
                    regs[first].epoch = 0;
                    regs[first + 1].epoch = 0;
                    if results.len() == MAX_STRINGS {
                        return results;
                    }
                }
            }
        } else if w & 0xffe0_ffe0 == 0xaa00_03e0
            || w & 0xff80_0000 == 0x9100_0000
            || (w & 0xff20_0000 == 0x8b00_0000 && (w >> 22) & 3 != 3)
        {
            // MOV Xd,Xm; ADD Xd,Xn,#imm; ADD Xd,Xn,Xm,shift.
            // Only preserve unrelated constants; do not infer pointer values.
            if rd < 31 {
                regs[rd].epoch = 0;
            }
        } else {
            // Unknown instructions, calls, branches, loads, and stores are
            // barriers. Generation tags make invalidation constant time.
            epoch += 1;
        }
    }
    results
}

#[cfg(test)]
mod tests;
