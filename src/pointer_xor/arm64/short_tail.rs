//! Bounded 5..7/9..11-byte XOR literals: a verified word loop and integer tail.
#![allow(clippy::cast_possible_truncation)]
use super::{Region, Setup, bitmask, branch_target, fold, local_seed, sequence, word};
const MAX_STEPS: usize = 64;
const MAX_DEPTH: usize = 2;

fn constant<'a>(regions: &'a [Region<'_>], address: u64, length: usize) -> Option<&'a [u8]> {
    regions.iter().find_map(|r| r.at(address, length))
}
fn prefix4(
    code: &Region<'_>,
    regions: &[Region<'_>],
    start: u64,
    init: u64,
) -> Option<(u64, u64, usize)> {
    sequence(code, init, &[0xd2800009, 0xb900b3ff])?;
    let mut pc = start.checked_add(4)?;
    if word(code, init.checked_add(8)?)? == 0xd65f03c0 {
        sequence(
            code,
            branch_target(code, pc)?,
            &[0x790043ff, 0x52800028, 0x9102c3eb, 0xd65f03c0],
        )?;
        pc = pc.checked_add(4)?;
    } else {
        sequence(
            code,
            init.checked_add(8)?,
            &[0x390083ff, 0x52800028, 0x9102c3eb, 0xd65f03c0],
        )?;
    }
    let low = word(code, pc)?;
    let high = word(code, pc.checked_add(4)?)?;
    if low & 0xffe0001f != 0x5280000a || high & 0xffe0001f != 0x72a0000a {
        return None;
    }
    let mut cipher = u64::from(((low >> 5) & 65535) | (((high >> 5) & 65535) << 16));
    pc = pc.checked_add(8)?;
    if word(code, pc)? == 0x39008bff {
        pc = pc.checked_add(4)?;
    }
    let page = word(code, pc)?;
    let low = word(code, pc.checked_add(4)?)?;
    if page & 0x9f00001f != 0x9000000c || low & 0xffc003ff != 0x9100018c {
        return None;
    }
    let delta = i64::from(((page >> 5) & 0x7ffff) << 2 | ((page >> 29) & 3));
    let address = (pc & !4095)
        .checked_add_signed((delta << 43 >> 43) << 12)?
        .checked_add(u64::from((low >> 10) & 4095))?;
    sequence(code, pc.checked_add(8)?, &[0x36000068])?;
    sequence(
        code,
        branch_target(code, pc.checked_add(12)?)?,
        &[
            0x52800008, 0xb869680d, 0x38696989, 0x2a0a0129, 0x4a0d0129, 0xb9000169, 0x910083eb,
            0x52800089, 0xd65f03c0,
        ],
    )?;
    sequence(code, pc.checked_add(16)?, &[0x3707ffe8])?;
    cipher |= u64::from(constant(regions, address, 1)?[0]);
    Some((cipher, pc.checked_add(20)?, 4))
}
fn prefix(code: &Region<'_>, regions: &[Region<'_>], start: u64) -> Option<(u64, u64, usize)> {
    let init = branch_target(code, start)?;
    if word(code, init.checked_add(4)?)? == 0xb900b3ff {
        return prefix4(code, regions, start, init);
    }
    let (register, address_reg, body) = match word(code, init)? {
        0xd2800009 => {
            sequence(
                code,
                init,
                &[
                    0xd2800009, 0xf9005bff, 0x790043ff, 0x52800028, 0x9102c3eb, 0xd65f03c0,
                ],
            )?;
            (
                10,
                12,
                [
                    0x52800008, 0xf869680d, 0x38696989, 0xaa0a0129, 0xca0d0129, 0xf9000169,
                    0x910083eb, 0x52800109, 0xd65f03c0,
                ],
            )
        }
        0xd280000b => {
            let zero = word(code, init.checked_add(8)?)?;
            if !matches!(zero, 0x390083ff | 0x790043ff) {
                return None;
            }
            sequence(
                code,
                init,
                &[
                    0xd280000b, 0xf9005bff, zero, 0x52800028, 0x9102c3ea, 0xd65f03c0,
                ],
            )?;
            (
                9,
                12,
                [
                    0x52800008, 0xf86b680d, 0x386b698b, 0xaa09016b, 0xca0d016b, 0xf900014b,
                    0x910083ea, 0x5280010b, 0xd65f03c0,
                ],
            )
        }
        0xd280000c => {
            sequence(
                code,
                init,
                &[0xd280000c, 0xf9005bff, 0x52800028, 0x9102c3ea, 0xd65f03c0],
            )?;
            (
                9,
                11,
                [
                    0x52800008, 0xf86c680d, 0x386c696c, 0xaa09018c, 0xca0d018c, 0xf900014c,
                    0x910083ea, 0x5280010c, 0xd65f03c0,
                ],
            )
        }
        _ => return None,
    };
    let mut pc = start.checked_add(4)?;
    let first = word(code, pc)?;
    if first & 0xff80001f != 0xd2800000 | register {
        return None;
    }
    let initial_shift = ((first >> 21) & 3) * 16;
    let mut cipher = u64::from((first >> 5) & 65535) << initial_shift;
    pc = pc.checked_add(4)?;
    let mut last_shift = initial_shift;
    // MOVZ defines all bits; at most three ascending MOVK lanes may replace them.
    for _ in 0..3 {
        let w = word(code, pc)?;
        if w & 0xff80001f != 0xf2800000 | register {
            break;
        }
        let shift = ((w >> 21) & 3) * 16;
        if shift <= last_shift {
            return None;
        }
        cipher |= u64::from((w >> 5) & 65535) << shift;
        last_shift = shift;
        pc = pc.checked_add(4)?;
    }
    if register == 10 {
        sequence(code, pc, &[0x39008bff])?;
        pc = pc.checked_add(4)?;
    }
    let page = word(code, pc)?;
    let low = word(code, pc.checked_add(4)?)?;
    if page & 0x9f00001f != 0x90000000 | address_reg
        || low & 0xffc003ff != 0x91000000 | (address_reg << 5) | address_reg
    {
        return None;
    }
    let delta = i64::from(((page >> 5) & 0x7ffff) << 2 | ((page >> 29) & 3));
    let address = (pc & !4095)
        .checked_add_signed((delta << 43 >> 43) << 12)?
        .checked_add(u64::from((low >> 10) & 4095))?;
    sequence(code, pc.checked_add(8)?, &[0x36000068])?;
    sequence(code, branch_target(code, pc.checked_add(12)?)?, &body)?;
    sequence(code, pc.checked_add(16)?, &[0x3707ffe8])?;
    cipher |= u64::from(constant(regions, address, 1)?[0]);
    Some((cipher, pc.checked_add(20)?, 8))
}
fn get(regs: &[Option<u64>; 4], r: u32) -> Option<u32> {
    if r == 31 {
        Some(0)
    } else {
        Some(*regs.get(r.checked_sub(8)? as usize)?.as_ref()? as u32)
    }
}
fn tail(
    code: &Region<'_>,
    regions: &[Region<'_>],
    start: u64,
    mut pc: u64,
    key: u64,
    head: u64,
    head_width: usize,
) -> Option<(Vec<u8>, u32)> {
    let mut regs = [None; 4];
    let mut output = [None; 11];
    let mut output_base = None;
    let mut returns = [0; MAX_DEPTH];
    let mut depth = 0;
    let mut args = [false; 2];
    let mut length = None;
    let mut end = pc;
    let main_end = start.checked_add(128)?;
    for _ in 0..MAX_STEPS {
        let w = word(code, pc)?;
        let next = pc.checked_add(4)?;
        if depth == 0 {
            if !(start..main_end).contains(&pc) {
                return None;
            }
            end = end.max(next);
        }
        if w & 0x7c000000 == 0x14000000 {
            let target = pc.checked_add_signed(i64::from(w & 0x03ffffff) << 38 >> 36)?;
            word(code, target)?;
            if args == [true, true] && length.is_some() {
                let n = length?;
                if output[n..].iter().any(Option::is_some) {
                    return None;
                }
                let value: Option<Vec<_>> = output[..n].iter().copied().collect();
                return Some((value?, u32::try_from(end.checked_sub(start)?).ok()?));
            }
            // Tail branches are only accepted at the checked string consumer.
            if w >> 31 == 0 || depth == MAX_DEPTH {
                return None;
            }
            returns[depth] = next;
            depth += 1;
            pc = target;
            continue;
        }
        if w == 0xd65f03c0 {
            depth = depth.checked_sub(1)?;
            pc = returns[depth];
            continue;
        }
        if w & 0xffc003ff == 0x910003e0 {
            args[0] = true;
            pc = next;
            continue;
        }
        if w & 0xffc003ff == 0x910003e1 {
            if output_base != Some(((w >> 10) & 4095) as usize) {
                return None;
            }
            args[1] = true;
            pc = next;
            continue;
        }
        if w & 0xffe0001f == 0x52800002 {
            let n = ((w >> 5) & 65535) as usize;
            if !(head_width + 1..=head_width + 3).contains(&n) {
                return None;
            }
            length = Some(n);
            pc = next;
            continue;
        }
        let dst = w & 31;
        if !(8..=11).contains(&dst) {
            return None;
        }
        let slot = (dst - 8) as usize;
        if matches!(w & 0xffc003e0, 0x39400000 | 0x79400000) {
            if args[0] {
                return None;
            }
            let size = 1usize << ((w >> 30) & 3);
            let offset = ((w >> 10) & 4095) as usize * size;
            if offset < head_width || offset.checked_add(size)? > head_width + 3 {
                return None;
            }
            let bytes = constant(regions, key.checked_add(offset as u64)?, size)?;
            regs[slot] = Some(
                bytes
                    .iter()
                    .enumerate()
                    .fold(0u64, |a, (i, b)| a | (u64::from(*b) << (i * 8))),
            );
        } else if w & !31
            == (if head_width == 4 {
                0xb940b3e0
            } else {
                0xf9405be0
            })
        {
            regs[slot] = Some(head);
        } else if head_width == 4 && w & !31 == 0x39008be0 {
            if output_base.is_some() {
                return None;
            }
            regs[slot]?; // Scratch byte is overwritten by the later complete output copy.
        } else if matches!(
            w & 0xffc003e0,
            0x390003e0 | 0x790003e0 | 0xb90003e0 | 0xf90003e0
        ) {
            let size = 1usize << ((w >> 30) & 3);
            let address = ((w >> 10) & 4095) as usize * size;
            if output_base.is_none() {
                // The output buffer must not overwrite the qword source at SP+0xb0.
                if size != head_width || address.checked_add(head_width + 3)? > 0xb0 {
                    return None;
                }
                output_base = Some(address);
            }
            let offset = address.checked_sub(output_base?)?;
            let end = offset.checked_add(size)?;
            if end > head_width + 3 {
                return None;
            }
            let dest = output.get_mut(offset..end)?;
            let bytes = regs[slot]?.to_le_bytes();
            for (out, byte) in dest.iter_mut().zip(bytes) {
                *out = Some(byte);
            }
        } else if w >> 31 == 0 && w & 0x1f800000 == 0x12800000 {
            let shift = ((w >> 21) & 3) * 16;
            if shift >= 32 {
                return None;
            }
            let imm = ((w >> 5) & 65535) << shift;
            regs[slot] = Some(u64::from(match (w >> 29) & 3 {
                0 => !imm,
                2 => imm,
                3 => (regs[slot]? as u32 & !(65535 << shift)) | imm,
                _ => return None,
            }));
        } else if w >> 31 == 0 && w & 0x1f800000 == 0x12000000 {
            let a = get(&regs, (w >> 5) & 31)?;
            let b = bitmask(w)?;
            regs[slot] = Some(u64::from(match (w >> 29) & 3 {
                0 => a & b,
                1 => a | b,
                2 => a ^ b,
                _ => return None,
            }));
        } else if w & 0xffc00000 == 0x53000000 {
            let r = (w >> 16) & 63;
            let end = (w >> 10) & 63;
            if r == 0 || r >= 32 || end + 1 != r {
                return None;
            }
            regs[slot] = Some(u64::from(get(&regs, (w >> 5) & 31)? << (32 - r)));
        } else if w & 0xfffffc00 == 0x33001c00 {
            let a = get(&regs, (w >> 5) & 31)?;
            regs[slot] = Some(u64::from((regs[slot]? as u32 & !255) | (a & 255)));
        } else if w >> 31 == 0 && w & 0x1f200000 == 0x0a000000 {
            let amount = (w >> 10) & 63;
            if amount >= 32 || (w >> 22) & 3 > 1 {
                return None;
            }
            let a = get(&regs, (w >> 5) & 31)?;
            let b = get(&regs, (w >> 16) & 31)?;
            let b = if (w >> 22) & 3 == 0 {
                b << amount
            } else {
                b >> amount
            };
            regs[slot] = Some(u64::from(match (w >> 29) & 3 {
                0 => a & b,
                1 => a | b,
                2 => a ^ b,
                _ => return None,
            }));
        } else {
            return None;
        }
        pc = next;
    }
    None
}
pub(super) fn extract(
    code: &Region<'_>,
    regions: &[Region<'_>],
    setup: &Setup,
    slice_base: u64,
    min: usize,
) -> Option<crate::ExtractedString> {
    if min > 11 {
        return None;
    }
    let (cipher, after, width) = prefix(code, regions, setup.after)?;
    let key = fold(code, setup.helper, setup.base, local_seed(code, setup)?)?;
    let head = cipher
        ^ constant(regions, key, width)?
            .iter()
            .enumerate()
            .fold(0u64, |v, (i, b)| v | (u64::from(*b) << (i * 8)));
    let (bytes, span) = tail(code, regions, setup.after, after, key, head, width)?;
    if bytes.len() < min {
        return None;
    }
    let value = String::from_utf8(bytes).ok()?;
    if !value
        .chars()
        .all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
    {
        return None;
    }
    Some(crate::ExtractedString {
        kind: crate::classify_string(&value),
        value,
        data_offset: slice_base
            .checked_add(code.offset)?
            .checked_add(setup.after.checked_sub(code.addr)?)?,
        data_len: span,
        method: crate::StringMethod::XorDecode,
        ..Default::default()
    })
}
#[cfg(test)]
mod tests;
