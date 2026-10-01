//! Bounded register-only folding for ARM64 pointer-derived XOR keys.
//! The caller must first validate the literal setup and complete decoding loop.
#![allow(clippy::cast_possible_truncation)]
use super::Region;
use crate::arm64_effects as effects;
mod functions;
mod helpers;
mod immediate;
mod loops;
mod short_tail;

const MAX_STEPS: usize = 40;
const MAX_TAILS: usize = 2;

fn word(code: &Region<'_>, pc: u64) -> Option<u32> {
    if pc & 3 != 0 {
        return None;
    }
    Some(u32::from_le_bytes(code.at(pc, 4)?.try_into().ok()?))
}

fn get(regs: &[Option<u64>; 31], reg: u32) -> Option<u64> {
    if reg == 31 {
        Some(0)
    } else {
        regs[reg as usize]
    }
}

fn shifted(value: u32, kind: u32, amount: u32) -> u32 {
    match kind {
        0 => value.wrapping_shl(amount),
        1 => value.wrapping_shr(amount),
        2 => ((value as i32) >> amount).cast_unsigned(),
        _ => value.rotate_right(amount),
    }
}

// Decode a 32-bit logical immediate, including repeated two-bit elements.
fn bitmask(inst: u32) -> Option<u32> {
    if inst & (1 << 22) != 0 {
        return None;
    }
    let s = (inst >> 10) & 63;
    let r = (inst >> 16) & 63;
    let len = 31u32.checked_sub(((!s) & 63).leading_zeros())?;
    if !(1..=5).contains(&len) {
        return None;
    }
    let width = 1 << len;
    let levels = width - 1;
    let ones = s & levels;
    if ones == levels {
        return None;
    }
    let element_mask = u32::MAX >> (32 - width);
    let pattern = (1u32 << (ones + 1)) - 1;
    let rotate = r & levels;
    let element = if rotate == 0 {
        pattern
    } else {
        (pattern >> rotate | pattern << (width - rotate)) & element_mask
    };
    let mut value = 0;
    for shift in (0..32).step_by(width as usize) {
        value |= element << shift;
    }
    Some(value)
}

/// Fold only pure 32-bit arithmetic followed by `ADD X0,X0,Xn; RET`.
/// Unknown registers, memory access, calls, flags and unsupported encodings fail.
/// At most two direct tail branches and forty instructions are followed.
pub(super) fn fold(code: &Region<'_>, start: u64, base: u64, seed: u32) -> Option<u64> {
    let mut regs = [None; 31];
    regs[0] = Some(base);
    regs[1] = Some(u64::from(seed));
    let mut pc = start;
    let mut tails = 0;
    let mut finished = false;
    for _ in 0..MAX_STEPS {
        let inst = word(code, pc)?;
        pc = pc.checked_add(4)?;
        if finished {
            return (inst == 0xd65f03c0).then_some(regs[0]?);
        }
        if inst & 0xfc000000 == 0x14000000 {
            tails += 1;
            if tails > MAX_TAILS {
                return None;
            }
            let delta = i64::from(inst & 0x03ffffff) << 38 >> 36;
            pc = pc.checked_sub(4)?.checked_add_signed(delta)?;
            continue;
        }
        // The only 64-bit operation allowed is the final pointer addition.
        if inst & 0xffe0ffff == 0x8b000000 {
            let delta = get(&regs, (inst >> 16) & 31)?;
            if delta > 0xffff {
                return None;
            }
            regs[0] = Some(base.checked_add(delta)?);
            finished = true;
            continue;
        }
        if inst & 0x80000000 != 0 {
            return None;
        }
        let dst = inst & 31;
        // x0 is reserved for the base pointer; x1 is an immutable seed.
        if !(2..31).contains(&dst) {
            return None;
        }
        let rn = (inst >> 5) & 31;
        let rm = (inst >> 16) & 31;
        let source = || get(&regs, rn).map(|v| v as u32);
        let other = || get(&regs, rm).map(|v| v as u32);
        let value = if inst & 0x1f800000 == 0x12800000 {
            let shift = ((inst >> 21) & 3) * 16;
            if shift >= 32 {
                return None;
            }
            let imm = ((inst >> 5) & 0xffff) << shift;
            match (inst >> 29) & 3 {
                0 => !imm,
                2 => imm,
                3 => (get(&regs, dst)? as u32 & !(0xffff << shift)) | imm,
                _ => return None,
            }
        } else if matches!(inst & 0x7f800000, 0x11000000 | 0x51000000) {
            let imm = ((inst >> 10) & 0xfff) << (((inst >> 22) & 1) * 12);
            if inst & 0x40000000 == 0 {
                source()?.wrapping_add(imm)
            } else {
                source()?.wrapping_sub(imm)
            }
        } else if matches!(inst & 0x7f200000, 0x0b000000 | 0x4b000000) {
            let amount = (inst >> 10) & 63;
            let kind = (inst >> 22) & 3;
            if amount >= 32 || kind == 3 {
                return None;
            }
            let b = shifted(other()?, kind, amount);
            if inst & 0x40000000 == 0 {
                source()?.wrapping_add(b)
            } else {
                source()?.wrapping_sub(b)
            }
        } else if inst & 0x1f000000 == 0x0a000000 {
            let amount = (inst >> 10) & 63;
            if amount >= 32 {
                return None;
            }
            let mut b = shifted(other()?, (inst >> 22) & 3, amount);
            if inst & (1 << 21) != 0 {
                b = !b;
            }
            match (inst >> 29) & 3 {
                0 => source()? & b,
                1 => source()? | b,
                2 => source()? ^ b,
                _ => return None,
            }
        } else if inst & 0x1f800000 == 0x12000000 {
            let b = bitmask(inst)?;
            match (inst >> 29) & 3 {
                0 => source()? & b,
                1 => source()? | b,
                2 => source()? ^ b,
                _ => return None,
            }
        } else if inst & 0xffe08000 == 0x1b000000 {
            let addend = get(&regs, (inst >> 10) & 31)? as u32;
            source()?.wrapping_mul(other()?).wrapping_add(addend)
        } else if inst & 0x1f800000 == 0x13000000 {
            let r = (inst >> 16) & 63;
            let s = (inst >> 10) & 63;
            if inst & (1 << 22) != 0 || r > s || s >= 32 {
                return None;
            }
            match (inst >> 29) & 3 {
                0 if s == 31 => ((source()? as i32) >> r).cast_unsigned(),
                2 if s == 31 => source()? >> r,
                1 => {
                    let mask = u32::MAX >> (31 - (s - r));
                    (get(&regs, dst)? as u32 & !mask) | ((source()? >> r) & mask)
                }
                _ => return None,
            }
        } else if inst & 0xffe00000 == 0x13800000 {
            let amount = (inst >> 10) & 63;
            if amount >= 32 {
                return None;
            }
            (((u64::from(source()?) << 32) | u64::from(other()?)) >> amount) as u32
        } else {
            return None;
        };
        regs[dst as usize] = Some(u64::from(value));
    }
    None
}

#[cfg(test)]
mod tests;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Seed {
    Immediate(u32),
    // The caller must establish the saved register's value and preservation.
    Saved { register: u32, add: u32 },
}

#[derive(Debug)]
pub(super) struct Setup {
    pub helper: u64,
    pub base: u64,
    pub seed: Seed,
    pub after: u64,
}

fn branch_target(code: &Region<'_>, pc: u64) -> Option<u64> {
    let inst = word(code, pc)?;
    if inst & 0xfc000000 != 0x94000000 {
        return None;
    }
    pc.checked_add_signed(i64::from(inst & 0x03ffffff) << 38 >> 36)
}

fn sequence(code: &Region<'_>, pc: u64, words: &[u32]) -> Option<()> {
    for (i, expected) in words.iter().enumerate() {
        if word(code, pc.checked_add((i * 4) as u64)?)? != *expected {
            return None;
        }
    }
    Some(())
}

// The outlined base-store helper must have exactly this side-effect grammar.
fn base_store(code: &Region<'_>, call: u64, add: bool) -> Option<()> {
    let mut pc = branch_target(code, call)?;
    if add {
        sequence(code, pc, &[0x8b090108])?;
        pc = pc.checked_add(4)?;
    }
    sequence(code, pc, &[0xf9005be8])?;
    pc = pc.checked_add(4)?;
    if matches!(word(code, pc)?, 0x9102c3e8 | 0x9102c3f3) {
        pc = pc.checked_add(4)?;
    }
    sequence(code, pc, &[0xd65f03c0])
}

fn seed_store(code: &Region<'_>, call: u64) -> Option<()> {
    sequence(
        code,
        branch_target(code, call)?,
        &[0xb900b3e8, 0x9102c3e8, 0xd65f03c0],
    )
}

/// Recognize argument setup only; does not establish a complete XOR literal.
/// Saved-register seed expressions remain unresolved until preservation is proven.
pub(super) fn setup(code: &Region<'_>, call: u64) -> Option<Setup> {
    sequence(code, call.checked_sub(4)?, &[0xb940b3e1])?;
    let helper = branch_target(code, call)?;
    // Require a mapped helper, even before evaluating its arithmetic.
    word(code, helper)?;
    let (start, seed) = if seed_store(code, call.checked_sub(8)?).is_some() {
        let low = word(code, call.checked_sub(16)?)?;
        let high = word(code, call.checked_sub(12)?)?;
        if low & 0xffe0001f == 0x52800008 && high & 0xffe0001f == 0x72a00008 {
            (
                call.checked_sub(36)?,
                Seed::Immediate(((low >> 5) & 0xffff) | (((high >> 5) & 0xffff) << 16)),
            )
        } else {
            // ADD W8,W19..W28,#imm, optionally shifted by 12.
            if high & 0xff80001f != 0x11000008 {
                return None;
            }
            let register = (high >> 5) & 31;
            if !(19..=28).contains(&register) {
                return None;
            }
            (
                call.checked_sub(32)?,
                Seed::Saved {
                    register,
                    add: ((high >> 10) & 0xfff) << (((high >> 22) & 1) * 12),
                },
            )
        }
    } else {
        sequence(code, call.checked_sub(8)?, &[0x9102c3e8])?;
        let store = word(code, call.checked_sub(12)?)?;
        if store & !31 != 0xb900b3e0 {
            return None;
        }
        let register = store & 31;
        if !(19..=28).contains(&register) {
            return None;
        }
        (call.checked_sub(32)?, Seed::Saved { register, add: 0 })
    };
    let page = word(code, start)?;
    let offset = word(code, start.checked_add(4)?)?;
    if page & 0x9f00001f != 0x90000008 || offset & 0xffc003ff != 0x91000108 {
        return None;
    }
    let address = crate::arm64::adrp_add(start, page, offset)?;
    let bias = word(code, start.checked_add(8)?)?;
    let store = start.checked_add(12)?;
    let base = if bias & 0xffe0001f == 0x92800009 {
        // MOVN X9,#imm (negative bias), then ADD X8,X8,X9 in helper.
        base_store(code, store, true)?;
        address.checked_sub(u64::from((bias >> 5) & 0xffff) + 1)?
    } else if bias & 0xff8003ff == 0xd1000108 {
        if word(code, store)? != 0xf9005be8 {
            base_store(code, store, false)?;
        }
        address.checked_sub(u64::from((bias >> 10) & 0xfff) << (((bias >> 22) & 1) * 12))?
    } else {
        return None;
    };
    sequence(code, start.checked_add(16)?, &[0xf9405be0])?;
    Some(Setup {
        helper,
        base,
        seed,
        after: call.checked_add(4)?,
    })
}

/// A single fixed-byte search gates the more expensive setup/helper checks.
/// Candidate attempts are capped, including malformed candidates.
pub(super) fn setups<'a>(code: &'a Region<'_>) -> impl Iterator<Item = Setup> + 'a {
    let bytes = if code.bytes.len() <= super::MAX_CODE {
        code.bytes
    } else {
        &[]
    };
    memchr::memmem::find_iter(bytes, b"\xe1\xb3\x40\xb9")
        .take(super::MAX_CANDIDATES)
        .filter_map(move |at| {
            if at & 3 != 0 {
                return None;
            }
            setup(code, code.addr.checked_add(at as u64)?.checked_add(4)?)
        })
}

/// Resolve a seed whose saved-register constant pair immediately precedes the
/// already validated setup. Setup helpers only modify X8/X9/X19; other saved
/// registers retain their value through this bounded sequence.
pub(super) fn local_seed(code: &Region<'_>, setup: &Setup) -> Option<u32> {
    let Seed::Saved { register, add } = setup.seed else {
        return match setup.seed {
            Seed::Immediate(value) => Some(value),
            _ => None,
        };
    };
    // X19 may be overwritten by the validated base-store helper.
    if !(20..=28).contains(&register) {
        return None;
    }
    let call = setup.after.checked_sub(4)?;
    let low = word(code, call.checked_sub(40)?)?;
    let high = word(code, call.checked_sub(36)?)?;
    if low & 0xffe0001f != 0x52800000 | register || high & 0xffe0001f != 0x72a00000 | register {
        return None;
    }
    Some((((low >> 5) & 0xffff) | (((high >> 5) & 0xffff) << 16)).wrapping_add(add))
}

/// Recover complete literals determined by constant inputs and a bounded XOR
/// loop. This does not establish execution or aliasing into a later consumer.
pub(super) fn extract(
    code: &Region<'_>,
    constants: &[Region<'_>],
    slice_base: u64,
    min: usize,
) -> Vec<crate::ExtractedString> {
    let mut out = Vec::new();
    if min > 32 {
        return out;
    }
    for setup in setups(code) {
        if let Some(value) = immediate::extract(code, constants, &setup, slice_base, min)
            .or_else(|| short_tail::extract(code, constants, &setup, slice_base, min))
        {
            out.push(value);
            continue;
        }
        let Some(literal) = loops::read(code, setup.after) else {
            continue;
        };
        if literal.length < min {
            continue;
        }
        let Some(seed) = local_seed(code, &setup) else {
            continue;
        };
        let Some(key) = fold(code, setup.helper, setup.base, seed) else {
            continue;
        };
        let Some(cipher) = constants
            .iter()
            .find(|r| r.at(literal.cipher, literal.length).is_some())
        else {
            continue;
        };
        let Some(encoded) = cipher.at(literal.cipher, literal.length) else {
            continue;
        };
        let Some(key) = constants.iter().find_map(|r| r.at(key, literal.length)) else {
            continue;
        };
        let decoded: Vec<_> = encoded.iter().zip(key).map(|(a, b)| a ^ b).collect();
        let Ok(value) = String::from_utf8(decoded) else {
            continue;
        };
        if !value
            .chars()
            .all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
        {
            continue;
        }
        let Some(offset) = slice_base
            .checked_add(cipher.offset)
            .and_then(|n| n.checked_add(literal.cipher - cipher.addr))
        else {
            continue;
        };
        out.push(crate::ExtractedString {
            kind: crate::classify_string(&value),
            value,
            data_offset: offset,
            data_len: u32::try_from(literal.length).unwrap_or(u32::MAX),
            method: crate::StringMethod::XorDecode,
            ..Default::default()
        });
    }
    out
}
