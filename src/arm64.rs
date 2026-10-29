//! ARM64 instruction fields shared by the instruction-pattern decoders.

pub(crate) mod effects;
pub(crate) mod frame;
pub(crate) mod walk;

/// `RET` through the link register.
pub(crate) const RET: u32 = 0xd65f_03c0;
/// `NOP`.
pub(crate) const NOP: u32 = 0xd503_201f;

/// The instruction at byte offset `at` in `code`; `None` if `at` is not
/// word-aligned or runs past the end.
pub(crate) fn word(code: &[u8], at: usize) -> Option<u32> {
    if !at.is_multiple_of(4) {
        return None;
    }
    Some(u32::from_le_bytes(*code.get(at..)?.first_chunk()?))
}

/// Whether `inst` is `BL`.
pub(crate) fn is_bl(inst: u32) -> bool {
    inst & 0xfc00_0000 == 0x9400_0000
}

/// Whether `inst` is an unconditional `B`.
pub(crate) fn is_b(inst: u32) -> bool {
    inst & 0xfc00_0000 == 0x1400_0000
}

/// `pc` plus `field`, a signed offset of `width` bits counted in words.
pub(crate) fn relative(pc: u64, field: u32, width: u32) -> Option<u64> {
    pc.checked_add_signed(i64::from(field) << (64 - width) >> (62 - width))
}

/// Where the `B` or `BL` at `pc` goes.
pub(crate) fn branch_target(pc: u64, inst: u32) -> Option<u64> {
    relative(pc, inst & 0x03ff_ffff, 26)
}

/// The offset field and its width of a conditional branch: `B.cond`,
/// `CBZ`/`CBNZ` (19 bits) or `TBZ`/`TBNZ` (14 bits).
pub(crate) fn conditional(inst: u32) -> Option<(u32, u32)> {
    if inst & 0xff00_0010 == 0x5400_0000 || inst & 0x7e00_0000 == 0x3400_0000 {
        Some(((inst >> 5) & 0x7ffff, 19))
    } else if inst & 0x7e00_0000 == 0x3600_0000 {
        Some(((inst >> 5) & 0x3fff, 14))
    } else {
        None
    }
}

/// A `MOVZ` or `MOVK`: one 16-bit lane of `rd`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MoveWide {
    pub(crate) rd: u32,
    /// `MOVK` keeps the other lanes; `MOVZ` clears them.
    pub(crate) keep: bool,
    /// Whether `rd` is an X register.
    pub(crate) wide: bool,
    pub(crate) shift: u32,
    /// The immediate, already shifted into its lane.
    pub(crate) imm: u64,
}

impl MoveWide {
    /// `rd`'s value after this instruction, given its value before.
    pub(crate) fn apply(self, before: u64) -> u64 {
        let value = if self.keep {
            before & !(0xffff << self.shift) | self.imm
        } else {
            self.imm
        };
        if self.wide {
            value
        } else {
            value & 0xffff_ffff
        }
    }
}

/// Decode `MOVZ`/`MOVK`. `None` for anything else, including the reserved
/// upper-lane forms on W registers.
pub(crate) fn move_wide(inst: u32) -> Option<MoveWide> {
    let keep = match inst & 0x7f80_0000 {
        0x5280_0000 => false,
        0x7280_0000 => true,
        _ => return None,
    };
    let wide = inst >> 31 == 1;
    let shift = ((inst >> 21) & 3) * 16;
    if !wide && shift >= 32 {
        return None;
    }
    Some(MoveWide {
        rd: inst & 31,
        keep,
        wide,
        shift,
        imm: u64::from((inst >> 5) & 0xffff) << shift,
    })
}

/// The value a logical (immediate) instruction's `N:immr:imms` encodes,
/// replicated to the register width; `None` for a reserved encoding. This is
/// the Arm ARM's `DecodeBitMasks`.
pub(crate) fn bitmask_imm(inst: u32) -> Option<u64> {
    let wide = inst >> 31 == 1;
    let n = (inst >> 22) & 1;
    let immr = (inst >> 16) & 63;
    let imms = (inst >> 10) & 63;
    if !wide && n == 1 {
        return None;
    }
    // The element is 2^len bits, len the highest set bit of N:NOT(imms).
    let len = 31u32.checked_sub(((n << 6) | (!imms & 63)).leading_zeros())?;
    if len < 1 {
        return None;
    }
    let size = 1u32 << len;
    let levels = size - 1;
    let (ones, rotate) = (imms & levels, immr & levels);
    if ones == levels {
        return None;
    }
    let mask = u64::MAX >> (64 - size);
    let run = (1u64 << (ones + 1)) - 1;
    let element = if rotate == 0 {
        run
    } else {
        (run >> rotate | run << (size - rotate)) & mask
    };
    let width = if wide { 64 } else { 32 };
    Some(
        (0..width)
            .step_by(size as usize)
            .fold(0, |v, shift| v | element << shift),
    )
}

/// The 4 KiB page an `ADRP` at `pc` selects, relative to `pc`'s page. `None`
/// when that falls outside the address space.
pub(crate) fn adrp_page(pc: u64, adrp: u32) -> Option<u64> {
    // immhi (bits 5..24) and immlo (bits 29..31) form a signed 21-bit page count.
    let pages = i64::from(((adrp >> 5) & 0x7ffff) << 2 | ((adrp >> 29) & 3));
    (pc & !4095).checked_add_signed((pages << 43 >> 43) << 12)
}

/// The address an `ADRP` (`page`) at `pc` and the `ADD #imm12` (`low`) after
/// it form: [`adrp_page`] plus the low 12 bits. `None` when that falls outside
/// the address space.
pub(crate) fn adrp_add(pc: u64, page: u32, low: u32) -> Option<u64> {
    adrp_page(pc, page)?.checked_add(u64::from((low >> 10) & 0xfff))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitmask_imm_decodes_and_rejects_reserved() {
        // ORR X0, XZR, #1
        assert_eq!(bitmask_imm(0xb240_0000), Some(1));
        // ORR W0, WZR, #0x55555555 (2-bit elements)
        assert_eq!(bitmask_imm(0x3200_f3e0), Some(0x5555_5555));
        // ORR X0, XZR, #0xff000000ff000000 (32-bit elements, rotated)
        assert_eq!(bitmask_imm(0xb208_1fe0), Some(0xff00_0000_ff00_0000));
        // All ones in the element is reserved; N=1 with a W register too.
        assert_eq!(bitmask_imm(0xb240_fc00), None);
        assert_eq!(bitmask_imm(0x3240_0000), None);
    }

    #[test]
    fn adrp_add_resolves_forward_and_backward_pages() {
        // ADRP X8, #+1 page ; ADD X8, X8, #0x10
        assert_eq!(adrp_add(0x1004, 0xb000_0008, 0x9100_4108), Some(0x2010));
        // ADRP X8, #-1 page ; ADD X8, X8, #0x10
        assert_eq!(adrp_add(0x2000, 0xf0ff_ffe8, 0x9100_4108), Some(0x1010));
        // A page below address zero.
        assert_eq!(adrp_add(0x10, 0xf0ff_ffe8, 0x9100_4108), None);
    }
}
