//! ARM64 instruction fields shared by the instruction-pattern decoders.

/// The address an `ADRP` (`page`) at `pc` and the `ADD #imm12` (`low`) after
/// it form: the 4 KiB page `ADRP` selects relative to `pc`'s page, plus the
/// low 12 bits. `None` when that falls outside the address space.
pub(crate) fn adrp_add(pc: u64, page: u32, low: u32) -> Option<u64> {
    // immhi (bits 5..24) and immlo (bits 29..31) form a signed 21-bit page count.
    let pages = i64::from(((page >> 5) & 0x7ffff) << 2 | ((page >> 29) & 3));
    (pc & !4095)
        .checked_add_signed((pages << 43 >> 43) << 12)?
        .checked_add(u64::from((low >> 10) & 0xfff))
}

#[cfg(test)]
mod tests {
    use super::*;

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
