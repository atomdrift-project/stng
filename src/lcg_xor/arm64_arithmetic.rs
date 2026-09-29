//! ARM64 table arithmetic: complete loops and address setup, without emulation.
use super::ArithmeticTables;

fn word(code: &[u8], pos: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        code.get(pos..pos.checked_add(4)?)?.try_into().ok()?,
    ))
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

fn table(code: &[u8], pc: u64, pos: usize) -> Option<ArithmeticTables> {
    let first = word(code, pos)?;
    let post = first == 0xb84046c8; // LDR W8,[X22],#4
    let scaled = first == 0xb8737a88; // LDR W8,[X20,X19,LSL #2]
    let loads = if post {
        [0xb84046c8, 0xb8404689, 0xb840466a]
    } else if scaled {
        [0xb8737a88, 0xb8737aa9, 0xb8737aca]
    } else {
        [0xb8736a88, 0xb8736aa9, 0xb8736aca]
    };
    for (i, expected) in loads.into_iter().enumerate() {
        if word(code, pos + i * 4)? != expected {
            return None;
        }
    }
    for (i, expected) in [
        (3, 0x4b090108),
        (4, 0x4a0a0108),
        (7, 0x4b0a0108),
        (10, 0x13001d01),
    ] {
        if word(code, pos + i * 4)? != expected {
            return None;
        }
    }
    // The volatile intermediate is stored and reloaded twice at the same slot.
    let store = word(code, pos + 20)?;
    let (mask, opcode) = if post {
        (!0x003f_fc00, 0xb90003e8)
    } else {
        (!0x001f_f000, 0xb80003a8)
    };
    if store & mask != opcode
        || word(code, pos + 32)? != store
        || word(code, pos + 24)? != store | 0x00400000
        || word(code, pos + 36)? != store | 0x00400000
    {
        return None;
    }
    let object = word(code, pos + 44)?;
    // SUB X0,X29,#imm or ADD X0,SP,#imm; then append the computed byte W1.
    if !matches!(object & !0x003f_fc00, 0xd10003a0 | 0x910003e0)
        || word(code, pos + 48)? & 0xfc000000 != 0x94000000
    {
        return None;
    }
    let setup = pos.checked_sub(28)?;
    let (addresses, count) = if post {
        let count = word(code, setup + 16)?;
        if count & !0x001f_ffe0 != 0x52800015 // MOV W21,#count
            || word(code, pos + 52)? != 0xf10006b5 // SUBS X21,X21,#1
            || word(code, pos + 56)? != 0x54fffe41
        // B.NE loop
        {
            return None;
        }
        (
            [
                address(code, pc, setup + 20, 22)?,
                address(code, pc, setup + 8, 20)?,
                address(code, pc, setup, 19)?,
            ],
            ((count >> 5) & 0xffff) as usize,
        )
    } else {
        let cmp = word(code, pos + 56)?;
        if word(code, setup)? != 0xd2800013 // MOV X19,#0
            || word(code, pos + 52)? != if scaled { 0x91000673 } else { 0x91001273 }
            || cmp & !0x003f_fc00 != 0xf100027f
            || word(code, pos + 60)? != 0x54fffe21
        {
            return None;
        }
        let bound = ((cmp >> 10) & 0xfff) as usize;
        if !scaled && bound % 4 != 0 {
            return None;
        }
        (
            [
                address(code, pc, setup + 4, 20)?,
                address(code, pc, setup + 12, 21)?,
                address(code, pc, setup + 20, 22)?,
            ],
            if scaled { bound } else { bound / 4 },
        )
    };
    if count < 2 || count % 2 != 0 || count > 128 * 1024 {
        return None;
    }
    Some(ArithmeticTables {
        addresses,
        length: count * 4,
        subtract_address: Some(addresses[2]),
        permutation: None,
        literal_tail: None,
    })
}

// Three-state dispatcher: initialize index/state, append the arithmetic byte,
// increment the index, then exit after the inclusive bound. Every edge is fixed.
fn dispatch_table(code: &[u8], pc: u64, pos: usize) -> Option<ArithmeticTables> {
    let first = word(code, pos)?;
    let large = match first {
        0x93407d17 => false,
        0x93407d18 => true,
        _ => return None,
    };
    let fixed = [
        (2, if large { 0x1a94b699 } else { 0x1a94b698 }),
        (3, 0xaa0903e8),
        (4, 0x7100051f),
        (5, 0x54000161),
        (6, if large { 0xb8787aa8 } else { 0xb8777a68 }),
        (7, if large { 0xb8787ac9 } else { 0xb8777aa9 }),
        (8, if large { 0xb8787aea } else { 0xb8777aca }),
        (9, 0x4b090108),
        (10, 0x4a0a0108),
        (11, 0x13001d01),
        (14, if large { 0xaa1903e8 } else { 0xaa1803e8 }),
        (15, 0x17fffff5),
        (16, 0x34000088),
        (17, 0x7100091f),
        (18, 0x54000081),
        (19, if large { 0x11000708 } else { 0x110006e8 }),
        (20, 0x52800029),
        (21, 0x17ffffeb),
    ];
    for (i, expected) in fixed {
        if word(code, pos + i * 4)? != expected {
            return None;
        }
    }
    if word(code, pos + 52)? & 0xfc000000 != 0x94000000 {
        return None;
    }
    let setup = pos.checked_sub(if large { 48 } else { 44 })?;
    if word(code, setup)? != 0x52800008
        || word(code, setup + 4)? != 0x52800009
        || word(code, setup + if large { 16 } else { 20 })? != 0x52800054
    {
        return None;
    }
    // The append target must be the same 24-byte string initialized by setup.
    let object = word(code, pos + 48)?;
    let offset = ((object >> 10) & 0xfff) as i32;
    let pair = word(code, setup + 8)?;
    let tail = word(code, setup + if large { 20 } else { 24 })?;
    let pair_offset = (((pair >> 15) & 127) as i32) << 25 >> 22;
    match object & !0x003ffc00 {
        0x910003e0 => {
            if pair & !0x003f8000 != 0xa9007fff
                || pair_offset != offset
                || tail & !0x003ffc00 != 0xf90003ff
                || ((tail >> 10) & 0xfff) as i32 * 8 != offset + 16
            {
                return None;
            }
        }
        0xd10003a0 => {
            let tail_offset = (((tail >> 12) & 511) as i32) << 23 >> 23;
            if pair & !0x003f8000 != 0xa9007fbf
                || pair_offset != -offset
                || tail & !0x001ff000 != 0xf80003bf
                || tail_offset != 16 - offset
            {
                return None;
            }
        }
        _ => return None,
    }
    let cmp = word(code, pos + 4)?;
    let (addresses, bound) = if large {
        let limit = word(code, setup + 12)?;
        if cmp != 0x6b13011f || limit & !0x001fffe0 != 0x52800013 {
            return None;
        }
        (
            [
                address(code, pc, setup + 24, 21)?,
                address(code, pc, setup + 32, 22)?,
                address(code, pc, setup + 40, 23)?,
            ],
            ((limit >> 5) & 0xffff) as usize,
        )
    } else {
        if cmp & !0x003ffc00 != 0x7100011f {
            return None;
        }
        (
            [
                address(code, pc, setup + 12, 19)?,
                address(code, pc, setup + 28, 21)?,
                address(code, pc, setup + 36, 22)?,
            ],
            ((cmp >> 10) & 0xfff) as usize,
        )
    };
    let count = bound + 1;
    if count < 8 || count % 2 != 0 {
        return None;
    }
    Some(ArithmeticTables {
        addresses,
        length: count * 4,
        subtract_address: None,
        permutation: None,
        literal_tail: None,
    })
}

// Validate zero or two constant-folded tail writes and the following allocation.
// Both unrolled permutation forms share this epilogue.
fn permutation_end(
    code: &[u8],
    pos: usize,
    output: u32,
    count: usize,
) -> Option<(usize, Option<[(usize, u8); 2]>)> {
    let mut literal_tail = None;
    if word(code, pos)? & !0x001fffe0 == 0x52800008 {
        let mut tail = [(0, 0); 2];
        for (i, item) in tail.iter_mut().enumerate() {
            let mov = word(code, pos + i * 8)?;
            let store = word(code, pos + 4 + i * 8)?;
            let value = (mov >> 5) & 65535;
            let index = ((store >> 10) & 4095) as usize;
            if mov & !0x001fffe0 != 0x52800008
                || store & !0x003ffc00 != 0x39000008 | output << 5
                || value > 255
                || index >= count + 2
            {
                return None;
            }
            *item = (index, value as u8);
        }
        literal_tail = Some(tail);
    }
    // The next allocation must have the rounded-up string size, bounding the
    // loop output and distinguishing a missing/malformed literal tail.
    let length = count + if literal_tail.is_some() { 2 } else { 0 };
    let next = pos + if literal_tail.is_some() { 16 } else { 0 };
    let alloc = word(code, next)?;
    if alloc & !0x001fffe0 != 0x52800000
        || ((alloc >> 5) & 65535) as usize != (length | 7) + 1
        || word(code, next + 4)? & 0xfc000000 != 0x94000000
    {
        return None;
    }
    Some((length, literal_tail))
}

// Four-way unrolled permutation. Every load, arithmetic operation, output index,
// pointer stride and back edge is checked. No data-dependent code search.
fn permuted_table(code: &[u8], pc: u64, pos: usize) -> Option<ArithmeticTables> {
    let large = match word(code, pos)? {
        0x697f390d => false, // LDPSW X13,X14,[X8,#-8]
        0x697f350c => true,  // LDPSW X12,X13,[X8,#-8]
        _ => return None,
    };
    let output = (word(code, pos + 88)? >> 5) & 31;
    if !matches!(output, 19 | 20 | 22) || (large && output != 22) {
        return None;
    }
    let scratch = word(code, pos + 44)? & 31;
    if !large && (!matches!(scratch, 19 | 21) || scratch == output) {
        return None;
    }
    let small = [
        0x697f390d,
        0xb86d794f,
        0xb86e7950,
        0x68c20111,
        0xb8717941,
        0xb8607942,
        0xb86d7963,
        0xb86e7964,
        0xb8717965,
        0xb8607966,
        0xb86d7987,
        0xb86e7980 | scratch,
        0x4b0301ef,
        0x4a0701ef,
        0xb8717983,
        0x4b040210,
        0x4a000210 | scratch << 16,
        0xb8607984,
        0x4b050021,
        0x4a030021,
        0x4b060042,
        0x4a040042,
        0x382d680f | output << 5,
        0x382e6810 | output << 5,
        0x38316801 | output << 5,
        0x38206802 | output << 5,
        0xf1001129,
        0x54fffca1,
    ];
    let big = [
        0x697f350c, 0xb86c792e, 0xb86d792f, 0x68c24510, 0xb8707920, 0xb8717921, 0xb86c7942,
        0xb86d7943, 0xb8707944, 0xb8717945, 0xb86c7966, 0xb86d7967, 0x4b0201ce, 0x4a0601ce,
        0xb8707962, 0x4b0301ef, 0x4a0701ef, 0xb8717963, 0x4b040000, 0x4a020000, 0x4b050021,
        0x4a030021, 0x382c6ace, 0x382d6acf, 0x38306ac0, 0x38316ac1, 0xf1001294, 0x54fffca1,
    ];
    for (i, expected) in (if large { big } else { small }).into_iter().enumerate() {
        if word(code, pos + i * 4)? != expected {
            return None;
        }
    }
    let (setup, count, addresses) = if large {
        let setup = pos.checked_sub(32)?;
        let count = word(code, setup.checked_sub(12)?)?;
        if count & !0x001fffe0 != 0x52800014
            || word(code, setup - 8)? != (count & !31) | 1
            || word(code, setup - 4)? & 0xfc000000 != 0x94000000
        {
            return None;
        }
        (
            setup,
            ((count >> 5) & 65535) as usize,
            [
                address(code, pc, setup + 8, 9)?,
                address(code, pc, setup + 16, 10)?,
                address(code, pc, setup + 24, 11)?,
            ],
        )
    } else {
        let padding = usize::from(word(code, pos.checked_sub(4)?)? == 0xad000000) * 4;
        let setup = pos.checked_sub(36 + padding)?;
        let count = word(code, setup + 8)?;
        if count & !0x001fffe0 != 0x52800009 {
            return None;
        }
        (
            setup,
            ((count >> 5) & 65535) as usize,
            [
                address(code, pc, setup + 12, 10)?,
                address(code, pc, setup + 20, 11)?,
                address(code, pc, setup + 28, 12)?,
            ],
        )
    };
    if count < 8 || count % 4 != 0 {
        return None;
    }
    let (length, literal_tail) = permutation_end(code, pos + 112, output, count)?;
    let init_distance = if large {
        16
    } else if output == 19 {
        24
    } else if output == 20 {
        20
    } else {
        12
    };
    let init = setup.checked_sub(init_distance)?;
    if word(code, init)? != 0xaa0003e0 | output
        || word(code, init.checked_sub(4)?)? & 0xfc000000 != 0x94000000
        || word(code, init.checked_sub(8)?)? != 0x52800000 | (length as u32) << 5
    {
        return None;
    }
    // Preserve the allocated output pointer through the intervening setup.
    let preserved: &[u32] = match output {
        19 => &[0xd10183b4, 0x6f00e400, 0xad030000, 0xad020000, 0xad010000],
        20 => &[0x6f00e400, 0x3c82c000, 0xad008000, 0x3d800000],
        22 if !large => &[0x52800001 | (length as u32) << 5],
        _ => &[],
    };
    for (i, expected) in preserved.iter().enumerate() {
        if word(code, init + 4 + i * 4)? != *expected {
            return None;
        }
    }
    if output == 22 && !large && word(code, setup - 4)? & 0xfc000000 != 0x94000000 {
        return None;
    }
    Some(ArithmeticTables {
        addresses,
        length: length * 4,
        subtract_address: None,
        permutation: Some(address(code, pc, setup, 8)?.checked_sub(8)?),
        literal_tail,
    })
}

// Four-table checksum fallback. Its complete permutation uses the same index
// for all four sources and the destination, with an optional two-byte tail.
// The allocation immediately after the loop excludes partial traversal cases.
fn four_table(code: &[u8], pc: u64, pos: usize) -> Option<ArithmeticTables> {
    if word(code, pos)? != 0x697f3d0e {
        return None;
    }
    const BODY: [u32; 36] = [
        0x697f3d0e, 0xb86e7950, 0xb86f7951, 0x68c20500, 0xb8607942, 0xb8617943, 0xb86e7964,
        0xb86f7965, 0xb8607966, 0xb8617967, 0xb86e7995, 0xb86f7996, 0x4b040210, 0x4a150210,
        0xb8607984, 0x4b050231, 0x4a160231, 0xb8617985, 0x4b060042, 0x4a040042, 0x4b070063,
        0x4a050063, 0xb86e79a4, 0xb86f79a5, 0xb86079a6, 0xb86179a7, 0x4b040210, 0x4b050231,
        0x4b060042, 0x4b070063, 0x382e6a70, 0x382f6a71, 0x38206a62, 0x38216a63, 0xf1001129,
        0x54fffba1,
    ];
    for (i, expected) in BODY.into_iter().enumerate() {
        if word(code, pos + i * 4)? != expected {
            return None;
        }
    }
    let setup = pos.checked_sub(44)?;
    let count = word(code, setup + 8)?;
    if count & !0x001fffe0 != 0x52800009 {
        return None;
    }
    let count = ((count >> 5) & 65535) as usize;
    if count < 8 || count % 4 != 0 {
        return None;
    }
    let (length, literal_tail) = permutation_end(code, pos + 144, 19, count)?;
    Some(ArithmeticTables {
        addresses: [
            address(code, pc, setup + 12, 10)?,
            address(code, pc, setup + 20, 11)?,
            address(code, pc, setup + 28, 12)?,
        ],
        length: length * 4,
        subtract_address: Some(address(code, pc, setup + 36, 13)?),
        permutation: Some(address(code, pc, setup, 8)?.checked_sub(8)?),
        literal_tail,
    })
}

pub(super) fn tables(code: &[u8], pc: u64) -> Vec<ArithmeticTables> {
    // The caller rejects code >32 KiB and unsuitable section metadata first.
    (0..code.len())
        .step_by(4)
        .filter_map(|pos| {
            table(code, pc, pos)
                .or_else(|| dispatch_table(code, pc, pos))
                .or_else(|| permuted_table(code, pc, pos))
                .or_else(|| four_table(code, pc, pos))
        })
        .take(8)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn candidate_processing_stops_at_eight_complete_loops() {
        let fixture = include_bytes!("../../testdata/macho/amos_arithmetic_tables_universal.macho");
        let code = &fixture[819200 + 0xc98..819200 + 0xcf4];
        let repeated = code.repeat(9);
        assert_eq!(tables(&repeated, 0x100000c98).len(), 8);
        for end in 0..code.len() {
            assert!(tables(&code[..end], 0x100000c98).is_empty());
        }
        assert_eq!(tables(code, 0x100000c98).len(), 1);
        assert!(tables(code, u64::MAX).is_empty());
    }
}
