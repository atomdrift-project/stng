//! Complete outlined and inline qword XOR loops with exact consumer lengths.
use super::{Region, branch_target, sequence, word};

#[derive(Debug, PartialEq, Eq)]
pub(super) enum OutputLink {
    // A later copy reads another register. This records an unproven alias
    // relationship, not a prerequisite for recovering the loop's XOR bytes.
    Copied {
        write_register: u32,
        copy_register: u32,
        delta: u64,
    },
    // Both the loop and consumer use the same unmodified frame register.
    Frame,
}
#[derive(Debug)]
pub(super) struct Literal {
    pub cipher: u64,
    pub length: usize,
    #[allow(dead_code)] // Retained for analysis/tests; extraction makes no alias claim.
    pub link: OutputLink,
}
fn target(code: &Region<'_>, pc: u64, opcode: u32) -> Option<u64> {
    let inst = word(code, pc)?;
    if inst & 0xfc000000 != opcode {
        return None;
    }
    pc.checked_add_signed(i64::from(inst & 0x03ffffff) << 38 >> 36)
}
fn called(code: &Region<'_>, pc: u64, body: &[u32]) -> Option<()> {
    sequence(code, branch_target(code, pc)?, body)
}
fn address(code: &Region<'_>, pc: u64) -> Option<u64> {
    let page = word(code, pc)?;
    let low = word(code, pc.checked_add(4)?)?;
    if page & 0x9f00001f != 0x90000008 || low & 0xffc003ff != 0x91000108 {
        return None;
    }
    let delta = i64::from(((page >> 5) & 0x7ffff) << 2 | ((page >> 29) & 3));
    (pc & !4095)
        .checked_add_signed((delta << 43 >> 43) << 12)?
        .checked_add(u64::from((low >> 10) & 0xfff))
}

/// Validate complete constant-input decoding and a following matching length.
/// Copied forms do not establish aliasing into that following consumer.
#[allow(dead_code)]
pub(super) fn read(code: &Region<'_>, start: u64) -> Option<Literal> {
    // Guard arithmetic below once, including all inline instructions.
    start.checked_add(72)?;
    if word(code, start)? == 0x6f00e400 {
        return inline(code, start);
    }
    called(code, start, &[0x6f00e400, 0xad010280, 0xd65f03c0])?;
    let cipher = address(code, start + 4)?.checked_sub(3)?;
    sequence(code, start + 12, &[0x52800069])?;
    called(code, start + 16, &[0xd1000d2a, 0xf1007d5f, 0xd65f03c0])?;
    sequence(code, start + 20, &[0x54000068])?; // B.HI start+32
    called(
        code,
        start + 24,
        &[
            0xf840840a, 0xf85fd10b, 0xca0a016a, 0x8b09026b, 0xf81fd16a, 0x91002129, 0x91002108,
            0xd65f03c0,
        ],
    )?;
    if target(code, start + 28, 0x14000000)? != start + 16 {
        return None;
    }
    let copy = branch_target(code, start + 32)?;
    sequence(code, copy, &[0xad410680])?;
    let store = word(code, copy.checked_add(4)?)?;
    if store & !0x003f8000 != 0xad0007e0 || store & (1 << 21) != 0 {
        return None;
    }
    let stack_offset = ((store >> 15) & 63) * 16;
    sequence(code, copy.checked_add(8)?, &[0xd65f03c0])?;
    let wrapper = branch_target(code, start + 36)?;
    if word(code, wrapper)? & 0xffc003ff != 0x910003e0 {
        return None;
    }
    sequence(
        code,
        wrapper.checked_add(4)?,
        &[0x910003e1 | (stack_offset << 10), 0x52800402],
    )?;
    let consumer = target(code, wrapper.checked_add(12)?, 0x14000000)?;
    word(code, consumer)?;
    Some(Literal {
        cipher,
        length: 32,
        link: OutputLink::Copied {
            write_register: 19,
            copy_register: 20,
            delta: 32,
        },
    })
}
fn inline(code: &Region<'_>, start: u64) -> Option<Literal> {
    // Full 32-byte writes supersede the zero initialization, but the permitted
    // initialization must not modify the key/source/frame registers.
    let zero_store = word(code, start + 4)?;
    if zero_store & !0x003f8000 != 0xad000280 {
        return None;
    }
    let cipher = address(code, start + 8)?.checked_sub(3)?;
    sequence(code, start + 16, &[0x52800069])?;
    let frame = word(code, start + 20)?;
    if frame & 0xffc003ff != 0xd10003aa {
        return None;
    } // SUB X10,X29,#imm
    called(code, start + 24, &[0xd1000d2b, 0xf1007d7f, 0xd65f03c0])?;
    sequence(
        code,
        start + 28,
        &[0x540000e8, 0xf840840b, 0xf85fd10c, 0xca0b018b, 0x8b09014c],
    )?;
    called(
        code,
        start + 48,
        &[0xf81fd18b, 0x91002129, 0x91002108, 0xd65f03c0],
    )?;
    if target(code, start + 52, 0x14000000)? != start + 24 {
        return None;
    }
    sequence(code, start + 56, &[0x910083e0])?;
    if word(code, start + 60)? != (frame & !31) | 1 {
        return None;
    }
    sequence(code, start + 64, &[0x52800402])?;
    let consumer = branch_target(code, start + 68)?;
    word(code, consumer)?;
    Some(Literal {
        cipher,
        length: 32,
        link: OutputLink::Frame,
    })
}
