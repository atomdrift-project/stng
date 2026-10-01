//! One-iteration qword XOR with ciphertext assembled from immediates and a byte.
use super::{Region, Setup, branch_target, fold, local_seed, sequence, word};

fn read(code: &Region<'_>, constants: &[Region<'_>], start: u64) -> Option<[u8; 8]> {
    start.checked_add(48)?;
    sequence(
        code,
        branch_target(code, start)?,
        &[0xd2800008, 0xd280000c, 0x52800029, 0xd65f03c0],
    )?;
    let mut cipher = 0u64;
    for i in 0u32..4 {
        let w = word(code, start + 4 + u64::from(i) * 4)?;
        let opcode = if i == 0 { 0xd280000a } else { 0xf280000a };
        if w & 0xffe0001f != opcode | (i << 21) {
            return None;
        }
        cipher |= u64::from((w >> 5) & 0xffff) << (i * 16);
    }
    let page = word(code, start + 20)?;
    let low = word(code, start + 24)?;
    if page & 0x9f00001f != 0x9000000b || low & 0xffc003ff != 0x9100016b {
        return None;
    }
    let address = crate::arm64::adrp_add(start + 20, page, low)?;
    // The initializer sets W9=1; the helper clears it. Exactly one iteration.
    sequence(code, start + 28, &[0x36000069])?;
    sequence(
        code,
        branch_target(code, start + 32)?,
        &[
            0x52800009, 0xf86c6808, 0x386c696c, 0xaa0a018c, 0xca080188, 0x5280010c, 0xd65f03c0,
        ],
    )?;
    sequence(code, start + 36, &[0x3707ffe9, 0xf9003be8])?;
    let consumer = branch_target(code, start + 44)?;
    sequence(code, consumer, &[0x910243e0, 0x9101c3e1, 0x52800102])?;
    let tail = word(code, consumer.checked_add(12)?)?;
    if tail & 0xfc000000 != 0x14000000 {
        return None;
    }
    let target = consumer
        .checked_add(12)?
        .checked_add_signed(i64::from(tail & 0x03ffffff) << 38 >> 36)?;
    word(code, target)?;
    let byte = constants.iter().find_map(|r| r.at(address, 1))?[0];
    Some((cipher | u64::from(byte)).to_le_bytes())
}

pub(super) fn extract(
    code: &Region<'_>,
    constants: &[Region<'_>],
    setup: &Setup,
    slice_base: u64,
    min: usize,
) -> Option<crate::ExtractedString> {
    if min > 8 {
        return None;
    }
    let encoded = read(code, constants, setup.after)?;
    let key = fold(code, setup.helper, setup.base, local_seed(code, setup)?)?;
    let key = constants.iter().find_map(|r| r.at(key, 8))?;
    let value = String::from_utf8(encoded.iter().zip(key).map(|(a, b)| a ^ b).collect()).ok()?;
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
        data_len: 48,
        method: crate::StringMethod::XorDecode,
        ..Default::default()
    })
}

#[cfg(test)]
mod tests;
