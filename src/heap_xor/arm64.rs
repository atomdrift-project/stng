//! ARM64 immediate arrays and a complete checked-index byte XOR loop.
use super::{MAX_ARRAY, MAX_CANDIDATES, MAX_CODE};
struct Code<'a> {
    bytes: &'a [u8],
    addr: u64,
}
impl Code<'_> {
    fn word(&self, pos: usize) -> Option<u32> {
        if pos & 3 != 0 {
            return None;
        }
        Some(u32::from_le_bytes(
            self.bytes.get(pos..pos.checked_add(4)?)?.try_into().ok()?,
        ))
    }
    fn at(&self, addr: u64) -> Option<usize> {
        usize::try_from(addr.checked_sub(self.addr)?).ok()
    }
    fn call(&self, pos: usize) -> Option<usize> {
        let w = self.word(pos)?;
        if w & 0xfc000000 != 0x94000000 {
            return None;
        }
        let pc = self.addr.checked_add(pos as u64)?;
        self.at(pc.checked_add_signed(i64::from(w & 0x03ffffff) << 38 >> 36)?)
    }
    fn seq(&self, pos: usize, words: &[u32]) -> Option<()> {
        for (i, w) in words.iter().enumerate() {
            if self.word(pos.checked_add(i * 4)?)? != *w {
                return None;
            }
        }
        Some(())
    }
}
fn preserved(r: u32) -> bool {
    (19..=28).contains(&r)
}
struct Array {
    bytes: Vec<u8>,
    base: u32,
    counter: Option<u32>,
    allocator: usize,
}
fn array(code: &Code<'_>, pos: &mut usize, min: usize, first: Option<u32>) -> Option<Array> {
    let size = code.word(*pos)?;
    if size & 0xffe0001f != 0x52800000 {
        return None;
    }
    let len = ((size >> 5) & 0xffff) as usize;
    if len == 0 || len < min || len > MAX_ARRAY {
        return None;
    }
    let allocator = code.call(pos.checked_add(4)?)?;
    code.seq(allocator, &[0x52800021])?;
    let tail = code.word(allocator.checked_add(4)?)?;
    if tail & 0xfc000000 != 0x14000000 {
        return None;
    }
    let target = code
        .addr
        .checked_add(allocator as u64)?
        .checked_add(4)?
        .checked_add_signed(i64::from(tail & 0x03ffffff) << 38 >> 36)?;
    code.word(code.at(target)?)?;
    *pos = pos.checked_add(8)?;
    let save = code.word(*pos)?;
    let (base, counter) = if first.is_none() {
        if save & !31 != 0xaa0003e0 || !preserved(save & 31) {
            return None;
        }
        (save & 31, None)
    } else {
        let helper = code.call(*pos)?;
        let mov = code.word(helper)?;
        let zero = code.word(helper.checked_add(4)?)?;
        if mov & !31 != 0xaa0003e0 || zero & !31 != 0xd2800000 {
            return None;
        }
        code.seq(helper.checked_add(8)?, &[0xd65f03c0])?;
        let (base, counter) = (mov & 31, zero & 31);
        if !preserved(base)
            || !preserved(counter)
            || base == counter
            || first == Some(base)
            || first == Some(counter)
        {
            return None;
        }
        (base, Some(counter))
    };
    *pos = pos.checked_add(4)?;
    let mut values = [None; 2];
    let mut bytes = Vec::with_capacity(len);
    let mut side_addresses = 0;
    for _ in 0..len.checked_mul(2)?.checked_add(8)? {
        if bytes.len() == len {
            return Some(Array {
                bytes,
                base,
                counter,
                allocator,
            });
        }
        let w = code.word(*pos)?;
        *pos = pos.checked_add(4)?;
        let reg = w & 31;
        if w & 0x1f800000 == 0x12800000 {
            if !(8..=9).contains(&reg) {
                return None;
            }
            let width = if w >> 31 == 0 { 32 } else { 64 };
            let shift = ((w >> 21) & 3) * 16;
            if shift >= width {
                return None;
            }
            let imm = u64::from((w >> 5) & 0xffff) << shift;
            let slot = &mut values[(reg - 8) as usize];
            let value = match (w >> 29) & 3 {
                0 => !imm,
                2 => imm,
                3 => (slot.as_ref().copied()? & !(0xffffu64 << shift)) | imm,
                _ => return None,
            };
            *slot = Some(if width == 32 {
                value & 0xffffffff
            } else {
                value
            });
            continue;
        }
        if w & 0xffc003e0 == 0x910003e0 {
            if side_addresses == 1
                || !preserved(reg)
                || reg == base
                || first == Some(reg)
                || counter == Some(reg)
            {
                return None;
            }
            side_addresses += 1;
            continue;
        }
        let (offset, width, second) = if w & 0xffc003e0 == 0xa9000000 {
            let imm = (w >> 15) & 127;
            if imm & 64 != 0 {
                return None;
            }
            (imm as usize * 8, 8, Some((w >> 10) & 31))
        } else if w & 0x3fc003e0 == 0x39000000 {
            let width = 1usize << ((w >> 30) & 3);
            (((w >> 10) & 0xfff) as usize * width, width, None)
        } else {
            return None;
        };
        let total = width * if second.is_some() { 2 } else { 1 };
        if offset != bytes.len() || offset.checked_add(total)? > len || !(8..=9).contains(&reg) {
            return None;
        }
        bytes.extend_from_slice(&values[(reg - 8) as usize]?.to_le_bytes()[..width]);
        if let Some(reg) = second {
            if !(8..=9).contains(&reg) {
                return None;
            }
            bytes.extend_from_slice(&values[(reg - 8) as usize]?.to_le_bytes()[..width]);
        }
    }
    (bytes.len() == len).then_some(Array {
        bytes,
        base,
        counter,
        allocator,
    })
}
fn decode(code: &Code<'_>, start: usize, min: usize) -> Option<(String, u32)> {
    let mut pos = start;
    let a = array(code, &mut pos, min, None)?;
    let b = array(code, &mut pos, min, Some(a.base))?;
    if a.allocator != b.allocator || a.bytes.len() != b.bytes.len() {
        return None;
    }
    let count = b.counter?;
    let desc = code.word(pos)?;
    let desc_reg = desc & 31;
    if desc & 0x9f000000 != 0x90000000
        || !preserved(desc_reg)
        || [a.base, b.base, count].contains(&desc_reg)
    {
        return None;
    }
    let add = code.word(pos.checked_add(4)?)?;
    if add & 0xffc003ff != 0x91000000 | (desc_reg << 5) | desc_reg {
        return None;
    }
    pos = pos.checked_add(8)?;
    let begin = pos;
    begin.checked_add(56)?;
    let cmp = code.word(pos)?;
    if cmp & 0xff8003ff != 0xf100001f | (count << 5)
        || (((cmp >> 10) & 0xfff) << (((cmp >> 22) & 1) * 12)) as usize != a.bytes.len()
    {
        return None;
    }
    code.seq(pos + 4, &[0x540001a0, 0xaa0003e0 | (a.base << 16)])?;
    let length = 0x52800001 | ((a.bytes.len() as u32) << 5);
    code.seq(pos + 12, &[length])?;
    let args = code.call(pos + 16)?;
    code.seq(
        args,
        &[
            0xaa0003e2 | (count << 16),
            0xaa0003e3 | (desc_reg << 16),
            0xd65f03c0,
        ],
    )?;
    let index = code.call(pos + 20)?;
    // The out-of-range branch is unreachable for the verified 0..length loop.
    code.seq(index, &[0xeb01005f, 0x54000062, 0x8b020000, 0xd65f03c0])?;
    let load = code.word(pos + 24)?;
    let value = load & 31;
    if load & !31 != 0x39400000
        || value < 4
        || value >= 30
        || [a.base, b.base, count, desc_reg].contains(&value)
    {
        return None;
    }
    code.seq(pos + 28, &[0xaa0003e0 | (b.base << 16), length])?;
    if code.call(pos + 36)? != args || code.call(pos + 40)? != index {
        return None;
    }
    let xor = code.call(pos + 44)?;
    let read = code.word(xor)?;
    let temp = read & 31;
    if read & !31 != 0x39400000
        || temp == 0
        || temp >= 30
        || [a.base, b.base, count, desc_reg, value].contains(&temp)
    {
        return None;
    }
    code.seq(
        xor + 4,
        &[
            0x4a000000 | (value << 16) | (temp << 5) | temp,
            0x39000000 | temp,
            0xd65f03c0,
        ],
    )?;
    code.seq(pos + 48, &[0x91000400 | (count << 5) | count, 0x17fffff3])?;
    let value =
        String::from_utf8(a.bytes.iter().zip(b.bytes).map(|(x, y)| x ^ y).collect()).ok()?;
    if !value
        .chars()
        .all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
    {
        return None;
    }
    Some((
        value,
        u32::try_from(begin.checked_add(56)?.checked_sub(start)?).ok()?,
    ))
}

pub(super) fn extract(
    bytes: &[u8],
    addr: u64,
    offset: u64,
    slice_base: u64,
    min: usize,
) -> Vec<crate::ExtractedString> {
    if bytes.len() > MAX_CODE || addr & 3 != 0 || min > MAX_ARRAY {
        return Vec::new();
    }
    let code = Code { bytes, addr };
    let mut out = Vec::new();
    // MOV X19..X28,X0, preceded by MOV W0,#size; BL allocation thunk.
    let candidates = memchr::memmem::find_iter(bytes, b"\x03\x00\xaa")
        .filter_map(|hit| {
            let save = hit.checked_sub(1)?;
            let start = save.checked_sub(8)?;
            let w = code.word(save)?;
            let size = code.word(start)?;
            (w & !31 == 0xaa0003e0 && preserved(w & 31) && size & 0xffe0001f == 0x52800000)
                .then_some(start)
        })
        .take(MAX_CANDIDATES);
    for start in candidates {
        let Some((value, len)) = decode(&code, start, min) else {
            continue;
        };
        let Some(data_offset) = slice_base
            .checked_add(offset)
            .and_then(|n| n.checked_add(start as u64))
        else {
            continue;
        };
        out.push(crate::ExtractedString {
            kind: crate::classify_string(&value),
            value,
            data_offset,
            data_len: len,
            method: crate::StringMethod::XorDecode,
            ..Default::default()
        });
    }
    out
}
#[cfg(test)]
mod tests;
