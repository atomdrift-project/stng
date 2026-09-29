//! Bounded def/use checks for a constant pointer copied into a call argument.
use super::{decode_arm_mov_immediate, decode_rodata_string};
use crate::arm64_effects;
const MAX_CODE: usize = 8 * 1024 * 1024;
const MAX_CANDIDATES: usize = 256;
const MAX_HELPERS: usize = 128;
const MAX_WORDS: usize = 128;
const MAX_BRANCHES: usize = 8;
const MAX_DEPTH: usize = 2;
const WINDOW: usize = 32;

pub(super) struct Context<'a> {
    code: &'a [u8],
    addr: u64,
    attempts: usize,
    helpers: Vec<(usize, Option<u32>)>,
}
impl<'a> Context<'a> {
    pub(super) fn new(code: &'a [u8], addr: u64) -> Self {
        Self {
            code,
            addr,
            attempts: 0,
            helpers: Vec::new(),
        }
    }
    fn word(&self, pc: usize) -> Option<u32> {
        if pc & 3 != 0 {
            return None;
        }
        Some(u32::from_le_bytes(
            self.code.get(pc..pc.checked_add(4)?)?.try_into().ok()?,
        ))
    }
    fn target(&self, pc: usize, bits: u32, width: u32) -> Option<usize> {
        let delta = i64::from(bits) << (64 - width) >> (62 - width);
        usize::try_from(
            self.addr
                .checked_add(pc as u64)?
                .checked_add_signed(delta)?
                .checked_sub(self.addr)?,
        )
        .ok()
    }
    fn helper(&mut self, entry: usize) -> Option<u32> {
        match self.helpers.binary_search_by_key(&entry, |r| r.0) {
            Ok(i) => self.helpers[i].1,
            Err(i) => {
                if self.helpers.len() == MAX_HELPERS {
                    return None;
                }
                let mut budget = MAX_WORDS;
                let value = self.summarize(entry, 0, &mut budget).map(|writes| {
                    // Only framed helpers touching saved GPRs need the more precise
                    // stack check. Unsupported stores/calls/paths retain the union result.
                    if writes & (1 << 31) != 0 && writes & 0x1ff80000 != 0 {
                        self.addr
                            .checked_add(entry as u64)
                            .and_then(|address| {
                                crate::arm64_frame::clobbers(self.code, self.addr, address)
                            })
                            .unwrap_or(writes)
                    } else {
                        writes
                    }
                });
                self.helpers.insert(i, (entry, value));
                value
            }
        }
    }
    fn summarize(&self, entry: usize, depth: usize, budget: &mut usize) -> Option<u32> {
        if depth > MAX_DEPTH {
            return None;
        }
        let mut pending = [0usize; MAX_BRANCHES + 1];
        pending[0] = entry;
        let mut pending_len = 1;
        let mut seen = [0usize; MAX_WORDS];
        let mut seen_len = 0;
        let mut branches = 0;
        let mut writes = 0;
        let mut returned = false;
        while pending_len > 0 {
            pending_len -= 1;
            let mut pc = pending[pending_len];
            loop {
                if seen[..seen_len].contains(&pc) {
                    break;
                }
                *budget = budget.checked_sub(1)?;
                if seen_len == seen.len() {
                    return None;
                }
                seen[seen_len] = pc;
                seen_len += 1;
                let w = self.word(pc)?;
                if w == 0xd65f03c0 {
                    returned = true;
                    break;
                }
                writes |= arm64_effects::writes(w)?;
                if w & 0xfc000000 == 0x94000000 {
                    writes |=
                        self.summarize(self.target(pc, w & 0x03ffffff, 26)?, depth + 1, budget)?;
                } else if w & 0xfc000000 == 0x14000000 {
                    branches += 1;
                    if branches > MAX_BRANCHES {
                        return None;
                    }
                    pc = self.target(pc, w & 0x03ffffff, 26)?;
                    continue;
                } else if let Some((bits, width)) = conditional(w) {
                    branches += 1;
                    if branches > MAX_BRANCHES || pending_len == pending.len() {
                        return None;
                    }
                    pending[pending_len] = self.target(pc, bits, width)?;
                    pending_len += 1;
                }
                pc = pc.checked_add(4)?;
            }
        }
        returned.then_some(writes)
    }
    /// Establish a literal on a path from a local ADRP/ADD to a pointer copy.
    /// This does not claim that the call executes or that every incoming path
    /// uses this value. Intervening instructions and called helpers must leave
    /// the source register untouched; unsupported effects fail closed.
    pub(super) fn recover(
        &mut self,
        call: usize,
        data: &[u8],
        data_addr: u64,
        min: usize,
    ) -> Option<(String, u64)> {
        if self.code.len() > MAX_CODE
            || self.addr & 3 != 0
            || call < 8
            || min > 1000
            || self.word(call)? & 0xfc000000 != 0x94000000
        {
            return None;
        }
        let mov = self.word(call - 8)?;
        let length = self.word(call - 4)?;
        if mov & 0xffe0ffe0 != 0xaa0003e0 {
            return None;
        }
        let argument = mov & 31;
        let source = (mov >> 16) & 31;
        if argument >= 7 || !(19..=28).contains(&source) || length & 31 != argument + 1 {
            return None;
        }
        let len = decode_arm_mov_immediate(length)?;
        if len < min as u64 || len == 0 || len > 1000 {
            return None;
        }
        if self.attempts == MAX_CANDIDATES {
            return None;
        }
        self.attempts += 1;
        let end = call - 8;
        let begin = end.saturating_sub(WINDOW * 4);
        let mut pc = end;
        while pc >= begin + 4 {
            pc -= 4;
            let w = self.word(pc)?;
            if w & 0xffc003ff == 0x91000000 | (source << 5) | source && pc >= 4 {
                let page = self.word(pc - 4)?;
                if page & 0x9f00001f != 0x90000000 | source {
                    return None;
                }
                // Unconditional branches must stay in the checked interval.
                for at in (pc + 4..end).step_by(4) {
                    let branch = self.word(at)?;
                    if branch & 0xfc000000 == 0x14000000 {
                        let target = self.target(at, branch & 0x03ffffff, 26)?;
                        if !(pc + 4..=end).contains(&target) {
                            return None;
                        }
                    }
                }
                let delta = i64::from(((page >> 5) & 0x7ffff) << 2 | ((page >> 29) & 3));
                let address = (self.addr.checked_add((pc - 4) as u64)? & !4095)
                    .checked_add_signed((delta << 43 >> 43) << 12)?
                    .checked_add(u64::from((w >> 10) & 4095))?;
                return Some((
                    decode_rodata_string(address, len, data, data_addr)?,
                    address,
                ));
            }
            let writes = if w & 0xfc000000 == 0x94000000 {
                self.helper(self.target(pc, w & 0x03ffffff, 26)?)?
            } else {
                arm64_effects::writes(w)?
            };
            if writes & (1 << source) != 0 {
                return None;
            }
            // Returns are not fallthrough paths to this call.
            if w == 0xd65f03c0 {
                return None;
            }
        }
        None
    }
}
fn conditional(w: u32) -> Option<(u32, u32)> {
    if w & 0xff000010 == 0x54000000 || w & 0x7e000000 == 0x34000000 {
        Some(((w >> 5) & 0x7ffff, 19))
    } else if w & 0x7e000000 == 0x36000000 {
        Some(((w >> 5) & 0x3fff, 14))
    } else {
        None
    }
}
#[cfg(test)]
mod tests;
