//! Bounded def/use checks for a constant pointer copied into a call argument.
use super::{decode_arm_mov_immediate, decode_rodata_string};
use crate::arm64::walk::{self, Path};
use crate::arm64::{effects, frame};
const MAX_CODE: usize = 8 * 1024 * 1024;
const MAX_CANDIDATES: usize = 256;
const MAX_HELPERS: usize = 128;
const WINDOW: usize = 32;

/// The registers a path writes, ignoring what it saves and restores.
#[derive(Clone, Copy)]
struct Writes(u32);

impl Path for Writes {
    const UNION: bool = true;
    fn step(&mut self, inst: u32) -> Option<()> {
        self.0 |= effects::writes(inst)?;
        Some(())
    }
    fn enter(&mut self, _return_pc: u64) -> Option<()> {
        // BL writes the link register, X30.
        self.0 |= 1 << 30;
        Some(())
    }
    fn returned(&self) -> Option<u32> {
        Some(self.0)
    }
}

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
        crate::arm64::word(self.code, pc)
    }
    fn target(&self, pc: usize, bits: u32, width: u32) -> Option<usize> {
        let to = crate::arm64::relative(self.addr.checked_add(pc as u64)?, bits, width)?;
        usize::try_from(to.checked_sub(self.addr)?).ok()
    }
    /// The registers the helper at `entry` may change, cached per entry.
    fn helper(&mut self, entry: usize) -> Option<u32> {
        let i = match self.helpers.binary_search_by_key(&entry, |r| r.0) {
            Ok(i) => return self.helpers[i].1,
            Err(i) => i,
        };
        if self.helpers.len() == MAX_HELPERS {
            return None;
        }
        let value = self.summarize(entry);
        self.helpers.insert(i, (entry, value));
        value
    }
    /// Every register the helper at `entry` writes. A framed helper (it moves
    /// SP) that writes callee-saved X19..X28 may only be spilling them, so the
    /// stack model narrows the set; where that model cannot follow, the union
    /// stands.
    fn summarize(&self, entry: usize) -> Option<u32> {
        let address = self.addr.checked_add(entry as u64)?;
        let writes = walk::walk(self.code, self.addr, address, Writes(0), 2)?;
        if writes & (1 << 31) != 0 && writes & 0x1ff8_0000 != 0 {
            return Some(frame::clobbers(self.code, self.addr, address).unwrap_or(writes));
        }
        Some(writes)
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
        if self.attempts >= MAX_CANDIDATES {
            // Counting past the limit marks it reported.
            if self.attempts == MAX_CANDIDATES {
                tracing::debug!(
                    MAX_CANDIDATES,
                    "ARM64 preserved-register strings: attempt limit"
                );
                self.attempts += 1;
            }
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
                let address =
                    crate::arm64::adrp_add(self.addr.checked_add((pc - 4) as u64)?, page, w)?;
                return Some((
                    decode_rodata_string(address, len, data, data_addr)?,
                    address,
                ));
            }
            let writes = if w & 0xfc000000 == 0x94000000 {
                self.helper(self.target(pc, w & 0x03ffffff, 26)?)?
            } else {
                effects::writes(w)?
            };
            if writes & (1 << source) != 0 {
                return None;
            }
            // Returns are not fallthrough paths to this call.
            if w == crate::arm64::RET {
                return None;
            }
        }
        None
    }
}
#[cfg(test)]
mod tests;
