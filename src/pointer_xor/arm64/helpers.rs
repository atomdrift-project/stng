//! Conservative write summaries of bounded, call-free outlined helpers.
use super::{Region, effects, word};
const MAX_WORDS: usize = 128;
const MAX_BRANCHES: usize = 8;

fn relative(pc: u64, bits: u32, width: u32) -> Option<u64> {
    let delta = i64::from(bits) << (64 - width) >> (62 - width);
    pc.checked_add_signed(delta)
}

/// Union writes across all reachable instructions, including both sides of
/// conditional branches. This proves only that unlisted registers are untouched
/// on return; it does not resolve values or recognize framed save/restore calls.
/// Calls, unsupported instructions, unmapped targets and exhausted budgets fail.
#[allow(dead_code)] // Connected with the caller-state solver.
pub(super) fn clobbers(code: &Region<'_>, entry: u64) -> Option<u32> {
    let mut pending = [0; MAX_BRANCHES + 1];
    pending[0] = entry;
    let mut pending_len = 1;
    let mut visited = [0; MAX_WORDS];
    let mut visited_len = 0;
    let mut branches = 0;
    let mut result = 0;
    let mut returned = false;
    while pending_len > 0 {
        pending_len -= 1;
        let mut pc = pending[pending_len];
        loop {
            if visited[..visited_len].contains(&pc) {
                break;
            }
            if visited_len == MAX_WORDS {
                return None;
            }
            visited[visited_len] = pc;
            visited_len += 1;
            let inst = word(code, pc)?;
            if inst == 0xd65f03c0 {
                returned = true;
                break;
            }
            if inst & 0xfc000000 == 0x94000000 {
                return None;
            }
            result |= effects::writes(inst)?;
            if inst & 0xfc000000 == 0x14000000 {
                branches += 1;
                if branches > MAX_BRANCHES {
                    return None;
                }
                pc = relative(pc, inst & 0x03ffffff, 26)?;
                continue;
            }
            let conditional = if inst & 0xff000010 == 0x54000000 || inst & 0x7e000000 == 0x34000000
            {
                Some(relative(pc, (inst >> 5) & 0x7ffff, 19)?)
            } else if inst & 0x7e000000 == 0x36000000 {
                Some(relative(pc, (inst >> 5) & 0x3fff, 14)?)
            } else {
                None
            };
            if let Some(target) = conditional {
                branches += 1;
                if branches > MAX_BRANCHES || pending_len == pending.len() {
                    return None;
                }
                pending[pending_len] = target;
                pending_len += 1;
            }
            pc = pc.checked_add(4)?;
        }
    }
    returned.then_some(result)
}

const MAX_SUMMARIES: usize = 1024;

/// A per-code-region cache: unknown results are retained too, and saturation
/// returns unknown without evaluating more helpers. Sorted entries keep lookups
/// bounded without a per-entry allocation or an external hashing dependency.
#[allow(dead_code)]
pub(super) struct Cache<'a, 'data> {
    code: &'a Region<'data>,
    entries: Vec<(u64, Option<u32>)>,
}
#[allow(dead_code)]
impl<'a, 'data> Cache<'a, 'data> {
    pub(super) fn new(code: &'a Region<'data>) -> Self {
        Self {
            code,
            entries: Vec::new(),
        }
    }
    pub(super) fn get(&mut self, entry: u64) -> Option<u32> {
        match self.entries.binary_search_by_key(&entry, |row| row.0) {
            Ok(index) => self.entries[index].1,
            Err(index) => {
                if self.entries.len() == MAX_SUMMARIES {
                    return None;
                }
                let value = clobbers(self.code, entry);
                self.entries.insert(index, (entry, value));
                value
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn run(words: &[u32]) -> Option<u32> {
        let bytes: Vec<_> = words.iter().flat_map(|x| x.to_le_bytes()).collect();
        clobbers(
            &Region {
                addr: 0x1000,
                offset: 0,
                bytes: &bytes,
            },
            0x1000,
        )
    }
    #[test]
    fn all_independently_reviewed_leaf_summaries_match() {
        let code = super::super::tests::code();
        let rows = include_bytes!("../../../testdata/macho/rust_arm64_helper_writes.bin");
        assert_eq!(rows.len() % 12, 0);
        assert!(rows.len() / 12 > 650);
        for row in rows.chunks_exact(12) {
            let entry = u64::from_le_bytes([
                row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7],
            ]);
            let mask = u32::from_le_bytes([row[8], row[9], row[10], row[11]]);
            assert_eq!(clobbers(&code, entry), Some(mask), "helper {entry:x}");
        }
    }
    #[test]
    fn conditional_paths_and_tail_branches_are_both_followed() {
        // B.EQ path2; MOV W19,#0; B done; MOV W20,#0; RET.
        assert_eq!(
            run(&[0x54000060, 0x52800013, 0x14000002, 0x52800014, 0xd65f03c0]),
            Some((1 << 19) | (1 << 20))
        );
        for branch in [0x34000060, 0x35000060, 0xb4000060, 0x36000060, 0x37000060] {
            assert_eq!(
                run(&[branch, 0x52800013, 0x14000002, 0x52800014, 0xd65f03c0]),
                Some((1 << 19) | (1 << 20))
            );
        }
        // A backward edge is visited once; its writes cannot be missed.
        assert_eq!(run(&[0x52800013, 0x35ffffe0, 0xd65f03c0]), Some(1 << 19));
        assert_eq!(run(&[0x14000000]), None); // no returning path
    }
    #[test]
    fn unknown_instructions_and_calls_on_either_path_reject() {
        for bad in [
            0, 0xffffffff, 0x94000000, 0xd63f0000, 0xd61f0000, 0xd4000001,
        ] {
            assert_eq!(run(&[0x54000040, 0xd65f03c0, bad, 0xd65f03c0]), None);
            assert_eq!(run(&[0x54000040, bad, 0xd65f03c0]), None);
        }
    }
    #[test]
    fn branch_instruction_and_address_limits_fail_closed() {
        let mut exact = vec![0x52800008; MAX_WORDS - 1];
        exact.push(0xd65f03c0);
        assert_eq!(run(&exact), Some(1 << 8));
        exact.insert(0, 0x52800008);
        assert_eq!(run(&exact), None);
        let mut branches = vec![0x14000001; MAX_BRANCHES];
        branches.push(0xd65f03c0);
        assert_eq!(run(&branches), Some(0));
        branches.insert(0, 0x14000001);
        assert_eq!(run(&branches), None);
        for words in [
            &[][..],
            &[0x14000002],
            &[0x17ffffff],
            &[0x54000040, 0xd65f03c0],
        ] {
            assert_eq!(run(words), None);
        }
        let bytes = 0xd65f03c0u32.to_le_bytes();
        assert_eq!(
            clobbers(
                &Region {
                    addr: 0x1000,
                    offset: 0,
                    bytes: &bytes
                },
                0x1001
            ),
            None
        );
        assert_eq!(relative(0, 0x03ffffff, 26), None);
        assert_eq!(relative(u64::MAX - 3, 1, 26), None);
    }
    #[test]
    fn introduced_saved_register_writes_are_never_reported_as_preserved() {
        let original = super::super::tests::code();
        let mut bytes = original.bytes.to_vec();
        for row in
            include_bytes!("../../../testdata/macho/rust_arm64_helper_writes.bin").chunks_exact(12)
        {
            let entry = u64::from_le_bytes([
                row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7],
            ]);
            let at = (entry - original.addr) as usize;
            let saved = [bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]];
            bytes[at..at + 4].copy_from_slice(&0x52800016u32.to_le_bytes()); // MOV W22,#0
            let mutated = Region {
                addr: original.addr,
                offset: 0,
                bytes: &bytes,
            };
            if let Some(mask) = clobbers(&mutated, entry) {
                assert_ne!(mask & (1 << 22), 0, "{entry:x}");
            }
            bytes[at..at + 4].copy_from_slice(&saved);
        }
    }
    #[test]
    fn cache_reuses_known_and_unknown_results_and_stops_at_capacity() {
        let bytes = 0xd65f03c0u32.to_le_bytes();
        let code = Region {
            addr: 0x1000,
            offset: 0,
            bytes: &bytes,
        };
        let mut cache = Cache::new(&code);
        assert_eq!(cache.get(0x1000), Some(0));
        assert_eq!(cache.entries.len(), 1);
        for _ in 0..100 {
            assert_eq!(cache.get(0x1000), Some(0));
            assert_eq!(cache.get(0x1004), None);
        }
        assert_eq!(cache.entries.len(), 2);
        for i in 2..MAX_SUMMARIES {
            assert_eq!(cache.get(0x1000 + i as u64 * 4), None);
        }
        assert_eq!(cache.entries.len(), MAX_SUMMARIES);
        assert_eq!(cache.get(0), None);
        assert_eq!(cache.entries.len(), MAX_SUMMARIES);
        assert_eq!(cache.get(0x1000), Some(0));
    }
    #[test]
    fn reviewed_allocation_size_helper_reports_its_saved_register_write() {
        let code = super::super::tests::code();
        // MOV X19,X0; ADD/SUB/NEG/AND; UMULH X9,X8,X1; CMP; RET.
        // The helper changes X19 and must never be treated as preserving it.
        assert_eq!(
            clobbers(&code, 0x1001b5ac0),
            Some((1 << 19) | (1 << 8) | (1 << 9))
        );
    }
}
