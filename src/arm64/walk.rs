//! A bounded walk of every path from a function's entry to its return.

use super::{RET, branch_target, conditional, is_b, is_bl, relative, word};
use std::collections::HashSet;

/// Instructions a walk may execute, over all its paths.
pub(crate) const MAX_STEPS: usize = 128;
/// Branches a walk may follow, over all its paths.
pub(crate) const MAX_BRANCHES: usize = 8;
/// Largest code region a walk reads.
const MAX_CODE: usize = 8 * 1024 * 1024;

/// What a walk tracks along one path. Any `None` fails the whole walk.
pub(crate) trait Path: Clone {
    /// Whether a path's contribution is the union of its instructions'
    /// effects. Then the walk merges paths: one that reaches an instruction
    /// already executed in the same call context (a loop, or a join with an
    /// earlier path) ends there, contributing what `returned` reports. A
    /// path-sensitive model sees every path separately, loops exhaust the
    /// step budget, and only paths that return contribute.
    const UNION: bool;

    /// The effect of an instruction that is not a branch, call or return.
    fn step(&mut self, inst: u32) -> Option<()>;
    /// A `BL` whose callee the walk inlines; it returns to `return_pc`.
    fn enter(&mut self, return_pc: u64) -> Option<()>;
    /// The `RET` that ends the innermost inlined call, back to `return_pc`.
    fn leave(&mut self, _return_pc: u64) -> Option<()> {
        Some(())
    }
    /// What a path contributes when it returns from the entry function.
    fn returned(&self) -> Option<u32>;
}

/// Follow every path from `entry` through `code`, which starts at address
/// `base`, to its return, inlining direct calls up to `max_calls` deep, and OR
/// together what the paths contribute. Indirect branches, exhausted budgets
/// and instructions a path rejects fail the walk, as does a walk in which no
/// path returns.
pub(crate) fn walk<P: Path>(
    code: &[u8],
    base: u64,
    entry: u64,
    start: P,
    max_calls: usize,
) -> Option<u32> {
    if base & 3 != 0 || code.len() > MAX_CODE {
        return None;
    }
    let at = |pc: u64| word(code, usize::try_from(pc.checked_sub(base)?).ok()?);
    let mut pending = vec![(entry, start, Vec::<u64>::new())];
    let mut visited: HashSet<(u64, Vec<u64>)> = HashSet::new();
    let (mut steps, mut branches) = (0, 0);
    let (mut result, mut returned) = (0, false);
    while let Some((mut pc, mut path, mut calls)) = pending.pop() {
        loop {
            if P::UNION && !visited.insert((pc, calls.clone())) {
                result |= path.returned()?;
                break;
            }
            steps += 1;
            if steps > MAX_STEPS {
                return None;
            }
            let inst = at(pc)?;
            if inst == RET {
                let Some(return_pc) = calls.pop() else {
                    result |= path.returned()?;
                    returned = true;
                    break;
                };
                path.leave(return_pc)?;
                pc = return_pc;
                continue;
            }
            if is_bl(inst) {
                if calls.len() == max_calls {
                    return None;
                }
                let return_pc = pc.checked_add(4)?;
                path.enter(return_pc)?;
                calls.push(return_pc);
                pc = branch_target(pc, inst)?;
                continue;
            }
            let fork = conditional(inst);
            if is_b(inst) || fork.is_some() {
                branches += 1;
                if branches > MAX_BRANCHES {
                    return None;
                }
            }
            if is_b(inst) {
                pc = branch_target(pc, inst)?;
                continue;
            }
            if let Some((field, width)) = fork {
                pending.push((relative(pc, field, width)?, path.clone(), calls.clone()));
            } else {
                path.step(inst)?;
            }
            pc = pc.checked_add(4)?;
        }
    }
    returned.then_some(result)
}
