//! Small abstract stack model for bounded ARM64 register-preservation checks.
//! Stack slots retain exact values only; any overlapping write invalidates them.
//! Unknown stores fail closed. This is not a general memory emulator.
const MAX_SLOTS: usize = 64;
const STACK_BOUND: i32 = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Value {
    Unknown,
    Initial(u8),
    Stack(i32),
    Constant(u64),
}
#[derive(Clone, Debug)]
struct Slot {
    offset: i32,
    size: u8,
    value: Value,
}
#[derive(Clone, Debug)]
pub(crate) struct State {
    pub(crate) registers: [Value; 32],
    slots: Vec<Slot>,
}
impl State {
    pub(crate) fn new() -> Self {
        let mut registers = std::array::from_fn(|r| Value::Initial(u8::try_from(r).unwrap_or(0)));
        registers[31] = Value::Stack(0);
        Self {
            registers,
            slots: Vec::new(),
        }
    }
    fn reg(&self, r: u32) -> Value {
        if r == 31 {
            Value::Constant(0)
        } else {
            self.registers[r as usize]
        }
    }
    fn put(&mut self, r: u32, value: Value, width: usize) {
        if r == 31 {
            return;
        }
        self.registers[r as usize] = if width == 8 {
            value
        } else {
            match value {
                Value::Constant(v) => Value::Constant(v & ((1u64 << (width * 8)) - 1)),
                _ => Value::Unknown,
            }
        };
    }
    fn add(value: Value, delta: i64) -> Option<Value> {
        Some(match value {
            Value::Stack(v) => {
                let result = i64::from(v).checked_add(delta)?;
                if !(-i64::from(STACK_BOUND)..=i64::from(STACK_BOUND)).contains(&result) {
                    return None;
                }
                Value::Stack(i32::try_from(result).ok()?)
            }
            Value::Constant(v) => Value::Constant(v.wrapping_add_signed(delta)),
            _ if delta == 0 => value,
            _ => Value::Unknown,
        })
    }
    fn range(offset: i32, size: usize) -> Option<i32> {
        let end = offset.checked_add(i32::try_from(size).ok()?)?;
        if offset < -STACK_BOUND || end > STACK_BOUND {
            return None;
        }
        Some(end)
    }
    fn load(&self, address: Value, size: usize) -> Option<Value> {
        let Value::Stack(offset) = address else {
            return Some(Value::Unknown);
        };
        Self::range(offset, size)?;
        Some(
            self.slots
                .iter()
                .find(|s| s.offset == offset && usize::from(s.size) == size)
                .map_or(Value::Unknown, |s| s.value),
        )
    }
    fn store(&mut self, address: Value, size: usize, value: Value) -> Option<()> {
        let Value::Stack(offset) = address else {
            return None;
        };
        let end = Self::range(offset, size)?;
        self.slots
            .retain(|s| s.offset >= end || s.offset + i32::from(s.size) <= offset);
        if value != Value::Unknown {
            if self.slots.len() == MAX_SLOTS {
                return None;
            }
            self.slots.push(Slot {
                offset,
                size: u8::try_from(size).ok()?,
                value,
            });
        }
        Some(())
    }
    fn memory(&mut self, inst: u32) -> Option<()> {
        let rt = inst & 31;
        let rn = (inst >> 5) & 31;
        let vector = inst & (1 << 26) != 0;
        let pair = inst & 0x3a000000 == 0x28000000;
        let (load, size, delta, writeback, post, second) = if pair {
            let opc = inst >> 30;
            if opc == 3 || (!vector && opc == 1) {
                return None;
            }
            let size = if vector {
                4usize << opc
            } else {
                4usize << (opc >> 1)
            };
            let mode = (inst >> 23) & 3;
            let delta = (i64::from((inst >> 15) & 127) << 57 >> 57) * size as i64;
            (
                inst & (1 << 22) != 0,
                size,
                delta,
                matches!(mode, 1 | 3),
                mode == 1,
                Some((inst >> 10) & 31),
            )
        } else {
            let opc = (inst >> 22) & 3;
            let scale = inst >> 30;
            if (!vector && opc > 1) || (vector && opc > 1 && scale != 0) {
                return None;
            }
            let size = if vector && opc > 1 {
                16
            } else {
                1usize << scale
            };
            let unsigned = inst & 0x3b000000 == 0x39000000;
            let mode = (inst >> 10) & 3;
            let (delta, writeback, post) = if unsigned {
                (i64::from((inst >> 10) & 4095) * size as i64, false, false)
            } else {
                // Register-offset and unprivileged forms are deliberately unsupported.
                if inst & (1 << 21) != 0 || mode == 2 {
                    return None;
                }
                (
                    i64::from((inst >> 12) & 511) << 55 >> 55,
                    matches!(mode, 1 | 3),
                    mode == 1,
                )
            };
            (opc & 1 != 0, size, delta, writeback, post, None)
        };
        if !vector
            && ((writeback && rn != 31 && (rn == rt || second == Some(rn)))
                || (load && second == Some(rt)))
        {
            return None;
        }
        let base = self.registers[rn as usize];
        let adjusted = Self::add(base, delta)?;
        let address = if post { base } else { adjusted };
        for (i, r) in [Some(rt), second].into_iter().flatten().enumerate() {
            let at = Self::add(address, (i * size) as i64)?;
            if load {
                let value = self.load(at, size)?;
                if !vector {
                    self.put(r, value, size);
                }
            } else {
                let value = if vector { Value::Unknown } else { self.reg(r) };
                self.store(at, size, value)?;
            }
        }
        if writeback {
            self.registers[rn as usize] = adjusted;
        }
        Some(())
    }
    /// Process one non-control instruction. Calls and branches belong to the
    /// bounded control-flow driver. Failure invalidates the whole analysis.
    pub(crate) fn step(&mut self, inst: u32) -> Option<()> {
        if inst == 0xd503201f {
            return Some(());
        }
        if inst & 0x7c000000 == 0x14000000
            || inst == 0xd65f03c0
            || inst & 0xff000010 == 0x54000000
            || matches!(inst & 0x7e000000, 0x34000000 | 0x36000000)
        {
            return None;
        }
        if matches!(inst & 0x3b000000, 0x39000000 | 0x38000000) || inst & 0x3a000000 == 0x28000000 {
            return self.memory(inst);
        }
        let rd = inst & 31;
        let rn = (inst >> 5) & 31;
        if inst & 0xffe0ffe0 == 0xaa0003e0 {
            self.put(rd, self.reg((inst >> 16) & 31), 8);
            return Some(());
        }
        if inst & 0xbf800000 == 0x91000000 {
            let mut delta = i64::from((inst >> 10) & 4095) << ((inst >> 22 & 1) * 12);
            if inst & (1 << 30) != 0 {
                delta = -delta;
            }
            self.registers[rd as usize] = Self::add(self.registers[rn as usize], delta)?;
            return Some(());
        }
        let writes = crate::arm64_effects::writes(inst)?;
        if writes & (1 << 31) != 0 {
            return None;
        }
        for r in 0..31 {
            if writes & (1 << r) != 0 {
                self.registers[r] = Value::Unknown;
            }
        }
        Some(())
    }
    pub(crate) fn returned_clobbers(&self) -> Option<u32> {
        if self.registers[31] != Value::Stack(0) || self.registers[30] != Value::Initial(30) {
            return None;
        }
        Some((0u8..30).fold(0u32, |mask, r| {
            mask | if self.registers[usize::from(r)] == Value::Initial(r) {
                0
            } else {
                1 << r
            }
        }))
    }
}

/// Bounded local calls share one stack-value model and instruction budget.
/// Every return must restore the call-entry SP and its checked return address.
/// Unknown external calls/stores and indirect control flow remain unsupported.
pub(crate) fn clobbers(code: &[u8], base: u64, entry: u64) -> Option<u32> {
    if base & 3 != 0 || code.len() > 8 * 1024 * 1024 {
        return None;
    }
    let word = |pc: u64| {
        if pc & 3 != 0 {
            return None;
        }
        let at = usize::try_from(pc.checked_sub(base)?).ok()?;
        Some(u32::from_le_bytes(
            code.get(at..at.checked_add(4)?)?.try_into().ok()?,
        ))
    };
    let relative = |pc: u64, bits: u32, width: u32| {
        pc.checked_add_signed(i64::from(bits) << (64 - width) >> (62 - width))
    };
    let mut pending = vec![(entry, State::new(), Vec::<(u64, Value)>::new())];
    let mut steps = 0;
    let mut branches = 0;
    let mut result = 0;
    let mut returned = false;
    while let Some((mut pc, mut state, mut calls)) = pending.pop() {
        loop {
            steps += 1;
            if steps > 128 {
                return None;
            }
            let inst = word(pc)?;
            if inst == 0xd65f03c0 {
                if let Some((return_pc, stack)) = calls.pop() {
                    if state.registers[30] != Value::Constant(return_pc)
                        || state.registers[31] != stack
                    {
                        return None;
                    }
                    pc = return_pc;
                    continue;
                }
                result |= state.returned_clobbers()?;
                returned = true;
                break;
            }
            if inst & 0xfc000000 == 0x94000000 {
                if calls.len() == 4 {
                    return None;
                }
                let return_pc = pc.checked_add(4)?;
                calls.push((return_pc, state.registers[31]));
                state.registers[30] = Value::Constant(return_pc);
                pc = relative(pc, inst & 0x03ffffff, 26)?;
                continue;
            }
            if inst & 0xfc000000 == 0x14000000 {
                branches += 1;
                if branches > 8 {
                    return None;
                }
                pc = relative(pc, inst & 0x03ffffff, 26)?;
                continue;
            }
            let conditional = if inst & 0xff000010 == 0x54000000 || inst & 0x7e000000 == 0x34000000
            {
                Some(((inst >> 5) & 0x7ffff, 19))
            } else if inst & 0x7e000000 == 0x36000000 {
                Some(((inst >> 5) & 0x3fff, 14))
            } else {
                None
            };
            if let Some((bits, width)) = conditional {
                branches += 1;
                if branches > 8 {
                    return None;
                }
                pending.push((relative(pc, bits, width)?, state.clone(), calls.clone()));
            } else {
                state.step(inst)?;
            }
            pc = pc.checked_add(4)?;
        }
    }
    returned.then_some(result)
}
#[cfg(test)]
mod tests;
