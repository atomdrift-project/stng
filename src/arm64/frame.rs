//! Small abstract stack model for bounded ARM64 register-preservation checks.
//! Stack slots retain exact values only; any overlapping write invalidates them.
//! Unknown stores fail closed. This is not a general memory emulator.
use crate::arm64;

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
            if opc > 1 && (!vector || scale != 0) {
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
        if inst == arm64::NOP {
            return Some(());
        }
        // B, BL, RET and conditional branches belong to the control-flow driver.
        if inst & 0x7c00_0000 == 0x1400_0000
            || inst == arm64::RET
            || arm64::conditional(inst).is_some()
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
        let writes = crate::arm64::effects::writes(inst)?;
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

/// A path's stack model, and the stack pointer at each inlined call.
#[derive(Clone)]
struct Frame {
    state: State,
    saved_sp: Vec<Value>,
}

impl super::walk::Path for Frame {
    const UNION: bool = false;
    fn step(&mut self, inst: u32) -> Option<()> {
        self.state.step(inst)
    }
    fn enter(&mut self, return_pc: u64) -> Option<()> {
        self.saved_sp.push(self.state.registers[31]);
        self.state.registers[30] = Value::Constant(return_pc);
        Some(())
    }
    /// A return must restore the call's return address and stack pointer.
    fn leave(&mut self, return_pc: u64) -> Option<()> {
        let stack = self.saved_sp.pop()?;
        (self.state.registers[30] == Value::Constant(return_pc)
            && self.state.registers[31] == stack)
            .then_some(())
    }
    fn returned(&self) -> Option<u32> {
        self.state.returned_clobbers()
    }
}

/// The registers a function at `entry` may change, with the stack model
/// proving which ones it saves and restores. Local calls are followed up to
/// four deep; unknown external calls, stores and indirect control flow fail.
pub(crate) fn clobbers(code: &[u8], base: u64, entry: u64) -> Option<u32> {
    let start = Frame {
        state: State::new(),
        saved_sp: Vec::new(),
    };
    super::walk::walk(code, base, entry, start, 4)
}

#[cfg(test)]
mod tests;
