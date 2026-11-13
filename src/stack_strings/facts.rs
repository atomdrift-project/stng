//! Straight-line register and frame-slot facts for stack-string recovery.
//!
//! Some builders never store a character immediate. Unoptimised code
//! computes each character into a register and stores it through a pointer
//! it reloads from a global or a frame slot every time (Dofoil's crypter
//! stub builds `interface\{3050F557-…}` so):
//!
//! ```text
//! mov dword [ebp-4], 0
//! mov eax, [ebp-4]          ; eax = 0
//! add eax, 0x69             ; eax = 'i'
//! mov ecx, [0x4090a4]       ; ecx = *global
//! mov word [ecx], ax        ; L"i" at (*global)+0
//! ```
//!
//! [`Facts`] follows just enough of this within one straight-line block:
//! constant register values (`mov`, `add`/`sub`/`xor`/`or`/`and`, `inc`,
//! `dec`), frame slots holding constants, and which registers hold a
//! pointer loaded from the same location, so the stores through them group
//! as one buffer. Anything it does not model forgets what it overwrites,
//! and the caller clears it at every branch. A store through some other
//! pointer is assumed not to alias a frame slot or a pointer's source.

use iced_x86::{Instruction, Mnemonic, OpKind, Register};

/// Frame slots with known values tracked at once; more are forgotten.
const MAX_LOCALS: usize = 32;
/// Pointer sources tracked at once; past this, loads give no shared base.
const MAX_SOURCES: usize = 16;

/// What a store's address is relative to: the key that groups the writes
/// into one buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Base {
    /// A register the scan knows nothing about, frame registers included.
    Reg(Register),
    /// A pointer loaded from `from`; `epoch` changes whenever a store may
    /// have replaced the pointer there.
    Loaded { from: Slot, epoch: u32 },
}

/// A memory location a pointer is loaded from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Slot {
    /// An absolute (i386) or RIP-relative (x86-64) address.
    Global(u64),
    /// `[frame + disp]`, `frame` being the full RBP or RSP.
    Frame(Register, i64),
}

impl Slot {
    /// The slot that `instr`'s memory operand names, if it is one.
    fn of(instr: &Instruction) -> Option<Self> {
        if instr.memory_index() != Register::None || instr.segment_prefix() != Register::None {
            return None;
        }
        let base = instr.memory_base();
        let disp = instr.memory_displacement64();
        match base {
            Register::None | Register::RIP | Register::EIP => Some(Self::Global(disp)),
            _ if is_frame(base) => Some(Self::Frame(base.full_register(), disp.cast_signed())),
            _ => None,
        }
    }

    /// Whether `len` bytes at `self` overlap `other_len` bytes at `other`.
    fn overlaps(self, len: usize, other: Self, other_len: usize) -> bool {
        let (a, b) = match (self, other) {
            (Self::Global(a), Self::Global(b)) => (a.cast_signed(), b.cast_signed()),
            (Self::Frame(r, a), Self::Frame(s, b)) if r == s => (a, b),
            _ => return false,
        };
        let end = |at: i64, n: usize| at.saturating_add(i64::try_from(n).unwrap_or(i64::MAX));
        a < end(b, other_len) && b < end(a, len)
    }
}

/// A frame slot holding a known constant.
#[derive(Debug, Clone, Copy)]
struct Local {
    frame: Register,
    disp: i64,
    size: usize,
    value: u64,
}

/// Register and memory facts for the current straight-line block.
#[derive(Debug, Default)]
pub(super) struct Facts {
    /// Constant values of RAX..R15, indexed by [`gpr`].
    values: [Option<u64>; 16],
    /// Pointer origins of RAX..R15, indexed by [`gpr`].
    bases: [Option<Base>; 16],
    locals: Vec<Local>,
    /// Where this block's [`Base::Loaded`] pointers came from.
    sources: Vec<Slot>,
    epoch: u32,
}

/// The index of `r`'s full register among RAX..R15, or `None` for a
/// register that is not a general-purpose one.
fn gpr(r: Register) -> Option<usize> {
    (r.full_register() as usize)
        .checked_sub(Register::RAX as usize)
        .filter(|&i| i < 16)
}

/// Whether `r` addresses the frame: (E/R)BP or (E/R)SP.
fn is_frame(r: Register) -> bool {
    matches!(r.full_register(), Register::RBP | Register::RSP)
}

/// Whether `r` is one of the legacy high-byte registers (AH, CH, DH, BH).
fn is_high_byte(r: Register) -> bool {
    matches!(r, Register::AH | Register::CH | Register::DH | Register::BH)
}

/// The mask of a `size`-byte value.
fn mask(size: usize) -> u64 {
    match size {
        0 => 0,
        1..=7 => (1u64 << (size * 8)) - 1,
        _ => u64::MAX,
    }
}

impl Facts {
    /// Forget everything: a branch target or call may follow.
    pub(super) fn clear(&mut self) {
        self.values = [None; 16];
        self.bases = [None; 16];
        self.locals.clear();
        self.sources.clear();
    }

    /// `r`'s value, if it is a known constant.
    pub(super) fn value(&self, r: Register) -> Option<u64> {
        let v = self.values[gpr(r)?]?;
        Some(if is_high_byte(r) {
            (v >> 8) & 0xff
        } else {
            v & mask(r.size())
        })
    }

    /// What `instr`'s memory operand is relative to.
    pub(super) fn base(&self, instr: &Instruction) -> Base {
        let base = instr.memory_base();
        if instr.memory_index() == Register::None
            && let Some(loaded) = gpr(base).and_then(|i| self.bases[i])
        {
            return loaded;
        }
        Base::Reg(base)
    }

    /// The value `instr` stores from operand 1, if it is a known constant.
    pub(super) fn stored_value(&self, instr: &Instruction) -> Option<u64> {
        match instr.op1_kind() {
            OpKind::Register => self.value(instr.op1_register()),
            _ => instr.try_immediate(1).ok(),
        }
    }

    /// Record what `instr` does to registers and memory. Call it after the
    /// stores it makes are recorded, since those read the facts before it.
    pub(super) fn update(&mut self, instr: &Instruction, bits: u32) {
        let mnemonic = instr.mnemonic();
        if matches!(mnemonic, Mnemonic::Cmp | Mnemonic::Test | Mnemonic::Bt) {
            return;
        }
        if implicitly_writes(mnemonic) {
            self.values = [None; 16];
            self.bases = [None; 16];
            self.locals.clear();
            self.forget_sources(|_| true);
            return;
        }
        if instr.op_count() == 0 {
            return;
        }
        let op0 = instr.op0_kind();
        if op0 == OpKind::Memory && mnemonic != Mnemonic::Push {
            let value = if mnemonic == Mnemonic::Mov {
                self.stored_value(instr)
            } else {
                None
            };
            self.store(instr, value);
        }
        if moves_stack_pointer(instr) {
            self.locals.retain(|l| l.frame != Register::RSP);
            self.forget_sources(|s| matches!(s, Slot::Frame(Register::RSP, _)));
        }
        if op0 != OpKind::Register || mnemonic == Mnemonic::Push {
            return;
        }
        let dst = instr.op0_register();
        let Some(i) = gpr(dst) else { return };
        let (value, base) = match (mnemonic, instr.op1_kind()) {
            (Mnemonic::Mov, OpKind::Memory) => self.load(instr, bits),
            (Mnemonic::Mov, OpKind::Register) => {
                let src = instr.op1_register();
                let ptr = usize::try_from(bits / 8).unwrap_or(0);
                let base = gpr(src)
                    .filter(|_| dst.size() == ptr && src.size() == ptr)
                    .and_then(|s| self.bases[s]);
                (self.value(src), base)
            }
            (Mnemonic::Mov, _) => (self.stored_value(instr), None),
            (Mnemonic::Xor | Mnemonic::Sub, OpKind::Register) if instr.op1_register() == dst => {
                (Some(0), None)
            }
            (Mnemonic::Add | Mnemonic::Sub | Mnemonic::Xor | Mnemonic::Or | Mnemonic::And, _) => {
                let fold = |a: u64, b: u64| match mnemonic {
                    Mnemonic::Add => a.wrapping_add(b),
                    Mnemonic::Sub => a.wrapping_sub(b),
                    Mnemonic::Xor => a ^ b,
                    Mnemonic::Or => a | b,
                    _ => a & b,
                };
                let value = self
                    .value(dst)
                    .zip(self.stored_value(instr))
                    .map(|(a, b)| fold(a, b));
                (value, None)
            }
            (Mnemonic::Inc, _) => (self.value(dst).map(|v| v.wrapping_add(1)), None),
            (Mnemonic::Dec, _) => (self.value(dst).map(|v| v.wrapping_sub(1)), None),
            _ => (None, None),
        };
        self.set(dst, value);
        self.bases[i] = base;
    }

    /// `mov dst, [mem]`: the frame slot's constant, and, for a pointer-sized
    /// load from a slot, the shared base its stores group under.
    fn load(&mut self, instr: &Instruction, bits: u32) -> (Option<u64>, Option<Base>) {
        let Some(slot) = Slot::of(instr) else {
            return (None, None);
        };
        let size = instr.memory_size().size();
        let value = match slot {
            Slot::Frame(frame, disp) => self
                .locals
                .iter()
                .rev()
                .find(|l| l.frame == frame && l.disp == disp && size <= l.size)
                .map(|l| l.value & mask(size)),
            Slot::Global(_) => None,
        };
        let ptr = usize::try_from(bits / 8).unwrap_or(0);
        if size != ptr {
            return (value, None);
        }
        if !self.sources.contains(&slot) {
            if self.sources.len() >= MAX_SOURCES {
                return (value, None);
            }
            self.sources.push(slot);
        }
        let base = Base::Loaded {
            from: slot,
            epoch: self.epoch,
        };
        (value, Some(base))
    }

    /// A store of `value` (when known) to `instr`'s memory operand.
    fn store(&mut self, instr: &Instruction, value: Option<u64>) {
        let Some(slot) = Slot::of(instr) else { return };
        let size = instr.memory_size().size();
        // A pointer is at most eight bytes wide.
        self.forget_sources(|s| slot.overlaps(size, s, 8));
        let Slot::Frame(frame, disp) = slot else {
            return;
        };
        self.locals
            .retain(|l| !slot.overlaps(size, Slot::Frame(l.frame, l.disp), l.size));
        if let Some(value) = value
            && self.locals.len() < MAX_LOCALS
        {
            self.locals.push(Local {
                frame,
                disp,
                size,
                value: value & mask(size),
            });
        }
    }

    /// Drop the pointer sources `stale` selects; pointers loaded from them
    /// afterwards belong to a new epoch.
    fn forget_sources(&mut self, stale: impl Fn(Slot) -> bool) {
        let before = self.sources.len();
        self.sources.retain(|&s| !stale(s));
        if self.sources.len() != before {
            self.epoch = self.epoch.wrapping_add(1);
        }
    }

    /// Set `r` to `value`, with x86 sub-register semantics: a 32-bit write
    /// zero-extends, an 8- or 16-bit one keeps the rest of the register.
    fn set(&mut self, r: Register, value: Option<u64>) {
        let Some(i) = gpr(r) else { return };
        self.values[i] = match (r.size(), value) {
            (8, v) => v,
            (4, v) => v.map(|v| v & mask(4)),
            (1 | 2, Some(v)) => self.values[i].map(|old| {
                let (shift, m) = if is_high_byte(r) {
                    (8, 0xff00)
                } else {
                    (0, mask(r.size()))
                };
                (old & !m) | ((v << shift) & m)
            }),
            _ => None,
        };
    }
}

/// Whether `instr` moves the stack pointer, so RSP-relative slots shift.
fn moves_stack_pointer(instr: &Instruction) -> bool {
    matches!(
        instr.mnemonic(),
        Mnemonic::Push
            | Mnemonic::Pop
            | Mnemonic::Pushfd
            | Mnemonic::Popfd
            | Mnemonic::Pushfq
            | Mnemonic::Popfq
    ) || (instr.op0_kind() == OpKind::Register
        && instr.op0_register().full_register() == Register::RSP)
}

/// Whether `mnemonic` writes registers or memory beyond its explicit
/// destination operand; the facts are dropped wholesale after one.
fn implicitly_writes(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Mul
            | Mnemonic::Imul
            | Mnemonic::Div
            | Mnemonic::Idiv
            | Mnemonic::Cbw
            | Mnemonic::Cwde
            | Mnemonic::Cdqe
            | Mnemonic::Cwd
            | Mnemonic::Cdq
            | Mnemonic::Cqo
            | Mnemonic::Cpuid
            | Mnemonic::Rdtsc
            | Mnemonic::Rdtscp
            | Mnemonic::Rdmsr
            | Mnemonic::Rdpmc
            | Mnemonic::Xgetbv
            | Mnemonic::Xchg
            | Mnemonic::Xadd
            | Mnemonic::Cmpxchg
            | Mnemonic::Cmpxchg8b
            | Mnemonic::Cmpxchg16b
            | Mnemonic::Pusha
            | Mnemonic::Pushad
            | Mnemonic::Popa
            | Mnemonic::Popad
            | Mnemonic::Enter
            | Mnemonic::Leave
            | Mnemonic::Lahf
            | Mnemonic::Xlatb
            | Mnemonic::In
            | Mnemonic::Insb
            | Mnemonic::Insw
            | Mnemonic::Insd
            | Mnemonic::Lodsb
            | Mnemonic::Lodsw
            | Mnemonic::Lodsd
            | Mnemonic::Lodsq
            | Mnemonic::Stosb
            | Mnemonic::Stosw
            | Mnemonic::Stosd
            | Mnemonic::Stosq
            | Mnemonic::Movsb
            | Mnemonic::Movsw
            | Mnemonic::Movsd
            | Mnemonic::Movsq
            | Mnemonic::Scasb
            | Mnemonic::Scasw
            | Mnemonic::Scasd
            | Mnemonic::Scasq
            | Mnemonic::Cmpsb
            | Mnemonic::Cmpsw
            | Mnemonic::Cmpsd
            | Mnemonic::Cmpsq
            | Mnemonic::Loop
            | Mnemonic::Loope
            | Mnemonic::Loopne
            | Mnemonic::Int
            | Mnemonic::Int1
            | Mnemonic::Int3
            | Mnemonic::Into
            | Mnemonic::Syscall
            | Mnemonic::Sysenter
            | Mnemonic::Aaa
            | Mnemonic::Aad
            | Mnemonic::Aam
            | Mnemonic::Aas
            | Mnemonic::Daa
            | Mnemonic::Das
    )
}
