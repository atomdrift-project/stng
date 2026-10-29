//! x86-64 operand predicates shared by the instruction-pattern decoders.

use iced_x86::{Instruction, Mnemonic, OpKind, Register};

/// Whether `i` is `mov dst, src` between registers.
pub(crate) fn reg_move(i: &Instruction, dst: Register, src: Register) -> bool {
    i.mnemonic() == Mnemonic::Mov
        && i.op0_kind() == OpKind::Register
        && i.op1_kind() == OpKind::Register
        && i.op0_register() == dst
        && i.op1_register() == src
}

/// Whether `i`'s memory operand is exactly `[base + index + displacement]`,
/// unscaled and without a segment override.
pub(crate) fn memory(i: &Instruction, base: Register, index: Register, displacement: u64) -> bool {
    i.memory_base() == base
        && i.memory_index() == index
        && i.memory_displacement64() == displacement
        && i.memory_index_scale() == 1
        && i.segment_prefix() == Register::None
}

/// Whether the System V ABI preserves `r` across calls (besides RBP and RSP).
pub(crate) fn callee_saved(r: Register) -> bool {
    matches!(
        r,
        Register::RBX | Register::R12 | Register::R13 | Register::R14 | Register::R15
    )
}
