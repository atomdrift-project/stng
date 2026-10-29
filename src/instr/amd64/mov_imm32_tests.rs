use super::decode_mov_imm32;

#[test]
fn rex_b_selects_the_high_registers() {
    // mov eax, 5 ; mov r9d, 5
    assert_eq!(decode_mov_imm32(&[0xB8, 5, 0, 0, 0], 0), Some((0, 5)));
    assert_eq!(decode_mov_imm32(&[0x41, 0xB9, 5, 0, 0, 0], 0), Some((9, 5)));
    // mov rax, 5 ; mov r8, 5 ; REX.R is not part of the destination.
    assert_eq!(
        decode_mov_imm32(&[0x48, 0xC7, 0xC0, 5, 0, 0, 0], 0),
        Some((0, 5))
    );
    assert_eq!(
        decode_mov_imm32(&[0x49, 0xC7, 0xC0, 5, 0, 0, 0], 0),
        Some((8, 5))
    );
    assert_eq!(
        decode_mov_imm32(&[0x4C, 0xC7, 0xC0, 5, 0, 0, 0], 0),
        Some((0, 5))
    );
    // mov [rax], 5 (ModRM.mod != 11) is not a register load.
    assert_eq!(decode_mov_imm32(&[0x48, 0xC7, 0x00, 5, 0, 0, 0], 0), None);
}
