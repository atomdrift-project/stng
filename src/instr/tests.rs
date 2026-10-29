use super::amd64::{
    AMD64_STORED_PAIR_GAP, extract_amd64_stored_strings, extract_amd64_value_string,
    extract_inline_strings_amd64,
};
use super::arm64::{
    ARM64_STORED_WINDOW, decode_arm_mov_immediate, decode_arm64_string,
    extract_inline_strings_arm64,
};
use super::*;
use crate::types::StringMethod;
use std::collections::HashSet;

#[test]
fn test_is_valid_utf8_string() {
    assert!(is_valid_utf8_string("hello"));
    assert!(is_valid_utf8_string("Hello World!"));
    assert!(!is_valid_utf8_string(""));
    assert!(!is_valid_utf8_string("\x01\x02\x03"));
}

#[test]
fn test_is_valid_utf8_string_unicode() {
    assert!(is_valid_utf8_string("Héllo Wörld"));
    assert!(is_valid_utf8_string("日本語"));
    assert!(is_valid_utf8_string("emoji: 🎉"));
}

#[test]
fn test_is_valid_utf8_string_mostly_printable() {
    // More than 50% printable should pass
    assert!(is_valid_utf8_string("ab\x01")); // 2/3 printable
    // Less than 50% should fail
    assert!(!is_valid_utf8_string("\x01\x02\x03a")); // 1/4 printable
}

#[test]
fn test_decode_arm_mov_immediate() {
    // MOVZ X0, #5 would be: D2 80 00 A0 (0xD28000A0)
    // imm16 = 5, shift = 0
    let inst = 0xD28000A0;
    let result = decode_arm_mov_immediate(inst);
    assert_eq!(result, Some(5));
}

#[test]
fn test_decode_arm_mov_immediate_zero() {
    // MOVZ with 0 value
    let inst = 0xD2800000;
    let result = decode_arm_mov_immediate(inst);
    assert_eq!(result, Some(0));
}

#[test]
fn test_decode_arm_mov_immediate_with_shift() {
    // MOVZ X0, #1, LSL #16 would have shift = 1
    // Value 1 shifted left by 16 = 0x10000
    let inst = 0xD2A00020;
    assert_eq!(decode_arm_mov_immediate(inst), Some(0x10000));
}

#[test]
fn test_decode_arm_mov_immediate_invalid() {
    // Not a MOV instruction
    let inst = 0x00000000;
    let result = decode_arm_mov_immediate(inst);
    assert!(result.is_none());
}

#[test]
fn test_looks_like_key_basic() {
    assert!(looks_like_key("name"));
    assert!(looks_like_key("user_id"));
    assert!(looks_like_key("config.timeout"));
    assert!(looks_like_key("api-key"));
}

#[test]
fn test_looks_like_key_too_long() {
    let long_string = "a".repeat(50);
    assert!(!looks_like_key(&long_string));
}

#[test]
fn test_looks_like_key_with_spaces() {
    assert!(!looks_like_key("has spaces"));
    assert!(!looks_like_key("hello world"));
}

#[test]
fn test_looks_like_key_paths() {
    assert!(!looks_like_key("/usr/bin"));
    assert!(!looks_like_key("./config"));
}

#[test]
fn test_looks_like_key_urls() {
    assert!(!looks_like_key("http://example.com"));
    assert!(!looks_like_key("https://api.server.com"));
}

#[test]
fn test_looks_like_key_special_chars() {
    assert!(!looks_like_key("key@value"));
    assert!(!looks_like_key("key#value"));
    assert!(!looks_like_key("key$value"));
}

#[test]
fn test_extract_inline_strings_arm64_empty() {
    let text_data = &[];
    let rodata_data = b"Hello World";

    let strings = extract_inline_strings_arm64(text_data, 0x1000, rodata_data, 0x2000, 4);

    assert!(strings.is_empty());
}

#[test]
fn test_extract_inline_strings_arm64_no_bl() {
    // Code without BL instructions
    let text_data = vec![0x00u8; 100];
    let rodata_data = b"Hello World";

    let strings = extract_inline_strings_arm64(&text_data, 0x1000, rodata_data, 0x2000, 4);

    assert!(strings.is_empty());
}

#[test]
fn test_extract_inline_strings_amd64_empty() {
    let text_data = &[];
    let rodata_data = b"Hello World";

    let strings = extract_inline_strings_amd64(text_data, 0x1000, rodata_data, 0x2000, 4);

    assert!(strings.is_empty());
}

#[test]
fn test_extract_inline_strings_amd64_no_call() {
    // Code without CALL instructions
    let text_data = vec![0x90u8; 100]; // NOP instructions
    let rodata_data = b"Hello World";

    let strings = extract_inline_strings_amd64(&text_data, 0x1000, rodata_data, 0x2000, 4);

    assert!(strings.is_empty());
}

#[test]
fn test_extract_inline_strings_amd64_with_call() {
    // Create code with a CALL instruction but no valid string pattern
    let mut text_data = vec![0x90u8; 100];
    text_data[50] = 0xE8; // CALL opcode
    // Rest is garbage offset

    let rodata_data = b"Hello World";

    let strings = extract_inline_strings_amd64(&text_data, 0x1000, rodata_data, 0x2000, 4);

    // No valid pattern found
    assert!(strings.is_empty());
}

#[test]
fn test_extract_arm64_pattern_short_lookback() {
    // Test with code too short for lookback
    let text_data = vec![0x00u8; 8];
    let rodata_data = b"Test";

    let strings = extract_inline_strings_arm64(&text_data, 0x1000, rodata_data, 0x2000, 4);

    assert!(strings.is_empty());
}

#[test]
fn test_decode_arm64_string_invalid_addr() {
    // Address outside rodata range
    let scan = Scan::new(&[], 0x1000, &[0u8; 100], 0x5000, 4);
    let result = decode_arm64_string(
        0x90000000, // ADRP
        0x91000000, // ADD
        0xD2800000, // MOV
        0, &scan,
    );

    assert!(result.is_none());
}

#[test]
fn test_decode_arm64_string_invalid_length() {
    // Length too long
    let scan = Scan::new(&[], 0x5000, &[0u8; 100], 0x5000, 4);
    let result = decode_arm64_string(
        0x90000000, 0x91000000, 0xD2BC4000, // Encodes large value
        0, &scan,
    );

    // Should return None for invalid length
    assert!(result.is_none());
}

#[test]
fn test_amd64_value_string_short_data() {
    let text_data = vec![0xE8u8, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let rodata_data = b"Test";
    let mut strings = Vec::new();
    let mut seen = HashSet::new();

    let scan = Scan::new(&text_data, 0x1000, rodata_data, 0x2000, 4);
    extract_amd64_value_string(0, &scan, &mut strings, &mut seen);

    assert!(strings.is_empty());
}

// Encodings from `llvm-mc -triple=aarch64 -show-encoding`. Text sits at
// 0x100000 and rodata one page up, so `adrp x2, #4096` reaches it.
const ADRP_X2: u32 = 0xb000_0002; // adrp x2, #4096
const ADD_X2_0: u32 = 0x9100_0042; // add x2, x2, #0
const ADD_X2_16: u32 = 0x9100_4042; // add x2, x2, #16
const ADD_X2_32: u32 = 0x9100_8042; // add x2, x2, #32
const ADD_X2_OUT: u32 = 0x913f_fc42; // add x2, x2, #0xfff (past rodata)
const MOV_X3_11: u32 = 0xd280_0163; // mov x3, #11
const ORR_X4_7: u32 = 0xb240_0be4; // orr x4, xzr, #0x7
const STP_X2_X3: u32 = 0xa909_0fe2; // stp x2, x3, [sp, #144]
const STP_X2_X4: u32 = 0xa90a_13e2; // stp x2, x4, [sp, #160]
const B_NEXT: u32 = 0x1400_0001; // b #4
const LDR_X3: u32 = 0xf940_07e3; // ldr x3, [sp, #8]
const STR_X3: u32 = 0xf900_07e3; // str x3, [sp, #8]
const MOV_X3_X5: u32 = 0xaa05_03e3; // mov x3, x5
const NOP: u32 = 0xd503_201f;

fn text(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

/// Strings packed back to back, as Go lays out rodata: a wrong length
/// still decodes to printable text, so these tests catch a stale length
/// rather than relying on the decoder to reject it.
fn packed_rodata() -> Vec<u8> {
    let mut r = vec![b'x'; 0x100];
    r[0..11].copy_from_slice(b"test_string");
    r[16..23].copy_from_slice(b"abcdefg");
    r[32..39].copy_from_slice(b"hijklmn");
    r
}

fn stored(words: &[u32]) -> Vec<String> {
    extract_inline_strings_arm64(&text(words), 0x100000, &packed_rodata(), 0x101000, 4)
        .into_iter()
        .map(|s| s.value)
        .collect()
}

#[test]
fn arm64_stored_string_header_is_decoded() {
    let found = extract_inline_strings_arm64(
        &text(&[ADRP_X2, ADD_X2_0, MOV_X3_11, STP_X2_X3]),
        0x100000,
        &packed_rodata(),
        0x101000,
        4,
    );
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].value, "test_string");
    assert_eq!(found[0].data_offset, 0x101000);
    assert_eq!(found[0].method, StringMethod::InstructionPattern);
}

/// Go reloads a length register only when the length changes: the second
/// element here reuses x4 = 7 from the first.
#[test]
fn arm64_stored_length_register_is_reused_across_elements() {
    let found = stored(&[
        ADRP_X2, ADD_X2_16, ORR_X4_7, STP_X2_X4, ADRP_X2, ADD_X2_32, STP_X2_X4,
    ]);
    assert_eq!(found, ["abcdefg", "hijklmn"]);
}

#[test]
fn arm64_stored_state_does_not_survive_a_branch() {
    assert!(stored(&[ADRP_X2, ADD_X2_0, MOV_X3_11, B_NEXT, STP_X2_X3]).is_empty());
}

#[test]
fn arm64_stored_length_overwritten_is_not_used() {
    assert!(stored(&[ADRP_X2, ADD_X2_0, MOV_X3_11, MOV_X3_X5, STP_X2_X3]).is_empty());
    assert!(stored(&[ADRP_X2, ADD_X2_0, MOV_X3_11, LDR_X3, STP_X2_X3]).is_empty());
}

/// A store reads its register; it must not invalidate it.
#[test]
fn arm64_stored_intervening_store_keeps_state() {
    assert_eq!(
        stored(&[ADRP_X2, ADD_X2_0, MOV_X3_11, STR_X3, STP_X2_X3]),
        ["test_string"]
    );
}

#[test]
fn arm64_stored_values_expire_after_the_window() {
    let within = |gap: usize| {
        let mut words = vec![ADRP_X2, ADD_X2_0, MOV_X3_11];
        words.extend(std::iter::repeat_n(NOP, gap));
        words.push(STP_X2_X3);
        !stored(&words).is_empty()
    };
    // The pointer was set two instructions before the length, so it is
    // the first to age out.
    assert!(within(ARM64_STORED_WINDOW - 2));
    assert!(!within(ARM64_STORED_WINDOW - 1));
}

#[test]
fn arm64_stored_pointer_outside_rodata_is_ignored() {
    assert!(stored(&[ADRP_X2, ADD_X2_OUT, MOV_X3_11, STP_X2_X3]).is_empty());
}

// x86-64 encodings from `llvm-mc -triple=x86_64 -show-encoding`. Text at
// 0x1000, rodata at 0x3000; `lea` at text offset `at` reaching rodata+off
// needs disp = 0x3000 + off - (0x1000 + at + 7).
fn lea(reg_rex: u8, modrm: u8, at: usize, off: u32) -> Vec<u8> {
    let disp = i64::from(0x3000 + off) - (0x1000 + at as i64 + 7);
    let mut v = vec![reg_rex, 0x8d, modrm];
    v.extend((disp as i32).to_le_bytes());
    v
}
const LEA_RCX: (u8, u8) = (0x48, 0x0d); // lea rcx, [rip+d]
const LEA_RAX: (u8, u8) = (0x48, 0x05); // lea rax, [rip+d]
const STORE_RCX_RDI: [u8; 3] = [0x48, 0x89, 0x0f]; // mov [rdi], rcx
const STORE_RCX_RDI8: [u8; 4] = [0x48, 0x89, 0x4f, 0x08]; // mov [rdi+8], rcx
const STORE_RCX_RDI16: [u8; 4] = [0x48, 0x89, 0x4f, 0x10]; // mov [rdi+16], rcx
const MOV_ECX_11: [u8; 5] = [0xb9, 0x0b, 0, 0, 0]; // mov ecx, 11
const STORE_RAX_RSP20: [u8; 5] = [0x48, 0x89, 0x44, 0x24, 0x20]; // mov [rsp+0x20], rax
const STORE_IMM11_RSP28: [u8; 9] = [0x48, 0xc7, 0x44, 0x24, 0x28, 0x0b, 0, 0, 0]; // mov qword [rsp+0x28], 11
const STORE_IMM7_RDI8: [u8; 8] = [0x48, 0xc7, 0x47, 0x08, 0x07, 0, 0, 0]; // mov qword [rdi+8], 7

fn amd64_stored(parts: &[&[u8]]) -> Vec<String> {
    let text: Vec<u8> = parts.concat();
    let mut rodata = vec![b'x'; 0x100];
    rodata[0..11].copy_from_slice(b"test_string");
    rodata[16..23].copy_from_slice(b"abcdefg");
    let mut out = Vec::new();
    extract_amd64_stored_strings(&text, 0x1000, &rodata, 0x3000, 4, &mut out);
    out.into_iter().map(|s| s.value).collect()
}

/// Pointer stored to [rdi], length loaded into a register and stored to
/// [rdi+8]: rustc's shape for a `[&str; N]` element.
#[test]
fn amd64_stored_header_with_register_length() {
    let lea = lea(LEA_RCX.0, LEA_RCX.1, 0, 0);
    assert_eq!(
        amd64_stored(&[&lea, &STORE_RCX_RDI, &MOV_ECX_11, &STORE_RCX_RDI8]),
        ["test_string"]
    );
}

/// A stack-spilled header (SIB-addressed) with an immediate length store.
#[test]
fn amd64_stored_header_on_the_stack_with_immediate_length() {
    let lea = lea(LEA_RAX.0, LEA_RAX.1, 0, 0);
    assert_eq!(
        amd64_stored(&[&lea, &STORE_RAX_RSP20, &STORE_IMM11_RSP28]),
        ["test_string"]
    );
}

/// The first LEA's pointer is never stored before the register is
/// reloaded; pairing it with the second element's stores would decode
/// "test_string" with the wrong length. Only the second element counts.
#[test]
fn amd64_stored_register_reload_closes_the_window() {
    let first = lea(LEA_RCX.0, LEA_RCX.1, 0, 0);
    let second = lea(LEA_RCX.0, LEA_RCX.1, 7, 16);
    assert_eq!(
        amd64_stored(&[&first, &second, &STORE_RCX_RDI, &STORE_IMM7_RDI8]),
        ["abcdefg"]
    );
}

/// The length must sit in the slot right after the pointer.
#[test]
fn amd64_stored_length_must_be_adjacent() {
    let lea = lea(LEA_RCX.0, LEA_RCX.1, 0, 0);
    assert!(amd64_stored(&[&lea, &STORE_RCX_RDI, &MOV_ECX_11, &STORE_RCX_RDI16]).is_empty());
}

/// A length store far from the pointer store belongs to something else.
#[test]
fn amd64_stored_length_must_be_near_the_pointer_store() {
    let lea = lea(LEA_RCX.0, LEA_RCX.1, 0, 0);
    let padding = [0x90u8; AMD64_STORED_PAIR_GAP + 1];
    assert!(
        amd64_stored(&[&lea, &STORE_RCX_RDI, &MOV_ECX_11, &padding, &STORE_RCX_RDI8]).is_empty()
    );
}

#[test]
fn test_empty_inputs_both_arches() {
    assert!(extract_inline_strings_arm64(&[], 0x100000, &[], 0x101000, 4).is_empty());
    assert!(extract_inline_strings_amd64(&[], 0x100000, &[], 0x101000, 4).is_empty());
}

#[test]
fn test_truncated_arm64_instructions() {
    let text_data = vec![0x00, 0x00]; // Only 2 bytes, incomplete ARM64 instruction
    let results = extract_inline_strings_arm64(&text_data, 0x100000, &[], 0x101000, 4);
    assert!(results.is_empty());
}

#[test]
fn test_large_code_section_arm64() {
    let text_data: Vec<u8> = (0..65536u32)
        .map(|i| u8::try_from(i % 256).unwrap_or(0))
        .collect();
    let rodata_data = vec![0u8; 4096];
    // Must not panic; rodata holds only zeros, so nothing is recovered.
    assert!(
        extract_inline_strings_arm64(&text_data, 0x100000, &rodata_data, 0x110000, 4).is_empty()
    );
}

#[test]
fn test_out_of_bounds_addresses_arm64() {
    let text_data = vec![
        0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x91, 0x41, 0x01, 0x80, 0xD2, 0x00, 0x00, 0x00,
        0x94,
    ];
    let rodata_data = vec![0u8; 0x100];
    let results = extract_inline_strings_arm64(&text_data, 0x100000, &rodata_data, 0x101000, 4);
    for s in results {
        assert!(!s.value.is_empty());
    }
}

#[test]
fn test_min_length_enforcement_both_arches() {
    let text_arm64 = vec![
        0x00, 0x00, 0x00, 0x90, 0x00, 0x00, 0x00, 0x91, 0x41, 0x01, 0x80, 0xD2, 0x00, 0x00, 0x00,
        0x94,
    ];
    let text_amd64 = vec![
        0x48, 0x8D, 0x3D, 0x00, 0x01, 0x00, 0x00, 0xBE, 0x0B, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00,
        0x00, 0x00,
    ];
    let mut rodata = vec![0u8; 0x200];
    rodata[0..20].copy_from_slice(b"exactly_20_chars_str");
    let min_len = 25;
    let results_arm =
        extract_inline_strings_arm64(&text_arm64, 0x100000, &rodata, 0x101000, min_len);
    let results_amd =
        extract_inline_strings_amd64(&text_amd64, 0x100000, &rodata, 0x101000, min_len);
    for s in results_arm.iter().chain(results_amd.iter()) {
        assert!(
            s.value.len() >= min_len,
            "String '{}' is {} chars, expected >= {}",
            s.value,
            s.value.len(),
            min_len
        );
    }
}

/// Regression: a string materialized as `LEA RBX, <rodata>; MOV ECX, len`
/// (the shape Go emits for `[]byte(constant)`, e.g. the GhostDog script)
/// must be recovered. The length lands in ECX, which no fixed register-pair
/// list covered, so this whole class of literals was previously dropped.
#[test]
fn test_amd64_non_arg_register_pair() {
    // 48 8D 1D F9 0F 00 00  LEA RBX, [rip+0xFF9]   -> 0x101000
    // B9 10 00 00 00        MOV ECX, 16            (length, not in ESI/EDX/EBX/EDI)
    // E8 00 00 00 00        CALL
    // Trailing NOPs so the CALL site clears the scanner's end-of-text guard.
    let text = vec![
        0x48, 0x8D, 0x1D, 0xF9, 0x0F, 0x00, 0x00, 0xB9, 0x10, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00,
        0x00, 0x00, 0x90, 0x90, 0x90, 0x90,
    ];
    let mut rodata = vec![0u8; 0x40];
    rodata[0..16].copy_from_slice(b"echo hello world");
    let results = extract_inline_strings_amd64(&text, 0x100000, &rodata, 0x101000, 4);
    assert!(
        results.iter().any(|s| s.value == "echo hello world"),
        "LEA RBX + MOV ECX length pair should be recovered, got {:?}",
        results.iter().map(|s| &s.value).collect::<Vec<_>>(),
    );
}

/// Go may leave substantial setup code between a literal's LEA/length
/// pair and the runtime call that consumes it. The association must remain
/// bounded, but must cover that legitimate shape.
#[test]
fn test_amd64_long_setup_before_call() {
    let mut text = vec![
        0x48, 0x8D, 0x05, 0xF9, 0x0F, 0x00, 0x00, // LEA RAX, [rip+0xff9]
        0xBB, 0x10, 0x00, 0x00, 0x00, // MOV EBX, 16
    ];
    text.resize(140, 0x90);
    text.extend_from_slice(&[0xE8, 0x00, 0x00, 0x00, 0x00]);
    text.extend_from_slice(&[0x90; 8]);
    let mut rodata = vec![0u8; 0x40];
    rodata[..16].copy_from_slice(b"/v1/teams/ingest");

    let results = extract_inline_strings_amd64(&text, 0x100000, &rodata, 0x101000, 4);
    assert!(
        results.iter().any(|s| s.value == "/v1/teams/ingest"),
        "long-distance LEA/MOV pair should be recovered, got {:?}",
        results.iter().map(|s| &s.value).collect::<Vec<_>>(),
    );
}

/// A Go branch can place the immediate length directly before the pointer
/// LEA rather than after it.
#[test]
fn test_amd64_preceding_length_before_lea() {
    let mut text = vec![
        0xBB, 0x10, 0x00, 0x00, 0x00, // MOV EBX, 16
        0x48, 0x8D, 0x05, 0xF4, 0x0F, 0x00, 0x00, // LEA RAX, [rip+0xff4]
    ];
    text.extend_from_slice(&[0x90; 32]);
    text.extend_from_slice(&[0xE8, 0x00, 0x00, 0x00, 0x00]);
    text.extend_from_slice(&[0x90; 8]);
    let mut rodata = vec![0u8; 0x40];
    rodata[..16].copy_from_slice(b"/v1/teams/ingest");

    let results = extract_inline_strings_amd64(&text, 0x100000, &rodata, 0x101000, 4);
    assert!(
        results.iter().any(|s| s.value == "/v1/teams/ingest"),
        "preceding MOV/LEA pair should be recovered, got {:?}",
        results.iter().map(|s| &s.value).collect::<Vec<_>>(),
    );
}

/// Regression: the ARM64 equivalent — `ADRP x1; ADD x1; MOVZ x2, len` — the
/// register pair `runtime.stringtoslicebyte` uses, outside the old x0/x1 and
/// x2/x3 cases.
#[test]
fn test_arm64_non_arg_register_pair() {
    // ADRP x1, +0x10 pages ; ADD x1, x1, #0 ; MOVZ x2, #16 ; BL
    let text = vec![
        0x81, 0x00, 0x00, 0x90, 0x21, 0x00, 0x00, 0x91, 0x02, 0x02, 0x80, 0xD2, 0x00, 0x00, 0x00,
        0x94,
    ];
    let mut rodata = vec![0u8; 0x40];
    rodata[0..16].copy_from_slice(b"echo hello world");
    let results = extract_inline_strings_arm64(&text, 0x100000, &rodata, 0x110000, 4);
    assert!(
        results.iter().any(|s| s.value == "echo hello world"),
        "ADRP x1 + MOVZ x2 length pair should be recovered, got {:?}",
        results.iter().map(|s| &s.value).collect::<Vec<_>>(),
    );
}
