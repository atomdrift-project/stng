//! What the matcher generalizes over: a generator emits the instruction
//! sequence it accepts with chosen registers, so these tests record which
//! variations of the one compiled build still match and which do not.

use super::*;

const PLAIN: &[u8; 16] = b"variant-test-ok!";
const KEY: &[u8; 16] = b"\x13\x37\x5a\xa5\x01\x02\x03\x04\x55\x66\x77\x88\x99\xaa\xbb\xcc";

/// Register roles: the two array bases, the loop counter, the descriptor,
/// the plaintext byte and the XOR temporary.
#[derive(Clone, Copy)]
struct Regs {
    a: u32,
    b: u32,
    count: u32,
    desc: u32,
    value: u32,
    temp: u32,
}

const DEFAULT: Regs = Regs {
    a: 19,
    b: 20,
    count: 21,
    desc: 22,
    value: 4,
    temp: 5,
};

/// Changes to the generated sequence.
#[derive(Clone, Copy, Default)]
struct Edits {
    nop_in_loop: bool,
    allocator_flag: Option<u32>,
}

const BASE: u64 = 0x1000;

/// B or BL from word `from` to word `to`: a 26-bit two's-complement offset.
fn branch(op: u32, from: usize, to: usize) -> u32 {
    op | u32::try_from(to.wrapping_sub(from) & 0x03ff_ffff).unwrap()
}

/// MOVZ + three MOVK building `value` in X`reg`.
fn load64(reg: u32, value: u64) -> [u32; 4] {
    std::array::from_fn(|hw| {
        let imm = u32::try_from((value >> (hw * 16)) & 0xffff).unwrap();
        let op = if hw == 0 { 0xd280_0000 } else { 0xf280_0000 };
        op | (u32::try_from(hw).unwrap() << 21) | (imm << 5) | reg
    })
}

/// One array: length, allocation, base save (or the helper that saves the
/// second base and zeroes the counter), then the 16 bytes stored as a pair.
fn emit_array(w: &mut Vec<u32>, bytes: &[u8; 16], save: impl FnOnce(usize) -> u32, alloc: usize) {
    w.push(0x5280_0000 | (16 << 5)); // MOV W0, #16
    let at = w.len();
    w.push(branch(0x9400_0000, at, alloc));
    w.push(save(at + 1));
    let lo = u64::from_le_bytes(bytes[..8].try_into().unwrap());
    let hi = u64::from_le_bytes(bytes[8..].try_into().unwrap());
    w.extend(load64(8, lo));
    w.extend(load64(9, hi));
    w.push(0xa900_0000 | (9 << 10) | 8); // STP X8, X9, [X0]
}

fn program(r: Regs, e: Edits) -> Vec<u32> {
    let cipher: [u8; 16] = std::array::from_fn(|i| PLAIN[i] ^ KEY[i]);
    // Helpers live after the main sequence, at fixed word indices.
    let (alloc, helper, args, index, xor, end) = (100, 104, 108, 112, 120, 128);
    let mut w = Vec::new();
    emit_array(&mut w, &cipher, |_| 0xaa00_03e0 | r.a, alloc); // MOV Xa, X0
    emit_array(&mut w, KEY, |at| branch(0x9400_0000, at, helper), alloc);
    w.push(0x9000_0000 | r.desc); // ADRP Xdesc
    w.push(0x9100_0000 | (r.desc << 5) | r.desc); // ADD Xdesc, Xdesc, #0
    let top = w.len();
    w.push(0xf100_001f | (16 << 10) | (r.count << 5)); // CMP Xcount, #16
    w.push(0x5400_01a0); // B.EQ out
    w.push(0xaa00_03e0 | (r.a << 16)); // MOV X0, Xa
    w.push(0x5280_0001 | (16 << 5)); // MOV W1, #16
    let at = w.len();
    w.push(branch(0x9400_0000, at, args));
    w.push(branch(0x9400_0000, at + 1, index));
    w.push(0x3940_0000 | r.value); // LDRB Wvalue, [X0]
    w.push(0xaa00_03e0 | (r.b << 16)); // MOV X0, Xb
    w.push(0x5280_0001 | (16 << 5));
    let at = w.len();
    w.push(branch(0x9400_0000, at, args));
    w.push(branch(0x9400_0000, at + 1, index));
    w.push(branch(0x9400_0000, at + 2, xor));
    if e.nop_in_loop {
        w.push(crate::arm64::NOP);
    }
    w.push(0x9100_0400 | (r.count << 5) | r.count); // ADD Xcount, Xcount, #1
    let at = w.len();
    w.push(branch(0x1400_0000, at, top));
    w.resize(end, crate::arm64::NOP);
    let flag = e.allocator_flag.unwrap_or(1);
    w[alloc..alloc + 3].copy_from_slice(&[
        0x5280_0001 | (flag << 5), // MOV W1, #flag
        branch(0x1400_0000, alloc + 1, alloc + 2),
        RET,
    ]);
    w[helper..helper + 3].copy_from_slice(&[
        0xaa00_03e0 | r.b,     // MOV Xb, X0
        0xd280_0000 | r.count, // MOV Xcount, #0
        RET,
    ]);
    w[args..args + 3].copy_from_slice(&[
        0xaa00_03e2 | (r.count << 16), // MOV X2, Xcount
        0xaa00_03e3 | (r.desc << 16),  // MOV X3, Xdesc
        RET,
    ]);
    w[index..index + 4].copy_from_slice(&[0xeb01_005f, 0x5400_0062, 0x8b02_0000, RET]);
    w[xor..xor + 4].copy_from_slice(&[
        0x3940_0000 | r.temp,                                   // LDRB Wtemp, [X0]
        0x4a00_0000 | (r.value << 16) | (r.temp << 5) | r.temp, // EOR
        0x3900_0000 | r.temp,                                   // STRB Wtemp, [X0]
        RET,
    ]);
    w
}

fn run(r: Regs, e: Edits) -> Option<String> {
    let bytes: Vec<u8> = program(r, e).iter().flat_map(|w| w.to_le_bytes()).collect();
    decode(
        &Code {
            bytes: &bytes,
            addr: BASE,
        },
        0,
        4,
    )
    .map(|(value, _)| value)
}

#[test]
fn generated_sequence_decodes() {
    let bytes: Vec<u8> = program(DEFAULT, Edits::default())
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
    let found = extract(&bytes, BASE, 0, 0, 4);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].value, "variant-test-ok!");
    assert_eq!(
        run(DEFAULT, Edits::default()).as_deref(),
        Some("variant-test-ok!")
    );
}

/// Register allocation is read from the code: any distinct callee-saved
/// bases, counter and descriptor, and any free value and temporary, match.
#[test]
fn register_renaming_still_matches() {
    for r in [
        Regs {
            a: 28,
            b: 27,
            count: 26,
            desc: 25,
            value: 9,
            temp: 10,
        },
        Regs {
            a: 23,
            b: 19,
            count: 24,
            desc: 20,
            value: 17,
            temp: 1,
        },
    ] {
        assert_eq!(
            run(r, Edits::default()).as_deref(),
            Some("variant-test-ok!")
        );
    }
}

/// What is fixed to the one build: callee-saved bases, the exact loop
/// layout (one extra instruction moves every checked word), and the
/// allocator thunk's flag.
#[test]
fn layout_and_abi_variations_do_not_match() {
    let caller_saved = Regs { a: 9, ..DEFAULT };
    assert_eq!(run(caller_saved, Edits::default()), None);
    let nop = Edits {
        nop_in_loop: true,
        ..Edits::default()
    };
    assert_eq!(run(DEFAULT, nop), None);
    let flag = Edits {
        allocator_flag: Some(2),
        ..Edits::default()
    };
    assert_eq!(run(DEFAULT, flag), None);
}
