//! A table of short NUL-terminated paths under a printable single-byte key.
//!
//! Modeled on a static musl crypter stub (sha256 a3c64998…): `decode_str`
//! walks a C string, stops at its NUL and XORs each byte with the immediate
//! 0x26 (`&`), and the paths it decodes sit packed in `.rodata` — 8-byte
//! aligned, one or more NULs apart. Three things hid them: "/proc/…" was
//! taken for a garbled "%PROGRAMDATA%"; a NUL decodes to `&`, so expansion ran
//! through every terminator into the neighbors; and `/tmp/.b` is under the
//! 10-byte floor. The fixture is synthetic: the same shapes, not the sample.

use crate::common::build_elf_with_sections;
use stng::{ExtractOptions, StringMethod, extract_strings_with_options};

const KEY: u8 = 0x26;
const TEXT_OFFSET: u64 = 0x1000;
const RODATA_OFFSET: u64 = 0x2000;

/// The decode loop: `movzx ecx, byte [rdi+rax]; test cl, cl; je done;
/// cmp edx, eax; jle done; xor ecx, 0x26; mov [rsi+rax], cl; inc rax; jmp`.
const DECODE_LOOP: &[u8] = &[
    0x31, 0xc0, // xor eax, eax
    0x0f, 0xb6, 0x0c, 0x07, // loop: movzx ecx, byte [rdi+rax]
    0x84, 0xc9, // test cl, cl
    0x74, 0x0f, // je done
    0x39, 0xc2, // cmp edx, eax
    0x7e, 0x0b, // jle done
    0x83, 0xf1, KEY, // xor ecx, 0x26
    0x88, 0x0c, 0x06, // mov [rsi+rax], cl
    0x48, 0xff, 0xc0, // inc rax
    0xeb, 0xe9, // jmp loop
    0xc6, 0x04, 0x06, 0x00, // done: mov byte [rsi+rax], 0
    0xc3, // ret
];

/// The encoded paths, in table order.
const PATHS: &[&str] = &["/proc/self/fd/", "/var/tmp/.b", "/tmp/.b", "/proc/self/exe"];

/// Plaintext that shares `.rodata` with the table. Under a key below 0x40
/// it decodes to printable text too, which must not be reported.
const PLAINTEXT: &[&str] = &[
    "No such process",
    "Permission denied",
    "__stdio_close",
    "memcpy",
];

/// `.rodata`, and the offset of each encoded path within it.
fn rodata() -> (Vec<u8>, Vec<usize>) {
    let mut rodata = b"abcdefghijklmnopqrstuvwxyz0123456789".to_vec();
    let mut offsets = Vec::new();
    for path in PATHS {
        // At least one NUL, then pad to the next 8-byte boundary.
        rodata.push(0);
        rodata.resize(rodata.len().next_multiple_of(8), 0);
        offsets.push(rodata.len());
        rodata.extend(path.bytes().map(|b| b ^ KEY));
    }
    for text in PLAINTEXT {
        rodata.push(0);
        rodata.extend_from_slice(text.as_bytes());
    }
    rodata.push(0);
    (rodata, offsets)
}

#[test]
fn test_short_nul_terminated_paths_under_printable_key() {
    let (rodata, offsets) = rodata();
    // The layout the sample has: `/tmp/.b` and `/proc/self/exe` one NUL apart.
    assert_eq!(offsets[3] - offsets[2], "/tmp/.b".len() + 1);
    let elf = build_elf_with_sections(&[
        (".text", TEXT_OFFSET, 0x401000, DECODE_LOOP, 0x6), // SHF_ALLOC | SHF_EXECINSTR
        (".rodata", RODATA_OFFSET, 0x402000, &rodata, 0x2), // SHF_ALLOC
    ]);
    let results =
        extract_strings_with_options(&elf, &ExtractOptions::new(4).with_xor(stng::XorMode::Auto));
    let xor: Vec<_> = results
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .collect();

    for (path, offset) in PATHS.iter().zip(&offsets) {
        let at = RODATA_OFFSET + *offset as u64;
        let found = xor
            .iter()
            .find(|s| s.data_offset == at)
            .unwrap_or_else(|| panic!("{path} at {at:#x} not decoded: {xor:?}"));
        assert_eq!(found.value, *path, "wrong extent at {at:#x}: {xor:?}");
        let key = elf[usize::try_from(at).unwrap()] ^ found.value.as_bytes()[0];
        assert_eq!(key, KEY, "{path} decoded with the wrong key");
    }

    let plaintext_start = RODATA_OFFSET + *offsets.last().unwrap() as u64;
    let permuted: Vec<_> = xor
        .iter()
        .filter(|s| s.data_offset > plaintext_start)
        .collect();
    assert!(
        permuted.is_empty(),
        "plaintext decoded with the key is not a string: {permuted:?}"
    );
}
