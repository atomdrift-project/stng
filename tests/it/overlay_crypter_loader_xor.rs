//! Real-world test for a Linux overlay crypter stub (see
//! `testdata/xor/overlay_crypter_loader_xor.md`).
//!
//! The loader hides `/proc/self/exe`, `/proc/self/fd/` and its temp-file
//! prefixes as NUL-terminated strings under single-byte XOR key `0x26`. The
//! key is printable, so raw NUL terminators decode to `&`, and the strings are
//! packed one NUL apart and as short as 7 bytes. Nothing tells stng the key.

use stng::{ExtractOptions, StringMethod, extract_strings_with_options};

const KEY: u8 = 0x26;

/// (file offset, decoded string)
const ENCODED: &[(u64, &str)] = &[
    (0x59e8, "/proc/self/fd/"),
    (0x59f8, "/var/tmp/.b"),
    (0x5a08, "/tmp/.b"),
    (0x5a10, "/proc/self/exe"),
];

#[test]
fn test_overlay_crypter_loader_xor_paths() {
    let data = std::fs::read(crate::common::path(
        "testdata/xor/overlay_crypter_loader_xor",
    ))
    .expect("Failed to read overlay crypter loader sample");
    // Automatic XOR detection, no key hint (`with_xor(None)`).
    let extracted = extract_strings_with_options(&data, &ExtractOptions::new(4).with_xor(None));
    let xor: Vec<_> = extracted
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .collect();

    for &(offset, path) in ENCODED {
        let found = xor
            .iter()
            .find(|s| s.data_offset == offset)
            .unwrap_or_else(|| panic!("{path} at {offset:#x} not decoded: {xor:?}"));
        assert_eq!(found.value, path, "wrong extent at {offset:#x}");
        let at = usize::try_from(offset).unwrap();
        assert_eq!(
            data[at] ^ found.value.as_bytes()[0],
            KEY,
            "{path}: wrong key"
        );
    }
}
