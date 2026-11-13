//! Integration tests for stng library.

use crate::common::minimal_elf_header;
use stng::{
    ExtractOptions, ExtractedString, StringKind, StringMethod, detect_language, extract_strings,
    extract_strings_with_options, is_garbage, is_go_binary, is_rust_binary,
};

// Test data: minimal Mach-O header for 64-bit
fn minimal_macho_header() -> Vec<u8> {
    let mut data = vec![0u8; 512];
    // Mach-O 64-bit magic
    data[0..4].copy_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]);
    // CPU type: x86_64 (0x01000007)
    data[4..8].copy_from_slice(&[0x07, 0x00, 0x00, 0x01]);
    // CPU subtype
    data[8..12].copy_from_slice(&[0x03, 0x00, 0x00, 0x00]);
    // File type: executable (2)
    data[12..16].copy_from_slice(&[0x02, 0x00, 0x00, 0x00]);
    // Number of load commands
    data[16..20].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    // Size of load commands
    data[20..24].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    data
}

#[test]
fn finds_nothing_in_empty_input() {
    let strings = extract_strings(&[], 4);
    assert!(strings.is_empty());
}

#[test]
fn finds_whole_printable_input() {
    // Printable data should be extracted (like traditional `strings`)
    let data = b"not a valid binary format at all";
    let strings = extract_strings(data, 4);
    // The whole input is one printable run, found raw at offset 0.
    assert!(
        strings
            .iter()
            .any(|s| s.value == "not a valid binary format at all"
                && s.data_offset == 0
                && s.method == StringMethod::RawScan),
        "{strings:?}"
    );
}

#[test]
fn finds_nothing_in_unprintable_bytes() {
    // Pure binary data with no printable runs should return empty
    let data = &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let strings = extract_strings(data, 4);
    assert!(strings.is_empty());
}

#[test]
fn finds_nothing_in_bare_elf_header() {
    let data = minimal_elf_header();
    let strings = extract_strings(&data, 4);
    // Minimal ELF with no sections should return empty
    assert!(strings.is_empty());
}

#[test]
fn finds_nothing_in_bare_macho_header() {
    let data = minimal_macho_header();
    let strings = extract_strings(&data, 4);
    // Minimal Mach-O with no segments should return empty
    assert!(strings.is_empty());
}

#[test]
fn detects_plain_text() {
    // Plain text should be detected as "text"
    assert_eq!(detect_language(b"not a binary"), stng::Language::Text);
}

#[test]
fn detects_unknown_for_binary_noise() {
    // Binary garbage should be "unknown"
    assert_eq!(
        detect_language(&[0x00, 0x01, 0x02, 0x03, 0x04]),
        stng::Language::Unknown
    );
}

#[test]
fn detects_unknown_for_bare_elf() {
    let data = minimal_elf_header();
    assert_eq!(detect_language(&data), stng::Language::Unknown); // No Go/Rust sections
}

#[test]
fn empty_input_is_not_go() {
    assert!(!is_go_binary(&[]));
}

#[test]
fn text_is_not_go() {
    assert!(!is_go_binary(b"not a binary"));
}

#[test]
fn empty_input_is_not_rust() {
    assert!(!is_rust_binary(&[]));
}

#[test]
fn text_is_not_rust() {
    assert!(!is_rust_binary(b"not a binary"));
}

#[test]
fn new_options_set_min_length_and_xor_off() {
    let opts = ExtractOptions::new(4);
    assert_eq!(opts.min_length(), 4);
    assert_eq!(*opts.xor(), stng::XorMode::Off);
}

#[test]
fn options_find_nothing_in_empty_input() {
    let opts = ExtractOptions::new(4);
    let strings = extract_strings_with_options(&[], &opts);
    assert!(strings.is_empty());
}

// Garbage detection tests
#[test]
fn keeps_common_binary_strings() {
    assert!(!is_garbage("Hello World"));
    assert!(!is_garbage("go1.22.0"));
    assert!(!is_garbage("/usr/lib/go"));
    assert!(!is_garbage("runtime.memequal"));
    assert!(!is_garbage("SIGFPE: floating-point exception"));
    assert!(!is_garbage("Bool"));
    assert!(!is_garbage("Time"));
    assert!(!is_garbage("linux"));
    assert!(!is_garbage("amd64"));
    assert!(!is_garbage("https://example.com"));
    assert!(!is_garbage("ERROR_CODE_123"));
}

#[test]
fn rejects_empty_and_single_char() {
    assert!(is_garbage(""));
    assert!(is_garbage(" "));
    assert!(is_garbage("a")); // Single char
}

#[test]
fn rejects_embedded_control_chars() {
    assert!(is_garbage("ab\x00cd"));
    assert!(is_garbage("\x01\x02\x03"));
    assert!(is_garbage("hello\x00world"));
}

#[test]
fn rejects_misaligned_go_reads() {
    assert!(is_garbage("asL "));
    assert!(is_garbage("``L "));
    assert!(is_garbage("dL "));
    assert!(is_garbage("`L "));
}

#[test]
fn rejects_short_mixed_case() {
    assert!(is_garbage("P9O"));
    assert!(is_garbage("8ZAj"));
    assert!(is_garbage("pIo2"));
}

#[test]
fn keeps_short_all_caps() {
    // All caps short strings are OK
    assert!(!is_garbage("API"));
    assert!(!is_garbage("HTTP"));
    assert!(!is_garbage("GET"));
}

#[test]
fn keeps_short_lowercase() {
    assert!(!is_garbage("foo"));
    assert!(!is_garbage("bar"));
    assert!(!is_garbage("test"));
}

#[test]
fn keeps_short_digits() {
    assert!(!is_garbage("1234"));
    assert!(!is_garbage("2024"));
}

#[test]
fn rejects_repeated_chars() {
    assert!(is_garbage("aaaa"));
    assert!(is_garbage("...."));
    assert!(is_garbage("----"));
}

#[test]
fn rejects_single_char_padded_by_spaces() {
    assert!(is_garbage("   a   ")); // Single char after trim
    // "ab cd" after trim has proper content, may not be garbage
}

#[test]
fn rejects_trailing_cyrillic() {
    assert!(is_garbage("333333ӿ"));
    assert!(is_garbage("abcӿ"));
}

#[test]
fn rejects_noise_punctuation() {
    assert!(is_garbage("@#$%"));
    assert!(is_garbage("@E?"));
    assert!(is_garbage("P$O"));
}

#[test]
fn keeps_eight_char_hex_runs() {
    // Pure-hex runs ≥8 chars are kept — could be hash fragments,
    // short build IDs, or other hex identifiers.
    assert!(!is_garbage("deadbeef"));
    assert!(!is_garbage("0a1b2c3d"));
}

/// The npm install-hook packer decodes through charcodes and a recovered Caesar
/// shift, exposing the AES staging call underneath.
///
/// Regression for a real miss: the payload was invisible end to end because the
/// charcode recipe was written as an array `.map(...)` rather than a direct
/// `eval(String.fromCharCode(...))`, and because the shift was 6 rather than the
/// ROT13 everyone tries. Both had to be fixed for a single string of the
/// payload to reach a rule.
#[test]
fn npm_charcode_rot_packer_exposes_aes_staging() {
    let src = crate::common::bytes("testdata/script/npm-charcode-rot-packer.js").leak();
    let results = stng::script::deobfuscate_script(src);
    let decoded: String = results.iter().map(|r| r.decoded.as_str()).collect();

    assert!(
        !results.is_empty(),
        "packer produced no deobfuscation results"
    );
    assert!(
        decoded.contains("createDecipheriv"),
        "AES staging call not recovered: {}",
        &decoded[..decoded.len().min(200)]
    );
    assert!(
        decoded.contains("aes-128-gcm"),
        "cipher name not recovered from the decoded payload"
    );
    assert!(
        results
            .iter()
            .any(|r| r.chain_description.contains("charcode-array")),
        "expected the charcode-array chain, got: {:?}",
        results
            .iter()
            .map(|r| r.chain_description.as_str())
            .collect::<Vec<_>>()
    );
}

mod api;
mod cross_compiled;
mod edge_cases;
mod extract_from;
mod extraction_scenarios;
mod fat_binary;
mod filter;
mod garbage_edge_cases;
mod go_binary;
mod ip_detection;
mod numeric_strings;
mod pe_pointer_stack_strings;
mod real_binary;
mod rust_binary;
mod rust_pe;
mod severity;
mod shell_detection;
mod sockaddr_extraction;
mod string_deduplication;
mod string_kinds;
mod testdata_binaries;
mod wide_strings;
mod xor_detection;

/// A minimal PE with `strings` embedded as ASCII, for the submodules.
fn minimal_pe_with_strings(strings: &[&str]) -> Vec<u8> {
    let mut data = vec![0u8; 1024];

    // DOS header magic
    data[0..2].copy_from_slice(&[0x4D, 0x5A]); // MZ

    // PE offset at 0x3C
    data[0x3C..0x40].copy_from_slice(&[0x80, 0x00, 0x00, 0x00]);

    // PE signature at 0x80
    data[0x80..0x84].copy_from_slice(&[0x50, 0x45, 0x00, 0x00]); // PE\0\0

    // Embed strings starting at 0x200
    let mut offset = 0x200;
    for s in strings {
        let bytes = s.as_bytes();
        data[offset..offset + bytes.len()].copy_from_slice(bytes);
        data[offset + bytes.len()] = 0; // null terminator
        offset += bytes.len() + 1;
    }

    data
}
