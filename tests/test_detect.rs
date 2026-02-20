//! Tests for language and file type detection (detect.rs, binary.rs detection functions).

use std::path::Path;
use stng::{detect_language, is_go_binary, is_rust_binary, is_text_file};

fn minimal_elf_header() -> Vec<u8> {
    let mut data = vec![0u8; 512];
    data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    data[4] = 2; // 64-bit
    data[5] = 1; // little-endian
    data[6] = 1; // version
    data[16..18].copy_from_slice(&[2, 0]); // ET_EXEC
    data[18..20].copy_from_slice(&[0x3E, 0]); // EM_X86_64
    data[20..24].copy_from_slice(&[1, 0, 0, 0]); // EV_CURRENT
    data
}

#[test]
fn test_detect_language_plain_text() {
    let data = b"Hello, world! This is a plain text file.\n\
                 It has multiple lines and ASCII characters like ABC123.\n\
                 The content is all printable and has no binary markers.";
    assert_eq!(
        detect_language(data),
        "text",
        "ASCII text should be detected as 'text'"
    );
}

#[test]
fn test_detect_language_empty() {
    assert_eq!(
        detect_language(&[]),
        "unknown",
        "Empty data should be 'unknown'"
    );
}

#[test]
fn test_detect_language_all_zeros() {
    let data = vec![0u8; 512];
    assert_eq!(
        detect_language(&data),
        "unknown",
        "All-zero bytes should be 'unknown'"
    );
}

#[test]
fn test_detect_language_elf_no_language_markers() {
    // Minimal ELF without Go or Rust section markers — neither language, but is a binary
    let data = minimal_elf_header();
    assert_eq!(
        detect_language(&data),
        "unknown",
        "ELF without language markers should be 'unknown'"
    );
}

#[test]
fn test_is_text_file_plain_ascii() {
    let data =
        b"This is a plain text file.\nWith multiple lines.\nAnd mostly printable ASCII content.";
    assert!(is_text_file(data), "Plain ASCII should be text");
}

#[test]
fn test_is_text_file_empty() {
    assert!(!is_text_file(&[]), "Empty data is not text");
}

#[test]
fn test_is_text_file_rejects_elf_magic() {
    let mut data = vec![b'A'; 200];
    data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    assert!(
        !is_text_file(&data),
        "ELF magic must be rejected as text even if rest is printable"
    );
}

#[test]
fn test_is_text_file_rejects_macho_64bit_le() {
    let mut data = vec![b'A'; 200];
    data[0..4].copy_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]);
    assert!(
        !is_text_file(&data),
        "64-bit Mach-O LE magic must be rejected as text"
    );
}

#[test]
fn test_is_text_file_rejects_macho_32bit_le() {
    let mut data = vec![b'A'; 200];
    data[0..4].copy_from_slice(&[0xCE, 0xFA, 0xED, 0xFE]);
    assert!(
        !is_text_file(&data),
        "32-bit Mach-O LE magic must be rejected as text"
    );
}

#[test]
fn test_is_text_file_rejects_fat_macho() {
    let mut data = vec![b'A'; 200];
    data[0..4].copy_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
    assert!(
        !is_text_file(&data),
        "Fat Mach-O magic must be rejected as text"
    );
}

#[test]
fn test_is_text_file_rejects_pe_mz_header() {
    let mut data = vec![b'A'; 200];
    data[0..2].copy_from_slice(b"MZ");
    assert!(
        !is_text_file(&data),
        "PE MZ header must be rejected as text"
    );
}

#[test]
fn test_is_text_file_rejects_high_binary_ratio() {
    // Cycle through all byte values — far below 85% printable
    let data: Vec<u8> = (0u8..=255).cycle().take(256).collect();
    assert!(
        !is_text_file(&data),
        "Data with many non-printable bytes should not be text"
    );
}

#[test]
fn test_is_text_file_rejects_more_than_two_nulls() {
    let mut data = vec![b'A'; 200];
    data[10] = 0;
    data[50] = 0;
    data[100] = 0; // third null — exceeds the tolerance of 2
    assert!(
        !is_text_file(&data),
        "Data with more than 2 null bytes should not be text"
    );
}

#[test]
fn test_is_text_file_allows_two_nulls() {
    // Exactly 2 null bytes within otherwise printable text should still pass
    let mut data = b"This is printable text content for testing null byte tolerance.".to_vec();
    data.extend(
        b"More content to ensure sample size is sufficient for the 85% threshold test.\n".repeat(3),
    );
    data[20] = 0;
    data[40] = 0;
    assert!(
        is_text_file(&data),
        "Data with exactly 2 null bytes should still be considered text if otherwise printable"
    );
}

#[test]
fn test_is_go_binary_false_for_minimal_elf() {
    let data = minimal_elf_header();
    assert!(
        !is_go_binary(&data),
        "Minimal ELF without .gopclntab or .go.buildinfo should not be Go"
    );
}

#[test]
fn test_is_go_binary_false_for_text() {
    let data = b"Just a plain text string with no binary markers at all.";
    assert!(!is_go_binary(data), "Plain text should not be a Go binary");
}

#[test]
fn test_is_rust_binary_false_for_minimal_elf() {
    let data = minimal_elf_header();
    assert!(
        !is_rust_binary(&data),
        "Minimal ELF without .rustc section should not be Rust"
    );
}

#[test]
fn test_is_rust_binary_false_for_text() {
    let data = b"This is not a Rust binary, just text.";
    assert!(
        !is_rust_binary(data),
        "Plain text should not be a Rust binary"
    );
}

#[test]
fn test_detect_language_with_real_go_binary() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/testdata/hello_linux_amd64"
    );
    if !Path::new(path).exists() {
        return; // Skip if fixture not available
    }
    let data = std::fs::read(path).expect("Failed to read test binary");
    assert_eq!(
        detect_language(&data),
        "go",
        "hello_linux_amd64 should be detected as 'go' via .gopclntab marker"
    );
}

#[test]
fn test_is_go_binary_true_for_real_go_binary() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/testdata/hello_linux_amd64"
    );
    if !Path::new(path).exists() {
        return;
    }
    let data = std::fs::read(path).expect("Failed to read test binary");
    assert!(
        is_go_binary(&data),
        "hello_linux_amd64 should be identified as a Go binary"
    );
}

#[test]
fn test_is_rust_binary_false_for_go_binary() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/testdata/hello_linux_amd64"
    );
    if !Path::new(path).exists() {
        return;
    }
    let data = std::fs::read(path).expect("Failed to read test binary");
    assert!(
        !is_rust_binary(&data),
        "hello_linux_amd64 (Go binary) should not be identified as Rust"
    );
}
