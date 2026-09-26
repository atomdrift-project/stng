#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Recognising an ordinary Rust executable as Rust.
//!
//! ELF (and Mach-O) Rust detection used to key on a `rust`-named section. Only
//! dylibs and proc-macros carry `.rustc`; an ordinary executable -- stripped or
//! not -- has none, so every Rust program went down the unknown-binary path and
//! its `&str` literals were never sliced out of rustc's packed string blob: the
//! raw scan reported the blob as long merged runs instead.
//!
//! The fixture is a dependency-free program built stripped by a distro
//! toolchain, which remaps libstd's source prefix: it carries neither
//! `/rustc/<sha>` nor `index.crates.io`, only `library/std/src/...` panic
//! locations. See `testdata/rust_elf/src`.

use std::path::Path;

use stng::{StringMethod, extract_strings, is_rust_binary};

fn fixture(rel: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/testdata")
        .join(rel);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn stripped_rust_executable_is_detected() {
    assert!(is_rust_binary(&fixture("rust_elf/linux_amd64")));
}

#[test]
fn non_rust_binaries_are_not_detected() {
    for rel in [
        "go_pclntab/linux_amd64",
        "go_pclntab/darwin_arm64",
        "go_pclntab/windows_amd64",
    ] {
        assert!(!is_rust_binary(&fixture(rel)), "{rel} detected as Rust");
    }
}

/// The literals come out whole, through the Rust passes, at their own bytes --
/// not as a fragment of a longer raw-scan run over the packed blob.
#[test]
fn rust_literals_are_sliced_from_the_packed_blob() {
    let data = fixture("rust_elf/linux_amd64");
    let strings = extract_strings(&data, 4);
    for literal in [
        "stng-rust-fixture-alpha-literal",
        "stng-rust-fixture-bravo-literal",
        "stng-rust-fixture-charlie-literal",
        "stng-rust-fixture-delta-literal",
    ] {
        let hit = strings
            .iter()
            .find(|s| {
                s.value == literal
                    && matches!(
                        s.method,
                        StringMethod::Structure | StringMethod::InstructionPattern
                    )
            })
            .unwrap_or_else(|| panic!("{literal} not recovered by the Rust passes"));
        let start = usize::try_from(hit.data_offset).unwrap();
        assert_eq!(
            data.get(start..start + literal.len()),
            Some(literal.as_bytes()),
            "{literal} reported at {:#x}, but those bytes differ",
            hit.data_offset
        );
    }
}

/// The Rust passes only cover literals Rust code names. Everything the raw
/// scan found before -- here the dynamic linker's library and symbol-version
/// strings -- must still be reported now that Rust executables take this path.
#[test]
fn raw_scan_strings_survive_the_rust_path() {
    let strings = extract_strings(&fixture("rust_elf/linux_amd64"), 4);
    for raw in ["libc.so.6", "GLIBC_2.2.5"] {
        assert!(
            strings.iter().any(|s| s.value == raw),
            "{raw} lost on the Rust path"
        );
    }
}
