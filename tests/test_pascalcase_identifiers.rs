#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Regression test: PascalCase symbol names must not be filtered as chaotic.
//!
//! Pre-fix, the chaotic-pattern detector inside `is_garbage` rejected
//! identifiers whose Upper↔Lower runs were short — even when those identifiers
//! were perfectly valid PascalCase. The real-world example that surfaced the
//! bug was a .NET PE where `strings(1)` reported `CallByName` but `stng` did
//! not, because the chaos check saw avg run length 1.67 over 10 chars and
//! flagged it.
//!
//! This test runs the full extraction pipeline against a synthetic blob and
//! asserts that PascalCase identifiers — including ones with a leading tab,
//! which is how Go's pclntab serialises method names — survive the garbage
//! filter.

use stng::{extract_strings_with_options, ExtractOptions};

#[test]
fn pascalcase_identifiers_survive_garbage_filter() {
    let mut blob = Vec::new();
    let identifiers = [
        "CallByName",
        "FooBarBaz",
        "PtrToThis",
        "SetIterKey",
        "FileSizeLow",
        "LowDateTime",
        "MaxSockAddr",
        "ReturnIsPtr",
        "GetHashCode",
        "AddRange",
    ];
    for ident in identifiers {
        // 4-byte zero padding around each string prevents the stack-string
        // extractor from interpreting the bytes as x86 instructions and
        // chopping the prefix off (e.g. seeing `5Hash` as `XOR EAX, "Hash"`).
        blob.extend_from_slice(&[0u8; 4]);
        blob.extend_from_slice(ident.as_bytes());
        blob.push(0);
    }

    let opts = ExtractOptions::new(4).with_garbage_filter(true);
    let extracted = extract_strings_with_options(&blob, &opts);
    let values: Vec<&str> = extracted.iter().map(|s| s.value.as_str()).collect();

    let missing: Vec<&str> = identifiers
        .iter()
        .copied()
        .filter(|needle| !values.iter().any(|v| v == needle))
        .collect();

    assert!(
        missing.is_empty(),
        "PascalCase identifiers filtered out: {missing:?}\nextracted: {values:?}",
    );
}

#[test]
fn tab_prefixed_identifiers_survive_garbage_filter() {
    // Go's pclntab stores method names with a literal `\t` byte prefix.
    // The control-char fast-path used to reject these because it checked the
    // pre-trim original string for any control character.
    let mut blob = Vec::new();
    let identifiers = ["\tPtrToThis", "\tSetIterKey", "\tFileSizeLow"];
    for ident in identifiers {
        // 4-byte zero padding around each string prevents the stack-string
        // extractor from interpreting the bytes as x86 instructions and
        // chopping the prefix off (e.g. seeing `5Hash` as `XOR EAX, "Hash"`).
        blob.extend_from_slice(&[0u8; 4]);
        blob.extend_from_slice(ident.as_bytes());
        blob.push(0);
    }

    let opts = ExtractOptions::new(4).with_garbage_filter(true);
    let extracted = extract_strings_with_options(&blob, &opts);
    let values: Vec<&str> = extracted.iter().map(|s| s.value.as_str()).collect();

    for ident in identifiers {
        let trimmed = ident.trim_start();
        assert!(
            values.iter().any(|v| v.trim_start() == trimmed),
            "tab-prefixed identifier {ident:?} missing from {values:?}",
        );
    }
}

#[test]
fn crypto_and_type_names_with_digits_survive() {
    // Crypto/hash names (`MD5Hash`, `SHA256Init`, `Curve25519`, `Ed25519`)
    // and runtime-style type names (`ToInt32`, `Int64`, `Argon2`) used to
    // be killed by the medium-mixed-case-digit filter.
    let mut blob = Vec::new();
    let identifiers = [
        "SHA256Init",
        "Curve25519",
        "Ed25519",
        "Argon2",
        "ToInt32",
        "Int64",
        "BCrypt",
    ];
    for ident in identifiers {
        blob.extend_from_slice(ident.as_bytes());
        blob.push(0);
    }
    // `MD5Hash` is verified separately in the validation unit tests — its
    // bytes happen to disassemble such that the stack-string extractor
    // picks up `Hash` as an x86 immediate (`XOR EAX, 0x68736148`), which
    // confuses the simple end-to-end check used here. That's an
    // orthogonal extraction-pipeline quirk, not a garbage-filter bug.

    let opts = ExtractOptions::new(4).with_garbage_filter(true);
    let extracted = extract_strings_with_options(&blob, &opts);
    let values: Vec<&str> = extracted.iter().map(|s| s.value.as_str()).collect();

    let missing: Vec<&str> = identifiers
        .iter()
        .copied()
        .filter(|needle| !values.iter().any(|v| v == needle))
        .collect();

    assert!(
        missing.is_empty(),
        "crypto/type names filtered out: {missing:?}\nextracted: {values:?}",
    );
}

#[test]
fn file_glob_patterns_survive() {
    // `*.exe`, `*.dll`, etc. are top-tier malware indicators (dropped-file
    // patterns, search filters) but were killed by the short-string
    // noise-punctuation filter because `*` is in the noise set.
    let mut blob = Vec::new();
    let globs = ["*.exe", "*.dll", "*.bin", "*.tmp", "*.log"];
    for g in globs {
        blob.extend_from_slice(g.as_bytes());
        blob.push(0);
    }

    let opts = ExtractOptions::new(4).with_garbage_filter(true);
    let extracted = extract_strings_with_options(&blob, &opts);
    let values: Vec<&str> = extracted.iter().map(|s| s.value.as_str()).collect();

    let missing: Vec<&str> = globs
        .iter()
        .copied()
        .filter(|g| !values.iter().any(|v| v == g))
        .collect();

    assert!(missing.is_empty(), "file globs filtered out: {missing:?}");
}

#[test]
fn short_camelcase_and_brand_identifiers_survive() {
    // 4-char camelCase shapes — Apple brand IDs, Hungarian notation,
    // abbreviated identifiers — used to be killed by the 7-char floor.
    let mut blob = Vec::new();
    let identifiers = ["iPad", "iMac", "iPod", "hWnd", "lpSz", "dwId"];
    for ident in identifiers {
        blob.extend_from_slice(ident.as_bytes());
        blob.push(0);
    }

    let opts = ExtractOptions::new(4).with_garbage_filter(true);
    let extracted = extract_strings_with_options(&blob, &opts);
    let values: Vec<&str> = extracted.iter().map(|s| s.value.as_str()).collect();

    let missing: Vec<&str> = identifiers
        .iter()
        .copied()
        .filter(|needle| !values.iter().any(|v| v == needle))
        .collect();

    assert!(
        missing.is_empty(),
        "4-char camelCase identifiers filtered out: {missing:?}",
    );
}

#[test]
fn assembly_fragments_survive() {
    // Disassembly-style fragments like `MOV EAX, 0` — multi-word strings
    // with whitespace separating tokens are meaningful even when each
    // individual token looks like noise.
    let mut blob = Vec::new();
    let fragments = ["MOV EAX, 0", "JMP +5", "SUB ESP, 8", "PUSH EAX"];
    for f in fragments {
        blob.extend_from_slice(f.as_bytes());
        blob.push(0);
    }

    let opts = ExtractOptions::new(4).with_garbage_filter(true);
    let extracted = extract_strings_with_options(&blob, &opts);
    let values: Vec<&str> = extracted.iter().map(|s| s.value.as_str()).collect();

    let missing: Vec<&str> = fragments
        .iter()
        .copied()
        .filter(|f| !values.iter().any(|v| v == f))
        .collect();

    assert!(
        missing.is_empty(),
        "asm fragments filtered out: {missing:?}",
    );
}

#[test]
fn long_alternating_case_letter_strings_survive() {
    // Long pure-ASCII letter strings — even with frequent case alternation —
    // are likely meaningful (identifiers, obfuscated text, words) and should
    // not be filtered as chaotic.
    let mut blob = Vec::new();
    let identifiers = ["AbCdEfGh", "PaSsWoRd", "TheQuickBrownFox", "AaBbCcDdEe"];
    for ident in identifiers {
        // 4-byte zero padding around each string prevents the stack-string
        // extractor from interpreting the bytes as x86 instructions and
        // chopping the prefix off (e.g. seeing `5Hash` as `XOR EAX, "Hash"`).
        blob.extend_from_slice(&[0u8; 4]);
        blob.extend_from_slice(ident.as_bytes());
        blob.push(0);
    }

    let opts = ExtractOptions::new(4).with_garbage_filter(true);
    let extracted = extract_strings_with_options(&blob, &opts);
    let values: Vec<&str> = extracted.iter().map(|s| s.value.as_str()).collect();

    let missing: Vec<&str> = identifiers
        .iter()
        .copied()
        .filter(|needle| !values.iter().any(|v| v == needle))
        .collect();

    assert!(
        missing.is_empty(),
        "long alternating-case letter strings filtered out: {missing:?}",
    );
}
