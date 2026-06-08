#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Native (no-radare2) PE import recovery.
//!
//! PE import names live behind RVA tables in the import directory, not as
//! inline literals, so a raw byte scan never surfaces them — they appeared only
//! under radare2. stng now resolves them via goblin's parsed import directory.
//! Regression guard: `imp.*` API names like `CreateProcessW` must be present
//! and typed without r2, and the `caller_provides_symbols` hint must suppress
//! the structured pass when the client (filefacts) already parses imports.

use stng::{ExtractOptions, StringKind, extract_strings_with_options};

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testdata/malware/sorry_ransomware.exe"
);

fn extract(caller_provides_symbols: bool) -> Vec<stng::ExtractedString> {
    let data = std::fs::read(FIXTURE).expect("read PE fixture");
    let opts = ExtractOptions {
        min_length: 4,
        filter_garbage: false,
        use_cache: false,
        caller_provides_symbols,
        ..Default::default()
    };
    extract_strings_with_options(&data, &opts)
}

#[test]
fn pe_imports_recovered_and_typed_without_r2() {
    let strings = extract(false);
    let import = |needle: &str| {
        strings
            .iter()
            .find(|s| s.value == needle)
            .unwrap_or_else(|| panic!("import {needle:?} present"))
    };

    // Win32 APIs the malware calls — invisible to a raw scan, recovered from the
    // import directory.
    for api in ["CreateProcessW", "ReadFile", "CreateThread", "ExitProcess"] {
        assert_eq!(import(api).kind, Some(StringKind::Import), "{api} typed");
    }
}

#[test]
fn caller_provides_symbols_suppresses_pe_imports() {
    // filefacts parses the import table itself; stng should not redo it. The
    // RVA-table names aren't inline literals, so suppressing the structured pass
    // legitimately drops them from stng's output (the caller owns them).
    let with = extract(false);
    let without = extract(true);
    let has = |v: &[stng::ExtractedString], n: &str| v.iter().any(|s| s.value == n);

    assert!(has(&with, "CreateProcessW"));
    assert!(
        !has(&without, "CreateProcessW"),
        "import directory pass should be skipped when caller owns symbols"
    );
}
