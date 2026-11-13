//! PE import recovery.
//!
//! PE import names live behind RVA tables in the import directory; stng
//! resolves them through goblin's parsed import directory and types them. API names like `CreateProcessW`
//! must be present and typed, and the `caller_provides_symbols`
//! hint must suppress the structured pass for a caller that parses imports
//! itself.

use stng::{ExtractOptions, StringKind, extract_strings_with_options};

static FIXTURE: std::sync::LazyLock<&str> =
    std::sync::LazyLock::new(|| crate::common::path("testdata/malware/sorry_ransomware.exe"));

fn extract(caller_provides_symbols: bool) -> Vec<stng::ExtractedString> {
    let data = std::fs::read(*FIXTURE).expect("read PE fixture");
    let opts = ExtractOptions::new(4).with_caller_provides_symbols(caller_provides_symbols);
    extract_strings_with_options(&data, &opts)
}

#[test]
fn pe_imports_recovered_and_typed() {
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
    // A caller that parses the import table itself does not want stng to redo
    // it: no string is typed as an import. The hint/name table's bytes still
    // sit in `.rdata`, so the raw scan may report the same text untyped, as it
    // does for any PE.
    let with = extract(false);
    let without = extract(true);
    let import = |v: &[stng::ExtractedString], n: &str| {
        v.iter()
            .any(|s| s.value == n && s.kind == Some(StringKind::Import))
    };

    assert!(import(&with, "CreateProcessW"));
    assert!(
        !import(&without, "CreateProcessW"),
        "import directory pass should be skipped when caller owns symbols"
    );
}
