#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Native (no-radare2) Mach-O string fidelity.
//!
//! `wallet_report_objc` is an Objective-C wallet-stealer specimen whose
//! `find … -iname "*wallet*"` command is split across separate C-string
//! literals (`find`, `-maxdepth`, `*wallet*`, …) and assembled at runtime via
//! `snprintf` — a string-splitting evasion. stng must not reassemble it (that
//! would fabricate data), but every fragment, the format template, and the
//! Objective-C selectors must SURVIVE with an accurate location so an analyst
//! can correlate them by section + offset.
//!
//! Regression guard for two native-extractor bugs that previously dropped data
//! whenever radare2 was unavailable:
//!   1. the `__objc_methname` selector section was never scanned, and
//!   2. section-relative offsets collided in the offset-only dedup, dropping
//!      e.g. `find` (`__cstring:0`) against `__mh_execute_header` (`:0`).

use stng::{ExtractOptions, extract_strings_with_options};

/// Extract with the same options a downstream pipeline client uses: a plain
/// raw-byte scan with garbage filtering off and **no radare2** (default
/// `ExtractOptions` leaves `use_r2 == false`), so the test is hermetic and
/// exercises the native parser only.
fn native_strings() -> Vec<stng::ExtractedString> {
    let data = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/macho/wallet_report_objc"
    ))
    .expect("read fixture");
    let opts = ExtractOptions {
        min_length: 4,
        filter_garbage: false,
        use_cache: false,
        ..Default::default()
    };
    extract_strings_with_options(&data, &opts)
}

#[test]
fn obfuscation_fragments_survive_without_r2() {
    let strings = native_strings();
    let has = |needle: &str| strings.iter().any(|s| s.value == needle);

    // The split command fragments and the snprintf format template. The
    // leading `find` literal previously vanished to an offset-dedup collision.
    for fragment in [
        "find",
        "-maxdepth",
        "*wallet*",
        "*keystore*",
        "id.json",
        r#"%s %s %s 6 -iname "%s" -o -iname "%s" -o -iname "%s" 2>/dev/null | head -30"#,
        "https://api.telegram.org/bot123456789:ABCDEF/sendMessage",
    ] {
        assert!(has(fragment), "missing fragment: {fragment:?}");
    }
}

#[test]
fn objc_selectors_survive_without_r2() {
    let strings = native_strings();
    let has = |needle: &str| strings.iter().any(|s| s.value == needle);

    // __objc_methname selectors describe the runtime behaviour (build an
    // NSURLRequest, set the HTTP body, POST it). The native parser used to skip
    // the whole section, so these only appeared under radare2.
    for selector in [
        "URLWithString:",
        "requestWithURL:",
        "setHTTPBody:",
        "setHTTPMethod:",
        "setValue:forHTTPHeaderField:",
        "dataUsingEncoding:",
        "stringWithFormat:",
    ] {
        assert!(has(selector), "missing ObjC selector: {selector:?}");
    }
}

#[test]
fn symbol_table_entries_are_typed_without_r2() {
    let strings = native_strings();
    let kind_of = |needle: &str| {
        strings
            .iter()
            .find(|s| s.value == needle)
            .unwrap_or_else(|| panic!("symbol {needle:?} present"))
            .kind
    };

    // Native nlist walk classifies symbols the bind-info / export-trie views
    // miss. These previously appeared only as untyped raw __LINKEDIT scan hits.
    use stng::StringKind;
    assert_eq!(kind_of("_popen"), Some(StringKind::Import));
    assert_eq!(kind_of("_OBJC_CLASS_$_NSURL"), Some(StringKind::Import));
    assert_eq!(
        kind_of("_objc_msgSend$setHTTPBody:"),
        Some(StringKind::FuncName)
    );
}

#[test]
fn caller_provides_symbols_skips_typing_but_keeps_strings() {
    // When the caller owns symbol extraction (e.g. filefacts), stng must not
    // redo the structured pass — but the names must still SURVIVE as strings so
    // nothing is lost; only the typing is suppressed.
    let data = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/macho/wallet_report_objc"
    ))
    .expect("read fixture");
    let opts = ExtractOptions {
        min_length: 4,
        filter_garbage: false,
        use_cache: false,
        caller_provides_symbols: true,
        ..Default::default()
    };
    let strings = extract_strings_with_options(&data, &opts);
    let entry = |needle: &str| strings.iter().find(|s| s.value == needle);

    // Still present (raw scan of __LINKEDIT), but no longer typed as an import.
    let popen = entry("_popen").expect("`_popen` still present as a string");
    assert_eq!(
        popen.kind, None,
        "structured import typing should be suppressed"
    );
    // Ordinary string-literal extraction is unaffected.
    assert!(entry("find").is_some());
    assert!(entry("setHTTPBody:").is_some());
}

#[test]
fn from_object_matches_full_parse() {
    // The pre-parsed entry point lets a caller (filefacts) parse the binary once
    // and hand the goblin object to stng, skipping a second parse. Guard that it
    // yields the same string set as the parse-it-yourself path, so the
    // double-parse optimisation is behaviour-preserving.
    let data = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/macho/wallet_report_objc"
    ))
    .expect("read fixture");
    let opts = ExtractOptions {
        min_length: 4,
        filter_garbage: false,
        use_cache: false,
        ..Default::default()
    };

    let via_bytes = extract_strings_with_options(&data, &opts);
    let object = stng::goblin::Object::parse(&data).expect("parse object");
    let via_object = stng::extract_strings_from_object(&object, &data, &opts);

    let set = |v: &[stng::ExtractedString]| {
        v.iter()
            .map(|s| s.value.clone())
            .collect::<std::collections::BTreeSet<_>>()
    };
    assert_eq!(
        set(&via_bytes),
        set(&via_object),
        "pre-parsed object path must extract the same strings"
    );
}

#[test]
fn fragments_are_locatable_by_section_and_offset() {
    let strings = native_strings();

    // `find` lives at the very start of __cstring; correlation by location
    // depends on both the section tag and the section-relative offset.
    let find = strings
        .iter()
        .find(|s| s.value == "find")
        .expect("`find` present");
    assert_eq!(find.section.as_deref(), Some("__cstring"));
    assert_eq!(find.data_offset, 0, "`find` is the first __cstring entry");

    // A selector must be tagged to its own section, not collapsed into another.
    let selector = strings
        .iter()
        .find(|s| s.value == "setHTTPBody:")
        .expect("selector present");
    assert_eq!(selector.section.as_deref(), Some("__objc_methname"));
}
