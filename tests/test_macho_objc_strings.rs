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
