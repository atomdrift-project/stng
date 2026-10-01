#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use goblin::{Object, mach::Mach};
static FILE: std::sync::LazyLock<&[u8]> = std::sync::LazyLock::new(|| {
    crate::test_fixture("testdata/macho/rust_heap_xor_installer_universal.macho")
});
fn path_strings(bytes: &[u8]) -> Vec<ExtractedString> {
    let Object::Mach(Mach::Binary(m)) = Object::parse(bytes).unwrap() else {
        panic!("thin")
    };
    RustStringExtractor::new(4)
        .extract_macho(&m, 8192)
        .into_iter()
        .filter(|s| {
            s.value == "/Local Extension Settings" && s.method == crate::StringMethod::Structure
        })
        .collect()
}
#[test]
fn slice_headers_in_both_data_segment_names_preserve_exact_string_and_offset() {
    let original = &FILE[8192..8192 + 4143304];
    let mut p = 32;
    let mut header = None;
    let word = |p| u32::from_le_bytes(original[p..p + 4].try_into().unwrap()) as usize;
    for _ in 0..word(16) {
        if word(p) == 0x19
            && original[p + 8..p + 24].split(|b| *b == 0).next().unwrap() == b"__DATA"
        {
            header = Some(p);
        }
        p += word(p + 4);
    }
    for name in ["__DATA", "__DATA_CONST", "__IGNORED"] {
        let mut b = original.to_vec();
        let p = header.unwrap() + 8;
        b[p..p + 16].fill(0);
        b[p..p + name.len()].copy_from_slice(name.as_bytes());
        let out = path_strings(&b);
        if name == "__IGNORED" {
            assert!(out.is_empty());
        } else {
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].data_offset, 2837322);
            assert_eq!(out[0].source_spans().collect::<Vec<_>>(), [(2837322, 25)]);
        }
    }
}
#[test]
fn public_pipeline_recovers_all_six_reviewed_sql_literal_boundaries() {
    let opts = crate::ExtractOptions {
        caller_provides_symbols: true,
        filter_garbage: true,
        ..Default::default()
    };
    let out = crate::extract_strings_with_options(*FILE, &opts);
    for (text, offset) in [
        (
            "SELECT origin_url, username_value, password_value FROM logins;",
            2836615,
        ),
        (
            "SELECT service, encrypted_token FROM token_service;",
            2836729,
        ),
        ("SELECT name, value FROM autofill;", 2836834),
        ("SELECT title, url, visit_count FROM urls;", 2836899),
        (
            "SELECT name_on_card, card_number_encrypted, expiration_month, expiration_year FROM credit_cards;",
            2836987,
        ),
        (
            "SELECT host_key, name, samesite, value, encrypted_value, path, expires_utc, is_secure, is_httponly FROM cookies;",
            2837164,
        ),
    ] {
        assert_eq!(&FILE[offset..offset + text.len()], text.as_bytes());
        assert!(
            out.iter().any(|s| s.value == text
                && s.method == crate::StringMethod::InstructionPattern
                && s.source_spans().collect::<Vec<_>>() == [(offset as u64, text.len() as u64)]),
            "{text}"
        );
    }
}
