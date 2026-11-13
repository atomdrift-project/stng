use stng::{ExtractOptions, extract_strings_with_options};

use super::rust_pe::pe_with_rdata;

/// NUL-terminated UTF-16LE bytes for `s`.
fn utf16z(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(u16::to_le_bytes)
        .collect()
}

/// A numeric value is a string someone wrote: the Dofoil/Smoke Loader crypter
/// (2018) passed the wide literal `1444444444` to CreateFileW as a sandbox
/// probe, and the digit-run garbage rule used to drop it. A single repeated
/// digit, the filler u16 lookup tables produce, is still noise. The garbage
/// filter is on, as cleave runs it.
#[test]
fn pe_keeps_numeric_wide_values_but_not_digit_filler() {
    let mut rdata = vec![0u8; 16];
    rdata.extend(utf16z("1444444444"));
    rdata.extend([0u8; 16]);
    rdata.extend(utf16z("22222222"));
    let pe = pe_with_rdata(&rdata);

    let values: Vec<String> =
        extract_strings_with_options(&pe, &ExtractOptions::new(4).with_garbage_filter(true))
            .into_iter()
            .map(|s| s.value)
            .collect();
    assert!(
        values.iter().any(|v| v == "1444444444"),
        "numeric wide value was dropped: {values:?}"
    );
    assert!(
        !values.iter().any(|v| v == "22222222"),
        "single-digit filler was kept: {values:?}"
    );
}
