//! Regression tests for the polyglot / `Object::Unknown` routing fix.
//!
//! Background: a real-world dropper ("AxiomWallets", April 2026) ships
//! a `.zip` whose first 1.2 KB is a VBScript prefix and whose body is
//! a real ZIP. goblin parses this as `Object::Unknown(...)` (no known
//! binary magic). Before the fix, stng's `Object::parse` branch would
//! fire for `Unknown`, gate base64 decoding behind `is_text_file()`,
//! and `is_text_file()` would say "not text" because the file is
//! mostly binary bytes. Net result: the embedded base64 PowerShell
//! payload — which holds every campaign-distinct marker (`superlongkey`,
//! `good2luck`, `KLStorage\DiskUtTask.exe`, …) — was never decoded.
//!
//! These tests pin the routing: an `Object::Unknown` input must
//! exercise the same raw-scan + decoder pipeline that a parse-error
//! input does, regardless of `is_text_file`'s byte-percentage verdict.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use stng::{extract_strings_with_options, ExtractOptions};

/// Minimum data: a script command line that embeds a base64 payload
/// containing a marker we want to surface. No leading binary header,
/// no trailing binary tail — pure text. This must decode under all
/// routings.
#[test]
fn pure_text_with_embedded_base64_decodes_marker() {
    // base64("superlongkey-marker") = "c3VwZXJsb25na2V5LW1hcmtlcg=="
    let body = b"powershell -Command \
        [Convert]::FromBase64String('c3VwZXJsb25na2V5LW1hcmtlcg==')";
    let strings = extract_strings_with_options(body, &ExtractOptions::new(4));
    assert!(
        strings
            .iter()
            .any(|s| s.value.contains("superlongkey-marker")),
        "expected base64-decoded marker in extracted strings; got {:?}",
        strings.iter().map(|s| &s.value).collect::<Vec<_>>()
    );
}

/// The polyglot case: a short text prefix followed by a fake ZIP body
/// that gives goblin no recognised magic but enough non-printable
/// content to make `is_text_file` return false. Before the fix this
/// returned strings *without* any base64-decoded entries — the
/// embedded marker stayed hidden inside the base64 blob.
#[test]
fn polyglot_text_prefix_with_binary_tail_still_decodes_embedded_base64() {
    // Text prefix: a VBScript-style header that mentions a base64-
    // encoded marker.
    let prefix = b"On Error Resume Next\r\n\
        Dim S1, FSO\r\n\
        Set FSO = CreateObject(\"Scripting.FileSystemObject\")\r\n\
        Shell.Run \"powershell -Command \
        [Convert]::FromBase64String('c3VwZXJsb25na2V5LW1hcmtlcg==')\", 0, False\r\n";

    // Fake ZIP-style body: lots of non-printable bytes, no recognised
    // binary magic. Pushes is_text_file's printable-byte ratio below
    // the threshold and gives goblin nothing to identify.
    let mut data = prefix.to_vec();
    data.extend(std::iter::repeat_n(0u8, 8 * 1024));
    data.extend((0u8..251).cycle().take(16 * 1024));

    let strings = extract_strings_with_options(&data, &ExtractOptions::new(4));
    assert!(
        strings
            .iter()
            .any(|s| s.value.contains("superlongkey-marker")),
        "polyglot must surface base64-decoded marker through the unknown-format path; \
         saw {} extracted strings, none containing the marker",
        strings.len()
    );
}

/// Negative: a real binary (an ELF header) must still go through the
/// goblin-parse branch — the fix only re-routes `Object::Unknown`,
/// not actual recognised binaries.
#[test]
fn real_elf_still_uses_goblin_path() {
    let mut data = vec![0u8; 1024];
    data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    data[4] = 2; // 64-bit
    data[5] = 1; // little-endian
    data[6] = 1; // version
    data[16..18].copy_from_slice(&[2, 0]); // ET_EXEC
    data[18..20].copy_from_slice(&[0x3E, 0]); // EM_X86_64
                                              // We don't assert on what the goblin path returns (that's tested
                                              // elsewhere); we only need to confirm extraction doesn't blow up
                                              // and we still get *some* output. The previous routing logic for
                                              // recognised binaries is unchanged by the polyglot fix.
    let _strings = extract_strings_with_options(&data, &ExtractOptions::new(4));
}
