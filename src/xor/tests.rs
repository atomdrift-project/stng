use super::key::is_good_xor_key_candidate;
use super::scan::extract_custom_xor_strings;
use super::validate::{
    has_known_path_prefix, is_locale_string, is_meaningful_string, is_partial_xor_decode,
    is_valid_ip, is_valid_port, is_valid_xor_string, nul_ends_string,
};
use super::*;
use crate::bytes::entropy;
use crate::{ExtractedString, StringKind, StringMethod};

#[test]
fn accepts_plausible_c2_ips_only() {
    // Valid C2-like IPs
    assert!(is_valid_ip("192.168.1.1"));
    assert!(is_valid_ip("10.0.0.1"));
    assert!(is_valid_ip("45.33.32.156"));
    assert!(is_valid_ip("185.199.108.153"));

    // Invalid: out of range
    assert!(!is_valid_ip("256.1.1.1"));

    // Invalid: localhost/reserved
    assert!(!is_valid_ip("127.0.0.1"));
    assert!(!is_valid_ip("0.0.0.0"));

    // Invalid: x.0.0.0 pattern
    assert!(!is_valid_ip("1.0.0.0"));

    // Invalid: first octet is 0
    assert!(!is_valid_ip("0.7.2.126"));

    // Invalid: first octet < 10 (likely XOR artifact)
    assert!(!is_valid_ip("4.3.4.32"));

    // Invalid: all same octets (clear XOR artifact)
    assert!(!is_valid_ip("182.182.182.182"));
    assert!(!is_valid_ip("8.8.8.8")); // OK to reject popular DNS
    assert!(!is_valid_ip("1.1.1.1"));

    // Invalid: last octet is 0
    assert!(!is_valid_ip("192.168.1.0"));
}

#[test]
fn accepts_ports_in_range() {
    assert!(is_valid_port("80"));
    assert!(is_valid_port("443"));
    assert!(!is_valid_port("0"));
    assert!(!is_valid_port("65536"));
}

#[test]
fn recognizes_meaningful_strings() {
    assert!(is_meaningful_string("http://example.com"));
    assert!(is_meaningful_string("/etc/passwd"));
    assert!(!is_meaningful_string(""));
    assert!(!is_meaningful_string("XYZQWFGH")); // No vowels
}

#[test]
fn accepts_linux_rootkit_paths() {
    assert!(
        is_valid_xor_string("/proc/net/tcp"),
        "/proc/net/tcp should be valid"
    );
    assert!(
        is_valid_xor_string("/proc/net/tcp6"),
        "/proc/net/tcp6 should be valid"
    );
    assert!(
        is_valid_xor_string("ld.so.preload"),
        "ld.so.preload should be valid"
    );
}

#[test]
fn distinguishes_proc_paths_from_partial_decodes() {
    // "/proc" shares P-R-O with "%PROG"; it is not a garbled %PROGRAMDATA%.
    assert!(!is_partial_xor_decode("/proc/self/fd/"));
    assert!(!is_partial_xor_decode("/proc/self/exe"));
    assert!(is_partial_xor_decode("%UsERP4NFINE%\\"));
}

#[test]
fn splits_on_nul_only_between_strings() {
    // Encode C strings with `key`, keeping their NUL terminators raw.
    let encode = |parts: &[&[u8]], key: u8| {
        let mut out = Vec::new();
        for (i, part) in parts.iter().enumerate() {
            if i > 0 {
                out.push(0);
            }
            out.extend(part.iter().map(|b| b ^ key));
        }
        out
    };
    // A plaintext byte equal to the key encodes as a NUL mid-word.
    let password = encode(&[b"password"], b'w');
    assert_eq!(password[4], 0);
    assert!(!nul_ends_string(&password, 4, b'w'));
    // Between packed C strings a lone NUL ends one, whether the key is
    // punctuation or a letter, since its neighbors do not form a word.
    for key in *b"&x" {
        let table = encode(&[b"/tmp/.b", b"/proc"], key);
        assert!(nul_ends_string(&table, 7, key), "key {key:#x}");
    }
    // Padding (a NUL run) always ends a string.
    let padded = encode(&[b"abc", b"", b"def"], b'x');
    assert!(nul_ends_string(&padded, 3, b'x'));
}

fn make_xor_test_data(plaintext: &[u8], key: u8, offset: usize) -> Vec<u8> {
    let fill_byte = 0x01 ^ key;
    let mut data = vec![fill_byte; 100];
    for (i, b) in plaintext.iter().enumerate() {
        data[offset + i] = b ^ key;
    }
    data
}

#[test]
fn finds_single_byte_xor_url() {
    let plaintext = b"http://evil.com";
    let key: u8 = 0x42;
    let data = make_xor_test_data(plaintext, key, 20);
    let results = extract_xor_strings(&data, 10, false);
    assert!(
        results.iter().any(|r| r.value == "http://evil.com"),
        "Should find URL with XOR key 0x42. Results: {results:?}"
    );
}

#[test]
fn finds_xor_callwindowproc_anchor() {
    let key = 0x23;
    let plaintext = b"user32.dll::CallWindowProcA";
    let data = make_xor_test_data(plaintext, key, 20);
    let results = extract_xor_strings(&data, 10, false);
    assert!(
        results.iter().any(|r| r.value.contains("CallWindowProcA")),
        "XOR scan should recover a CallWindowProc execution anchor: {results:?}"
    );
}

#[test]
fn finds_single_byte_xor_ip() {
    let plaintext = b"192.168.1.100";
    let key: u8 = 0x5A;
    let data = make_xor_test_data(plaintext, key, 30);
    let results = extract_xor_strings(&data, 8, false);
    assert!(
        results.iter().any(|r| r.value == "192.168.1.100"),
        "Should find IP with XOR key 0x5A. Results: {results:?}"
    );
}

#[test]
fn finds_single_byte_xor_ip_port() {
    let plaintext = b"10.0.0.1:8080";
    let key: u8 = 0x3C;
    let data = make_xor_test_data(plaintext, key, 25);
    let results = extract_xor_strings(&data, 8, false);
    assert!(
        results.iter().any(|r| r.value == "10.0.0.1:8080"),
        "IP:port should be detected with XOR key 0x3C. Results: {results:?}"
    );
}

#[test]
fn finds_single_byte_xor_path() {
    let plaintext = b"/etc/passwd";
    let key: u8 = 0xAB;
    let data = make_xor_test_data(plaintext, key, 10);
    let results = extract_xor_strings(&data, 10, false);
    assert!(
        results.iter().any(|r| r.value == "/etc/passwd"),
        "Should find path with XOR key 0xAB. Results: {results:?}"
    );
}

#[test]
fn finds_single_byte_xor_password() {
    let plaintext = b"password=secret123";
    let key: u8 = 0x77;
    let data = make_xor_test_data(plaintext, key, 20);
    let results = extract_xor_strings(&data, 10, false);
    assert!(
        results.iter().any(|r| r.value == "password=secret123"),
        "Should find password string with XOR key 0x77. Results: {results:?}"
    );
}

#[test]
fn few_hits_on_pseudorandom_data() {
    let data: Vec<u8> = (0..1000u32)
        .map(|i| u8::try_from((i * 7 + 13) % 256).unwrap_or(0))
        .collect();
    let results = extract_xor_strings(&data, 10, false);
    assert!(
        results.len() < 10,
        "Should have few false positives on random data"
    );
}

#[test]
fn skips_case_flipping_key_0x20() {
    // Key 0x20 should be skipped - it just flips case
    let plaintext = b"GOROOT OBJECT";
    let key: u8 = 0x20;
    let data = make_xor_test_data(plaintext, key, 20);
    let results = extract_xor_strings(&data, 6, false);
    // Key 0x20 is skipped, so the plaintext must not be recovered.
    assert!(
        !results.iter().any(|r| r.value == "GOROOT OBJECT"),
        "Should skip key 0x20. Results: {results:?}"
    );
}

#[test]
fn finds_single_byte_xor_hostname() {
    let plaintext = b"evil.malware.com";
    let key: u8 = 0x55;
    let data = make_xor_test_data(plaintext, key, 20);
    let results = extract_xor_strings(&data, 10, false);
    assert!(
        results.iter().any(|r| r.value == "evil.malware.com"),
        "Hostname should be detected with XOR key 0x55. Results: {results:?}"
    );
}

#[test]
fn finds_xor_user_agent_after_padding() {
    // Simulate the actual Go PE binary scenario:
    // - Lots of 0x00/0x01 padding before the Mozilla pattern
    // - XOR key 0x42
    let key: u8 = 0x42;
    let mozilla = b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Safari/537.36";

    // Create data with padding (0x00 and 0x01 bytes)
    let mut data = vec![0x00; 50];
    data.extend(std::iter::repeat_n(0x01, 20));
    // Add XOR'd Mozilla string
    for b in mozilla {
        data.push(b ^ key);
    }
    // Add trailing padding
    data.extend(std::iter::repeat_n(0x00, 20));

    let results = extract_xor_strings(&data, 10, false);
    assert!(
        results.iter().any(|r| r.value.contains("Mozilla")),
        "Mozilla user agent should be detected with XOR key 0x42. Results: {results:?}"
    );
}

#[test]
fn rejects_xaml_margin_as_xor_ip() {
    // XAML Margin="30,10,30,0" with key 0x02: comma (0x2C) XOR 0x02 = period (0x2E),
    // turning "30,10,30,0" into "12.32.12.2" which looks like an IP.
    // The scanner must reject keys where '.' maps to common separators.
    let xaml = b"<StackPanel Margin=\"30,10,30,0\" Width=\"418\">";
    let key: u8 = 0x02;
    let data = make_xor_test_data(xaml, key, 10);
    let results = extract_xor_strings(&data, 8, false);
    assert!(
        !results
            .iter()
            .any(|r| r.value == "12.32.12.2" && r.kind == Some(StringKind::Ip)),
        "XAML margin commas must not produce false IP via XOR key 0x02. Results: {results:?}"
    );
}

#[test]
fn custom_key_decodes_single_byte_url() {
    // Test with single-byte custom XOR key
    let plaintext = b"http://malware.example.com";
    let key = vec![0x42];
    let xored: Vec<u8> = plaintext.iter().map(|b| b ^ key[0]).collect();

    let results = extract_custom_xor_strings(&xored, &key, 10, false);
    assert!(
        results
            .iter()
            .any(|r| r.value == "http://malware.example.com"),
        "Custom single-byte XOR should decode URL. Results: {results:?}"
    );
}

#[test]
fn custom_key_decodes_multi_byte_password() {
    // Test with multi-byte custom XOR key
    let plaintext = b"secret password: admin123";
    let key = b"KEY";
    let xored: Vec<u8> = plaintext
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect();

    let results = extract_custom_xor_strings(&xored, key, 10, false);
    assert!(
        results
            .iter()
            .any(|r| r.value == "secret password: admin123"),
        "Custom multi-byte XOR should decode password. Results: {results:?}"
    );
}

#[test]
fn custom_key_decodes_string_keyed_url() {
    // Test with a realistic string key
    // Use a key that doesn't produce non-printable characters when XOR'd with the plaintext
    let plaintext = b"https://c2server.evil.com/api/";
    let key = b"KEYDATA";
    let xored: Vec<u8> = plaintext
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect();

    let results = extract_custom_xor_strings(&xored, key, 10, false);
    assert!(
        results
            .iter()
            .any(|r| r.value == "https://c2server.evil.com/api/"),
        "Custom string XOR key should decode C2 URL. Results: {results:?}"
    );
}

#[test]
fn custom_empty_key_finds_nothing() {
    // Empty key should return no results
    let data = b"test data";
    let key = vec![];
    let results = extract_custom_xor_strings(data, &key, 4, false);
    assert!(results.is_empty(), "Empty key should return no results");
}

#[test]
fn custom_key_on_empty_data_finds_nothing() {
    // Empty data should return no results
    let data = b"";
    let key = b"KEY";
    let results = extract_custom_xor_strings(data, key, 4, false);
    assert!(results.is_empty(), "Empty data should return no results");
}

#[test]
fn custom_key_finds_ip_with_context() {
    // IP addresses alone (no letters) are filtered out by the alphabetic requirement
    // Test an IP with context that has letters
    let plaintext = b"Server:192.168.1.100";
    let key = b"SECRET";
    let xored: Vec<u8> = plaintext
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect();

    let results = extract_custom_xor_strings(&xored, key, 8, false);
    assert!(
        results.iter().any(|r| r.value.contains("192.168.1.100")),
        "Custom XOR should detect IP addresses with context. Results: {results:?}"
    );
}

#[test]
fn custom_key_finds_path() {
    // Test path detection with custom XOR
    let plaintext = b"/bin/bash";
    let key = b"XOR";
    let xored: Vec<u8> = plaintext
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect();

    let results = extract_custom_xor_strings(&xored, key, 4, false);
    assert!(
        results.iter().any(|r| r.value == "/bin/bash"),
        "Custom XOR should detect paths. Results: {results:?}"
    );
}

#[test]
fn classifies_xor_keystore_path_as_suspicious() {
    // Test that suspicious paths are detected even with trailing garbage
    // (Leading garbage would shift key alignment and garble the entire string)
    let plaintext = b"/Library/Ethereum/keystore";
    let key = b"KEY";
    let xored: Vec<u8> = plaintext
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect();

    let results = extract_custom_xor_strings(&xored, key, 10, false);
    assert!(
        results
            .iter()
            .any(|r| r.kind == Some(StringKind::SuspiciousPath)
                && r.value.contains("/Library/Ethereum/keystore")),
        "Should detect Ethereum keystore path. Results: {results:?}"
    );
}

#[test]
fn classifies_shell_command_despite_trailing_garbage() {
    // Real-world case: screencapture command with trailing garbage
    let plaintext = b"fscreencapture -x -t %s \"%s\"SlY";
    let key = b"KEY";
    let xored: Vec<u8> = plaintext
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect();

    let results = extract_custom_xor_strings(&xored, key, 10, false);
    assert!(
        results
            .iter()
            .any(|r| r.kind == Some(StringKind::ShellCmd) && r.value.contains("screencapture")),
        "Should detect screencapture command even with trailing garbage. Results: {results:?}"
    );
}

#[test]
fn rejects_backtick_garbage_as_shell() {
    // Garbage starting with backtick should NOT be classified as shell command
    let garbage = b"`{ Cy\\.ADpv~~AblBWJU,OWJ.wZOR+qnt";
    let key = b"KEY";
    let xored: Vec<u8> = garbage
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect();

    let results = extract_custom_xor_strings(&xored, key, 10, false);
    assert!(
        !results.iter().any(|r| r.kind == Some(StringKind::ShellCmd)),
        "Garbage with backtick should NOT be shell command. Results: {results:?}"
    );
}

#[test]
fn rejects_garbage_paths() {
    let key = b"KEY";

    // Test garbage with special chars
    let garbage1 = b"/<})M9*&D@44$]";
    let xored1: Vec<u8> = garbage1
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect();
    let results1 = extract_custom_xor_strings(&xored1, key, 4, false);
    assert!(
        !results1.iter().any(|r| r.kind == Some(StringKind::Path)),
        "Garbage with special chars should NOT be path"
    );

    // Test garbage with mixed case + digits
    let garbage2 = b"/1H1ktn5UtJ8VKgaf";
    let xored2: Vec<u8> = garbage2
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect();
    let results2 = extract_custom_xor_strings(&xored2, key, 4, false);
    assert!(
        !results2.iter().any(|r| r.kind == Some(StringKind::Path)),
        "Garbage with mixed case and digits should NOT be path"
    );

    // Test garbage with mixed case + special chars
    let garbage3 = b"/o2lBYC}rOkeH^";
    let xored3: Vec<u8> = garbage3
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect();
    let results3 = extract_custom_xor_strings(&xored3, key, 4, false);
    assert!(
        !results3.iter().any(|r| r.kind == Some(StringKind::Path)),
        "Garbage with special chars should NOT be path"
    );
}

#[test]
fn finds_xor_library_path() {
    // Test Library pattern detection
    let plaintext = b"/Library/Application Support/";
    let key: u8 = 0x33;
    let data = make_xor_test_data(plaintext, key, 20);
    let results = extract_xor_strings(&data, 10, false);
    assert!(
        results.iter().any(|r| r.value.contains("Library")),
        "Should detect Library in XOR'd path. Results: {results:?}"
    );
}

#[test]
fn finds_xor_ethereum_path() {
    // Test Ethereum pattern detection
    let plaintext = b"/Library/Ethereum/keystore";
    let key: u8 = 0x7F;
    let data = make_xor_test_data(plaintext, key, 15);
    let results = extract_xor_strings(&data, 10, false);
    assert!(
        results.iter().any(|r| r.value.contains("Ethereum")),
        "Should detect Ethereum in XOR'd path. Results: {results:?}"
    );
}

#[test]
fn finds_xor_format_string() {
    // Test " %s " pattern detection with a longer, more meaningful string
    let plaintext = b"File path is %s and size is %d bytes";
    let key: u8 = 0x42;
    let data = make_xor_test_data(plaintext, key, 25);
    let results = extract_xor_strings(&data, 10, false);
    assert!(
        results
            .iter()
            .any(|r| r.value == "File path is %s and size is %d bytes"
                && r.data_offset == 25
                && r.method == StringMethod::XorDecode),
        "Should detect format string with ' %s ' pattern. Results: {results:?}"
    );
}

#[test]
fn accepts_known_malware_xor_keys() {
    // Test known DPRK and other malware XOR keys
    let known_keys = vec![
        "fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf", // HomaBrew malware
        "Moz&Wie;#t/6T!2y",                // DPRK malware
        "12GWAPCT1F0I1S14",                // DPRK malware
        "009WAYHb90687PXkS",               // Another sample
        ".sV%58&.lypQ[$=",                 // Another sample
    ];

    for key in &known_keys {
        let entropy = entropy(key.as_bytes());
        assert!(
            is_good_xor_key_candidate(key, entropy),
            "Known XOR key '{key}' should qualify (entropy: {entropy:.2})"
        );
    }
}

#[test]
fn rejects_weak_xor_key_candidates() {
    // These should NOT qualify as good XOR keys
    let bad_keys = vec![
        "abcdefghijklmnopqrstuvwxyz", // Sequential, despite high entropy
        "short",                      // Too short
        "this_has_underscores_12345", // Has underscores
        "AAAAAAAAAAAAAAAAA",          // Low entropy
        "1111111111111111",           // Low entropy, all same type
        "verylongkeythatexceedsthirtytwocharacterslimit", // Too long
    ];

    for key in &bad_keys {
        let entropy = entropy(key.as_bytes());
        assert!(
            !is_good_xor_key_candidate(key, entropy),
            "Bad key candidate '{key}' should NOT qualify"
        );
    }
}

#[test]
fn entropy_tracks_byte_diversity() {
    // Test entropy calculation
    let uniform = "abcdefgh"; // 8 unique chars = 3.0 bits
    let entropy1 = entropy(uniform.as_bytes());
    assert!(
        entropy1 > 2.9 && entropy1 < 3.1,
        "Uniform distribution should have ~3.0 bits entropy, got {entropy1:.2}"
    );

    let repeated = "aaaaaaaa"; // All same = 0 bits
    let entropy2 = entropy(repeated.as_bytes());
    assert!(
        entropy2 < 0.1,
        "All same character should have ~0 bits entropy, got {entropy2:.2}"
    );

    let mixed = "aAbBcCdD1!2@3#"; // High entropy
    let entropy3 = entropy(mixed.as_bytes());
    assert!(
        entropy3 > 3.5,
        "Mixed characters should have high entropy, got {entropy3:.2}"
    );
}

#[test]
fn auto_detect_needs_more_than_one_short_hit() {
    // Create test data with a known XOR key (realistic DPRK-style key)
    let plaintext = b"http://evil.com/malware.exe";
    let key_string = "fYztZORL5VNS7nC"; // 15 chars, high entropy
    let key_bytes = key_string.as_bytes();

    // XOR the plaintext
    let xored: Vec<u8> = plaintext
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key_bytes[i % key_bytes.len()])
        .collect();

    // Create candidate strings (simulating extracted strings from binary)
    let candidates = vec![
        ExtractedString {
            value: "some_underscore_string".to_string(),
            data_offset: 0,
            method: StringMethod::RawScan,
            kind: None,
            ..Default::default()
        },
        ExtractedString {
            value: "cstr.SomeString".to_string(),
            data_offset: 100,
            method: StringMethod::RawScan,
            kind: None,
            ..Default::default()
        },
        ExtractedString {
            value: "ShortKey".to_string(),
            data_offset: 200,
            method: StringMethod::RawScan,
            kind: None,
            ..Default::default()
        },
        ExtractedString {
            value: key_string.to_string(), // The actual key
            data_offset: 300,
            method: StringMethod::RawScan,
            kind: None,
            ..Default::default()
        },
    ];

    // Auto-detect should find the right key
    let detected = auto_detect_xor_key(&xored, &candidates, 10);

    // One short URL is below the evidence threshold; detection on a
    // real sample is covered by tests/it/xor_realworld.rs.
    assert_eq!(detected, None);
}

#[test]
fn detects_brew_agent_xor_key() {
    // Test that we can auto-detect the correct XOR key for HomeBrew malware
    // The correct key is "fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf"
    // This key should score highest because it decodes osascript commands and Ethereum paths

    let key_string = "fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf";
    let key_bytes = key_string.as_bytes();

    // XOR some high-value strings with this key
    let strings = vec![
        "osascript 2>&1 <<EOD",
        "/Library/Ethereum/keystore",
        "screencapture -x -t %s",
        "en-US",
        "ru-RU",
        "Safari/537.36",
    ];

    let mut xored_data = Vec::new();
    for s in &strings {
        let xored: Vec<u8> = s
            .as_bytes()
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key_bytes[i % key_bytes.len()])
            .collect();
        xored_data.extend_from_slice(&xored);
        xored_data.extend_from_slice(&[0xFF; 50]); // Padding (use 0xFF to avoid null regions)
    }

    // Create candidate strings including the real key
    let candidates = vec![
        ExtractedString {
            value: "some_other_key_12345".to_string(),
            data_offset: 0,
            method: StringMethod::RawScan,
            kind: None,
            ..Default::default()
        },
        ExtractedString {
            value: key_string.to_string(),
            data_offset: 100,
            method: StringMethod::RawScan,
            kind: None,
            ..Default::default()
        },
    ];

    // Auto-detect should find the correct key
    let detected = auto_detect_xor_key(&xored_data, &candidates, 10);
    assert!(
        detected.is_some(),
        "Should auto-detect XOR key from candidates"
    );

    let (detected_key, detected_str, _) = detected.unwrap();
    assert_eq!(
        detected_key, key_bytes,
        "Should detect the correct XOR key based on osascript and Ethereum strings"
    );
    assert_eq!(detected_str, key_string);

    // Verify that the detected key decodes the strings correctly
    let decoded_results = extract_custom_xor_strings(&xored_data, &detected_key, 10, false);
    let decoded_values: Vec<String> = decoded_results.iter().map(|r| r.value.clone()).collect();

    // Should find osascript (highest priority)
    assert!(
        decoded_values.iter().any(|s| s.contains("osascript")),
        "Should decode osascript command"
    );

    // Should find Ethereum path (crypto keyword, high priority)
    assert!(
        decoded_values.iter().any(|s| s.contains("Ethereum")),
        "Should decode Ethereum keystore path"
    );

    // Should find Safari (browser keyword)
    assert!(
        decoded_values.iter().any(|s| s.contains("Safari")),
        "Should decode Safari user agent"
    );
}

#[test]
fn recognizes_locale_strings() {
    // Test locale string recognition
    assert!(is_locale_string("en-US"));
    assert!(is_locale_string("ru-RU"));
    assert!(is_locale_string("zh-CN"));
    assert!(is_locale_string("en_US"));
    assert!(is_locale_string("ru_RU"));
    assert!(is_locale_string("eng-US")); // 3-letter code

    // Not locale strings
    assert!(!is_locale_string("en"));
    assert!(!is_locale_string("USA"));
    assert!(!is_locale_string("en-us")); // lowercase country code
    assert!(!is_locale_string("EN-US")); // uppercase language code
    assert!(!is_locale_string("e1-US")); // digit in language code
    assert!(!is_locale_string("toolong"));
}

#[test]
fn recognizes_known_path_prefixes() {
    // UNIX/Linux paths
    assert!(has_known_path_prefix("/bin/bash"));
    assert!(has_known_path_prefix("/usr/bin/python"));
    assert!(has_known_path_prefix("/etc/passwd"));
    assert!(has_known_path_prefix("/tmp/test.txt"));

    // macOS paths
    assert!(has_known_path_prefix("/Library/Ethereum/keystore"));
    assert!(has_known_path_prefix("/Users/admin/.ssh/id_rsa"));
    assert!(has_known_path_prefix("/Applications/Safari.app"));

    // Windows paths
    assert!(has_known_path_prefix("C:\\Windows\\System32"));
    assert!(has_known_path_prefix("C:\\Program Files\\app"));
    assert!(has_known_path_prefix("%APPDATA%\\data"));

    // Relative paths with structure
    assert!(has_known_path_prefix("./lib/module/file.js"));
    assert!(has_known_path_prefix("../config/settings.json"));

    // Relative paths with single component (common for malware)
    assert!(has_known_path_prefix("./malware"));
    assert!(has_known_path_prefix("./payload"));
    assert!(has_known_path_prefix("./a"));

    // Not known prefixes
    assert!(!has_known_path_prefix("/unknown/path"));
    assert!(!has_known_path_prefix("random/path")); // No leading ./
    assert!(!has_known_path_prefix("./")); // Empty after ./
}
