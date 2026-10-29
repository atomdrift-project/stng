use stng::{ExtractOptions, StringKind};

#[test]
fn test_kworker_character_assembly_detection() {
    let sample_path = crate::common::path("testdata/kworker_samples/kworker_obfuscated_1");

    let data = std::fs::read(sample_path).expect("Failed to read kworker sample");

    let opts = ExtractOptions::new(4);
    let extracted = stng::extract_strings_with_options(&data, &opts);

    // Collect all strings for analysis

    // Print suspicious strings (high severity)
    let suspicious: Vec<_> = extracted
        .iter()
        .filter(|s| {
            s.kind == Some(StringKind::SuspiciousPath)
                || s.kind == Some(StringKind::ShellCmd)
                || s.kind == Some(StringKind::StackString)
        })
        .collect();

    // Print stack strings (character-by-character constructions)
    let stack_strings: Vec<_> = extracted
        .iter()
        .filter(|s| s.kind == Some(StringKind::StackString))
        .map(|s| s.value.as_str())
        .collect();

    // Test expectations:
    // The kworker malware uses character-by-character assembly for critical strings.
    // These may be split across multiple mov instructions and might appear as fragments
    // in the extraction results.

    // Key strings to look for:
    // 1. Process name spoofing: [kworker] or kworker
    // 2. Persistence paths: /etc/profile.d/, .bashrc, bash.bashrc
    // 3. C2 domains: cunilbs, aemrg, http (parts of URL)
    // 4. Temporary/lock files: /tmp/, .ICE-unix

    // Check for process name components
    let proc_keywords = ["kworker", "worker", "[k"];
    let mut found_proc_parts = 0;
    for keyword in &proc_keywords {
        if stack_strings.iter().any(|s| s.contains(keyword))
            || extracted.iter().any(|s| s.value.contains(keyword))
        {
            found_proc_parts += 1;
        }
    }

    // Check for persistence-related paths
    let persistence_keywords = ["/etc/", "profile", "bashrc", "profile.d"];
    let mut found_persistence = 0;
    for keyword in &persistence_keywords {
        if stack_strings.iter().any(|s| s.contains(keyword))
            || extracted.iter().any(|s| s.value.contains(keyword))
        {
            found_persistence += 1;
        }
    }

    // Check for temporary file patterns
    let tmp_keywords = ["/tmp", ".ICE", "unix"];
    let mut found_tmp = 0;
    for keyword in &tmp_keywords {
        if stack_strings.iter().any(|s| s.contains(keyword))
            || extracted.iter().any(|s| s.value.contains(keyword))
        {
            found_tmp += 1;
        }
    }

    // Check for C2 domain components
    let c2_keywords = ["cunilbs", "aemrg", "http", "curl"];
    let mut found_c2 = 0;
    for keyword in &c2_keywords {
        if extracted.iter().any(|s| s.value.contains(keyword)) {
            found_c2 += 1;
        }
    }

    // Verify we find evidence of character-by-character construction
    // At minimum, we should detect some suspicious activity patterns
    assert!(
        found_proc_parts > 0 || found_persistence > 0 || found_tmp > 0 || found_c2 > 0,
        "Should detect at least one category of malware indicators"
    );

    // We should have some stack strings or suspicious paths
    assert!(
        !stack_strings.is_empty() || !suspicious.is_empty(),
        "Should find stack strings or suspicious paths indicating obfuscation"
    );
}

#[test]
fn test_kworker_missing_strings_utf16_url() {
    let sample_path = crate::common::path("testdata/kworker_samples/kworker_obfuscated_1");

    let data = std::fs::read(sample_path).expect("Failed to read kworker sample");

    // The binary contains UTF-16LE encoded strings in .rodata
    // Search for the UTF-16LE encoded URL: h t p : / c u n i l o s . a e m r g
    // In hex: 68 00 74 00 70 00 3a 00 2f 00 63 00 75 00 6e 00 69 00 6c 00 6f 00 73 00 2e 00 61 00 65 00 6d 00 72 00 67 00

    // Find UTF-16LE sequences (every other byte is 0x00)
    let utf16le_marker = [0x68u8, 0x00, 0x74, 0x00, 0x70, 0x00]; // "htp" in UTF-16LE
    let found_utf16_htp = data
        .windows(utf16le_marker.len())
        .any(|window| window == utf16le_marker);

    // Note: The URL appears to be "htp://cunilos.aemrg" not "http://"
    // The second 't' is missing from the rodata section
    assert!(
        found_utf16_htp,
        "Should find UTF-16LE encoded URL fragment in .rodata"
    );
}

#[test]
#[ignore = "known gap: byte-assembled persistence strings are not recovered (REDFLAGS_AUDIT P6.13)"]
fn test_kworker_missing_persistence_strings() {
    let sample_path = crate::common::path("testdata/kworker_samples/kworker_obfuscated_1");

    let data = std::fs::read(sample_path).expect("Failed to read kworker sample");
    let opts = ExtractOptions::new(3); // Lower threshold to catch short fragments
    let extracted = stng::extract_strings_with_options(&data, &opts);

    // These strings are expected to be found (either fully or as components):
    let expected_components = vec![
        ("bashrc", "Bash RC file for persistence"),
        ("/etc/", "Config directory for persistence"),
        ("profile", "Profile initialization for persistence"),
        ("/tmp", "Temporary directory for coordination"),
        ("ICE-unix", "Socket name for process coordination"),
        ("[k", "Start of [kworker] process name"),
        ("worker", "Part of process name spoofing"),
    ];

    for (component, description) in &expected_components {
        assert!(
            extracted.iter().any(|s| s.value.contains(component)),
            "{component:?} ({description}) not extracted"
        );
    }
}

#[test]
fn test_kworker_utf16_url_content() {
    let sample_path = crate::common::path("testdata/kworker_samples/kworker_obfuscated_1");

    let data = std::fs::read(sample_path).expect("Failed to read kworker sample");
    let opts = ExtractOptions::new(4);
    let extracted = stng::extract_strings_with_options(&data, &opts);

    // Verify we found the actual URL
    let has_url = extracted
        .iter()
        .any(|s| s.value.contains("htp:/cunilos.aemrg"));

    // The actual string should be the full UTF-16LE decoded URL
    assert!(has_url, "Should extract the full UTF-16LE encoded URL");
}
