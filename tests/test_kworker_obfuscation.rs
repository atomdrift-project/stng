use stng::{ExtractOptions, StringKind};

#[test]
fn test_kworker_character_assembly_detection() {
    let sample_path = "testdata/kworker_samples/kworker_obfuscated_1";
    if !std::path::Path::new(sample_path).exists() {
        eprintln!(
            "Skipping - kworker malware sample not found at {}",
            sample_path
        );
        return;
    }

    let data = std::fs::read(sample_path).expect("Failed to read kworker sample");

    let opts = ExtractOptions::new(4);
    let extracted = stng::extract_strings_with_options(&data, &opts);

    // Collect all strings for analysis
    println!("\n=== KWorker Malware Analysis ===");
    println!("Total strings extracted: {}", extracted.len());

    // Print suspicious strings (high severity)
    let suspicious: Vec<_> = extracted
        .iter()
        .filter(|s| {
            s.kind == StringKind::SuspiciousPath
                || s.kind == StringKind::ShellCmd
                || s.kind == StringKind::StackString
        })
        .collect();

    println!("\nSuspicious strings found: {}", suspicious.len());
    for s in &suspicious {
        println!("  [{:?}] 0x{:x}: {}", s.kind, s.data_offset, s.value);
    }

    // Print stack strings (character-by-character constructions)
    let stack_strings: Vec<_> = extracted
        .iter()
        .filter(|s| s.kind == StringKind::StackString)
        .map(|s| s.value.as_str())
        .collect();

    println!("\nStack-constructed strings found: {}", stack_strings.len());
    for s in &stack_strings {
        println!("  - {}", s);
    }

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
            println!("\n✓ Found process name keyword: {}", keyword);
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
            println!("✓ Found persistence keyword: {}", keyword);
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
            println!("✓ Found tmp file keyword: {}", keyword);
        }
    }

    // Check for C2 domain components
    let c2_keywords = ["cunilbs", "aemrg", "http", "curl"];
    let mut found_c2 = 0;
    for keyword in &c2_keywords {
        if extracted.iter().any(|s| s.value.contains(keyword)) {
            found_c2 += 1;
            println!("✓ Found C2 keyword: {}", keyword);
        }
    }

    println!("\n=== Detection Summary ===");
    println!("Process name components: {}/3", found_proc_parts);
    println!("Persistence paths: {}/4", found_persistence);
    println!("Temporary files: {}/3", found_tmp);
    println!("C2 indicators: {}/4", found_c2);

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
    let sample_path = "testdata/kworker_samples/kworker_obfuscated_1";
    if !std::path::Path::new(sample_path).exists() {
        eprintln!(
            "Skipping - kworker malware sample not found at {}",
            sample_path
        );
        return;
    }

    let data = std::fs::read(sample_path).expect("Failed to read kworker sample");

    // The binary contains UTF-16LE encoded strings in .rodata
    // Search for the UTF-16LE encoded URL: h t p : / c u n i l o s . a e m r g
    // In hex: 68 00 74 00 70 00 3a 00 2f 00 63 00 75 00 6e 00 69 00 6c 00 6f 00 73 00 2e 00 61 00 65 00 6d 00 72 00 67 00

    // Find UTF-16LE sequences (every other byte is 0x00)
    let utf16le_marker = [0x68u8, 0x00, 0x74, 0x00, 0x70, 0x00]; // "htp" in UTF-16LE
    let found_utf16_htp = data
        .windows(utf16le_marker.len())
        .any(|window| window == utf16le_marker);

    println!("\n=== UTF-16LE URL Detection ===");
    println!("Found UTF-16LE 'htp' pattern: {}", found_utf16_htp);

    // Note: The URL appears to be "htp://cunilos.aemrg" not "http://"
    // The second 't' is missing from the rodata section
    assert!(
        found_utf16_htp,
        "Should find UTF-16LE encoded URL fragment in .rodata"
    );
}

#[test]
fn test_kworker_missing_persistence_strings() {
    let sample_path = "testdata/kworker_samples/kworker_obfuscated_1";
    if !std::path::Path::new(sample_path).exists() {
        eprintln!(
            "Skipping - kworker malware sample not found at {}",
            sample_path
        );
        return;
    }

    let data = std::fs::read(sample_path).expect("Failed to read kworker sample");
    let opts = ExtractOptions::new(3); // Lower threshold to catch short fragments
    let extracted = stng::extract_strings_with_options(&data, &opts);

    println!("\n=== Missing Persistence Strings Analysis ===");
    println!("Total extracted with min_length=3: {}", extracted.len());

    // Look for persistence-related strings that SHOULD be there but may not be extracted properly
    let all_values: Vec<String> = extracted.iter().map(|s| s.value.clone()).collect();
    println!("\nAll extracted values: {:?}", all_values);

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
        let found = extracted.iter().any(|s| s.value.contains(component));
        println!(
            "  {}: {} ({})",
            if found { "✓" } else { "✗" },
            component,
            description
        );
    }
}

#[test]
fn test_kworker_stack_string_assembly_patterns() {
    let sample_path = "testdata/kworker_samples/kworker_obfuscated_1";
    if !std::path::Path::new(sample_path).exists() {
        eprintln!(
            "Skipping - kworker malware sample not found at {}",
            sample_path
        );
        return;
    }

    let data = std::fs::read(sample_path).expect("Failed to read kworker sample");
    let opts = ExtractOptions::new(2); // Very low threshold to catch byte pairs
    let extracted = stng::extract_strings_with_options(&data, &opts);

    println!("\n=== Stack String Assembly Patterns ===");

    // Look for 2-byte immediate patterns that could be part of character-by-character assembly
    // Pattern: mov instructions with ASCII-decodable immediates
    let mut two_byte_immediates = Vec::new();
    for window in data.windows(2) {
        let byte1 = window[0];
        let byte2 = window[1];

        if byte1.is_ascii_graphic() && byte2.is_ascii_graphic() {
            two_byte_immediates.push((byte1 as char, byte2 as char));
        }
    }

    println!(
        "Found {} potential 2-byte ASCII sequences",
        two_byte_immediates.len()
    );

    // Check for specific patterns we know should exist:
    // "kw" from "[kworker]"
    let has_kw = data.windows(2).any(|w| w == b"kw");
    // "or" from "worker" or "profile"
    let has_or = data.windows(2).any(|w| w == b"or");
    // "ba" from "bashrc"
    let has_ba = data.windows(2).any(|w| w == b"ba");

    println!("2-byte patterns found:");
    println!("  'kw': {}", if has_kw { "✓" } else { "✗" });
    println!("  'or': {}", if has_or { "✓" } else { "✗" });
    println!("  'ba': {}", if has_ba { "✓" } else { "✗" });

    // Print some extracted short strings
    let short_strings: Vec<_> = extracted
        .iter()
        .filter(|s| s.value.len() >= 2 && s.value.len() <= 4)
        .map(|s| s.value.as_str())
        .collect();

    println!("\nShort extracted strings (2-4 chars): {:?}", short_strings);
}

#[test]
fn test_kworker_utf16_url_content() {
    let sample_path = "testdata/kworker_samples/kworker_obfuscated_1";
    if !std::path::Path::new(sample_path).exists() {
        eprintln!(
            "Skipping - kworker malware sample not found at {}",
            sample_path
        );
        return;
    }

    let data = std::fs::read(sample_path).expect("Failed to read kworker sample");
    let opts = ExtractOptions::new(4);
    let extracted = stng::extract_strings_with_options(&data, &opts);

    println!("\n=== UTF-16LE URL Detection Results ===");

    // Look for the URL we detected
    let url_strings: Vec<_> = extracted
        .iter()
        .filter(|s| {
            s.value.contains("htp") || s.value.contains("cunilos") || s.value.contains("aemrg")
        })
        .collect();

    println!("Found {} URL-related strings:", url_strings.len());
    for s in &url_strings {
        println!(
            "  0x{:x}: {} (method: {:?})",
            s.data_offset, s.value, s.method
        );
    }

    // Verify we found the actual URL
    let has_url = extracted
        .iter()
        .any(|s| s.value.contains("htp:/cunilos.aemrg"));
    println!("\nFull URL detected: {}", if has_url { "✓" } else { "✗" });

    // The actual string should be the full UTF-16LE decoded URL
    assert!(has_url, "Should extract the full UTF-16LE encoded URL");
}
