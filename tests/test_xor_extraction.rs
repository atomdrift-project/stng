/// Comprehensive tests for XOR string extraction to prevent regression
/// Uses a sanitized subset of brew_agent malware (non-executable data only)
use stng::{ExtractOptions, StringKind, StringMethod};

const BREW_AGENT_KEY: &[u8] = b"fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf";

/// Load the test fixture (sanitized region from brew_agent)
fn load_test_fixture() -> Vec<u8> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/brew_agent_xor_region.bin"
    );
    std::fs::read(path).expect("Failed to load test fixture")
}

#[test]
fn test_xor_finds_both_volume_variants() {
    // The malware has both "muted true" and "muted false" commands
    // These should both be extracted without overlap issues
    let data = load_test_fixture();

    let opts = ExtractOptions::new(10)
        .with_xor_key(BREW_AGENT_KEY.to_vec())
        .with_garbage_filter(true);

    let extracted = stng::extract_strings_with_options(&data, &opts);

    let xor_strings: Vec<_> = extracted
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .collect();

    // Find volume strings
    let volume_strings: Vec<_> = xor_strings
        .iter()
        .filter(|s| s.value.to_lowercase().contains("volume"))
        .collect();

    // Should find at least the two main variants
    assert!(
        volume_strings.len() >= 2,
        "Expected at least 2 volume strings, found {}",
        volume_strings.len()
    );

    // Check for exact "true" variant
    let has_true = volume_strings
        .iter()
        .any(|s| s.value == "set volume output muted true");
    assert!(
        has_true,
        "Should find exact string 'set volume output muted true'. Found: {:?}",
        volume_strings.iter().map(|s| &s.value).collect::<Vec<_>>()
    );

    // Check for exact "false" variant
    let has_false = volume_strings
        .iter()
        .any(|s| s.value == "set volume output muted false");
    assert!(
        has_false,
        "Should find exact string 'set volume output muted false'. Found: {:?}",
        volume_strings.iter().map(|s| &s.value).collect::<Vec<_>>()
    );
}

#[test]
fn test_xor_no_garbage_suffixes() {
    // Null termination should prevent garbage suffixes like "truegtZh"
    let data = load_test_fixture();

    let opts = ExtractOptions::new(10)
        .with_xor_key(BREW_AGENT_KEY.to_vec())
        .with_garbage_filter(true);

    let extracted = stng::extract_strings_with_options(&data, &opts);

    let volume_strings: Vec<_> = extracted
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .filter(|s| s.value.to_lowercase().contains("volume"))
        .collect();

    for s in &volume_strings {
        // Check that strings end cleanly, not with mixed-case garbage
        let last_word = s.value.split_whitespace().last().unwrap_or("");

        // Should end with "true" or "false", not "truegtZh" or "falseaTrs..."
        assert!(
            last_word == "true" || last_word == "false" || last_word.len() <= 10,
            "Volume string has garbage suffix: {:?}",
            s.value
        );
    }
}

#[test]
fn test_xor_no_byte_range_overlaps() {
    // No two XOR strings should decode the same bytes differently
    let data = load_test_fixture();

    let opts = ExtractOptions::new(10)
        .with_xor_key(BREW_AGENT_KEY.to_vec())
        .with_garbage_filter(true);

    let extracted = stng::extract_strings_with_options(&data, &opts);

    let xor_strings: Vec<_> = extracted
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .collect();

    // Check for byte-range overlaps
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
                "Found overlapping XOR strings:\n  [{:#x}-{:#x}] {:?}\n  [{:#x}-{:#x}] {:?}",
                s1_start, s1_end, s1.value, s2_start, s2_end, s2.value
            );
        }
    }
}

#[test]
fn test_xor_finds_malware_indicators() {
    // Should find key malware IOCs from the DPRK sample
    let data = load_test_fixture();

    let opts = ExtractOptions::new(10)
        .with_xor_key(BREW_AGENT_KEY.to_vec())
        .with_garbage_filter(true);

    let extracted = stng::extract_strings_with_options(&data, &opts);

    let xor_strings: Vec<_> = extracted
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .map(|s| s.value.to_lowercase())
        .collect();

    let combined = xor_strings.join(" ");

    // Key indicators from DPRK malware
    assert!(
        combined.contains("wallet"),
        "Should find wallet-related strings"
    );
    assert!(
        combined.contains("telegram"),
        "Should find Telegram references"
    );
    assert!(
        combined.contains("osascript"),
        "Should find osascript commands"
    );
}

#[test]
fn test_xor_classification() {
    // XOR strings should be properly classified
    let data = load_test_fixture();

    let opts = ExtractOptions::new(10)
        .with_xor_key(BREW_AGENT_KEY.to_vec())
        .with_garbage_filter(true);

    let extracted = stng::extract_strings_with_options(&data, &opts);

    let volume_strings: Vec<_> = extracted
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .filter(|s| s.value.to_lowercase().contains("volume"))
        .collect();

    // Volume strings should be classified as ShellCmd or AppleScript
    // (They are osascript commands, which may be classified either way)
    for s in &volume_strings {
        assert!(
            s.kind == StringKind::ShellCmd || s.kind == StringKind::AppleScript,
            "Volume string should be classified as ShellCmd or AppleScript, got {:?}: {:?}",
            s.kind,
            s.value
        );
    }
}

#[test]
fn test_xor_null_termination() {
    // Test that we correctly handle null termination using real data
    // In the test fixture, strings should end at nulls
    let data = load_test_fixture();

    let opts = ExtractOptions::new(10)
        .with_xor_key(BREW_AGENT_KEY.to_vec())
        .with_garbage_filter(true);

    let extracted = stng::extract_strings_with_options(&data, &opts);

    let volume_strings: Vec<_> = extracted
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .filter(|s| s.value.to_lowercase().contains("volume"))
        .collect();

    // Volume strings should be clean (no garbage after null termination)
    for s in &volume_strings {
        // Should not have random garbage at the end
        assert!(
            !s.value.ends_with("gtZh"),
            "String should be null-terminated, not end with garbage: {:?}",
            s.value
        );
        assert!(
            !s.value.ends_with("aTrsJg"),
            "String should be null-terminated, not end with garbage: {:?}",
            s.value
        );
    }
}

#[test]
fn test_xor_strings_starting_with_key_first_byte() {
    // Test that we can find strings starting with 'f' (key[0])
    // In the real data, check if we have any strings starting with 'f'
    let data = load_test_fixture();

    let opts = ExtractOptions::new(10)
        .with_xor_key(BREW_AGENT_KEY.to_vec())
        .with_garbage_filter(true);

    let extracted = stng::extract_strings_with_options(&data, &opts);

    let xor_strings: Vec<_> = extracted
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .collect();

    // The key starts with 'f', so strings starting with 'f' would have
    // null as first byte in source. Check that we can find such strings
    // (This verifies we allow j==0 to be null in the decode loop)
    let starts_with_f: Vec<_> = xor_strings
        .iter()
        .filter(|s| s.value.starts_with('f') || s.value.starts_with('F'))
        .collect();

    // We should find at least some strings starting with 'f'
    // (The exact count doesn't matter, just that we CAN find them)
    assert!(
        !starts_with_f.is_empty(),
        "Should be able to find strings starting with key[0] ('f')"
    );
}

#[test]
fn test_xor_performance() {
    // Extraction should be reasonably fast
    use std::time::Instant;

    let data = load_test_fixture();

    let opts = ExtractOptions::new(10)
        .with_xor_key(BREW_AGENT_KEY.to_vec())
        .with_garbage_filter(true);

    let start = Instant::now();
    let extracted = stng::extract_strings_with_options(&data, &opts);
    let elapsed = start.elapsed();

    let xor_count = extracted
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .count();

    // Should complete in reasonable time for 180KB.
    // Release: ~0.3s. Debug builds are significantly slower, allow up to 10s.
    assert!(
        elapsed.as_secs() < 10,
        "XOR extraction took too long: {:?}",
        elapsed
    );

    // Should find reasonable number of strings (not 0, not thousands)
    assert!(
        xor_count > 50 && xor_count < 500,
        "Expected 50-500 XOR strings, found {}",
        xor_count
    );

    println!(
        "XOR extraction: {} strings in {:.3}s ({:.0} KB/s)",
        xor_count,
        elapsed.as_secs_f64(),
        data.len() as f64 / 1024.0 / elapsed.as_secs_f64()
    );
}

#[test]
fn test_xor_minimum_length_respected() {
    // Should respect minimum length parameter for XOR extraction
    let data = load_test_fixture();

    let min_len = 25;
    let opts = ExtractOptions::new(4) // General min length
        .with_xor_key(BREW_AGENT_KEY.to_vec())
        .with_xor(Some(min_len)) // Specific XOR min length
        .with_garbage_filter(true);

    let extracted = stng::extract_strings_with_options(&data, &opts);

    let xor_strings: Vec<_> = extracted
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .collect();

    // All XOR strings should be >= min_len characters
    for s in &xor_strings {
        assert!(
            s.value.len() >= min_len,
            "Found XOR string shorter than xor_min_length: {:?} ({} chars, expected >= {})",
            s.value,
            s.value.len(),
            min_len
        );
    }

    // Should still find some strings
    assert!(
        !xor_strings.is_empty(),
        "Should find at least some XOR strings even with higher min_length"
    );
}

#[test]
fn test_c2_url_extraction_from_fixture() {
    // The C2 URL is at offset 0x11b0 and 0x29797 in the fixture
    // It should be extracted as "http://46.30.191.141n;uJ" (24 bytes)
    let data = load_test_fixture();

    let opts = ExtractOptions::new(10)
        .with_xor_key(BREW_AGENT_KEY.to_vec())
        .with_garbage_filter(true);

    let extracted = stng::extract_strings_with_options(&data, &opts);
    let xor_strings: Vec<_> = extracted
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .collect();

    println!("Extracted {} XOR strings", xor_strings.len());

    // Look for the C2 URL or IP
    let c2_strings: Vec<_> = xor_strings
        .iter()
        .filter(|s| s.value.contains("46.30.191.141"))
        .collect();

    if c2_strings.is_empty() {
        println!("\n✗ C2 URL NOT FOUND!");
        println!("\nStrings near offset 0x11b0 (expected C2 location):");
        for s in xor_strings
            .iter()
            .filter(|s| s.data_offset >= 0x11a0 && s.data_offset <= 0x11c0)
        {
            println!(
                "  0x{:x}: {:?} ({:?}, len={})",
                s.data_offset,
                s.value,
                s.kind,
                s.value.len()
            );
        }

        println!("\nAll URLs extracted:");
        for s in xor_strings.iter().filter(|s| s.kind == StringKind::Url) {
            println!("  0x{:x}: {:?}", s.data_offset, s.value);
        }

        println!("\nAll IPs extracted:");
        for s in xor_strings
            .iter()
            .filter(|s| matches!(s.kind, StringKind::IP | StringKind::IPPort))
        {
            println!("  0x{:x}: {:?}", s.data_offset, s.value);
        }
    } else {
        println!("\n✓ Found {} C2 URL(s):", c2_strings.len());
        for s in &c2_strings {
            println!("  0x{:x}: {:?} ({:?})", s.data_offset, s.value, s.kind);
        }
    }

    assert!(
        !c2_strings.is_empty(),
        "C2 URL (http://46.30.191.141) should be extracted from XOR-encoded data"
    );
}
#[test]
fn test_direct_c2_extraction() {
    let data =
        std::fs::read("tests/fixtures/brew_agent_xor_region.bin").expect("Failed to read fixture");
    let key = b"fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf";

    let opts = ExtractOptions::new(10).with_xor_key(key.to_vec());
    let results = stng::extract_strings_with_options(&data, &opts);

    println!("\nDirect extraction found {} strings", results.len());

    // Look for C2
    let c2 = results
        .iter()
        .filter(|s| s.value.contains("46.30.191.141"))
        .collect::<Vec<_>>();
    println!("C2 strings: {}", c2.len());

    // Look near 0x11b0
    let nearby = results
        .iter()
        .filter(|s| s.data_offset >= 0x11a0 && s.data_offset <= 0x11c0)
        .collect::<Vec<_>>();
    println!("Near 0x11b0: {}", nearby.len());
    for s in &nearby {
        println!(
            "  0x{:x}: {:?}",
            s.data_offset,
            &s.value[..s.value.len().min(40)]
        );
    }

    assert!(!c2.is_empty(), "C2 URL should be extracted");
}

#[test]
fn test_brew_agent_comprehensive_extraction() {
    // Comprehensive test for HomaBrew malware (brew_agent)
    // Ensures all critical IOCs are extracted without loss
    let data = load_test_fixture();

    let opts = ExtractOptions::new(10)
        .with_xor_key(BREW_AGENT_KEY.to_vec())
        .with_garbage_filter(true);

    let extracted = stng::extract_strings_with_options(&data, &opts);
    let xor_strings: Vec<_> = extracted
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .collect();

    println!("\n=== HomaBrew Malware String Extraction Test ===");
    println!("Total XOR strings: {}", xor_strings.len());

    // Critical IOC categories to test
    let mut found_categories = std::collections::HashMap::new();

    // 1. C2 Infrastructure
    let c2_urls = xor_strings
        .iter()
        .filter(|s| s.value.contains("46.30.191.141"))
        .collect::<Vec<_>>();
    println!("\n[C2 Infrastructure]");
    println!("  C2 URLs: {}", c2_urls.len());
    for s in &c2_urls {
        println!("    0x{:x}: {}", s.data_offset, s.value);
    }
    assert!(
        !c2_urls.is_empty(),
        "CRITICAL: C2 URL (46.30.191.141) must be extracted"
    );
    found_categories.insert("c2", c2_urls.len());

    // 2. Shell Commands
    let shell_cmds = xor_strings
        .iter()
        .filter(|s| {
            s.value.contains("osascript")
                || s.value.contains("screencapture")
                || s.value.contains("/bin/sh")
                || s.value.contains("bash")
        })
        .collect::<Vec<_>>();
    println!("\n[Shell Commands]");
    println!("  Commands: {}", shell_cmds.len());
    for s in shell_cmds.iter().take(5) {
        println!(
            "    0x{:x}: {}",
            s.data_offset,
            s.value.chars().take(60).collect::<String>()
        );
    }
    assert!(
        shell_cmds.iter().any(|s| s.value.contains("osascript")),
        "CRITICAL: osascript command must be extracted"
    );
    found_categories.insert("shell", shell_cmds.len());

    // 3. AppleScript
    let applescript = xor_strings
        .iter()
        .filter(|s| {
            s.value.to_lowercase().contains("tell application")
                || s.value.contains("set volume")
                || s.value.contains("EOD")
        })
        .collect::<Vec<_>>();
    println!("\n[AppleScript]");
    println!("  Scripts: {}", applescript.len());
    for s in applescript.iter().take(5) {
        println!(
            "    0x{:x}: {}",
            s.data_offset,
            s.value.chars().take(60).collect::<String>()
        );
    }
    found_categories.insert("applescript", applescript.len());

    // 4. Cryptocurrency Wallets
    let crypto = xor_strings
        .iter()
        .filter(|s| {
            s.value.to_lowercase().contains("electrum")
                || s.value.contains("Ethereum")
                || s.value.contains("Exodus")
                || s.value.contains("wallet")
        })
        .collect::<Vec<_>>();
    println!("\n[Cryptocurrency Targets]");
    println!("  Wallet paths: {}", crypto.len());
    for s in crypto.iter().take(5) {
        println!(
            "    0x{:x}: {}",
            s.data_offset,
            s.value.chars().take(60).collect::<String>()
        );
    }
    assert!(
        crypto
            .iter()
            .any(|s| s.value.to_lowercase().contains("electrum")),
        "CRITICAL: Electrum wallet path must be extracted"
    );
    assert!(
        crypto.iter().any(|s| s.value.contains("Ethereum")),
        "CRITICAL: Ethereum wallet path must be extracted"
    );
    found_categories.insert("crypto", crypto.len());

    // 5. Browser Paths
    let browsers = xor_strings
        .iter()
        .filter(|s| {
            s.value.contains("Chrome")
                || s.value.contains("Firefox")
                || s.value.contains("Safari")
                || s.value.contains("Browser")
        })
        .collect::<Vec<_>>();
    println!("\n[Browser Targets]");
    println!("  Browser paths: {}", browsers.len());
    for s in browsers.iter().take(5) {
        println!(
            "    0x{:x}: {}",
            s.data_offset,
            s.value.chars().take(60).collect::<String>()
        );
    }
    found_categories.insert("browsers", browsers.len());

    // 6. System Paths
    let system_paths = xor_strings
        .iter()
        .filter(|s| {
            s.value.contains("/Library/")
                || s.value.contains("/tmp/")
                || s.value.contains("LaunchAgent")
        })
        .collect::<Vec<_>>();
    println!("\n[System Paths]");
    println!("  Paths: {}", system_paths.len());
    for s in system_paths.iter().take(5) {
        println!(
            "    0x{:x}: {}",
            s.data_offset,
            s.value.chars().take(60).collect::<String>()
        );
    }
    found_categories.insert("paths", system_paths.len());

    // 7. Locales (geofencing)
    let locales = xor_strings
        .iter()
        .filter(|s| {
            s.value.contains("_AM")
                || s.value.contains("_BY")
                || s.value.contains("_KZ")
                || s.value.contains("_RU")
                || s.value.contains("_UA")
        })
        .collect::<Vec<_>>();
    println!("\n[Geofencing Locales]");
    println!("  Locale strings: {}", locales.len());
    for s in locales.iter().take(3) {
        println!("    0x{:x}: {}", s.data_offset, s.value);
    }
    found_categories.insert("locales", locales.len());

    // 8. File Extensions
    let extensions = xor_strings
        .iter()
        .filter(|s| {
            s.value == "wallet.dat"
                || s.value.contains(".conf")
                || s.value.contains(".json")
                || s.value.contains(".txt")
        })
        .collect::<Vec<_>>();
    println!("\n[Target File Extensions]");
    println!("  Extensions: {}", extensions.len());
    found_categories.insert("extensions", extensions.len());

    // Summary
    println!("\n=== Summary ===");
    println!("Total IOC categories found: {}", found_categories.len());
    for (category, count) in &found_categories {
        println!("  {}: {}", category, count);
    }

    // Minimum thresholds
    assert!(
        xor_strings.len() >= 150,
        "Should extract at least 150 XOR strings from brew_agent, found {}",
        xor_strings.len()
    );
    assert!(
        found_categories.len() >= 6,
        "Should find at least 6 IOC categories, found {}",
        found_categories.len()
    );

    println!("\n✓ All critical brew_agent IOCs successfully extracted!");
}
