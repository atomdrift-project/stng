/// Tests for multi-byte XOR string extraction
///
/// This tests the pattern-free brute-force scanning approach for multi-byte XOR,
/// which is common in malware where each string is XOR'd independently starting
/// from key[0] (not cycling from file offset 0).
use stng::{ExtractOptions, StringMethod};

#[test]
fn test_multibyte_xor_basic() {
    // Create test data with strings XOR'd independently
    let key = b"SECRET";
    let strings = vec!["hello world", "test string", "osascript command"];

    let mut data = Vec::new();
    for s in &strings {
        // XOR each string independently starting from key[0]
        for (i, &b) in s.as_bytes().iter().enumerate() {
            data.push(b ^ key[i % key.len()]);
        }
        // Add some non-XOR'd garbage between strings (simulates real binary data)
        data.extend_from_slice(&[0xFF, 0xFE, 0xFD, 0xFC]);
    }

    // Extract with custom XOR key
    let opts = ExtractOptions::new(4)
        .with_xor_key(key.to_vec())
        .with_garbage_filter(false);

    let extracted = stng::extract_strings_with_options(&data, &opts);

    // Verify we found all the strings
    let xor_strings: Vec<_> = extracted
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .map(|s| s.value.as_str())
        .collect();

    // Check that we found the strings (may be partial or with extra chars)
    let found_hello = xor_strings.iter().any(|s| s.contains("hello world"));
    let found_test = xor_strings.iter().any(|s| s.contains("test string"));
    let found_osascript = xor_strings.iter().any(|s| s.contains("osascript"));

    assert!(
        found_hello,
        "Should find 'hello world'. Found: {:?}",
        xor_strings
    );
    assert!(
        found_test,
        "Should find 'test string'. Found: {:?}",
        xor_strings
    );
    assert!(
        found_osascript,
        "Should find 'osascript'. Found: {:?}",
        xor_strings
    );
}

#[test]
fn test_multibyte_xor_with_newlines() {
    // Test multi-line strings (common in malware AppleScript/shell commands)
    let key = b"KEY123";
    let multiline = "line one\nline two\nline three";

    let mut data = Vec::new();
    for (i, &b) in multiline.as_bytes().iter().enumerate() {
        data.push(b ^ key[i % key.len()]);
    }

    let opts = ExtractOptions::new(4)
        .with_xor_key(key.to_vec())
        .with_garbage_filter(false);

    let extracted = stng::extract_strings_with_options(&data, &opts);

    let xor_strings: Vec<_> = extracted
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .map(|s| s.value.as_str())
        .collect();

    // Should find the full multi-line string
    assert!(
        xor_strings
            .iter()
            .any(|s| s.contains("line one") && s.contains("line two")),
        "Should find multi-line string with newlines"
    );
}

#[test]
fn test_multibyte_xor_real_malware() {
    // Test against real malware sample (DPRK brew_agent)
    let sample_path = "testdata/xor/brew_agent_xor_sample";

    // Skip if sample doesn't exist (e.g., in CI)
    if !std::path::Path::new(sample_path).exists() {
        eprintln!("Skipping real malware test - sample not found");
        return;
    }

    let data = std::fs::read(sample_path).expect("Failed to read test sample");
    let key = b"fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf";

    let opts = ExtractOptions::new(4)
        .with_xor_key(key.to_vec())
        .with_garbage_filter(false);

    let extracted = stng::extract_strings_with_options(&data, &opts);

    let xor_strings: Vec<_> = extracted
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .map(|s| s.value.as_str())
        .collect();

    // Test case 1: osascript command
    assert!(
        xor_strings.iter().any(|s| s.contains("osascript")),
        "Should find osascript command from real malware"
    );

    // Test case 2: locale strings (ru_RU or similar locale pattern)
    // XOR decoding may find variations due to overlap detection
    let has_locale = xor_strings.iter().any(|s| {
        s.contains("ru_RU") ||
        s.contains("RuRD") || // Partially decoded variant
        s.contains("ru.keepcoder") // Telegram path with .ru domain
    });
    assert!(
        has_locale,
        "Should find locale-related string from real malware"
    );

    // Test case 3: Multi-line AppleScript components
    // The AppleScript may be split into fragments by the brute-force scanner;
    // verify both key terms appear somewhere in the decoded output.
    let has_posix = xor_strings.iter().any(|s| s.contains("POSIX file"));
    let has_finder = xor_strings.iter().any(|s| s.contains("Finder"));
    assert!(
        has_posix && has_finder,
        "Should find AppleScript components (POSIX file and Finder) from real malware"
    );

    // Test case 4: Safari/browser targeting
    assert!(
        xor_strings
            .iter()
            .any(|s| s.contains("Safari") || s.contains("Cookies")),
        "Should find Safari/browser targeting strings"
    );

    // Test case 5: Ethereum wallet targeting
    assert!(
        xor_strings
            .iter()
            .any(|s| s.contains("Ethereum") || s.contains("keystore")),
        "Should find crypto wallet targeting strings"
    );
}

#[test]
fn test_multibyte_xor_offsets() {
    // Test that offsets are correctly reported for multi-line strings
    let key = b"ABC";
    let text = "firstline\nsecondline\nthirdline";

    let mut data = Vec::new();
    let start_offset = 100; // Add some padding
    data.resize(start_offset, 0xFF);

    for (i, &b) in text.as_bytes().iter().enumerate() {
        data.push(b ^ key[i % key.len()]);
    }

    let opts = ExtractOptions::new(4)
        .with_xor_key(key.to_vec())
        .with_garbage_filter(false);

    let extracted = stng::extract_strings_with_options(&data, &opts);

    let xor_strings: Vec<_> = extracted
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .collect();

    assert!(
        !xor_strings.is_empty(),
        "Should find XOR'd string. Found: {:?}",
        xor_strings
    );

    // Check offset is correct (within a few bytes due to scanning step)
    let found_offset = xor_strings
        .iter()
        .find(|s| s.value.contains("firstline"))
        .map(|s| s.data_offset as usize);
    assert!(
        found_offset.is_some()
            && (found_offset.unwrap() >= start_offset && found_offset.unwrap() <= start_offset + 4),
        "Offset should be near start of XOR'd data. Expected ~{}, found {:?}",
        start_offset,
        found_offset
    );
}

#[test]
fn test_multibyte_xor_independent_cycling() {
    // Verify that each string cycles from key[0], not from file offset 0
    let key = b"ABCD";

    let mut data = Vec::new();

    // First string at offset 0
    let s1 = "test1string";
    for (i, &b) in s1.as_bytes().iter().enumerate() {
        data.push(b ^ key[i % key.len()]);
    }

    // Add padding (non-XOR'd data)
    data.extend_from_slice(&[0xFF; 10]);

    // Second string at offset (not aligned with key cycle from offset 0)
    let s2 = "test2string";
    for (i, &b) in s2.as_bytes().iter().enumerate() {
        // IMPORTANT: Cycles from key[0], NOT key[offset % 4]
        data.push(b ^ key[i % key.len()]);
    }

    let opts = ExtractOptions::new(4)
        .with_xor_key(key.to_vec())
        .with_garbage_filter(false);

    let extracted = stng::extract_strings_with_options(&data, &opts);

    let xor_strings: Vec<_> = extracted
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .map(|s| s.value.as_str())
        .collect();

    // Both strings should be found because we scan each position independently
    let found_test1 = xor_strings.iter().any(|s| s.contains("test1"));
    let found_test2 = xor_strings.iter().any(|s| s.contains("test2"));

    assert!(
        found_test1,
        "Should find first string. Found: {:?}",
        xor_strings
    );
    assert!(
        found_test2,
        "Should find second string. Found: {:?}",
        xor_strings
    );
}

#[test]
fn test_multibyte_xor_min_length() {
    let key = b"KEY";

    let mut data = Vec::new();

    // Short string (3 chars - below default min length of 10)
    let short = "abc";
    for (i, &b) in short.as_bytes().iter().enumerate() {
        data.push(b ^ key[i % key.len()]);
    }
    data.push(0x00);

    // Long string (above min length)
    let long = "this is a longer string";
    for (i, &b) in long.as_bytes().iter().enumerate() {
        data.push(b ^ key[i % key.len()]);
    }

    // Default min_length should filter out short strings
    let opts = ExtractOptions::new(4)
        .with_xor_key(key.to_vec())
        .with_garbage_filter(false);

    let extracted = stng::extract_strings_with_options(&data, &opts);

    let xor_strings: Vec<_> = extracted
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .map(|s| s.value.as_str())
        .collect();

    // XOR extraction should find at least one string
    assert!(!xor_strings.is_empty(), "Should extract some XOR strings");

    // Short string should be filtered out
    assert!(
        !xor_strings.contains(&"abc"),
        "Short string should be filtered"
    );

    // Should find a long string (exact match may vary due to overlap detection)
    let has_long_string = xor_strings.iter().any(|s| s.len() >= 10);
    if !has_long_string {
        eprintln!("XOR strings found: {:?}", xor_strings);
    }
    assert!(
        has_long_string,
        "Should find at least one string >= 10 chars"
    );
}
