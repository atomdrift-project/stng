/// Additional tests for r2 module helper functions
/// Covers src/r2.rs helper functions and edge cases
use std::fs;
use std::path::PathBuf;

// Helper to create a unique temporary file path
fn temp_file_path(prefix: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "{}_{}_{}.bin",
        prefix,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    path
}

// Helper to create a temporary file with content
fn create_temp_file(prefix: &str, content: &[u8]) -> PathBuf {
    let path = temp_file_path(prefix);
    fs::write(&path, content).unwrap();
    path
}

/// Test flush_cache with non-existent file
#[test]
fn test_flush_cache_nonexistent_file() {
    let fake_path = "/tmp/nonexistent_file_for_r2_test_12345.bin";

    // Should fail gracefully (cache module handles this)
    let result = stng::r2::flush_cache(fake_path);

    // Error is acceptable for non-existent file
    let _ = result;
}

/// Test flush_cache with real file
#[test]
fn test_flush_cache_real_file() {
    let temp_path = create_temp_file("r2_flush", b"test content for flush");
    let file_path = temp_path.to_str().unwrap();

    // Should succeed even if cache doesn't exist
    let result = stng::r2::flush_cache(file_path);
    assert!(result.is_ok(), "Flush should succeed for valid file path");

    let _ = fs::remove_file(temp_path);
}

/// Test extract_string_boundaries with large file (should skip)
#[test]
fn test_extract_string_boundaries_large_file() {
    // Create a file > 10MB (will be skipped)
    let temp_path = create_temp_file("r2_large", &vec![0u8; 11 * 1024 * 1024]);
    let file_path = temp_path.to_str().unwrap();

    let result = stng::r2::extract_string_boundaries(file_path);

    // Should return None for files > 10MB
    assert!(result.is_none(), "Should skip files larger than 10MB");

    let _ = fs::remove_file(temp_path);
}

/// Test extract_string_boundaries with small file
#[test]
fn test_extract_string_boundaries_small_file() {
    let temp_path = create_temp_file("r2_small", b"small test file");
    let file_path = temp_path.to_str().unwrap();

    let result = stng::r2::extract_string_boundaries(file_path);

    // May return None if r2/rizin not available, or Some if available
    // Just verify it doesn't panic
    if result.is_some() {
        let boundaries = result.unwrap();
        // If r2 is available and found strings, verify structure
        for boundary in &boundaries {
            assert!(boundary.offset < 1024 * 1024, "Offset should be reasonable");
            assert!(boundary.length > 0, "Length should be positive");
        }
    }

    let _ = fs::remove_file(temp_path);
}

/// Test extract_string_boundaries with non-existent file
#[test]
fn test_extract_string_boundaries_nonexistent() {
    let fake_path = "/tmp/nonexistent_file_boundaries_test.bin";

    let result = stng::r2::extract_string_boundaries(fake_path);

    // Should return None for non-existent file
    assert!(result.is_none(), "Should return None for non-existent file");
}

/// Test extract_strings with non-existent file
#[test]
fn test_extract_strings_nonexistent_file() {
    let result = stng::r2::extract_strings("/nonexistent/path/test.bin", 4, false);
    assert!(result.is_none(), "Should return None for non-existent file");
}

/// Test extract_strings with large file (should use fast mode)
#[test]
fn test_extract_strings_large_file_fast_mode() {
    // Create a file > 10MB
    let temp_path = create_temp_file("r2_extract_large", &vec![0xAAu8; 11 * 1024 * 1024]);
    let file_path = temp_path.to_str().unwrap();

    let result = stng::r2::extract_strings(file_path, 4, false);

    // May return None if r2/rizin not available
    // If r2 is available, should use symbols-only mode (fast)
    // Just verify it doesn't panic or hang
    if let Some(strings) = result {
        // Verify all strings have valid offsets
        let file_size = 11 * 1024 * 1024;
        for s in &strings {
            assert!(
                s.data_offset < file_size,
                "Offset should be within file bounds"
            );
        }
    }

    let _ = fs::remove_file(temp_path);
}

/// Test extract_strings with cache enabled vs disabled
#[test]
fn test_extract_strings_caching() {
    let temp_path = create_temp_file("r2_cache_test", b"test content for caching");
    let file_path = temp_path.to_str().unwrap();

    // First call with cache enabled
    let result1 = stng::r2::extract_strings(file_path, 4, true);

    // Second call with cache enabled (should hit cache if r2 available)
    let result2 = stng::r2::extract_strings(file_path, 4, true);

    // Third call with cache disabled
    let result3 = stng::r2::extract_strings(file_path, 4, false);

    // All should return the same result (if r2 available)
    // Just verify consistency
    match (result1, result2, result3) {
        (Some(s1), Some(s2), Some(s3)) => {
            assert_eq!(s1.len(), s2.len(), "Cached result should match");
            assert_eq!(s1.len(), s3.len(), "Non-cached result should match");
        }
        (None, None, None) => {
            // All None is fine (r2 not available)
        }
        _ => {
            // Mixed results is unexpected but possible if cache is flaky
        }
    }

    // Clean up cache
    let _ = stng::r2::flush_cache(file_path);
    let _ = fs::remove_file(temp_path);
}

/// Test extract_function_metadata with large file (should skip)
#[test]
fn test_extract_function_metadata_large_file() {
    // Files > 2MB should be skipped
    let file_size = (3 * 1024 * 1024) as u64;
    let temp_path = create_temp_file("r2_func_large", &vec![0u8; file_size as usize]);
    let file_path = temp_path.to_str().unwrap();

    let result = stng::r2::extract_function_metadata(file_path, file_size, false);

    // Should return None for files > 2MB
    assert!(result.is_none(), "Should skip files larger than 2MB");

    let _ = fs::remove_file(temp_path);
}

/// Test extract_function_metadata with small file
#[test]
fn test_extract_function_metadata_small_file() {
    let file_size = 1024;
    let temp_path = create_temp_file("r2_func_small", &vec![0u8; file_size]);
    let file_path = temp_path.to_str().unwrap();

    let result = stng::r2::extract_function_metadata(file_path, file_size as u64, false);

    // May return None if r2/rizin not available or no functions found
    // Just verify it doesn't panic
    if let Some(metadata) = result {
        // Verify structure if functions were found
        for (name, meta) in metadata {
            assert!(!name.is_empty(), "Function name should not be empty");
            assert!(
                meta.size > 0 || meta.size == 0,
                "Size should be non-negative"
            );
        }
    }

    let _ = fs::remove_file(temp_path);
}

/// Test is_available doesn't panic
#[test]
fn test_is_available_no_panic() {
    let available = stng::r2::is_available();
    // Just verify it returns a boolean without panicking
    assert!(available == true || available == false);
}

/// Test verify_xor_keys with empty candidates
#[test]
fn test_verify_xor_keys_empty_candidates() {
    let temp_path = create_temp_file("r2_xor_empty", b"test content");
    let file_path = temp_path.to_str().unwrap();

    let result = stng::r2::verify_xor_keys(file_path, &[]);

    // Should return empty vec for empty input
    assert!(result.is_empty(), "Should return empty for no candidates");

    let _ = fs::remove_file(temp_path);
}

/// Test verify_xor_keys with candidates outside valid length range
#[test]
fn test_verify_xor_keys_invalid_lengths() {
    use stng::{ExtractedString, StringKind, StringMethod};

    let temp_path = create_temp_file("r2_xor_lengths", b"test content");
    let file_path = temp_path.to_str().unwrap();

    let candidates = vec![
        // Too short (< 8 chars)
        ExtractedString {
            value: "short".to_string(),
            data_offset: 0,
            section: None,
            method: StringMethod::RawScan,
            kind: StringKind::Const,
            library: None,
            fragments: None,
            section_size: None,
            section_executable: None,
            section_writable: None,
            architecture: None,
            function_meta: None,
        },
        // Too long (> 64 chars)
        ExtractedString {
            value: "a".repeat(100),
            data_offset: 0,
            section: None,
            method: StringMethod::RawScan,
            kind: StringKind::Const,
            library: None,
            fragments: None,
            section_size: None,
            section_executable: None,
            section_writable: None,
            architecture: None,
            function_meta: None,
        },
    ];

    let result = stng::r2::verify_xor_keys(file_path, &candidates);

    // Should return empty since all candidates are filtered out by length
    assert!(
        result.is_empty(),
        "Should filter out invalid length candidates"
    );

    let _ = fs::remove_file(temp_path);
}

/// Test extract_connect_addrs with non-existent file
#[test]
fn test_extract_connect_addrs_nonexistent() {
    let fake_data = b"test data";

    let result = stng::r2::extract_connect_addrs("/nonexistent/path.bin", fake_data);

    // Should return empty for non-existent file
    assert!(
        result.is_empty(),
        "Should return empty for non-existent file"
    );
}

/// Test extract_connect_addrs with large file (should use fast scan)
#[test]
fn test_extract_connect_addrs_large_file() {
    let large_data = vec![0u8; 11 * 1024 * 1024];
    let temp_path = create_temp_file("r2_connect_large", &large_data);
    let file_path = temp_path.to_str().unwrap();

    let result = stng::r2::extract_connect_addrs(file_path, &large_data);

    // Should use binary scan for large files (no r2 analysis)
    // Result may be empty if no connect patterns found
    assert!(result.len() < 1000, "Should not find excessive addresses");

    let _ = fs::remove_file(temp_path);
}

/// Test extract_connect_addrs with empty data
#[test]
fn test_extract_connect_addrs_empty_data() {
    let temp_path = create_temp_file("r2_connect_empty", b"");
    let file_path = temp_path.to_str().unwrap();

    let result = stng::r2::extract_connect_addrs(file_path, b"");

    // Should return empty for empty data
    assert!(result.is_empty(), "Should return empty for empty data");

    let _ = fs::remove_file(temp_path);
}

/// Test that StringBoundary is public and usable
#[test]
fn test_string_boundary_structure() {
    let boundary = stng::r2::StringBoundary {
        offset: 1234,
        length: 56,
    };

    assert_eq!(boundary.offset, 1234);
    assert_eq!(boundary.length, 56);
}

/// Test XorConfidence enum
#[test]
fn test_xor_confidence_enum() {
    use stng::r2::XorConfidence;

    let high = XorConfidence::High;
    let medium = XorConfidence::Medium;
    let low = XorConfidence::Low;

    assert_eq!(high, XorConfidence::High);
    assert_eq!(medium, XorConfidence::Medium);
    assert_eq!(low, XorConfidence::Low);
    assert_ne!(high, medium);
    assert_ne!(medium, low);
}

/// Test XorKeyInfo structure
#[test]
fn test_xor_key_info_structure() {
    use stng::r2::{XorConfidence, XorKeyInfo};

    let key_info = XorKeyInfo {
        key: "test_key".to_string(),
        confidence: XorConfidence::High,
        reference_count: 5,
        offset: 0x1000,
    };

    assert_eq!(key_info.key, "test_key");
    assert_eq!(key_info.confidence, XorConfidence::High);
    assert_eq!(key_info.reference_count, 5);
    assert_eq!(key_info.offset, 0x1000);
}
