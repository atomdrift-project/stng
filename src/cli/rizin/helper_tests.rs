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

/// Test extract_string_boundaries with large file (should skip)
#[test]
fn test_extract_string_boundaries_large_file() {
    // Create a file > 10MB (will be skipped)
    let temp_path = create_temp_file("r2_large", &vec![0u8; 11 * 1024 * 1024]);
    let file_path = temp_path.to_str().unwrap();

    let result = super::extract_string_boundaries(file_path, false);

    // Should return None for files > 10MB
    assert!(result.is_none(), "Should skip files larger than 10MB");

    let _ = fs::remove_file(temp_path);
}

/// Test extract_string_boundaries with non-existent file
#[test]
fn test_extract_string_boundaries_nonexistent() {
    let fake_path = "/nonexistent/boundaries_test.bin";

    let result = super::extract_string_boundaries(fake_path, false);

    // Should return None for non-existent file
    assert!(result.is_none(), "Should return None for non-existent file");
}

/// Test extract_strings with non-existent file
#[test]
fn test_extract_strings_nonexistent_file() {
    let result = super::extract_strings("/nonexistent/path/test.bin", 4, false);
    assert!(result.is_none(), "Should return None for non-existent file");
}

/// Test extract_connect_addrs with non-existent file
#[test]
fn test_extract_connect_addrs_nonexistent() {
    let fake_data = b"test data";

    let result = super::extract_connect_addrs("/nonexistent/path.bin", fake_data, false);

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

    let result = super::extract_connect_addrs(file_path, &large_data, false);

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

    let result = super::extract_connect_addrs(file_path, b"", false);

    // Should return empty for empty data
    assert!(result.is_empty(), "Should return empty for empty data");

    let _ = fs::remove_file(temp_path);
}
