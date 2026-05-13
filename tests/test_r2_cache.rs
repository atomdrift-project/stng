#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
/// Comprehensive tests for r2 cache functionality
/// Covers src/r2/cache.rs (~245 lines, 0% → 80% coverage)
use std::fs;
use std::path::PathBuf;

// Re-export cache types for testing
use stng::r2::cache::R2Cache;

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

fn temp_cache_path(prefix: &str) -> PathBuf {
    let mut path = temp_file_path(prefix);
    path.set_extension("cache");
    path
}

fn test_cache(prefix: &str) -> (R2Cache, PathBuf) {
    let cache_dir = temp_cache_path(prefix);
    let cache = R2Cache::with_cache_dir(true, &cache_dir).unwrap();
    (cache, cache_dir)
}

// Helper to create a temporary file with content
fn create_temp_file(prefix: &str, content: &[u8]) -> PathBuf {
    let path = temp_file_path(prefix);
    fs::write(&path, content).unwrap();
    path
}

/// Test cache creation and directory structure
#[test]
fn test_cache_creation() {
    let cache_dir = temp_cache_path("cache_creation");
    let cache = R2Cache::with_cache_dir(true, &cache_dir);
    assert!(cache.is_ok(), "Cache creation should succeed");

    let cache = R2Cache::with_cache_dir(true, &cache_dir);
    assert!(
        cache.is_ok(),
        "Cache creation with enabled=true should succeed"
    );

    let cache = R2Cache::with_cache_dir(false, &cache_dir);
    assert!(
        cache.is_ok(),
        "Cache creation with enabled=false should succeed"
    );

    let _ = fs::remove_dir_all(cache_dir);
}

/// Test cache set and get operations (cache hit)
#[test]
fn test_cache_hit() {
    let (cache, cache_dir) = test_cache("cache_hit_cache");

    // Create a temporary file
    let temp_path = create_temp_file("cache_hit", b"test binary content");
    let file_path = temp_path.to_str().unwrap();

    // Set cache value
    let command = "isj";
    let output = r#"[{"name":"main","vaddr":12345}]"#;
    let result = cache.set(file_path, command, output);
    assert!(result.is_ok(), "Cache set should succeed");

    // Get cache value (should hit)
    let cached = cache.get(file_path, command);
    assert!(cached.is_some(), "Cache should return value");
    assert_eq!(cached.unwrap(), output, "Cached value should match");

    // Clean up cache and file
    let _ = cache.clear(file_path);
    let _ = fs::remove_file(temp_path);
    let _ = fs::remove_dir_all(cache_dir);
}

/// Test cache miss for non-existent command
#[test]
fn test_cache_miss() {
    let (cache, cache_dir) = test_cache("cache_miss_cache");

    let temp_path = create_temp_file("cache_miss", b"test binary");
    let file_path = temp_path.to_str().unwrap();

    // Try to get cache for command that was never set
    let cached = cache.get(file_path, "nonexistent_command");
    assert!(
        cached.is_none(),
        "Cache should miss for non-existent command"
    );

    let _ = fs::remove_file(temp_path);
    let _ = fs::remove_dir_all(cache_dir);
}

/// Test multiple commands cached for same file
#[test]
fn test_multiple_commands_same_file() {
    let (cache, cache_dir) = test_cache("multi_cmd_cache");

    let temp_path = create_temp_file("multi_cmd", b"unique binary for multi cmd test");
    let file_path = temp_path.to_str().unwrap();

    // Cache multiple commands
    let cmd1 = "isj";
    let out1 = r#"[{"name":"main"}]"#;
    cache.set(file_path, cmd1, out1).unwrap();

    let cmd2 = "izzj";
    let out2 = r#"[{"string":"hello"}]"#;
    cache.set(file_path, cmd2, out2).unwrap();

    let cmd3 = "aaa; aflj";
    let out3 = r#"[{"name":"func1"}]"#;
    cache.set(file_path, cmd3, out3).unwrap();

    // Verify all cached
    assert_eq!(cache.get(file_path, cmd1).unwrap(), out1);
    assert_eq!(cache.get(file_path, cmd2).unwrap(), out2);
    assert_eq!(cache.get(file_path, cmd3).unwrap(), out3);

    // Clean up
    let _ = cache.clear(file_path);
    let _ = fs::remove_file(temp_path);
    let _ = fs::remove_dir_all(cache_dir);
}

/// Test cache invalidation when file size changes
#[test]
fn test_cache_invalidation_on_file_size_change() {
    let (cache, cache_dir) = test_cache("invalidate_cache");

    let temp_path = create_temp_file("invalidate", b"original content");
    let file_path = temp_path.to_str().unwrap();

    // Set cache
    let command = "isj";
    let output = r#"[{"name":"func"}]"#;
    cache.set(file_path, command, output).unwrap();

    // Verify cache hit
    assert!(cache.get(file_path, command).is_some());

    // Modify file (change size)
    fs::write(&temp_path, b"modified content with different size").unwrap();

    // Cache should be invalidated (miss)
    let result = cache.get(file_path, command);
    assert!(
        result.is_none(),
        "Cache should be invalidated when file size changes"
    );

    // Clean up
    let _ = cache.clear(file_path);
    let _ = fs::remove_file(temp_path);
    let _ = fs::remove_dir_all(cache_dir);
}

/// Test cache clear operation
#[test]
fn test_cache_clear() {
    let (cache, cache_dir) = test_cache("clear_cache");

    let temp_path = create_temp_file("clear", b"unique content for clear test");
    let file_path = temp_path.to_str().unwrap();

    // Set multiple cached values
    cache.set(file_path, "isj", r#"[{"name":"main"}]"#).unwrap();
    cache
        .set(file_path, "izzj", r#"[{"string":"test"}]"#)
        .unwrap();

    // Verify cached
    assert!(cache.get(file_path, "isj").is_some());
    assert!(cache.get(file_path, "izzj").is_some());

    // Clear cache
    let result = cache.clear(file_path);
    assert!(result.is_ok(), "Cache clear should succeed");

    // Verify cache cleared
    assert!(cache.get(file_path, "isj").is_none());
    assert!(cache.get(file_path, "izzj").is_none());

    let _ = fs::remove_file(temp_path);
    let _ = fs::remove_dir_all(cache_dir);
}

/// Test cache with disabled mode
#[test]
fn test_cache_disabled_mode() {
    let cache_dir = temp_cache_path("disabled_cache");
    let cache = R2Cache::with_cache_dir(false, &cache_dir).unwrap();

    let temp_path = create_temp_file("disabled", b"unique content for disabled test");
    let file_path = temp_path.to_str().unwrap();

    // Try to set (should succeed but do nothing)
    let result = cache.set(file_path, "isj", r#"[{"name":"main"}]"#);
    assert!(result.is_ok(), "Set should succeed even when disabled");

    // Try to get (should return None)
    let cached = cache.get(file_path, "isj");
    assert!(
        cached.is_none(),
        "Get should return None when cache is disabled"
    );

    // Clear should also succeed (no-op)
    let result = cache.clear(file_path);
    assert!(result.is_ok(), "Clear should succeed when disabled");

    let _ = fs::remove_file(temp_path);
    let _ = fs::remove_dir_all(cache_dir);
}

/// Test cache with special characters in command
#[test]
fn test_cache_special_command_characters() {
    let (cache, cache_dir) = test_cache("special_chars_cache");

    let temp_path = create_temp_file("special_chars", b"unique content for special chars test");
    let file_path = temp_path.to_str().unwrap();

    // Commands with special characters that need sanitization
    let commands = [
        "aaa; aflj",
        "aaa; e scr.color=0",
        "pdf @ entry0",
        "aaa; e scr.color=0; pdf @ entry0",
    ];

    for (i, cmd) in commands.iter().enumerate() {
        let output = format!(r#"[{{"result":{}}}]"#, i);
        cache.set(file_path, cmd, &output).unwrap();

        let cached = cache.get(file_path, cmd);
        assert!(
            cached.is_some(),
            "Should cache command with special chars: {}",
            cmd
        );
        assert_eq!(cached.unwrap(), output);
    }

    // Clean up
    let _ = cache.clear(file_path);
    let _ = fs::remove_file(temp_path);
    let _ = fs::remove_dir_all(cache_dir);
}

/// Test cache persistence across cache instances
#[test]
fn test_cache_persistence() {
    let cache_dir = temp_cache_path("persist_cache");
    let temp_path = create_temp_file("persist", b"test binary data");
    let file_path = temp_path.to_str().unwrap();

    let command = "isj";
    let output = r#"[{"name":"persistent"}]"#;

    // Create first cache instance and set value
    {
        let cache1 = R2Cache::with_cache_dir(true, &cache_dir).unwrap();
        cache1.set(file_path, command, output).unwrap();
    } // cache1 dropped

    // Create second cache instance and verify value persists
    {
        let cache2 = R2Cache::with_cache_dir(true, &cache_dir).unwrap();
        let cached = cache2.get(file_path, command);
        assert!(
            cached.is_some(),
            "Cache should persist across cache instances"
        );
        assert_eq!(cached.unwrap(), output);

        // Clean up
        let _ = cache2.clear(file_path);
    }

    let _ = fs::remove_file(temp_path);
    let _ = fs::remove_dir_all(cache_dir);
}

/// Test cache with non-existent file (should handle gracefully)
#[test]
fn test_cache_nonexistent_file() {
    let (cache, cache_dir) = test_cache("nonexistent_cache");

    let fake_path = "/tmp/nonexistent_file_12345678.bin";

    // Get should return None
    let result = cache.get(fake_path, "isj");
    assert!(result.is_none(), "Should return None for non-existent file");

    // Set should fail gracefully
    let result = cache.set(fake_path, "isj", "output");
    assert!(result.is_err(), "Should fail to cache non-existent file");

    let _ = fs::remove_dir_all(cache_dir);
}

/// Test empty command and output
#[test]
fn test_cache_empty_values() {
    let (cache, cache_dir) = test_cache("empty_cache");

    let temp_path = create_temp_file("empty", b"unique content for empty values test");
    let file_path = temp_path.to_str().unwrap();

    // Empty command (unusual but should work)
    cache.set(file_path, "", "output").unwrap();
    let cached = cache.get(file_path, "");
    assert!(cached.is_some(), "Should handle empty command");

    // Empty output (valid case)
    cache.set(file_path, "cmd", "").unwrap();
    let cached = cache.get(file_path, "cmd");
    assert!(cached.is_some(), "Should handle empty output");
    assert_eq!(cached.unwrap(), "");

    // Clean up
    let _ = cache.clear(file_path);
    let _ = fs::remove_file(temp_path);
    let _ = fs::remove_dir_all(cache_dir);
}

/// Test large cache output
#[test]
fn test_cache_large_output() {
    let (cache, cache_dir) = test_cache("large_cache");

    let temp_path = create_temp_file("large", b"unique content for large output test");
    let file_path = temp_path.to_str().unwrap();

    // Generate large output (simulating large function list)
    let large_output = format!(
        r#"[{}]"#,
        (0..1000)
            .map(|i| format!(r#"{{"name":"func{}","addr":{}}}"#, i, i * 100))
            .collect::<Vec<_>>()
            .join(",")
    );

    cache.set(file_path, "aflj", &large_output).unwrap();

    let cached = cache.get(file_path, "aflj");
    assert!(cached.is_some(), "Should cache large output");
    assert_eq!(cached.unwrap().len(), large_output.len());

    // Clean up
    let _ = cache.clear(file_path);
    let _ = fs::remove_file(temp_path);
    let _ = fs::remove_dir_all(cache_dir);
}

/// Test cache clear on non-existent cache (should succeed)
#[test]
fn test_cache_clear_nonexistent() {
    let (cache, cache_dir) = test_cache("clear_none_cache");

    let temp_path = create_temp_file("clear_none", b"unique content for clear nonexistent test");
    let file_path = temp_path.to_str().unwrap();

    // Clear cache that was never created
    let result = cache.clear(file_path);
    assert!(result.is_ok(), "Clearing non-existent cache should succeed");

    let _ = fs::remove_file(temp_path);
    let _ = fs::remove_dir_all(cache_dir);
}
