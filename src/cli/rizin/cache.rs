//! Caching for radare2/rizin command outputs to avoid expensive re-analysis.
//!
//! Cache structure:
//! ```text
//! ~/.cache/stng/r2/<sha256>/
//!   isj.json           # symbols
//!   izzj.json          # strings
//!   aaa_aflj.json      # functions (command sanitized for filesystem)
//!   meta.json          # cache metadata
//! ```

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

/// Global cache for file hashes to avoid redundant hashing of large binaries.
/// Map of absolute path -> SHA256 hex string.
static HASH_CACHE: LazyLock<Mutex<HashMap<String, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub(crate) struct R2Cache {
    cache_dir: PathBuf,
    enabled: bool,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct CacheMeta {
    file_size: u64,
    stng_version: String,
    created_at: u64, // unix timestamp
}

/// Entries (one directory per analysed file) kept before the oldest go.
const MAX_ENTRIES: usize = 4096;
/// Entries untouched for this long are dropped.
const MAX_AGE: std::time::Duration = std::time::Duration::from_secs(30 * 24 * 60 * 60);

/// The r2/rizin cache root (`…/stng/r2`), or `None` when no cache location can
/// be determined. Mirrors the path [`R2Cache::with_enabled`] uses, and is the
/// directory [`R2Cache::prune`] bounds.
#[must_use]
pub(crate) fn cache_dir() -> Option<PathBuf> {
    // Linux: ~/.cache/stng/r2 · macOS: ~/Library/Caches/stng/r2
    // Windows: C:\Users\<user>\AppData\Local\stng\r2
    if let Some(base) = dirs::cache_dir() {
        return Some(base.join("stng").join("r2"));
    }
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache").join("stng").join("r2"))
}

impl R2Cache {
    /// Create a new cache instance with caching enabled.
    pub(crate) fn new() -> Result<Self, std::io::Error> {
        Self::with_enabled(true)
    }

    /// Create a cache instance with explicit enable/disable control.
    pub(crate) fn with_enabled(enabled: bool) -> Result<Self, std::io::Error> {
        // No cache location (no home directory): run uncached rather than
        // write into the working directory.
        match cache_dir() {
            Some(dir) => Self::with_cache_dir(enabled, dir),
            None => Self::with_cache_dir(false, PathBuf::new()),
        }
    }

    /// Create a cache instance rooted at an explicit cache directory.
    pub(crate) fn with_cache_dir<P: AsRef<Path>>(
        enabled: bool,
        cache_dir: P,
    ) -> Result<Self, std::io::Error> {
        let cache_dir = cache_dir.as_ref().to_path_buf();
        if enabled {
            fs::create_dir_all(&cache_dir)?;
        }

        Ok(Self { cache_dir, enabled })
    }

    /// Get cached r2 command output.
    /// Returns None if cache miss or cache disabled.
    #[must_use]
    pub(crate) fn get(&self, file_path: &str, command: &str) -> Option<String> {
        if !self.enabled {
            return None;
        }

        let hash = compute_file_hash(file_path).ok()?;
        let filename = sanitize_command_for_filename(command);
        let cache_path = self.cache_dir.join(&hash).join(format!("{filename}.json"));

        // Validate cache is still valid
        if !self.is_cache_valid(file_path, &hash) {
            return None;
        }

        fs::read_to_string(&cache_path).ok()
    }

    /// Set cached r2 command output.
    pub(crate) fn set(
        &self,
        file_path: &str,
        command: &str,
        output: &str,
    ) -> Result<(), std::io::Error> {
        if !self.enabled {
            return Ok(());
        }

        let hash = compute_file_hash(file_path)?;
        let cache_dir = self.cache_dir.join(&hash);
        if !cache_dir.exists() {
            // A new file: this run is spending seconds in rizin anyway, so a
            // walk of the cache to bound it costs nothing noticeable.
            self.prune();
        }
        fs::create_dir_all(&cache_dir)?;

        // Write command output
        let filename = sanitize_command_for_filename(command);
        let output_path = cache_dir.join(format!("{filename}.json"));

        fs::write(output_path, output)?;

        // Write/update metadata
        self.write_meta(file_path, &hash)?;

        Ok(())
    }

    /// Clear cache for a specific file.
    pub(crate) fn clear(&self, file_path: &str) -> Result<(), std::io::Error> {
        if !self.enabled {
            return Ok(());
        }

        let hash = compute_file_hash(file_path)?;
        let cache_dir = self.cache_dir.join(&hash);

        if cache_dir.exists() {
            fs::remove_dir_all(cache_dir)?;
        }

        Ok(())
    }

    /// Drop entries untouched for [`MAX_AGE`], then the oldest beyond
    /// [`MAX_ENTRIES`]. Best-effort: a failure costs disk, never a result.
    fn prune(&self) {
        let Ok(dir) = fs::read_dir(&self.cache_dir) else {
            return;
        };
        let mut entries: Vec<(std::time::SystemTime, PathBuf)> = dir
            .flatten()
            .filter_map(|e| {
                let meta = e.metadata().ok()?;
                meta.is_dir().then_some((meta.modified().ok()?, e.path()))
            })
            .collect();
        entries.sort();
        let excess = entries.len().saturating_sub(MAX_ENTRIES);
        for (i, (modified, path)) in entries.iter().enumerate() {
            let stale = modified.elapsed().is_ok_and(|age| age > MAX_AGE);
            if i < excess || stale {
                let _ = fs::remove_dir_all(path);
            }
        }
    }

    fn is_cache_valid(&self, file_path: &str, hash: &str) -> bool {
        let meta_path = self.cache_dir.join(hash).join("meta.json");
        let Ok(meta_content) = fs::read_to_string(meta_path) else {
            return false;
        };

        let meta: CacheMeta = match serde_json::from_str(&meta_content) {
            Ok(m) => m,
            Err(_) => return false,
        };

        // Validate file size hasn't changed
        if let Ok(metadata) = fs::metadata(file_path) {
            metadata.len() == meta.file_size
        } else {
            false
        }
    }

    fn write_meta(&self, file_path: &str, hash: &str) -> Result<(), std::io::Error> {
        let metadata = fs::metadata(file_path)?;
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(std::io::Error::other)?
            .as_secs();
        let meta = CacheMeta {
            file_size: metadata.len(),
            stng_version: env!("CARGO_PKG_VERSION").to_string(),
            created_at,
        };

        let meta_path = self.cache_dir.join(hash).join("meta.json");
        fs::write(meta_path, serde_json::to_string(&meta)?)?;
        Ok(())
    }
}

/// Compute SHA256 hash of file contents with memoization.
fn compute_file_hash(path: &str) -> Result<String, std::io::Error> {
    // Check cache first (canonicalize path to ensure consistent keys)
    let canon_path = fs::canonicalize(path)?.to_string_lossy().to_string();

    {
        let cache = HASH_CACHE
            .lock()
            .map_err(|e| std::io::Error::other(format!("Hash cache lock failed: {e}")))?;
        if let Some(hash) = cache.get(&canon_path) {
            return Ok(hash.clone());
        }
    }

    // Cache miss - compute hash
    let data = fs::read(path)?;
    let hash = Sha256::digest(&data);
    let hash_hex = crate::cli::hex(&hash);

    // Update cache (skip on mutex poison — next call will recompute the hash)
    match HASH_CACHE.lock() {
        Ok(mut cache) => {
            cache.insert(canon_path, hash_hex.clone());
        }
        Err(e) => tracing::warn!("Hash cache mutex poisoned, skipping update: {e}"),
    }

    Ok(hash_hex)
}

/// Sanitize r2 command for use as filename.
///
/// Replaces non-alphanumeric characters (except dash and period) with underscore.
/// For very long commands, returns a hash of the command to avoid exceeding
/// OS filename limits (typically 255 characters).
fn sanitize_command_for_filename(cmd: &str) -> String {
    if cmd.len() < 100 {
        cmd.chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '.' {
                    c
                } else {
                    '_'
                }
            })
            .collect()
    } else {
        // Use SHA256 hash for long commands to ensure safe filename
        let mut hasher = Sha256::new();
        hasher.update(cmd.as_bytes());
        format!("cmd_{}", crate::cli::hex(&hasher.finalize()))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_simple_command() {
        assert_eq!(sanitize_command_for_filename("isj"), "isj");
        assert_eq!(sanitize_command_for_filename("izzj"), "izzj");
    }

    #[test]
    fn test_sanitize_compound_command() {
        assert_eq!(sanitize_command_for_filename("aaa; aflj"), "aaa__aflj");
        assert_eq!(
            sanitize_command_for_filename("aaa; e scr.color=0"),
            "aaa__e_scr.color_0"
        );
    }

    #[test]
    fn test_sanitize_complex_command() {
        assert_eq!(
            sanitize_command_for_filename("pdf @ entry0"),
            "pdf___entry0"
        );
        assert_eq!(
            sanitize_command_for_filename("aaa; e scr.color=0; pdf @ entry0"),
            "aaa__e_scr.color_0__pdf___entry0"
        );
    }

    #[test]
    fn test_cache_disabled() {
        let cache = R2Cache::with_enabled(false).unwrap();
        let result = cache.get("/bin/ls", "isj");
        assert!(result.is_none());
    }
}

/// Moved from `tests/` when this module moved from the library to the CLI.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod behavior_tests {
    use super::*;
    /// Comprehensive tests for r2 cache functionality
    /// Covers src/r2/cache.rs (~245 lines, 0% → 80% coverage)
    use std::fs;
    use std::path::PathBuf;

    // Re-export cache types for testing

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
            let output = format!(r#"[{{"result":{i}}}]"#);
            cache.set(file_path, cmd, &output).unwrap();

            let cached = cache.get(file_path, cmd);
            assert!(
                cached.is_some(),
                "Should cache command with special chars: {cmd}"
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
            r"[{}]",
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

        let temp_path =
            create_temp_file("clear_none", b"unique content for clear nonexistent test");
        let file_path = temp_path.to_str().unwrap();

        // Clear cache that was never created
        let result = cache.clear(file_path);
        assert!(result.is_ok(), "Clearing non-existent cache should succeed");

        let _ = fs::remove_file(temp_path);
        let _ = fs::remove_dir_all(cache_dir);
    }
}
