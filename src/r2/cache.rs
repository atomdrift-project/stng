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

pub struct R2Cache {
    cache_dir: PathBuf,
    enabled: bool,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct CacheMeta {
    file_size: u64,
    stng_version: String,
    created_at: u64, // unix timestamp
}

/// The r2/rizin cache root (`…/stng/r2`), or `None` when no cache location can
/// be determined. Mirrors the path [`R2Cache::with_enabled`] uses, and is the
/// directory [`crate::cache_sweep`] reclaims.
#[must_use]
pub fn cache_dir() -> Option<PathBuf> {
    // Linux: ~/.cache/stng/r2 · macOS: ~/Library/Caches/stng/r2
    // Windows: C:\Users\<user>\AppData\Local\stng\r2
    if let Some(base) = dirs::cache_dir() {
        return Some(base.join("stng").join("r2"));
    }
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache").join("stng").join("r2"))
}

impl R2Cache {
    /// Create a new cache instance with caching enabled.
    pub fn new() -> Result<Self, std::io::Error> {
        Self::with_enabled(true)
    }

    /// Create a cache instance with explicit enable/disable control.
    pub fn with_enabled(enabled: bool) -> Result<Self, std::io::Error> {
        let cache_dir = cache_dir()
            .unwrap_or_else(|| PathBuf::from(".").join(".cache").join("stng").join("r2"));
        Self::with_cache_dir(enabled, cache_dir)
    }

    /// Create a cache instance rooted at an explicit cache directory.
    pub fn with_cache_dir<P: AsRef<Path>>(
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
    pub fn get(&self, file_path: &str, command: &str) -> Option<String> {
        if !self.enabled {
            return None;
        }

        let hash = compute_file_hash(file_path).ok()?;
        let filename = sanitize_command_for_filename(command);
        let cache_path = self
            .cache_dir
            .join(&hash)
            .join(format!("{}.json", filename));

        // Validate cache is still valid
        if !self.is_cache_valid(file_path, &hash) {
            return None;
        }

        fs::read_to_string(&cache_path).ok()
    }

    /// Set cached r2 command output.
    pub fn set(&self, file_path: &str, command: &str, output: &str) -> Result<(), std::io::Error> {
        if !self.enabled {
            return Ok(());
        }

        let hash = compute_file_hash(file_path)?;
        let cache_dir = self.cache_dir.join(&hash);
        fs::create_dir_all(&cache_dir)?;

        // Write command output
        let filename = sanitize_command_for_filename(command);
        let output_path = cache_dir.join(format!("{}.json", filename));

        fs::write(output_path, output)?;

        // Write/update metadata
        self.write_meta(file_path, &hash)?;

        Ok(())
    }

    /// Clear cache for a specific file.
    pub fn clear(&self, file_path: &str) -> Result<(), std::io::Error> {
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
    let hash_hex = hex::encode(hash);

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
        format!("cmd_{}", hex::encode(hasher.finalize()))
    }
}

#[cfg(test)]
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
