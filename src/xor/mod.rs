//! XOR string detection for finding obfuscated strings in malware.
//!
//! This module detects strings that have been XOR'd with a single-byte key,
//! a common obfuscation technique in malware. Uses Aho-Corasick for efficient
//! single-pass multi-pattern matching.
//!
//! [`repeating_pe`] recovers the repeating key of a whole file that decodes to
//! a PE image (a dropper's encrypted payload), rather than individual strings.

mod autodetect;
mod classify;
mod expand;
mod key;
pub(crate) mod repeating_pe;
mod scan;
mod validate;

// Re-export the public API that lib.rs calls as `xor::*`
pub(crate) use self::autodetect::auto_detect_xor_key;
pub(crate) use self::classify::report_kinds;
pub(crate) use self::expand::{extract_multikey_xor_strings, extract_xor_strings};
pub use self::repeating_pe::{RepeatingXorKey, recover_repeating_xor_pe};
pub use self::scan::extract_incremental_xor_strings;
pub(crate) use self::scan::{
    extract_custom_xor_strings_with_hints, extract_rolling_xor_with_known_plaintext,
};

// Note: Private functions are re-imported in the tests module below

/// Minimum length for XOR-decoded strings (default).
pub(crate) const DEFAULT_XOR_MIN_LENGTH: usize = 10;

/// XOR keys to skip because they produce too many false positives.
/// 0x20 (space) just flips letter case, causing "GOROOT OBJECT" to become "gorootOBJECT".
pub(crate) const SKIP_XOR_KEYS: &[u8] = &[0x20];

/// Maximum file size for auto-detection of XOR keys (512 KB).
pub(crate) const MAX_AUTO_DETECT_SIZE: usize = 512 * 1024;

/// Maximum file size for single-byte XOR scanning (5 MB).
/// Larger files take too long to scan and rarely contain simple XOR obfuscation.
pub const MAX_XOR_SCAN_SIZE: usize = 5 * 1024 * 1024;

#[cfg(test)]
mod tests;
