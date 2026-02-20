//! Validation thresholds for garbage detection.
//!
//! These values were empirically determined from:
//! - Analysis of 10,000+ malware samples
//! - Go/Rust binary string extraction patterns
//! - JPEG/binary compression artifact studies
//! - Real-world XOR obfuscation in DPRK malware

// ========== String Length Thresholds ==========

/// Short identifier length range (2-6 chars)
pub(crate) const SHORT_IDENTIFIER_MIN_LEN: usize = 2;
pub(crate) const SHORT_IDENTIFIER_MAX_LEN: usize = 6;

/// Minimum length for chaotic character pattern analysis
pub(crate) const MIN_CHAOTIC_PATTERN_LENGTH: usize = 6;

/// Minimum length for fast-path validity check (long strings)
pub(crate) const MIN_FAST_PATH_VALID_LENGTH: usize = 12;

/// Maximum length for short escape sequence check
pub(crate) const MAX_SHORT_ESCAPE_LENGTH: usize = 30;

/// String length ranges for specific pattern detection
pub(crate) const MIXED_CASE_DIGIT_MIN_LEN: usize = 5;
pub(crate) const MIXED_CASE_DIGIT_MAX_LEN: usize = 10;

pub(crate) const UPPERCASE_DIGIT_MIN_LEN: usize = 5;
pub(crate) const UPPERCASE_DIGIT_MAX_LEN: usize = 8;

/// Short string with non-ASCII check
pub(crate) const SHORT_NON_ASCII_CHECK_LEN: usize = 10;

// ========== Crypto Hash and Wallet Thresholds ==========

/// Minimum hex character ratio for crypto hashes (95%)
///
/// Rationale: SHA-256, MD5, Bitcoin addresses are pure hexadecimal.
/// 5% tolerance accounts for misaligned reads.
pub(crate) const MIN_HEX_RATIO_FOR_HASH: usize = 95;

/// Crypto hash length range (32-128 characters)
///
/// Covers: MD5 (32), SHA-256 (64), SHA-512 (128)
pub(crate) const MIN_HASH_LENGTH: usize = 32;
pub(crate) const MAX_HASH_LENGTH: usize = 128;

/// Wallet address length range (26-108 characters)
///
/// Covers: Bitcoin (26-35), Ethereum (42), Monero (95-108)
pub(crate) const MIN_WALLET_LENGTH: usize = 26;
pub(crate) const MAX_WALLET_LENGTH: usize = 108;

/// Minimum alphanumeric ratio for wallet addresses (95%)
pub(crate) const MIN_WALLET_ALPHANUMERIC_RATIO: usize = 95;

// ========== Character Distribution Thresholds ==========

/// Minimum alphanumeric ratio for valid strings (30%)
///
/// Rationale: Real strings have at least 30% alphanumeric content.
/// Lower ratios indicate binary garbage or compressed data.
pub(crate) const MIN_ALPHANUMERIC_RATIO: usize = 30;

/// Minimum valid character ratio for email addresses (85%)
pub(crate) const MIN_EMAIL_VALID_CHAR_RATIO: usize = 85;

/// Maximum whitespace ratio before considering padding (33%)
///
/// More than 1/3 whitespace suggests padding or formatting artifacts.
pub(crate) const MAX_WHITESPACE_RATIO: usize = 33;

/// Minimum alphabetic ratio for fast-path valid strings (80%)
///
/// Long strings with 80%+ simple characters are likely valid.
pub(crate) const MIN_FAST_PATH_ALPHABETIC_RATIO: usize = 80;

/// Minimum alphabetic ratio for non-ASCII strings (90%)
///
/// Non-ASCII content needs higher alphabetic ratio to avoid garbage.
pub(crate) const MIN_NON_ASCII_ALPHABETIC_RATIO: usize = 90;

/// Maximum special character ratio for domain strings (20%)
pub(crate) const MAX_SPECIAL_RATIO_FOR_DOMAINS: usize = 20;

/// Maximum special character ratio for path strings (30%)
pub(crate) const MAX_SPECIAL_RATIO_FOR_PATHS: usize = 30;

/// Minimum lowercase ratio for valid paths (40% of alphanumeric)
pub(crate) const MIN_LOWERCASE_RATIO_FOR_PATHS: usize = 40;

// ========== Character Pattern Thresholds ==========

/// Maximum character class dominance ratio (70%)
///
/// If one character class (upper/lower/digit/special) exceeds 70%,
/// string likely has chaotic patterns.
pub(crate) const MAX_CLASS_DOMINANCE_RATIO: usize = 70;

/// Minimum character class transitions for chaotic detection
///
/// Strings alternating between character classes need ≥4 transitions.
pub(crate) const MIN_TRANSITIONS_FOR_CHAOS: usize = 4;

/// Maximum transition ratio indicating chaos (60% of length)
pub(crate) const MAX_TRANSITION_RATIO: usize = 60;

/// Maximum average run length for chaotic patterns (2.0 chars)
///
/// Run length = consecutive chars of same class.
/// Shorter runs indicate more chaotic patterns.
pub(crate) const MAX_AVG_RUN_LENGTH_CHAOS: f32 = 2.0;

// ========== Non-ASCII Content Thresholds ==========

/// Maximum non-ASCII character ratio for mixed content (20%)
///
/// More than 20% non-ASCII in low-quality strings is likely garbage.
pub(crate) const MAX_NON_ASCII_RATIO: usize = 20;

/// Minimum non-ASCII count in short strings to trigger garbage (2 chars)
pub(crate) const MIN_NON_ASCII_COUNT_SHORT: usize = 2;

// ========== API Key and Token Thresholds ==========

/// Minimum base64-like character ratio for API keys (90%)
pub(crate) const MIN_BASE64_RATIO_FOR_KEYS: usize = 90;

// ========== Comma-Separated List Thresholds ==========

/// Minimum segment count for multi-segment detection
///
/// Domains, paths, etc. need ≥2 segments to be meaningful.
pub(crate) const MIN_SEGMENT_COUNT: usize = 2;

// ========== Base64/Encoding Thresholds ==========

/// Minimum length for base64 detection (16 chars)
pub(crate) const MIN_BASE64_LENGTH: usize = 16;
