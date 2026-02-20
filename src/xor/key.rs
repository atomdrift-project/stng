//! XOR key scoring and candidacy detection.
//!
//! Pure functions for evaluating whether a string looks like an XOR encryption key
//! and scoring it as a candidate. Used by the auto-detection pipeline.

/// Calculate Shannon entropy of a byte string.
/// Returns a value between 0.0 (no entropy) and 8.0 (maximum entropy for bytes).
pub(super) fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u32; 256];
    for &byte in data {
        freq[usize::from(byte)] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &freq {
        if count > 0 {
            let p = f64::from(count) / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Check if a string is a good XOR key candidate based on entropy.
/// DPRK malware often uses high-entropy keys like "Moz&Wie;#t/6T!2y", "12GWAPCT1F0I1S14".
///
/// `entropy` must be pre-computed by the caller via `calculate_entropy`.
pub(super) fn is_good_xor_key_candidate(s: &str, entropy: f64) -> bool {
    let len = s.len();

    // Length between 15-32 characters (typical for XOR keys)
    if !(15..=32).contains(&len) {
        return false;
    }

    // Must be ASCII
    if !s.is_ascii() {
        return false;
    }

    // Reject strings with underscores (typically not used in XOR keys)
    if s.contains('_') {
        return false;
    }

    // Reject obvious legitimate strings that aren't XOR keys
    let lower = s.to_ascii_lowercase();
    if lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("ftp://")
        || lower.contains("apple")
        || lower.contains("software")
        || lower.contains("signing")
        || lower.contains("certification")
        || lower.contains("authority")
        || lower.contains("directory")
        || lower.contains("cycle")
        || lower.contains("invalid")
        || lower.contains("error")
        || lower.contains("fail")
        || lower.contains("unknown")
        || lower.contains(" %s")
        || lower.contains(" %d")
        || lower.contains("%x")
    {
        return false;
    }

    // High entropy threshold: > 3.5 bits per byte
    // This catches keys like "Moz&Wie;#t/6T!2y" (entropy ~4.0)
    // and "12GWAPCT1F0I1S14" (entropy ~3.5)
    // but filters out low-entropy patterns
    if entropy < 3.5 {
        return false;
    }

    // Check for variety in character types (not just numbers, not just letters)
    let has_upper = s.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = s.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = s.chars().any(|c| c.is_ascii_digit());
    let has_special = s.chars().any(|c| !c.is_ascii_alphanumeric());

    // Good keys typically have at least 2 different character types
    let type_count = [has_upper, has_lower, has_digit, has_special]
        .iter()
        .filter(|&&x| x)
        .count();

    if type_count < 2 {
        return false;
    }

    // Reject sequential patterns (like "abcdefghijklmnopqrstuvwxyz")
    let mut sequential_count = 0;
    let bytes = s.as_bytes();
    for i in 0..bytes.len().saturating_sub(2) {
        if bytes[i] + 1 == bytes[i + 1] && bytes[i + 1] + 1 == bytes[i + 2] {
            sequential_count += 1;
        }
    }
    // Reject if more than 20% sequential
    if sequential_count * 5 > bytes.len() {
        return false;
    }

    true
}

/// Score a candidate string as a potential XOR key.
/// Higher scores indicate better XOR key candidates.
/// Good XOR keys typically have:
/// - Low character repetition (no character appears too many times)
/// - High character diversity (uses many different characters)
/// - High entropy (random-looking)
///
/// `entropy` must be pre-computed by the caller to avoid redundant calculation
/// (callers that already ran `is_good_xor_key_candidate` already computed it).
pub(super) fn score_xor_key_candidate(s: &str, entropy: f64) -> u32 {
    let mut score = 0u32;

    // Bonus for length (32-char keys are ideal)
    let len = s.len();
    if len == 32 {
        score += 100;
    } else if len >= 24 {
        score += 80;
    } else if len >= 20 {
        score += 60;
    } else if len >= 15 {
        score += 40;
    }

    // Calculate character frequency - good keys have low repetition
    let mut char_freq = [0u32; 256];
    for &byte in s.as_bytes() {
        char_freq[usize::from(byte)] += 1;
    }

    // Bonus for diversity: penalize if any character appears too often
    let max_freq = *char_freq.iter().max().unwrap_or(&1);
    let unique_chars = char_freq.iter().filter(|&&f| f > 0).count();

    // Max frequency should be low for good keys
    if max_freq <= 2 {
        score += 80; // Excellent - no character repeats more than twice
    } else if max_freq <= 3 {
        score += 60;
    } else if max_freq <= 4 {
        score += 40;
    } else if max_freq <= 5 {
        score += 20;
    }
    // else: penalize heavily for high repetition

    // Bonus for unique character count (good keys use many different chars)
    if unique_chars >= 20 {
        score += 60;
    } else if unique_chars >= 15 {
        score += 40;
    } else if unique_chars >= 12 {
        score += 20;
    }

    // Bonus for high entropy
    if entropy >= 4.5 {
        score += 50;
    } else if entropy >= 4.0 {
        score += 40;
    } else if entropy >= 3.5 {
        score += 20;
    }

    score
}
