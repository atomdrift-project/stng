//! Edge cases for `is_garbage`.

use stng::is_garbage;

#[test]
fn keeps_deep_paths() {
    // Paths with multiple separators
    assert!(!is_garbage("/usr/local/bin/test"));
    assert!(!is_garbage("C:\\Windows\\System32\\cmd.exe"));
}

#[test]
fn keeps_format_strings() {
    // Printf-style format strings should not be garbage
    assert!(!is_garbage("Error: %s at line %d"));
    assert!(!is_garbage("Processing %d of %d items"));
}

#[test]
fn keeps_urls() {
    assert!(!is_garbage("https://example.com/path"));
    assert!(!is_garbage("http://localhost:8080"));
}

#[test]
fn keeps_json_rejects_short_array() {
    assert!(!is_garbage("{\"key\": \"value\"}"));
    // Short strings with punctuation are filtered
    assert!(is_garbage("[1, 2, 3]"));
}

#[test]
fn rejects_one_char_keeps_two() {
    // Very short strings
    assert!(is_garbage("a")); // 1 char is garbage
    // 2-3 char strings can be valid identifiers
    assert!(!is_garbage("ab"));
    assert!(!is_garbage("abc"));

    // Exactly at boundary
    assert!(!is_garbage("test")); // 4 chars, should be ok if valid
}

#[test]
fn keeps_padded_phrase_rejects_tab() {
    // Leading/trailing whitespace
    assert!(!is_garbage("  hello world  "));
    // Tabs are control characters and filtered
    assert!(is_garbage("hello\tworld"));
}

#[test]
fn rejects_bare_dotted_triple_keeps_versions() {
    // Short strings with dots are filtered as noise punctuation
    assert!(is_garbage("1.2.3"));
    assert!(!is_garbage("v2.0.0"));
    // Hex addresses
    assert!(!is_garbage("0x12345678"));
}
