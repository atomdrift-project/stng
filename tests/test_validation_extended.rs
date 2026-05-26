#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Extended validation tests for edge cases and special patterns.
//!
//! These tests complement the existing validation tests in src/validation.rs
//! by testing additional edge cases and boundary conditions.

use stng::is_garbage;

// ===== MAC Address Tests =====

#[test]
fn test_mac_address_formats() {
    // Colon format: 00:1A:2B:3C:4D:5E
    assert!(!is_garbage("00:1A:2B:3C:4D:5E"), "MAC colon format");
    assert!(!is_garbage("FF:FF:FF:FF:FF:FF"), "MAC broadcast");
    assert!(!is_garbage("aa:bb:cc:dd:ee:ff"), "MAC lowercase hex");

    // Dash format: 00-1A-2B-3C-4D-5E
    assert!(!is_garbage("00-1A-2B-3C-4D-5E"), "MAC dash format");
    assert!(!is_garbage("AA-BB-CC-DD-EE-FF"), "MAC dash uppercase");

    // Cisco format: 001A.2B3C.4D5E
    assert!(!is_garbage("001A.2B3C.4D5E"), "MAC Cisco format");
    assert!(!is_garbage("aabb.ccdd.eeff"), "MAC Cisco lowercase");
}

#[test]
fn test_incomplete_mac_addresses() {
    // Incomplete MACs are still valid strings (not garbage)
    assert!(!is_garbage("00:1A:2B:3C:4D"), "Incomplete MAC");
}

// ===== IPv6 Address Tests =====

#[test]
fn test_ipv6_addresses() {
    // Full IPv6
    assert!(
        !is_garbage("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
        "IPv6 full"
    );

    // Compressed IPv6
    assert!(
        !is_garbage("2001:db8:85a3::8a2e:370:7334"),
        "IPv6 compressed"
    );
    assert!(!is_garbage("2001:db8::1"), "IPv6 short compressed");

    // Special IPv6 addresses
    assert!(!is_garbage("::1"), "IPv6 loopback");
    // Note: "::" alone is too short (len=2) and is garbage
    assert!(!is_garbage("fe80::1"), "IPv6 link-local");
    assert!(!is_garbage("ff02::1"), "IPv6 multicast");

    // IPv6 with IPv4
    assert!(!is_garbage("::ffff:192.0.2.1"), "IPv6 with IPv4 mapped");
    assert!(!is_garbage("2001:db8::192.0.2.1"), "IPv6 with IPv4 suffix");
}

#[test]
fn test_short_ipv6_like_strings() {
    // Short strings with colons are not automatically garbage
    assert!(!is_garbage("2001:db8:1"), "Short IPv6-like string");
}

// ===== Crypto Hash Tests =====

#[test]
fn test_crypto_hashes() {
    // MD5 (32 hex chars)
    assert!(!is_garbage("5d41402abc4b2a76b9719d911017c592"), "MD5 hash");

    // SHA1 (40 hex chars)
    assert!(
        !is_garbage("356a192b7913b04c54574d18c28d46e6395428ab"),
        "SHA1 hash"
    );

    // SHA256 (64 hex chars)
    assert!(
        !is_garbage("a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"),
        "SHA256 hash"
    );

    // SHA512 (128 hex chars)
    assert!(
        !is_garbage(
            "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff"
        ),
        "SHA512 hash"
    );

    // Uppercase hex
    assert!(
        !is_garbage("5D41402ABC4B2A76B9719D911017C592"),
        "MD5 uppercase"
    );
}

#[test]
fn test_non_hash_hex_strings() {
    // Short hex strings (< 32 chars) are not automatically garbage
    assert!(!is_garbage("deadbeef"), "Short hex identifier");
    assert!(!is_garbage("cafebabe"), "Hex pattern");

    // Too long (> 128 chars) - not tested as it depends on other heuristics

    // Not all hex (< 95% hex) - this would fail hash detection but may not be garbage
    assert!(
        !is_garbage("5d41402abc4b2a76b9719d911017c59z"),
        "Non-hex char"
    );
}

// ===== Locale String Tests =====

#[test]
fn test_locale_strings() {
    // Standard locales (2 lower + underscore + 2 upper)
    assert!(!is_garbage("en_US"), "English US locale");
    assert!(!is_garbage("zh_CN"), "Chinese locale");
    assert!(!is_garbage("fr_FR"), "French locale");
    assert!(!is_garbage("de_DE"), "German locale");
    assert!(!is_garbage("ja_JP"), "Japanese locale");

    // Extended locales (3 lower + underscore + 2 upper)
    assert!(!is_garbage("eng_US"), "3-letter language code");
}

#[test]
fn test_invalid_locales() {
    // Wrong case pattern
    assert!(is_garbage("EN_us"), "Uppercase-lowercase locale");
    assert!(is_garbage("en_us"), "All lowercase locale");

    // Wrong length
    assert!(is_garbage("e_US"), "Too short language code");
    assert!(is_garbage("en_U"), "Too short country code");
}

// ===== XML/Plist Tag Tests =====

#[test]
fn test_xml_tags() {
    assert!(!is_garbage("<array>"), "XML array tag");
    assert!(!is_garbage("<dict>"), "XML dict tag");
    assert!(!is_garbage("<key>"), "XML key tag");
    assert!(!is_garbage("<string>"), "XML string tag");
    assert!(!is_garbage("<true>"), "XML true tag");
    assert!(!is_garbage("<false>"), "XML false tag");
    assert!(!is_garbage("<data>"), "XML data tag");
    assert!(!is_garbage("</array>"), "XML closing tag");
}

#[test]
fn test_invalid_xml_tags() {
    // Empty tags
    assert!(is_garbage("<>"), "Empty tag");

    // Tags with spaces or special chars
    assert!(is_garbage("<my tag>"), "Tag with space");
    assert!(is_garbage("<tag!>"), "Tag with special char");
}

// ===== Shell Command Redirection Tests =====

#[test]
fn test_shell_redirections() {
    assert!(!is_garbage("command 2>&1"), "Stderr to stdout");
    assert!(!is_garbage("ls 2>/dev/null"), "Stderr to file");
    assert!(!is_garbage("cat <<EOF"), "Heredoc");
    assert!(
        !is_garbage("echo test > output.txt"),
        "Redirect with spaces"
    );
    assert!(!is_garbage("osascript 2>&1 <<EOD"), "Combined redirects");
}

#[test]
fn test_invalid_redirections() {
    // Very short strings (2 chars) are garbage
    assert!(is_garbage("<<"), "Too short");

    // Shell redirect operators are valid even if short
    assert!(!is_garbage("2>&1"), "Redirect operator is valid");

    // Strings with shell command context are not garbage even with some non-ASCII
    // if they have enough other valid content
    let non_ascii = "cmd 2>&1 ñ";
    assert!(!is_garbage(non_ascii), "Command with redirect is valid");
}

// ===== Short String Pattern Tests =====

#[test]
fn test_short_string_patterns() {
    // All uppercase (OK)
    assert!(!is_garbage("API"), "All uppercase OK");
    assert!(!is_garbage("HTTP"), "Protocol uppercase");

    // All lowercase (OK)
    assert!(!is_garbage("foo"), "All lowercase OK");
    assert!(!is_garbage("bar"), "Short lowercase OK");

    // All digits (OK)
    assert!(!is_garbage("123"), "All digits OK");
    assert!(!is_garbage("8080"), "Port number OK");

    // Digit + uppercase ID (OK)
    assert!(!is_garbage("8BIM"), "Photoshop marker");
    assert!(!is_garbage("3DES"), "Encryption algorithm");
    assert!(!is_garbage("2FA"), "Two-factor auth");

    // PascalCase (OK)
    assert!(!is_garbage("Bool"), "PascalCase bool");
    assert!(!is_garbage("Time"), "PascalCase time");
    assert!(!is_garbage("Exif"), "PascalCase Exif");

    // Lowercase with trailing digits (OK)
    assert!(!is_garbage("amd64"), "Architecture");
    assert!(!is_garbage("utf8"), "Encoding");
    assert!(!is_garbage("sha256"), "Hash algorithm");
}

#[test]
fn test_short_garbage_patterns() {
    // Consistent case alphanumeric is now accepted (could be identifiers)
    assert!(
        !is_garbage("9N2A"),
        "Consistent uppercase with digits is valid"
    );
    // Digits at BOTH ends is garbage
    assert!(is_garbage("0YI0"), "Digits at start AND end");
    // Mixed case (upper and lower) with digits is garbage
    assert!(is_garbage("8oz1"), "Mixed case with digits");

    // `gnzUrs` shares its shape (lowercase prefix + one uppercase + lowercase)
    // with valid camelCase like `getTime` / `setLine`, so the looser
    // identifier-shape rule now keeps it. `phbS` is still 4 chars and rejected
    // because the alphanumeric arm only fires at length >= 5.
    assert!(!is_garbage("gnzUrs"), "Short camelCase-shaped mixed");
    assert!(is_garbage("phbS"), "4-char mixed case");

    // Internal whitespace (garbage)
    assert!(is_garbage("5c 9"), "Digits with space");
    assert!(is_garbage("VW N"), "Mixed with space");
}

// ===== camelCase Tests =====

#[test]
fn test_camelcase_patterns() {
    // Valid camelCase (>= 7 chars, lowercase start, one uppercase not at end)
    assert!(!is_garbage("myValue"), "camelCase myValue");
    assert!(!is_garbage("someWord"), "camelCase someWord");
    assert!(!is_garbage("firstName"), "camelCase firstName");
    assert!(!is_garbage("getUserData"), "camelCase function");
}

#[test]
fn test_short_camelcase_accepted() {
    // 5+ char camelCase identifiers are now kept — `myVal`, `getId`,
    // `iOSv2` are all valid abbreviated names that security analysts
    // care about. The 4-char floor in `looks_like_word_like` still
    // rejects 4-char mixed-case noise.
    assert!(!is_garbage("myVal"));
    assert!(!is_garbage("someworD"));
}

// ===== Filename and Section Tests =====

#[test]
fn test_filenames_with_dots() {
    assert!(!is_garbage("d.exe"), "d.exe filename");
    assert!(!is_garbage("a.out"), "a.out filename");
    assert!(!is_garbage("lib.so"), "lib.so filename");
    assert!(!is_garbage("core.dll"), "core.dll filename");
}

#[test]
fn test_section_names() {
    assert!(!is_garbage(".text"), "Text section");
    assert!(!is_garbage(".data"), "Data section");
    assert!(!is_garbage(".bss"), "BSS section");
    assert!(!is_garbage(".init"), "Init section");
    assert!(!is_garbage(".rodata"), "Read-only data");
}

#[test]
fn test_invalid_dot_patterns() {
    // Leading dot
    assert!(is_garbage("."), "Single dot");
    assert!(is_garbage(".."), "Double dot");

    // Trailing dot
    assert!(is_garbage("file."), "Trailing dot");

    // Multiple dots
    assert!(is_garbage("a..b"), "Double dot in middle");
}

// ===== Format String Tests =====

#[test]
fn test_format_strings() {
    // Short format strings with noise punctuation may be garbage
    // Longer format strings with more context are not garbage
    assert!(
        !is_garbage("Error message: %s"),
        "Format with %s and context"
    );
    assert!(
        !is_garbage("Count is: %d items"),
        "Format with %d and context"
    );
    assert!(
        !is_garbage("Value: %f seconds"),
        "Format with %f and context"
    );
    assert!(!is_garbage("Error: %s at line %d"), "Multiple format specs");
}

// ===== Path Pattern Tests =====

#[test]
fn test_path_patterns() {
    assert!(!is_garbage("/usr/lib/go"), "Unix path");
    assert!(!is_garbage("/etc/passwd"), "Config path");
    assert!(!is_garbage("C:\\Windows\\System32"), "Windows path");
    assert!(!is_garbage("/home/user/.bashrc"), "Hidden file path");
    assert!(!is_garbage("/var/log/syslog"), "Log path");
}

#[test]
fn test_invalid_paths() {
    // Too many special characters (> 30%)
    assert!(is_garbage("/!!!!/####/$$$$"), "Too many special chars");

    // Not enough alphanumeric
    assert!(is_garbage("///"), "Just slashes");

    // Note: Uppercase paths are valid (some systems use them)
    assert!(
        !is_garbage("/AAAA/BBBB/CCCC"),
        "All uppercase path is valid"
    );
}

// ===== Version String Tests =====

#[test]
fn test_version_strings() {
    assert!(!is_garbage("v1.0"), "Version v1.0");
    assert!(!is_garbage("v2.3.4"), "Version v2.3.4");
    // Note: Short versions like "V10.5" (5 chars with mixed case+digits) may be garbage
    assert!(!is_garbage("v10.5.0"), "Version with more digits");
    assert!(!is_garbage("go1.22"), "Go version");
    assert!(!is_garbage("go1.22.0"), "Full Go version");
}

// ===== Base64-like Pattern Tests =====

#[test]
fn test_base64_like_patterns() {
    // Long base64 strings (>= 16 chars, only [A-Za-z0-9+/=])
    assert!(!is_garbage("VGhpcyBpcyBhIHNlY3JldA=="), "Base64 string");
    assert!(!is_garbage("SGVsbG8gV29ybGQh"), "Base64 no padding");
    assert!(!is_garbage("YWJjZGVmZ2hpamts"), "Base64 alphabet");
}

// ===== Character Class Transition Tests =====

#[test]
fn test_low_transition_patterns() {
    // Legitimate strings with reasonable run lengths
    assert!(!is_garbage("HelloWorld"), "PascalCase compound");
    assert!(!is_garbage("test_function_name"), "Snake case");
    assert!(!is_garbage("CONSTANT_VALUE"), "Constant naming");
}

#[test]
fn test_high_transition_patterns() {
    // Pure-hex runs ≥8 chars are kept (see is_hex_id_run): they could
    // be hash fragments, build IDs, or other identifiers.
    assert!(!is_garbage("aB1cD2eF3"), "All-hex run is a valid hex id");
    assert!(!is_garbage("1a2b3c4d"), "All-hex run is a valid hex id");
    // Same chaotic shape but with non-hex letters stays garbage.
    assert!(is_garbage("1z2y3x4w"), "Non-hex chaotic alternation");
}

// ===== Whitespace Tests =====

#[test]
fn test_excessive_whitespace() {
    // Strings with whitespace are complex - only garbage if whitespace > 0 AND whitespace * 3 > len
    // AND meets other criteria. The exact threshold depends on content.
    // Strings with some alphanumeric content may pass even with lots of spaces
    // Test case where whitespace dominates with no redeeming content
    assert!(is_garbage("     "), "Only whitespace");
    assert!(is_garbage("   "), "Mostly whitespace");
}

#[test]
fn test_reasonable_whitespace() {
    // Normal sentences
    assert!(!is_garbage("Hello World"), "Normal spacing");
    assert!(!is_garbage("Error message here"), "Sentence spacing");
}

// ===== Non-ASCII Content Tests =====

#[test]
fn test_short_strings_with_non_ascii() {
    // < 30 chars with > 20% non-ASCII
    assert!(is_garbage("test€€€€"), "Short with non-ASCII");

    // < 10 chars with >= 2 non-ASCII
    assert!(is_garbage("ab€€cd"), "Very short with non-ASCII");
}

#[test]
fn test_long_strings_with_non_ascii() {
    // >= 30 chars with > 30% non-ASCII should be garbage
    let s = "test".repeat(5) + &"€".repeat(10); // 20 ASCII + 10 non-ASCII = 33% non-ASCII
    assert!(is_garbage(&s), "Long with too much non-ASCII");
}

#[test]
fn test_acceptable_non_ascii() {
    // Short strings with non-ASCII are generally filtered
    // For very short strings (< 10 chars), >= 2 non-ASCII chars triggers garbage
    // "Café" has 1 non-ASCII char but is only 4 chars, may be filtered
    // Longer strings with minimal non-ASCII may be OK
    assert!(!is_garbage("Photoshop application"), "Mostly ASCII");
}

// ===== Repeated Character Tests =====

#[test]
fn test_repeated_characters() {
    assert!(is_garbage("aaaa"), "Repeated a");
    assert!(is_garbage("1111"), "Repeated 1");
    assert!(is_garbage("!!!!"), "Repeated !");
    assert!(is_garbage("----"), "Repeated dash");
}

// ===== Alphanumeric Ratio Tests =====

#[test]
fn test_low_alphanumeric_ratio() {
    // < 30% alphanumeric for > 6 chars
    assert!(is_garbage("!!!@@@###$$$"), "All special chars");
    assert!(is_garbage("...---___|||"), "Mostly punctuation");
}

// ===== Noise Punctuation Tests =====

#[test]
fn test_short_strings_with_noise() {
    // <= 10 chars with noise punctuation
    assert!(is_garbage("abc#def"), "Short with #");
    assert!(is_garbage("test@foo"), "Short with @");
    assert!(is_garbage("bar?baz"), "Short with ?");
}

// ===== Hex-Only Pattern Tests =====

#[test]
fn test_hex_only_patterns() {
    // Note: Short hex strings are valid identifiers (not garbage)
    // Longer random hex might be, but 8-char hex strings like "deadbeef" are valid
    assert!(!is_garbage("deadbeef"), "Valid hex identifier");
    assert!(!is_garbage("cafebabe"), "Valid hex pattern");
}

#[test]
fn test_non_hex_only_ok() {
    // Has non-hex letters
    assert!(!is_garbage("testfile"), "Has 't' (non-hex)");
    assert!(!is_garbage("logging"), "Has 'g' (non-hex)");

    // Has 0x prefix
    assert!(!is_garbage("0xdeadbeef"), "Hex with 0x prefix");

    // Has dots
    assert!(!is_garbage("cafe.babe"), "Hex with dot");
}

// ===== Trailing Space Tests =====

#[test]
fn test_trailing_spaces() {
    // Ends with space, < 10 chars, < 4 alphanumeric
    assert!(is_garbage("ab "), "Short with trailing space");
    assert!(is_garbage("xyz  "), "Multiple trailing spaces");
}

// ===== Backtick Pattern Tests =====

#[test]
fn test_backtick_patterns() {
    // Backtick followed by single letter (Go misaligned reads)
    assert!(is_garbage("`L"), "Backtick + L");
    assert!(is_garbage("`M"), "Backtick + M");
    assert!(is_garbage("test`X"), "String ending with backtick + letter");
}

// ===== Unbalanced Punctuation Tests =====

#[test]
fn test_unbalanced_punctuation() {
    // <= 8 chars with unbalanced parens
    assert!(is_garbage("(abc"), "Unclosed paren");
    assert!(is_garbage("def)"), "Extra close paren");
    assert!(is_garbage("[xyz"), "Unclosed bracket");

    // Single quote
    assert!(is_garbage("test'"), "Single quote");
}

#[test]
fn test_balanced_punctuation() {
    // Short strings (<= 8 chars) with unbalanced punctuation are garbage
    // But "(abc)" has balanced parens (open=1, close=1) yet is still garbage
    // because it has quotes issue or other heuristics
    // Let's test longer strings with balanced punctuation
    assert!(
        !is_garbage("function(arg1, arg2)"),
        "Balanced parens in function"
    );
    assert!(!is_garbage("array[index]"), "Balanced brackets");
}

// ===== Medium-Length Mixed Patterns =====

#[test]
fn test_medium_mixed_case_digits() {
    // 5-10 chars with digits + uppercase + lowercase: identifier-shaped
    // alphanumeric strings (`fprzTR8`-style — a random-looking ID could
    // be a mutex name, hash prefix, or generated token) are now kept.
    // Strings with embedded punctuation (`=`, `:`) still get filtered.
    assert!(!is_garbage("fprzTR8"));
    assert!(is_garbage("J=22KJT"), "Mixed with equals");
    assert!(is_garbage("V1rN:R"), "Mixed with colon");
}

#[test]
fn test_medium_version_like() {
    // Version-like patterns are OK
    assert!(!is_garbage("go1.22"), "Go version");
    assert!(!is_garbage("v1.0.5"), "Version string");
}

// ===== Short Uppercase + Digits Tests =====

#[test]
fn test_short_upper_digits() {
    // Consistent-case alphanumeric patterns (digits + uppercase, no lowercase) are valid
    // Multi-digit leading numbers are OK (could be product codes, etc.)
    assert!(!is_garbage("55LYE"), "Multi-digit leading number is valid");

    // Single leading 0 or 1 is suspicious (real identifiers use meaningful numbers)
    assert!(is_garbage("0GZF"), "Single leading 0 is garbage");
    assert!(is_garbage("1ABC"), "Single leading 1 is garbage");

    // But multi-digit numbers starting with 0 or 1 are OK
    assert!(!is_garbage("10NET"), "Leading 10 is valid");

    // Digits at BOTH ends is garbage (like random hex)
    assert!(is_garbage("0YI0"), "Digits at both ends is garbage");
}

#[test]
fn test_valid_upper_digits() {
    // Alphanumeric identifiers with consistent case (4-8 chars) are valid
    // File signatures, algorithms, encodings, architectures
    assert!(!is_garbage("UTF8"), "encoding");
    assert!(!is_garbage("SHA1"), "algorithm");
    assert!(!is_garbage("SHA256"), "algorithm");
    assert!(!is_garbage("BASE64"), "encoding");
    assert!(!is_garbage("UTF16LE"), "encoding");
    assert!(!is_garbage("amd64"), "architecture");
    assert!(!is_garbage("arm64"), "architecture");

    // Longer identifiers with clear patterns work better
    assert!(!is_garbage("CONSTANT_VALUE"), "Longer constant name");
}

// ===== Literal Escape Sequence Tests =====

#[test]
fn test_literal_escapes_without_code_context() {
    // < 30 chars with \x, \u, \U but no code context
    // Note: "bar\\U00000041" is 15 chars and may not trigger garbage
    // Let's test shorter ones that definitely should
    assert!(is_garbage("\\x41\\x42"), "Short literal escapes");
    assert!(is_garbage("\\u0041"), "Short unicode escape");
}

#[test]
fn test_escapes_with_code_context() {
    // Has code context (quotes, parens, print, echo, const, var)
    assert!(!is_garbage("print \"\\x41\""), "print with escape");
    assert!(!is_garbage("echo '\\x48'"), "echo with escape");
    assert!(!is_garbage("const x = \"\\u0041\""), "const with escape");
    assert!(!is_garbage("var y = '\\x42'"), "var with escape");
}

// ===== Edge Cases =====

#[test]
fn test_empty_and_whitespace() {
    assert!(is_garbage(""), "Empty string");
    assert!(is_garbage(" "), "Single space");
    assert!(is_garbage("   "), "Multiple spaces");
    assert!(is_garbage("\t"), "Tab");
    assert!(is_garbage("\n"), "Newline");
}

#[test]
fn test_control_characters() {
    assert!(is_garbage("ab\x00cd"), "Null byte");
    assert!(is_garbage("\x01\x02\x03"), "Control chars");
    assert!(is_garbage("test\x07"), "Bell char");
}

#[test]
fn test_trailing_newline_exception() {
    // Trailing newline should NOT trigger control char detection
    assert!(!is_garbage("hello world\n"), "Trailing newline OK");
    assert!(!is_garbage("test\n"), "Short with newline OK");
}

// ===== Special Obfuscation Patterns =====

#[test]
fn test_obfuscated_javascript_hex_identifiers() {
    assert!(
        !is_garbage("const _0x1c1000=_0x230d;"),
        "Hex identifier const"
    );
    assert!(
        !is_garbage("function _0x230d(_0x996a22)"),
        "Hex identifier function"
    );
    assert!(
        !is_garbage("_0x4a5b['base64']"),
        "Hex identifier array access"
    );
}

#[test]
fn test_obfuscated_python_mangled_identifiers() {
    assert!(
        !is_garbage("def llIIlIlllllIIlllII(arg):"),
        "Python mangled def"
    );
    assert!(
        !is_garbage("return lIlIlIlIIIlIllllll(arg)"),
        "Python mangled return"
    );
}

// ===== API Keys and Secrets =====

#[test]
fn test_api_key_formats() {
    assert!(!is_garbage("AKIA0123456789ABCDEF"), "AWS access key");
    assert!(
        !is_garbage("ghp_0123456789abcdefghijklmnopqrstuv"),
        "GitHub token"
    );
    assert!(
        !is_garbage("sk_live_0123456789abcdefghijklmn"),
        "Stripe key"
    );
    assert!(
        !is_garbage("xoxb-1234567890-1234567890-abcdefghijklmnop"),
        "Slack token"
    );
}

// ===== SQL and XSS Patterns =====

#[test]
fn test_sql_injection_patterns() {
    assert!(!is_garbage("' OR '1'='1"), "SQL injection OR");
    assert!(!is_garbage("admin'--"), "SQL comment injection");
    assert!(!is_garbage("1' UNION SELECT NULL--"), "SQL union");
}

#[test]
fn test_xss_patterns() {
    assert!(!is_garbage("<script>alert(1)</script>"), "XSS script");
    assert!(!is_garbage("<img src=x onerror=alert(1)>"), "XSS img");
    assert!(
        !is_garbage("javascript:alert(1)"),
        "XSS javascript protocol"
    );
}

// ===== Windows Patterns =====

#[test]
fn test_windows_registry_paths() {
    assert!(
        !is_garbage("HKLM\\SOFTWARE\\Microsoft\\Windows"),
        "Registry HKLM"
    );
    assert!(!is_garbage("HKCU\\Software\\Classes"), "Registry HKCU");
}

#[test]
fn test_windows_mutexes() {
    assert!(!is_garbage("Global\\MutexName"), "Windows global mutex");
    // Note: GUIDs with braces have special chars and may be flagged
    // Full GUID format is more recognizable
    assert!(
        !is_garbage("{8F6F0AC4-B9A1-45fd-A8CF-72997C3991B9}"),
        "Full GUID"
    );
}

// ===== Cryptocurrency Patterns =====

#[test]
fn test_mining_pool_patterns() {
    assert!(!is_garbage("pool.minexmr.com:4444"), "Mining pool");
    assert!(!is_garbage("stratum+tcp://pool.com:3333"), "Stratum URL");
    assert!(!is_garbage("xmr-eu1.nanopool.org:14444"), "Nanopool");
}

#[test]
fn test_miner_commands() {
    assert!(!is_garbage("xmrig"), "XMRig miner");
    assert!(!is_garbage("--donate-level=1"), "Miner flag");
    assert!(!is_garbage("--algo=cryptonight"), "Mining algo");
}

// ===== Tor/Onion Patterns =====

#[test]
fn test_onion_addresses() {
    assert!(!is_garbage("http://example.onion"), "Onion HTTP");
    assert!(!is_garbage("https://3g2upl4pq6kufc4m.onion"), "Onion HTTPS");
    assert!(!is_garbage("ransomware2x4ytmz.onion"), "Onion domain");
}

// ===== CTF Flag Patterns =====

#[test]
fn test_ctf_flags() {
    assert!(!is_garbage("CTF{th1s_1s_4_fl4g}"), "CTF flag");
    assert!(!is_garbage("flag{secret}"), "flag format");
    assert!(!is_garbage("picoCTF{pwn3d}"), "picoCTF");
    assert!(!is_garbage("HTB{h4ck_th3_b0x}"), "HackTheBox");
}

// ===== PEM/JWT Patterns =====

#[test]
fn test_pem_headers() {
    assert!(!is_garbage("-----BEGIN PUBLIC KEY-----"), "PEM begin");
    assert!(!is_garbage("-----END PRIVATE KEY-----"), "PEM end");
    assert!(
        !is_garbage("-----BEGIN CERTIFICATE-----"),
        "Certificate begin"
    );
}

#[test]
fn test_jwt_tokens() {
    // Standalone header (base64url, not a full JWT) — kept by the base64 classifier.
    assert!(
        !is_garbage("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"),
        "JWT header"
    );

    // RFC 7519 example: HS256 "Joe" token.
    assert!(
        !is_garbage(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        ),
        "full HS256 JWT"
    );

    // RS256 JWT (longer signature segment, all base64url).
    assert!(
        !is_garbage(
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuYXV0aDAuY29tLyIsInN1YiI6ImF1dGgwfDEyMzQ1Njc4OTAiLCJhdWQiOiJodHRwczovL2FwaS5leGFtcGxlLmNvbS8iLCJleHAiOjE2NDE2NzgwMDB9.abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        ),
        "RS256 JWT"
    );

    // Hyphens and underscores (base64url without padding).
    assert!(
        !is_garbage(
            "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWxpY2UtYm9iX3VzZXIifQ.xK-n_2aBcDeFgHiJkLmNoPqRsTuVwXyZ01234abc"
        ),
        "JWT with base64url dashes/underscores"
    );

    // Negatives: three-dot identifiers that are NOT JWTs must still classify.
    // (These may be kept or dropped, but they must not be mis-labelled as JWTs —
    // we assert no crash and some determinate behaviour.)
    let _ = is_garbage("foo.bar.baz");
    let _ = is_garbage("pkg.sub.Module");
}

// ===== Telegram Bot Tokens =====

#[test]
fn test_telegram_bot_tokens() {
    // Real shape observed in DPRK Teams sample (2026-04).
    assert!(
        !is_garbage("8520232238:AAF6xeNiv-OKpAPrnRmv7AsjmJAmkRjf0I4"),
        "DPRK Teams Telegram bot token"
    );

    // Classic 10-digit bot_id + 35-char body (docs example shape).
    assert!(
        !is_garbage("110201543:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw"),
        "canonical Telegram bot token"
    );

    // With underscores in body.
    assert!(
        !is_garbage("6789012345:ABC_def123GHI_jklMNO-pqrSTU_vwxYZ01"),
        "Telegram token with underscores"
    );

    // Short bot_id (8 digits) — still in spec.
    assert!(
        !is_garbage("12345678:AAF6xeNiv-OKpAPrnRmv7AsjmJAmkRjf0I4"),
        "Telegram token with 8-digit bot id"
    );
}

// Predicate-level negatives (malformed tokens the Telegram rule must not
// whitelist) live in src/validation.rs — is_telegram_bot_token is private,
// and is_garbage can still pass these via unrelated rules
// (path/url/domain shape), so asserting on is_garbage here would be noise.

// ===== Swift Mangled Symbols =====

#[test]
fn test_swift_mangled_symbols() {
    // _Tt-prefix (Swift 1-3 class metadata) — the kind that was dropped before.
    assert!(
        !is_garbage("_TtC7TeamAppP33_464D6157E8D96D7B7ECE5C61C5669F7019ResourceBundleClass"),
        "Swift _TtC class mangling (DPRK Teams sample)"
    );
    assert!(
        !is_garbage("_TtP10Foundation10CodingKey_"),
        "Swift _TtP protocol mangling"
    );

    // Swift 5 stable ABI ($s / _$s prefix).
    assert!(
        !is_garbage("_$sSo17OS_dispatch_queueC8DispatchE4mainABvgZ"),
        "Swift 5 _$s dispatch queue accessor"
    );
    assert!(
        !is_garbage("$s10Foundation4DataV5bytesAC10ByteBufferVyXlSgvg"),
        "Swift 5 $s mangled accessor"
    );

    // Swift 4 ABI (_T0).
    assert!(
        !is_garbage("_T010Foundation4DataVMa"),
        "Swift 4 _T0 mangling"
    );
}

// Predicate-level negatives (non-Swift `_T…` ids, `_TtC` with a path
// separator, etc.) live in src/validation.rs — is_swift_mangled_symbol is
// private, and is_garbage can still pass these via path/identifier rules,
// so the whole-pipeline assertion would be meaningless.

// ===== Ransom Note Patterns =====

#[test]
fn test_ransom_patterns() {
    assert!(
        !is_garbage("YOUR FILES HAVE BEEN ENCRYPTED"),
        "Ransom message"
    );
    assert!(!is_garbage("Send $500 in Bitcoin to"), "Ransom demand");
    assert!(!is_garbage("DECRYPT-INSTRUCTIONS.txt"), "Decrypt filename");
}

// ===== LDAP Patterns =====

#[test]
fn test_ldap_paths() {
    assert!(!is_garbage("LDAP://CN=Users,DC=domain,DC=com"), "LDAP path");
    assert!(!is_garbage("CN=Administrator,CN=Users"), "AD DN");
}

// ===== Ransomware Extensions =====

#[test]
fn test_ransomware_extensions() {
    assert!(!is_garbage(".locked"), "Locked extension");
    assert!(!is_garbage(".encrypted"), "Encrypted extension");
    assert!(!is_garbage(".wannacry"), "WannaCry extension");
    assert!(!is_garbage(".ryuk"), "Ryuk extension");
}
