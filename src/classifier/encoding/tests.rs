use super::*;
use crate::classifier::classify_string;
use crate::types::StringKind;

#[test]
fn recognizes_hex_encoded_text() {
    // Valid hex-encoded strings (from actual malware samples)
    // "const _0x1c31000=_0x2330d;"
    assert!(is_hex_encoded(
        "636F6E7374205F307831633331303030333D5F3078323330643B"
    ));

    // "function _0x2330d(_0x99a22,_0x58a56){"
    assert!(is_hex_encoded(
        "66756E6374696F6E205F307832333064285F3078393961322C5F30783538613536297B"
    ));

    // "Mozilla/5.0 (Windows NT 10.0; Win64)"
    assert!(is_hex_encoded(
        "4D6F7A696C6C612F352E30202857696E646F7773204E542031302E303B2057696E3634"
    ));

    // Long hex string with spaces
    assert!(is_hex_encoded(
        "48656C6C6F20576F726C642120546869732069732061207465737420737472696E67"
    ));
}

#[test]
fn rejects_short_odd_binary_or_hash_hex() {
    // Too short
    assert!(!is_hex_encoded("48656C6C6F"));

    // Odd length (51 chars)
    assert!(!is_hex_encoded(
        "48656C6C6F20576F726C6421205468697320697320612074657"
    ));

    // Not hex (contains 'G')
    assert!(!is_hex_encoded(
        "48656C6C6F20576F726C6421205468697320697320612074657374G1"
    ));

    // Valid hex but decodes to mostly non-printable
    assert!(!is_hex_encoded(
        "00010203040506070809FF00010203040506070809FF00010203040506070809FF"
    ));

    // All zeros
    assert!(!is_hex_encoded(
        "00000000000000000000000000000000000000000000000000000000"
    ));

    // Real SHA256 hash (should not be detected as hex-encoded text)
    assert!(!is_hex_encoded(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ));
}

#[test]
fn classifies_guids() {
    // Braced COM GUID
    assert_eq!(
        classify_string("{550e8400-e29b-41d4-a716-446655440000}"),
        Some(StringKind::Guid)
    );
    // Bare canonical UUID (RFC 4122 / Mythic payload_uuid)
    assert_eq!(
        classify_string("88a39a12-f279-4bb2-b102-1ee1157ad859"),
        Some(StringKind::Guid)
    );
    assert_eq!(
        classify_string("550e8400-e29b-41d4-a716-446655440000"),
        Some(StringKind::Guid)
    );
    // Uppercase
    assert_eq!(
        classify_string("88A39A12-F279-4BB2-B102-1EE1157AD859"),
        Some(StringKind::Guid)
    );
    // Wrong shape — not classified as GUID
    assert_ne!(
        classify_string("88a39a12f2794bb2b1021ee1157ad859"),
        Some(StringKind::Guid)
    );
    assert_ne!(
        classify_string("88a39a12-f279-4bb2-b102"),
        Some(StringKind::Guid)
    );
}

#[test]
fn classifies_hex_encoded_text() {
    // Hex-encoded JavaScript (from actual malware)
    assert_eq!(
        classify_string("636F6E7374205F307831633331303030333D5F3078323330643B"),
        Some(StringKind::HexEncoded)
    );

    // Hex-encoded function
    assert_eq!(
        classify_string("66756E6374696F6E205F307832333064285F3078393961322C5F30783538613536297B"),
        Some(StringKind::HexEncoded)
    );

    // Should not be hex-encoded (too short)
    assert_ne!(classify_string("48656C6C6F"), Some(StringKind::HexEncoded));

    // Should not be hex-encoded (odd length)
    assert_ne!(
        classify_string("48656C6C6F20576F726C642120546869732069732061207465737420737472696E6"),
        Some(StringKind::HexEncoded)
    );
}

#[test]
fn decodes_hex_pairs_to_text() {
    let hex = "48656C6C6F20576F726C64";
    assert_eq!(classify_string(hex), Some(StringKind::HexEncoded));
    let input = crate::ExtractedString::new(hex, 0, crate::StringMethod::RawScan);
    let decoded: Vec<_> = crate::decoders::decode_hex_strings(&[input])
        .into_iter()
        .map(|s| (s.value, s.method))
        .collect();
    assert_eq!(
        decoded,
        [("Hello World".to_string(), crate::StringMethod::HexDecode)]
    );
}

#[test]
fn recognizes_escaped_text() {
    // Valid \xXX format (from actual malware)
    assert!(is_unicode_escaped(
        "\\x27;\\x20const\\x20fs\\x20=\\x20require(\\x27fs\\x27);"
    ));

    // Mixed \xXX and regular text
    assert!(is_unicode_escaped(
        "\\x48\\x65\\x6c\\x6c\\x6f\\x20\\x57\\x6f\\x72\\x6c\\x64"
    ));

    // \uXXXX format
    assert!(is_unicode_escaped("\\u0048\\u0065\\u006c\\u006c\\u006f"));

    // Mixed format
    assert!(is_unicode_escaped(
        "const\\x20url\\x20=\\x20\\x27https://example.com\\x27;"
    ));
}

#[test]
fn rejects_sparse_or_malformed_escapes() {
    // Too short
    assert!(!is_unicode_escaped("\\x48\\x65"));

    // Too few escape sequences
    assert!(!is_unicode_escaped("Hello \\x20 World"));

    // Not actually escaped
    assert!(!is_unicode_escaped("const url = 'https://example.com';"));

    // Invalid escape sequences
    assert!(!is_unicode_escaped("\\x\\x\\x\\x\\x\\x\\x\\x"));
}

#[test]
fn classifies_escaped_text() {
    // JavaScript with \xXX escapes (from actual malware)
    assert_eq!(
        classify_string("\\x27;\\x20const\\x20fs\\x20=\\x20require(\\x27fs\\x27);"),
        Some(StringKind::UnicodeEscaped)
    );

    // \uXXXX format
    assert_eq!(
        classify_string("\\u0048\\u0065\\u006c\\u006c\\u006f"),
        Some(StringKind::UnicodeEscaped)
    );

    // Should not be Unicode escaped (too few sequences)
    assert_ne!(
        classify_string("Hello \\x20 World"),
        Some(StringKind::UnicodeEscaped)
    );
}

#[test]
fn unescapes_hex_and_unicode_escapes() {
    // Test \xXX format
    let decoded = unescape_to_bytes("\\x48\\x65\\x6c\\x6c\\x6f");
    let text = String::from_utf8(decoded).unwrap();
    assert_eq!(text, "Hello");

    // Test \uXXXX format
    let decoded = unescape_to_bytes("\\u0048\\u0065\\u006c\\u006c\\u006f");
    let text = String::from_utf8(decoded).unwrap();
    assert_eq!(text, "Hello");

    // Test mixed content
    let decoded = unescape_to_bytes("const\\x20fs\\x20=\\x20require");
    let text = String::from_utf8(decoded).unwrap();
    assert_eq!(text, "const fs = require");

    // Test actual malware pattern
    let decoded = unescape_to_bytes("\\x27;\\x20const\\x20fs\\x20=\\x20require(\\x27fs\\x27);");
    let text = String::from_utf8(decoded).unwrap();
    assert_eq!(text, "'; const fs = require('fs');");
}

#[test]
fn recognizes_url_encoded_payloads() {
    // Valid URL-encoded strings (from web shells)
    assert!(is_url_encoded(
        "%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E"
    ));

    // SQL injection payload
    assert!(is_url_encoded("%27%20OR%20%271%27%3D%271"));

    // Command injection
    assert!(is_url_encoded("%3Bcat%20%2Fetc%2Fpasswd"));

    // Mixed with plus signs and multiple encoded chars
    assert!(is_url_encoded("param1%3Dvalue1%26param2%3Dvalue2"));
}

#[test]
fn rejects_printf_and_sparse_percent_strings() {
    // Too short
    assert!(!is_url_encoded("%48%65"));

    // Too few percent signs (only 1)
    assert!(!is_url_encoded("Hello%20World"));

    // Not actually URL encoded (no percent signs)
    assert!(!is_url_encoded("regular text with some words"));

    // Has percent but not valid encoding (non-hex after %)
    assert!(!is_url_encoded("100% complete status check"));

    // C format strings should NOT be detected as URL encoded
    // %02d has hex digits (0, 2) but it's a printf specifier, not URL encoding
    assert!(!is_url_encoded("%d%02d%02d %02d:%02d:%02d"));
    assert!(!is_url_encoded("%d%02d%02dd%02d:%02d:%02d"));
    assert!(!is_url_encoded("Time: %02d:%02d:%02d Date: %04d-%02d-%02d"));
    assert!(!is_url_encoded("%s %d %f %x %o %p %c"));
    assert!(!is_url_encoded("Error code: %d, message: %s"));
    assert!(!is_url_encoded("%ld %lld %zu %zd"));
    assert!(!is_url_encoded("%-10s %+5d %#08x"));
}

#[test]
fn classifies_url_encoded_payloads() {
    // XSS payload
    assert_eq!(
        classify_string("%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E"),
        Some(StringKind::UrlEncoded)
    );

    // SQL injection
    assert_eq!(
        classify_string("%27%20OR%20%271%27%3D%271"),
        Some(StringKind::UrlEncoded)
    );

    // Should not be URL encoded (too few percent signs)
    assert_ne!(
        classify_string("Hello%20World"),
        Some(StringKind::UrlEncoded)
    );
}

#[test]
fn percent_decodes_payloads() {
    // Test basic decoding
    let decoded = decode_url_encoding("%48%65%6c%6c%6f");
    let text = String::from_utf8(decoded).unwrap();
    assert_eq!(text, "Hello");

    // A plus stays a plus, as in every other stng percent-decoder.
    let decoded = decode_url_encoding("Hello+World%21");
    let text = String::from_utf8(decoded).unwrap();
    assert_eq!(text, "Hello+World!");

    // Test XSS payload
    let decoded = decode_url_encoding("%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E");
    let text = String::from_utf8(decoded).unwrap();
    assert_eq!(text, "<script>alert('XSS')</script>");

    // Test SQL injection
    let decoded = decode_url_encoding("%27%20OR%20%271%27%3D%271");
    let text = String::from_utf8(decoded).unwrap();
    assert_eq!(text, "' OR '1'='1");

    // Test command injection
    let decoded = decode_url_encoding("%3Bcat%20%2Fetc%2Fpasswd");
    let text = String::from_utf8(decoded).unwrap();
    assert_eq!(text, ";cat /etc/passwd");
}

#[test]
fn recognizes_base32() {
    // Tor v2 onion address (Base32)
    assert!(is_base32("THEHIDDENWIKI3IKNKD7A"));

    // Generic Base32 encoded data
    assert!(is_base32("JBSWY3DPEBLW64TMMQ======"));
    assert!(is_base32("NFXGO2LUNBQXIIDUNBSSA"));

    // Without padding
    assert!(is_base32("MFRGG3DFMZTWQ2LK"));
}

#[test]
fn rejects_non_base32() {
    // Too short
    assert!(!is_base32("ABCD"));

    // Contains lowercase (not valid Base32)
    assert!(!is_base32("JbSwY3DpEbLw64TmMq"));

    // Contains 0, 1, 8, 9 (not valid Base32)
    assert!(!is_base32("JBSWY3DPEBLW01089"));

    // Plain text (all letters, no digits)
    assert!(!is_base32("THISISPLAINTEXT"));

    // All digits (no letters)
    assert!(!is_base32("2345672345672345"));
}

#[test]
fn classifies_base32() {
    // Tor onion address
    assert_eq!(
        classify_string("THEHIDDENWIKI3IKNKD7A"),
        Some(StringKind::Base32)
    );

    // With padding
    assert_eq!(
        classify_string("JBSWY3DPEBLW64TMMQ======"),
        Some(StringKind::Base32)
    );

    // Should not be Base32 (has lowercase)
    assert_ne!(
        classify_string("JbSwY3DpEbLw64TmMq"),
        Some(StringKind::Base32)
    );
}

#[test]
fn recognizes_base58_wallet_addresses() {
    // Bitcoin P2PKH address (starts with 1)
    assert!(is_base58("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"));

    // Bitcoin P2SH address (starts with 3)
    assert!(is_base58("3J98t1WpEZ73CNmYviecrnyiWrnqRhWNLy"));

    // Bitcoin mainnet address
    assert!(is_base58("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"));

    // Litecoin address (starts with L)
    assert!(is_base58("LdP8Qox1VAhCzLJNqrr74YovaWYyNBUWvL"));

    // Monero address fragment (for testing, partial)
    assert!(is_base58("4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfpAV"));

    // Generic Base58 with good entropy
    assert!(is_base58(
        "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
    ));
}

#[test]
fn base58_rejects_excluded_alphabet_chars() {
    // Too short
    assert!(!is_base58("1A1zP1eP5Q"));
    assert!(!is_base58("short"));

    // Contains 0 (zero) - not in Base58 alphabet
    assert!(!is_base58("1A1zP1eP5QGefi2DMP0fTL5SLmv7DivfNa"));
    assert!(!is_base58("10000000000000000000"));

    // Contains O (capital O) - not in Base58 alphabet
    assert!(!is_base58("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfOa"));
    assert!(!is_base58("OOOOOOOOOOOOOOOOOOOO"));

    // Contains I (capital I) - not in Base58 alphabet
    assert!(!is_base58("1A1zP1eP5QGefi2DMPIfTL5SLmv7DivfNa"));
    assert!(!is_base58("IIIIIIIIIIIIIIIIIIII"));

    // Contains l (lowercase L) - not in Base58 alphabet
    assert!(!is_base58("1A1zP1eP5QGefi2DMPlTL5SLmv7DivfNa"));
    assert!(!is_base58("llllllllllllllllllll"));

    // Mixed invalid characters
    assert!(!is_base58("1A1zP1eP5QGefi2DMP0IfTL5SLmv7DivfOa"));
}

#[test]
fn base58_requires_upper_lower_and_digits() {
    // All uppercase (no lowercase or digits)
    assert!(!is_base58("ABCDEFGHJKMNPQRSTUVWXYZ"));
    assert!(!is_base58("THEQUICKBRWNFXJUMPS"));

    // All lowercase (no uppercase or digits)
    assert!(!is_base58("abcdefghjkmnpqrstuvwxyz"));
    assert!(!is_base58("thequickbrwnfxjumps"));

    // All digits (no letters)
    assert!(!is_base58("12345678912345678912"));

    // Only uppercase + digits (missing lowercase)
    assert!(!is_base58("ABC123DEF456GHJ789MN"));

    // Only lowercase + digits (missing uppercase)
    assert!(!is_base58("abc123def456ghj789mn"));

    // Only uppercase + lowercase (missing digits)
    assert!(!is_base58("ABCdefGHJmnpQRStuv"));
}

#[test]
fn base58_rejects_objc_class_names() {
    // Objective-C class names (NS prefix with CamelCase)
    assert!(!is_base58("NSKnownKeysMappingStrategy1"));
    assert!(!is_base58("NSKnownKeysDictionary1"));
    assert!(!is_base58("NSMutableAttributedString1"));
    assert!(!is_base58("NSURLSessionConfiguration1"));
    assert!(!is_base58("NSUserNotificationCenter1"));

    // iOS/macOS classes (UI/CA/CG prefixes)
    assert!(!is_base58("UIViewControllerTransition1"));
    assert!(!is_base58("CABasicAnimationDelegate1"));
    assert!(!is_base58("CGAffineTransformMakeScale1"));
}

#[test]
fn base58_rejects_acronym_prefixed_class_names() {
    // Java/C# class names (XML, HTTP, SQL prefixes)
    assert!(!is_base58("XMLHttpRequestFactory1"));
    assert!(!is_base58("HTTPConnectionManager1"));
    assert!(!is_base58("SQLDatabaseConnectionPool1"));
}

#[test]
fn base58_rejects_camel_case_text() {
    // Plain English text with many CamelCase transitions (7+)
    assert!(!is_base58("TheQuickBrownFoxJumpsOverTheLazyDog1"));
    assert!(!is_base58(
        "ThisIsAVeryLongStringWithManyCamelCaseWordsForTesting1"
    ));

    // Code-like text with many transitions
    assert!(!is_base58("thisIsAVariableNameWithManyWordsInCamelCase1"));
}

#[test]
fn base58_accepts_random_mixes() {
    // Random-looking Base58 with numbers at start (like Bitcoin addresses)
    assert!(is_base58("1Qqwerty2Asdfgh3Zxcvbn4Mjkuyt5Pqazwsx"));

    // Base58 with high entropy (random mix)
    assert!(is_base58("5Km2kuu7vtFDPpxywn4u3NLpbr5jKpTB3TXKWTNFyqn"));

    // One CamelCase transition is OK (not a class name pattern)
    assert!(is_base58("1234567aBcdefghJkmnpqrstuvwxyz"));

    // Starts with single uppercase (not multi-char prefix)
    assert!(is_base58("A1bcdefgh2Jkmnpqrs3tuvwxyz4"));
}

#[test]
fn base58_accepts_few_camel_transitions() {
    // Two uppercase at start but only 1 CamelCase transition = OK
    // (not enough transitions to be a class name)
    assert!(is_base58("AB1cdefgh2Jkmnpqrs3tuvwxyz4"));

    // Three CamelCase transitions but starts lowercase = OK
    // (class names typically start with uppercase)
    assert!(is_base58("a1BcD2eFg3HjK4mnp5qrs6tuv7wxyz8"));
}

#[test]
fn base58_rejects_go_identifiers() {
    // Go package/type names containing http2/grpc/proto keywords
    assert!(!is_base58("http2ConnectionError"));
    assert!(!is_base58("http2writeResHeaders"));
    assert!(!is_base58("grpcServerConnection1234"));
    assert!(!is_base58("protoMessageDescriptor1234"));
}

#[test]
fn classifies_bitcoin_address_as_crypto_wallet() {
    // Bitcoin address - now classified as CryptoWallet (more specific than Base58)
    assert_eq!(
        classify_string("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
        Some(StringKind::CryptoWallet)
    );

    // Should not be Base58/CryptoWallet (contains 0, which is invalid in Base58)
    assert_ne!(
        classify_string("1A1zP1eP5QGefi2DMP0fTL5SLmv7DivfNa"),
        Some(StringKind::Base58)
    );
    assert_ne!(
        classify_string("1A1zP1eP5QGefi2DMP0fTL5SLmv7DivfNa"),
        Some(StringKind::CryptoWallet)
    );
}

#[test]
fn recognizes_base64() {
    // Valid base64 strings
    assert!(is_base64("SGVsbG8gV29ybGQhCg=="));
    assert!(is_base64(
        "VGhpcyBpcyBhIHNlY3JldCBtZXNzYWdlIGZvciB0ZXN0aW5n"
    ));
    assert!(is_base64(
        "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkw"
    ));
}

#[test]
fn rejects_non_base64() {
    // Too short
    assert!(!is_base64("SGVsbG8="));

    // Not multiple of 4
    assert!(!is_base64("SGVsbG8gV29ybGQhCg"));

    // Contains spaces
    assert!(!is_base64("SGVs bG8g V29y bGQh Cg=="));

    // Sequential patterns (test data)
    assert!(!is_base64("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"));

    // Plain text patterns
    assert!(!is_base64("the quick brown fox ===="));

    // Missing mixed case
    assert!(!is_base64("AAAAAAAAAAAAAAAAAAAA")); // all uppercase
    assert!(!is_base64("aaaaaaaaaaaaaaaaaaaaaa==")); // all lowercase
    assert!(!is_base64("1234567890123456789012345678")); // all digits

    // Invalid characters
    assert!(!is_base64("SGVsbG8gV29ybGQh@g==")); // @ is not valid
}

#[test]
fn base64_rejects_go_identifiers() {
    // Go package/type names containing http2/grpc/proto
    assert!(!is_base64("http2Request1234AbCd")); // http2 keyword
    assert!(!is_base64("grpcConnection12345A")); // grpc keyword
    assert!(!is_base64("protoMessage1234AbCd")); // proto keyword
}

#[test]
fn base64_rejects_framework_prefixes() {
    // 4+ consecutive uppercase at start (HTTP*, POST*, NSUR*, XML*)
    assert!(!is_base64("HTTPConnection12345A")); // 4 consecutive upper
    assert!(!is_base64("POSTRequest123456AbC")); // 4 consecutive upper
    assert!(!is_base64("NSURLSession12345AbC")); // 4 consecutive upper (NSUR)
    assert!(!is_base64("XMLParserDelegate123")); // 4 consecutive upper (XMLP)
}

#[test]
fn base64_rejects_asn1_timestamps() {
    // ASN.1 certificate timestamps (UTCTime/GeneralizedTime + next field)
    // e.g. "201229235959Z0b1" = "20121229235959Z" + ASN.1 tag "0b1"
    assert!(!is_base64("201229235959Z0b1"));
    assert!(!is_base64("310111235959Z0w1"));
}

#[test]
fn base64_rejects_x86_jump_bytes() {
    // x86 conditional jump patterns: Ht (test+jz) and HH sequences
    // These have high character repetition but decode to non-printable garbage
    assert!(!is_base64("rtVHHtRHt2HtLHHu"));
}

#[test]
fn base64_accepts_accidental_camel_case() {
    // Valid base64 should pass regardless of CamelCase patterns
    assert!(is_base64("SGVsbG8gV29ybGQhCg==")); // "Hello World!\n"
    assert!(is_base64(
        "VGhpcyBpcyBhIHNlY3JldCBtZXNzYWdlIGZvciB0ZXN0aW5n"
    )); // Long
    assert!(is_base64(
        "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkw"
    )); // alphabet

    // Base64 with many accidental CamelCase transitions should still pass
    assert!(is_base64("aB3cD5eF7gH9iJ1kL2mN4oP6qR8sT0uV")); // Random patterns
    assert!(is_base64("Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv")); // Random patterns
}

#[test]
fn base64_rejects_four_leading_capitals() {
    // Borderline: 3 consecutive uppercase at start (should accept, threshold is 4)
    assert!(is_base64("SGVsbG8gV29ybGQhCg==")); // Valid base64: "Hello World!\n"
    assert!(is_base64("ABCdefGHIjklMNOpqrSTUvwxYZ123456")); // 3 upper at start (ABC)

    // Borderline: Exactly 4 consecutive uppercase (should reject)
    assert!(!is_base64("ABCDefGHIjklMNOpqrSTUvwxYZ123456")); // 4 upper at start (ABCD)
}

#[test]
fn rejects_non_base85() {
    // Too short
    assert!(!is_base85("9jqo^BlbD"));

    // Environment variable pattern (all uppercase + underscores)
    assert!(!is_base85("DYLD_INSERT_LIBRARIES"));
    assert!(!is_base85("LD_PRELOAD_PATH_VAR"));

    // No lowercase or punctuation (just uppercase)
    assert!(!is_base85("ABCDEFGHIJKLMNOPQRST"));

    // Poor character diversity (< 8 unique chars)
    assert!(!is_base85("!!!!!!!!!!!!!!!!!!!!!"));
    assert!(!is_base85("aaaaaaaaaaaaaaaaaaaaaa"));

    // Too few valid ASCII85 characters (< 90%)
    assert!(!is_base85("regular text with spaces here"));

    // Passwd entries should NOT be classified as base85
    assert!(!is_base85(
        "_datadetectors:*:257:257:DataDetectors:/var/db/datadetectors:/usr/bin/false"
    ));
    assert!(!is_base85(
        "_mmaintenanced:*:283:283:mmaintenanced:/var/db/mmaintenanced:/usr/bin/false"
    ));
    assert!(!is_base85(
        "_biome:*:289:289:Biome:/var/db/biome:/usr/bin/false"
    ));
    assert!(!is_base85(
        "_terminusd:*:295:295:Terminus:/var/db/terminus:/usr/bin/false"
    ));
    assert!(!is_base85(
        "_nsurlsessiond:*:242:242:NSURLSession Daemon:/var/db/nsurlsessiond:/usr/bin/false"
    ));
}

#[test]
fn base32_rejects_single_class_or_bad_chars() {
    // All valid base32 chars but no digits - should fail
    assert!(!is_base32("AAAABBBBCCCCDDDD"));

    // All digits but no letters - should fail
    assert!(!is_base32("2222333344445555"));

    // Contains invalid digits (0, 1, 8, 9)
    assert!(!is_base32("ABCD0123EFGH89IJ"));

    // Contains lowercase
    assert!(!is_base32("ABCDEFGHabcdefgh"));
}

#[test]
fn base58_rejects_missing_classes_and_excluded_chars() {
    // Missing uppercase
    assert!(!is_base58("abcdefghijklmnopqrstuvwxyz123456"));

    // Missing lowercase
    assert!(!is_base58("ABCDEFGHJKMNPQRSTUVWXYZ123456"));

    // Missing digits
    assert!(!is_base58("ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz"));

    // Contains excluded characters (0, O, I, l)
    assert!(!is_base58("1A1zP1eP5QGefi2DMP0fTL5SLmv7DivfNa")); // has 0
    assert!(!is_base58("1A1zP1eP5QGefi2DMPOfTL5SLmv7DivfNa")); // has O
    assert!(!is_base58("1A1zP1eP5QGefi2DMPIfTL5SLmv7DivfNa")); // has I
    assert!(!is_base58("1A1zP1eP5QGefi2DMPlfTL5SLmv7DivfNa")); // has l
}

#[test]
fn base64_rejects_early_invalid_char() {
    // This test ensures the optimization works - it should reject quickly
    // on first invalid character without scanning the whole string
    let invalid_at_start = format!("@{}", "A".repeat(100));
    assert!(!is_base64(&invalid_at_start));

    let with_space = "SGVs bG8g".repeat(10);
    assert!(!is_base64(&with_space));
}
