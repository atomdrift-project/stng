![stng](media/logo-small.png)

**stng** — modern string extraction for binary malware analysis. Extract indicators, hardcoded credentials, C2 addresses, and obfuscated strings from any binary.

## Screenshot

Demonstrating the automatic XOR-decoding capabilities on a malware sample (macOS/machO):
![screenshot](media/screenshot.png)

## Installation

Requires a modern version of rust & cargo:

```bash
cargo install --git https://codeberg.org/HEXXDECIMAL/stng
```

## Quick Start

```bash
stng malware.bin              # Full analysis with XOR auto-detection
stng -i malware.bin           # Show interesting strings
stng --json malware.bin       # Machine-readable output with encoding metadata
```

## Features

- **Garbage filtering**: Filters out unusable garbage by default (but supports `--unfiltered`)
- **Language-aware extraction**: Go/Rust `{ptr, len}`, DWARF stack strings
- **Binary network structures**: Finds hardcoded IPs/ports in socket structures
- **XOR obfuscation**: Single/multi-byte keys with entropy analysis, double-layer (encoding+XOR)
- **Encoding detection**: Base64, Base32, Base85, hex, URL-encoding, Unicode escapes
- **IOC classification**: IPs, URLs, shell commands, paths, credentials
- **Wide strings**: UTF-16LE in Windows PE binaries
- **Format support**: ELF, PE, Mach-O, raw binaries, overlays

## Use Cases

Initial triage of a binary for "what the hell does this program do?". Things it helps with in particularl:

- **C2 enumeration**: Extract hardcoded callbacks, encryption keys, beacon URLs
- **Credential/evasion analysis**: Database passwords, API keys, XOR'd strings, packed payloads
- **YARA acceleration**: Find strings for signature development

## Library

```rust
let strings = stng::extract_strings(&std::fs::read("sample")?, 4);
```
License: Apache-2.0
