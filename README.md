<p align="center">
  <img src="media/logo.svg" alt="stng" width="240">
</p>

**stng** — modern string extraction for binary analysis. All of the good stuff, none of the garbage.

![screenshot](media/screenshot.png)

## Installation

```bash
brew install atomdrift/tap/stng
```

Or with cargo:

```bash
cargo install --git https://codeberg.org/atomdrift/stng
```

## Quick Start

```bash
stng malware.bin              # Full analysis with XOR auto-detection
stng -i malware.bin           # Show interesting strings
stng --json malware.bin       # Machine-readable output with encoding metadata
```

## Features

- **Garbage filtering**: Filters out unusable garbage by default (supports `--unfiltered`)
- **Language-aware extraction**: Go/Rust `{ptr, len}`, DWARF stack strings
- **XOR obfuscation**: Single/multi-byte keys with entropy analysis, double-layer (encoding+XOR)
- **Encoding detection**: Base64, Base32, Base85, hex, URL-encoding, Unicode escapes
- **IOC classification**: IPs, URLs, shell commands, paths, credentials, hardcoded socket structures
- **Wide strings**: UTF-16LE in Windows PE binaries
- **Format support**: ELF, PE, Mach-O, raw binaries, overlays

Useful for initial triage, C2 enumeration, credential extraction, and YARA signature development.

License: Apache-2.0
