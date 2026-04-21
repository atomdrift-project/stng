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

- **Garbage filtering**: Filters unusable noise by default (`--unfiltered` to disable)
- **Language-aware extraction**: Go/Rust `{ptr, len}`, Go pclntab symbols, stack-string reconstruction (x86 and arm64)
- **XOR obfuscation**: Single/multi-byte keys, entropy analysis, arm64 stack-XOR, double-layer (encoding+XOR)
- **Script deobfuscation**: Decodes obfuscated Python/JS/PHP/PowerShell payloads and re-scans them
- **Encoding detection**: Base64, Base32, Base85, hex, URL-encoding, Unicode escapes, UTF-16LE wide strings
- **IOC classification**: IPs, URLs, hostnames, shell commands, suspicious paths, crypto wallets, Tor addresses, JWTs, API keys, mining pools, ransom notes
- **Mach-O specifics**: Code signatures, entitlements, fat/universal binaries
- **Format support**: ELF, PE, Mach-O, raw binaries, overlays

Useful for initial triage, C2 enumeration, credential extraction, and YARA signature development.

License: Apache-2.0
