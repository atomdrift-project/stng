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
cargo install --git https://github.com/atomdrift-project/stng
```

Optionally install [rizin](https://rizin.re) or [radare2](https://radare.org) to enable deep XOR scanning (`--xorscan`) and `connect()` address recovery. stng works without them, skipping those passes.

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

## Caching

Rizin analysis and extracted strings are cached on disk (`~/.cache/stng`, `~/Library/Caches/stng` on macOS) to speed up repeat scans. The cache self-reclaims in the background — entries older than 30 days or exceeding 2 GiB are swept at most once per day, never blocking a scan.

| Variable | Default | Effect |
|---|---|---|
| `STNG_CACHE_TTL_DAYS` | `30` | Age after which entries are dropped |
| `STNG_CACHE_MAX_BYTES` | `2147483648` | Size ceiling before oldest entries are dropped |
| `STNG_STRING_CACHE` | `1` | Set `0` to disable the string cache |

License: Apache-2.0
