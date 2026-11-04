# Changelog

All notable changes to stng. Versions follow [semantic versioning](README.md#versioning).

## 3.0.0 (unreleased)

### Breaking

- `ExtractOptions` fields are private; configure it with the builders.
  `with_xor(XorMode)` replaces `with_xor(Option<usize>)`, `with_xor_key` and
  `with_xor_key_offsets` (`XorMode::{Off, Auto, Scan, Key}`), and
  `with_xor_min_length` sets the minimum length. `with_r2_strings`,
  `with_rizin_boundaries`, `with_rizin_connect_addrs` and
  `with_xor_key_offsets` are gone with no replacement: stng no longer takes
  results from rizin (see below).
- `StringMethod::R2String` and `R2Symbol` are removed, and `StringBoundary`
  is no longer public.
- `ExtractedString`, `StringContext`, `OverlayInfo` and
  `Severity` are `#[non_exhaustive]`: build strings with
  `ExtractedString::new(value, offset, method)` and the `with_*` methods.
- `StringKind` and `StringMethod` use Rust casing (`Ip`, `IpPort`, `Jwt`,
  `ApiKey`, `Guid`, `CtfFlag`, `SqlInjection`, `XssPayload`, `LdapPath`)
  and serialize in snake_case (`"ip"`,
  `"raw_scan"`).
- `detect_language` returns a `Language`; `DeobfuscationResult::language` is
  a `ScriptLanguage`, which gains `Batch` and `VbScript`.
- `decode_lcg_xor(data, range, &Lcg)` replaces the seven-argument form.
- `is_garbage_with_kind` is gone; use `is_garbage_with_context` with
  `StringContext::with_kind`.
- `script_decode` strings are located at the encoded blob they came from,
  not past the end of the file. An auto-detected XOR key not otherwise found
  is reported at its real offset, not 0.
- No longer public: the `binary` module (its `is_go_binary` and
  `is_rust_binary` remain at the crate root), `script::decode_chain`,
  `BinaryInfo`, `StringStruct`, `detect_elf_overlay_from_elf`,
  `extract_incremental_xor_strings`, `extract_macho_xor_macho_strings`, and
  `stng::subprocess` (depend on `stng-process` directly).
- `ExtractedString::source_spans` returns `impl Iterator<Item = (u64, u64)>`.
- Raw-scan strings are located at their trimmed value's bytes, so offsets of
  tokens decoded from inside them are exact.
- The `stng` command runs everything, text included, through the library:
  the text-only pipeline, the second deduplication table, and the display-time
  re-decoding of base64, hex, URL and Unicode escapes are gone, so
  `--simple`, `-i`, `--xor` and `--xor-lcg` behave the same on text.
  `--flat`, `--r2`, `--no-r2`, `--no-cache`, `--flush-cache` and
  `--xor-min-length` are removed, and XOR-decoded strings keep the library's
  minimum length.
  `--xor` reads hex only after `0x` or `hex:`; anything
  else is the literal key text. `--json` on a directory prints one
  `{"path", "strings"}` object per line instead of concatenated arrays.

### Added

- Decoding for more encoded forms, including VBScript paired arrays and
  inlined `strcat` chains.
- JavaScript permutation and better batch and PowerShell deobfuscation.
- Overlay crypter recovery for ELF.
- `extract_strings_from_parsed` takes, beside goblin's object, the binform
  layouts the caller already read (`stng::Layout`: a layout and the file
  offset it was read from), so a binary is read once by both. stng re-exports
  `binform`.
- `make deny` and a cargo-deny CI job; Windows and x86_64 musl builds are
  release-blocking, and Windows runs the test suite.

### Changed

- Hostile-input hardening: 64-bit hosts only, work budgets on every
  input-driven loop, logged cutoffs, and no regex compiled per call.
- The garbage filter defers to the classifier for indicators.
- A single text-file test; the CLI reports non-UTF-8 text through the library,
  with correct offsets.
- Stack-XOR keys are reported at the store that wrote them.
- The `stng` command no longer runs rizin or radare2, and keeps no cache.
  What rizin contributed is now native or gone:
  - XOR decoding is aimed at the NUL-bounded extents around the strings the
    raw scan found, in place of rizin's `izz` extents. This decodes more:
    whole XOR-encoded strings rather than fragments, on Mirai, 3CX and
    `brew_agent` samples among others.
  - `--xorscan` now means XOR-scanning Go and platform-signed binaries too;
    the rizin-located multi-byte key offsets it added found only noise.
  - The `connect()` address scan is dropped; call-site arguments belong in a
    disassembler, not a string extractor.
  - `--no-rizin` is still accepted and does nothing.
- Import, export and dynamic-symbol names come from binform's tables
  instead of goblin's, read only when needed (no caller-provided symbols,
  or an ARM64 Mach-O's stack-XOR pass): goblin's Mach-O bind interpreter
  no longer runs. Their offsets are file offsets of the import slot or
  the code: PE imports were RVAs, ELF ones virtual addresses, and fat
  Mach-O ones slice-relative. ELF imports goblin's dynamic symbol walk
  missed are found.
- Go binaries yield absolute build paths from the pclntab file table
  (`/root/go/...`, module-cache `pkg@version` paths).
- Language string structures that span a NUL are dropped rather than
  reported with the NUL inside.
- Go toolchain install paths (`Cellar/go/<version>`, `/usr/local/go`,
  `go1.N` directories) are not reported as path IOCs.
- Internal reorganisation: smaller files and functions, shared Go/Rust pointer
  pipelines, XOR passes under `xor/`. The public API is unchanged.

### Fixed

- XOR overruns into neighbouring strings, fuzzy base64 edge cases, and
  noise strings in the golden corpus.

## 2.1.1 (2026-10-10)

- Security hardening, especially of terminal output against ANSI escapes.
- Rust 1.97.

## 2.1.0 (2026-10-08)

- Obfuscated Lua decoding.
- Base64-wrapped zlib payloads decoded.
- Better CMD parsing; ARM64 stack-XOR fixes.
- XOR scanners run on binary input only; better rayon granularity.

## 2.0.1 (2026-10-01)

- More reliable macOS tests.

## 2.0.0 (2026-10-01)

First 2.x release. Earlier history is in the git tags.
