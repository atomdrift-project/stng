# Changelog

All notable changes to stng. Versions follow [semantic versioning](README.md#versioning).

## 3.0.0 (unreleased)

### Breaking

- `ExtractOptions` fields are private; configure it with the builders.
  `with_xor(XorMode)` replaces `with_xor(Option<usize>)`, `with_xor_key` and
  `with_xor_key_offsets` (`XorMode::{Off, Auto, Scan, Key}`), and
  `with_xor_min_length` sets the minimum length. `with_hints(ExternalHints)`
  replaces `with_r2_strings`, `with_rizin_boundaries`,
  `with_rizin_connect_addrs` and `with_xor_key_offsets`.
- `ExtractedString`, `StringBoundary`, `StringContext`, `OverlayInfo` and
  `Severity` are `#[non_exhaustive]`: build strings with
  `ExtractedString::new(value, offset, method)` and the `with_*` methods.
- `StringKind` and `StringMethod` use Rust casing (`Ip`, `IpPort`, `Jwt`,
  `ApiKey`, `Guid`, `CtfFlag`, `SqlInjection`, `XssPayload`, `LdapPath`,
  `RizinString`, `RizinSymbol`) and serialize in snake_case (`"ip"`,
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

### Added

- Decoding for more encoded forms, including VBScript paired arrays and
  inlined `strcat` chains.
- JavaScript permutation and better batch and PowerShell deobfuscation.
- Overlay crypter recovery for ELF.
- `make deny` and a cargo-deny CI job; Windows and x86_64 musl builds are
  release-blocking, and Windows runs the test suite.

### Changed

- Hostile-input hardening: 64-bit hosts only, work budgets on every
  input-driven loop, logged cutoffs, and no regex compiled per call.
- The garbage filter defers to the classifier for indicators.
- A single text-file test; the CLI reports non-UTF-8 text through the library,
  with correct offsets.
- Stack-XOR keys are reported at the store that wrote them.
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
