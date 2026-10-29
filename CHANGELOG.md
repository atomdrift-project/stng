# Changelog

All notable changes to stng. Versions follow [semantic versioning](README.md#versioning).

## Unreleased

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
