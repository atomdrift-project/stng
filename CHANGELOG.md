# Changelog

All notable changes to stng. Versions follow [semantic versioning](README.md#versioning).

## 3.0.0-beta.3 (2026-11-13)

### Features

- stack strings stored a character at a time through a reloaded pointer are recovered now, as dofoil builds them.
- utf-16 stack strings written by immediate stores are now recovered too.

### Fixes

- rust PE .rdata was never raw-scanned, so literals named straight from code vanished, including the javs backdoor's c2 vocabulary.
- numeric strings like `1444444444` were dropped as noise; only a single repeated digit is filler now.

## 3.0.0-beta.2 (2026-11-09)

### Features

- Extract strings from data appended to PE files, as was already done for ELF.
- Add `detect_overlay` for parsed ELF and PE files; the CLI now reports PE overlays.
- Breaking: XOR-scan platform-signed binaries by default; opt out with `--skip-platform-signed`.
- Breaking: make the classifier and script detection modules private; import `ScriptLanguage` from script.
- Breaking: remove `extract_strings_from_object`; pass parsed objects to extract_strings_from_parsed.
- Breaking: read string fragments through `fragments()`, and build layouts with Layout::new.
- Breaking: return a Result with `LcgError` from decode_lcg_xor instead of an Option.
- Breaking: order Severity from Info up to High, so higher severities compare greater.
- Breaking: reject conflicting XOR or output flags, and a zero `--min-length`, on the command line.

### Fixes

- Stop panicking on crafted x86 stack stores with negative displacements.
- Exit quietly when stdout closes, and log to stderr so `--json` output stays parseable.
- Exit non-zero when any file in a directory fails, naming the file in the error.
- Refuse FIFOs and devices instead of hanging on them.
- Keep encoded strings beside what they decode to, instead of replacing them.
- Read entitlements from each slice's signature slot, not the first plist found.
- Report UTF-16 text and nested script payloads at their offsets in the file.
- Stop calling times, MAC addresses, prose and x509 errors IPs, shell commands or AppleScript.
- Verify wallet checksums and require real onion labels before classifying addresses.
- Decode every `-EncodedCommand` spelling PowerShell accepts, including -ec and partial prefixes.
- Keep sync, strcpy and similar words the garbage filter wrongly dropped.
- Keep the best four sockaddr addresses instead of none when decoys exceed the cap.
- Make `--no-xor` disable every XOR pass, including PE rolling XOR.
- Wrap long values only on a terminal, so piped output keeps one string per line.
- Model ARM64 vector loads, stores and XOR, dropping about 200 spliced stack-XOR strings.
- Keep the leading slash of absolute paths that happen to start with a length byte.
- Classify PowerShell, cmd and Windows system-tool commands as shell commands.
- Decode a bare FromBase64String as UTF-8 unless its bytes look like UTF-16.
- Stop decoding the `\x64` in Windows paths as an escape sequence.
- Stop reporting a URL's own path as a separate path string.
- Detect Go PE binaries by their build-info header; `--detect` reported them as unknown.

### Optimizations

- Bound URL, PowerShell, sockaddr and ARM64 stack-XOR scans that crafted input made quadratic.

### Security

- Escape C1 controls and bidi overrides in JSON, which serde_json printed raw to terminals.
- Refuse files swapped for symlinks or devices mid-scan, and read growing files only to their listed size.
- Report a panic on one file and continue the directory scan instead of aborting.

## 3.0.0-beta.1 (2026-11-04)

### Features

- Decode JavaScript permutation obfuscation.
- Recover more from batch and PowerShell obfuscation, including environment-variable tricks.
- Decode VBScript paired arrays and inlined `strcat` chains.
- Decode literal URLs embedded inside encoded HTML and script buffers.
- Recover more strings from ELF binaries packed with overlay crypters.
- Extract absolute build paths from the Go pclntab file table.
- XOR-scan Go and platform-signed binaries too when `--xorscan` is set.
- Accept caller-parsed binform layouts in `extract_strings_from_parsed`, so each binary is read once.
- Breaking: stop running rizin; its builders, string methods, cache and CLI flags are gone.
- Breaking: configure `ExtractOptions` through builders, with a single XorMode replacing the XOR options.
- Breaking: mark public structs non-exhaustive; build strings with `ExtractedString::new`.
- Breaking: serialize string kinds and methods in snake_case, such as `raw_scan`.
- Breaking: read `--xor` keys as hex only after a 0x or hex: prefix, otherwise as literal text.
- Breaking: print one object per line for directories with `--json`, instead of concatenated arrays.
- Breaking: require a 64-bit host; 32-bit builds are no longer supported.

### Fixes

- Stop XOR decoding from overrunning into neighbouring strings.
- Decode whole XOR-encoded strings instead of fragments in Mirai, 3CX and similar samples.
- Report import offsets as file offsets; PE, ELF and fat Mach-O each disagreed before.
- Report exact offsets for decoded script strings, raw-scan tokens and XOR keys.
- Find ELF imports that goblin's dynamic symbol walk missed.
- Stop reporting Go toolchain install paths as path IOCs.
- Bound ARM64 stack-XOR decoding, which runs of stores and calls drove into quadratic time.
- Log each work-budget cutoff, so truncated analysis no longer passes silently.

### Optimizations

- Skip rizin's analysis pass entirely, which previously dominated default wall time.
- Read symbol tables from binform only when needed, and stop running goblin's Mach-O bind interpreter.

## 2.1.1 (2026-10-10)

### Fixes

- Escape control, C1 and bidi characters in CLI output, blocking terminal-escape injection.
- Pass absolute paths to rizin so filenames like `-x` or `dbg://` aren't misparsed.
- Kill rizin after 300 seconds and drop output over 512 MiB.
- Decode rizin output as lossy UTF-8 so one bad symbol can't void analysis.
- Write the rizin cache with 0700 permissions and atomic renames.
- Cap zlib inflation at 40 MB per pass in base64 and script deobfuscation.
- Cap batch `%var%` expansion at 256 MiB and Lua folding output at 16 MiB.
- Reject NaN, infinite, fractional and >2^53 numbers in Lua constant folding.
- Bound Mach-O symbol iteration by file size, defeating forged `nsyms` values.
- Bound XOR scanning on fat Mach-O slices and files over 5 MiB.
- Use checked arithmetic for offsets across ELF, Mach-O, PE, .NET, Go and Rust decoders.
- Log XOR keys and version-info IPs as escaped fields, preventing log forgery.
- Fall back to normal scanning when decoy Go sections lack Go string structures.
- Raw-scan bytes after Java class constant pools, recovering appended payload strings.
- Decode UTF-16-BOM 8-bit text despite stray NULs or invalid UTF-8.
- Extract URLs from `SuspiciousPath` strings, surfacing C2 URLs in stealer configs.
- Fix multibyte-boundary bugs that dropped non-ASCII JavaScript and reversed payloads.

### Features

- IOC URL parsing reads hosts like browsers: hex, octal and integer IPv4, percent-escapes.
- Minimum Rust version raised from 1.94 to 1.97.

### Optimizations

- Skip overlapping sections in Go/Rust scans, avoiding duplicate work from repeated headers.
- Use binary search for skip ranges in raw, wide and XOR scans, removing quadratic behavior.
- Make CLI line wrapping single-pass, fixing quadratic printing of huge strings.
- Use smarter scan advancement in Go funcnametab extraction and PowerShell base64 filtering.
- Reuse one buffer across multi-key XOR rotations.

## 2.1.0 (2026-10-09)

### Features

- Decodes Lua scripts obfuscated with Prometheus EncryptStrings by reading their syntax with tree-sitter, without running any Lua.
- Inflates base64-encoded zlib text in scripts and binaries, with checksum verification and a 10 MiB limit.
- Batch/CMD parsing now skips the `;`, `,` and `=` separators that CMD allows before a command, so `set` variables are tracked correctly.
- Detects Lua scripts so they go through script deobfuscation.

### Fixes

- Mach-O import parsing refuses bind streams with forged repeat counts that previously used gigabytes of memory.
- The arm64 stack-XOR scanner skips work early for non-arm64 binaries.
- Offsets in text input no longer drift one byte earlier per CRLF line.

### Optimizations

- Parallel work is split more coarsely across the ELF, PE, Mach-O, Go and Rust paths, cutting overhead on small inputs.
- XOR scanners now run only on binary input, skipping text that previously cost about a tenth of extraction time.

## 2.0.1 (2026-10-01)

- macOS: Ensure that tests don't cause XProtect false-positives.

## 2.0.0 (2026-10-01)

### Features

- Recovers dropper-embedded PE payloads encrypted with a short repeating XOR key.
- Decodes strings from x86 PE repeating-key XOR routines via a bounded interpreter.
- Adds `--xor-lcg` for analyst-supplied LCG-XOR ranges; Mach-O LCG loaders decode automatically.
- Extracts strings from single-byte-XOR universal Mach-O payloads hidden in `__const` sections.
- ARM64: recovers XOR literals with pointer-derived keys and Rust heap-array XOR loops.
- Decrypts macOS stealer strings sealed with a MurmurHash3-finalizer keystream.
- Recovers Swift small strings assembled with ARM64 move-wide instructions.
- Go: extracts Mach-O `__gopclntab` function names and struct tags via reflection metadata.
- Go/Rust: recovers string headers stored into literal tables on ARM64 and x86-64.
- Rust: detects stripped executables and recovers PIE literals via RELATIVE relocations.
- Scripts: decodes VBScript.Encode blocks and expands cmd.exe batch variable-splicing obfuscation.
- Decrypts legacy ColdFusion CFCRYPT (cfencode) templates back to CFML source.
- Hex-encoded blobs are now scanned for single-byte-XOR strings hidden inside.
- Decodes Base64 with omitted padding, and UTF-8 text behind a bogus UTF-16 BOM.
- Flags credential stores, wallets, browser data and shell history as suspicious paths.
- New `cli` feature: `default-features = false` builds the library without CLI dependencies.

### Fixes

- ELF Go and Rust strings now report file offsets instead of virtual addresses.
- Go funcnametab recovery no longer drops long module paths or generic instantiations.
- Platform-signature check reads only the embedded signature, so Developer ID malware gets scanned.
- Rust Mach-O string tables in `__DATA,__const` from older linkers are now extracted.
- Crafted Mach-O bind opcodes no longer panic extraction; only imports are lost.
- Script decompression is capped at 10 MiB while inflating, blocking decompression bombs.
- Hardened header-offset arithmetic; a new mutation test asserts hostile files never panic.
- Injection detection requires whole-word commands after `;`/`|`, cutting false ShellCmd hits.
- Strings with `@` that aren't emails now fall through to URL/path/command classification.

### Optimizations

- XOR pattern scan finds each printable run once per alignment, removing quadratic blowups.
- Hostname expansion is bounded by DNS name length, avoiding quadratic walks on long runs.
- CLI caps rayon at 16 threads: 15–40% faster, 4–8× less CPU on 128 cores.
- Dropped hex and urlencoding deps; library builds skip clap, sha2, jemalloc, tracing-subscriber.
- Published crate ships only `src/`, excluding ~90 MB of test data.

### Breaking

- String cache and cache sweeper removed; caching now belongs to callers.
- rizin/radare2 integration moved into the CLI; `with_r2` removed.
- Section-info collectors return `Vec<SectionInfo>`, since names repeat across segments.

## 1.12.0 (2026-09-14)

### Features

- Cache sweep gained an entry-count ceiling (16,384 default, `STNG_CACHE_MAX_ENTRIES`).
- Sweep marker records completion — an interrupted sweep retries within the hour instead of booking a full day.
- A long run re-sweeps after writing a ceiling's worth of entries, closing the batch-run gap.
- Cache hits refresh mtime daily, making eviction least-recently-used.

### Fixes

- JVM class files are parsed via the constant pool instead of being mistaken for fat Mach-O (shared `CAFEBABE`), which returned no strings at all.
- Go PE string offsets convert back to `.rdata` file offsets so section matching works.
- Go recovery accepts `MOV len; LEA ptr` ordering and a 256-byte backward window.

## 1.11.0 (2026-09-10)

### Features

- Hex runs of 32+ nibbles embedded inside larger strings now decode (the `echo <hex> | xxd -r -p | sh` dropper shape).

### Fixes

- Base64 candidate selection no longer panics when quartet truncation lands mid-UTF-8 character.

## 1.10.0 (2026-09-08)

### Features

- New ROT13+base64 decoder, exposed as `StringMethod::Rot13Base64Decode`.
- Generalized ROT/charCode packer decoding for JavaScript.

### Fixes

- Dropped the tracing-log bridge: a forged PE import directory turned goblin's per-entry warnings into a CPU livelock for the whole binary.
- Unicode escape decoding no longer emits redundant backslashes.

### Optimizations

- The XOR auto-detect prefilter now tests the full `min_length` prefix instead of one byte.
- ARM64 stack-XOR extraction above 1 MiB now runs only on binaries the ordinary string pass calls opaque.

## 1.9.1 (2026-08-25)

- Added 32-bit ARM musl libgcc linking support.
- Removed duplicate XOR scanning for unknown formats.
- Updated dependencies.

## 1.9.0 (2026-08-14)

### Detection

- IOC extraction (new): IPs, hostnames, hardcoded paths, and key material, deduplicated with counts and locations. Values preserved bit-for-bit; key bytes never serialized.
- 3CX-class XOR strings recovered: NUL-padded records are split and validated individually instead of rejected as null-heavy. 3CX libffmpeg is now a regression test.
- Short base64 decoded: floor down to 12 chars (`/bin/rm`, `uname -a`), or 8 when padded or paired with a `base64 -d`.
- `TracerPid:` no longer dropped: colon-terminated labels were scored as garbage, hiding anti-debug checks in ELFs.

### Performance

- XOR scan rewritten with anchor inversion + Aho-Corasick.
- Baked-in jemalloc tuning: 26–55% lower peak RSS for ~1% wall.

### Distribution

- Signed releases with sigstore provenance across 13 targets — Linux (gnu/musl, x86_64→riscv64, s390x), macOS, Windows, illumos, BSDs.
- Stripped binaries; smoke-tested on real distros.

## 1.8.0 (2026-07-25)

### Performance

- ~5× faster on binaries needing rizin/radare2 analysis. The expensive `aaa` pass now overlaps native extraction, skips non-ARM binaries where it can't detect anything, and merges what were multiple rizin invocations into one.
- Repeated scans of the same file are cheaper — rizin outputs are memoized in-process and cached on disk.

### Detection

- Fixed: structured `{ptr, len}` strings (e.g. in xclip PE) were being dropped by the garbage filter — now surfaced.

### Caching (new)

- Persistent on-disk cache for rizin/string results at `~/.cache/stng` (Linux) / `~/Library/Caches/stng` (macOS).
- Auto-reclaimed in the background: entries older than 30 days or beyond 2 GiB are swept.

### Project

- Moved to GitHub!

## 1.7.1 (2026-07-06)

### Features

- New stng-owned string cache (in-memory + disk) so consumers share one copy instead of re-extracting.
- Strings now carry their source byte extent, fixing span math for UTF-16LE, base64, and stack strings.

### Fixes

- Stack-string junk (stack fills, register-save patterns) no longer bypasses the garbage filter.
- Fixed a quadratic slowdown in XOR scanning on large payloads (tens of seconds → fast, identical output).

### Performance

- 40% faster test suite.
- Bumped jemalloc to 0.7.
- Trimmed per-string memory (dropped unused metadata fields).

## 1.7.0 (2026-06-20)

- Added generic decoded-string extraction for text inputs.
- Added base64-over-UTF-16LE decoding.
- Improved Go PE inline string recovery.
- Reduced PE/network false-positive IPs.
- Tightened URL-decoding false positives.
- Improved Python/JS code classification.
- Parallelized decoder and filtering hot paths.
- Added `Deserialize` for extracted string metadata.
- Added focused regression tests.
- Added pre-commit hook support.

## 1.6.2 (2026-06-14)

### Detection

- XOR decoder now drops strings ≥16 chars where one character is >50% of the content. Kills false positives from repeated-byte runs (e.g. spaces) that XOR into base64-looking junk. Expect fewer XOR hits, not more.

### Performance

- Dotted-pattern XOR scan: was up to 255 full-buffer passes per file, now one pass. Same output, much faster on large inputs.

### API (breaking)

- `FormatHint::Binary` removed. Use `Auto`. `Text` unchanged.

### Supply chain / cleanup

- Dropped thiserror dependency (consolidated on anyhow).
- Removed ~764 lines of dead amd64 code. Active extractors untouched.
- Routine bumps: cc, memchr, miniz_oxide, wasm-bindgen. No advisory fixes.

## 1.6.0 (2026-06-09)

### Features

- Native PE import recovery now surfaces API names like `CreateProcessW` without radare2.
- Mach-O symbol extraction now types imports, exports, ObjC classes, and stub helpers.
- Callers can skip stng symbol extraction when symbols are already parsed upstream.

### Performance

- Avoids duplicate symbol/import parsing when `caller_provides_symbols` is set.

### Bugfixes

- Native Mach-O scans now preserve ObjC selectors and split command fragments without radare2.
- Fixed Mach-O dedup dropping strings that shared section-relative offsets.
- Go Mach-O packed `__rodata` recovery now finds high-signal URLs and `find` command fragments.

## 1.5.2 (2026-06-07)

### Fixes

- XOR scan no longer mistakes pure-letter .NET identifiers (e.g. `WrapNonExceptionThrows`) for XOR keys — keys now require a digit or symbol.
- IPv6 classification requires a multi-digit hextet, so noise like `0::c` is no longer flagged as an IP.

### Performance

- Raw extraction classifies runs in bounded 64K batches, capping intermediate memory on string-dense files.
- `function_meta` is now boxed, shrinking every extracted string.
- UTF-16 decode streams directly from bytes (no whole-file `Vec<u16>`).
- Rust section scanner borrows segments instead of copying the section.
- `--json` streams to stdout instead of building the full document in memory.

## 1.5.1 (2026-05-28)

- Fewer false-positive IPs in Windows PE files — compiler-emitted u16 tables (unwind info, C++ exception metadata, jump tables) no longer get mistaken for `sockaddr_in` structures.
- ~5x faster tests — `cargo test` drops from ~95s to ~17s via `opt-level = 2` on the test profile.
- Rust 2024 cleanup and dependency updates.

## 1.5.0 (2026-05-26)

- Rust 2024 edition: bumped `edition = "2021"` → `"2024"` in Cargo.toml.
- Migrated codebase to 2024 syntax.
- Dep bumps: goblin 0.10.5 → 0.10.6, log 0.4.29 → 0.4.30 (patch updates only).

## 1.4.0 (2026-05-24)

### Bugfixes

- `extract_stack_off`: no more panic on multibyte box-drawing chars in r2 output.
- `sockaddr_in` scan now honors the binary's native endianness.
- Registry classifier recognizes root-relative subkeys (`Software\Microsoft\…`, `System\CurrentControlSet\…`, `SAM\`, `SECURITY\`).
- Garbage filter keeps canonical UUIDs and hex runs ≥ 8 with ≥ 4 distinct digits.
- Short-identifier filter keeps 4-char camelCase (`iPad`, `hWnd`), balanced call shapes (`Run()`), and whitespace-separated disasm (`JMP +5`).

### Build

- Optional jemalloc on Unix (skipped on the *BSDs / illumos / Solaris).
- New profiling profile and bench-build / heap-build / sampled-benchmark / heap-benchmark targets.
- `MAKEFLAGS` scrubbed so jemalloc-sys's nested make doesn't choke.

### Testing

- Regression coverage for `extract_stack_off` on non-char-boundary input.
- New suites for PascalCase identifiers and per-endianness `sockaddr` acceptance.
- GUID classifier tests cover braced, bare, uppercase, and wrong-shape inputs.

## 1.3.1 (2026-05-13)

Pre-CackalackyCon release.

### Bugfixes

- Added coverage for mixed script/binary inputs that previously could miss decoded campaign markers.

### Testing

- Added regression coverage for polyglot/unknown inputs to ensure embedded base64 payloads are decoded even when the file is mostly binary.
- Rizin/r2 cache tests now use isolated temporary cache directories, avoiding shared cache state across test runs.

## 1.3.0 (2026-05-08)

### Features

- Better Go PE recovery with image-base-aware string structures, pclntab varint/null table extraction, and stack-built Win32 API names.
- Added Rust PE detection and structure-based `.rdata` string slicing.
- Better multi-key XOR recovery using rizin/r2 lea-near-xor analysis and high-entropy key candidates.
- Added blind decode fallback for high-confidence XOR keys, improving recovery of short/split IOCs.
- Raw/unknown inputs now run raw, wide, binary IP, stack-string, decoder, script, and requested XOR extraction.

### Performance

- PE stack-string scans are limited to executable sections.
- Go and Rust PE packed string sections are skipped by raw/wide scans to avoid huge concatenated blobs.
- Go PE pclntab varint and null-separated scanners run in parallel per section.
- ELF overlay detection reuses parsed ELF metadata instead of reparsing.

### Bugfixes

- Fixed stripped Go PE detection to avoid false XOR payloads from pclntab data.
- Fixed Go PE image-base handling so `{ptr,len}` strings resolve correctly.
- Fixed Go varint length prefixes leaking into module/package path strings.
- Fixed noisy Go/Rust packed-string extraction that emitted merged `.rdata` blobs.
- Fixed x86 instruction-byte fragments leaking as strings with arch/section-aware filtering.
- Tightened binary IP detection to reject linear, gateway-like, and repeated low-octet false positives.

## 1.2.2 (2026-05-01)

### Features

- Better multi-key XOR recovery using rizin/r2 lea-near-xor analysis and high-entropy key candidates.
- Added blind decode fallback for high-confidence XOR keys, improving recovery of short/split IOCs.
- Raw/unknown inputs now run binary IP, stack-string, and requested XOR extraction.

### Performance

- Simplified rizin/r2 integration while preserving key extraction paths.
- PE stack-string scans now only inspect executable sections.
- Go binaries skip raw/wide scans over packed string blobs.

### Bugfixes

- Fixed noisy Go string extraction that emitted huge concatenated `.rodata` blobs.
- Fixed ARM64 Go inline string offsets so strings dedupe correctly.
- Improved stripped Go PE detection to reduce false XOR payloads.
- Fixed decoded URL cleanup for multibyte domains and IP:port URLs.

## 1.2.1 (2026-04-28)

### Features

- Detect Telegram bot tokens.
- Detect Swift mangled symbols.

### Bugfixes

- Require `eyJ` prefix for JWT matches.
- Skip XOR IP matches inside binary data tables.
- Stop misdetecting Java/Kotlin code as Python.

## 1.2.0 (2026-04-21)

### Features

- macOS/arm64 stack-XOR decoder — recovers strings built on the stack via MOVZ/MOVK/ADD/STR, including pad reuse across blobs; handles fat binaries.
- `FormatHint` (`Auto`/`Binary`/`Text`) lets callers skip XOR and other binary-only passes on known-text input.
- Cancellation via `ExtractOptions::cancel` returns partial results when set.

### Performance

- XOR scan skips executable sections (60–80% fewer bytes scanned).
- XOR scan skips Apple/Microsoft platform-signed binaries.
- Stack-string extraction is now per-section and parallel on PE/Mach-O.
- Validation hotpath moved from chained `contains` to Aho-Corasick.
- Dead garble deobfuscation code removed (~4000 lines); rayon integration simplified.

### Bug fixes

- `18.0.0.23` and similar PE ProductVersion strings no longer classified as IPv4.
- Go symbols (`go.shape.`, `syscall.Handle`) no longer flagged as Python.
- Stripped Go PEs detected via `.symtab`, stopping pclntab noise from producing garbled XOR "payloads".
- Go module paths no longer misclassified as email/JWT; JWT now requires `eyJ…` header.
- Timezone-shaped bytes (`10-11-12-08-09+13`) no longer produce spurious XOR IPs.
- 32-bit section-range overflow fixed.
- Panic hardening across stack_strings, entitlements, instr, overlay, and Go/Rust extractors.

## 1.1.8 (2026-04-10)

### Features

- XOR detection improvements for ELF binaries.
- Better PE/XOR support (fixes office_update sample handling).

### Performance

- Switched to iced-x86 + rayon for faster disassembly with parallelism.
- Aho-Corasick algorithm for XOR/string classification (significant speedup over linear scan).
- Better SHA/rizin result caching to avoid redundant work.
- Linux micro-optimizations and timing improvements throughout.

## 1.1.7 (2026-03-26)

### Bugfixes

- Fixed false positives where `#!` appearing later in a file could misclassify plain text or shell content as Python or JavaScript.

### Performance

- Reduced overhead in XOR validation by avoiding unnecessary overlapping pattern scans.

## 1.1.6 (2026-03-26)

- Fix bug with incorrectly detecting shebang programs as having embedded shell.

## 1.1.5 (2026-03-25)

- Add raw string fallback for Go-based ELF/Mach-O binaries (PE already had this).

## 1.1.4 (2026-03-24)

### Bugfixes

- Fix false positive PHP detection from `.reloc` section garbage matching `<?=` short echo tags.
- Fix false positive base64 classification on ASN.1 certificate timestamps and x86 instruction byte patterns.
- Fix false positive XOR-decoded IPs from XAML/CSV numeric data where commas XOR to periods.
- Fix dead code in shell command detection.
- Fix section header output printed unconditionally instead of only on section change.

## 1.1.3 (2026-03-24)

- Go binary analysis: improve short-string array extraction; for example: `"gh"`, `"auth"`, `"token"`.

## 1.1.2 (2026-03-23)

### Improvements

- Recover Go Pclntab function names — Extract function names from Go's Pclntab (Program Counter Line Table), improving analysis of Go binaries.
- Improve Go string handling for Wazero binaries — Better string recovery from Go binaries using the Wazero runtime.

### Maintenance

- Upgrade itoa dependency.
- Code cleanup and removal of extra debug statements.

## 1.1.1 (2026-03-17)

- Show XOR key in header consistently.
- Update dependencies.

## 1.1.0 (2026-03-16)

### New features

- Add initial garble deobfuscation support for Go binaries (rodata scanning + emulator).
- Add script deobfuscation engine (Python, JavaScript, PHP, PowerShell).
- Support spaced ASCII decoding (common in PE `.rsrc` / .NET metadata).
- Rolling XOR with known-plaintext for .NET malware (e.g. Redline).
- Improved XOR/.NET string decodings.

### Fixes

- Fix embedded base64 detection when used as a library.
- Fix shell detection.
- Fix extraction for exotic C binaries.
- Reduce false IP matches for Win32/Go binaries.
- Improve URL encoding detection.

### Performance

- Optimize degarble fast-path on non-garbled binaries.
- XOR scan and general performance tuning.

Earlier history is in the git tags.
