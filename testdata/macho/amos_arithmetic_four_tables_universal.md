# AMOS four-table arithmetic fixture

Malicious universal x86_64/arm64 Mach-O, retained for static analysis only.
SHA-256: `27dd03510188c3ed0473d71fdedb1add484ccd709ec978fc6834f23a2accebca`.
Source: August 2025 abuse.ch corpus in the triage input.

The x86 entrypoint (`0x100006210`) calls four string-building helpers. They use
an indirect dispatcher with five traversal implementations and an FNV-1a
checksum fallback. Every implementation applies the low byte of
`((A[index] - C[index]) ^ B[index]) - D[index]`, writing to `output[index]`.
The fifth table is a complete permutation. The initial linear loop and the
checksum fallback share a 15-instruction pattern with explicit addresses and
bounds, which the extractor recognizes without emulating the dispatcher.

Static dispatcher choices: payload and cleanup use the linear path; alphabet
uses one literal byte followed by the remaining permuted indices; gate builds
an identity index array with vector instructions before applying the permutation.
The alphabet's literal equals the arithmetic result at the first index.

Independent reconstruction matches all four embedded FNV-1a checksums of the
hex strings: alphabet `7b809ed3`, gate `809ee3d1`, payload `4741044a`, cleanup
`db272952`. Hex/custom Base64 decoding yields:

| Stage | Length | SHA-256 |
| --- | ---: | --- |
| VM gate | 536 | `22422ea28dc3168fca0f6633341402f35ad168770ad51960e030a9f94946e080` |
| AppleScript | 23862 | `5e31896ef8bb791fbd9dca54d6c855cbbc7508c7e879e3d0b1105a2d5275e65d` |
| Terminal cleanup | 22 | `20a60a29c697e89aeab8cc741327f19f84b599e628d175aab132f1551f1da29c` |

The complete script differs from the September arithmetic fixture only in
campaign IDs. It phishes credentials, collects and uploads sensitive stores,
replaces Ledger Live and installs a root LaunchDaemon. Initial instruction analysis covered the x86 slice; the ARM follow-up below
adds complete native coverage. No sample code was executed.

## Dedicated regression coverage

`src/lcg_xor/arithmetic_variant_tests.rs` now retains direct tests for this
recognizer and its independently decoded original specimen. Tests cover public
thin/FAT output, exact hashes and spans, every recognized setup/loop instruction,
branch targets, bounds, malformed data and table addresses, minimum length and
overflow. Permutation forms additionally reject duplicate, negative and
out-of-range indexes and accept another complete permutation. Dispatcher tests
also cover both ARM forms, initialization slots, state transitions, truncation
and the eight-candidate limit. See `arithmetic_variants_expected.json`.

## ARM64 follow-up

All 25 ARM native function starts were reviewed. Independent reconstruction of
primary and checksum-fallback paths matches every checksum and the three stage
hashes above. The gate fallback uses 1,428 permutation entries followed by two
literal stores. Six `arm_four_table_*` regression tests cover this original
fixture, public thin/FAT extraction, every matched instruction, all four source
tables, valid and malformed permutations, literal overrides, truncation, bounds,
overflow and candidate limits. Combined relevant suites: 628 passed, zero failed,
four ignored; the manual timing test separately passed.

Analysis and test logs: `/var/tmp/triage40/review/macho-27dd-arm/README.md`.
