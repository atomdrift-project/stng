# Rust heap-array XOR fixture

Universal x86_64/arm64 Mach-O, retained for static analysis only.
SHA-256: `78371a85a51dee581823243272525e119ce88255e2ad75bc5980870681999970`.
Source: the `.back/installer` in MalwareBazaar DMG
`230081198d15ae14d9eaae5339298a1879555b232732bbfd48418a38b8b65685`.
The x86 slice starts at file offset 8192. No sample code was executed.

At x86 VA `0x10003bb50`, two 302-byte arrays are allocated and initialized
with immediate stores. The loop at `0x10003c02c` applies `b[i] ^= a[i]`.
Both indexing calls target `0x100060ea0`, whose successful branch checks
`i < length` and returns `base + i`. The recovered string is passed to the
command argument builder after `osascript` and `-e`:

```applescript
display dialog "The current version of the app is not fully compatible with your version of MacOS.

For the app to work correctly please, enter password of your system." with title "Application Error" default answer "" with icon caution buttons {"Continue"} default button "Continue" with hidden answer
```

The recognizer only accepts complete, consecutive array writes, matching
allocation sizes, distinct preserved registers, the complete bounded XOR
loop, and the checked-index helper. It does not generalize to this binary's
other constant-obfuscation scheme. Work is bounded to 8 MiB of x86 code,
128 candidate allocation prefixes, and arrays of at most 4096 bytes.
Evidence spans cover the encoded instructions in the original outer file.

## Pointer-derived constant XOR

The separate `pointer_xor` recognizer recovers the constant scheme used by
the extension IDs and upload URLs. An eight-byte setup signature gates a
strict instruction grammar: key base and seed setup, stack initialization,
complete qword XOR loop, and a matching literal length at the next call.
Only then does it fold the short register-only key helper. Both ciphertext
and key must lie entirely inside Mach-O constant sections. It supports RBP
and RSP stack slots, including a distinct output buffer and a copied length
register. This x86 grammar does not decode byte tails. ARM64 extraction now
covers complete constant-input qword XOR loops. Unresolved saved-register seeds
and byte-tail display names remain deferred, as detailed below.

Limits are 8 MiB of x86 code, 1024 setup candidates, 24 helper instructions
within 128 bytes, and 512 bytes per literal. There is no external tool,
new dependency, key search, or general memory emulator. These limits bound
work; they are not a production throughput measurement.

The x86 native output includes all IDs in the independently reconstructed 298-row
target table (277 distinct IDs; Coinbase already had an instruction-derived
copy). It also recovers these three 32-byte padded URL literals:

| Ciphertext VA | Outer file offset | Decoded URL |
| --- | ---: | --- |
| `0x1002b6a1a` | 2853402 | `https://cloudproxy.link/m/opened` |
| `0x1002b6a85` | 2853509 | `https://cloudproxy.link/m/decode` |
| `0x1002b6ad5` | 2853589 | `https://cloudproxy.link/db/debug` |

The archive-upload helper at `0x10000e84d` computes key pointer
`0x1002ae646` from base `0x1002a5ea4` and seed `0x2c45387b`.
Its caller at `0x10004bac9` uses an RSP-based output slot. Evidence offsets
refer to ciphertext in the original universal file, not to decoded text.

Most target display names have byte tails and remain unsupported by this
recognizer. Their independent reconstruction is retained in the triage report.

## Rust literal argument length

This fixture also contains a Rust string call at x86 VA `0x100017996`:
`lea rdx, [0x1002b2887]; lea rdi, [rbp-0x80]; push 0x3e; pop rcx; call`.
The 62-byte literal is `SELECT origin_url, username_value, password_value FROM logins;`.
The instruction extractor recognizes the adjacent positive push/pop length
load, allowing one intervening stack-address LEA for the output slot. It
requires the length load to end at the call and rejects register clobbers.
This extends the existing bounded call-site scan without an additional pass.

## Rust slice headers in the older data segment

This binary stores its slice headers in `__DATA,__const` (259712 bytes),
not `__DATA_CONST,__const`. The Rust extractor now passes either section
through the existing aligned pointer-and-length scanner. Two optional section
slots avoid a new allocation or an unrestricted section search.

For example, the formatting pieces at x86 VA `0x1003abc30` include the pair
`(0x1002b2b4a, 25)` at `0x1003abc60`. The exact referenced bytes are
`/Local Extension Settings`, at outer file offset 2837322. Previously only
heuristic fragments `/Local`, `Extension`, and `Settingssrc` survived.
The corrected output reports the full path with method `Structure`.
Cache version 21 invalidates output produced before this section fix.

## Regression tests

- `src/heap_xor/tests.rs`: 7 tests pin the original specimen and independent
  prompt digest, full instruction provenance, every loop/helper instruction,
  malformed arrays, text, truncation, code/candidate budgets and public extraction.
- `src/pointer_xor/tests.rs`: 8 tests compare all 298 independently reconstructed
  extension-ID rows and key helpers (`rust_pointer_xor_expected.json`), the three
  endpoint literals, setup/loop mutations, helper grammar, consumer lengths,
  region bounds, malformed text and code/candidate limits.
- `src/rust/triage_tests.rs`: checks both Rust slice-header segment names and
  an unsupported-segment negative, plus all six SQL literals and exact spans.
- `src/instr/push_length_regressions.rs`: tests the full positive imm8 range,
  extended registers, optional stack LEA, clobbers, negative/zero lengths, gaps
  and truncation.

These tests perform static extraction only. No throughput benchmark was run.

## ARM64 independent oracle (extraction still pending)

`rust_pointer_xor_arm64_expected.json` retains 596 independently reconstructed
ARM64 literal outputs, helper addresses, seed/base/key values, and binary reads.
The associated universal specimen above is unchanged. All lengths were taken
from ARM string-conversion arguments after statically interpreting the decoding
instructions, including immediate fragments and byte tails. The 298 pairs
contain 277 unique IDs and 296 unique display names. The five-byte inline name
is `MewCx`. Only after reconstruction were outputs compared with x86: every
value and length matches. This fixture prepares regression coverage for the
currently unsupported ARM64 pointer-derived decoding path; it does not imply
that the current extractor recovers these ARM64 literals.

The native ARM64 key folder now has seven tests in
`src/pointer_xor/arm64/tests.rs`, including all 596 oracle rows and mutation
of each executed key-helper instruction. The folder has fixed register state,
a 40-instruction limit, and at most two tail branches. Literal setup/loop
recognition and runtime integration remain pending; current extraction
behavior has not changed.

## ARM64 setup recognition checkpoint

The native setup recognizer now matches all 596 reviewed call sites and
validates the complete outlined base/seed store helpers. It resolves 594
immediate seeds; two saved-register cases remain explicit `Seed::Saved`
expressions until the caller proves the saved value and preservation.
A fixed four-byte signature scan is capped at 8 MiB and 1,024 candidate
attempts, including invalid hits. No scanner runtime integration is enabled yet.

Thirteen ARM64 tests cover all setups and key helpers, every required setup
and store-helper instruction mutated to an invalid opcode, mismatched slots
and registers, malformed/truncated code, reserved encodings, and code/attempt
budgets. Full library run: **606 passed, 3 ignored**, retained in the review
log `arm-setup-lib-tests.log`. Saved-seed preservation and complete literal
decoding/consumer validation remain required before runtime integration.

## ARM64 local saved-seed checkpoint

Native `local_seed` resolves 595 of 596 reviewed seeds: 594 immediate values
and one adjacent MOVZ/MOVK saved-register constant. It rejects mismatched
registers, nonadjacent definitions, wrong MOVK halves and X19 (which a validated
base helper may overwrite). One seed remains explicitly unresolved.

Fourteen focused ARM64 tests pass; the full library run reports **607 passed,
3 ignored** (`arm-local-seed-lib-tests.log`). Runtime extraction remains disabled
until the longer register-preservation check and complete literal decoding are
implemented. `arm-deferred-seed-preservation.json` records the remaining
905-instruction interval, its 100 distinct direct callees, and 80 local branches
(all within the interval). String conversion saves, temporarily changes, and
restores X22; checking only direct caller writes would miss this distinction.

## ARM64 complete qword-loop checkpoint

`src/pointer_xor/arm64/loops.rs` validates all 298 extension-ID decoding loops:
296 outlined loops with three copy/consumer arrangements, plus two inline
frame-relative loops. The grammar checks the full XOR body, exact iteration
bound/stride/back edge, copied destination versus consumer pointer, and exact
32-byte consumer length. Copied forms return an explicit requirement that
X19 equals X20+32; the caller must prove it before extraction. Inline forms
write and consume through the same unmodified frame register and displacement.

Twenty ARM64 tests pass. The loop/arithmetic comparison reproduces all 298
independent IDs using native key folding; it explicitly supplies the one
deferred seed from the oracle, so this is not a claim of complete runtime
extraction. Mutation tests cover every required loop/outline instruction,
wrong XOR/bounds/strides/branches, incorrect copy/consumer buffers and lengths,
and truncated/unaligned/overflowing code. Full library: **613 passed, 3 ignored**
(`arm-qword-loops-lib-tests.log`).

Caller register preservation, the deferred seed, display-name byte tails,
evidence offsets and scanner integration remain pending. No cache bump or
changed runtime extraction behavior is claimed at this stage.

## ARM64 frame-relative runtime integration

The proven frame-relative forms are now connected to the normal Mach-O
extractor. They recover `ghmbeldphafepmbegfdlkpapadhbakde` (ProtonPass) and
`fdjamakpfbbddfjaooikfcpapjohcfmg` (DashlanePass), each 32 bytes, at ARM slice
offsets 2812431 and 2812475. Cache version 35 invalidates previous results.
Copied-buffer forms remain explicitly deferred; no caller register values are
assumed. The bounded signature scan rejects oversized code and exhausts its
candidate budget on malformed candidates as well. Constant/key reads must
fit mapped Mach-O constant sections and decoded text must be valid printable
UTF-8.

There are now 24 ARM64 tests and 32 total pointer-XOR tests. Full library:
**617 passed, 3 ignored** (`arm-frame-integration-lib-tests.log`). New checks
exercise the public ARM-only pipeline, exact thin/fat evidence spans, missing
constants, bad UTF-8/NUL, minimum length, offset overflow, rejection of unresolved
copied forms, and the independently reviewed benign Swift WebView specimen.
The rebuilt stng CLI reproduces both strings (`arm-stng-frame-integration.json`).

The rebuilt Cleave scanner reports 4H/1S for the universal specimen and 0H/0S
for the benign control. **The malicious ARM-only slice still reports 0H/0S**: this
is insufficient extraction/detection coverage, not evidence of benign behavior.
The 296 copied ID loops, saved-register preservation, name byte tails and other
ARM-only encoded behavior remain unfinished work. No final training-pool move
or claim of complete ARM64 extraction has been made.

## Complete constant-input ARM64 loops enabled

The extractor now emits **297 of 298 extension-ID occurrences (276 distinct
IDs)** from the ARM slice, with cache version 36. The earlier requirement to
prove the later output-copy alias was unnecessary for recovering bytes already
fully determined by constant ciphertext, a folded constant key and a verified
complete bounded XOR loop. Extraction makes no claim of runtime execution or
consumption. The loop and matching-length checks remain in place.

The Fin Wallet For Sei ID `dbgnhckhnppddckangcjbkjnlddbjkna` (ordinal 91)
remains deferred because its saved-register seed is unresolved. No seed is
guessed. Name byte tails also remain unfinished. The framed-call review now
contains 60 recorded functions and six resolved imports; four targets remain
unrecorded in `arm-framed-call-closure.json`.

All 297 independent thin/fat source spans and public ARM-only outputs are
covered by tests, including duplicate IDs stored at different addresses. The
expanded span test initially selected the first duplicate by text alone; its
lookup now requires the exact oracle address as well. Full library: **637
passed, 3 ignored** (`arm-copied-loop-lib-tests.log`). Rebuilt stng CLI output
confirms every one of the 276 distinct IDs (`arm-stng-copied-loops.json`).
Cleave still reports 0H/0S for the malicious ARM slice (104 notable findings)
and 0H/0S for the benign control. Coverage remains insufficient.

The independently reconstructed 302-byte ARM password prompt is still absent
from native extraction; `arm-password-prompt.json` pins its exact bytes and
hash. That heap-XOR extraction gap is detection-critical and remains queued
alongside the one deferred extension seed and display-name decoding.

## ARM64 immediate heap-XOR prompt recovery

The ARM-only extractor now recovers the independently reconstructed 302-byte
compatibility/password prompt. Its SHA-256 is
`23627563d528164b23449ca26ef9a8202bafd87d2d64454165107b76a0a2987f`;
the thin instruction span starts at `0x28fa0` and covers 1468 bytes. The
original universal specimen remains in stng testdata. Cache version is 37.

`src/heap_xor/arm64.rs` recognizes complete constant array initialization and
the checked-index byte-XOR loop with its outlined helpers. Work is bounded by
8 MiB of code, 128 candidate attempts, 4096 bytes per array and at most
`2*length+8` initializer instructions. Recovery needs no external tools or
execution. The decoder rejects unsupported instruction sequences and malformed
text. Static recovery establishes plaintext, without claiming execution.

Nine new tests cover the independent plaintext and thin/fat spans, every
required instruction mutation, array/loop/helper mismatches, malformed text,
truncation, alignment, overflow, exact work limits, changed keys/registers,
argument/call register clobbers, the public ARM-only pipeline and benign control.
A review caught byte-register choices overwritten by argument setup or BL;
these now reject, with a regression test. Full library: **646 passed, zero
failed, 3 ignored** (`arm-heap-xor-lib-tests.log`). Both binaries were rebuilt
with that fix before the following CLI checks.

`arm-stng-heap-prompt.json` reproduces the independent prompt hash and retains
all 276 previously recovered distinct extension IDs. Cleave now reports
**1H/1S** on the ARM-only sample (compatibility-password-harvest and
password-phishing-comp), **4H/1S** on the universal sample and **0H/0S** on the
benign Swift control. See `arm-cleave-heap-prompt.json`,
`universal-cleave-heap-prompt.json` and `arm-heap-benign-cleave.json`.

ARM behavior coverage remains incomplete. The deferred saved-register seed,
display-name byte tails and other missing encoded behavior remain open; this
checkpoint does not claim complete extraction or final taxonomy validation.

## Native ARM64 immediate qword names

`src/pointer_xor/arm64/immediate.rs` now recovers the reviewed one-iteration
qword form: four MOV/MOVK immediates plus one constant-section byte form the
ciphertext, which is XORed with the independently folded eight-byte key. Exact
initializer, loop flag, outlined helper, stack store and matching consumer-length
checks are required. This form needs no inherited-register assumption. The
existing bounded setup search and key folder are reused; no additional scan or
runtime emulator was introduced. Cache version is 38.

The native ARM-only output recovers all nine names with exact 48-byte instruction
spans: Tronlink, Metamask, Coinbase, Backpack, D/Wallet, D-Wallet, V Wallet,
MetaMask and LastPass. The retained original and independent JSON oracle back
six new tests covering thin/fat evidence, all required instruction mutations,
semantic mismatches, malformed text, missing constants, truncation and arithmetic
bounds, changed keys/immediates, and the public ARM-only pipeline. Existing
candidate-budget and benign-control tests also pass. Full library: **652 passed,
zero failed, 3 ignored** (`arm-immediate-lib-tests.log`).

Both binaries were rebuilt. `arm-stng-immediate.json` matches every new name and
span and retains all 774 distinct prior XOR outputs. Cleave adds two accurate
notable brand references (Coinbase and MetaMask), with no prior findings lost:
ARM-only **1H/1S/113N**, benign Swift **0H/0S/12N**. See
`arm-cleave-immediate.json` and `arm-immediate-benign-cleave.json`. No trait edit
was needed for these newly exposed facts. Longer names, byte-tail forms, the
caller-dependent seed and wider corpus coverage remain open.

## Native ARM64 short integer tails

`src/pointer_xor/arm64/short_tail.rs` now handles all 68 reviewed nine-to-eleven-
byte name occurrences. It verifies the qword-loop prefix, folds the key with the
existing bounded folder, and evaluates the short integer tail with four
registers, eleven output bytes, two nested calls and at most 64 instructions.
The main evidence span is bounded to 128 bytes. Unknown instructions or values
reject. The shared 8 MiB code/1024 candidate-attempt limits remain in effect;
no new scan or unbounded evaluator is added. Cache version is 39.

Regression work found and accommodated actual compiler variations: separate
pointer and length argument helpers, a MOVZ beginning in the second halfword,
and an output buffer at SP+0x90 instead of SP+0x70. The consumer must point to
the buffer actually written; that buffer must not overwrite the qword source.
BFXIL rotation bits are checked explicitly. All output bytes must be known.

Six new tests use the retained original, plaintext oracle and independent
instruction-path fixture `rust_arm64_short_tail_expected.json`. They verify all
68 exact thin/fat instruction spans, mutate every executed instruction, exercise
altered keys, malformed/missing data, incorrect merges, unknown registers,
incomplete output, source/output overlap, consumer mismatch, recursion and the
exact 64-instruction boundary. Full library: **658 passed, zero failed, 3
ignored** (`arm-short-tail-lib-tests.log`).

Both tools were rebuilt. The CLI exposes all **67 distinct names** with valid
independent evidence spans and retains all 783 prior distinct XOR output values
(850 total). The existing public pipeline deduplicates the two NamiWallet
occurrences; native tests verify both source spans. See
`arm-short-tail-cli-check.json` and `arm-stng-short-tail.json`.

Cleave remains at ARM-only **1H/1S/113N**, universal **4H/1S/124N**, and benign
Swift **0H/0S/12N**. No existing ARM findings were removed and no traits were
changed. This improves recovered facts; it does not create a new independent
hostile behavior. Shorter five-to-seven-byte names, inherited-register/longer
names and the deferred ID seed remain open, alongside broader corpus work.

## Native ARM64 four-byte prefixes

The existing short-tail evaluator now also verifies four-byte XOR prefixes and
recovers all nine reviewed five-to-seven-byte names: Ambire, iWallet, Wombat,
MewCx, Phantom, Oxygen, BoltX, UniSat and Koala. It checks split initializers,
word-width loads/stores, the single-iteration loop, and the scratch-byte store
before the complete output copy. Checked 32-bit LSL and LSR operations handle
the seven-byte forms. The same 64-instruction/two-helper-depth bounds apply;
no additional runtime scan was introduced. Cache version is 40.

The independent instruction/span fixture now contains 77 short-tail occurrences
(68 earlier and nine new). Three new tests and the expanded all-instruction
mutation check cover original thin/fat spans, public ARM-only output, malformed
keys, width substitutions, shift truncation and reserved encodings. Full library:
**661 passed, zero failed, 3 ignored** (`arm-small-tail-lib-tests.log`).

Both tools were rebuilt. `arm-stng-small-tail.json` recovers every new name and
exact span, retaining all 850 prior distinct XOR values (859 total). Cleave
retains the same ARM-only **1H/1S/113N** findings and the benign Swift control
remains **0H/0S/12N**. No trait edits were needed. Together with the earlier
qword names this covers all 86 name occurrences whose decoding needs no
inherited register input. The 212 remaining names and one deferred ID seed
still need caller-state support; broader ARM/corpus and validation work remain
open.

## ARM64 direct string arguments: credential SQL

The remaining hostile-composite gaps were traced to missing exact SQL and salt
literals. Both SQL calls use ADRP/ADD into X2, a separate ADD-from-SP result
pointer into X0, then MOV W3 of the exact length before BL. The inline extractor
previously required an adjacent length instruction and recognized only the
64-bit MOVZ form. `arm-credential-literal-refs.jsonl` records the original code;
every instruction was checked against the retained ARM slice.

`src/instr.rs` now accepts zero-extending W lengths and the precise independent
stack-result setup. Immediate decoding rejects reserved W lanes, MOVK, and ORR
from a live register. Stored string headers also accept W lengths. Inline
candidates no longer survive intervening calls, branches, argument-register
clobbers or unsupported operations. The existing 20-instruction lookback stays
bounded. Cache version is 41.

Six new regression tests cover the original two credential queries with exact
thin/fat/public spans, W/X variants, branch/clobber barriers, width/source checks,
stored headers, truncation and length bounds. Full library: **667 passed, zero
failed, 3 ignored** (`arm-argument-lib-tests.log`). Both tools were rebuilt.
The ARM CLI now recovers all six reviewed SQL queries with exact boundaries.
Cleave adds login/card SQL references, Ledger/Trezor paths and a Rust unwrap
message: **1H/1S/120N**, with no previous findings removed. Those new raw spans
were checked. Ledger/Trezor references do not establish application replacement.
The benign Swift control remains **0H/0S/12N**.

The exact nine-byte salt at `0x1002aadfb` remains missing. Its X21 pointer is
formed at `0x100015c6c/70`, then passed as X1 with W2=9 to `0x100012448` at
`0x100015cb0`. A local zeroing loop and outlined context-copy call intervene.
Fresh disassembly of `0x1001bab9c`, `0x100012f14` and its three small helpers is
saved in `arm-salt-helper.jsonl`, `arm-salt-copy.jsonl` and
`arm-salt-copy-helpers.jsonl`. Native bounded preservation analysis for that
reference is the next extraction gap; traits were not loosened to compensate.

## ARM64 preserved constant-pointer arguments (cache 42)

Independent disassembly traced the nine-byte `saltysalt` pointer in X21 through
the local zeroing loop and context-copy helpers to the argument copy. Native
extraction now checks those register-write effects using the shared ARM decoder.
It does not assume ABI preservation or claim execution/all-path reachability.
The existing BL scan uses a cheap argument-shape prefilter; candidate attempts,
lookback, code size, helper cache, recursion, instructions and branches are bounded.
Unknown instructions and clobbers fail closed. Exact NOP is now supported.

Six new tests cover the retained original, thin/fat/public offsets, every relevant
instruction mutation, malformed inputs, both helper branches, clobbers, recursion
and exact work limits. Full library: **673 passed, zero failed, 3 ignored**.
`arm-preserved-checkpoint.json` records bounds and test/scan evidence.

Rebuilt CLI adds only `saltysalt`, verified against the nine original bytes at
thin offset 2797051; no prior strings disappear. ARM Cleave now reports
**4H/1S/121N**, universal **4H/1S/124N**, and benign Swift **0H/0S/12N**.
Three existing credential composites now match without trait changes. The 212
inherited-input names and one deferred ID remain open, as do broader corpus and
validation work. These are bounded-work regression results, not a production
throughput benchmark.

## Full ARM name caller-input audit

The 212 names formerly reconstructed with inherited-register assumptions now
have explicit caller provenance. Thirty non-leaf helpers were audited for all
X19..X29 registers: 29 preserve them and one explicitly assigns X19=SP+0xb0.
Two leaf helpers make the same assignment; original instruction words verify
those effects. A must-value dataflow pass over 15,909 caller instructions follows
both successors of every conditional, merges differing values as unknown, and
checks for direct re-entry from omitted later code. It resolves all stack aliases
and the additional constants used by 19 names, plus the deferred ID's X22 seed.

`reconstruct-arm-names-provenance.py` independently reconstructs all **298 names**
using only the checked caller inputs, X0 key and symbolic SP. It starts with no
inherited memory or guessed register defaults and agrees byte-for-byte with the
previous reconstruction. Existing ten frame checks and six new mutation checks
cover register resets, lost aliases and changed constants. Details and runnable
scripts are listed in `arm-name-provenance-checkpoint.json`.

This proof is conditional on normal control flow, the explicit imported C ABI
contracts and valid heap objects disjoint from owned stack frames. It does not
prove arbitrary memory safety, exceptions or that the code executes. Native
extraction remains unchanged: 212 names and one deferred ID still need a bounded
structural implementation; no sample-address allowlists have been added.

## Native stack-value tracking (cache 43)

`src/arm64_frame.rs` now tracks exact saved register tokens and bounded stack
slots for call-free framed helpers. Any overlapping byte/word/vector write
invalidates a saved token. Both conditional successors are checked; all returns
require restored SP and the original return-address token. Unknown stores,
nested calls, unsupported addressing and work exhaustion reject the precision
check. The existing inline literal helper cache invokes this only when its
conservative write summary touches SP and saved GPRs; rejection retains that
conservative summary. No additional whole-code scan is introduced.

Seven new tests cover register fields, original specimen save/restore sequences
and omitted-restore mutations, partial/vector overwrites, width distinctions,
both paths, malformed instructions, exact bounds and end-to-end framed literal
recovery. The original frame-sequence tests do not claim the full nested helper
bodies are supported. Full library: **680 passed, zero failed, 3 ignored**.

After rebuilding both binaries, ARM string output is unchanged (9861 entries).
All trait IDs remain unchanged on ARM **4H/1S/121N**, universal **4H/1S/124N**,
and benign Swift **0H/0S/12N**. Bounds and artifacts are recorded in
`arm-frame-native-checkpoint.json`. Checked nested-call/memory handling and caller
state integration remain necessary for the 212 names and one deferred ID.

## Bounded local calls in native frame tracking (cache 44)

Direct local BL calls now share the saved-slot model. Each RET must match the
recorded return address and call-entry SP. A child store can invalidate its
caller's saved pointer or LR; such writes are not hidden behind an assumed ABI.
The 128-instruction/8-branch global limits remain; local depth is limited to four
(the enclosing cheap write-summary gate currently permits two).

Three new tests cover child clobbers, caller-slot corruption, both branch paths,
wrong returns, unbalanced SP, recursion/unmapped calls and exact depth limits,
plus integrated literal recovery. Full suite: **683 passed, zero failed,
3 ignored**. Both binaries rebuilt. ARM string JSON is exactly unchanged and
all trait IDs are unchanged on ARM/universal/benign controls. The unresolved
imported-call contracts and full caller-state/name integration remain recorded
in `arm-frame-nested-checkpoint.json`.
