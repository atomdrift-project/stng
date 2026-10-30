# Rust heap-array and pointer-derived XOR fixture

Universal x86_64/arm64 Mach-O, retained for static analysis only.
SHA-256: `78371a85a51dee581823243272525e119ce88255e2ad75bc5980870681999970`.
Source: the `.back/installer` in MalwareBazaar DMG
`230081198d15ae14d9eaae5339298a1879555b232732bbfd48418a38b8b65685`.
The x86 slice starts at file offset 8192. No sample code was executed.

The binary hides a password prompt, browser-extension IDs and names, upload
URLs and credential SQL behind several compile-time obfuscation schemes. Each
recognizer below matches the code this one rustc/LLVM build emitted; its tests
record which parts are fixed and which registers it reads from the code.

## Heap-array XOR (`src/xor/heap.rs`, `src/xor/heap/arm64.rs`)

At x86 VA `0x10003bb50`, two 302-byte arrays are allocated and filled with
immediate stores; the loop at `0x10003c02c` applies `b[i] ^= a[i]` through a
checked-index helper. The result is passed to `osascript -e`:

```applescript
display dialog "The current version of the app is not fully compatible with your version of MacOS.

For the app to work correctly please, enter password of your system." with title "Application Error" default answer "" with icon caution buttons {"Continue"} default button "Continue" with hidden answer
```

The ARM64 slice builds the same prompt (SHA-256
`23627563d528164b23449ca26ef9a8202bafd87d2d64454165107b76a0a2987f`) from an
instruction span starting at thin offset `0x28fa0`. Both recognizers require
complete array initialisation, matching allocation sizes, the full bounded
loop and the checked-index helper. Limits: 8 MiB of code, 128 candidates,
4096-byte arrays.

## Pointer-derived constant XOR (`src/xor/pointer.rs`, `src/xor/pointer/arm64/`)

Extension IDs, their display names and upload URLs are XORed with a key whose
address a short helper computes from a base and seed. An eight-byte setup
signature gates a strict grammar: key base and seed setup, stack
initialisation, a complete qword XOR loop, and a matching literal length at
the consumer. Ciphertext and key must lie inside Mach-O constant sections.
Limits: 8 MiB of code, 1024 setup candidates, 512 bytes per literal.

x86 recovers the ID in all 298 rows of the reconstructed target table (277
distinct IDs) and three URLs. Most display names end in byte tails, which the
x86 grammar does not decode.

| Ciphertext VA | File offset | Decoded URL |
| --- | ---: | --- |
| `0x1002b6a1a` | 2853402 | `https://cloudproxy.link/m/opened` |
| `0x1002b6a85` | 2853509 | `https://cloudproxy.link/m/decode` |
| `0x1002b6ad5` | 2853589 | `https://cloudproxy.link/db/debug` |

ARM64 recovers 383 of the 596 rows in `rust_pointer_xor_arm64_expected.json`
(IDs and names, independently reconstructed): qword loops, one-iteration
immediate forms (`immediate.rs`) and short byte tails (`short_tail.rs`). Not
recovered: 212 names whose decoding depends on caller register state, and the
ID `dbgnhckhnppddckangcjbkjnlddbjkna`, whose seed comes from a saved register.
No seed is guessed.

## Literal arguments (`src/instr/`)

- x86: the 62-byte `SELECT origin_url, username_value, password_value FROM
  logins;` at VA `0x100017996` is loaded with `push 0x3e; pop rcx` before the
  call, one stack-address `lea` between.
- ARM64: credential SQL passed as ADRP/ADD into X2 with `mov w3, #len`, and
  the nine-byte `saltysalt`, whose pointer X21 survives a zeroing loop and
  context-copy helpers before becoming an argument (`arm64_preserved.rs`,
  with `src/arm64/frame.rs` tracking saved registers and stack slots).

## Rust slice headers in `__DATA,__const`

This binary keeps its slice headers in `__DATA,__const` rather than
`__DATA_CONST,__const`; the Rust extractor reads both. For example the pair
`(0x1002b2b4a, 25)` at VA `0x1003abc60` yields `/Local Extension Settings`
at file offset 2837322.

## Tests

`src/xor/heap/tests.rs`, `src/xor/heap/arm64/tests.rs`,
`src/xor/pointer/tests.rs`, `src/xor/pointer/arm64/tests.rs`,
`src/rust/triage_tests.rs`, `src/instr/amd64/push_length_tests.rs`,
`src/instr/arm64/argument_tests.rs`,
`src/instr/arm64_preserved/tests.rs` and `src/arm64/frame/tests.rs` pin the
recovered values, their exact source spans in thin and fat files, mutations
of every required instruction, and the work limits.
