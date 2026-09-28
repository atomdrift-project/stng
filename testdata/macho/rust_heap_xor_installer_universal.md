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
register. It does not decode byte tails or ARM64-only files.

Limits are 8 MiB of x86 code, 1024 setup candidates, 24 helper instructions
within 128 bytes, and 512 bytes per literal. There is no external tool,
new dependency, key search, or general memory emulator. These limits bound
work; they are not a production throughput measurement.

The native output includes all IDs in the independently reconstructed 298-row
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
