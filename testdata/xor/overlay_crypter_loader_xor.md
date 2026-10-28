# overlay_crypter_loader_xor

**Source**: Linux crypter stub delivering a Mirai-family DDoS bot (2026)
**SHA-256**: `a3c64998a58595b7a6c2d16db68a767a87c9f3c3eb89784870ce51667a09d15b`
**Size**: 228,572 bytes, stored gzip-compressed

## What is this?

A live, unmodified static-pie musl x86-64 ELF loader. Never execute it. Its
encrypted overlay (about 82% of the file) holds the bot; the stub reads its own
image, checks an HMAC over a 33-byte trailer, decrypts and decompresses the
payload, and runs it from a memfd (`fexecve`), falling back to a hidden temp
file.

## Why it is here

The stub hides the paths it needs behind a NUL-terminated single-byte XOR
(key `0x26`, `&`), decoded at runtime by `decode_str`
(`xor ecx, 0x26` in a byte loop). The encoded strings are short and packed in
`.rodata`, `/tmp/.b` and `/proc/self/exe` only one NUL apart:

| Offset | Decoded |
|---|---|
| `0x59e8` | `/proc/self/fd/` |
| `0x59f8` | `/var/tmp/.b` |
| `0x5a08` | `/tmp/.b` |
| `0x5a10` | `/proc/self/exe` |

Before the fixes this sample guards, stng decoded none of them:
- Raw NULs decode to the printable key byte, so expansion ran through every
  terminator.
- The `%PROGRAMDATA%` near-miss check rejected every `/proc` decode.
- The 10-byte minimum dropped `/tmp/.b`.

`tests/it/overlay_crypter_loader_xor.rs` asserts all four, found without a key
hint.
