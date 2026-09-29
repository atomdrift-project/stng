# Shuffled xorshift / custom Base64 stages on both architectures

Actual hostile universal Mach-O, SHA-256:
`1d24320db02da6a181abbfe2dfee898231d3cc95af6067fbe97a298b87c2eb8a`.
Preserved for static extraction; never execute it or recovered commands.

Both architectures reconstruct four hex strings using xorshift64 shifts
12-right, 25-left, 27-right; a seed warm-up; source bytes at stride two;
and a complete u16 destination permutation. The byte is
`(source[2*i] - 7 - 3*i) ^ (state * 29)`, modulo 256.
The hex-decoded 64-byte alphabet decodes the other three strings as Base64.
Native addresses and full stages were independently reconstructed in
`/var/tmp/triage40/review/macho-1d243/reconstruct.py`.

| Stage | Length | SHA-256 |
| --- | ---: | --- |
| VM gate | 536 | `22422ea28dc3168fca0f6633341402f35ad168770ad51960e030a9f94946e080` |
| AppleScript | 23874 | `873d8880d494887ec33291cc88063de732054450a368f176fe8d84d495bb162c` |
| Terminal cleanup | 22 | `20a60a29c697e89aeab8cc741327f19f84b599e628d175aab132f1551f1da29c` |

The slice bases are 0x1000 (x86-64) and 0x48000 (ARM64). Thin ARM64 source
offsets: alphabet 0x40b60, gate 0x40e50, payload 0x28a0, cleanup 0x40d60.
Thin x86 source offsets: alphabet 0x40fb0, gate 0x412b0, payload 0x2cf0,
cleanup 0x411b0. Whole-file offsets add the relevant slice base.

The payload phishes the account password, copies browser/wallet/keychain/Notes
and Telegram data, posts an archive, replaces Ledger Live and installs a root
LaunchDaemon. Remote replacement/agent payloads were unavailable.

ARM64 extraction validates the complete bounded instruction loop, setup,
register relationships, back edge and permutation. Limits: 32 KiB code,
512 KiB constants, eight candidates, 65,536 output positions per candidate.
No disassembler dependency, emulation or seed search. x86 cleanup extraction
runs only after the existing gate and payload decoders succeed.
