# ARM64 call-free helper write oracle

`rust_arm64_helper_writes.bin` contains 722 packed records: a little-endian
`u64` helper address followed by a little-endian `u32` GPR/SP-write mask. Its
8,664 bytes have SHA-256
`b39a3a3161d2850ebd0844ec54f23f14b62c96db2f0b34b4a74f2974b32608e4`.

The original specimen is `rust_heap_xor_installer_universal.macho`, SHA-256
`78371a85a51dee581823243272525e119ce88255e2ad75bc5980870681999970`.
Masks were derived independently from recorded Rizin disassembly and the
register-write oracle: follow both conditional paths and direct tail branches,
union reachable writes, and exclude calls or unrecorded targets. The readable
source is `/var/tmp/triage40/review/macho-rust-heap-xor/arm-helper-write-oracle.json`.
The largest included helper closure has 17 instructions. No specimen code ran.

These masks prove only which registers are untouched on return. They do not
recover values, recognize stack save/restore, or establish termination. The
native summary has a 128-instruction/eight-branch budget and rejects unsupported
instructions, calls and unmapped targets. Its per-code-region cache keeps at
most 1,024 summaries, including unknown results.
