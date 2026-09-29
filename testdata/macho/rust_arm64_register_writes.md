# ARM64 register-write oracle

`rust_arm64_register_writes.bin` contains 13,064 records of two little-endian
`u32` values: an instruction word followed by its GPR-write mask. Bit 31 denotes
SP; writes to XZR/WZR and vector registers do not set GPR bits. Loads with
writeback include the base register, and paired loads include both destinations.
BL includes X30. Flags and memory effects are outside this fixture's scope.

Fixture size: 104,512 bytes.
SHA-256: `6ab047751369f7ff63c16dfcb684ced5c28f77da63f5d02e9264e9cbc2e4f1bd`.

The words come from the independently reviewed ARM64 table builder and its
outlined helpers in `rust_heap_xor_installer_universal.macho` (original SHA-256
`78371a85a51dee581823243272525e119ce88255e2ad75bc5980870681999970`). They represent
21,138 recorded instruction occurrences, deduplicated by word. Expected masks
were derived from Rizin disassembly operands before the native effect decoder
was implemented. The readable source artifact is
`/var/tmp/triage40/review/macho-rust-heap-xor/arm-register-write-oracle.json`.
No sample instructions were executed.

This is a write-footprint oracle, not evidence of register preservation or
control-flow reachability. `src/pointer_xor/arm64/effects.rs` compares every
record and separately tests register fields, SP/zero-register distinctions,
writeback modes, pair destinations, and rejection of unsupported encodings.
