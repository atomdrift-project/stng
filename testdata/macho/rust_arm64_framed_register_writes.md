# ARM64 nested framed-callee write oracle

`rust_arm64_framed_register_writes.bin` contains 201 records, each two
little-endian `u32` values: instruction word and GPR/SP-write mask. Its 1,608
bytes have SHA-256
`9ee6da6ea93282f4d33dace64dad2ad847ca7a41954e121b853c98e5c6ff7bb8`.

The instructions come from nested allocation/vector-growth routines in the
retained `rust_heap_xor_installer_universal.macho` specimen, SHA-256
`78371a85a51dee581823243272525e119ce88255e2ad75bc5980870681999970`.
Expected masks were derived from independently recorded Rizin instruction
operands. The generator first pins the ARM slice hash and checks each recorded
instruction's bytes against the original. It does not execute specimen code.

Readable evidence and generator:
`/var/tmp/triage40/review/macho-rust-heap-xor/arm-framed-register-write-oracle.json`
and `build-framed-write-oracle.py` in the same directory. The four disassembly
batches are `arm-framed-callees.jsonl` and `arm-framed-callees-{2,3,4}.jsonl`.

This fixture tests write footprints, including UMULH and conditional selects.
It does not establish framed-call preservation, imported ABI contracts, or
nonreturning error paths. Those remain separate caller-state work.
