# x86_64 repeating-XOR uploader fixture

SHA-256: `09cae9413387356f4a1f138be252b8a2ffe8f61990cc353738776bfaeeee761d`.
Size: 32,032 bytes. Untrusted malware fixture; static extraction only.

This is the first slice of `repeating_xor_uploader_universal.macho`, copied from
file offset 16,384. Ghidra review covered the complete application code and both
XOR helpers. All 17 initialized constants were reconstructed independently from
the instruction operands before implementing native extraction.

Expected: 14 XOR-decoded strings with the default minimum length of four, or 17
with minimum length one. These include the curl-to-osascript pipeline, the dd /
curl PUT chunk-upload command, `/tmp/osalogging.zip`, and `/tmp/.httpcode`.
The short constants are `%d`, `r`, and `w`. All values agree with the ARM64 slice.
Thin source spans must equal universal source spans minus 16,384 after value
deduplication selects the first slice's evidence.

`src/x86_repeating_xor.rs` recognizes the complete 69-byte helper at virtual
address 0x100001270. The signature gates instruction decoding and state allocation.
Limits: 1 MiB text, 16 helpers, 8 KiB tracked stack, 4 KiB literal, 32-byte key,
512 direct calls, and 64 KiB output. Unknown operations invalidate state;
memcpy requires a resolved import stub. No external analysis process is used.
This supports one compiler helper shape, not arbitrary x86 XOR implementations.

Independent evidence: `/var/tmp/triage40/review/macho-xor-upload-universal/`
(`x86_64.c`, `x86-decoded-constants.json`, `x86-extraction-audit.json`).
Eight shared regression tests now cover both architectures and both variants
in `src/repeating_xor_tests.rs`. No production throughput benchmark performed.
