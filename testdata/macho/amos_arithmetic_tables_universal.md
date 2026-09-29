This static-analysis fixture is the malicious universal x86_64/arm64 Mach-O sample
`eb784deb84a4aa892ef26901619688f124b51ec460e60076a7c24aa08da2f98c`.
It was copied from the September 2025 abuse.ch corpus in the triage input.

The x86 entrypoint constructs a custom alphabet, a VM-check command, an
AppleScript infostealer, and a Terminal-cleanup command. Each output byte comes
from three u32 tables: `((a - c) ^ b) - b`, followed by hex and custom Base64
decoding. Table addresses and loop bounds are visible in the decoder code.
The sample was analyzed statically, not executed.

The regression checks compare complete recovered stages with hashes from the
independent manual decode, verify thin/universal offsets, and reject a changed
arithmetic instruction or an out-of-range table reference.

ARM64 coverage added after independent reconstruction of all four tables. The
ARM slice begins at 819200 and is 844232 bytes long. Its byte-offset, scaled-index
and advancing-pointer loops implement the same transform and recover identical
stages. `tests/test_macho_arm64_arithmetic.rs` checks exact bytes/digests, source
spans, thin/FAT public extraction with the x86 decoder disabled, every loop/setup
instruction mutation, register/slot/branch mismatches, bad counts/tables/hex,
UTF-8/control rejection, minimum length, overflow, section limits, truncation,
and a benign Swift control. A unit test checks the eight-candidate cap. The
ignored timing test measures extraction on already-parsed inputs.
