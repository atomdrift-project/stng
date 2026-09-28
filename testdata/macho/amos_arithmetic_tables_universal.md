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
