# XOR-embedded universal Mach-O dropper

Wrapper SHA-256: `30c99015f9c432604d8a8206ce8dcb4fba7866b062e5bd1a8f0adb88fba8807c`.
Untrusted malware fixture; static extraction only. Size: 227,184 bytes.

The reviewed `xeryna` function copies 153,824 bytes from file offset 0x6210,
XORs every byte with the global key 0x9c, writes `/var/tmp/exe`, makes it
executable, invokes it, and removes it. The recovered image is a universal
Mach-O with x86_64 and ARM64 slices. SHA-256:
`5f522222dd8c3237058f7b7b00e717d1365f14aea6f45e41c9f982dd866cb8c0`.

The existing string pass recovers an XorKey observation at offset 0x6210 and
raw strings from this image. `decode_xor_fat_macho` exposes the same validated
binary recovery to consumers. It takes an already located candidate and key,
uses the FAT architecture table for the exact extent, caps output at 32 MiB,
and requires every slice to parse as Mach-O. Zero keys are rejected.

Independent manual XOR and the native API produce identical bytes. Regression
coverage in `tests/it/xor_fat_macho.rs` includes the original specimen and
output hashes, key provenance, malformed tables and slices, truncation,
arbitrary keys and size limits.
