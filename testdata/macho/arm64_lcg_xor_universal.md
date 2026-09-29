# Universal ARM64/Intel LCG-XOR launcher

SHA256 a4c3c55d1ca3e406fa8db67d6b8ec395ebb2d8ba76f835bae987733d71ee8fb1.
Malicious sample: static analysis only. Both slices decode the same 19775-byte
osascript command followed by NUL. ARM64 starts at FAT offset 65536; ciphertext
at slice offset 0x3238, length 0x4d40. Seed 0xb853, multiplier 0x11bcb,
mask 9; ARM64 modulus 0x92fc, reciprocal 0x37bbdb51, shift 45. Intel uses
modulus 0x92fb. Update state with 32-bit wrapping multiplication.

ARM64 extraction requires the full verified 13-instruction loop, register
setup, length, and ADRP/ADD source address. No brute-force constants, entropy
pass, external disassembler, or sample execution. Scan at most 1 MiB code,
read at most 8 MiB payload, validate a 96-byte stack preview before allocating.
