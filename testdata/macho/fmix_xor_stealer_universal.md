# Universal ARM64/Intel MurmurHash3-keystream stealer

SHA256 bfc96a7fa7aaf817b083b72d71f58c3b962d3192ae6f79b6abda9911d73b1ea9.
Malicious sample: static analysis only. Tests read it at runtime; never embed
it with `include_bytes!`. AMOS-family macOS stealer (Swift UI, C++
collectors, miniz archives, fake authorization prompt, C2 109.238.87.110/111).

Every string is a record `seed: u32 LE | ciphertext | encrypted NUL | zero
padding to 4`. Byte i decrypts as `c ^ fmix(prev * 0x85ebca77 + seed + i *
0x9e3779b9)` with `prev` = seed low byte, then the previous ciphertext byte;
fmix is MurmurHash3's finalizer (shifts 16, 13, 8; multipliers 0x85ebca6b,
0xc2b2ae35). The ARM64 slice inlines 391 loops (388 data records, 3 stack
immediates of at most 3 characters); records live in `__TEXT,__const` in both
slices. Intel keeps short strings as records too, so it yields a few more.
