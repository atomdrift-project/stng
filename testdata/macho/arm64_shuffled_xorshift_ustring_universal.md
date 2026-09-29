# Shuffled xorshift indexes in __ustring

Original universal Mach-O specimen, SHA-256
`ad79962c1152ec553c885f545f42c7b0672ca186399a0089401dca4952bd1f5e`.
Contains x86-64 and ARM64 credential-stealing AppleScript carriers. Do not execute.

The ARM64 alphabet's u16 permutation is at VA 0x10004242c in
`__TEXT,__ustring`; its encoded source is at 0x100040bb0 in `__const`.
Other permutation tables remain in `__const`. This catches an assumption that
all directly referenced tables share one section. Extraction uses verified
instruction addresses and bounded borrowed slices, without scanning the data
sections or copying them together.

Expected decoded strings on both architectures:

| Stage | Bytes | SHA-256 |
| --- | ---: | --- |
| VM gate | 536 | 22422ea28dc3168fca0f6633341402f35ad168770ad51960e030a9f94946e080 |
| Payload | 23874 | 5195a3d0dac1c124be1ae3396d1f17444c3accd141fd81769c57cdea4c1f2af4 |
| Cleanup | 22 | 20a60a29c697e89aeab8cc741327f19f84b599e628d175aab132f1551f1da29c |

Independent reconstruction and native analysis:
`/var/tmp/triage40/review/macho-ad799/`.
