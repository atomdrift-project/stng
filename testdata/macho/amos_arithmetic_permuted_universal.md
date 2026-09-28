# AMOS permuted arithmetic tables

Malicious universal x86_64/arm64 Mach-O retained for static analysis only.
SHA-256: `4da3f063566aeeca35c172aa0aa468bac72972607f7d395043d9f1dcbc593532`.
Source: August 2025 abuse.ch corpus in the triage input.

The x86 entrypoint at `0x100001df0` reconstructs four hex strings from three
u32 arrays and a fourth array of indices. Its unrolled loop computes the low
byte of `(A[index] - C[index]) ^ B[index]`, writing to `output[index]`.
The index arrays are complete permutations. Their order therefore changes
visitation order without changing the final output. The alphabet loop starts
at zero; the other loops start at one and load indices at offsets -4 and 0.
The extractor validates both compiler forms and the entire permutation before
decoding in index order. Addresses and bounds come from instructions.

The decoded alphabet has 64 unique bytes and is used for custom Base64
decoding of the three remaining hex strings. Independent static decoding:

| Stage | Length | SHA-256 |
| --- | ---: | --- |
| VM gate | 536 | `22422ea28dc3168fca0f6633341402f35ad168770ad51960e030a9f94946e080` |
| AppleScript | 23862 | `43c1519d82bcb8a05135d88adefe6c6c9a4d00d29b370bba45d9ed3454074ca8` |
| Terminal cleanup | 22 | `20a60a29c697e89aeab8cc741327f19f84b599e628d175aab132f1551f1da29c` |

The VM gate controls execution of the remaining stages. The AppleScript
matches the September arithmetic fixture except for campaign identifiers:
credential phishing, sensitive-store collection and upload, Ledger Live
replacement and a root LaunchDaemon. The specimen was never executed.

The paired sample `72967172020b2dfc4a622623c5dafe28ff7e53c26b42b68008ae7d715ee85ba4`
has byte-identical x86 code and different ciphertext tables. Its payload hash
is `35549a8fa7bf5a3770056ed82c8d5610e7dde657a03e44b6cd1caa1fa1838051`;
the gate and cleanup hashes are identical.
