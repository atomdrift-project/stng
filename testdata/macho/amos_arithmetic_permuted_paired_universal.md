# Paired arithmetic decoder regression specimen

Original malicious universal Mach-O, retained for static analysis only.
SHA-256: `72967172020b2dfc4a622623c5dafe28ff7e53c26b42b68008ae7d715ee85ba4`.

This paired specimen exercises a second independently decoded table set. See
`arithmetic_variants_expected.json` for complete stage hashes, lengths, source
spans and offsets obtained during the manual native-code review. The dispatcher
pair also has a different inclusive payload loop bound. Tests never execute it.

Coverage is in `src/lcg_xor/arithmetic_variant_tests.rs`: exact outputs and
provenance, public extraction, complete instruction/branch/bound mutations,
malformed arrays/permutations, valid alternative permutations, minimum length
and offset overflow. Both dispatcher architectures are covered.

## ARM64 permutation regression coverage

Cache version 33 adds four-way ARM permutation loops and two constant-folded
VM-gate tail writes. Both ARM slices start at 1097728. The 536-byte gate,
23862-byte payload and 22-byte cleanup exactly match the independently recovered
x86 stages above. Thin source offsets are 0xfce90, 0x39d0 and 0xfcad0; spans
are 5720, 254528 and 240 bytes. Seven arm_permutation tests in
src/lcg_xor/arithmetic_variant_tests.rs cover hashes/provenance, public thin/FAT
extraction, every setup/loop/tail instruction, invalid and reordered indexes,
unused table entries versus literal writes, malformed operands/data and limits.
Independent ARM reconstruction and native review: /var/tmp/triage40/review/macho-4da3-arm/.
