# Paired arithmetic decoder regression specimen

Original malicious universal Mach-O, retained for static analysis only.
SHA-256: `ddfe3bd14685967a31dc1c9b2fabd68c3df6d9294a5eb7324d02b258507b97ae`.

This paired specimen exercises a second independently decoded table set. See
`arithmetic_variants_expected.json` for complete stage hashes, lengths, source
spans and offsets obtained during the manual native-code review. The dispatcher
pair also has a different inclusive payload loop bound. Tests never execute it.

Coverage is in `src/lcg_xor/arithmetic_variant_tests.rs`: exact outputs and
provenance, public extraction, complete instruction/branch/bound mutations,
malformed arrays/permutations, valid alternative permutations, minimum length
and offset overflow. Both dispatcher architectures are covered.
