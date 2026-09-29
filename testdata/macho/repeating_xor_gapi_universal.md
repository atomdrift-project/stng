# Second repeating-XOR uploader specimen

SHA-256: `d29ae5317de4d11481e1fde1961dd85b56c364cb8467f9771ec97bfdb792e486`.
Original universal Mach-O, retained for static analysis only. Do not execute.
Both architectures and all 17 constants were independently reverse engineered
in `/var/tmp/triage40/review/macho-gapi-update/`. The primary domain and build ID
differ from `repeating_xor_uploader_universal.macho`.

`repeating_xor_gapi_expected.json` preserves the independently reconstructed
ciphertext, four-byte key and full plaintext for each constant. The companion
`repeating_xor_expected.json` preserves the same evidence for the first variant.
These are test data, not commands to run. `src/repeating_xor_tests.rs` verifies
the original specimen hashes, all constants on both architectures, exact rebased
provenance, FAT second-slice traversal, helper signatures, malformed inputs,
synthetic disjoint-buffer calls and hard work limits.
