# ARM64 short-tail instruction oracle

Retained specimen: `rust_heap_xor_installer_universal.macho`.
Universal SHA-256: `78371a85a51dee581823243272525e119ce88255e2ad75bc5980870681999970`.
ARM slice SHA-256: `51563b6cc5f7799124391a0d1884692d66b1fb39b44289977e99527abf16589a`.

The JSON records 77 independently reconstructed five-to-seven and nine-to-eleven-byte names by
ordinal in `rust_pointer_xor_arm64_expected.json`, exact main instruction spans,
and unique executed instruction addresses. Those paths came from the analyst's
ARM-only reconstruction before native tail support was written. Every listed
instruction was checked against the retained specimen bytes. Expected plaintext
is in the existing pointer-XOR oracle, not derived by the native implementation.

Tests assert every span and reject mutations of every listed instruction. The
public CLI deduplicates the two NamiWallet occurrences, yielding 76 names; the
native extraction tests retain and check both original occurrences.

The nine four-byte-prefix cases were added from the same pre-existing independent
reconstruction, with every instruction checked against the retained ARM bytes.
