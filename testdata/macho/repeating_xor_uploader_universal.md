# Universal repeating-XOR uploader fixture

SHA-256: `4a6250d7dab7d82255cc526f6b857af8f53378c186700dd8682408180b92cb6a`.
Untrusted malware fixture; static extraction only.

x86_64 is the first slice (offset 16,384, size 32,032), byte-identical to
`x86_repeating_xor_uploader.macho`. ARM64 is the second (offset 49,152, size
69,152), byte-identical to `arm64_repeating_xor_uploader.macho`.

Both slices were reverse engineered independently. All 17 initialized constants
and the main control flow agree. Both native decoders now recover 14 strings at
the default minimum length of four, including the remote AppleScript pipeline
and chunk-upload command. Universal extraction deduplicates these values and
retains the first slice's evidence: thin x86 spans plus 16,384.

This fixture also preserves the former FAT iteration bug: extraction stopped
after the first architecture. Before the x86 decoder was added, fixing iteration
exposed all 14 strings through the second, ARM64 slice. The historical audit
`fat-offset-audit.json` records ARM64 spans plus 49,152; the current audit
`x86-extraction-audit.json` records the first-slice spans. Both are in
`/var/tmp/triage40/review/macho-xor-upload-universal/`.

Eight shared regression tests now cover both architectures and both variants
in `src/repeating_xor_tests.rs`. No production throughput benchmark performed.
