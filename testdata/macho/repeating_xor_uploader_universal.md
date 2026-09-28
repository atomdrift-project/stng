# Universal repeating-XOR uploader fixture

SHA-256: `4a6250d7dab7d82255cc526f6b857af8f53378c186700dd8682408180b92cb6a`. Untrusted malware fixture; static extraction only.

x86_64 is the first slice (offset 16,384, size 32,032). ARM64 is the second
(offset 49,152, size 69,152), byte-identical to
`arm64_repeating_xor_uploader.macho` (SHA `4a187d1d3dcc1e684a3a9e7bade340d032d6b77a7a232067eb55f85685c971ca`).

This exercises universal-file iteration: the ARM64 decoding pass must run even
when the first slice uses an unsupported encoding. Expected: 14 XOR-decoded
strings, including curl-to-osascript and the chunk-upload command. Their source
spans must equal the standalone ARM64 spans plus 49,152. The static extraction
comparison is recorded in the triage review's fat-offset-audit.json.

The x86_64 slice was independently reviewed; all 17 initialized strings and its
control flow match the ARM64 behavior. Standalone x86_64 helper extraction remains
a known unsupported case. No unit tests added or run for this fixture.
