# Bounded PE XOR recovery

`ExtractOptions::with_xor` includes an in-process x86 PE pass for small
repeating-key XOR decoders. It does not require Rizin, brute-force keys, or
execute a binary. The normal PE parse is reused.

A fast byte prefilter looks for four distinct immediate register assignments
followed by a direct call. Two assignments must be mapped file-backed pointers
and two must be bounded nonzero lengths. Assignment order and register roles
are not fixed. Only then does iced-x86 decode the callee and its helper routines.
The interpreter accepts a restricted integer/load/store/control-flow subset.
Unsupported instructions, unknown operands, non-file-backed memory, invalid
control flow, reads of modified bytes, self-modifying decoder code, and exhausted budgets discard the candidate completely.

Accepted output must be a complete, sequential in-place buffer transformation.
Every written byte must have provenance proving ciphertext XOR a separate,
contiguous repeating key. Both buffer length and key length must agree with the
setup arguments. These checks establish a decoding operation, not that the
program reaches it at runtime or that it is malicious.

Recovered ASCII and ASCII-subset UTF-16LE strings use the existing `XorDecode`
method. Their `data_offset` and `data_len` describe ciphertext, and
`source_spans()` includes both the ciphertext extent and the key extent. They
remain decoded content references, never PE imports or confirmed calls.
Callers that cache stng's output (filefacts) key it on the stng commit, so new
output never meets stale entries.
No fields or allocations are added to the common `ExtractedString` layout.

## Per-file limits

- x86 PE only, at most 96 sections; skip Go PE and an explicit caller XOR key.
- Scan at most 4 MiB of executable section bytes and 65,536 CALL-byte anchors.
- Interpret at most four candidates, sharing 262,144 instruction steps.
- At most 128 decoded instructions, 32 stack slots and 16 KiB output per candidate.
- Keys must be 1–64 bytes and wrap at least once in the output.

Ordinary misses do not allocate interpreter state or disassemble code. The
work limits are shared across sections, so section/candidate multiplication
cannot bypass them. These are deliberate coverage limits: x64, stack-passed
arguments, noncontiguous setup instructions, heap buffers, other ciphers, and
arbitrary unpacking are outside this implementation.

## Validation and profiling

`cargo test --lib pe_xor` exercises inline and split-helper loops, changed keys,
image bases, offsets, register roles, setup order, wide strings, malformed
mappings, unsupported calls/instructions, incomplete decoding and infinite loops.

Run the isolated, optimized microbenchmark with:

```sh
cargo test --lib pe_xor::tests::benchmark_prefilter_and_recovery -- --ignored --nocapture
```

The repository's test profile is optimized. Timings isolate the new pass and
exclude PE parsing, normal string extraction and caches; they are not end-to-end
throughput claims. `STNG_XOR_SAMPLE` optionally benchmarks an analyst-supplied
specimen. `STNG_XOR_FIXTURE_OUT` writes the inert synthetic decoder fixture used
by filefacts' cache/provenance integration test. Neither test executes a sample.
