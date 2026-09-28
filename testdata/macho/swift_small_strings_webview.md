# ARM64 Swift small-string fixture

SHA-256: `e804a52fe033d7e99f4e51c5b7f70bd5101e61de1478f5c619219fea8ef8a957`

Source: triage40 e804a52fe033 specimen, standalone Swift WebView executable.
This fixture is for static extraction only. The submitted native module was
reviewed as good; the referenced HTML bundle resource was not provided, so that
page and the whole app bundle are outside the verdict.

The native code constructs Swift inline ASCII values in adjacent registers using
MOVZ/MOVK and an explicit length/discriminator byte. Expected extracted values
and source spans (file offsets, hexadecimal):

| Value | Span |
|---|---|
| `index` | 0x1ee8–0x1ef8 |
| `html` | 0x1ef8–0x1f04 |
| `username` | 0x1fd4–0x1fec |
| `.private` | 0x21ec–0x2204 |
| ` but found ` | 0x3680–0x369c |

The native app reads ~/.private as UTF-8, trims whitespace, and passes its value
as a username query item to bundled index.html. Missing/empty file contents use
the literal `standart`. That fallback crosses calls/branches and deliberately
falls outside this extractor's straight-line grammar.

`swift_small_strings.rs` emits Structure provenance (explicit tagged string
layout), preserving short values through normal garbage filtering. It accepts
only ARM64 Mach-O files containing Swift type metadata, at most 1 MiB of code,
16 instructions of constant lifetime, and 4,096 results. There are no external
processes, dependencies, unbounded searches, or allocations before output beyond
existing Mach-O section enumeration. Unicode, pointer-backed Swift strings,
interprocedural values, and x86 Swift small strings are not covered.

Native stng static extraction and offline stng/cleave builds were used during
authoring. No unit tests were added or run; no production throughput benchmark
was performed.
