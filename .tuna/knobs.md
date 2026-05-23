# Edit allowlist for implementing agents (stng)

The proposer hands ideas to a coding-agent (gemini by default) which
edits files inside the worktree. The agent has wide latitude in *how*
to realize an idea, but the following boundaries are enforced.

## May edit

- `src/**/*.rs`
- `Cargo.toml`
- `Cargo.lock` (let cargo regenerate after dep changes)
- Anywhere under a Rust source tree the proposer named explicitly via `hints`.

## Must not edit

- `tests/**` — never weaken test coverage to make a perf change pass.
- `.github/**` — CI changes are out of scope.
- `Makefile` — bench targets are the contract; changing them invalidates the measurement.
- `benches/**` — criterion benches are a separate measurement contract.
- `vendor/**` — vendored sources are locked.
- `testdata/**` — fixture files; changes invalidate the bench corpus.
- `media/**` — docs/assets, not perf-relevant.

## Trigger an auto-revert

`cleave-tuna` reverts the experiment without benchmarking if:

- `cargo check` fails.
- `cargo test --lib` fails.
- The agent produced no changes after its run.
- Diff touches any path in the "must not edit" list.

## stng-specific guardrails

- The `#[global_allocator]` declaration in `src/main.rs` is load-
  bearing for heap profiling. Tuna's memory-mode hotspot data depends
  on `tikv_jemallocator::Jemalloc` being the active allocator with the
  `jemalloc-prof` feature available. Don't replace it.
- The directory walk in `src/main.rs::main` is what cleave-tuna's
  bench invocation exercises. Refactoring it is fine; removing the
  `path.is_dir()` branch would break the bench.
