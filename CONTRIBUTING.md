# Contributing

## Setup

You need Rust 1.97 (`rust-toolchain.toml` selects it under rustup) and a C
compiler: tree-sitter and its Lua grammar, and jemalloc for the command, build
from C sources.
[cargo-nextest](https://nexte.st/) and
[cargo-machete](https://github.com/bnjbvr/cargo-machete) are optional; `make`
uses them when they are installed.

```bash
make install-precommit   # runs scripts/check-overrides, make test, make lint
make test                # unit, integration and doc tests
make lint                # rustfmt, clippy (crate and library alone), rustdoc, machete
make deny                # advisories, licences, dependency sources (cargo-deny)
```

CI runs `make lint` and the same tests on the same toolchain, so a clean local
run means a clean CI run.

## Changing output

`tests/golden.tsv` fingerprints stng's output for every fixture, in two
configurations. Any change to what stng reports fails `golden` until it is
reviewed and accepted:

```bash
scripts/golden-diff                      # which strings changed versus HEAD
STNG_GOLDEN_DUMP=/tmp/after cargo test --test it golden   # dump full output
STNG_BLESS=1 cargo test --test it golden                  # accept the change
```

Bless only after reading the diff, and say in the pull request what changed and
why it is better. Never adjust a test's input to make a test pass.

`tests/it/ioc_corpus.rs` lists the exact indicators `extract_iocs` reports for
a set of samples. A change there fails the test with the actual list; update
the expected entries by hand, with the same review as a golden change.

`tests/hostile_input.rs` mutates every fixture and fails on any panic;
`STNG_MUTANTS` and `STNG_MUTANT_FILTER` widen or narrow it.

## Fuzzing

`fuzz/` holds a [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) target
that runs every extraction mode over arbitrary bytes. CI runs it nightly.

```bash
cargo install cargo-fuzz
cd fuzz && cargo +nightly fuzz run extract              # until stopped
cargo +nightly fuzz run extract artifacts/extract/crash-…  # replay a crash
```

Add the input of any crash you fix to `fuzz/corpus/extract/`, and a regression
test beside the code.

## Tests

- No `#[ignore]`: fix the gap, or don't add the test.
- Platform-specific tests use `#[cfg(...)]`.

## Fixtures

`testdata/` holds real malware. Read `testdata/README.md` before adding to it.

- Commit samples gzip-compressed (`name.gz`); tests read them through
  `crate::test_fixture` or `tests/common`, which inflate them on first use.
- Never `include_bytes!` or `include_str!` a sample. Small synthetic tables
  generated for a test (the ARM64 oracle `.bin` files) may be embedded.
- Record each new sample's SHA-256, origin and redistribution basis in
  `testdata/README.md`.

## Code

- No `unsafe` (the crate forbids it), and no `unwrap`, `expect` or `panic!` on
  data from the input.
- Every offset and length from a file is checked; wrapping arithmetic says so
  with `wrapping_*`.
- Any loop driven by the input has a bound, and hitting it is logged.
- Keep files under 1000 lines and functions under 150. (`script/lua/constants.rs`,
  a bounded constant folder, is the one exception.)

## Pins Dependabot cannot see

Dependabot bumps crates and action SHAs. These are pinned by hand. Review
them at each release, and at least every three months:

- The Rust toolchain: `rust-toolchain.toml`, every `rustup toolchain install`
  in `.github/workflows/`, and the README's "Rust 1.97+". Move all of them
  together, then fix what the new clippy reports.
- The fuzz job's nightly date and the `cargo-fuzz` and `cargo-deny` versions
  in `ci.yml`.
- `CROSS_REV` in `build.yml`, and the image digests in `Cross.toml`. A new
  digest is a supply-chain change: say where it came from in the commit.

The VM and cross builds are best effort (`continue-on-error`). The nightly
run's `soft failures` job lists any that broke and turns the run red.
