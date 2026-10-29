# Contributing

## Setup

You need Rust 1.97 and a C compiler (jemalloc builds from source).
[cargo-nextest](https://nexte.st/) and
[cargo-machete](https://github.com/bnjbvr/cargo-machete) are optional; `make`
uses them when they are installed.

```bash
make install-precommit   # runs scripts/check-overrides, make test, make lint
make test                # unit, integration and doc tests
make lint                # rustfmt, clippy (crate and library alone), rustdoc, machete
make deny                # advisories, licences, dependency sources (cargo-deny)
```

CI runs the same `make lint` and the same tests, so a clean local run means a
clean CI run.

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

`tests/hostile_input.rs` mutates every fixture and fails on any panic;
`STNG_MUTANTS` and `STNG_MUTANT_FILTER` widen or narrow it.

## Tests

- No `#[ignore]`: fix the gap, or don't add the test.
- Platform-specific tests use `#[cfg(...)]`.
- Tests that need rizin return early, with a note on stderr, when it is not
  installed.

## Fixtures

`testdata/` holds real malware. Read `testdata/README.md` before adding to it.

- Commit samples gzip-compressed (`name.gz`); tests read them through
  `crate::test_fixture` or `tests/common`, which inflate them on first use.
- Never `include_bytes!` or `include_str!` a sample.
- Record each new sample's SHA-256, origin and redistribution basis in
  `testdata/README.md`.

## Code

- No `unsafe` (the crate forbids it), and no `unwrap`, `expect` or `panic!` on
  data from the input.
- Every offset and length from a file is checked; wrapping arithmetic says so
  with `wrapping_*`.
- Any loop driven by the input has a bound, and hitting it is logged.
- Keep files under 1000 lines and functions under 150.
