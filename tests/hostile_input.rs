//! Hostile input. stng parses attacker-controlled files, so a panic is a
//! denial of service. Every fixture is mutated deterministically (byte flips,
//! boundary values written over header fields, truncation) and run through
//! extraction with every pass enabled; no mutant may panic. The test profile
//! keeps overflow checks on, so unchecked offset arithmetic panics here too.
//!
//! ```text
//! STNG_MUTANTS=200 cargo test --test hostile_input        # soak: more mutants per fixture
//! STNG_MUTANT_FILTER=garble cargo test --test hostile_input  # only matching fixtures
//! ```
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use rayon::prelude::*;
use std::panic::{self, AssertUnwindSafe};
use std::path::Path;
use std::sync::Mutex;

const ROOT: &str = env!("CARGO_MANIFEST_DIR");
const DEFAULT_MUTANTS: u64 = 4;

/// xorshift64*: a deterministic stream, so a failing (fixture, seed) pair
/// reproduces exactly on every run.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1)
    }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % n.max(1) as u64).unwrap()
    }
}

/// A position biased toward the places parsers trust most: the first and last
/// 64 KiB hold the ELF/PE/Mach-O headers, load commands and section tables.
fn position(rng: &mut Rng, len: usize) -> usize {
    const EDGE: usize = 64 * 1024;
    match rng.below(4) {
        0 | 1 => rng.below(len.min(EDGE)),
        2 => len.saturating_sub(EDGE) + rng.below(len.min(EDGE)),
        _ => rng.below(len),
    }
}

fn mutate(data: &[u8], seed: u64) -> Vec<u8> {
    let mut rng = Rng::new(seed);
    let mut out = data.to_vec();
    if out.is_empty() {
        return out;
    }
    if seed % 4 == 3 {
        out.truncate(position(&mut rng, data.len()));
        return out;
    }
    let len = out.len() as u64;
    let interesting: [u64; 10] = [
        0,
        1,
        0x7f,
        0x80,
        0xffff,
        0x7fff_ffff,
        0xffff_ffff,
        u64::MAX,
        len,
        len.wrapping_sub(1),
    ];
    for _ in 0..1 + rng.below(8) {
        let at = position(&mut rng, out.len());
        if rng.below(2) == 0 {
            out[at] ^= 1 << rng.below(8);
        } else {
            let value = interesting[rng.below(interesting.len())].to_le_bytes();
            let width = [2, 4, 8][rng.below(3)];
            let end = (at + width).min(out.len());
            out[at..end].copy_from_slice(&value[..end - at]);
        }
    }
    out
}

fn fixtures() -> Vec<String> {
    fn walk(dir: &Path, out: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, out);
            } else {
                let rel = path.strip_prefix(ROOT).unwrap().to_str().unwrap();
                out.push(rel.strip_suffix(".gz").unwrap_or(rel).to_owned());
            }
        }
    }
    let mut out = Vec::new();
    walk(&Path::new(ROOT).join("testdata"), &mut out);
    out.sort();
    out
}

#[test]
fn mutated_fixtures_never_panic() {
    let mutants: u64 = std::env::var("STNG_MUTANTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MUTANTS);
    let filter = std::env::var("STNG_MUTANT_FILTER").unwrap_or_default();
    // Every pass on: XOR scanning, symbol tables, no garbage filter.
    let opts = stng::ExtractOptions::new(4).with_xor(None);

    // Panics inside rayon workers lose their location by the time they reach
    // catch_unwind, so record it from the hook.
    static WHERE: Mutex<Vec<String>> = Mutex::new(Vec::new());
    panic::set_hook(Box::new(|info| {
        let msg = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| (*s).to_owned())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_default();
        let at = info.location().map(ToString::to_string).unwrap_or_default();
        WHERE.lock().unwrap().push(format!("{at}: {msg}"));
    }));

    let jobs: Vec<(String, u64)> = fixtures()
        .into_iter()
        .filter(|rel| rel.contains(&filter))
        .flat_map(|rel| (0..mutants).map(move |seed| (rel.clone(), seed)))
        .collect();
    let failures: Vec<String> = jobs
        .par_iter()
        .filter_map(|(rel, seed)| {
            let data = mutate(&common::bytes(rel), *seed);
            panic::catch_unwind(AssertUnwindSafe(|| {
                std::hint::black_box(stng::extract_strings_with_options(&data, &opts));
            }))
            .err()
            .map(|_| format!("{rel} seed {seed}"))
        })
        .collect();
    let _ = panic::take_hook();

    let mut sites = WHERE.lock().unwrap().clone();
    sites.sort();
    sites.dedup();
    assert!(
        failures.is_empty(),
        "{} of {} mutants panicked.\nMutants:\n  {}\nPanic sites:\n  {}",
        failures.len(),
        jobs.len(),
        failures.join("\n  "),
        sites.join("\n  ")
    );
}

/// A minimal 64-bit ARM64 Mach-O: one `__DATA` segment, one dylib, and a
/// `LC_DYLD_INFO_ONLY` whose bind stream is `bind`.
fn arm64_macho_with_bind_stream(bind: &[u8]) -> Vec<u8> {
    const SEGMENT: u32 = 72;
    const DYLIB: u32 = 40;
    const DYLD_INFO: u32 = 48;
    let bind_off = 32 + SEGMENT + DYLIB + DYLD_INFO;
    let mut file = Vec::new();
    let words = |file: &mut Vec<u8>, ws: &[u32]| {
        for w in ws {
            file.extend_from_slice(&w.to_le_bytes());
        }
    };
    // MH_MAGIC_64, CPU_TYPE_ARM64, subtype, MH_EXECUTE, 3 commands.
    words(
        &mut file,
        &[
            0xfeed_facf,
            0x0100_000c,
            0,
            2,
            3,
            SEGMENT + DYLIB + DYLD_INFO,
            0,
            0,
        ],
    );
    words(&mut file, &[0x19, SEGMENT]);
    file.extend_from_slice(b"__DATA\0\0\0\0\0\0\0\0\0\0");
    for q in [0x1000_u64, 0x1000, 0, 0] {
        file.extend_from_slice(&q.to_le_bytes());
    }
    words(&mut file, &[3, 3, 0, 0]);
    words(&mut file, &[0x0c, DYLIB, 24, 0, 0, 0]);
    file.extend_from_slice(b"libx.dylib\0\0\0\0\0\0");
    let bind_len = u32::try_from(bind.len()).unwrap();
    words(
        &mut file,
        &[
            0x8000_0022,
            DYLD_INFO,
            0,
            0,
            bind_off,
            bind_len,
            0,
            0,
            0,
            0,
            0,
            0,
        ],
    );
    file.extend_from_slice(bind);
    file
}

/// A bind stream repeating one import 2^32 - 1 times. goblin's `imports()`
/// replays it into a multi-gigabyte list, which no panic guard stops; the
/// ARM64 stack-XOR scan and the import pass both used to call it unchecked
/// (found by fuzzing filefacts).
#[test]
fn forged_bind_repeat_count_is_not_replayed() {
    // Symbol `_a`, ordinal 1, segment 0, then
    // DO_BIND_ULEB_TIMES_SKIPPING_ULEB with count 2^32 - 1, skip 0.
    let bind = [
        0x11, 0x40, b'_', b'a', 0x00, 0x70, 0x00, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F, 0x00, 0x00,
    ];
    let data = arm64_macho_with_bind_stream(&bind);
    let started = std::time::Instant::now();
    std::hint::black_box(stng::extract_strings_with_options(
        &data,
        &stng::ExtractOptions::new(4),
    ));
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "took {:?}",
        started.elapsed()
    );
}
