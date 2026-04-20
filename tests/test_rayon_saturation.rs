//! Regression test: stng must not bottleneck parallel callers.
//!
//! A previous revision routed every `extract_strings_with_options` call from a
//! rayon worker through a hidden 1-thread pool (`SERIAL_POOL`).  Callers that
//! fanned out 16 concurrent stng invocations from a `par_iter` would serialize
//! through that single thread while 15 workers sat idle.
//!
//! This test fans out a fixed batch of stng calls on a dedicated multi-thread
//! rayon pool and measures the wall-clock ratio against the sequential
//! baseline.  The speedup floor is deliberately loose (2×) so CI noise does
//! not flake, yet any reintroduction of cross-registry routing will crash
//! through it — single-thread bottlenecking collapses speedup to ~1×.

use rayon::prelude::*;
use std::time::Instant;

fn synthetic_elf_like(size_bytes: usize) -> Vec<u8> {
    let mut data = vec![0u8; size_bytes];
    data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    // Sprinkle ASCII strings so stng actually produces output.
    for (i, chunk) in data.chunks_mut(128).enumerate() {
        let tag = format!("string-{i:05}\0");
        let bytes = tag.as_bytes();
        let n = bytes.len().min(chunk.len());
        chunk[..n].copy_from_slice(&bytes[..n]);
    }
    data
}

#[test]
fn stng_parallelizes_under_par_iter() {
    let data = synthetic_elf_like(512 * 1024);
    let opts = stng::ExtractOptions::new(4);
    let n_iters: usize = 32;
    let n_threads: usize = 8;

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(n_threads)
        .thread_name(|i| format!("saturation-test-{i}"))
        .build()
        .expect("build test rayon pool");

    // Sequential baseline — no pool install, single-thread processing.
    let serial = {
        let t = Instant::now();
        for _ in 0..n_iters {
            let _ = stng::extract_strings_with_options(&data, &opts);
        }
        t.elapsed()
    };

    // Parallel run on a pool of `n_threads`.
    let parallel = pool.install(|| {
        let t = Instant::now();
        (0..n_iters).into_par_iter().for_each(|_| {
            let _ = stng::extract_strings_with_options(&data, &opts);
        });
        t.elapsed()
    });

    let speedup = serial.as_secs_f64() / parallel.as_secs_f64();
    assert!(
        speedup > 2.0,
        "stng serialized under par_iter: serial={serial:?} parallel={parallel:?} speedup={speedup:.2}x (expected >2x on {n_threads} threads)"
    );
}
