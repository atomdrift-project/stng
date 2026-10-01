//! Regression test: stng must not bottleneck parallel callers.
//!
//! A previous revision routed every `extract_strings_with_options` call from a
//! rayon worker through a hidden 1-thread pool (`SERIAL_POOL`).  Callers that
//! fanned out 16 concurrent stng invocations from a `par_iter` would serialize
//! through that single thread while 15 workers sat idle.
//!
//! This test runs a fixed batch of stng calls on a 1-thread pool and again on
//! an N-thread pool, N being the machine's cores up to 8, and compares wall
//! clock. Both runs keep stng's own internal parallelism inside their pool, so
//! the ratio measures how calls scale with threads. The speedup floor is
//! deliberately loose (1.5×) so CI noise and small runners do not flake, yet
//! any reintroduction of cross-registry routing will crash through it:
//! single-thread bottlenecking collapses speedup to ~1×.
//!
//! A binary of its own, so no other test competes for the cores it measures.

use rayon::prelude::*;
use std::time::{Duration, Instant};

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
fn stng_parallelizes_under_par_iter() -> Result<(), Box<dyn std::error::Error>> {
    let n_threads = std::thread::available_parallelism().map_or(1, |n| n.get().min(8));
    if n_threads < 2 {
        return Ok(()); // One core: there is no speedup to measure.
    }
    let data = synthetic_elf_like(256 * 1024);
    let opts = stng::ExtractOptions::new(4);
    let n_iters: usize = 32;

    let time_on = |threads: usize| -> Result<Duration, rayon::ThreadPoolBuildError> {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .thread_name(|i| format!("saturation-test-{i}"))
            .build()?;
        Ok(pool.install(|| {
            let t = Instant::now();
            (0..n_iters).into_par_iter().for_each(|_| {
                let _ = stng::extract_strings_with_options(&data, &opts);
            });
            t.elapsed()
        }))
    };
    let serial = time_on(1)?;
    let parallel = time_on(n_threads)?;

    let speedup = serial.as_secs_f64() / parallel.as_secs_f64();
    assert!(
        speedup > 1.5,
        "stng serialized under par_iter: serial={serial:?} parallel={parallel:?} speedup={speedup:.2}x (expected >1.5x on {n_threads} threads)"
    );

    Ok(())
}
