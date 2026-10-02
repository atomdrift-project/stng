//! When a pass is worth splitting across rayon's pool.
//!
//! A split is not free. Each job pushed onto the pool wakes an idle worker,
//! and a woken worker spins looking for more work before it sleeps again; on
//! a many-core host, splitting a pass that takes microseconds burns far more
//! CPU in those spins than the pass itself — on 128 cores, 10–20× the work.
//! Most inputs stng is handed are small (source files, configuration,
//! documents), so each pass splits only once its input is large enough to
//! repay the wake-ups. Small inputs run on the calling thread, and the pool is
//! never touched.

/// Fewest items one job takes in a per-item pass — classifying or decoding a
/// string, finishing an XOR candidate, decoding a call site.
pub(crate) const MIN_ITEMS_PER_JOB: usize = 1024;

/// Fewest input bytes for which a pass over the whole input splits.
const MIN_SPLIT_BYTES: usize = 256 * 1024;

/// Whether a pass over `bytes` of input is worth splitting.
pub(crate) const fn splits(bytes: usize) -> bool {
    bytes >= MIN_SPLIT_BYTES
}

/// Run `a` and `b`, concurrently when their `bytes` of input is worth
/// splitting.
pub(crate) fn join<A, B, RA, RB>(bytes: usize, a: A, b: B) -> (RA, RB)
where
    A: FnOnce() -> RA + Send,
    B: FnOnce() -> RB + Send,
    RA: Send,
    RB: Send,
{
    if splits(bytes) {
        rayon::join(a, b)
    } else {
        (a(), b())
    }
}

/// Items per job for a pass whose `items` together cover `bytes` of input:
/// one job of all of them when the input is too small to split.
pub(crate) fn job_len(items: usize, bytes: usize) -> usize {
    if splits(bytes) { 1 } else { items.max(1) }
}
