//! stng-owned caching of extracted strings.
//!
//! stng is the producer of extracted strings, so it owns their cache — both an
//! in-process memo and a disk cache. Consumers (filefacts, cleave) call
//! [`cached_strings_with_options`] and receive a shared [`Arc`] slice rather
//! than each cloning and re-storing their own copy. This makes stng the single
//! source of truth for string data: downstream caches persist only their own
//! derived facts plus the content key, and rehydrate the strings from here.
//!
//! Cache layout (mirrors the r2 cache under the same `stng` root):
//! ```text
//! ~/.cache/stng/strings/<key>.json   # one serialized Vec<ExtractedString>
//! ```
//! where `<key>` hashes the input bytes, the output-affecting options, and a
//! cache-format version so a logic change invalidates stale entries.
//!
//! Retention is [`crate::cache_sweep`]'s: entries are bounded by age, count and
//! total bytes, evicted oldest-first. A hit refreshes an entry's mtime (see
//! [`touch`]), making that order least-recently-*used*, and a write reports
//! itself so a long batch run re-sweeps before it can outgrow the ceiling.

use crate::{ExtractOptions, ExtractedString};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, SystemTime};

/// How stale an entry's mtime must be before a cache hit rewrites it. Bounds
/// the cost of LRU tracking to one `set_modified` per entry per day.
const LRU_GRANULARITY: Duration = Duration::from_secs(24 * 60 * 60);

/// Bump when extraction output changes shape so stale disk entries are ignored.
/// Unlike filefacts' cache, this key carries no build fingerprint, so a change
/// to the decoder pipeline is invisible to it until this constant moves.
///
/// - `2`: short/command-vouched embedded base64 now decodes (`base64 -d <<< …`
///   → `/bin/rm`), so entries keyed under `1` are missing those rows.
/// - `3`: the JavaScript charcode-array packer decodes, with its Caesar shift
///   recovered (`[...].map(c => String.fromCharCode(c)).join("")` handed to a
///   rotation before `eval`). Entries keyed under `2` hold only the outer
///   wrapper's strings and none of the payload's.
/// - `4`: hex runs embedded in a larger string now decode (`echo <hex> | xxd
///   -r -p | sh`), where previously only a value that was hex end to end did.
///   Entries keyed under `3` hold the wrapping command but not the payload.
const CACHE_VERSION: &str = "4";

/// Maximum number of distinct inputs retained in the in-process memo. Bounds
/// memory during a directory walk (one entry per processed file); evicted
/// entries stay alive as long as a consumer holds the [`Arc`].
const MEMO_CAP: usize = 16;

/// In-process memo of recently extracted strings, keyed by [`cache_key`].
static MEMO: LazyLock<Mutex<Memo>> = LazyLock::new(|| Mutex::new(Memo::default()));

#[derive(Default)]
struct Memo {
    map: HashMap<String, Arc<[ExtractedString]>>,
    order: VecDeque<String>,
}

/// Extract strings for `data`/`opts`, reusing stng's cache.
///
/// Returns a shared slice so every caller in the process points at one
/// allocation. On a cacheable configuration the result is memoized in process
/// and persisted to disk; non-cacheable configurations (rizin/r2 feeds or a
/// custom XOR key, whose output isn't a pure function of the bytes) fall back
/// to a fresh extraction wrapped in an `Arc`.
#[must_use]
pub fn cached_strings_with_options(data: &[u8], opts: &ExtractOptions) -> Arc<[ExtractedString]> {
    if !is_cacheable(opts) {
        return Arc::from(crate::extract_strings_with_options(data, opts));
    }

    let key = cache_key(data, opts);

    if let Some(hit) = memo_get(&key) {
        return hit;
    }

    if let Some(vec) = disk_load(&key) {
        let arc: Arc<[ExtractedString]> = Arc::from(vec);
        memo_put(&key, &arc);
        return arc;
    }

    let arc: Arc<[ExtractedString]> = Arc::from(crate::extract_strings_with_options(data, opts));
    disk_store(&key, &arc);
    memo_put(&key, &arc);
    arc
}

/// Like [`cached_strings_with_options`] but extracts from an already-parsed
/// goblin object on a cache miss, skipping a redundant re-parse. The cache key
/// is the bytes + options (identical to the data path), so a hit from either
/// entry point serves the other — the object is only an extraction shortcut.
#[must_use]
pub fn cached_strings_from_object(
    object: &goblin::Object<'_>,
    data: &[u8],
    opts: &ExtractOptions,
) -> Arc<[ExtractedString]> {
    if !is_cacheable(opts) {
        return Arc::from(crate::extract_strings_from_object(object, data, opts));
    }

    let key = cache_key(data, opts);

    if let Some(hit) = memo_get(&key) {
        return hit;
    }

    if let Some(vec) = disk_load(&key) {
        let arc: Arc<[ExtractedString]> = Arc::from(vec);
        memo_put(&key, &arc);
        return arc;
    }

    let arc: Arc<[ExtractedString]> =
        Arc::from(crate::extract_strings_from_object(object, data, opts));
    disk_store(&key, &arc);
    memo_put(&key, &arc);
    arc
}

/// The cache key stng uses for these inputs, or `None` when the configuration
/// isn't cacheable. A downstream cache records this key and later rehydrates the
/// strings via [`cached_strings_by_key`] instead of persisting its own copy.
#[must_use]
pub fn cache_key_for(data: &[u8], opts: &ExtractOptions) -> Option<String> {
    is_cacheable(opts).then(|| cache_key(data, opts))
}

/// Load cached strings by a key from [`cache_key_for`], without extracting.
/// Returns `None` if the entry is in neither the in-process memo nor on disk —
/// the caller should then fall back to a full recompute.
#[must_use]
pub fn cached_strings_by_key(key: &str) -> Option<Arc<[ExtractedString]>> {
    if let Some(hit) = memo_get(key) {
        return Some(hit);
    }
    let arc: Arc<[ExtractedString]> = Arc::from(disk_load(key)?);
    memo_put(key, &arc);
    Some(arc)
}

/// Only configurations whose output is a pure function of the bytes are cached.
/// Anything fed by rizin/r2 or a caller-supplied XOR key varies independently
/// of `data`, so it would poison a content-keyed cache.
fn is_cacheable(opts: &ExtractOptions) -> bool {
    !opts.use_r2
        && opts.r2_strings.is_none()
        && opts.xor_key.is_none()
        && opts.rizin_boundaries.is_none()
        && opts.rizin_connect_addrs.is_none()
        && opts.rizin_xor_candidates.is_none()
}

/// Hash the input bytes plus every output-affecting option into a hex key.
fn cache_key(data: &[u8], opts: &ExtractOptions) -> String {
    let mut h = Sha256::new();
    h.update(data);
    h.update(opts.min_length.to_le_bytes());
    h.update(opts.xor_min_length.to_le_bytes());
    h.update([
        u8::from(opts.filter_garbage),
        u8::from(opts.xor_scan),
        u8::from(opts.xor_scan_multi),
        u8::from(opts.caller_provides_symbols),
    ]);
    h.update(format!("{:?}", opts.format_hint).as_bytes());
    h.update(CACHE_VERSION.as_bytes());
    hex::encode(h.finalize())
}

fn memo_get(key: &str) -> Option<Arc<[ExtractedString]>> {
    MEMO.lock().ok()?.map.get(key).cloned()
}

fn memo_put(key: &str, arc: &Arc<[ExtractedString]>) {
    let Ok(mut memo) = MEMO.lock() else { return };
    if memo.map.insert(key.to_string(), arc.clone()).is_none() {
        memo.order.push_back(key.to_string());
        while memo.order.len() > MEMO_CAP {
            if let Some(old) = memo.order.pop_front() {
                memo.map.remove(&old);
            }
        }
    }
}

/// Disk cache directory, or `None` when disabled.
///
/// `STNG_STRING_CACHE=0`/`false` disables the disk tier; `STNG_STRING_CACHE_DIR`
/// overrides the location (used by tests to avoid touching the user's cache).
///
/// Public so [`crate::cache_sweep`] reclaims exactly the directory written here.
#[must_use]
pub fn cache_dir() -> Option<PathBuf> {
    match std::env::var("STNG_STRING_CACHE") {
        Ok(v) if v == "0" || v.eq_ignore_ascii_case("false") => return None,
        _ => {}
    }
    if let Ok(dir) = std::env::var("STNG_STRING_CACHE_DIR") {
        return Some(PathBuf::from(dir));
    }
    let base = dirs::cache_dir()
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))?;
    Some(base.join("stng").join("strings"))
}

fn disk_load(key: &str) -> Option<Vec<ExtractedString>> {
    disk_load_at(&cache_dir()?, key)
}

fn disk_load_at(dir: &Path, key: &str) -> Option<Vec<ExtractedString>> {
    let path = dir.join(format!("{key}.json"));
    let bytes = std::fs::read(&path).ok()?;
    let strings = serde_json::from_slice(&bytes).ok()?;
    // Only a usable entry counts as used: an unparseable one is a miss, and
    // refreshing it would keep it alive past the age that would have cleared it.
    touch(&path);
    Some(strings)
}

/// Mark `path` as used now, so [`crate::cache_sweep`] — which orders eviction
/// by mtime — drops entries that are least recently *used* rather than merely
/// oldest. Without this a daily-hit entry dies at the retention window while a
/// write-once entry of the same age survives on nothing but a later write.
///
/// Granular to a day: an entry already touched within the window is left alone,
/// so a cache hit stays a read in every case but the first of each day.
fn touch(path: &Path) {
    let used_today = std::fs::metadata(path)
        .and_then(|m| m.modified())
        .is_ok_and(|m| m.elapsed().is_ok_and(|since| since < LRU_GRANULARITY));
    if used_today {
        return;
    }
    // Best-effort, like every other cache operation: a read-only cache dir
    // costs LRU ordering, never a failed extraction.
    if let Ok(f) = std::fs::File::options().write(true).open(path) {
        let _ = f.set_modified(SystemTime::now());
    }
}

fn disk_store(key: &str, strings: &[ExtractedString]) {
    if let Some(dir) = cache_dir() {
        disk_store_at(&dir, key, strings);
    }
}

fn disk_store_at(dir: &Path, key: &str, strings: &[ExtractedString]) {
    if std::fs::create_dir_all(dir).is_err() {
        return;
    }
    let Ok(bytes) = serde_json::to_vec(strings) else {
        return;
    };
    // Best-effort: a cache write failure must never fail extraction. Write to a
    // temp sibling and rename so a concurrent reader never sees a partial file.
    let tmp_path = dir.join(format!("{key}.json.tmp"));
    if std::fs::write(&tmp_path, &bytes).is_ok()
        && std::fs::rename(tmp_path, dir.join(format!("{key}.json"))).is_ok()
    {
        crate::cache_sweep::note_write();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StringMethod;

    fn sample() -> Vec<ExtractedString> {
        vec![ExtractedString {
            value: "https://example.com/payload".to_string(),
            data_offset: 0x40,
            data_len: 0,
            method: StringMethod::RawScan,
            kind: None,
            fragments: None,
        }]
    }

    #[test]
    fn key_changes_with_options() {
        let data = b"the quick brown fox jumps over the lazy dog";
        let a = cache_key(data, &ExtractOptions::new(4));
        let b = cache_key(data, &ExtractOptions::new(8));
        assert_ne!(a, b, "min_length must affect the key");
        let c = cache_key(b"different bytes entirely here", &ExtractOptions::new(4));
        assert_ne!(a, c, "content must affect the key");
    }

    #[test]
    fn rizin_fed_options_are_not_cacheable() {
        let mut opts = ExtractOptions::new(4);
        assert!(is_cacheable(&opts));
        opts.r2_strings = Some(sample());
        assert!(!is_cacheable(&opts), "r2-fed output is not content-pure");
    }

    #[test]
    fn disk_round_trips_through_temp_dir() {
        let dir = std::env::temp_dir().join(format!("stng-strcache-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let key = "deadbeef_test_key";
        assert!(disk_load_at(&dir, key).is_none(), "clean dir starts empty");
        let strings = sample();
        disk_store_at(&dir, key, &strings);
        assert_eq!(disk_load_at(&dir, key).as_deref(), Some(strings.as_slice()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_hit_refreshes_a_stale_entry_but_not_a_fresh_one() {
        let dir = std::env::temp_dir().join(format!("stng-strcache-lru-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let key = "lru_test_key";
        disk_store_at(&dir, key, &sample());
        let path = dir.join(format!("{key}.json"));

        // Age the entry past the retention window, then hit it: the sweeper
        // orders by mtime, so a hit has to move it or the entry dies in use.
        let stale = SystemTime::now() - Duration::from_secs(40 * 24 * 60 * 60);
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(stale)
            .unwrap();
        assert!(disk_load_at(&dir, key).is_some());
        let refreshed = std::fs::metadata(&path).unwrap().modified().unwrap();
        assert!(
            refreshed > stale,
            "a hit on a stale entry rewrites its mtime"
        );

        // A second hit the same day leaves it alone — LRU costs one write per
        // entry per day, not one per read.
        assert!(disk_load_at(&dir, key).is_some());
        assert_eq!(
            std::fs::metadata(&path).unwrap().modified().unwrap(),
            refreshed,
            "an entry already touched today is left untouched"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
