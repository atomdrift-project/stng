//! Best-effort, non-blocking cache reclamation.
//!
//! A cache here is a directory of entries, each carrying an mtime. A *sweep*
//! deletes the oldest entries until the directory is within a time and size
//! budget. The whole thing runs on one detached thread that dies with the
//! process — no daemon, no async runtime, no persistent index.
//!
//! Two properties keep it cheap and safe:
//! - A once-a-day `.last-sweep` marker gates the walk, so the common case is a
//!   single `stat`, never a scan of a million-entry directory.
//! - Every filesystem error is ignored: reclaiming disk must never disturb the
//!   program it runs alongside. These caches are written once and never
//!   rewritten, and on Unix unlinking a file another thread has open leaves that
//!   reader's descriptor valid, so a concurrent reader never sees a torn file.
//!
//! Consumers that already link stng reuse both the mechanism ([`spawn`]) and
//! stng's own policy ([`stng_budget`]); the one crate that does not link stng
//! (fletch) keeps a verbatim copy of this file.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

/// Default retention window: entries older than this are dropped.
const DEFAULT_TTL_DAYS: u64 = 30;
/// Default aggregate ceiling per component: 2 GiB.
const DEFAULT_MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Re-walk a cache at most this often; cheaper runs just read the marker.
const SWEEP_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
/// Marker file whose mtime records the last sweep, written in the primary root.
const MARKER: &str = ".last-sweep";

/// A cache directory and how deep its entries live below it.
#[derive(Debug)]
pub struct Root {
    /// Directory to sweep.
    pub path: PathBuf,
    /// `1` = direct children are entries (files or dirs); `2` = grandchildren
    /// are entries and each child is a container to descend into.
    pub depth: u8,
}

/// One component's caches and the budget they must collectively stay within.
#[derive(Debug)]
pub struct Budget {
    /// Component name, for a debug log line.
    pub label: &'static str,
    /// One or more directories sharing the `max_bytes` ceiling. The first is
    /// the *primary* root and holds the sweep marker.
    pub roots: Vec<Root>,
    /// Delete entries older than this.
    pub max_age: Duration,
    /// After the age pass, delete oldest entries until the total across all
    /// roots is at or below this.
    pub max_bytes: u64,
}

/// One sweep in flight per process; a second [`spawn`] is a no-op until it ends.
static RUNNING: AtomicBool = AtomicBool::new(false);

/// Sweep `budgets` on a detached thread and return immediately. The thread is
/// reaped when the process exits; a partial sweep simply resumes next run.
///
/// For a one-shot CLI, call once at startup — it races the real work. For a
/// long-lived daemon, use [`spawn_periodic`] instead.
pub fn spawn(mut budgets: Vec<Budget>) {
    budgets.retain(|b| !b.roots.is_empty());
    if budgets.is_empty() {
        return;
    }
    if RUNNING.swap(true, Ordering::AcqRel) {
        return; // a sweep is already running
    }
    std::thread::spawn(move || {
        run_all(&budgets);
        RUNNING.store(false, Ordering::Release);
    });
}

/// Sweep `budgets` now and every `interval` thereafter, on one detached thread,
/// for the life of the process. For daemons whose process never exits, so a
/// startup-only sweep would never fire again. The daily marker keeps each wake
/// cheap regardless of `interval`.
pub fn spawn_periodic(mut budgets: Vec<Budget>, interval: Duration) {
    budgets.retain(|b| !b.roots.is_empty());
    if budgets.is_empty() {
        return;
    }
    std::thread::spawn(move || {
        loop {
            run_all(&budgets);
            std::thread::sleep(interval);
        }
    });
}

/// stng's own budget: the string cache and the r2/rizin cache, sharing one
/// ceiling. Empty roots (a disabled tier) are skipped.
#[must_use]
pub fn stng_budget() -> Budget {
    let mut roots = Vec::new();
    if let Some(path) = crate::string_cache::cache_dir() {
        roots.push(Root { path, depth: 1 });
    }
    if let Some(path) = crate::r2::cache::cache_dir() {
        roots.push(Root { path, depth: 1 });
    }
    Budget {
        label: "stng",
        roots,
        max_age: max_age_from_env("STNG_CACHE_TTL_DAYS"),
        max_bytes: max_bytes_from_env("STNG_CACHE_MAX_BYTES"),
    }
}

/// Retention window from `var` (in days), or the 30-day default.
#[must_use]
pub fn max_age_from_env(var: &str) -> Duration {
    let days = std::env::var(var)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&d| d > 0)
        .unwrap_or(DEFAULT_TTL_DAYS);
    Duration::from_secs(days * 24 * 60 * 60)
}

/// Byte ceiling from `var`, or the 2 GiB default.
#[must_use]
pub fn max_bytes_from_env(var: &str) -> u64 {
    std::env::var(var)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&b| b > 0)
        .unwrap_or(DEFAULT_MAX_BYTES)
}

fn run_all(budgets: &[Budget]) {
    for b in budgets {
        run(b);
    }
}

/// An entry considered for eviction: its path, whether it is a directory, and
/// the size and mtime read once and reused by both passes.
struct Entry {
    path: PathBuf,
    is_dir: bool,
    modified: SystemTime,
    bytes: u64,
}

fn run(b: &Budget) {
    let Some(primary) = b.roots.first() else {
        return;
    };
    if !due(&primary.path) {
        return;
    }
    // Mark the start (mtime = now) so a racing process sees a fresh marker and
    // skips. Best-effort; if the directory doesn't exist yet, there's nothing
    // to sweep anyway.
    let _ = fs::write(primary.path.join(MARKER), b"");

    let mut entries = Vec::new();
    for r in &b.roots {
        collect(&r.path, r.depth, &mut entries);
    }

    let now = SystemTime::now();
    let mut freed = 0u64;
    let mut removed = 0usize;

    // Age pass: drop anything past the retention window outright.
    entries.retain(|e| {
        if now.duration_since(e.modified).unwrap_or_default() > b.max_age && remove(e) {
            freed += e.bytes;
            removed += 1;
            false
        } else {
            true
        }
    });

    // Size pass: if still over budget, evict oldest first to 90% of the cap.
    let mut total: u64 = entries.iter().map(|e| e.bytes).sum();
    if total > b.max_bytes {
        entries.sort_by_key(|e| e.modified); // oldest first
        let target = b.max_bytes / 10 * 9;
        for e in &entries {
            if total <= target {
                break;
            }
            if remove(e) {
                total = total.saturating_sub(e.bytes);
                freed += e.bytes;
                removed += 1;
            }
        }
    }

    if removed > 0 {
        tracing::debug!(
            target: "cache_sweep",
            component = b.label,
            removed,
            freed_bytes = freed,
            "swept cache"
        );
    }
}

/// True unless this root was swept within [`SWEEP_INTERVAL`]. A missing or
/// unreadable marker counts as due, so a never-swept cache is handled on the
/// first run.
fn due(root: &Path) -> bool {
    match fs::metadata(root.join(MARKER)).and_then(|m| m.modified()) {
        Ok(t) => t.elapsed().map(|e| e >= SWEEP_INTERVAL).unwrap_or(true),
        Err(_) => true,
    }
}

/// Gather the cache entries at `depth` below `root` into `out`. At `depth <= 1`
/// each child is an entry; deeper, each directory child is descended into.
fn collect(root: &Path, depth: u8, out: &mut Vec<Entry>) {
    let Ok(rd) = fs::read_dir(root) else {
        return;
    };
    for e in rd.flatten() {
        let Ok(ft) = e.file_type() else {
            continue;
        };
        let path = e.path();
        if depth <= 1 {
            if path.file_name().is_some_and(|n| n == MARKER) {
                continue; // never evict our own marker
            }
            if let Some(entry) = stat_entry(path, ft.is_dir()) {
                out.push(entry);
            }
        } else if ft.is_dir() {
            collect(&path, depth - 1, out);
        }
    }
}

fn stat_entry(path: PathBuf, is_dir: bool) -> Option<Entry> {
    let meta = fs::metadata(&path).ok()?;
    let modified = meta.modified().ok()?;
    let bytes = if is_dir { dir_size(&path) } else { meta.len() };
    Some(Entry {
        path,
        is_dir,
        modified,
        bytes,
    })
}

/// Recursive byte size of a directory entry. Only ever called on the small
/// per-item directories stng's r2 cache uses (a handful of files each).
fn dir_size(dir: &Path) -> u64 {
    let Ok(rd) = fs::read_dir(dir) else {
        return 0;
    };
    let mut total = 0;
    for e in rd.flatten() {
        match e.metadata() {
            Ok(m) if m.is_dir() => total += dir_size(&e.path()),
            Ok(m) => total += m.len(),
            Err(_) => {}
        }
    }
    total
}

fn remove(e: &Entry) -> bool {
    let r = if e.is_dir {
        fs::remove_dir_all(&e.path)
    } else {
        fs::remove_file(&e.path)
    };
    r.is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("stng-sweep-{}-{}", std::process::id(), name));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_aged(path: &Path, bytes: usize, age: Duration) {
        let mut f = fs::File::create(path).unwrap();
        f.write_all(&vec![b'x'; bytes]).unwrap();
        f.set_modified(SystemTime::now() - age).unwrap();
    }

    fn day(n: u64) -> Duration {
        Duration::from_secs(n * 24 * 60 * 60)
    }

    #[test]
    fn age_pass_removes_only_old() {
        let dir = scratch("age");
        write_aged(&dir.join("old.json"), 10, day(40));
        write_aged(&dir.join("fresh.json"), 10, day(1));
        let budget = Budget {
            label: "test",
            roots: vec![Root {
                path: dir.clone(),
                depth: 1,
            }],
            max_age: day(30),
            max_bytes: u64::MAX,
        };
        run(&budget);
        assert!(!dir.join("old.json").exists(), "40-day entry evicted");
        assert!(dir.join("fresh.json").exists(), "1-day entry kept");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn size_pass_evicts_oldest_first() {
        let dir = scratch("size");
        // Five 400-byte entries, distinct ages newest→oldest; cap 1000 → 90% = 900.
        for (i, age) in [5u64, 4, 3, 2, 1].into_iter().enumerate() {
            write_aged(&dir.join(format!("e{i}.json")), 400, day(age));
        }
        let budget = Budget {
            label: "test",
            roots: vec![Root {
                path: dir.clone(),
                depth: 1,
            }],
            max_age: day(3650), // age pass inert
            max_bytes: 1000,
        };
        run(&budget);
        // 2000 bytes → evict oldest until ≤ 900: remove e0(5d), e1(4d), e2(3d).
        assert!(!dir.join("e0.json").exists(), "oldest evicted");
        assert!(!dir.join("e1.json").exists());
        assert!(!dir.join("e2.json").exists());
        assert!(dir.join("e3.json").exists(), "newest kept");
        assert!(dir.join("e4.json").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn depth_two_reaches_grandchildren() {
        let dir = scratch("depth2");
        let ver = dir.join("v1");
        fs::create_dir_all(&ver).unwrap();
        write_aged(&ver.join("a.zst"), 10, day(40));
        write_aged(&ver.join("b.zst"), 10, day(1));
        let budget = Budget {
            label: "test",
            roots: vec![Root {
                path: dir.clone(),
                depth: 2,
            }],
            max_age: day(30),
            max_bytes: u64::MAX,
        };
        run(&budget);
        assert!(!ver.join("a.zst").exists(), "aged grandchild evicted");
        assert!(ver.join("b.zst").exists(), "fresh grandchild kept");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn marker_gates_and_survives() {
        let dir = scratch("gate");
        assert!(due(&dir), "no marker ⇒ due");
        let budget = Budget {
            label: "test",
            roots: vec![Root {
                path: dir.clone(),
                depth: 1,
            }],
            max_age: day(30),
            max_bytes: u64::MAX,
        };
        run(&budget);
        assert!(dir.join(MARKER).exists(), "sweep writes the marker");
        assert!(!due(&dir), "fresh marker ⇒ not due");
        let _ = fs::remove_dir_all(&dir);
    }
}
