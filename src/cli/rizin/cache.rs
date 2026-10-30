//! On-disk cache of rizin command output, so a file analysed once is not
//! analysed again.
//!
//! ```text
//! <cache dir>/stng/r2/<key>/
//!   isj.json        # one file per command, named for the command
//!   izzj.json
//!   aaa__e_scr.color_0__s_entry0__pdf.json
//! ```
//!
//! An entry's key covers everything its output depends on: the bytes
//! analysed, the rizin install that analysed them, and this stng. A changed
//! input or an upgraded tool lands in a new entry, so nothing in an entry is
//! ever stale and nothing needs validating.

use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Entries (one directory per analysed input) kept before the oldest go.
const MAX_ENTRIES: usize = 4096;
/// Entries untouched for this long are dropped.
const MAX_AGE: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// One input's cached rizin output.
pub(crate) struct Entry {
    root: PathBuf,
    dir: PathBuf,
}

impl Entry {
    /// The entry for `data` as analysed by `tool`, under the user's cache
    /// directory. Fails when there is no cache directory or it cannot be
    /// created; stng then runs uncached.
    pub(crate) fn open(data: &[u8], tool: &Path) -> io::Result<Self> {
        // Linux: ~/.cache · macOS: ~/Library/Caches · Windows: %LOCALAPPDATA%
        let base = dirs::cache_dir()
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no cache directory"))?;
        Self::at(&base.join("stng").join("r2"), data, tool)
    }

    /// The entry for `data` as analysed by `tool`, under `root`.
    pub(crate) fn at(root: &Path, data: &[u8], tool: &Path) -> io::Result<Self> {
        create_private_dir(root)?;
        Ok(Self {
            root: root.to_path_buf(),
            dir: root.join(key(data, tool)),
        })
    }

    /// The cached output of `command`, if any.
    pub(crate) fn get(&self, command: &str) -> Option<String> {
        fs::read_to_string(self.file(command)).ok()
    }

    /// Cache `output` as the output of `command`.
    pub(crate) fn set(&self, command: &str, output: &str) -> io::Result<()> {
        if !self.dir.exists() {
            // A new input: this run spends seconds in rizin anyway, so a
            // walk to bound the cache costs nothing noticeable.
            prune(&self.root, MAX_ENTRIES);
            create_private_dir(&self.dir)?;
        }
        write_atomic(&self.file(command), output.as_bytes())
    }

    /// Remove every cached output for this input.
    pub(crate) fn clear(&self) -> io::Result<()> {
        match fs::remove_dir_all(&self.dir) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            result => result,
        }
    }

    fn file(&self, command: &str) -> PathBuf {
        self.dir.join(format!("{}.json", file_name(command)))
    }
}

/// The entry name for `data` analysed by `tool`. The tool is identified by
/// its resolved path and its file's size and modification time: an upgrade
/// changes at least one, and reading them costs no process spawn.
fn key(data: &[u8], tool: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update((data.len() as u64).to_le_bytes());
    hasher.update(data);
    let tool = fs::canonicalize(tool).unwrap_or_else(|_| tool.to_path_buf());
    hasher.update(tool.as_os_str().as_encoded_bytes());
    if let Ok(meta) = fs::metadata(&tool) {
        hasher.update(meta.len().to_le_bytes());
        if let Some(age) = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        {
            hasher.update(age.as_nanos().to_le_bytes());
        }
    }
    hasher.update(env!("CARGO_PKG_VERSION"));
    crate::cli::hex(&hasher.finalize())
}

/// Drop entries untouched for [`MAX_AGE`], then the oldest beyond
/// `max_entries`. Best-effort: a failure costs disk, never a result.
fn prune(root: &Path, max_entries: usize) {
    let Ok(dir) = fs::read_dir(root) else {
        return;
    };
    let mut entries: Vec<(SystemTime, PathBuf)> = dir
        .flatten()
        .filter_map(|e| {
            let meta = e.metadata().ok()?;
            meta.is_dir().then_some((meta.modified().ok()?, e.path()))
        })
        .collect();
    entries.sort();
    let excess = entries.len().saturating_sub(max_entries);
    for (i, (modified, path)) in entries.iter().enumerate() {
        let stale = modified.elapsed().is_ok_and(|age| age > MAX_AGE);
        if (i < excess || stale)
            && let Err(e) = fs::remove_dir_all(path)
        {
            tracing::debug!(path = %path.display(), error = %e, "could not prune rizin cache entry");
        }
    }
}

/// Create `dir` and its missing parents, readable only by this user on Unix:
/// cached rizin output holds the analysed files' strings and symbols.
fn create_private_dir(dir: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir)
}

/// Write `data` to `path` through a sibling temporary file and a rename, so a
/// concurrent stng never reads a half-written entry: a truncated `/at`
/// listing still parses, just with keys missing.
fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    // Unique per process and call: rizin passes run on parallel threads.
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(
        ".{}.{}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let tmp = PathBuf::from(tmp);
    if let Err(e) = fs::write(&tmp, data).and_then(|()| fs::rename(&tmp, path)) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// `command` as a file name: characters other than alphanumerics, `-` and
/// `.` become `_`, and a long command becomes its hash, within every
/// filesystem's name limit.
fn file_name(command: &str) -> String {
    if command.len() < 100 {
        command
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '.' {
                    c
                } else {
                    '_'
                }
            })
            .collect()
    } else {
        format!(
            "cmd_{}",
            crate::cli::hex(&Sha256::digest(command.as_bytes()))
        )
    }
}

#[cfg(test)]
mod tests;
