//! Test samples. Executables and malware live in git gzip-compressed, so no
//! checkout carries them raw and no test binary embeds them. A sample is
//! inflated on first use into `target/testdata/`, mirroring its path under the
//! crate root, because some consumers (the CLI, rizin) need a real file.
#![allow(dead_code, clippy::panic, clippy::expect_used, clippy::unwrap_used)] // Each test crate uses a different subset.

use flate2::read::GzDecoder;
use std::io::Read;
use std::path::{Path, PathBuf};

const ROOT: &str = env!("CARGO_MANIFEST_DIR");

/// Absolute path of the sample at `rel` (relative to the crate root, without
/// `.gz`), inflating it on first use. Plain files that were never compressed
/// resolve to themselves. Missing samples resolve to a path that does not
/// exist, so tests that skip absent fixtures keep doing so.
pub(crate) fn path(rel: &str) -> &'static str {
    let plain = Path::new(ROOT).join(rel);
    let packed = Path::new(ROOT).join(format!("{rel}.gz"));
    let resolved = if packed.is_file() {
        inflate(
            rel,
            &packed,
            &Path::new(ROOT).join("target/testdata").join(rel),
        )
    } else {
        plain
    };
    Box::leak(resolved.to_string_lossy().into_owned().into_boxed_str())
}

/// Contents of the sample at `rel`, inflated in memory.
pub(crate) fn bytes(rel: &str) -> Vec<u8> {
    let packed = Path::new(ROOT).join(format!("{rel}.gz"));
    let Ok(file) = std::fs::File::open(&packed) else {
        let plain = Path::new(ROOT).join(rel);
        return std::fs::read(&plain).unwrap_or_else(|e| panic!("{}: {e}", plain.display()));
    };
    let mut out = Vec::new();
    GzDecoder::new(file)
        .read_to_end(&mut out)
        .unwrap_or_else(|e| panic!("{}: {e}", packed.display()));
    out
}

/// Inflates `packed` (the sample `rel`) to `dest` unless an up-to-date copy is already there.
/// Test threads and nextest processes race here, so each writes a private
/// temporary and renames it into place; the rename is atomic.
fn inflate(rel: &str, packed: &Path, dest: &Path) -> PathBuf {
    let fresh = |d: &Path| {
        let (Ok(d), Ok(p)) = (d.metadata(), packed.metadata()) else {
            return false;
        };
        d.modified().ok() >= p.modified().ok()
    };
    if fresh(dest) {
        return dest.to_owned();
    }
    let data = bytes(rel);
    std::fs::create_dir_all(dest.parent().expect("sample has a parent directory"))
        .expect("create target/testdata");
    let tmp = dest.with_extension(format!(
        "tmp{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::write(&tmp, data).expect("write inflated sample");
    std::fs::rename(&tmp, dest).expect("move inflated sample into place");
    dest.to_owned()
}
