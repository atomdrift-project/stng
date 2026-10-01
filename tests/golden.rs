//! Golden output. Every fixture under `testdata/` and `tests/testdata/` is
//! extracted with the option sets stng's consumers use, and each result must
//! match its row in `tests/golden.tsv`: string count, a hash of the canonical
//! output, and per-method counts. A refactor that changes output fails here; a
//! deliberate change shows up as a reviewable diff of that file.
//!
//! ```text
//! STNG_BLESS=1 cargo test --test golden          # accept the current output
//! STNG_GOLDEN_DUMP=dir cargo test --test golden  # write full output to dir, skip the check
//! scripts/golden-diff [rev]                      # diff full output against rev
//! ```
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use stng::{ExtractOptions, ExtractedString};

const ROOT: &str = env!("CARGO_MANIFEST_DIR");
const MANIFEST: &str = "tests/golden.tsv";
const FIXTURE_DIRS: [&str; 2] = ["testdata", "tests/testdata"];

/// The option sets under test: what filefacts passes for code, and the plain
/// library default.
fn configs() -> [(&'static str, ExtractOptions); 2] {
    [
        (
            "filefacts",
            ExtractOptions::new(4)
                .with_garbage_filter(true)
                .with_caller_provides_symbols(true)
                .with_xor(None),
        ),
        ("default", ExtractOptions::new(4)),
    ]
}

/// Fixture paths relative to the crate root, without any `.gz` suffix.
fn fixtures() -> Vec<String> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, out);
            } else {
                out.push(path);
            }
        }
    }
    let mut paths = Vec::new();
    for dir in FIXTURE_DIRS {
        walk(&Path::new(ROOT).join(dir), &mut paths);
    }
    let mut rels: Vec<String> = paths
        .iter()
        .map(|p| {
            let rel = p.strip_prefix(ROOT).unwrap().to_str().unwrap();
            rel.strip_suffix(".gz").unwrap_or(rel).to_owned()
        })
        .collect();
    rels.sort();
    rels
}

/// One JSON line per string, ordered by offset then content, so the text is
/// independent of extraction order.
fn canonical(strings: &[ExtractedString]) -> Vec<String> {
    let mut lines: Vec<(u64, String)> = strings
        .iter()
        .map(|s| (s.data_offset, serde_json::to_string(s).unwrap()))
        .collect();
    lines.sort();
    lines.into_iter().map(|(_, line)| line).collect()
}

/// The manifest row for one fixture under one config.
fn row(config: &str, rel: &str, strings: &[ExtractedString], lines: &[String]) -> String {
    let mut hash = Sha256::new();
    for line in lines {
        hash.update(line.as_bytes());
        hash.update(b"\n");
    }
    let hash = hash.finalize();
    let mut methods = BTreeMap::new();
    for s in strings {
        *methods.entry(format!("{:?}", s.method)).or_insert(0usize) += 1;
    }
    let mut out = format!("{config}\t{rel}\t{}\t", strings.len());
    for b in &hash[..8] {
        write!(out, "{b:02x}").unwrap();
    }
    out.push('\t');
    let methods: Vec<String> = methods.iter().map(|(m, n)| format!("{m}={n}")).collect();
    out.push_str(&methods.join(" "));
    out
}

fn write_dump(dir: &Path, config: &str, rel: &str, lines: &[String]) {
    let path = dir.join(config).join(format!("{rel}.jsonl"));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, lines.join("\n") + "\n").unwrap();
}

#[test]
fn output_matches_golden_manifest() {
    let dump = std::env::var_os("STNG_GOLDEN_DUMP").map(PathBuf::from);
    let mismatch_dir = Path::new(ROOT).join("target/golden/actual");
    let fixtures = fixtures();
    let configs = configs();

    let jobs: Vec<(&str, &ExtractOptions, &str)> = configs
        .iter()
        .flat_map(|(name, opts)| fixtures.iter().map(move |rel| (*name, opts, rel.as_str())))
        .collect();
    let rows: Vec<(String, Vec<String>)> = jobs
        .par_iter()
        .map(|&(config, opts, rel)| {
            let data = common::bytes(rel);
            let strings = stng::extract_strings_with_options(&data, opts);
            let lines = canonical(&strings);
            if let Some(dir) = &dump {
                write_dump(dir, config, rel, &lines);
            }
            (row(config, rel, &strings, &lines), lines)
        })
        .collect();

    if dump.is_some() {
        return;
    }
    let actual: String = rows.iter().map(|(r, _)| format!("{r}\n")).collect();
    let manifest = Path::new(ROOT).join(MANIFEST);
    if std::env::var_os("STNG_BLESS").is_some() {
        std::fs::write(&manifest, &actual).unwrap();
        return;
    }

    let expected = std::fs::read_to_string(&manifest).unwrap_or_default();
    let key = |r: &str| r.splitn(3, '\t').take(2).collect::<Vec<_>>().join("\t");
    let want: BTreeMap<String, &str> = expected.lines().map(|r| (key(r), r)).collect();
    let mut problems = Vec::new();
    for (r, lines) in &rows {
        let k = key(r);
        match want.get(&k) {
            Some(w) if *w == r => {}
            Some(w) => {
                let mut parts = k.split('\t');
                let (config, rel) = (parts.next().unwrap(), parts.next().unwrap());
                write_dump(&mismatch_dir, config, rel, lines);
                problems.push(format!("changed:\n  - {w}\n  + {r}"));
            }
            None => problems.push(format!("new: {r}")),
        }
    }
    let have: std::collections::HashSet<String> = rows.iter().map(|(r, _)| key(r)).collect();
    for k in want.keys().filter(|k| !have.contains(*k)) {
        problems.push(format!("missing: {k}"));
    }
    assert!(
        problems.is_empty(),
        "{} golden row(s) differ from {MANIFEST}; full output of changed rows is in {}.\n\
         Run scripts/golden-diff to see the exact strings, or STNG_BLESS=1 to accept.\n\n{}",
        problems.len(),
        mismatch_dir.display(),
        problems.join("\n")
    );
}
