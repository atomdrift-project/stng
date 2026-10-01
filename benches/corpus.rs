//! Corpus benchmark: wall-clock and CPU time across rayon pool sizes, cold-start
//! latency, and per-method yield. Criterion (`benches/extract.rs`) times single
//! samples; this answers the pipeline questions — what a corpus costs in CPU,
//! how wall time scales with threads, and what the first call in a fresh
//! process pays.
//!
//! ```text
//! cargo bench --bench corpus -- [--threads 1,4,8] [--iters 3] [--opts filefacts|default] PATH...
//! ```
//!
//! PATHs are files or directories (walked recursively); `.gz` files are
//! inflated in memory. With no PATH, the fixture corpus is used. CPU time comes
//! from /proc/self/stat (all threads), so it is reported on Linux only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use flate2::read::GzDecoder;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use stng::ExtractOptions;

const COLD_RUNS: usize = 15;
const COLD_FILE: &str = "testdata/pe/msvc_console_amd64.exe.gz";

fn opts(name: &str) -> ExtractOptions {
    match name {
        "filefacts" => ExtractOptions::new(4)
            .with_garbage_filter(true)
            .with_caller_provides_symbols(true)
            .with_xor(None),
        "default" => ExtractOptions::new(4),
        other => panic!("unknown --opts {other}: want filefacts or default"),
    }
}

fn load(path: &Path) -> Vec<u8> {
    let raw = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    if path.extension().is_some_and(|e| e == "gz") {
        let mut out = Vec::new();
        GzDecoder::new(raw.as_slice())
            .read_to_end(&mut out)
            .unwrap();
        out
    } else {
        raw
    }
}

fn walk(path: &Path, out: &mut Vec<PathBuf>) {
    if path.is_dir() {
        for entry in std::fs::read_dir(path).unwrap() {
            walk(&entry.unwrap().path(), out);
        }
    } else {
        out.push(path.to_owned());
    }
}

/// Process CPU time (user + system, all threads), Linux only.
fn cpu_time() -> Option<Duration> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    // Fields after the parenthesised command name; utime and stime are the
    // 12th and 13th of those, in USER_HZ (100 on Linux) ticks.
    let rest = &stat[stat.rfind(')')? + 2..];
    let mut fields = rest.split(' ').skip(11);
    let ticks: u64 = fields.next()?.parse::<u64>().ok()? + fields.next()?.parse::<u64>().ok()?;
    Some(Duration::from_millis(ticks * 10))
}

fn ms(d: Duration) -> String {
    format!("{:.1}", d.as_secs_f64() * 1000.0)
}

/// Child mode: time the first extraction in this process, then a warm one.
fn cold_child(opts_name: &str) {
    let data = load(&Path::new(env!("CARGO_MANIFEST_DIR")).join(COLD_FILE));
    let opts = opts(opts_name);
    let t = Instant::now();
    std::hint::black_box(stng::extract_strings_with_options(&data, &opts));
    let first = t.elapsed();
    let t = Instant::now();
    std::hint::black_box(stng::extract_strings_with_options(&data, &opts));
    println!("{} {}", first.as_micros(), t.elapsed().as_micros());
}

/// Median first-call and warm-call latency over fresh processes.
fn cold_start(threads: usize, opts_name: &str) -> (u128, u128) {
    let exe = std::env::current_exe().unwrap();
    let mut runs: Vec<(u128, u128)> = (0..COLD_RUNS)
        .map(|_| {
            let out = Command::new(&exe)
                .args(["--cold-child", "--opts", opts_name])
                .env("RAYON_NUM_THREADS", threads.to_string())
                .output()
                .unwrap();
            let text = String::from_utf8(out.stdout).unwrap();
            let mut it = text.split_whitespace().map(|v| v.parse::<u128>().unwrap());
            (it.next().unwrap(), it.next().unwrap())
        })
        .collect();
    runs.sort_unstable();
    runs[runs.len() / 2]
}

fn main() {
    let mut threads = vec![1, 4, 8];
    let mut iters = 3usize;
    let mut opts_name = "filefacts".to_owned();
    let mut paths = Vec::new();
    let mut cold_child_mode = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--threads" => {
                threads = args
                    .next()
                    .unwrap()
                    .split(',')
                    .map(|t| t.parse().unwrap())
                    .collect();
            }
            "--iters" => iters = args.next().unwrap().parse().unwrap(),
            "--opts" => opts_name = args.next().unwrap(),
            "--cold-child" => cold_child_mode = true,
            "--bench" => {} // passed by `cargo bench`
            _ => paths.push(PathBuf::from(arg)),
        }
    }
    if cold_child_mode {
        cold_child(&opts_name);
        return;
    }
    if paths.is_empty() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        paths = vec![root.join("testdata")];
    }
    let mut files = Vec::new();
    for p in &paths {
        walk(p, &mut files);
    }
    files.sort();
    let corpus: Vec<(PathBuf, Vec<u8>)> =
        files.into_iter().map(|f| (f.clone(), load(&f))).collect();
    let bytes: usize = corpus.iter().map(|(_, d)| d.len()).sum();
    let opts = opts(&opts_name);
    println!(
        "corpus: {} files, {:.1} MB, opts={opts_name}, iters={iters}",
        corpus.len(),
        bytes as f64 / 1e6
    );

    println!("\nthreads\twall_ms\tcpu_ms\tcpu/wall\tcold_first_us\tcold_warm_us");
    let mut per_file: BTreeMap<usize, Vec<Duration>> = BTreeMap::new();
    let mut methods: BTreeMap<String, usize> = BTreeMap::new();
    for &n in &threads {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(n)
            .build()
            .unwrap();
        let (wall, cpu, times) = pool.install(|| {
            for (_, data) in &corpus {
                std::hint::black_box(stng::extract_strings_with_options(data, &opts));
            }
            let cpu0 = cpu_time();
            let t0 = Instant::now();
            let mut times = Vec::with_capacity(corpus.len());
            for (_, data) in &corpus {
                let t = Instant::now();
                for _ in 0..iters {
                    std::hint::black_box(stng::extract_strings_with_options(data, &opts));
                }
                times.push(t.elapsed() / u32::try_from(iters).unwrap());
            }
            let cpu = cpu_time()
                .zip(cpu0)
                .map(|(b, a)| (b - a) / u32::try_from(iters).unwrap());
            (t0.elapsed() / u32::try_from(iters).unwrap(), cpu, times)
        });
        if methods.is_empty() {
            for (_, data) in &corpus {
                for s in stng::extract_strings_with_options(data, &opts) {
                    *methods.entry(format!("{:?}", s.method)).or_default() += 1;
                }
            }
        }
        let (cold_first, cold_warm) = cold_start(n, &opts_name);
        println!(
            "{n}\t{}\t{}\t{}\t{cold_first}\t{cold_warm}",
            ms(wall),
            cpu.map_or("-".into(), ms),
            cpu.map_or("-".into(), |c| format!(
                "{:.2}",
                c.as_secs_f64() / wall.as_secs_f64()
            )),
        );
        per_file.insert(n, times);
    }

    println!("\nslowest files (ms/iter at each thread count):");
    let first = threads[0];
    let mut order: Vec<usize> = (0..corpus.len()).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(per_file[&first][i]));
    for &i in order.iter().take(10) {
        let cols: Vec<String> = threads.iter().map(|n| ms(per_file[n][i])).collect();
        let (path, data) = &corpus[i];
        println!(
            "  {:>10} B  {}  {}",
            data.len(),
            cols.join("\t"),
            path.display()
        );
    }

    println!("\nstrings by method:");
    for (method, count) in &methods {
        println!("  {count:>8}  {method}");
    }
}
