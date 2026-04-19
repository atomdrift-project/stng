//! End-to-end extraction benchmarks using real testdata samples.
//!
//! These benchmarks exercise the full extraction pipeline on representative
//! binaries so that profiling tools (perf, samply, flamegraph) can identify
//! real-world hotspots.
//!
//! Run all:        cargo bench --bench extract
//! Profile one:    cargo bench --bench extract -- "go_garble_3mb"
//! With flamegraph: cargo flamegraph --bench extract -- --bench "go_garble_3mb"

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::time::Duration;
use stng::ExtractOptions;

/// Load a testdata file, returning None if it doesn't exist (CI may lack large fixtures).
fn load(path: &str) -> Option<Vec<u8>> {
    std::fs::read(path).ok()
}

// ---------------------------------------------------------------------------
// Full extraction pipeline
// ---------------------------------------------------------------------------

fn bench_extract(c: &mut Criterion) {
    let mut g = c.benchmark_group("extract");
    g.sample_size(10);
    g.measurement_time(Duration::from_secs(15));

    let samples: &[(&str, &str)] = &[
        ("go_garble_3mb", "testdata/garble/garble_linux_amd64_1"),
        ("go_poolrat_2.7mb", "testdata/malware/poolrat"),
        (
            "pe_wizardnet_1.2mb",
            "testdata/malware/wizardnet_downloader.dll",
        ),
        ("go_vget_1.7mb", "testdata/malware/vget_sample"),
        ("elf_stealer_8.5mb", "testdata/malware/sample-stealer"),
        (
            "script_kworker_23kb",
            "testdata/kworker_samples/kworker_obfuscated_1",
        ),
    ];

    for (name, path) in samples {
        let Some(data) = load(path) else { continue };
        let len = data.len() as u64;

        g.throughput(Throughput::Bytes(len));
        g.bench_with_input(BenchmarkId::new("default", name), &data, |b, data| {
            b.iter(|| stng::extract_strings(black_box(data), 4));
        });
    }

    g.finish();
}

// ---------------------------------------------------------------------------
// Extraction with garbage filtering (mirrors CLI default)
// ---------------------------------------------------------------------------

fn bench_extract_filtered(c: &mut Criterion) {
    let mut g = c.benchmark_group("extract_filtered");
    g.sample_size(10);
    g.measurement_time(Duration::from_secs(15));

    let samples: &[(&str, &str)] = &[
        ("go_garble_3mb", "testdata/garble/garble_linux_amd64_1"),
        ("go_poolrat_2.7mb", "testdata/malware/poolrat"),
        ("elf_stealer_8.5mb", "testdata/malware/sample-stealer"),
    ];

    for (name, path) in samples {
        let Some(data) = load(path) else { continue };
        let len = data.len() as u64;
        let mut opts = ExtractOptions::new(4);
        opts.filter_garbage = true;

        g.throughput(Throughput::Bytes(len));
        g.bench_with_input(
            BenchmarkId::new("garbage_filter", name),
            &data,
            |b, data| {
                let opts = opts.clone();
                b.iter(|| stng::extract_strings_with_options(black_box(data), &opts));
            },
        );
    }

    g.finish();
}

// ---------------------------------------------------------------------------
// Extraction with XOR scanning enabled
// ---------------------------------------------------------------------------

fn bench_extract_xor(c: &mut Criterion) {
    let mut g = c.benchmark_group("extract_xor");
    g.sample_size(10);
    g.measurement_time(Duration::from_secs(20));

    let samples: &[(&str, &str)] = &[
        ("xor_brew_agent_363kb", "testdata/xor/brew_agent_xor_sample"),
        ("brew_agent_363kb", "testdata/malware/brew_agent"),
    ];

    for (name, path) in samples {
        let Some(data) = load(path) else { continue };
        let len = data.len() as u64;
        let mut opts = ExtractOptions::new(4);
        opts.xor_scan = true;
        opts.filter_garbage = true;

        g.throughput(Throughput::Bytes(len));
        g.bench_with_input(BenchmarkId::new("xor_scan", name), &data, |b, data| {
            let opts = opts.clone();
            b.iter(|| stng::extract_strings_with_options(black_box(data), &opts));
        });
    }

    g.finish();
}

// ---------------------------------------------------------------------------
// Validation / garbage detection in isolation
// ---------------------------------------------------------------------------

fn bench_validation(c: &mut Criterion) {
    let mut g = c.benchmark_group("validation");

    // Extract strings from a sample first, then benchmark is_garbage on them
    let Some(data) = load("testdata/malware/poolrat") else {
        return;
    };
    let strings = stng::extract_strings(&data, 4);

    // Collect a representative batch of extracted string values
    let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();

    g.throughput(Throughput::Elements(values.len() as u64));
    g.bench_function("is_garbage_batch", |b| {
        b.iter(|| {
            for s in &values {
                black_box(stng::is_garbage(black_box(s)));
            }
        });
    });

    g.bench_function("classify_batch", |b| {
        b.iter(|| {
            for s in &values {
                black_box(stng::classify_string(black_box(s)));
            }
        });
    });

    g.finish();
}

criterion_group!(
    benches,
    bench_extract,
    bench_extract_filtered,
    bench_extract_xor,
    bench_validation
);
criterion_main!(benches);
