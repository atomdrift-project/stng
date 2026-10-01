// Fixture for stng's Rust ELF detection tests: an ordinary stripped
// executable, which -- unlike a dylib or proc-macro -- carries no `.rustc`
// section. Its literals live in rustc's packed `&str` blob, reachable only
// through their (ptr, len) references. Does nothing useful when run.
use std::hint::black_box;

#[inline(never)]
fn table() -> [&'static str; 3] {
    [
        "stng-rust-fixture-alpha-literal",
        "stng-rust-fixture-bravo-literal",
        "stng-rust-fixture-charlie-literal",
    ]
}

fn main() {
    for s in black_box(table()) {
        println!("{s}");
    }
    eprintln!("{}", black_box("stng-rust-fixture-delta-literal"));
}
