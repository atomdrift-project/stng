use std::io::Write;
fn main() {
    let mut a = std::env::args().skip(1);
    let out = a.next().unwrap();
    let mut f = std::fs::File::create(&out).unwrap();
    for p in a {
        let d = std::fs::read(&p).unwrap();
        let t = std::time::Instant::now();
        let s = stng::extract_strings(&d, 4);
        let ms = t.elapsed().as_secs_f64() * 1000.0;
        eprintln!("{p}\t{:.0}ms\t{} strings\trust={}", ms, s.len(), stng::is_rust_binary(&d));
        for x in s { writeln!(f, "{p}\t{}", x.value.replace('\n', "\\n")).unwrap(); }
    }
}
