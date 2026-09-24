use std::io::Write;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut a = std::env::args().skip(1);
    let out = a.next().ok_or("usage: zz_set <out> <file>...")?;
    let mut f = std::fs::File::create(&out)?;
    for p in a {
        let d = std::fs::read(&p)?;
        let t = std::time::Instant::now();
        let s = stng::extract_strings(&d, 4);
        let ms = t.elapsed().as_secs_f64() * 1000.0;
        eprintln!(
            "{p}\t{:.0}ms\t{} strings\trust={}",
            ms,
            s.len(),
            stng::is_rust_binary(&d)
        );
        for x in s {
            writeln!(f, "{p}\t{}", x.value.replace('\n', "\\n"))?;
        }
    }
    Ok(())
}
