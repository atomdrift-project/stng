use std::time::Instant;

fn main() {
    let data = std::fs::read("/bin/cmake").unwrap();
    let elf = goblin::elf::Elf::parse(&data).unwrap();
    let t0 = Instant::now();
    let extractor = stng::rust::RustStringExtractor::new(4);
    let _ = extractor.extract_elf(&elf, &data);
    println!("extract_elf took {:?}", t0.elapsed());
}
