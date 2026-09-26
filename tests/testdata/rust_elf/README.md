# rust_elf fixture

A dependency-free Rust program (`src/`), built stripped, used by
`tests/test_rust_elf_detection.rs`. An ordinary executable carries no `.rustc`
section, and this one -- from Arch's distro toolchain, which remaps libstd's
source prefix -- carries neither `/rustc/<sha>` nor `index.crates.io` either;
only `library/std/src/...` panic locations identify it as Rust.

Built with rustc 1.98.1 (Arch Linux):

```sh
cd src && cargo build --release && cp target/release/stngrust ../linux_amd64
```
