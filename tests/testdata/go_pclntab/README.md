# go_pclntab fixtures

One small Go program (`src/main.go`), built stripped for six targets, used by

- `tests/test_macho_go_pclntab.rs` — Go function names are recovered from the
  pclntab of Mach-O builds as they are from ELF;
- `tests/test_go_stored_string_table.rs` — string literals Go stores on the
  stack as `{ptr, len}` pairs (`stngFixturePathTable`) are recovered on arm64
  as they are on amd64.

Built with Go 1.27.1:

```sh
cd src
for t in darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 windows/amd64 windows/arm64; do
  CGO_ENABLED=0 GOOS=${t%/*} GOARCH=${t#*/} \
    go build -trimpath -ldflags='-s -w -buildid=' -o ../${t%/*}_${t#*/} .
done
```

`-s -w` strips the symbol table and DWARF, as release malware builds are, so
the pclntab is the only place the function names survive. The tests build the
universal binary they need from the two darwin slices at run time rather than
carrying a fourth file.
