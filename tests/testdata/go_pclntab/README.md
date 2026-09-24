# go_pclntab fixtures

One small Go program (`src/main.go`), built stripped for three targets, used by
`tests/test_macho_go_pclntab.rs` to check that Go function names are recovered
from the pclntab of Mach-O builds as they are from ELF.

Built with Go 1.27.1:

```sh
cd src
for t in darwin/amd64 darwin/arm64 linux/amd64; do
  CGO_ENABLED=0 GOOS=${t%/*} GOARCH=${t#*/} \
    go build -trimpath -ldflags='-s -w -buildid=' -o ../${t%/*}_${t#*/} .
done
```

`-s -w` strips the symbol table and DWARF, as release malware builds are, so
the pclntab is the only place the function names survive. The tests build the
universal binary they need from the two darwin slices at run time rather than
carrying a fourth file.
