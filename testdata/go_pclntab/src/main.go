// Fixture for stng's Go function-name extraction tests. The function names
// are deliberately distinctive so a test can tell a recovered pclntab entry
// from any other string; //go:noinline keeps each one a real function with
// its own funcnametab entry. The path literals are ordinary string data, so
// the same build also shows whether Go string literals survive on each
// format. Nothing here does anything when run.
package main

import (
	"fmt"
	"os"
)

//go:noinline
func stngFixturePublishRecursively(depth int) int {
	if depth <= 0 {
		return 0
	}
	return depth + stngFixturePublishRecursively(depth-1)
}

//go:noinline
func stngFixtureReadCredentialFile(name string) string {
	return name + "/.git-credentials-fixture"
}

// stngFixturePathTable walks a local []string of constants. The slice does
// not escape, so Go builds its backing array on the stack: on arm64 each
// element is an ADRP+ADD pointer and a length stored with one STP, and no call
// follows to anchor a scan on — the shape of an implant's credential-path
// table.
//
//go:noinline
func stngFixturePathTable(home string) []string {
	var out []string
	for _, p := range []string{
		"/.stng-fixture-table-alpha",
		"/.stng-fixture-table-bravo",
		"/.stng-fixture-table-charlie",
		"/.stng-fixture-table-delta1",
	} {
		out = append(out, home+p)
	}
	return out
}

//go:noinline
func stngFixturePrepareRemoteTarget(dir string) string {
	return dir + "/.vault-token-fixture"
}

func main() {
	fmt.Println(stngFixturePublishRecursively(len(os.Args)))
	fmt.Println(stngFixtureReadCredentialFile(os.Getenv("HOME")))
	fmt.Println(stngFixturePrepareRemoteTarget(os.TempDir()))
	fmt.Println(stngFixturePathTable(os.Getenv("HOME")))
}
