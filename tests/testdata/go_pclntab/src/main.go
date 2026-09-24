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

//go:noinline
func stngFixturePrepareRemoteTarget(dir string) string {
	return dir + "/.vault-token-fixture"
}

func main() {
	fmt.Println(stngFixturePublishRecursively(len(os.Args)))
	fmt.Println(stngFixtureReadCredentialFile(os.Getenv("HOME")))
	fmt.Println(stngFixturePrepareRemoteTarget(os.TempDir()))
}
