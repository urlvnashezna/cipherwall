// Cipherwall - secret and dependency scanner for your repositories.
//
// Scans a working tree for leaked credentials (API keys, tokens, private
// keys) and checks dependency manifests against known advisories. Meant to
// run locally, in CI, or as a pre-commit hook.
package main

import (
	"fmt"
	"os"

	"github.com/urlvnashezna/cipherwall/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
