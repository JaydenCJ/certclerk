// Command certclerk is the entry point; all logic lives in
// internal/cli so it can be tested in-process.
package main

import (
	"os"

	"github.com/JaydenCJ/certclerk/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
