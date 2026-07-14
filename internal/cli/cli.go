// Package cli implements the certclerk command-line interface. Run
// takes argv and two writers and returns an exit code, so the entire
// surface is testable in-process without building a binary.
package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/JaydenCJ/certclerk/internal/version"
)

// Exit codes, documented in the README. ExitFindings is the
// machine-readable verdict for "the CA said no": a failed verify, a
// policy denial, or a broken audit chain.
const (
	ExitOK       = 0
	ExitFindings = 1
	ExitUsage    = 2
	ExitRuntime  = 3
)

// DefaultDir is used when neither --dir nor CERTCLERK_DIR names the CA
// directory. A dotted directory in the working tree, mirroring how
// people keep per-project state.
const DefaultDir = ".certclerk"

// timeNow is swapped by tests to pin issuance and revocation times.
var timeNow = time.Now

// Run dispatches argv and returns the process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stdout)
		return ExitOK
	}
	switch args[0] {
	case "init":
		return runInit(args[1:], stdout, stderr)
	case "issue":
		return runIssue(args[1:], stdout, stderr)
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	case "inspect":
		return runInspect(args[1:], stdout, stderr)
	case "revoke":
		return runRevoke(args[1:], stdout, stderr)
	case "krl":
		return runKRL(args[1:], stdout, stderr)
	case "policy":
		return runPolicy(args[1:], stdout, stderr)
	case "audit":
		return runAudit(args[1:], stdout, stderr)
	case "setup":
		return runSetup(args[1:], stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "certclerk %s\n", version.Version)
		return ExitOK
	case "help", "--help", "-h":
		usage(stdout)
		return ExitOK
	default:
		fmt.Fprintf(stderr, "certclerk: unknown command %q\n\n", args[0])
		usage(stderr)
		return ExitUsage
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `certclerk — tiny SSH certificate authority for plain OpenSSH.

Usage:
  certclerk <command> [flags] [args]

Commands:
  init     create a CA directory (keypair, policy.json, audit log)
  issue    sign a short-lived user certificate under the policy
  verify   check a certificate: signature, window, revocation
  inspect  print a certificate's contents (text or JSON)
  revoke   revoke by --serial or by --key-id
  krl      export the revocation list as an OpenSSH binary KRL
  policy   show the effective policy, whole or for one --user
  audit    print the audit log; --verify checks the hash chain
  setup    print the sshd_config snippet for your hosts
  version  print the version

The CA directory resolves from --dir, then $CERTCLERK_DIR, then ./.certclerk.
Exit codes: 0 ok, 1 denied/invalid/broken, 2 usage error, 3 runtime error.
`)
}

// newFlagSet builds a silent FlagSet whose errors we render ourselves,
// plus the --dir flag every command shares.
func newFlagSet(name string, stderr io.Writer) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "", "CA directory (default $CERTCLERK_DIR or "+DefaultDir+")")
	return fs, dir
}

// newBareFlagSet is newFlagSet without --dir, for commands (inspect)
// that operate on a file and never touch the CA directory.
func newBareFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// resolveDir applies the --dir > $CERTCLERK_DIR > default chain.
func resolveDir(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if env := os.Getenv("CERTCLERK_DIR"); env != "" {
		return env
	}
	return DefaultDir
}

// parseAt parses a --at timestamp, defaulting to the current time.
// Pinning --at keeps verify deterministic in tests and lets operators
// answer "was this cert valid last Tuesday?".
func parseAt(s string) (time.Time, error) {
	if s == "" {
		return time.Now(), nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("--at must be RFC 3339 (e.g. 2026-07-13T12:00:00Z): %v", err)
	}
	return t, nil
}

func usageErr(stderr io.Writer, fs *flag.FlagSet, format string, args ...any) int {
	fmt.Fprintf(stderr, "certclerk %s: %s\n", fs.Name(), fmt.Sprintf(format, args...))
	return ExitUsage
}

func runtimeErr(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "certclerk: %v\n", err)
	return ExitRuntime
}
