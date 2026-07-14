// Command implementations. Each run* function parses its own flags,
// delegates to the ca/policy/audit packages, and maps errors onto the
// documented exit codes.
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/JaydenCJ/certclerk/internal/audit"
	"github.com/JaydenCJ/certclerk/internal/ca"
	"github.com/JaydenCJ/certclerk/internal/policy"
	"github.com/JaydenCJ/certclerk/internal/sshcert"
)

func runInit(args []string, stdout, stderr io.Writer) int {
	fs, dir := newFlagSet("init", stderr)
	comment := fs.String("comment", "certclerk-ca", "comment on the CA public key")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	d := resolveDir(*dir)
	authority, err := ca.Init(d, *comment, timeNow())
	if err != nil {
		return runtimeErr(stderr, err)
	}
	fmt.Fprintf(stdout, "initialized CA in %s\n", d)
	fmt.Fprintf(stdout, "CA fingerprint: %s\n", authority.Pub.Fingerprint())
	fmt.Fprintf(stdout, "next steps: edit %s/policy.json, then `certclerk setup` for the host snippet\n", d)
	return ExitOK
}

func runIssue(args []string, stdout, stderr io.Writer) int {
	fs, dir := newFlagSet("issue", stderr)
	user := fs.String("user", "", "user requesting the certificate (required)")
	keyPath := fs.String("key", "", "path to the user's public key (required)")
	principalsCSV := fs.String("principals", "", "comma-separated principals (default: all the policy grants)")
	ttl := fs.String("ttl", "", "requested lifetime, e.g. 30m, 2h, 1d (default: the policy's max_ttl)")
	keyID := fs.String("key-id", "", "certificate key ID (default <user>@certclerk-<serial>)")
	backdate := fs.String("backdate", "60s", "shift ValidAfter into the past to absorb clock skew")
	out := fs.String("out", "", "output path (default <key>-cert.pub next to --key, `-` for stdout)")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if *user == "" || *keyPath == "" {
		return usageErr(stderr, fs, "--user and --key are required")
	}
	key, err := sshcert.LoadPublicKey(*keyPath)
	if err != nil {
		return runtimeErr(stderr, err)
	}
	req := ca.IssueRequest{User: *user, Key: key, Now: timeNow()}
	if *principalsCSV != "" {
		for _, p := range strings.Split(*principalsCSV, ",") {
			if p = strings.TrimSpace(p); p != "" {
				req.Principals = append(req.Principals, p)
			}
		}
	}
	if *ttl != "" {
		d, err := policy.ParseTTL(*ttl)
		if err != nil {
			return usageErr(stderr, fs, "--ttl: %v", err)
		}
		req.TTL = d
	}
	if *backdate != "" {
		d, err := policy.ParseTTL(*backdate)
		if err != nil {
			return usageErr(stderr, fs, "--backdate: %v", err)
		}
		req.Backdate = d
	}
	req.KeyID = *keyID
	authority, err := ca.Open(resolveDir(*dir))
	if err != nil {
		return runtimeErr(stderr, err)
	}
	issued, err := authority.Issue(req)
	var deny *policy.DenyError
	if errors.As(err, &deny) {
		fmt.Fprintf(stderr, "certclerk: %v\n", deny)
		return ExitFindings
	}
	if err != nil {
		return runtimeErr(stderr, err)
	}
	dest := *out
	if dest == "" {
		dest = strings.TrimSuffix(*keyPath, ".pub") + "-cert.pub"
	}
	if dest == "-" {
		fmt.Fprintln(stdout, issued.Line)
	} else if err := os.WriteFile(dest, []byte(issued.Line+"\n"), 0o644); err != nil {
		return runtimeErr(stderr, err)
	}
	c := issued.Cert
	fmt.Fprintf(stdout, "issued serial %d to %s: principals %s, valid %s (until %s)\n",
		c.Serial, *user, strings.Join(c.ValidPrincipals, ","),
		policy.FormatTTL(issued.Grant.TTL), issued.Entry.ValidBefore)
	if dest != "-" {
		fmt.Fprintf(stdout, "wrote %s\n", dest)
	}
	return ExitOK
}

func runVerify(args []string, stdout, stderr io.Writer) int {
	fs, dir := newFlagSet("verify", stderr)
	at := fs.String("at", "", "verify as of this RFC 3339 instant (default now)")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() != 1 {
		return usageErr(stderr, fs, "expected exactly one certificate file")
	}
	when, err := parseAt(*at)
	if err != nil {
		return usageErr(stderr, fs, "%v", err)
	}
	cert, err := loadCert(fs.Arg(0))
	if err != nil {
		return runtimeErr(stderr, err)
	}
	authority, err := ca.Open(resolveDir(*dir))
	if err != nil {
		return runtimeErr(stderr, err)
	}
	verdict, err := authority.Verify(cert, when)
	if err != nil {
		fmt.Fprintf(stderr, "certclerk: verify %s: %v\n", fs.Arg(0), err)
		return ExitFindings
	}
	fmt.Fprintln(stdout, verdict)
	return ExitOK
}

func runRevoke(args []string, stdout, stderr io.Writer) int {
	fs, dir := newFlagSet("revoke", stderr)
	serial := fs.Uint64("serial", 0, "serial to revoke (issued serials start at 1)")
	keyID := fs.String("key-id", "", "revoke every certificate with this key ID")
	reason := fs.String("reason", "", "free-text reason recorded in the audit log")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if (*serial == 0) == (*keyID == "") {
		return usageErr(stderr, fs, "exactly one of --serial or --key-id is required")
	}
	authority, err := ca.Open(resolveDir(*dir))
	if err != nil {
		return runtimeErr(stderr, err)
	}
	if *serial != 0 {
		if _, err := authority.RevokeSerial(*serial, *reason, timeNow()); err != nil {
			return runtimeErr(stderr, err)
		}
		fmt.Fprintf(stdout, "revoked serial %d\n", *serial)
	} else {
		if _, err := authority.RevokeKeyID(*keyID, *reason, timeNow()); err != nil {
			return runtimeErr(stderr, err)
		}
		fmt.Fprintf(stdout, "revoked key id %q\n", *keyID)
	}
	fmt.Fprintln(stdout, "re-export the KRL and redistribute it: certclerk krl --out revoked.krl")
	return ExitOK
}

func runKRL(args []string, stdout, stderr io.Writer) int {
	fs, dir := newFlagSet("krl", stderr)
	out := fs.String("out", "", "write the binary KRL here (default stdout)")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	authority, err := ca.Open(resolveDir(*dir))
	if err != nil {
		return runtimeErr(stderr, err)
	}
	blob, err := authority.KRL(timeNow())
	if err != nil {
		return runtimeErr(stderr, err)
	}
	if *out == "" || *out == "-" {
		if _, err := stdout.Write(blob); err != nil {
			return runtimeErr(stderr, err)
		}
		return ExitOK
	}
	if err := os.WriteFile(*out, blob, 0o644); err != nil {
		return runtimeErr(stderr, err)
	}
	revs, _ := authority.Revocations()
	fmt.Fprintf(stdout, "wrote %s (%s, %d bytes)\n", *out, plural(len(revs), "revocation"), len(blob))
	return ExitOK
}

func runPolicy(args []string, stdout, stderr io.Writer) int {
	fs, dir := newFlagSet("policy", stderr)
	user := fs.String("user", "", "show the effective rule for one user")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	authority, err := ca.Open(resolveDir(*dir))
	if err != nil {
		return runtimeErr(stderr, err)
	}
	if *user != "" {
		grant, err := authority.Policy.Describe(*user)
		if err != nil {
			fmt.Fprintf(stderr, "certclerk: %v\n", err)
			return ExitFindings
		}
		printGrant(stdout, grant)
		return ExitOK
	}
	users := make([]string, 0, len(authority.Policy.Users))
	for u := range authority.Policy.Users {
		users = append(users, u)
	}
	sort.Strings(users)
	fmt.Fprintf(stdout, "policy: %s, version %d\n", plural(len(users), "user"), authority.Policy.Version)
	for _, u := range users {
		grant, err := authority.Policy.Describe(u)
		if err != nil {
			return runtimeErr(stderr, err)
		}
		fmt.Fprintf(stdout, "  %-16s principals=%s max_ttl=%s\n",
			u, joinOrDash(grant.Principals), policy.FormatTTL(grant.MaxTTL))
	}
	return ExitOK
}

func printGrant(w io.Writer, g *policy.Grant) {
	fmt.Fprintf(w, "policy for %s:\n", g.User)
	fmt.Fprintf(w, "  principals:     %s\n", joinOrDash(g.Principals))
	fmt.Fprintf(w, "  max_ttl:        %s\n", policy.FormatTTL(g.MaxTTL))
	fmt.Fprintf(w, "  extensions:     %s\n", joinOrDash(g.Extensions))
	fmt.Fprintf(w, "  source_address: %s\n", joinOrDash(g.SourceAddress))
	fc := g.ForceCommand
	if fc == "" {
		fc = "(none)"
	}
	fmt.Fprintf(w, "  force_command:  %s\n", fc)
}

func joinOrDash(items []string) string {
	if len(items) == 0 {
		return "(none)"
	}
	return strings.Join(items, ",")
}

// plural renders "1 entry" / "3 entries" — counted nouns in CLI output
// go through here so no message ever reads "1 entries".
func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", noun)
	}
	if strings.HasSuffix(noun, "y") {
		noun = strings.TrimSuffix(noun, "y") + "ie"
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

func runAudit(args []string, stdout, stderr io.Writer) int {
	fs, dir := newFlagSet("audit", stderr)
	verify := fs.Bool("verify", false, "verify the hash chain instead of printing entries")
	format := fs.String("format", "text", "output format: text or json")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if *format != "text" && *format != "json" {
		return usageErr(stderr, fs, "--format must be text or json")
	}
	d := resolveDir(*dir)
	log := audit.Open(d + string(os.PathSeparator) + ca.FileAudit)
	entries, err := log.Entries()
	if err != nil {
		return runtimeErr(stderr, err)
	}
	if *verify {
		if err := audit.Verify(entries); err != nil {
			fmt.Fprintf(stderr, "certclerk: %v\n", err)
			return ExitFindings
		}
		fmt.Fprintf(stdout, "audit ok: %s, chain intact\n", plural(len(entries), "entry"))
		return ExitOK
	}
	for _, e := range entries {
		if *format == "json" {
			// The stored lines are already canonical JSON; re-marshaling
			// them could silently change what the hashes cover.
			fmt.Fprintln(stdout, auditJSON(e))
			continue
		}
		fmt.Fprintln(stdout, auditText(e))
	}
	return ExitOK
}

func runSetup(args []string, stdout, stderr io.Writer) int {
	fs, dir := newFlagSet("setup", stderr)
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	authority, err := ca.Open(resolveDir(*dir))
	if err != nil {
		return runtimeErr(stderr, err)
	}
	fmt.Fprintf(stdout, `# certclerk host setup — one-time, per host.
#
# 1. Copy the CA *public* key to each host (never ca.key):
#      %s
#    contents:
#      %s
#
# 2. Add to /etc/ssh/sshd_config, then reload sshd:
TrustedUserCAKeys /etc/ssh/certclerk-ca.pub
RevokedKeys /etc/ssh/certclerk-revoked.krl
#
# 3. Seed the revocation list (an empty KRL is valid) and re-copy it
#    after every revoke:
#      certclerk krl --out certclerk-revoked.krl
#
# Clients connect with their key + certificate, no authorized_keys entry:
#      ssh -i id_ed25519 -o CertificateFile=id_ed25519-cert.pub user@host
`, ca.FilePub, authority.Pub.MarshalAuthorizedKey())
	return ExitOK
}

// loadCert reads a certificate from a -cert.pub file.
func loadCert(path string) (*sshcert.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c, err := sshcert.ParseCertificateLine(string(b))
	if err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	return c, nil
}
