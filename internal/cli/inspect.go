// `inspect` output and audit-log rendering. Inspect needs no CA
// directory: it explains any OpenSSH certificate, including foreign
// ones, in text or stable JSON.
package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/JaydenCJ/certclerk/internal/audit"
	"github.com/JaydenCJ/certclerk/internal/sshcert"
)

func runInspect(args []string, stdout, stderr io.Writer) int {
	fs := newBareFlagSet("inspect", stderr)
	format := fs.String("format", "text", "output format: text or json")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if *format != "text" && *format != "json" {
		return usageErr(stderr, fs, "--format must be text or json")
	}
	if fs.NArg() != 1 {
		return usageErr(stderr, fs, "expected exactly one certificate file")
	}
	cert, err := loadCert(fs.Arg(0))
	if err != nil {
		return runtimeErr(stderr, err)
	}
	if *format == "json" {
		b, err := json.MarshalIndent(inspectJSON(cert), "", "  ")
		if err != nil {
			return runtimeErr(stderr, err)
		}
		fmt.Fprintln(stdout, string(b))
		return ExitOK
	}
	printCert(stdout, fs.Arg(0), cert)
	return ExitOK
}

func printCert(w io.Writer, path string, c *sshcert.Certificate) {
	sigCA, _ := c.SignatureCA()
	caLine := "(malformed)"
	if sigCA != nil {
		caLine = sigCA.Algo + " " + sigCA.Fingerprint()
	}
	fmt.Fprintf(w, "%s:\n", path)
	fmt.Fprintf(w, "        Type: %s %s certificate\n", c.Algo(), c.TypeString())
	fmt.Fprintf(w, "        Public key: %s %s\n", c.Key.Algo, c.Key.Fingerprint())
	fmt.Fprintf(w, "        Signing CA: %s\n", caLine)
	fmt.Fprintf(w, "        Key ID: %q\n", c.KeyID)
	fmt.Fprintf(w, "        Serial: %d\n", c.Serial)
	fmt.Fprintf(w, "        Valid: %s\n", validityString(c))
	fmt.Fprintf(w, "        Principals: %s\n", joinOrDash(c.ValidPrincipals))
	fmt.Fprintf(w, "        Critical Options: %s\n", optionsString(c.CriticalOptions))
	fmt.Fprintf(w, "        Extensions: %s\n", optionsString(c.Extensions))
}

func validityString(c *sshcert.Certificate) string {
	from := time.Unix(int64(c.ValidAfter), 0).UTC().Format(time.RFC3339)
	if c.ValidBefore == sshcert.InfiniteValidity {
		return "from " + from + " forever"
	}
	return "from " + from + " to " + time.Unix(int64(c.ValidBefore), 0).UTC().Format(time.RFC3339)
}

func optionsString(opts []sshcert.Option) string {
	if len(opts) == 0 {
		return "(none)"
	}
	parts := make([]string, 0, len(opts))
	for _, o := range opts {
		if o.Data == "" {
			parts = append(parts, o.Name)
		} else {
			parts = append(parts, o.Name+" "+o.Data)
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

// inspectJSON builds the stable JSON shape for `inspect --format json`.
func inspectJSON(c *sshcert.Certificate) map[string]any {
	sigCA, _ := c.SignatureCA()
	caFP := ""
	if sigCA != nil {
		caFP = sigCA.Fingerprint()
	}
	opts := func(in []sshcert.Option) map[string]string {
		out := map[string]string{}
		for _, o := range in {
			out[o.Name] = o.Data
		}
		return out
	}
	return map[string]any{
		"schema_version":   1,
		"type":             c.TypeString(),
		"algorithm":        c.Algo(),
		"serial":           c.Serial,
		"key_id":           c.KeyID,
		"public_key":       map[string]string{"algorithm": c.Key.Algo, "fingerprint": c.Key.Fingerprint()},
		"signing_ca":       caFP,
		"principals":       c.ValidPrincipals,
		"valid_after":      time.Unix(int64(c.ValidAfter), 0).UTC().Format(time.RFC3339),
		"valid_before":     time.Unix(int64(c.ValidBefore), 0).UTC().Format(time.RFC3339),
		"critical_options": opts(c.CriticalOptions),
		"extensions":       opts(c.Extensions),
	}
}

// auditText renders one audit entry as a grep-friendly line.
func auditText(e audit.Entry) string {
	var b strings.Builder
	fmt.Fprintf(&b, "#%d %s %-6s", e.Seq, e.Time, e.Action)
	if e.User != "" {
		fmt.Fprintf(&b, " user=%s", e.User)
	}
	if e.Serial != 0 {
		fmt.Fprintf(&b, " serial=%d", e.Serial)
	}
	if e.KeyID != "" {
		fmt.Fprintf(&b, " key_id=%q", e.KeyID)
	}
	if len(e.Principals) > 0 {
		fmt.Fprintf(&b, " principals=%s", strings.Join(e.Principals, ","))
	}
	if e.ValidBefore != "" {
		fmt.Fprintf(&b, " until=%s", e.ValidBefore)
	}
	if e.Fingerprint != "" {
		fmt.Fprintf(&b, " fp=%s", e.Fingerprint)
	}
	if e.Reason != "" {
		fmt.Fprintf(&b, " reason=%q", e.Reason)
	}
	return b.String()
}

// auditJSON re-emits the entry in its canonical stored form.
func auditJSON(e audit.Entry) string {
	b, err := json.Marshal(e)
	if err != nil {
		return "{}"
	}
	return string(b)
}
