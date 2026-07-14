// In-process CLI integration tests: Run() with real temp-dir CAs,
// asserting on stdout/stderr text and the documented exit codes — the
// same contract scripts and the smoke test depend on.
package cli

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JaydenCJ/certclerk/internal/sshcert"
	"github.com/JaydenCJ/certclerk/internal/version"
)

var t0 = time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)

const testPolicy = `{
  "version": 1,
  "defaults": {"max_ttl": "8h", "extensions": ["permit-pty"]},
  "users": {
    "alice": {"principals": ["alice", "deploy"], "max_ttl": "1h"}
  }
}
`

// run executes argv with a pinned clock and returns exit code + output.
func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	orig := timeNow
	timeNow = func() time.Time { return t0 }
	defer func() { timeNow = orig }()
	var stdout, stderr bytes.Buffer
	code := Run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// setupCA initializes a CA with the test policy and writes alice's key;
// returns (caDir, keyPath).
func setupCA(t *testing.T) (string, string) {
	t.Helper()
	base := t.TempDir()
	dir := filepath.Join(base, "ca")
	code, _, stderr := run(t, "init", "--dir", dir)
	if code != ExitOK {
		t.Fatalf("init failed: %s", stderr)
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.json"), []byte(testPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := sshcert.NewEd25519PublicKey(priv.Public().(ed25519.PublicKey), "alice@laptop")
	keyPath := filepath.Join(base, "alice.pub")
	if err := os.WriteFile(keyPath, []byte(pub.MarshalAuthorizedKey()+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir, keyPath
}

func issueCert(t *testing.T, dir, keyPath string, extra ...string) string {
	t.Helper()
	args := append([]string{"issue", "--dir", dir, "--user", "alice", "--key", keyPath, "--ttl", "30m"}, extra...)
	code, stdout, stderr := run(t, args...)
	if code != ExitOK {
		t.Fatalf("issue failed (%d): %s", code, stderr)
	}
	if !strings.Contains(stdout, "issued serial") {
		t.Fatalf("issue output: %q", stdout)
	}
	return strings.TrimSuffix(keyPath, ".pub") + "-cert.pub"
}

func TestUsageAndUnknownCommand(t *testing.T) {
	// Bare invocation is help, exit 0; a typoed command is exit 2.
	code, stdout, _ := run(t)
	if code != ExitOK || !strings.Contains(stdout, "Usage:") {
		t.Fatalf("code=%d stdout=%q", code, stdout)
	}
	code, _, stderr := run(t, "frobnicate")
	if code != ExitUsage || !strings.Contains(stderr, "unknown command") {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
}

func TestVersionMatchesPackage(t *testing.T) {
	for _, arg := range []string{"version", "--version", "-v"} {
		code, stdout, _ := run(t, arg)
		if code != ExitOK || stdout != "certclerk "+version.Version+"\n" {
			t.Fatalf("%s: code=%d stdout=%q", arg, code, stdout)
		}
	}
}

func TestInitReportsFingerprintAndRefusesRerun(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	code, stdout, _ := run(t, "init", "--dir", dir)
	if code != ExitOK || !strings.Contains(stdout, "CA fingerprint: SHA256:") {
		t.Fatalf("code=%d stdout=%q", code, stdout)
	}
	code, _, stderr := run(t, "init", "--dir", dir)
	if code != ExitRuntime || !strings.Contains(stderr, "already contains a CA") {
		t.Fatalf("re-init: code=%d stderr=%q", code, stderr)
	}
}

func TestIssueWritesCertNextToKey(t *testing.T) {
	dir, keyPath := setupCA(t)
	certPath := issueCert(t, dir, keyPath)
	b, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	c, err := sshcert.ParseCertificateLine(string(b))
	if err != nil {
		t.Fatal(err)
	}
	if c.Serial != 1 || c.KeyID != "alice@certclerk-1" {
		t.Fatalf("serial=%d key_id=%q", c.Serial, c.KeyID)
	}
	// Default --backdate 60s absorbs host clock skew.
	if uint64(t0.Unix())-c.ValidAfter != 60 {
		t.Fatalf("valid after = %d", c.ValidAfter)
	}
	// --out - streams the certificate line to stdout instead.
	code, stdout, stderr := run(t, "issue", "--dir", dir, "--user", "alice",
		"--key", keyPath, "--out", "-")
	if code != ExitOK {
		t.Fatal(stderr)
	}
	line := strings.SplitN(stdout, "\n", 2)[0]
	if _, err := sshcert.ParseCertificateLine(line); err != nil {
		t.Fatalf("stdout line is not a certificate: %v\n%q", err, line)
	}
}

func TestIssueErrorPaths(t *testing.T) {
	dir, keyPath := setupCA(t)
	// Missing required flags: usage error (2).
	code, _, stderr := run(t, "issue", "--dir", dir, "--user", "alice")
	if code != ExitUsage || !strings.Contains(stderr, "--user and --key") {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
	// Policy denials: findings (1), with the reason on stderr.
	code, _, stderr = run(t, "issue", "--dir", dir, "--user", "alice",
		"--key", keyPath, "--principals", "root")
	if code != ExitFindings || !strings.Contains(stderr, "denied") {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
	code, _, stderr = run(t, "issue", "--dir", dir, "--user", "mallory", "--key", keyPath)
	if code != ExitFindings || !strings.Contains(stderr, "not in the policy") {
		t.Fatalf("unknown user: code=%d stderr=%q", code, stderr)
	}
}

func TestVerifyOKThenExpiredThenRevoked(t *testing.T) {
	dir, keyPath := setupCA(t)
	certPath := issueCert(t, dir, keyPath)

	code, stdout, _ := run(t, "verify", "--dir", dir, "--at", "2026-07-13T12:10:00Z", certPath)
	if code != ExitOK || !strings.HasPrefix(stdout, "OK: serial 1") {
		t.Fatalf("code=%d stdout=%q", code, stdout)
	}
	code, _, stderr := run(t, "verify", "--dir", dir, "--at", "2026-07-13T13:00:00Z", certPath)
	if code != ExitFindings || !strings.Contains(stderr, "expired") {
		t.Fatalf("expired: code=%d stderr=%q", code, stderr)
	}
	if code, _, stderr = run(t, "revoke", "--dir", dir, "--serial", "1", "--reason", "test"); code != ExitOK {
		t.Fatal(stderr)
	}
	code, _, stderr = run(t, "verify", "--dir", dir, "--at", "2026-07-13T12:10:00Z", certPath)
	if code != ExitFindings || !strings.Contains(stderr, "revoked") {
		t.Fatalf("revoked: code=%d stderr=%q", code, stderr)
	}
	// And a malformed --at is a usage error, not a finding.
	if code, _, _ := run(t, "verify", "--dir", dir, "--at", "yesterday", certPath); code != ExitUsage {
		t.Fatalf("bad --at: code=%d, want usage error", code)
	}
}

func TestInspectTextAndJSON(t *testing.T) {
	dir, keyPath := setupCA(t)
	certPath := issueCert(t, dir, keyPath)

	code, stdout, _ := run(t, "inspect", certPath)
	if code != ExitOK {
		t.Fatal(stdout)
	}
	for _, want := range []string{
		"Type: ssh-ed25519-cert-v01@openssh.com user certificate",
		`Key ID: "alice@certclerk-1"`,
		"Serial: 1",
		"Principals: alice,deploy",
		"Extensions: permit-pty",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("inspect text missing %q:\n%s", want, stdout)
		}
	}

	code, stdout, _ = run(t, "inspect", "--format", "json", certPath)
	if code != ExitOK {
		t.Fatal(stdout)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("inspect json: %v", err)
	}
	if doc["serial"] != float64(1) || doc["type"] != "user" {
		t.Fatalf("json doc = %v", doc)
	}
	if doc["valid_before"] != "2026-07-13T12:30:00Z" {
		t.Fatalf("valid_before = %v", doc["valid_before"])
	}
}

func TestRevokeFlagValidation(t *testing.T) {
	dir, _ := setupCA(t)
	code, _, stderr := run(t, "revoke", "--dir", dir)
	if code != ExitUsage || !strings.Contains(stderr, "exactly one of") {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
	code, _, _ = run(t, "revoke", "--dir", dir, "--serial", "1", "--key-id", "x")
	if code != ExitUsage {
		t.Fatalf("both flags: code=%d", code)
	}
	code, _, stderr = run(t, "revoke", "--dir", dir, "--serial", "42")
	if code != ExitRuntime || !strings.Contains(stderr, "never issued") {
		t.Fatalf("unissued serial: code=%d stderr=%q", code, stderr)
	}
}

func TestKRLWriteAndStdout(t *testing.T) {
	dir, keyPath := setupCA(t)
	issueCert(t, dir, keyPath)
	if code, _, stderr := run(t, "revoke", "--dir", dir, "--serial", "1"); code != ExitOK {
		t.Fatal(stderr)
	}
	out := filepath.Join(t.TempDir(), "revoked.krl")
	code, stdout, stderr := run(t, "krl", "--dir", dir, "--out", out)
	if code != ExitOK || !strings.Contains(stdout, "1 revocation,") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(b, []byte("SSHKRL\n\x00")) {
		t.Fatalf("KRL magic missing: % x", b[:8])
	}
	// Default output is the raw binary on stdout.
	code, stdout, _ = run(t, "krl", "--dir", dir)
	if code != ExitOK || !strings.HasPrefix(stdout, "SSHKRL\n\x00") {
		t.Fatalf("stdout KRL: code=%d", code)
	}
}

func TestPolicyCommand(t *testing.T) {
	dir, _ := setupCA(t)
	code, stdout, _ := run(t, "policy", "--dir", dir)
	if code != ExitOK || !strings.Contains(stdout, "alice") || !strings.Contains(stdout, "max_ttl=1h") {
		t.Fatalf("code=%d stdout=%q", code, stdout)
	}
	code, stdout, _ = run(t, "policy", "--dir", dir, "--user", "alice")
	if code != ExitOK || !strings.Contains(stdout, "principals:     alice,deploy") {
		t.Fatalf("code=%d stdout=%q", code, stdout)
	}
	code, _, stderr := run(t, "policy", "--dir", dir, "--user", "mallory")
	if code != ExitFindings || !strings.Contains(stderr, "not in the policy") {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
}

func TestAuditListAndVerify(t *testing.T) {
	dir, keyPath := setupCA(t)
	issueCert(t, dir, keyPath)
	code, stdout, _ := run(t, "audit", "--dir", dir)
	if code != ExitOK {
		t.Fatal(stdout)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], "init") || !strings.Contains(lines[1], "issue") {
		t.Fatalf("audit lines: %q", lines)
	}
	code, stdout, _ = run(t, "audit", "--dir", dir, "--verify")
	if code != ExitOK || !strings.Contains(stdout, "chain intact") {
		t.Fatalf("code=%d stdout=%q", code, stdout)
	}
}

func TestAuditVerifyDetectsTamperingExit1(t *testing.T) {
	dir, keyPath := setupCA(t)
	issueCert(t, dir, keyPath)
	logPath := filepath.Join(dir, "audit.log")
	b, _ := os.ReadFile(logPath)
	tampered := bytes.Replace(b, []byte(`"user":"alice"`), []byte(`"user":"mallory"`), 1)
	if bytes.Equal(b, tampered) {
		t.Fatal("test setup: nothing replaced")
	}
	if err := os.WriteFile(logPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := run(t, "audit", "--dir", dir, "--verify")
	if code != ExitFindings || !strings.Contains(stderr, "hash") {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
}

func TestAuditJSONLinesAreCanonical(t *testing.T) {
	dir, keyPath := setupCA(t)
	issueCert(t, dir, keyPath)
	code, stdout, _ := run(t, "audit", "--dir", dir, "--format", "json")
	if code != ExitOK {
		t.Fatal(stdout)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "audit.log"))
	if stdout != string(raw) {
		t.Fatal("audit --format json must re-emit the canonical stored lines")
	}
}

func TestSetupPrintsSSHDSnippet(t *testing.T) {
	dir, _ := setupCA(t)
	code, stdout, _ := run(t, "setup", "--dir", dir)
	if code != ExitOK {
		t.Fatal(stdout)
	}
	for _, want := range []string{
		"TrustedUserCAKeys /etc/ssh/certclerk-ca.pub",
		"RevokedKeys /etc/ssh/certclerk-revoked.krl",
		"ssh-ed25519 ",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("setup missing %q", want)
		}
	}
}

func TestDirResolutionOrder(t *testing.T) {
	// --dir beats CERTCLERK_DIR beats the default.
	if got := resolveDir("/flag"); got != "/flag" {
		t.Fatalf("flag: %q", got)
	}
	t.Setenv("CERTCLERK_DIR", "/env")
	if got := resolveDir(""); got != "/env" {
		t.Fatalf("env: %q", got)
	}
	t.Setenv("CERTCLERK_DIR", "")
	if got := resolveDir(""); got != DefaultDir {
		t.Fatalf("default: %q", got)
	}
}

func TestInspectNeedsNoCADirectory(t *testing.T) {
	// inspect explains foreign certs too, so it must work with no CA
	// anywhere near the process.
	dir, keyPath := setupCA(t)
	certPath := issueCert(t, dir, keyPath)
	t.Setenv("CERTCLERK_DIR", filepath.Join(t.TempDir(), "nowhere"))
	code, stdout, stderr := run(t, "inspect", certPath)
	if code != ExitOK || !strings.Contains(stdout, "Serial: 1") {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
}
