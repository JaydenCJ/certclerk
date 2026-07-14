// Tests for the CA state machine: init/open lifecycle, serial
// monotonicity, policy-gated issuance, revocation semantics (serial vs
// key ID), the audit trail every operation leaves behind, and the KRL
// export. Everything runs against real temp directories — the same
// code paths the CLI exercises.
package ca

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/JaydenCJ/certclerk/internal/audit"
	"github.com/JaydenCJ/certclerk/internal/krl"
	"github.com/JaydenCJ/certclerk/internal/policy"
	"github.com/JaydenCJ/certclerk/internal/sshcert"
)

var t0 = time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)

const testPolicy = `{
  "version": 1,
  "defaults": {"max_ttl": "8h", "extensions": ["permit-pty"]},
  "users": {
    "alice":  {"principals": ["alice", "deploy"], "max_ttl": "1h"},
    "ci-bot": {"principals": ["deploy"], "max_ttl": "15m", "extensions": [],
               "source_address": ["10.0.0.0/8"], "force_command": "/usr/local/bin/deploy"}
  }
}
`

// newCA initializes a CA with the test policy in a temp dir.
func newCA(t *testing.T) *CA {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "ca")
	if _, err := Init(dir, "test-ca", t0); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, FilePolicy), []byte(testPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	authority, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

// userKey builds a deterministic user public key.
func userKey(t *testing.T, seed byte) *sshcert.PublicKey {
	t.Helper()
	seedBytes := bytes.Repeat([]byte{seed}, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seedBytes)
	return sshcert.NewEd25519PublicKey(priv.Public().(ed25519.PublicKey), "test")
}

func issueAlice(t *testing.T, authority *CA) *Issued {
	t.Helper()
	issued, err := authority.Issue(IssueRequest{
		User: "alice", Key: userKey(t, 1), TTL: 30 * time.Minute, Now: t0,
	})
	if err != nil {
		t.Fatal(err)
	}
	return issued
}

func TestInitCreatesAllStateFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	if _, err := Init(dir, "", t0); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{FileKey, FilePub, FilePolicy, FileSerial, FileAudit} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("missing %s: %v", f, err)
		}
	}
	// The private key must not be world-readable.
	info, _ := os.Stat(filepath.Join(dir, FileKey))
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("ca.key mode = %o, want 600", info.Mode().Perm())
	}
	// And a second init must never overwrite the CA key.
	if _, err := Init(dir, "", t0); err == nil {
		t.Fatal("re-init must not overwrite an existing CA key")
	}
}

func contains(s, sub string) bool { return bytes.Contains([]byte(s), []byte(sub)) }

func TestOpenFailsFastOnBrokenOrMissingState(t *testing.T) {
	// A missing directory points the operator at init...
	_, err := Open(filepath.Join(t.TempDir(), "nope"))
	if err == nil || !contains(err.Error(), "certclerk init") {
		t.Fatalf("err = %v, want a hint to run init", err)
	}
	// ...and a broken policy.json fails Open, not first use.
	authority := newCA(t)
	if err := os.WriteFile(filepath.Join(authority.Dir, FilePolicy), []byte(`{"version":9}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(authority.Dir); err == nil {
		t.Fatal("a broken policy.json must fail Open, not first use")
	}
}

func TestIssueSignsVerifiableCert(t *testing.T) {
	authority := newCA(t)
	issued := issueAlice(t, authority)
	c := issued.Cert
	if err := c.Verify(authority.Pub); err != nil {
		t.Fatal(err)
	}
	if c.Serial != 1 || c.CertType != sshcert.UserCert {
		t.Fatalf("serial=%d type=%d", c.Serial, c.CertType)
	}
	if c.KeyID != "alice@certclerk-1" {
		t.Fatalf("key id = %q", c.KeyID)
	}
	if len(c.ValidPrincipals) != 2 {
		t.Fatalf("principals = %v", c.ValidPrincipals)
	}
	// TTL 30m from a pinned now.
	if c.ValidBefore-uint64(t0.Unix()) != 30*60 {
		t.Fatalf("valid before = %d", c.ValidBefore)
	}
	// Round trip through the printable line.
	back, err := sshcert.ParseCertificateLine(issued.Line)
	if err != nil || back.Serial != 1 {
		t.Fatalf("line round trip: %v", err)
	}
}

func TestSerialsAreMonotonicAndPersisted(t *testing.T) {
	authority := newCA(t)
	first := issueAlice(t, authority)
	// Reopen the CA — the counter must survive the process boundary.
	reopened, err := Open(authority.Dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := reopened.Issue(IssueRequest{User: "alice", Key: userKey(t, 2), Now: t0})
	if err != nil {
		t.Fatal(err)
	}
	if first.Cert.Serial != 1 || second.Cert.Serial != 2 {
		t.Fatalf("serials = %d, %d", first.Cert.Serial, second.Cert.Serial)
	}
}

func TestIssueAppliesPolicyOptions(t *testing.T) {
	authority := newCA(t)
	issued, err := authority.Issue(IssueRequest{User: "ci-bot", Key: userKey(t, 3), Now: t0})
	if err != nil {
		t.Fatal(err)
	}
	c := issued.Cert
	if len(c.Extensions) != 0 {
		t.Fatalf("ci-bot must get no extensions, got %v", c.Extensions)
	}
	want := map[string]string{
		"force-command":  "/usr/local/bin/deploy",
		"source-address": "10.0.0.0/8",
	}
	if len(c.CriticalOptions) != 2 {
		t.Fatalf("critical options = %v", c.CriticalOptions)
	}
	for _, o := range c.CriticalOptions {
		if want[o.Name] != o.Data {
			t.Fatalf("option %s = %q", o.Name, o.Data)
		}
	}
	// TTL defaulted to ci-bot's 15m cap.
	if c.ValidBefore-uint64(t0.Unix()) != 15*60 {
		t.Fatalf("valid before = %d", c.ValidBefore)
	}
}

func TestIssueBackdatesValidAfter(t *testing.T) {
	authority := newCA(t)
	issued, err := authority.Issue(IssueRequest{
		User: "alice", Key: userKey(t, 1), Now: t0, Backdate: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := uint64(t0.Unix()) - issued.Cert.ValidAfter; got != 60 {
		t.Fatalf("backdate = %ds, want 60", got)
	}
}

func TestIssueDenialWritesNothing(t *testing.T) {
	authority := newCA(t)
	_, err := authority.Issue(IssueRequest{
		User: "alice", Key: userKey(t, 1), Principals: []string{"root"}, Now: t0,
	})
	var deny *policy.DenyError
	if !errors.As(err, &deny) {
		t.Fatalf("err = %v, want *policy.DenyError", err)
	}
	// No serial burned, no audit entry beyond init.
	entries, _ := authority.Audit.Entries()
	if len(entries) != 1 || entries[0].Action != audit.ActionInit {
		t.Fatalf("denied issuance left traces: %+v", entries)
	}
	serial, _ := os.ReadFile(filepath.Join(authority.Dir, FileSerial))
	if string(bytes.TrimSpace(serial)) != "1" {
		t.Fatalf("serial consumed on denial: %s", serial)
	}
}

func TestAuditChainAcrossLifecycle(t *testing.T) {
	authority := newCA(t)
	issued := issueAlice(t, authority)
	if _, err := authority.RevokeSerial(issued.Cert.Serial, "laptop stolen", t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	entries, err := authority.Audit.Entries()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want init+issue+revoke", len(entries))
	}
	if err := audit.Verify(entries); err != nil {
		t.Fatal(err)
	}
	if entries[2].Action != audit.ActionRevoke || entries[2].Reason != "laptop stolen" {
		t.Fatalf("revoke entry = %+v", entries[2])
	}
	// The revoke entry carries the issuance's user and key ID for
	// correlation.
	if entries[2].User != "alice" || entries[2].KeyID != "alice@certclerk-1" {
		t.Fatalf("revoke entry not correlated: %+v", entries[2])
	}
}

func TestRevokeSerialSemantics(t *testing.T) {
	authority := newCA(t)
	issued := issueAlice(t, authority)
	if _, err := authority.RevokeSerial(99, "", t0); err == nil {
		t.Fatal("revoking a never-issued serial must fail")
	}
	if _, err := authority.RevokeSerial(issued.Cert.Serial, "", t0); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.RevokeSerial(issued.Cert.Serial, "", t0); err == nil {
		t.Fatal("double revocation must fail")
	}
	rev, err := authority.IsRevoked(issued.Cert)
	if err != nil || rev == nil {
		t.Fatalf("cert not reported revoked: %v, %v", rev, err)
	}
}

func TestRevokeKeyIDCoversReissuedCerts(t *testing.T) {
	// Revoking by key ID must catch a cert issued later under the same
	// ID — the "stolen laptop keeps requesting" scenario.
	authority := newCA(t)
	if _, err := authority.RevokeKeyID("alice@laptop", "device lost", t0); err != nil {
		t.Fatal(err)
	}
	issued, err := authority.Issue(IssueRequest{
		User: "alice", Key: userKey(t, 1), KeyID: "alice@laptop", Now: t0,
	})
	if err != nil {
		t.Fatal(err)
	}
	rev, err := authority.IsRevoked(issued.Cert)
	if err != nil || rev == nil || rev.KeyID != "alice@laptop" {
		t.Fatalf("key-id revocation missed: %+v, %v", rev, err)
	}
	if _, err := authority.RevokeKeyID("alice@laptop", "", t0); err == nil {
		t.Fatal("double key-id revocation must fail")
	}
}

func TestKRLExportMatchesRevocations(t *testing.T) {
	authority := newCA(t)
	a := issueAlice(t, authority)
	b, _ := authority.Issue(IssueRequest{User: "alice", Key: userKey(t, 2), Now: t0})
	if _, err := authority.RevokeSerial(a.Cert.Serial, "", t0); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.RevokeSerial(b.Cert.Serial, "", t0); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.RevokeKeyID("gone@laptop", "", t0); err != nil {
		t.Fatal(err)
	}
	blob, err := authority.KRL(t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := krl.Parse(blob)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Serials) != 2 || parsed.Serials[0] != 1 || parsed.Serials[1] != 2 {
		t.Fatalf("KRL serials = %v", parsed.Serials)
	}
	if len(parsed.KeyIDs) != 1 || parsed.KeyIDs[0] != "gone@laptop" {
		t.Fatalf("KRL key ids = %v", parsed.KeyIDs)
	}
	if !bytes.Equal(parsed.CAKey, authority.Pub.Blob) {
		t.Fatal("KRL not scoped to the CA key")
	}
	if parsed.Version != 3 {
		t.Fatalf("KRL version = %d, want revocation count 3", parsed.Version)
	}
}

func TestVerifyFullAcceptancePath(t *testing.T) {
	authority := newCA(t)
	issued := issueAlice(t, authority)
	if _, err := authority.Verify(issued.Cert, t0.Add(time.Minute)); err != nil {
		t.Fatalf("fresh cert rejected: %v", err)
	}
	// Expired.
	if _, err := authority.Verify(issued.Cert, t0.Add(31*time.Minute)); err == nil {
		t.Fatal("expired cert accepted")
	}
	// Revoked.
	if _, err := authority.RevokeSerial(issued.Cert.Serial, "", t0); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.Verify(issued.Cert, t0.Add(time.Minute)); err == nil {
		t.Fatal("revoked cert accepted")
	}
}

func TestVerifyRejectsForeignCert(t *testing.T) {
	oursAuthority := newCA(t)
	otherAuthority := newCA(t)
	foreign := issueAlice(t, otherAuthority)
	if _, err := oursAuthority.Verify(foreign.Cert, t0.Add(time.Minute)); err == nil {
		t.Fatal("a certificate from another CA must not verify")
	}
}
