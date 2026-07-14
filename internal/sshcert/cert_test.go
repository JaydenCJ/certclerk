// Tests for certificate marshal/sign/parse/verify — the security core.
// These pin the exact PROTOCOL.certkeys byte layout (a golden blob from
// fixed inputs), prove tampering with any signed field breaks
// verification, and cover the option-encoding subtleties (sorting,
// valued vs flag options) that decide whether sshd accepts the cert.
package sshcert

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/JaydenCJ/certclerk/internal/wire"
)

// fixedCA returns a deterministic CA keypair.
func fixedCA(t *testing.T) (*PublicKey, ed25519.PrivateKey) {
	t.Helper()
	seed := bytes.Repeat([]byte{0xCA}, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)
	return NewEd25519PublicKey(priv.Public().(ed25519.PublicKey), "test-ca"), priv
}

// fixedCert builds and signs a fully deterministic certificate.
func fixedCert(t *testing.T) (*Certificate, *PublicKey) {
	t.Helper()
	caPub, caPriv := fixedCA(t)
	userLine, _ := testKeyLine(t, 0x11, "")
	userKey, err := ParseAuthorizedKey(userLine)
	if err != nil {
		t.Fatal(err)
	}
	c := &Certificate{
		Nonce:           bytes.Repeat([]byte{0x4E}, 32),
		Key:             userKey,
		Serial:          7,
		CertType:        UserCert,
		KeyID:           "alice@certclerk-7",
		ValidPrincipals: []string{"alice", "deploy"},
		ValidAfter:      1770000000,
		ValidBefore:     1770003600,
		CriticalOptions: []Option{{Name: "source-address", Data: "10.0.0.0/8"}},
		Extensions:      []Option{{Name: "permit-pty"}},
	}
	if err := c.Sign(caPub, caPriv, nil); err != nil {
		t.Fatal(err)
	}
	return c, caPub
}

func TestSignedCertRoundTripsThroughParse(t *testing.T) {
	c, caPub := fixedCert(t)
	back, err := ParseCertificate(c.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if back.Serial != 7 || back.KeyID != "alice@certclerk-7" || back.CertType != UserCert {
		t.Fatalf("core fields lost: %+v", back)
	}
	if len(back.ValidPrincipals) != 2 || back.ValidPrincipals[0] != "alice" || back.ValidPrincipals[1] != "deploy" {
		t.Fatalf("principals = %v", back.ValidPrincipals)
	}
	if back.ValidAfter != 1770000000 || back.ValidBefore != 1770003600 {
		t.Fatalf("window = %d..%d", back.ValidAfter, back.ValidBefore)
	}
	if !bytes.Equal(back.Key.Blob, c.Key.Blob) {
		t.Fatal("embedded public key changed across round trip")
	}
	if err := back.Verify(caPub); err != nil {
		t.Fatalf("re-parsed cert fails verification: %v", err)
	}
	if !bytes.Equal(back.Marshal(), c.Marshal()) {
		t.Fatal("re-marshaled bytes differ")
	}
}

func TestSigningIsDeterministicWithFixedNonce(t *testing.T) {
	// ed25519 signatures are deterministic, so a pinned nonce must give
	// byte-identical certificates — the property that makes golden
	// testing (and reproducible audits) possible.
	a, _ := fixedCert(t)
	b, _ := fixedCert(t)
	if !bytes.Equal(a.Marshal(), b.Marshal()) {
		t.Fatal("identical inputs produced different certificates")
	}
	// And without a pinned nonce, Sign must draw 32 random bytes.
	caPub, caPriv := fixedCA(t)
	line, _ := testKeyLine(t, 0x12, "")
	key, _ := ParseAuthorizedKey(line)
	c := &Certificate{Key: key, CertType: UserCert, Serial: 1, ValidBefore: 100}
	if err := c.Sign(caPub, caPriv, nil); err != nil {
		t.Fatal(err)
	}
	if len(c.Nonce) != 32 || bytes.Equal(c.Nonce, make([]byte, 32)) {
		t.Fatalf("nonce not drawn: % x", c.Nonce)
	}
}

func TestCertLineFormat(t *testing.T) {
	c, _ := fixedCert(t)
	line := c.MarshalLine("alice@certclerk-7")
	fields := strings.Fields(line)
	if len(fields) != 3 {
		t.Fatalf("line has %d fields: %q", len(fields), line)
	}
	if fields[0] != "ssh-ed25519-cert-v01@openssh.com" {
		t.Fatalf("algo = %q", fields[0])
	}
	if _, err := base64.StdEncoding.DecodeString(fields[1]); err != nil {
		t.Fatalf("payload is not standard base64: %v", err)
	}
	back, err := ParseCertificateLine(line)
	if err != nil {
		t.Fatal(err)
	}
	if back.Serial != c.Serial {
		t.Fatal("line round trip lost the serial")
	}
	// A line whose algo field disagrees with the blob is a forgery vector.
	spoofed := "ssh-rsa-cert-v01@openssh.com " + fields[1]
	if _, err := ParseCertificateLine(spoofed); err == nil {
		t.Fatal("expected an error when the line's algo disagrees with the blob")
	}
}

func TestVerifyDetectsTamperedFields(t *testing.T) {
	// Flip each signed field after signing; verification must fail for
	// every one — this is the whole point of a certificate.
	mutations := map[string]func(*Certificate){
		"serial":     func(c *Certificate) { c.Serial++ },
		"type":       func(c *Certificate) { c.CertType = HostCert },
		"key id":     func(c *Certificate) { c.KeyID = "mallory" },
		"principals": func(c *Certificate) { c.ValidPrincipals = append(c.ValidPrincipals, "root") },
		"window":     func(c *Certificate) { c.ValidBefore += 3600 },
		"critical options": func(c *Certificate) {
			c.CriticalOptions = nil
		},
		"extensions": func(c *Certificate) {
			c.Extensions = append(c.Extensions, Option{Name: "permit-port-forwarding"})
		},
	}
	for name, mutate := range mutations {
		c, caPub := fixedCert(t)
		mutate(c)
		if err := c.Verify(caPub); err == nil {
			t.Errorf("tampering with %s went undetected", name)
		}
	}
}

func TestVerifyRejectsWrongCAAndCorruptSignature(t *testing.T) {
	c, _ := fixedCert(t)
	otherSeed := bytes.Repeat([]byte{0xCB}, ed25519.SeedSize)
	otherPriv := ed25519.NewKeyFromSeed(otherSeed)
	otherPub := NewEd25519PublicKey(otherPriv.Public().(ed25519.PublicKey), "")
	err := c.Verify(otherPub)
	if err == nil {
		t.Fatal("expected verification to fail under a different CA")
	}
	if !strings.Contains(err.Error(), "different CA") {
		t.Fatalf("error should name the CA mismatch, got: %v", err)
	}
	// A single flipped signature bit must also fail, under the right CA.
	c2, caPub := fixedCert(t)
	c2.Signature[len(c2.Signature)-1] ^= 0x01
	if err := c2.Verify(caPub); err == nil {
		t.Fatal("expected verification to fail with a corrupted signature")
	}
}

func TestOptionsAreSortedInWireForm(t *testing.T) {
	// OpenSSH requires options sorted by name; give them reversed and
	// check the marshaled order.
	caPub, caPriv := fixedCA(t)
	line, _ := testKeyLine(t, 0x13, "")
	key, _ := ParseAuthorizedKey(line)
	c := &Certificate{
		Key:      key,
		CertType: UserCert,
		Extensions: []Option{
			{Name: "permit-user-rc"},
			{Name: "permit-pty"},
			{Name: "permit-agent-forwarding"},
		},
	}
	if err := c.Sign(caPub, caPriv, bytes.NewReader(make([]byte, 32))); err != nil {
		t.Fatal(err)
	}
	back, err := ParseCertificate(c.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	got := []string{back.Extensions[0].Name, back.Extensions[1].Name, back.Extensions[2].Name}
	want := []string{"permit-agent-forwarding", "permit-pty", "permit-user-rc"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("extension order = %v, want %v", got, want)
		}
	}
}

func TestValuedOptionEncodesNestedString(t *testing.T) {
	// force-command's data field must itself be a wire string containing
	// the command — a classic off-by-one-layer mistake in cert tooling.
	blob := packOptions([]Option{{Name: "force-command", Data: "/usr/bin/true"}})
	r := wire.NewReader(blob)
	name, _ := r.String()
	data, _ := r.Bytes32()
	if name != "force-command" {
		t.Fatalf("name = %q", name)
	}
	inner, err := wire.NewReader(data).String()
	if err != nil || inner != "/usr/bin/true" {
		t.Fatalf("inner = %q, %v", inner, err)
	}
	back, err := unpackOptions(blob)
	if err != nil || back[0].Data != "/usr/bin/true" {
		t.Fatalf("unpack = %+v, %v", back, err)
	}
	// A flag option (permit-pty) encodes a zero-length data field, with
	// no nested string at all.
	flagBlob := packOptions([]Option{{Name: "permit-pty"}})
	fr := wire.NewReader(flagBlob)
	_, _ = fr.String()
	flagData, _ := fr.Bytes32()
	if len(flagData) != 0 {
		t.Fatalf("flag option data = % x, want empty", flagData)
	}
}

func TestGoldenCertificateBytes(t *testing.T) {
	// Full golden pin of the wire format from fixed inputs (fixed CA
	// seed, fixed user key, fixed nonce; ed25519 signing is
	// deterministic). If this changes, the on-the-wire format changed
	// and previously issued certificates are at risk: understand why
	// before touching the constant.
	const golden = "AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIE5OTk5OTk5OTk5O" +
		"Tk5OTk5OTk5OTk5OTk5OTk5OTk5OAAAAINBKsjJ0K7SrOhNovUYV5ObQIkq3GgFrr4Ug" +
		"ozLJd4c3AAAAAAAAAAcAAAABAAAAEWFsaWNlQGNlcnRjbGVyay03AAAAEwAAAAVhbGlj" +
		"ZQAAAAZkZXBsb3kAAAAAaYAOgAAAAABpgByQAAAAJAAAAA5zb3VyY2UtYWRkcmVzcwAA" +
		"AA4AAAAKMTAuMC4wLjAvOAAAABIAAAAKcGVybWl0LXB0eQAAAAAAAAAAAAAAMwAAAAtz" +
		"c2gtZWQyNTUxOQAAACBGZifVJ3PJ1c2myP0o6jHse5TmiqjULirTGnXcjSTtBwAAAFMA" +
		"AAALc3NoLWVkMjU1MTkAAABA4ehaFcXDJOcD5dIN4hpFSvTeJ0GwpOOBtd2tbc89jgnN" +
		"lqWTmnp8Tivr9f1XJQG1HFgUyGYPY2mLENQ7O99hAw=="
	c, _ := fixedCert(t)
	got := base64.StdEncoding.EncodeToString(c.Marshal())
	if got != golden {
		t.Fatalf("wire format changed:\n got %s\nwant %s", got, golden)
	}
}

func TestRSAKeyEmbedsAndRoundTrips(t *testing.T) {
	// Certifying a non-ed25519 key must splice its fields (not its whole
	// blob) into the cert and reassemble them on parse.
	caPub, caPriv := fixedCA(t)
	key := &PublicKey{Algo: "ssh-rsa", Blob: rsaTestBlob()}
	c := &Certificate{
		Key:             key,
		Serial:          9,
		CertType:        UserCert,
		KeyID:           "rsa-user",
		ValidPrincipals: []string{"legacy"},
		ValidBefore:     1770003600,
	}
	if err := c.Sign(caPub, caPriv, bytes.NewReader(make([]byte, 32))); err != nil {
		t.Fatal(err)
	}
	if c.Algo() != "ssh-rsa-cert-v01@openssh.com" {
		t.Fatalf("algo = %q", c.Algo())
	}
	back, err := ParseCertificate(c.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if back.Key.Algo != "ssh-rsa" || !bytes.Equal(back.Key.Blob, key.Blob) {
		t.Fatal("rsa key blob not reassembled correctly")
	}
	if err := back.Verify(caPub); err != nil {
		t.Fatal(err)
	}
}

func TestSKKeyCertAlgoNaming(t *testing.T) {
	// FIDO keys put the -cert-v01 infix BEFORE @openssh.com.
	if got := certAlgo("sk-ssh-ed25519@openssh.com"); got != "sk-ssh-ed25519-cert-v01@openssh.com" {
		t.Fatalf("sk cert algo = %q", got)
	}
	base, err := baseAlgo("sk-ssh-ed25519-cert-v01@openssh.com")
	if err != nil || base != "sk-ssh-ed25519@openssh.com" {
		t.Fatalf("base = %q, %v", base, err)
	}
	if _, err := baseAlgo("ssh-quantum-cert-v01@openssh.com"); err == nil {
		t.Fatal("expected an error for an unknown key algorithm")
	}
	if _, err := baseAlgo("ssh-ed25519"); err == nil {
		t.Fatal("expected an error for a non-certificate algorithm")
	}
}

func TestParseCertificateRejectsTruncationAtEveryField(t *testing.T) {
	// Chop the blob at every byte boundary: parsing must error, never
	// panic — this is the fuzz-shaped guarantee for hostile input.
	c, _ := fixedCert(t)
	blob := c.Marshal()
	for i := 0; i < len(blob)-1; i++ {
		if _, err := ParseCertificate(blob[:i]); err == nil {
			t.Fatalf("truncation to %d bytes parsed successfully", i)
		}
	}
	// The other direction — extra bytes after the signature — must also fail.
	if _, err := ParseCertificate(append(blob, 0x00)); err == nil {
		t.Fatal("expected an error for trailing bytes")
	}
}

func TestParseCertificateRejectsUnknownType(t *testing.T) {
	c, _ := fixedCert(t)
	c.CertType = 3
	caPub, caPriv := fixedCA(t)
	_ = c.Sign(caPub, caPriv, bytes.NewReader(make([]byte, 32)))
	if _, err := ParseCertificate(c.Marshal()); err == nil {
		t.Fatal("expected an error for certificate type 3")
	}
}

func TestValidAtWindowEdges(t *testing.T) {
	c := &Certificate{ValidAfter: 1000, ValidBefore: 2000}
	cases := []struct {
		at int64
		ok bool
	}{
		{999, false},  // just before the window opens
		{1000, true},  // ValidAfter is inclusive
		{1999, true},  // last valid second
		{2000, false}, // ValidBefore is exclusive (matches sshd)
		{2001, false},
	}
	for _, tc := range cases {
		err := c.ValidAt(time.Unix(tc.at, 0))
		if (err == nil) != tc.ok {
			t.Errorf("ValidAt(%d): err = %v, want ok=%v", tc.at, err, tc.ok)
		}
	}
	// OpenSSH's "forever" sentinel must be honored when inspecting
	// foreign certificates.
	inf := &Certificate{ValidAfter: 0, ValidBefore: InfiniteValidity}
	if err := inf.ValidAt(time.Unix(1<<40, 0)); err != nil {
		t.Fatalf("infinite validity rejected: %v", err)
	}
}
