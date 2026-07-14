// Tests for authorized_keys parsing and key handling. The parser is
// the CA's front door: every byte a user hands to `issue` goes through
// ParseAuthorizedKey, so garbage must be rejected with a reason, never
// signed.
package sshcert

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/JaydenCJ/certclerk/internal/wire"
)

// testKeyLine builds a valid ed25519 authorized_keys line from a fixed
// seed, so tests are deterministic without any fixture files.
func testKeyLine(t *testing.T, seed byte, comment string) (string, ed25519.PrivateKey) {
	t.Helper()
	seedBytes := make([]byte, ed25519.SeedSize)
	for i := range seedBytes {
		seedBytes[i] = seed
	}
	priv := ed25519.NewKeyFromSeed(seedBytes)
	pub := NewEd25519PublicKey(priv.Public().(ed25519.PublicKey), comment)
	return pub.MarshalAuthorizedKey(), priv
}

func TestParseAuthorizedKeyRoundTrip(t *testing.T) {
	line, _ := testKeyLine(t, 1, "alice@laptop")
	k, err := ParseAuthorizedKey(line)
	if err != nil {
		t.Fatal(err)
	}
	if k.Algo != "ssh-ed25519" || k.Comment != "alice@laptop" {
		t.Fatalf("algo=%q comment=%q", k.Algo, k.Comment)
	}
	if k.MarshalAuthorizedKey() != line {
		t.Fatalf("round trip changed the line:\n%s\n%s", line, k.MarshalAuthorizedKey())
	}
}

func TestParseAuthorizedKeyCommentsAndWhitespace(t *testing.T) {
	// Multi-word comments survive, and surrounding whitespace/newlines
	// (as read from a .pub file) are tolerated.
	line, _ := testKeyLine(t, 1, "alice laptop key")
	k, err := ParseAuthorizedKey("  " + line + "  \n")
	if err != nil {
		t.Fatal(err)
	}
	if k.Comment != "alice laptop key" {
		t.Fatalf("comment = %q", k.Comment)
	}
}

func TestParseAuthorizedKeyRejectsGarbage(t *testing.T) {
	cases := map[string]string{
		"empty":          "",
		"comment line":   "# a comment",
		"one field":      "ssh-ed25519",
		"bad base64":     "ssh-ed25519 !!!not-base64!!!",
		"unknown algo":   "ssh-quantum AAAA",
		"truncated blob": "ssh-ed25519 AAAA",
	}
	for name, line := range cases {
		if _, err := ParseAuthorizedKey(line); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestParseAuthorizedKeyRejectsAlgoMismatch(t *testing.T) {
	// The line claims ssh-rsa but the blob embeds ssh-ed25519. sshd
	// rejects this; so must we.
	line, _ := testKeyLine(t, 3, "")
	spoofed := "ssh-rsa " + strings.Fields(line)[1]
	if _, err := ParseAuthorizedKey(spoofed); err == nil {
		t.Fatal("expected an algorithm mismatch error")
	}
}

func TestParseAuthorizedKeyRejectsTrailingBlobBytes(t *testing.T) {
	line, _ := testKeyLine(t, 4, "")
	k, _ := ParseAuthorizedKey(line)
	k.Blob = append(k.Blob, 0xEE)
	if _, err := ParseAuthorizedKey(k.MarshalAuthorizedKey()); err == nil {
		t.Fatal("expected an error for trailing bytes in the blob")
	}
}

func TestFingerprintFormatAndStability(t *testing.T) {
	line, _ := testKeyLine(t, 5, "")
	k, _ := ParseAuthorizedKey(line)
	fp := k.Fingerprint()
	if !strings.HasPrefix(fp, "SHA256:") {
		t.Fatalf("fingerprint %q lacks SHA256: prefix", fp)
	}
	if strings.HasSuffix(fp, "=") {
		t.Fatalf("fingerprint %q must use unpadded base64 (ssh-keygen -l format)", fp)
	}
	// SHA-256 in raw base64 is always 43 characters.
	if len(fp) != len("SHA256:")+43 {
		t.Fatalf("fingerprint %q has wrong length", fp)
	}
	if fp != k.Fingerprint() {
		t.Fatal("fingerprint must be deterministic")
	}
	other, _ := testKeyLine(t, 6, "")
	ko, _ := ParseAuthorizedKey(other)
	if ko.Fingerprint() == fp {
		t.Fatal("distinct keys must have distinct fingerprints")
	}
}

func TestEd25519Extraction(t *testing.T) {
	line, priv := testKeyLine(t, 8, "")
	k, _ := ParseAuthorizedKey(line)
	pk, err := k.Ed25519()
	if err != nil {
		t.Fatal(err)
	}
	if !pk.Equal(priv.Public().(ed25519.PublicKey)) {
		t.Fatal("extracted public key does not match the private key")
	}
	rsa := &PublicKey{Algo: "ssh-rsa", Blob: rsaTestBlob()}
	if _, err := rsa.Ed25519(); err == nil {
		t.Fatal("expected an error for a non-ed25519 key")
	}
}

func TestPrivateKeyPEMRoundTrip(t *testing.T) {
	_, priv, err := GenerateCA("test")
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := MarshalPrivateKeyPEM(priv)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParsePrivateKeyPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !back.Equal(priv) {
		t.Fatal("PEM round trip changed the key")
	}
	if _, err := ParsePrivateKeyPEM([]byte("not pem at all")); err == nil {
		t.Fatal("expected an error for non-PEM input")
	}
	if _, err := ParsePrivateKeyPEM([]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")); err == nil {
		t.Fatal("expected an error for a wrong PEM block type")
	}
}

// rsaTestBlob fabricates a structurally valid ssh-rsa public key blob
// (tiny fake e and n — fine for format-level tests, never used for
// actual RSA math).
func rsaTestBlob() []byte {
	var w wire.Buffer
	w.String("ssh-rsa")
	w.Bytes32([]byte{0x01, 0x00, 0x01})       // e = 65537
	w.Bytes32([]byte{0x00, 0xC1, 0x00, 0x01}) // fake modulus
	return w.Bytes()
}
