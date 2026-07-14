// Package sshcert implements the OpenSSH public-key and certificate
// formats (PROTOCOL.certkeys) from scratch on the standard library: it
// parses authorized_keys lines, computes SHA256 fingerprints, and
// marshals, signs, parses, and verifies *-cert-v01@openssh.com blobs
// that plain OpenSSH accepts.
package sshcert

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/JaydenCJ/certclerk/internal/wire"
)

// AlgoEd25519 is the only algorithm certclerk signs WITH. Certified user
// keys may use any algorithm in pubKeyFieldCount.
const AlgoEd25519 = "ssh-ed25519"

// pubKeyFieldCount maps a public-key algorithm to the number of wire
// fields that follow the algorithm name in its blob. Certificates embed
// exactly those fields between the nonce and the serial, so this table
// is what lets certclerk certify key types it cannot otherwise interpret.
var pubKeyFieldCount = map[string]int{
	"ssh-ed25519":                        1, // pk
	"ssh-rsa":                            2, // e, n
	"ssh-dss":                            4, // p, q, g, y
	"ecdsa-sha2-nistp256":                2, // curve, point
	"ecdsa-sha2-nistp384":                2,
	"ecdsa-sha2-nistp521":                2,
	"sk-ssh-ed25519@openssh.com":         2, // pk, application
	"sk-ecdsa-sha2-nistp256@openssh.com": 3, // curve, point, application
}

// PublicKey is a parsed SSH public key: the full wire blob (algorithm
// name included) plus the optional authorized_keys comment.
type PublicKey struct {
	Algo    string
	Blob    []byte
	Comment string
}

// ParseAuthorizedKey parses a single authorized_keys-format line:
// `<algo> <base64-blob> [comment]`. It rejects blank lines, comments,
// unknown algorithms, and blobs whose embedded algorithm name disagrees
// with the leading text field.
func ParseAuthorizedKey(line string) (*PublicKey, error) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return nil, errors.New("sshcert: not a public key line")
	}
	fields := strings.Fields(trimmed)
	if len(fields) < 2 {
		return nil, errors.New("sshcert: expected `<algo> <base64> [comment]`")
	}
	algo := fields[0]
	if _, ok := pubKeyFieldCount[algo]; !ok {
		return nil, fmt.Errorf("sshcert: unsupported key algorithm %q", algo)
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return nil, fmt.Errorf("sshcert: invalid base64 key data: %v", err)
	}
	embedded, err := wire.NewReader(blob).String()
	if err != nil {
		return nil, fmt.Errorf("sshcert: truncated key blob: %v", err)
	}
	if embedded != algo {
		return nil, fmt.Errorf("sshcert: key blob is %q but line says %q", embedded, algo)
	}
	if err := checkKeyFields(algo, blob); err != nil {
		return nil, err
	}
	comment := ""
	if len(fields) > 2 {
		comment = strings.Join(fields[2:], " ")
	}
	return &PublicKey{Algo: algo, Blob: blob, Comment: comment}, nil
}

// LoadPublicKey reads and parses an authorized_keys-format file.
func LoadPublicKey(path string) (*PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	k, err := ParseAuthorizedKey(string(b))
	if err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	return k, nil
}

// checkKeyFields verifies the blob contains exactly the expected wire
// fields for its algorithm, with no trailing garbage.
func checkKeyFields(algo string, blob []byte) error {
	r := wire.NewReader(blob)
	if _, err := r.String(); err != nil { // algorithm name
		return err
	}
	for i := 0; i < pubKeyFieldCount[algo]; i++ {
		if _, err := r.Bytes32(); err != nil {
			return fmt.Errorf("sshcert: %s blob field %d: %v", algo, i+1, err)
		}
	}
	if !r.Empty() {
		return fmt.Errorf("sshcert: %s blob has trailing bytes", algo)
	}
	return nil
}

// Fingerprint returns the OpenSSH SHA256 fingerprint of the key blob,
// e.g. `SHA256:oIvsdX0oRQJ...` (unpadded base64, same as ssh-keygen -l).
func (k *PublicKey) Fingerprint() string {
	sum := sha256.Sum256(k.Blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// MarshalAuthorizedKey renders the key back to a single-line
// authorized_keys entry (no trailing newline).
func (k *PublicKey) MarshalAuthorizedKey() string {
	line := k.Algo + " " + base64.StdEncoding.EncodeToString(k.Blob)
	if k.Comment != "" {
		line += " " + k.Comment
	}
	return line
}

// keyFields returns the algorithm-specific wire fields of the blob (the
// bytes after the embedded algorithm name), which is exactly what a
// certificate embeds after its nonce.
func (k *PublicKey) keyFields() []byte {
	r := wire.NewReader(k.Blob)
	_, _ = r.String()
	return r.Rest()
}

// Ed25519 extracts the raw ed25519 public key, or an error for other
// algorithms. Used to verify CA signatures.
func (k *PublicKey) Ed25519() (ed25519.PublicKey, error) {
	if k.Algo != AlgoEd25519 {
		return nil, fmt.Errorf("sshcert: %s is not an ed25519 key", k.Algo)
	}
	r := wire.NewReader(k.Blob)
	_, _ = r.String()
	pk, err := r.Bytes32()
	if err != nil || len(pk) != ed25519.PublicKeySize {
		return nil, errors.New("sshcert: malformed ed25519 public key")
	}
	return ed25519.PublicKey(pk), nil
}

// NewEd25519PublicKey wraps a raw ed25519 public key in a PublicKey.
func NewEd25519PublicKey(pk ed25519.PublicKey, comment string) *PublicKey {
	var w wire.Buffer
	w.String(AlgoEd25519)
	w.Bytes32(pk)
	return &PublicKey{Algo: AlgoEd25519, Blob: w.Bytes(), Comment: comment}
}

// GenerateCA creates a fresh ed25519 CA keypair.
func GenerateCA(comment string) (*PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return NewEd25519PublicKey(pub, comment), priv, nil
}

// MarshalPrivateKeyPEM encodes the CA private key as PKCS#8 PEM. The
// standard, widely tooled container; certclerk never writes it anywhere
// but the CA directory, with mode 0600.
func MarshalPrivateKeyPEM(priv ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParsePrivateKeyPEM decodes a PKCS#8 PEM ed25519 private key.
func ParsePrivateKeyPEM(b []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("sshcert: expected a PKCS#8 PRIVATE KEY PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("sshcert: parse private key: %v", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("sshcert: CA private key must be ed25519")
	}
	return priv, nil
}
