// OpenSSH certificate marshaling, signing, parsing, and verification.
// The format is PROTOCOL.certkeys: a signed blob embedding the certified
// public key's fields, a serial, principals, a validity window, critical
// options, and extensions.
package sshcert

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/JaydenCJ/certclerk/internal/wire"
)

// Certificate types (PROTOCOL.certkeys). certclerk only issues user
// certificates; host certs are parsed so `inspect` can explain them.
const (
	UserCert uint32 = 1
	HostCert uint32 = 2
)

// InfiniteValidity is OpenSSH's "forever" sentinel for ValidBefore.
// certclerk never issues it, but recognizes it when inspecting.
const InfiniteValidity = ^uint64(0)

// Option is a critical option or extension. For valued options
// (force-command, source-address) Data holds the value; for flag
// extensions (permit-pty, ...) Data is empty and encodes as a
// zero-length string, matching OpenSSH.
type Option struct {
	Name string
	Data string
}

// Certificate is a parsed or to-be-signed OpenSSH certificate.
type Certificate struct {
	Nonce           []byte
	Key             *PublicKey // the certified user key
	Serial          uint64
	CertType        uint32
	KeyID           string
	ValidPrincipals []string
	ValidAfter      uint64 // unix seconds
	ValidBefore     uint64 // unix seconds, or InfiniteValidity
	CriticalOptions []Option
	Extensions      []Option
	Reserved        []byte
	SignatureKey    []byte // CA public key blob
	Signature       []byte // signature blob (algo + raw signature)
}

// certAlgo derives the certificate algorithm name from the certified
// key's algorithm: `ssh-ed25519` -> `ssh-ed25519-cert-v01@openssh.com`,
// `sk-ssh-ed25519@openssh.com` -> `sk-ssh-ed25519-cert-v01@openssh.com`.
func certAlgo(keyAlgo string) string {
	if base, ok := strings.CutSuffix(keyAlgo, "@openssh.com"); ok {
		return base + "-cert-v01@openssh.com"
	}
	return keyAlgo + "-cert-v01@openssh.com"
}

// baseAlgo inverts certAlgo, resolving the ambiguity between plain and
// @openssh.com key algorithms via the field-count table.
func baseAlgo(certAlgoName string) (string, error) {
	trimmed, ok := strings.CutSuffix(certAlgoName, "-cert-v01@openssh.com")
	if !ok {
		return "", fmt.Errorf("sshcert: %q is not a certificate algorithm", certAlgoName)
	}
	if _, ok := pubKeyFieldCount[trimmed]; ok {
		return trimmed, nil
	}
	if _, ok := pubKeyFieldCount[trimmed+"@openssh.com"]; ok {
		return trimmed + "@openssh.com", nil
	}
	return "", fmt.Errorf("sshcert: unsupported certificate algorithm %q", certAlgoName)
}

// Algo returns the certificate's algorithm name.
func (c *Certificate) Algo() string { return certAlgo(c.Key.Algo) }

// packOptions encodes options sorted by name, as OpenSSH requires.
// A valued option's data is itself a wire string holding the value.
func packOptions(opts []Option) []byte {
	sorted := make([]Option, len(opts))
	copy(sorted, opts)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	var w wire.Buffer
	for _, o := range sorted {
		w.String(o.Name)
		if o.Data == "" {
			w.String("")
		} else {
			var inner wire.Buffer
			inner.String(o.Data)
			w.Bytes32(inner.Bytes())
		}
	}
	return w.Bytes()
}

// unpackOptions inverts packOptions.
func unpackOptions(b []byte) ([]Option, error) {
	r := wire.NewReader(b)
	var out []Option
	for !r.Empty() {
		name, err := r.String()
		if err != nil {
			return nil, err
		}
		data, err := r.Bytes32()
		if err != nil {
			return nil, err
		}
		o := Option{Name: name}
		if len(data) > 0 {
			inner := wire.NewReader(data)
			v, err := inner.String()
			if err != nil || !inner.Empty() {
				return nil, fmt.Errorf("sshcert: malformed data for option %q", name)
			}
			o.Data = v
		}
		out = append(out, o)
	}
	return out, nil
}

// tbs marshals the to-be-signed portion: every field up to and including
// the signature key, but not the signature itself.
func (c *Certificate) tbs() []byte {
	var w wire.Buffer
	w.String(c.Algo())
	w.Bytes32(c.Nonce)
	w.Raw(c.Key.keyFields())
	w.Uint64(c.Serial)
	w.Uint32(c.CertType)
	w.String(c.KeyID)
	w.Bytes32(wire.PackStringList(c.ValidPrincipals))
	w.Uint64(c.ValidAfter)
	w.Uint64(c.ValidBefore)
	w.Bytes32(packOptions(c.CriticalOptions))
	w.Bytes32(packOptions(c.Extensions))
	w.Bytes32(c.Reserved)
	w.Bytes32(c.SignatureKey)
	return w.Bytes()
}

// Sign completes the certificate with an ed25519 CA signature. If
// c.Nonce is unset, 32 bytes are drawn from nonceRand (crypto/rand when
// nil); tests pass a fixed reader for byte-identical certificates.
func (c *Certificate) Sign(caPub *PublicKey, caPriv ed25519.PrivateKey, nonceRand io.Reader) error {
	if caPub.Algo != AlgoEd25519 {
		return errors.New("sshcert: CA key must be ed25519")
	}
	if len(c.Nonce) == 0 {
		if nonceRand == nil {
			nonceRand = rand.Reader
		}
		nonce := make([]byte, 32)
		if _, err := io.ReadFull(nonceRand, nonce); err != nil {
			return fmt.Errorf("sshcert: read nonce: %v", err)
		}
		c.Nonce = nonce
	}
	c.SignatureKey = caPub.Blob
	sig := ed25519.Sign(caPriv, c.tbs())
	var w wire.Buffer
	w.String(AlgoEd25519)
	w.Bytes32(sig)
	c.Signature = w.Bytes()
	return nil
}

// Marshal renders the complete signed certificate blob.
func (c *Certificate) Marshal() []byte {
	var w wire.Buffer
	w.Raw(c.tbs())
	w.Bytes32(c.Signature)
	return w.Bytes()
}

// MarshalLine renders the certificate as a `-cert.pub` line, ready for
// `ssh -o CertificateFile=...` (no trailing newline).
func (c *Certificate) MarshalLine(comment string) string {
	line := c.Algo() + " " + base64.StdEncoding.EncodeToString(c.Marshal())
	if comment != "" {
		line += " " + comment
	}
	return line
}

// ParseCertificateLine parses a `-cert.pub` line.
func ParseCertificateLine(line string) (*Certificate, error) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 2 {
		return nil, errors.New("sshcert: expected `<cert-algo> <base64> [comment]`")
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return nil, fmt.Errorf("sshcert: invalid base64 certificate data: %v", err)
	}
	c, err := ParseCertificate(blob)
	if err != nil {
		return nil, err
	}
	if got := c.Algo(); got != fields[0] {
		return nil, fmt.Errorf("sshcert: certificate blob is %q but line says %q", got, fields[0])
	}
	return c, nil
}

// ParseCertificate parses a raw certificate blob.
func ParseCertificate(blob []byte) (*Certificate, error) {
	r := wire.NewReader(blob)
	algoName, err := r.String()
	if err != nil {
		return nil, err
	}
	keyAlgo, err := baseAlgo(algoName)
	if err != nil {
		return nil, err
	}
	c := &Certificate{}
	if c.Nonce, err = r.Bytes32(); err != nil {
		return nil, fmt.Errorf("sshcert: nonce: %v", err)
	}
	// Reassemble the certified key's standalone blob from its embedded fields.
	var kw wire.Buffer
	kw.String(keyAlgo)
	for i := 0; i < pubKeyFieldCount[keyAlgo]; i++ {
		f, err := r.Bytes32()
		if err != nil {
			return nil, fmt.Errorf("sshcert: public key field %d: %v", i+1, err)
		}
		kw.Bytes32(f)
	}
	c.Key = &PublicKey{Algo: keyAlgo, Blob: kw.Bytes()}
	if c.Serial, err = r.Uint64(); err != nil {
		return nil, fmt.Errorf("sshcert: serial: %v", err)
	}
	if c.CertType, err = r.Uint32(); err != nil {
		return nil, fmt.Errorf("sshcert: type: %v", err)
	}
	if c.CertType != UserCert && c.CertType != HostCert {
		return nil, fmt.Errorf("sshcert: unknown certificate type %d", c.CertType)
	}
	if c.KeyID, err = r.String(); err != nil {
		return nil, fmt.Errorf("sshcert: key id: %v", err)
	}
	principals, err := r.Bytes32()
	if err != nil {
		return nil, fmt.Errorf("sshcert: principals: %v", err)
	}
	if c.ValidPrincipals, err = wire.StringList(principals); err != nil {
		return nil, fmt.Errorf("sshcert: principals: %v", err)
	}
	if c.ValidAfter, err = r.Uint64(); err != nil {
		return nil, fmt.Errorf("sshcert: valid after: %v", err)
	}
	if c.ValidBefore, err = r.Uint64(); err != nil {
		return nil, fmt.Errorf("sshcert: valid before: %v", err)
	}
	crit, err := r.Bytes32()
	if err != nil {
		return nil, fmt.Errorf("sshcert: critical options: %v", err)
	}
	if c.CriticalOptions, err = unpackOptions(crit); err != nil {
		return nil, fmt.Errorf("sshcert: critical options: %v", err)
	}
	exts, err := r.Bytes32()
	if err != nil {
		return nil, fmt.Errorf("sshcert: extensions: %v", err)
	}
	if c.Extensions, err = unpackOptions(exts); err != nil {
		return nil, fmt.Errorf("sshcert: extensions: %v", err)
	}
	if c.Reserved, err = r.Bytes32(); err != nil {
		return nil, fmt.Errorf("sshcert: reserved: %v", err)
	}
	if c.SignatureKey, err = r.Bytes32(); err != nil {
		return nil, fmt.Errorf("sshcert: signature key: %v", err)
	}
	if c.Signature, err = r.Bytes32(); err != nil {
		return nil, fmt.Errorf("sshcert: signature: %v", err)
	}
	if !r.Empty() {
		return nil, errors.New("sshcert: trailing bytes after signature")
	}
	return c, nil
}

// SignatureCA returns the CA public key embedded in the certificate.
func (c *Certificate) SignatureCA() (*PublicKey, error) {
	r := wire.NewReader(c.SignatureKey)
	algo, err := r.String()
	if err != nil {
		return nil, errors.New("sshcert: malformed signature key")
	}
	if _, ok := pubKeyFieldCount[algo]; !ok {
		return nil, fmt.Errorf("sshcert: unsupported signature key algorithm %q", algo)
	}
	return &PublicKey{Algo: algo, Blob: c.SignatureKey}, nil
}

// Verify checks that the certificate is signed by exactly caPub. It does
// not check the validity window or revocation — see ValidAt and the ca
// package, which layer those checks separately so `inspect` can explain
// an expired-but-genuine certificate.
func (c *Certificate) Verify(caPub *PublicKey) error {
	sigCA, err := c.SignatureCA()
	if err != nil {
		return err
	}
	if string(sigCA.Blob) != string(caPub.Blob) {
		return fmt.Errorf("sshcert: signed by a different CA (%s, want %s)",
			sigCA.Fingerprint(), caPub.Fingerprint())
	}
	pk, err := caPub.Ed25519()
	if err != nil {
		return err
	}
	r := wire.NewReader(c.Signature)
	sigAlgo, err := r.String()
	if err != nil || sigAlgo != AlgoEd25519 {
		return errors.New("sshcert: malformed or non-ed25519 signature")
	}
	raw, err := r.Bytes32()
	if err != nil || !r.Empty() {
		return errors.New("sshcert: malformed signature blob")
	}
	if !ed25519.Verify(pk, c.tbs(), raw) {
		return errors.New("sshcert: signature verification failed")
	}
	return nil
}

// ValidAt checks the validity window at time t.
func (c *Certificate) ValidAt(t time.Time) error {
	ts := uint64(t.Unix())
	if ts < c.ValidAfter {
		return fmt.Errorf("sshcert: not valid before %s", time.Unix(int64(c.ValidAfter), 0).UTC().Format(time.RFC3339))
	}
	if c.ValidBefore != InfiniteValidity && ts >= c.ValidBefore {
		return fmt.Errorf("sshcert: expired at %s", time.Unix(int64(c.ValidBefore), 0).UTC().Format(time.RFC3339))
	}
	return nil
}

// TypeString names the certificate type for humans.
func (c *Certificate) TypeString() string {
	if c.CertType == HostCert {
		return "host"
	}
	return "user"
}
