// Package ca ties the pieces together into a certificate authority
// rooted in one directory: an ed25519 keypair, a policy document, a
// monotonic serial counter, a revocation list, and the audit log. All
// state is plain files, so the whole CA can be backed up with cp -r
// and diffed with git.
package ca

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/JaydenCJ/certclerk/internal/audit"
	"github.com/JaydenCJ/certclerk/internal/krl"
	"github.com/JaydenCJ/certclerk/internal/policy"
	"github.com/JaydenCJ/certclerk/internal/sshcert"
)

// File names inside the CA directory.
const (
	FileKey     = "ca.key"
	FilePub     = "ca.pub"
	FilePolicy  = "policy.json"
	FileSerial  = "serial"
	FileAudit   = "audit.log"
	FileRevoked = "revoked.json"
)

// CA is an opened certificate authority.
type CA struct {
	Dir    string
	Pub    *sshcert.PublicKey
	Policy *policy.Policy
	Audit  *audit.Log
	priv   ed25519.PrivateKey
}

// Revocation is one entry in revoked.json. Exactly one of Serial or
// KeyID is set: serials revoke a single certificate, key IDs revoke
// every certificate ever issued under that ID.
type Revocation struct {
	Serial uint64 `json:"serial,omitempty"`
	KeyID  string `json:"key_id,omitempty"`
	Time   string `json:"time"`
	Reason string `json:"reason,omitempty"`
}

// Init creates a new CA directory: fresh keypair, default policy, and
// the audit log's genesis entry. It refuses to touch a directory that
// already contains a CA key.
func Init(dir, comment string, now time.Time) (*CA, error) {
	if _, err := os.Stat(filepath.Join(dir, FileKey)); err == nil {
		return nil, fmt.Errorf("ca: %s already contains a CA (found %s)", dir, FileKey)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if comment == "" {
		comment = "certclerk-ca"
	}
	pub, priv, err := sshcert.GenerateCA(comment)
	if err != nil {
		return nil, err
	}
	keyPEM, err := sshcert.MarshalPrivateKeyPEM(priv)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, FileKey), keyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, FilePub), []byte(pub.MarshalAuthorizedKey()+"\n"), 0o644); err != nil {
		return nil, err
	}
	pol, err := policy.Default().Marshal()
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, FilePolicy), pol, 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, FileSerial), []byte("1\n"), 0o600); err != nil {
		return nil, err
	}
	ca := &CA{
		Dir:    dir,
		Pub:    pub,
		Policy: policy.Default(),
		Audit:  audit.Open(filepath.Join(dir, FileAudit)),
		priv:   priv,
	}
	_, err = ca.Audit.Append(audit.Entry{
		Action:      audit.ActionInit,
		Fingerprint: pub.Fingerprint(),
	}, now)
	if err != nil {
		return nil, err
	}
	return ca, nil
}

// Open loads an existing CA directory, validating the policy up front
// so every subcommand fails fast on a broken policy.json.
func Open(dir string) (*CA, error) {
	keyPEM, err := os.ReadFile(filepath.Join(dir, FileKey))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("ca: no CA in %s (run `certclerk init` first)", dir)
		}
		return nil, err
	}
	priv, err := sshcert.ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	pub, err := sshcert.LoadPublicKey(filepath.Join(dir, FilePub))
	if err != nil {
		return nil, fmt.Errorf("ca: %v", err)
	}
	polBytes, err := os.ReadFile(filepath.Join(dir, FilePolicy))
	if err != nil {
		return nil, err
	}
	pol, err := policy.Parse(polBytes)
	if err != nil {
		return nil, fmt.Errorf("ca: %s: %v", FilePolicy, err)
	}
	return &CA{
		Dir:    dir,
		Pub:    pub,
		Policy: pol,
		Audit:  audit.Open(filepath.Join(dir, FileAudit)),
		priv:   priv,
	}, nil
}

// nextSerial reads, returns, and increments the persisted counter.
func (ca *CA) nextSerial() (uint64, error) {
	path := filepath.Join(ca.Dir, FileSerial)
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("ca: corrupt serial file %s", path)
	}
	if err := os.WriteFile(path, []byte(strconv.FormatUint(n+1, 10)+"\n"), 0o600); err != nil {
		return 0, err
	}
	return n, nil
}

// IssueRequest describes one certificate issuance.
type IssueRequest struct {
	User       string
	Key        *sshcert.PublicKey
	Principals []string      // empty = all principals the policy names
	TTL        time.Duration // 0 = the policy's max_ttl
	KeyID      string        // empty = "<user>@certclerk-<serial>"
	Backdate   time.Duration // ValidAfter = Now - Backdate (clock-skew slack)
	Now        time.Time     // zero = time.Now(); tests pin it
	NonceRand  io.Reader     // nil = crypto/rand; tests pin it
}

// Issued is the result of a successful issuance.
type Issued struct {
	Cert  *sshcert.Certificate
	Line  string // the -cert.pub line, no trailing newline
	Grant *policy.Grant
	Entry audit.Entry
}

// Issue authorizes the request against the policy, signs a certificate,
// and appends the audit entry. Policy denials come back as
// *policy.DenyError; nothing is written in that case.
func (ca *CA) Issue(req IssueRequest) (*Issued, error) {
	if req.User == "" {
		return nil, errors.New("ca: issue: user is required")
	}
	if req.Key == nil {
		return nil, errors.New("ca: issue: public key is required")
	}
	grant, err := ca.Policy.Authorize(req.User, req.Principals, req.TTL)
	if err != nil {
		return nil, err
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC().Truncate(time.Second)
	backdate := req.Backdate
	if backdate < 0 {
		return nil, errors.New("ca: issue: backdate must not be negative")
	}
	serial, err := ca.nextSerial()
	if err != nil {
		return nil, err
	}
	keyID := req.KeyID
	if keyID == "" {
		keyID = fmt.Sprintf("%s@certclerk-%d", req.User, serial)
	}
	cert := &sshcert.Certificate{
		Key:             req.Key,
		Serial:          serial,
		CertType:        sshcert.UserCert,
		KeyID:           keyID,
		ValidPrincipals: grant.Principals,
		ValidAfter:      uint64(now.Add(-backdate).Unix()),
		ValidBefore:     uint64(now.Add(grant.TTL).Unix()),
		Extensions:      extensionOptions(grant.Extensions),
	}
	if grant.ForceCommand != "" {
		cert.CriticalOptions = append(cert.CriticalOptions,
			sshcert.Option{Name: "force-command", Data: grant.ForceCommand})
	}
	if len(grant.SourceAddress) > 0 {
		cert.CriticalOptions = append(cert.CriticalOptions,
			sshcert.Option{Name: "source-address", Data: strings.Join(grant.SourceAddress, ",")})
	}
	if err := cert.Sign(ca.Pub, ca.priv, req.NonceRand); err != nil {
		return nil, err
	}
	entry, err := ca.Audit.Append(audit.Entry{
		Action:      audit.ActionIssue,
		User:        req.User,
		Serial:      serial,
		KeyID:       keyID,
		Fingerprint: req.Key.Fingerprint(),
		Principals:  grant.Principals,
		ValidBefore: time.Unix(int64(cert.ValidBefore), 0).UTC().Format(time.RFC3339),
	}, now)
	if err != nil {
		return nil, err
	}
	return &Issued{
		Cert:  cert,
		Line:  cert.MarshalLine(keyID),
		Grant: grant,
		Entry: entry,
	}, nil
}

func extensionOptions(names []string) []sshcert.Option {
	var out []sshcert.Option
	for _, n := range names {
		out = append(out, sshcert.Option{Name: n})
	}
	return out
}

// Revocations reads revoked.json (absent file = empty list).
func (ca *CA) Revocations() ([]Revocation, error) {
	b, err := os.ReadFile(filepath.Join(ca.Dir, FileRevoked))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Revocation
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("ca: %s: %v", FileRevoked, err)
	}
	return out, nil
}

func (ca *CA) writeRevocations(revs []Revocation) error {
	b, err := json.MarshalIndent(revs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(ca.Dir, FileRevoked), append(b, '\n'), 0o600)
}

// issuedSerial consults the audit log to confirm a serial was issued
// and returns its issue entry. Revoking a never-issued serial is almost
// always a typo, so Revoke refuses it.
func (ca *CA) issuedSerial(serial uint64) (*audit.Entry, error) {
	entries, err := ca.Audit.Entries()
	if err != nil {
		return nil, err
	}
	for i := range entries {
		if entries[i].Action == audit.ActionIssue && entries[i].Serial == serial {
			return &entries[i], nil
		}
	}
	return nil, fmt.Errorf("ca: serial %d was never issued by this CA", serial)
}

// RevokeSerial revokes one certificate by serial.
func (ca *CA) RevokeSerial(serial uint64, reason string, now time.Time) (*Revocation, error) {
	issued, err := ca.issuedSerial(serial)
	if err != nil {
		return nil, err
	}
	revs, err := ca.Revocations()
	if err != nil {
		return nil, err
	}
	for _, r := range revs {
		if r.Serial == serial {
			return nil, fmt.Errorf("ca: serial %d is already revoked", serial)
		}
	}
	now = now.UTC().Truncate(time.Second)
	rev := Revocation{Serial: serial, Time: now.Format(time.RFC3339), Reason: reason}
	if err := ca.writeRevocations(append(revs, rev)); err != nil {
		return nil, err
	}
	_, err = ca.Audit.Append(audit.Entry{
		Action: audit.ActionRevoke,
		User:   issued.User,
		Serial: serial,
		KeyID:  issued.KeyID,
		Reason: reason,
	}, now)
	if err != nil {
		return nil, err
	}
	return &rev, nil
}

// RevokeKeyID revokes every certificate carrying the given key ID —
// the "this laptop is gone" hammer.
func (ca *CA) RevokeKeyID(keyID, reason string, now time.Time) (*Revocation, error) {
	if keyID == "" {
		return nil, errors.New("ca: revoke: key id must not be empty")
	}
	revs, err := ca.Revocations()
	if err != nil {
		return nil, err
	}
	for _, r := range revs {
		if r.KeyID == keyID && r.Serial == 0 {
			return nil, fmt.Errorf("ca: key id %q is already revoked", keyID)
		}
	}
	now = now.UTC().Truncate(time.Second)
	rev := Revocation{KeyID: keyID, Time: now.Format(time.RFC3339), Reason: reason}
	if err := ca.writeRevocations(append(revs, rev)); err != nil {
		return nil, err
	}
	_, err = ca.Audit.Append(audit.Entry{
		Action: audit.ActionRevoke,
		KeyID:  keyID,
		Reason: reason,
	}, now)
	if err != nil {
		return nil, err
	}
	return &rev, nil
}

// IsRevoked reports whether a certificate is covered by the revocation
// list, and by which entry.
func (ca *CA) IsRevoked(cert *sshcert.Certificate) (*Revocation, error) {
	revs, err := ca.Revocations()
	if err != nil {
		return nil, err
	}
	for i, r := range revs {
		if r.Serial != 0 && r.Serial == cert.Serial {
			return &revs[i], nil
		}
		if r.Serial == 0 && r.KeyID != "" && r.KeyID == cert.KeyID {
			return &revs[i], nil
		}
	}
	return nil, nil
}

// KRL renders the current revocation list as an OpenSSH binary KRL.
func (ca *CA) KRL(now time.Time) ([]byte, error) {
	revs, err := ca.Revocations()
	if err != nil {
		return nil, err
	}
	k := &krl.KRL{
		Version:     uint64(len(revs)),
		GeneratedAt: now.UTC(),
		Comment:     "certclerk revocation list",
		CAKey:       ca.Pub.Blob,
	}
	for _, r := range revs {
		if r.Serial != 0 {
			k.Serials = append(k.Serials, r.Serial)
		} else if r.KeyID != "" {
			k.KeyIDs = append(k.KeyIDs, r.KeyID)
		}
	}
	return k.Marshal(), nil
}

// Verify runs the full acceptance check sshd would apply at time at:
// user certificate, signed by this CA, inside its validity window, and
// not revoked. The returned string is a one-line human verdict.
func (ca *CA) Verify(cert *sshcert.Certificate, at time.Time) (string, error) {
	if cert.CertType != sshcert.UserCert {
		return "", fmt.Errorf("ca: not a user certificate (type %s)", cert.TypeString())
	}
	if err := cert.Verify(ca.Pub); err != nil {
		return "", err
	}
	if err := cert.ValidAt(at); err != nil {
		return "", err
	}
	rev, err := ca.IsRevoked(cert)
	if err != nil {
		return "", err
	}
	if rev != nil {
		by := fmt.Sprintf("serial %d", rev.Serial)
		if rev.Serial == 0 {
			by = fmt.Sprintf("key id %q", rev.KeyID)
		}
		return "", fmt.Errorf("ca: certificate revoked (%s at %s)", by, rev.Time)
	}
	return fmt.Sprintf("OK: serial %d key id %q principals %s valid until %s",
		cert.Serial, cert.KeyID, strings.Join(cert.ValidPrincipals, ","),
		time.Unix(int64(cert.ValidBefore), 0).UTC().Format(time.RFC3339)), nil
}
