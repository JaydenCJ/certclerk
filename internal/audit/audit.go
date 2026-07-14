// Package audit implements certclerk's append-only, tamper-evident
// audit log: one JSON object per line, each carrying the SHA-256 hash
// of its own canonical form and the hash of its predecessor. Editing,
// deleting, or reordering any historical line breaks the chain, and
// `certclerk audit --verify` says exactly where.
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Genesis is the Prev value of the first entry.
const Genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// Actions recorded in the log.
const (
	ActionInit   = "init"
	ActionIssue  = "issue"
	ActionRevoke = "revoke"
)

// Entry is one audit record. Field order is the canonical hashing order
// (encoding/json marshals struct fields in declaration order), so do
// not reorder fields without bumping a format version.
type Entry struct {
	Seq         uint64   `json:"seq"`
	Time        string   `json:"time"` // RFC 3339, UTC
	Action      string   `json:"action"`
	User        string   `json:"user,omitempty"`
	Serial      uint64   `json:"serial,omitempty"`
	KeyID       string   `json:"key_id,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	Principals  []string `json:"principals,omitempty"`
	ValidBefore string   `json:"valid_before,omitempty"`
	Reason      string   `json:"reason,omitempty"`
	Prev        string   `json:"prev"`
	Hash        string   `json:"hash"`
}

// computeHash hashes the canonical JSON of the entry with Hash blanked.
func (e Entry) computeHash() string {
	e.Hash = ""
	b, err := json.Marshal(e)
	if err != nil {
		// Entry has no unmarshalable fields; this cannot happen.
		panic(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Log is a handle on an audit file. Opening does not read anything;
// Append and Entries do the IO.
type Log struct {
	Path string
}

// Open returns a handle for the audit file at path.
func Open(path string) *Log { return &Log{Path: path} }

// Entries reads and decodes every line. A malformed line is an error —
// the log is evidence, not advisory output.
func (l *Log) Entries() ([]Entry, error) {
	f, err := os.Open(l.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	line := 0
	for sc.Scan() {
		line++
		if len(sc.Bytes()) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("audit: line %d: %v", line, err)
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("audit: %v", err)
	}
	return out, nil
}

// Append seals and writes a new entry: it fills Seq, Time (if empty),
// Prev, and Hash, then appends one line. The completed entry is
// returned so callers can echo the hash.
func (l *Log) Append(e Entry, now time.Time) (Entry, error) {
	prior, err := l.Entries()
	if err != nil {
		return Entry{}, err
	}
	e.Seq = uint64(len(prior)) + 1
	if e.Time == "" {
		e.Time = now.UTC().Format(time.RFC3339)
	}
	e.Prev = Genesis
	if len(prior) > 0 {
		e.Prev = prior[len(prior)-1].Hash
	}
	e.Hash = e.computeHash()
	line, err := json.Marshal(e)
	if err != nil {
		return Entry{}, err
	}
	f, err := os.OpenFile(l.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return Entry{}, err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return Entry{}, err
	}
	// The log is evidence: a swallowed close error could mean a silently
	// missing entry, so it fails the append.
	if err := f.Close(); err != nil {
		return Entry{}, err
	}
	return e, nil
}

// Verify checks the whole chain: sequence numbers contiguous from 1,
// each Prev equal to the predecessor's Hash, and each Hash equal to the
// recomputed canonical hash. The error names the first bad sequence
// number, which is also the line number for well-formed logs.
func Verify(entries []Entry) error {
	prev := Genesis
	for i, e := range entries {
		want := uint64(i) + 1
		if e.Seq != want {
			return fmt.Errorf("audit: entry %d: seq %d, want %d (entries removed or reordered)", i+1, e.Seq, want)
		}
		if e.Prev != prev {
			return fmt.Errorf("audit: entry %d: broken chain (prev %.12s..., want %.12s...)", e.Seq, e.Prev, prev)
		}
		if got := e.computeHash(); got != e.Hash {
			return fmt.Errorf("audit: entry %d: content does not match its hash (tampered?)", e.Seq)
		}
		prev = e.Hash
	}
	return nil
}
