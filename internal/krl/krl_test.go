// Tests for the OpenSSH KRL writer/parser. The binary layout is pinned
// byte-for-byte against PROTOCOL.krl (magic, header widths, section
// tags), because the artifact's only consumer is sshd — there is no
// second implementation to be lenient with us.
package krl

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/JaydenCJ/certclerk/internal/wire"
)

var genTime = time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)

func testCAKey() []byte {
	var w wire.Buffer
	w.String("ssh-ed25519")
	w.Bytes32(bytes.Repeat([]byte{0xAB}, 32))
	return w.Bytes()
}

func testKRL() *KRL {
	return &KRL{
		Version:     3,
		GeneratedAt: genTime,
		Comment:     "certclerk revocation list",
		CAKey:       testCAKey(),
		Serials:     []uint64{5, 2, 9},
		KeyIDs:      []string{"bob@certclerk-4", "alice@certclerk-1"},
	}
}

func TestHeaderLayout(t *testing.T) {
	b := testKRL().Marshal()
	// "SSHKRL\n\0" magic, format version 1.
	if !bytes.HasPrefix(b, []byte("SSHKRL\n\x00")) {
		t.Fatalf("magic missing: % x", b[:8])
	}
	if binary.BigEndian.Uint32(b[8:12]) != 1 {
		t.Fatalf("format version = %d", binary.BigEndian.Uint32(b[8:12]))
	}
	if binary.BigEndian.Uint64(b[12:20]) != 3 {
		t.Fatalf("krl version = %d", binary.BigEndian.Uint64(b[12:20]))
	}
	if got := binary.BigEndian.Uint64(b[20:28]); got != uint64(genTime.Unix()) {
		t.Fatalf("generated date = %d", got)
	}
	if binary.BigEndian.Uint64(b[28:36]) != 0 {
		t.Fatal("flags must be zero")
	}
}

func TestRoundTrip(t *testing.T) {
	k := testKRL()
	back, err := Parse(k.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if back.Version != 3 || back.Comment != "certclerk revocation list" {
		t.Fatalf("header lost: %+v", back)
	}
	if !back.GeneratedAt.Equal(genTime) {
		t.Fatalf("generated at = %v", back.GeneratedAt)
	}
	if !bytes.Equal(back.CAKey, k.CAKey) {
		t.Fatal("CA key scope lost")
	}
	// Serials come back sorted+deduped; key IDs sorted.
	wantSerials := []uint64{2, 5, 9}
	for i, s := range wantSerials {
		if back.Serials[i] != s {
			t.Fatalf("serials = %v", back.Serials)
		}
	}
	if back.KeyIDs[0] != "alice@certclerk-1" || back.KeyIDs[1] != "bob@certclerk-4" {
		t.Fatalf("key ids = %v", back.KeyIDs)
	}
}

func TestMarshalIsDeterministicAndOrderInsensitive(t *testing.T) {
	a := testKRL()
	b := testKRL()
	b.Serials = []uint64{9, 5, 2, 2} // shuffled + duplicated
	b.KeyIDs = []string{"alice@certclerk-1", "bob@certclerk-4"}
	if !bytes.Equal(a.Marshal(), b.Marshal()) {
		t.Fatal("input order changed the output bytes")
	}
}

func TestEmptyKRLIsValid(t *testing.T) {
	// `certclerk krl` before any revocation must still emit a KRL sshd
	// can load (an empty RevokedKeys file is how deployments start).
	k := &KRL{GeneratedAt: genTime, CAKey: testCAKey()}
	back, err := Parse(k.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Serials) != 0 || len(back.KeyIDs) != 0 {
		t.Fatalf("empty KRL round-tripped content: %+v", back)
	}
}

func TestSerialListSectionTags(t *testing.T) {
	b := testKRL().Marshal()
	// The certificates section is tag 0x01; inside it, serial list is
	// 0x20 and key IDs 0x23.
	if !bytes.Contains(b, []byte{0x20, 0x00, 0x00, 0x00, 24}) { // 3 serials × 8 bytes
		t.Fatal("serial list subsection (0x20, len 24) not found")
	}
	if !bytes.Contains(b, []byte{0x23}) {
		t.Fatal("key id subsection tag not found")
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	cases := map[string][]byte{
		"empty":       {},
		"bad magic":   []byte("NOTAKRL\x00rest"),
		"cut header":  []byte("SSHKRL\n\x00\x00\x00\x00\x01"),
		"cut section": append(testKRL().Marshal()[:40], 0x01),
	}
	for name, b := range cases {
		if _, err := Parse(b); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestParseExpandsSerialRanges(t *testing.T) {
	// Foreign KRLs (ssh-keygen -k) may use range subsections; Parse
	// must expand them for inspection.
	back, err := Parse(rangeKRL(10, 13))
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Serials) != 4 || back.Serials[0] != 10 || back.Serials[3] != 13 {
		t.Fatalf("serials = %v, want 10..13", back.Serials)
	}
	// But a memory-ballooning range in a hostile KRL is refused.
	if _, err := Parse(rangeKRL(0, 1<<40)); err == nil {
		t.Fatal("expected an error for an absurd range")
	}
}

// rangeKRL builds a KRL whose certificates section holds one serial range.
func rangeKRL(lo, hi uint64) []byte {
	var body wire.Buffer
	body.Bytes32(testCAKey())
	body.String("") // reserved
	var rng wire.Buffer
	rng.Uint64(lo)
	rng.Uint64(hi)
	body.Byte(certSectionSerialRange)
	body.Bytes32(rng.Bytes())

	var w wire.Buffer
	w.Uint64(magic)
	w.Uint32(formatVersion)
	w.Uint64(1)
	w.Uint64(uint64(genTime.Unix()))
	w.Uint64(0)
	w.String("")
	w.String("")
	w.Byte(sectionCertificates)
	w.Bytes32(body.Bytes())
	return w.Bytes()
}

func TestParseSkipsUnknownTopLevelSections(t *testing.T) {
	// KRLs may carry explicit-key or extension sections certclerk does
	// not model; they must be skipped, not fatal.
	b := testKRL().Marshal()
	var w wire.Buffer
	w.Raw(b)
	w.Byte(2) // KRL_SECTION_EXPLICIT_KEY
	w.Bytes32([]byte("opaque"))
	back, err := Parse(w.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Serials) != 3 {
		t.Fatalf("known sections lost: %+v", back)
	}
}
