// Tests for the SSH wire encoding. Every higher layer (keys, certs,
// KRLs) rides on these primitives, so the edge cases here — empty
// strings, truncation, oversized length prefixes — are what keep a
// malformed certificate from panicking the CLI.
package wire

import (
	"bytes"
	"errors"
	"testing"
)

func TestIntegerRoundTrips(t *testing.T) {
	var w Buffer
	w.Uint32(0xdeadbeef)
	w.Uint64(1<<63 + 42)
	r := NewReader(w.Bytes())
	if got, err := r.Uint32(); err != nil || got != 0xdeadbeef {
		t.Fatalf("uint32: got %x, %v", got, err)
	}
	if got, err := r.Uint64(); err != nil || got != 1<<63+42 {
		t.Fatalf("uint64: got %d, %v", got, err)
	}
	if !r.Empty() {
		t.Fatal("reader should be drained")
	}
}

func TestStringRoundTrip(t *testing.T) {
	var w Buffer
	w.String("ssh-ed25519")
	if w.Len() != 4+11 {
		t.Fatalf("encoded length = %d, want 15", w.Len())
	}
	got, err := NewReader(w.Bytes()).String()
	if err != nil || got != "ssh-ed25519" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestEmptyStringEncodesAsFourZeroBytes(t *testing.T) {
	// Certificates encode "no critical options" as an empty string field;
	// it must be 4 zero bytes, not nothing.
	var w Buffer
	w.String("")
	if !bytes.Equal(w.Bytes(), []byte{0, 0, 0, 0}) {
		t.Fatalf("got % x", w.Bytes())
	}
}

func TestReadsFromTruncatedDataFail(t *testing.T) {
	cases := map[string]func(*Reader) error{
		"uint32": func(r *Reader) error { _, err := r.Uint32(); return err },
		"uint64": func(r *Reader) error { _, err := r.Uint64(); return err },
		"byte":   func(r *Reader) error { _, err := r.Byte(); return err },
	}
	for name, read := range cases {
		if err := read(NewReader(nil)); !errors.Is(err, ErrShort) {
			t.Errorf("%s on empty input: err = %v, want ErrShort", name, err)
		}
	}
	// A 2-byte buffer is too short for any integer wider than a byte.
	if _, err := NewReader([]byte{1, 2}).Uint32(); !errors.Is(err, ErrShort) {
		t.Errorf("uint32 on 2 bytes: err = %v, want ErrShort", err)
	}
}

func TestStringLengthBeyondBufferFails(t *testing.T) {
	// A hostile length prefix must not read out of bounds.
	b := []byte{0xff, 0xff, 0xff, 0xff, 'x'}
	if _, err := NewReader(b).String(); err == nil {
		t.Fatal("expected an error for a 4 GiB length prefix on 1 byte")
	}
}

func TestRestDrainsReader(t *testing.T) {
	r := NewReader([]byte{1, 2, 3})
	if got := r.Rest(); !bytes.Equal(got, []byte{1, 2, 3}) {
		t.Fatalf("Rest = % x", got)
	}
	if !r.Empty() {
		t.Fatal("reader should be empty after Rest")
	}
}

func TestStringListRoundTrip(t *testing.T) {
	in := []string{"alice", "deploy", ""}
	out, err := StringList(PackStringList(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 3 || out[0] != "alice" || out[1] != "deploy" || out[2] != "" {
		t.Fatalf("round trip = %q", out)
	}
}

func TestStringListEdgeCases(t *testing.T) {
	// An empty blob is an empty (nil) list, not an error.
	if out, err := StringList(nil); err != nil || out != nil {
		t.Fatalf("empty blob: got %v, %v; want nil, nil", out, err)
	}
	// A truncated final entry must fail, not be silently dropped.
	blob := PackStringList([]string{"alice"})
	if _, err := StringList(blob[:len(blob)-1]); err == nil {
		t.Fatal("expected error for truncated list entry")
	}
}
