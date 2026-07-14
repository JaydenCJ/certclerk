// Tests for the hash-chained audit log. The log is only worth keeping
// if tampering is detectable, so most cases here edit history in some
// way — rewrite, delete, reorder, truncate — and demand that Verify
// names the first bad entry.
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)

// writeChain appends n issue entries to a fresh log and returns it.
func writeChain(t *testing.T, n int) (*Log, []Entry) {
	t.Helper()
	l := Open(filepath.Join(t.TempDir(), "audit.log"))
	for i := 0; i < n; i++ {
		_, err := l.Append(Entry{
			Action: ActionIssue,
			User:   "alice",
			Serial: uint64(i + 1),
			KeyID:  "alice@certclerk",
		}, t0.Add(time.Duration(i)*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
	}
	entries, err := l.Entries()
	if err != nil {
		t.Fatal(err)
	}
	return l, entries
}

func TestAppendFillsSeqPrevHash(t *testing.T) {
	_, entries := writeChain(t, 3)
	if len(entries) != 3 {
		t.Fatalf("got %d entries", len(entries))
	}
	if entries[0].Seq != 1 || entries[0].Prev != Genesis {
		t.Fatalf("first entry: seq=%d prev=%s", entries[0].Seq, entries[0].Prev)
	}
	for i := 1; i < 3; i++ {
		if entries[i].Prev != entries[i-1].Hash {
			t.Fatalf("entry %d prev does not link to predecessor", i+1)
		}
	}
	if entries[0].Time != "2026-07-13T12:00:00Z" {
		t.Fatalf("time = %q", entries[0].Time)
	}
}

func TestVerifyAcceptsIntactChainAndEmptyLog(t *testing.T) {
	_, entries := writeChain(t, 5)
	if err := Verify(entries); err != nil {
		t.Fatal(err)
	}
	if err := Verify(nil); err != nil {
		t.Fatalf("an empty log must verify: %v", err)
	}
}

func TestVerifyDetectsRewrittenEntry(t *testing.T) {
	_, entries := writeChain(t, 4)
	entries[1].User = "mallory" // rewrite history
	err := Verify(entries)
	if err == nil || !strings.Contains(err.Error(), "entry 2") {
		t.Fatalf("err = %v, want a hash mismatch at entry 2", err)
	}
}

func TestVerifyDetectsDeletionAndReordering(t *testing.T) {
	_, entries := writeChain(t, 4)
	deleted := make([]Entry, 0, 3)
	deleted = append(deleted, entries[0])
	deleted = append(deleted, entries[2:]...)
	if err := Verify(deleted); err == nil {
		t.Fatal("expected an error for a deleted entry")
	}
	swapped := append([]Entry(nil), entries...)
	swapped[1], swapped[2] = swapped[2], swapped[1]
	if err := Verify(swapped); err == nil {
		t.Fatal("expected an error for reordered entries")
	}
}

func TestVerifyDetectsForgedTail(t *testing.T) {
	// An attacker who appends a self-consistent entry with the wrong
	// prev hash must still be caught.
	_, entries := writeChain(t, 2)
	forged := Entry{Seq: 3, Time: "2026-07-13T12:09:00Z", Action: ActionRevoke, Prev: Genesis}
	forged.Hash = forged.computeHash()
	if err := Verify(append(entries, forged)); err == nil {
		t.Fatal("expected an error for a mislinked tail entry")
	}
}

func TestEntriesOnMissingFileIsEmpty(t *testing.T) {
	l := Open(filepath.Join(t.TempDir(), "nope.log"))
	entries, err := l.Entries()
	if err != nil || entries != nil {
		t.Fatalf("got %v, %v; want nil, nil", entries, err)
	}
}

func TestEntriesRejectMalformedLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(path, []byte("{\"seq\":1}\nnot json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Open(path).Entries()
	if err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("err = %v, want a line-2 parse error", err)
	}
}

func TestOnDiskLinesAreCanonicalJSON(t *testing.T) {
	// The stored line must hash-verify when read back raw, i.e. the
	// serialization on disk IS the canonical form.
	l, _ := writeChain(t, 1)
	raw, err := os.ReadFile(l.Path)
	if err != nil {
		t.Fatal(err)
	}
	var e Entry
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(raw))), &e); err != nil {
		t.Fatal(err)
	}
	if e.computeHash() != e.Hash {
		t.Fatal("disk representation does not match its own hash")
	}
}

func TestVerifyDetectsSeqGap(t *testing.T) {
	_, entries := writeChain(t, 3)
	entries[2].Seq = 7
	err := Verify(entries)
	if err == nil || !strings.Contains(err.Error(), "seq 7") {
		t.Fatalf("err = %v, want a seq mismatch", err)
	}
}
