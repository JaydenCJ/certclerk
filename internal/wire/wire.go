// Package wire implements the SSH wire encoding (RFC 4251 §5) shared by
// public-key blobs, certificates, and key revocation lists: big-endian
// fixed-width integers and length-prefixed strings. Everything else in
// certclerk is built on these two types, so encoding bugs surface here
// and nowhere else.
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrShort is returned when a read runs past the end of the buffer.
var ErrShort = errors.New("wire: unexpected end of data")

// Buffer accumulates wire-encoded fields. The zero value is ready to use.
type Buffer struct {
	b []byte
}

// Bytes returns the encoded contents. The slice aliases the buffer.
func (w *Buffer) Bytes() []byte { return w.b }

// Len returns the number of encoded bytes so far.
func (w *Buffer) Len() int { return len(w.b) }

// Byte appends a single raw byte (used by KRL section tags).
func (w *Buffer) Byte(v byte) { w.b = append(w.b, v) }

// Uint32 appends a big-endian uint32.
func (w *Buffer) Uint32(v uint32) {
	w.b = binary.BigEndian.AppendUint32(w.b, v)
}

// Uint64 appends a big-endian uint64.
func (w *Buffer) Uint64(v uint64) {
	w.b = binary.BigEndian.AppendUint64(w.b, v)
}

// Bytes32 appends a length-prefixed string field from raw bytes.
func (w *Buffer) Bytes32(v []byte) {
	w.Uint32(uint32(len(v)))
	w.b = append(w.b, v...)
}

// String appends a length-prefixed string field.
func (w *Buffer) String(s string) { w.Bytes32([]byte(s)) }

// Raw appends bytes verbatim, without a length prefix. Certificates use
// this to splice the algorithm-specific public-key fields into the body.
func (w *Buffer) Raw(v []byte) { w.b = append(w.b, v...) }

// Reader consumes wire-encoded fields from a byte slice.
type Reader struct {
	b []byte
}

// NewReader wraps b for reading. The reader does not copy b.
func NewReader(b []byte) *Reader { return &Reader{b: b} }

// Empty reports whether all bytes have been consumed.
func (r *Reader) Empty() bool { return len(r.b) == 0 }

// Rest returns the unconsumed remainder and drains the reader.
func (r *Reader) Rest() []byte {
	rest := r.b
	r.b = nil
	return rest
}

// Byte reads a single raw byte.
func (r *Reader) Byte() (byte, error) {
	if len(r.b) < 1 {
		return 0, ErrShort
	}
	v := r.b[0]
	r.b = r.b[1:]
	return v, nil
}

// Uint32 reads a big-endian uint32.
func (r *Reader) Uint32() (uint32, error) {
	if len(r.b) < 4 {
		return 0, ErrShort
	}
	v := binary.BigEndian.Uint32(r.b)
	r.b = r.b[4:]
	return v, nil
}

// Uint64 reads a big-endian uint64.
func (r *Reader) Uint64() (uint64, error) {
	if len(r.b) < 8 {
		return 0, ErrShort
	}
	v := binary.BigEndian.Uint64(r.b)
	r.b = r.b[8:]
	return v, nil
}

// Bytes32 reads a length-prefixed string field as raw bytes. The result
// aliases the reader's underlying slice.
func (r *Reader) Bytes32() ([]byte, error) {
	n, err := r.Uint32()
	if err != nil {
		return nil, err
	}
	if uint64(n) > uint64(len(r.b)) {
		return nil, fmt.Errorf("wire: string length %d exceeds remaining %d bytes", n, len(r.b))
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v, nil
}

// String reads a length-prefixed string field as a Go string.
func (r *Reader) String() (string, error) {
	v, err := r.Bytes32()
	return string(v), err
}

// StringList unpacks a wire blob that contains zero or more concatenated
// string fields (the encoding of a certificate's principal list).
func StringList(b []byte) ([]string, error) {
	r := NewReader(b)
	var out []string
	for !r.Empty() {
		s, err := r.String()
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// PackStringList encodes strings as concatenated string fields.
func PackStringList(items []string) []byte {
	var w Buffer
	for _, s := range items {
		w.String(s)
	}
	return w.Bytes()
}
