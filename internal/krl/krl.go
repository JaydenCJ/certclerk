// Package krl writes (and, for round-trip tests and inspection, reads)
// OpenSSH Key Revocation Lists in the binary format sshd consumes via
// the RevokedKeys directive (PROTOCOL.krl, format version 1). certclerk
// emits one CERTIFICATES section scoped to the CA key, revoking by
// serial and by key ID.
package krl

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/JaydenCJ/certclerk/internal/wire"
)

// magic is the file preamble "SSHKRL\n\0" read as a big-endian uint64.
const magic = 0x5353484b524c0a00

// formatVersion is the only KRL format OpenSSH has ever shipped.
const formatVersion = 1

// Section and certificate-subsection tags from PROTOCOL.krl.
const (
	sectionCertificates    = 1
	certSectionSerialList  = 0x20
	certSectionSerialRange = 0x21
	certSectionKeyID       = 0x23
)

// KRL is the revocation state to serialize.
type KRL struct {
	Version     uint64    // monotonically increasing; certclerk uses the revocation count
	GeneratedAt time.Time // stamped into the header
	Comment     string
	CAKey       []byte   // CA public key blob; scopes the certificate section
	Serials     []uint64 // revoked certificate serials
	KeyIDs      []string // revoked certificate key IDs
}

// Marshal renders the binary KRL. Output is deterministic for a given
// KRL value: serials are sorted and deduplicated, key IDs are sorted,
// and each subsection is emitted in ascending order. (Serial-range
// compression is roadmapped; Parse already accepts ranges.)
func (k *KRL) Marshal() []byte {
	var w wire.Buffer
	w.Uint64(magic)
	w.Uint32(formatVersion)
	w.Uint64(k.Version)
	w.Uint64(uint64(k.GeneratedAt.Unix()))
	w.Uint64(0)  // flags: reserved, always zero
	w.String("") // reserved
	w.String(k.Comment)

	var body wire.Buffer
	body.Bytes32(k.CAKey)
	body.String("") // reserved
	serials := dedupSorted(k.Serials)
	if len(serials) > 0 {
		var list wire.Buffer
		for _, s := range serials {
			list.Uint64(s)
		}
		body.Byte(certSectionSerialList)
		body.Bytes32(list.Bytes())
	}
	if len(k.KeyIDs) > 0 {
		ids := append([]string(nil), k.KeyIDs...)
		sort.Strings(ids)
		var list wire.Buffer
		for _, id := range ids {
			list.String(id)
		}
		body.Byte(certSectionKeyID)
		body.Bytes32(list.Bytes())
	}

	w.Byte(sectionCertificates)
	w.Bytes32(body.Bytes())
	return w.Bytes()
}

func dedupSorted(in []uint64) []uint64 {
	out := append([]uint64(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	n := 0
	for i, v := range out {
		if i == 0 || v != out[n-1] {
			out[n] = v
			n++
		}
	}
	return out[:n]
}

// Parse decodes a binary KRL produced by Marshal or by ssh-keygen -k.
// It understands the header and the certificate section's serial-list,
// serial-range, and key-ID subsections — enough to verify round-trips
// and inspect foreign KRLs.
func Parse(b []byte) (*KRL, error) {
	r := wire.NewReader(b)
	m, err := r.Uint64()
	if err != nil || m != magic {
		return nil, errors.New("krl: missing SSHKRL magic")
	}
	fv, err := r.Uint32()
	if err != nil || fv != formatVersion {
		return nil, fmt.Errorf("krl: unsupported format version")
	}
	k := &KRL{}
	if k.Version, err = r.Uint64(); err != nil {
		return nil, fmt.Errorf("krl: version: %v", err)
	}
	gen, err := r.Uint64()
	if err != nil {
		return nil, fmt.Errorf("krl: generated date: %v", err)
	}
	k.GeneratedAt = time.Unix(int64(gen), 0).UTC()
	if _, err = r.Uint64(); err != nil { // flags
		return nil, fmt.Errorf("krl: flags: %v", err)
	}
	if _, err = r.Bytes32(); err != nil { // reserved
		return nil, fmt.Errorf("krl: reserved: %v", err)
	}
	if k.Comment, err = r.String(); err != nil {
		return nil, fmt.Errorf("krl: comment: %v", err)
	}
	for !r.Empty() {
		tag, err := r.Byte()
		if err != nil {
			return nil, err
		}
		data, err := r.Bytes32()
		if err != nil {
			return nil, fmt.Errorf("krl: section 0x%02x: %v", tag, err)
		}
		if tag != sectionCertificates {
			continue // unknown top-level sections are skippable by design
		}
		if err := parseCertSection(data, k); err != nil {
			return nil, err
		}
	}
	return k, nil
}

func parseCertSection(data []byte, k *KRL) error {
	r := wire.NewReader(data)
	caKey, err := r.Bytes32()
	if err != nil {
		return fmt.Errorf("krl: certificates: ca key: %v", err)
	}
	k.CAKey = append([]byte(nil), caKey...)
	if _, err := r.Bytes32(); err != nil { // reserved
		return fmt.Errorf("krl: certificates: reserved: %v", err)
	}
	for !r.Empty() {
		tag, err := r.Byte()
		if err != nil {
			return err
		}
		sub, err := r.Bytes32()
		if err != nil {
			return fmt.Errorf("krl: cert subsection 0x%02x: %v", tag, err)
		}
		sr := wire.NewReader(sub)
		switch tag {
		case certSectionSerialList:
			for !sr.Empty() {
				s, err := sr.Uint64()
				if err != nil {
					return fmt.Errorf("krl: serial list: %v", err)
				}
				k.Serials = append(k.Serials, s)
			}
		case certSectionSerialRange:
			lo, err := sr.Uint64()
			if err != nil {
				return fmt.Errorf("krl: serial range: %v", err)
			}
			hi, err := sr.Uint64()
			if err != nil || hi < lo {
				return errors.New("krl: malformed serial range")
			}
			// Ranges are expanded for inspection; refuse absurd ones so a
			// hostile KRL cannot balloon memory.
			if hi-lo >= 1<<20 {
				return fmt.Errorf("krl: serial range %d-%d too large to expand", lo, hi)
			}
			for s := lo; s <= hi; s++ {
				k.Serials = append(k.Serials, s)
			}
		case certSectionKeyID:
			for !sr.Empty() {
				id, err := sr.String()
				if err != nil {
					return fmt.Errorf("krl: key id list: %v", err)
				}
				k.KeyIDs = append(k.KeyIDs, id)
			}
		default:
			return fmt.Errorf("krl: unsupported certificate subsection 0x%02x", tag)
		}
	}
	return nil
}
