// Package canonical implements the protocol's canonicalization function
// (¶0018, ¶0085): a transform of any protocol value into a canonical byte
// representation such that semantically equivalent inputs — regardless of map
// field ordering, integer/float encoding width, or serialization format —
// produce identical bytes, and therefore identical cryptographic digests.
//
// This is the single canonicalization function used everywhere the protocol
// computes a digest or signs a payload. Independence of the digest from field
// ordering and encoding is the property that lets an independent verifier
// recompute a digest from reproduced inputs without any access to enforcement
// point state (¶0017).
//
// The canonical form is CBOR under RFC 8949 §4.2 Core Deterministic Encoding:
// integers encoded at minimal width, map keys sorted by bytewise lexicographic
// order of their encoded form, no indefinite-length items, and shortest-form
// floats. Digests are SHA-256 (¶0018 reference algorithm; agility via the
// registered algorithm table in xap-spec/constants).
package canonical

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// ErrNonCanonical reports that input decoded successfully but was not in the
// canonical form ¶0085 requires.
//
// The decoder options below reject the encodings that change *meaning* —
// duplicate keys, unknown fields, bad UTF-8. They do not reject encodings that
// merely change *bytes*: map keys out of canonical order and integers at
// non-minimal width both round-trip silently. That gap matters because the
// protocol identifies artifacts by digests over these bytes. A digest is only
// an identity if one value has one encoding, so decoding has to reject a second
// encoding of the same value rather than accept it and canonicalize it away.
var ErrNonCanonical = errors.New("canonical: input is not in canonical form")

// encMode is the frozen Core Deterministic Encoding mode. Constructed once; a
// cbor.EncMode is safe for concurrent use.
var encMode cbor.EncMode

// decMode decodes canonical CBOR. It rejects duplicate map keys and
// indefinite-length items so that a non-canonical encoding cannot round-trip
// silently.
var decMode cbor.DecMode

func init() {
	em, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(fmt.Sprintf("canonical: building deterministic encoder: %v", err))
	}
	encMode = em

	dm, err := cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		UTF8:              cbor.UTF8RejectInvalid,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
	}.DecMode()
	if err != nil {
		panic(fmt.Sprintf("canonical: building decoder: %v", err))
	}
	decMode = dm
}

// Marshal encodes v into its canonical CBOR representation (¶0085). Two
// semantically equivalent values always produce byte-identical output.
func Marshal(v any) ([]byte, error) {
	return encMode.Marshal(v)
}

// Unmarshal decodes canonical CBOR bytes into v. Unknown fields, duplicate
// keys, indefinite lengths and invalid UTF-8 are rejected by the decoder; input
// that decodes but is not in canonical form is rejected by re-encoding the
// result and requiring byte equality (ErrNonCanonical).
//
// The round trip is the only check that covers key ordering and integer width,
// and it is exact rather than approximate: canonical encoding is a function, so
// the canonical encoding of a decoded value either is the input or the input
// was not canonical.
func Unmarshal(data []byte, v any) error {
	if err := decMode.Unmarshal(data, v); err != nil {
		return err
	}
	round, err := encMode.Marshal(v)
	if err != nil {
		return fmt.Errorf("canonical: re-encoding decoded value: %w", err)
	}
	if !bytes.Equal(data, round) {
		return fmt.Errorf("%w: %d bytes in, %d bytes re-encoded", ErrNonCanonical, len(data), len(round))
	}
	return nil
}

// Digest returns the SHA-256 digest of the canonical CBOR encoding of v
// (¶0018). This is the digest recomputed by an independent verifier from
// reproduced inputs.
func Digest(v any) ([32]byte, error) {
	b, err := Marshal(v)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// DigestBytes is Digest returning a slice, for embedding directly in a receipt
// field.
func DigestBytes(v any) ([]byte, error) {
	d, err := Digest(v)
	if err != nil {
		return nil, err
	}
	return d[:], nil
}
