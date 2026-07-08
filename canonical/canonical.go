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
	"crypto/sha256"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

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

// Unmarshal decodes canonical CBOR bytes into v. Non-canonical inputs (unknown
// fields, duplicate keys, indefinite lengths) are rejected.
func Unmarshal(data []byte, v any) error {
	return decMode.Unmarshal(data, v)
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
