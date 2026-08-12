package canonical

import (
	"bytes"
	"errors"
	"testing"
)

// The canonicalization function must produce identical bytes for semantically
// equivalent inputs regardless of map key insertion order, integer encoding
// width, or serialization path (¶0018, ¶0085). These properties are what let an
// independent verifier recompute a digest from reproduced inputs.

func TestMapKeyOrderIndependence(t *testing.T) {
	// Two maps with the same entries inserted in different orders must canonicalize
	// to identical bytes (Core Deterministic Encoding sorts keys).
	a := map[string]int{"zebra": 1, "alpha": 2, "mike": 3}
	b := map[string]int{"mike": 3, "zebra": 1, "alpha": 2}
	ab, err := Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	bb, err := Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ab, bb) {
		t.Fatalf("map key order changed canonical bytes:\n a=%x\n b=%x", ab, bb)
	}
}

func TestNestedStructFieldOrderIndependence(t *testing.T) {
	// Struct field declaration order must not affect the canonical bytes: the two
	// structs below carry the same logical fields in different declared order.
	type ab struct {
		A int `cbor:"a"`
		B int `cbor:"b"`
	}
	type ba struct {
		B int `cbor:"b"`
		A int `cbor:"a"`
	}
	x, err := Marshal(ab{A: 1, B: 2})
	if err != nil {
		t.Fatal(err)
	}
	y, err := Marshal(ba{B: 2, A: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(x, y) {
		t.Fatalf("struct field order changed canonical bytes:\n x=%x\n y=%x", x, y)
	}
}

func TestDigestIsStable(t *testing.T) {
	// The same value digests identically across repeated computation.
	v := map[string]any{"k": []int{1, 2, 3}, "n": 42}
	first, err := Digest(v)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1000; i++ {
		d, err := Digest(v)
		if err != nil {
			t.Fatal(err)
		}
		if d != first {
			t.Fatalf("digest not stable at iteration %d", i)
		}
	}
}

func TestUnmarshalRejectsNonCanonical(t *testing.T) {
	// An indefinite-length CBOR array (0x9f ... 0xff) is non-canonical and must be
	// rejected by the strict decoder.
	indefArray := []byte{0x9f, 0x01, 0x02, 0xff}
	var out []int
	if err := Unmarshal(indefArray, &out); err == nil {
		t.Fatal("expected rejection of indefinite-length array, got nil error")
	}
}

// Every option configured on decMode is a rule an attacker would like removed,
// so each one gets a case that fails if it is dropped. A dependency upgrade that
// silently changed a default would otherwise leave the whole suite green.
func TestUnmarshalRejectsDuplicateMapKey(t *testing.T) {
	// {"a": 1, "a": 2} — two entries under one key. Accepting this would let two
	// encodings carry different values while presenting the same decoded object,
	// and leave which value wins up to the decoder.
	dup := []byte{0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02}
	var out map[string]int
	if err := Unmarshal(dup, &out); err == nil {
		t.Fatalf("expected rejection of a duplicate map key, decoded %v", out)
	}
}

func TestUnmarshalRejectsInvalidUTF8(t *testing.T) {
	// A text string whose single byte (0xff) is not valid UTF-8. Accepting it
	// would admit two byte strings that compare equal after lossy decoding.
	bad := []byte{0xa1, 0x61, 0xff, 0x01}
	var out map[string]int
	if err := Unmarshal(bad, &out); err == nil {
		t.Fatalf("expected rejection of invalid UTF-8 in a text key, decoded %v", out)
	}
}

func TestUnmarshalRejectsIndefiniteLengthOfEveryKind(t *testing.T) {
	// The existing coverage is the indefinite-length array. The forbidden-ness is
	// a property of the encoding form, not of one CBOR major type.
	for _, tc := range []struct {
		name string
		in   []byte
		out  any
	}{
		{"map", []byte{0xbf, 0x61, 0x61, 0x01, 0xff}, new(map[string]int)},
		{"byte string", []byte{0x5f, 0x41, 0x01, 0xff}, new([]byte)},
		{"text string", []byte{0x7f, 0x61, 0x61, 0xff}, new(string)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := Unmarshal(tc.in, tc.out); err == nil {
				t.Fatalf("expected rejection of an indefinite-length %s", tc.name)
			}
		})
	}
}

// Canonical encoding is only useful if it is a fixed point: bytes that survive
// the strict decoder must re-encode to themselves. If decode-then-encode could
// move the bytes, two distinct encodings of one value could both be accepted
// and an independent verifier could not reproduce a digest from a decoded form.
func TestCanonicalBytesAreAFixedPoint(t *testing.T) {
	original, err := Marshal(map[string]any{
		"zebra": 1, "alpha": []int{3, 2, 1}, "mike": "x",
	})
	if err != nil {
		t.Fatal(err)
	}
	var round map[string]any
	if err := Unmarshal(original, &round); err != nil {
		t.Fatal(err)
	}
	again, err := Marshal(round)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, again) {
		t.Fatalf("canonical bytes are not a fixed point:\n in=%x\nout=%x", original, again)
	}
}

func TestUnmarshalRejectsUnknownField(t *testing.T) {
	type known struct {
		A int `cbor:"a"`
	}
	// Encode a map with an extra field the target struct does not declare.
	extra, err := Marshal(map[string]int{"a": 1, "b": 2})
	if err != nil {
		t.Fatal(err)
	}
	var k known
	if err := Unmarshal(extra, &k); err == nil {
		t.Fatal("expected rejection of unknown field, got nil error")
	}
}

// A digest is an identity only if one value has exactly one encoding. The
// decoder options reject encodings that change meaning; these are encodings
// that change only bytes, and they decode to a perfectly good value — which is
// what makes them dangerous rather than harmless.
func TestUnmarshalRejectsNonCanonicalOrderingAndWidth(t *testing.T) {
	type pair struct {
		A int `cbor:"a"`
		B int `cbor:"b"`
	}
	cases := []struct {
		name string
		in   []byte
	}{
		{
			// Map keys out of canonical order: "b" before "a". RFC 8949 §4.2
			// sorts by the bytewise order of the encoded key.
			name: "map keys out of order",
			in:   []byte{0xA2, 0x61, 'b', 0x01, 0x61, 'a', 0x02},
		},
		{
			// Integer 1 at non-minimal width (0x18 0x01 rather than 0x01).
			name: "non-minimal integer width",
			in:   []byte{0xA2, 0x61, 'a', 0x18, 0x01, 0x61, 'b', 0x02},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var p pair
			err := Unmarshal(tc.in, &p)
			if err == nil {
				t.Fatalf("accepted a non-canonical encoding decoding to %+v", p)
			}
			if !errors.Is(err, ErrNonCanonical) {
				t.Fatalf("rejected, but not as non-canonical: %v", err)
			}
		})
	}

	// The control: the canonical encoding of the same value is accepted.
	canon, err := Marshal(pair{A: 1, B: 2})
	if err != nil {
		t.Fatal(err)
	}
	var p pair
	if err := Unmarshal(canon, &p); err != nil {
		t.Fatalf("canonical encoding rejected: %v", err)
	}
	if p.A != 1 || p.B != 2 {
		t.Fatalf("round trip changed the value: %+v", p)
	}
}
