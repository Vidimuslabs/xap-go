package canonical

import (
	"bytes"
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
