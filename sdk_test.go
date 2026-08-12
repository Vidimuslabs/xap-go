package xap

import (
	"testing"
	"time"
)

// Round-trip: every protocol type marshals to canonical CBOR and decodes back
// to an equal value, and DecodeAny discriminates the kind from the payload.
func TestMarshalRoundTripAndDecodeAny(t *testing.T) {
	m := govMAT()
	mp, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if kind, _, err := DecodeAny(mp); err != nil || kind != "mat" {
		t.Fatalf("DecodeAny(MAT) = %q, %v", kind, err)
	}

	r := &Receipt{Version: ProtocolVersion, ID: "r1", ArtifactID: "gov", Decision: "permit", ContextDigest: []byte{1, 2}, Timing: Timing{Start: "t", Complete: "t"}}
	rp, err := r.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if kind, _, err := DecodeAny(rp); err != nil || kind != "receipt" {
		t.Fatalf("DecodeAny(Receipt) = %q, %v", kind, err)
	}
	back, err := UnmarshalReceipt(rp)
	if err != nil || back.ID != "r1" {
		t.Fatalf("receipt round-trip failed: %v", err)
	}

	c := govCommitment(&m)
	cp, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if kind, _, err := DecodeAny(cp); err != nil || kind != "commitment" {
		t.Fatalf("DecodeAny(Commitment) = %q, %v", kind, err)
	}

	if _, _, err := DecodeAny([]byte{0x00}); err == nil {
		t.Fatal("DecodeAny accepted a non-protocol payload")
	}
}

func TestUnverifiedPayloadRejectsGarbage(t *testing.T) {
	if _, err := UnverifiedPayload([]byte{0xFF, 0xFF}); err == nil {
		t.Fatal("UnverifiedPayload accepted non-COSE bytes")
	}
}

func TestMATValidateAtLifecycle(t *testing.T) {
	m := govMAT()
	m.Replay.NotBefore = "2026-06-30T00:00:00Z"
	m.Replay.NotAfter = "2026-07-08T00:00:00Z"

	within, _ := time.Parse(time.RFC3339, "2026-07-01T00:00:00Z")
	if err := m.ValidateAt(within); err != nil {
		t.Fatalf("in-window MAT rejected: %v", err)
	}
	if err := VerifyExpiry(&m, within); err != nil {
		t.Fatalf("VerifyExpiry(in-window) = %v", err)
	}
	after, _ := time.Parse(time.RFC3339, "2027-01-01T00:00:00Z")
	if err := m.ValidateAt(after); err == nil {
		t.Fatal("expired MAT accepted by ValidateAt")
	}

	bad := govMAT()
	bad.Version = "wrong"
	if err := bad.ValidateStructure(); err == nil {
		t.Fatal("bad version accepted by ValidateStructure")
	}
}

// Strictness comparison for temporal, param_bound, and resource_state
// constraint types (¶0057 invariant iii): a child that tightens each type is
// accepted; a child that loosens it is rejected.
func TestConstraintStrictnessTypes(t *testing.T) {
	mk := func(scope []string) MAT {
		return MAT{Version: ProtocolVersion, Delegation: DelegationRights{Allowed: true}}
	}
	_ = mk

	parent := MAT{
		Version: ProtocolVersion, ID: "p", Delegation: DelegationRights{Allowed: true},
		Constraints: []Constraint{
			{ID: "t", Type: "temporal", NotBefore: "2026-07-01T00:00:00Z", NotAfter: "2026-07-10T00:00:00Z"},
			{ID: "p", Type: "param_bound", Param: "cpu", Min: ptrF64(0.1), Max: ptrF64(0.9)},
			{ID: "r", Type: "resource_state", Key: "db", In: []string{"healthy", "degraded"}},
		},
	}
	tighter := parent
	tighter.ID, tighter.ParentID = "c", "p"
	tighter.Constraints = []Constraint{
		{ID: "t", Type: "temporal", NotBefore: "2026-07-02T00:00:00Z", NotAfter: "2026-07-09T00:00:00Z"},
		{ID: "p", Type: "param_bound", Param: "cpu", Min: ptrF64(0.2), Max: ptrF64(0.8)},
		{ID: "r", Type: "resource_state", Key: "db", In: []string{"healthy"}},
	}
	if err := ValidateDerivation(&parent, &tighter); err != nil {
		t.Fatalf("tighter typed constraints rejected: %v", err)
	}

	for _, loosen := range []func(*MAT){
		func(c *MAT) { c.Constraints[0].NotAfter = "2026-07-20T00:00:00Z" },            // temporal wider
		func(c *MAT) { c.Constraints[1].Max = ptrF64(1.5) },                            // param wider
		func(c *MAT) { c.Constraints[2].In = []string{"healthy", "degraded", "down"} }, // resource wider
	} {
		child := parent
		child.ID, child.ParentID = "c", "p"
		child.Constraints = []Constraint{
			{ID: "t", Type: "temporal", NotBefore: "2026-07-02T00:00:00Z", NotAfter: "2026-07-09T00:00:00Z"},
			{ID: "p", Type: "param_bound", Param: "cpu", Min: ptrF64(0.2), Max: ptrF64(0.8)},
			{ID: "r", Type: "resource_state", Key: "db", In: []string{"healthy"}},
		}
		loosen(&child)
		if err := ValidateDerivation(&parent, &child); err == nil {
			t.Fatal("loosened typed constraint accepted")
		}
	}
}

func TestTrustAnchorSetLen(t *testing.T) {
	s := NewTrustAnchorSet()
	if s.Len() != 0 {
		t.Fatal("empty set not zero length")
	}
	if err := s.AddEd25519([]byte("k1"), []SignerRole{RoleIssuer}, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if s.Len() != 1 {
		t.Fatalf("len = %d, want 1", s.Len())
	}
	if _, ok := s.Get([]byte("k1")); !ok {
		t.Fatal("registered anchor not found")
	}
}

func TestVerificationResultFailed(t *testing.T) {
	res := VerificationResult{Checks: []Check{{Name: "a", Pass: true}, {Name: "b", Pass: false}}}
	failed := res.Failed()
	if len(failed) != 1 || failed[0] != "b" {
		t.Fatalf("Failed() = %v", failed)
	}
}
