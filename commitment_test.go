package xap

import (
	"testing"
	"time"

	"github.com/Vidimuslabs/xap-go/canonical"
)

func govMAT() MAT {
	return MAT{
		Version: ProtocolVersion, ID: "gov",
		Scope:    ExecutionScope{Actions: []string{"deploy", "read"}, Resources: []string{"svc/*"}},
		Boundary: PermissionBoundary{MaxImpact: 100},
		Constraints: []Constraint{
			{ID: "c-zone", Type: "network_zone", Zones: []string{"prod"}},
			{ID: "c-rate", Type: "rate_limit", MaxRate: ptrI64(100)},
		},
		Replay: ReplayProtection{NotBefore: "2026-06-30T00:00:00Z", NotAfter: "2026-07-08T00:00:00Z"},
		Issuer: IssuerIdentity{ID: "issuer"},
	}
}

func govCommitment(m *MAT) CommitmentObject {
	cd, _ := m.ConstraintDigest()
	return CommitmentObject{
		Version: ProtocolVersion, ID: "commit",
		AgentIdentity:    MachineIdentity{Kind: "public_key", PublicKey: []byte{1, 2, 3}},
		SessionID:        "sess-1",
		DeclaredActions:  DeclaredActionSet{ActionTypes: []string{"read"}, Resources: []string{"svc/*"}},
		TemporalValidity: TemporalValidity{NotBefore: "2026-06-30T00:00:00Z", NotAfter: "2026-07-08T00:00:00Z"},
		Binding:          CommitmentBinding{ArtifactID: "gov", ConstraintDigest: cd},
	}
}

// Commitment Binding Verification (¶0084A): the constraint digest in the
// commitment must equal a fresh digest of the governing MAT's constraint set.
func TestCommitmentBindingAccepted(t *testing.T) {
	m := govMAT()
	c := govCommitment(&m)
	if err := c.VerifyBinding(&m); err != nil {
		t.Fatalf("valid binding rejected: %v", err)
	}
}

func TestCommitmentBindingWrongArtifact(t *testing.T) {
	m := govMAT()
	c := govCommitment(&m)
	c.Binding.ArtifactID = "other"
	if err := c.VerifyBinding(&m); err == nil {
		t.Fatal("binding to wrong artifact id was accepted")
	}
}

func TestCommitmentBindingConstraintDigestMismatch(t *testing.T) {
	// Constraint digest computed from a different constraint set must be rejected.
	m := govMAT()
	c := govCommitment(&m)
	other := []Constraint{{ID: "x", Type: "temporal"}}
	c.Binding.ConstraintDigest, _ = canonical.DigestBytes(other)
	if err := c.VerifyBinding(&m); err == nil {
		t.Fatal("constraint-digest mismatch was accepted (binding attack not caught)")
	}
}

func TestCommitmentTemporalValidity(t *testing.T) {
	m := govMAT()
	c := govCommitment(&m)
	within, _ := time.Parse(time.RFC3339, "2026-07-01T00:00:00Z")
	if err := c.ValidateTemporal(within); err != nil {
		t.Fatalf("in-window commitment rejected: %v", err)
	}
	outside, _ := time.Parse(time.RFC3339, "2026-08-01T00:00:00Z")
	if err := c.ValidateTemporal(outside); err == nil {
		t.Fatal("out-of-window commitment accepted")
	}
}

// Multi-agent provenance reconstruction (¶0084A): a chain reconstructs from
// receipts alone, and a broken link fails.
func TestProvenanceReconstructAndBreak(t *testing.T) {
	rootDigest := []byte{0xAA, 0x01}
	childDigest := []byte{0xBB, 0x02}

	root := &Receipt{ID: "r-root", ArtifactID: "mat-a", CommitmentDigest: rootDigest}
	child := &Receipt{
		ID: "r-child", ArtifactID: "mat-b", CommitmentDigest: childDigest,
		Provenance: &ProvenanceRef{ParentArtifactID: "mat-a", ParentCommitmentDigest: rootDigest},
	}

	chain, err := ReconstructProvenance([]*Receipt{child, root}) // order-independent
	if err != nil {
		t.Fatalf("reconstruct failed: %v", err)
	}
	if len(chain) != 2 || chain[0].ReceiptID != "r-root" || chain[1].ReceiptID != "r-child" {
		t.Fatalf("unexpected chain: %+v", chain)
	}

	// Break the link: child points at a parent commitment that is not present.
	broken := &Receipt{
		ID: "r-child", ArtifactID: "mat-b", CommitmentDigest: childDigest,
		Provenance: &ProvenanceRef{ParentArtifactID: "mat-a", ParentCommitmentDigest: []byte{0xFF, 0xFF}},
	}
	if _, err := ReconstructProvenance([]*Receipt{broken, root}); err == nil {
		t.Fatal("broken provenance link was reconstructed")
	}
}
