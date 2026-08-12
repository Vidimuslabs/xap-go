package xap

import (
	"fmt"
	"time"

	"github.com/Vidimuslabs/xap-go/canonical"
)

// MAT is a Machine Authority Token — the cryptographically signed data
// structure encoding a complete execution authority grant (FIG. 2, ¶0041). The
// nine semantic fields are the MAT structure; the issuer signature itself is
// carried by the COSE_Sign1 envelope (see SignedMAT), not this payload struct,
// so the payload canonicalizes independently of the signature (¶0041 field
// 136, "signatures over canonical serialization").
type MAT struct {
	// Version is the protocol version embedded in every MAT (¶0081).
	Version string `cbor:"v"`
	// ID is the artifact instance identifier (field 138 instance ID / ¶0084
	// Authority Identifier Field).
	ID string `cbor:"id"`
	// ParentID references the parent artifact for a derived MAT; empty for a
	// root MAT (monotonic delegation, ¶0057).
	ParentID string `cbor:"parent_id,omitempty"`

	MachineIdentity  MachineIdentity    `cbor:"machine_identity"`  // field 122
	Scope            ExecutionScope     `cbor:"scope"`             // field 124
	Boundary         PermissionBoundary `cbor:"boundary"`          // field 126
	TrustVector      TrustVector        `cbor:"trust_vector"`      // field 128
	ProofObligations []ProofObligation  `cbor:"proof_obligations"` // field 130
	Constraints      []Constraint       `cbor:"constraints"`       // field 132
	Delegation       DelegationRights   `cbor:"delegation"`        // field 134
	Issuer           IssuerIdentity     `cbor:"issuer"`            // field 136
	Replay           ReplayProtection   `cbor:"replay"`            // field 138
}

// SignedMAT is a MAT conveyed inside a COSE_Sign1 envelope. The envelope bytes
// are the wire artifact; the enclosed payload is the canonical CBOR of the MAT.
type SignedMAT struct {
	// Envelope is the COSE_Sign1 CBOR.
	Envelope []byte
	// MAT is the decoded payload (populated after ParseMAT).
	MAT MAT
	// SigningKID is the key id of the anchor that actually verified the
	// envelope. Kept because "which key signed this" is a different question
	// from "which key does the body claim signed this", and only the first is
	// evidence.
	SigningKID []byte
}

// ConstraintDigest returns the canonical digest over the MAT's constraint set
// (¶0084A). A commitment object's commitment-binding subfield must carry this
// exact digest; the mismatch check is the Commitment Binding Verification Field
// (¶0084A) that prevents binding a commitment computed from a different
// constraint set than the one the governing MAT encodes.
func (m *MAT) ConstraintDigest() ([]byte, error) {
	return canonical.DigestBytes(m.Constraints)
}

// Marshal returns the canonical CBOR payload of the MAT (¶0085). This is the
// exact byte sequence a signer signs and a verifier's digest is computed over.
func (m *MAT) Marshal() ([]byte, error) {
	return canonical.Marshal(m)
}

// UnmarshalMAT decodes a canonical CBOR payload into a MAT.
func UnmarshalMAT(payload []byte) (*MAT, error) {
	var m MAT
	if err := canonical.Unmarshal(payload, &m); err != nil {
		return nil, fmt.Errorf("decode MAT payload: %w", err)
	}
	return &m, nil
}

// ValidateStructure checks that a MAT is structurally well formed and carries a
// recognized protocol version. It does not check signatures (see ParseMAT) or
// lifecycle timing (see ValidateAt).
func (m *MAT) ValidateStructure() error {
	if m.Version != ProtocolVersion {
		return fmt.Errorf("unsupported protocol version %q (want %q)", m.Version, ProtocolVersion)
	}
	if m.ID == "" {
		return fmt.Errorf("MAT missing id")
	}
	if m.Issuer.ID == "" {
		return fmt.Errorf("MAT missing issuer id")
	}
	if m.Replay.NotBefore == "" || m.Replay.NotAfter == "" {
		return fmt.Errorf("MAT missing validity interval")
	}
	if _, err := time.Parse(time.RFC3339, m.Replay.NotBefore); err != nil {
		return fmt.Errorf("MAT not_before: %w", err)
	}
	if _, err := time.Parse(time.RFC3339, m.Replay.NotAfter); err != nil {
		return fmt.Errorf("MAT not_after: %w", err)
	}
	return nil
}

// Expired reports whether the MAT's validity interval does not include at.
// Expired artifacts are unconditionally rejected (¶0065). A parse error in the
// timestamps is treated as expired (fail closed).
func (m *MAT) Expired(at time.Time) bool {
	nb, err1 := time.Parse(time.RFC3339, m.Replay.NotBefore)
	na, err2 := time.Parse(time.RFC3339, m.Replay.NotAfter)
	if err1 != nil || err2 != nil {
		return true
	}
	return at.Before(nb) || at.After(na)
}

// ValidateAt checks structure and that the MAT is within its validity window at
// the given instant. It is the lifecycle gate applied before any execution
// evaluation (¶0065). Revocation state is external (a revocation set) and
// checked by the engine, not by the SDK.
func (m *MAT) ValidateAt(at time.Time) error {
	if err := m.ValidateStructure(); err != nil {
		return err
	}
	if m.Expired(at) {
		return fmt.Errorf("MAT %s outside validity interval at %s", m.ID, at.UTC().Format(time.RFC3339))
	}
	return nil
}

// CoversOperation reports whether the operation named by action and resource
// falls within this MAT's execution scope and is not forbidden by a permission
// boundary exclusion (¶0046, enforcement pipeline step 2).
//
// This is deliberately the *single* definition of the scope predicate. The
// enforcement point applies it when deciding, and an independent verifier
// re-applies it to the action and resource recorded in a receipt. Two
// implementations that agreed only by coincidence would verify nothing, so both
// sides call this.
//
// The numeric ceilings — max impact, max privilege delta, resource quotas — are
// not evaluated here. They are checked against per-request magnitudes that a
// receipt does not carry, so they remain attested by the enforcement point's
// signature rather than independently recomputable.
// coversResource applies the resource half of the scope predicate alone, for
// callers checking a resource pattern with no action in hand.
func (m *MAT) coversResource(resource string) error {
	if m.Scope.unconstrains(ScopeDimensionResources) {
		if hasTraversal(resource) {
			return fmt.Errorf("resource %q contains a traversal segment", resource)
		}
		return nil
	}
	if len(m.Scope.Resources) == 0 {
		return fmt.Errorf("scope permits no resources and does not declare resources unconstrained")
	}
	if !patternCovered(resource, m.Scope.Resources) {
		return fmt.Errorf("resource %q outside execution scope", resource)
	}
	if contains(m.Boundary.Exclusions, resource) {
		return fmt.Errorf("resource %q excluded by permission boundary", resource)
	}
	return nil
}

// ScopeReproducible reports whether a receipt disclosing this action and
// resource carries enough to re-evaluate every dimension the MAT constrains.
//
// It exists because "covered" and "checked" are different claims. CoversOperation
// skips the resource test when the receipt omits the resource, so a receipt that
// names an action and withholds its resource would otherwise return nil — and a
// verifier reporting that as a passing scope check would be asserting a gate it
// never applied. Selective disclosure (¶0071, ¶0079) makes such receipts
// legitimate; it does not make them checkable.
func (m *MAT) ScopeReproducible(action, resource string) bool {
	// Only an enumerated dimension needs the value: an unconstrained dimension
	// permits everything and an empty one permits nothing, and neither outcome
	// depends on what the receipt withheld. A non-empty list is the one case
	// where the answer cannot be reached without it.
	if len(m.Scope.Actions) > 0 && action == "" {
		return false
	}
	if len(m.Scope.Resources) > 0 && resource == "" {
		return false
	}
	return true
}

func (m *MAT) CoversOperation(action, resource string) error {
	// Absence denies. A dimension with no list permits nothing unless the scope
	// explicitly declares it unconstrained — see ExecutionScope.Unconstrained
	// for why the permissive reading cannot be the default.
	if !m.Scope.unconstrains(ScopeDimensionActions) {
		if len(m.Scope.Actions) == 0 {
			return fmt.Errorf("scope permits no actions and does not declare actions unconstrained")
		}
		if !contains(m.Scope.Actions, action) {
			return fmt.Errorf("action %q outside execution scope", action)
		}
	}
	if !m.Scope.unconstrains(ScopeDimensionResources) && resource != "" {
		if len(m.Scope.Resources) == 0 {
			return fmt.Errorf("scope permits no resources and does not declare resources unconstrained")
		}
		if !patternCovered(resource, m.Scope.Resources) {
			return fmt.Errorf("resource %q outside execution scope", resource)
		}
	}
	if resource != "" && hasTraversal(resource) {
		return fmt.Errorf("resource %q contains a traversal segment", resource)
	}
	if contains(m.Boundary.Exclusions, action) {
		return fmt.Errorf("action %q excluded by permission boundary", action)
	}
	if resource != "" && contains(m.Boundary.Exclusions, resource) {
		return fmt.Errorf("resource %q excluded by permission boundary", resource)
	}
	return nil
}
