package xap

import (
	"bytes"
	"fmt"
	"time"

	"github.com/Vidimuslabs/xap-go/canonical"
)

// CommitmentObject is the machine-readable structure an autonomous agent
// generates before an execution session, declaring the bounded set of actions
// it will propose and binding itself to a governing authority artifact
// (¶0095B, ¶0060 as replaced). The agent signature is carried by the
// COSE_Sign1 envelope, not this payload.
type CommitmentObject struct {
	Version string `cbor:"v"`
	// ID is the commitment object identifier.
	ID string `cbor:"id"`
	// AgentIdentity cryptographically binds the object to the generating agent.
	AgentIdentity MachineIdentity `cbor:"agent_identity"`
	// SessionID provides replay protection within a single session.
	SessionID string `cbor:"session_id"`
	// DeclaredActions is the bounded enumeration of action types, resource
	// targets, and parameter ranges the agent declares it will propose.
	DeclaredActions DeclaredActionSet `cbor:"declared_actions"`
	// TemporalValidity bounds when the object may be presented.
	TemporalValidity TemporalValidity `cbor:"temporal_validity"`
	// Binding names the governing artifact and carries the constraint digest
	// computed over that artifact's constraint set (¶0084A binding subfield).
	Binding CommitmentBinding `cbor:"binding"`

	// Optional fields (¶0095B).
	ResourceTargets []string              `cbor:"resource_targets,omitempty"`
	Provenance      *CommitmentProvenance `cbor:"provenance,omitempty"`
	ActionWindow    *TemporalValidity     `cbor:"action_window,omitempty"`
}

// DeclaredActionSet is the bounded action enumeration the agent commits to
// (¶0095B). Membership is evaluated with consistent, reproducible outcomes.
type DeclaredActionSet struct {
	ActionTypes []string     `cbor:"action_types"`
	Resources   []string     `cbor:"resources,omitempty"`
	ParamRanges []Constraint `cbor:"param_ranges,omitempty"`
}

// TemporalValidity is a validity interval (RFC3339 UTC).
type TemporalValidity struct {
	NotBefore string `cbor:"not_before"`
	NotAfter  string `cbor:"not_after"`
}

// CommitmentBinding binds a commitment object to exactly one governing artifact
// (¶0084A). ConstraintDigest must equal the governing MAT's ConstraintDigest.
type CommitmentBinding struct {
	ArtifactID       string `cbor:"artifact_id"`
	ConstraintDigest []byte `cbor:"constraint_digest"`
}

// CommitmentProvenance references a parent commitment in a multi-agent
// derivation chain (¶0084A Commitment Provenance Field).
type CommitmentProvenance struct {
	ParentArtifactID       string `cbor:"parent_artifact_id"`
	ParentCommitmentDigest []byte `cbor:"parent_commitment_digest"`
}

// SignedCommitment is a CommitmentObject conveyed inside a COSE_Sign1 envelope.
type SignedCommitment struct {
	Envelope   []byte
	Commitment CommitmentObject
}

// Digest returns the commitment digest — a hash over the canonical commitment
// object (¶0084A Commitment Digest Field). It is the value recorded in a
// receipt's commitment_digest field and referenced by a child's provenance.
func (c *CommitmentObject) Digest() ([]byte, error) {
	return canonical.DigestBytes(c)
}

// Marshal returns the canonical CBOR payload of the commitment object.
func (c *CommitmentObject) Marshal() ([]byte, error) {
	return canonical.Marshal(c)
}

// UnmarshalCommitment decodes a canonical CBOR payload into a CommitmentObject.
func UnmarshalCommitment(payload []byte) (*CommitmentObject, error) {
	var c CommitmentObject
	if err := canonical.Unmarshal(payload, &c); err != nil {
		return nil, fmt.Errorf("decode commitment payload: %w", err)
	}
	return &c, nil
}

// VerifyBinding performs the Commitment Binding Verification (¶0084A): it
// confirms the commitment's binding names the governing MAT and that its
// constraint digest matches a fresh digest of the governing MAT's constraint
// set. A mismatch means the commitment's declared constraint scope was computed
// from a different constraint set than the one the MAT encodes, and the
// commitment must be rejected.
func (c *CommitmentObject) VerifyBinding(gov *MAT) error {
	if c.Binding.ArtifactID != gov.ID {
		return fmt.Errorf("commitment binding artifact_id %q does not name governing MAT %q",
			c.Binding.ArtifactID, gov.ID)
	}
	want, err := gov.ConstraintDigest()
	if err != nil {
		return fmt.Errorf("compute governing constraint digest: %w", err)
	}
	if !bytes.Equal(c.Binding.ConstraintDigest, want) {
		return fmt.Errorf("commitment binding constraint digest mismatch: commitment computed from a different constraint set than governing MAT %q", gov.ID)
	}
	return nil
}

// ValidateTemporal reports whether the commitment object is within its temporal
// validity at the given instant.
func (c *CommitmentObject) ValidateTemporal(at time.Time) error {
	nb, err := time.Parse(time.RFC3339, c.TemporalValidity.NotBefore)
	if err != nil {
		return fmt.Errorf("commitment not_before: %w", err)
	}
	na, err := time.Parse(time.RFC3339, c.TemporalValidity.NotAfter)
	if err != nil {
		return fmt.Errorf("commitment not_after: %w", err)
	}
	if at.Before(nb) || at.After(na) {
		return fmt.Errorf("commitment %s outside temporal validity at %s", c.ID, at.UTC().Format(time.RFC3339))
	}
	return nil
}
