// Package xap is the reference SDK for the Execution Authority Protocol (XAP).
// It provides the protocol data types (Machine Authority Token, verifiable
// execution receipt, commitment object, runtime context), the canonical digest
// computation, MAT parsing and validation, receipt parsing and verification,
// delegation-chain validation, and multi-agent commitment provenance
// reconstruction.
//
// Boundary: this package is verification-side. It can validate MATs and verify
// receipts using public keys and trust anchors, and it can recompute digests
// and constraint outcomes to confirm a proof structure. It deliberately holds
// no signing keys and no issuance or enforcement logic — those live in the
// private engine and server. Nothing here imports a private package.
//
// Spec authority: the specification of U.S. Patent No. US-12,726,364-B1, issued
// September 1, 2026 from application 19/570,167 (including the preliminary
// amendment filed in that application). Paragraph anchors (¶NNNN) in comments
// cite that specification for every protocol-semantic decision. The protocol
// layer is transcribed in xap-spec/docs/SPEC.md.
package xap

import (
	"fmt"

	"github.com/Vidimuslabs/xap-spec/constants"
)

// Re-export the protocol version so SDK callers need not import constants
// directly for the common case.
const ProtocolVersion = constants.ProtocolVersion

// MachineIdentity binds an artifact or commitment object to a specific machine
// or agent entity (MAT field 122, ¶0041; commitment agent identity, ¶0095B).
// The identity may be a raw public key, a certificate reference, a hardware
// attestation-bound identifier, or a composite of several anchors.
type MachineIdentity struct {
	// Kind names how this identity is established and therefore which field
	// below carries it: one of the values in constants.IdentityKind. It is not
	// decorative — a relying party reads it to learn whether a machine proved
	// itself with a bare key or with hardware attestation — so Validate requires
	// it to agree with the material present.
	Kind        string            `cbor:"kind"`
	PublicKey   []byte            `cbor:"public_key,omitempty"`
	CertRef     string            `cbor:"cert_ref,omitempty"`
	Attestation *AttestationRef   `cbor:"attestation,omitempty"`
	Composite   []MachineIdentity `cbor:"composite,omitempty"`
}

// Validate reports whether the identity's kind is a recognized discriminant and
// agrees with the material actually present (SCHEMA.md, field 122).
//
// Kind was previously unread anywhere in the SDK: the type comment named an
// enum, but a MAT could authorize — and a commitment could present — an
// identity whose kind said "attestation" while it carried only a bare public
// key, or a kind outside the enum entirely, and nothing objected. Kind is bound
// by the issuer's signature, so a lying kind takes a malicious issuer rather
// than an outside party; but a verifier that never checks the discriminant it
// hands a relying party is asserting a shape it did not confirm. This closes
// that gap on the verification side, where the identity is read.
//
// The check is by-kind rather than "exactly one field set" because a kind is a
// claim about a specific field, not merely a claim that some field is present:
// an attestation-kind identity that happens to carry a public key is still
// failing to carry the attestation its kind promises.
func (m MachineIdentity) Validate() error {
	kind := constants.IdentityKind(m.Kind)
	if !kind.Valid() {
		return fmt.Errorf("machine identity kind %q is not a recognized identity kind", m.Kind)
	}
	switch kind {
	case constants.IdentityKindPublicKey:
		if len(m.PublicKey) == 0 {
			return fmt.Errorf("machine identity kind %q carries no public key", m.Kind)
		}
	case constants.IdentityKindCertRef:
		if m.CertRef == "" {
			return fmt.Errorf("machine identity kind %q carries no cert ref", m.Kind)
		}
	case constants.IdentityKindAttestation:
		if m.Attestation == nil {
			return fmt.Errorf("machine identity kind %q carries no attestation reference", m.Kind)
		}
	case constants.IdentityKindComposite:
		if len(m.Composite) == 0 {
			return fmt.Errorf("machine identity kind %q carries no composite members", m.Kind)
		}
		// A composite is only as well-formed as its members: an outer kind that
		// agrees with a non-empty composite list still lies if a member's own
		// kind does not match its material.
		for i := range m.Composite {
			if err := m.Composite[i].Validate(); err != nil {
				return fmt.Errorf("composite member %d: %w", i, err)
			}
		}
	}
	return nil
}

// AttestationRef references hardware-bound attestation evidence (FIG. 7, ¶0059).
type AttestationRef struct {
	// Category is the attestation category, e.g. "tpm_quote", "tee_report".
	Category string `cbor:"category"`
	// KeyDigest is a digest over the attested platform key.
	KeyDigest []byte `cbor:"key_digest,omitempty"`
}

// ExecutionScope defines permitted operations as a bounded structured
// enumeration or policy expression (MAT field 124, ¶0041).
type ExecutionScope struct {
	// Actions is the set of permitted operation identifiers.
	Actions []string `cbor:"actions,omitempty"`
	// Resources is the set of permitted resource-target patterns. A pattern
	// ending in "*" matches any target sharing the literal prefix.
	Resources []string `cbor:"resources,omitempty"`
	// Policy is an optional opaque policy expression evaluated by the engine.
	Policy string `cbor:"policy,omitempty"`
	// Unconstrained names the dimensions this scope deliberately does not
	// restrict — "actions", "resources", or both.
	//
	// It exists because absence is not a statement. Without it an empty list has
	// to mean either "nothing is permitted" or "everything is permitted", and
	// whichever is chosen, the other is what some issuer meant. Reading absence
	// as "everything" makes the most permissive grant in the protocol the one
	// requiring the least typing, and an artifact that says nothing about a
	// dimension indistinguishable from one that deliberately opened it.
	//
	// So absence now denies, and permitting a whole dimension requires naming it
	// here. Delegation carries the same rule: a child may declare a dimension
	// unconstrained only where its parent already did.
	//
	// Optional and omitempty: absent from every canonical vector digest issued
	// before it existed, which is what the frozen xap-1.0.0 schema requires of a
	// within-version addition (SCHEMA.md).
	Unconstrained []string `cbor:"unconstrained,omitempty"`
}

// ScopeDimension names a scope dimension for ExecutionScope.Unconstrained.
const (
	ScopeDimensionActions   = "actions"
	ScopeDimensionResources = "resources"
)

// unconstrains reports whether this scope declares the named dimension
// deliberately unrestricted.
func (s ExecutionScope) unconstrains(dimension string) bool {
	return contains(s.Unconstrained, dimension)
}

// PermissionBoundary encodes non-exceedable hard limits — a strict ceiling
// enforced by derivation proof validation (MAT field 126, ¶0041).
type PermissionBoundary struct {
	// MaxImpact is the maximum impact bound (a numeric ceiling).
	MaxImpact int64 `cbor:"max_impact"`
	// MaxPrivilegeDelta is the maximum privilege delta bound.
	MaxPrivilegeDelta int64 `cbor:"max_privilege_delta"`
	// ResourceQuotas is a per-resource numeric quota ceiling.
	ResourceQuotas map[string]int64 `cbor:"resource_quotas,omitempty"`
	// Exclusions lists actions or resources that are never permitted. A child
	// boundary that adds exclusions is more restrictive (¶0057 invariant ii).
	Exclusions []string `cbor:"exclusions,omitempty"`
}

// TrustVector encodes a quantitative or qualitative trust assessment (MAT
// field 128, ¶0041).
type TrustVector struct {
	Score int    `cbor:"score,omitempty"`
	Level string `cbor:"level,omitempty"`
}

// ProofObligation specifies a category and freshness requirement of integrity
// evidence (MAT field 130, ¶0041).
type ProofObligation struct {
	// Category, e.g. "software_attestation", "tpm_quote", "tee_report".
	Category string `cbor:"category"`
	// MaxAgeSeconds is the freshness window; evidence older than this fails
	// validation at execution time (¶0048).
	MaxAgeSeconds int64 `cbor:"max_age_seconds"`
}

// DelegationRights specifies whether and how deeply an artifact may be derived
// (MAT field 134, ¶0041; depth enforcement, ¶0073).
type DelegationRights struct {
	Allowed  bool `cbor:"allowed"`
	MaxDepth int  `cbor:"max_depth"`
}

// IssuerIdentity identifies the issuing authority (MAT field 136, ¶0041). The
// signature itself is carried by the COSE_Sign1 envelope, not this struct; KID
// matches the envelope's key identifier so a verifier can select the anchor.
type IssuerIdentity struct {
	ID  string `cbor:"id"`
	KID []byte `cbor:"kid,omitempty"`
}

// ReplayProtection encodes the validity interval, nonce, and instance
// identifier (MAT field 138, ¶0041).
type ReplayProtection struct {
	// NotBefore and NotAfter are RFC3339 UTC timestamps bounding validity.
	NotBefore string `cbor:"not_before"`
	NotAfter  string `cbor:"not_after"`
	// Nonce provides replay protection.
	Nonce []byte `cbor:"nonce"`
	// InstanceID uniquely identifies this artifact instance.
	InstanceID string `cbor:"instance_id"`
}
