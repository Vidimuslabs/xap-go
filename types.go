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
// Spec authority: AMIAP_Specification.docx as amended by
// AMIAP_PRELIMINARY_AMENDMENT.docx. Paragraph anchors (¶NNNN) in comments cite
// the amended specification for every protocol-semantic decision.
package xap

import "github.com/Vidimuslabs/xap-spec/constants"

// Re-export the protocol version so SDK callers need not import constants
// directly for the common case.
const ProtocolVersion = constants.ProtocolVersion

// MachineIdentity binds an artifact or commitment object to a specific machine
// or agent entity (MAT field 122, ¶0041; commitment agent identity, ¶0095B).
// The identity may be a raw public key, a certificate reference, a hardware
// attestation-bound identifier, or a composite of several anchors.
type MachineIdentity struct {
	// Kind is one of "public_key", "cert_ref", "attestation", "composite".
	Kind        string            `cbor:"kind"`
	PublicKey   []byte            `cbor:"public_key,omitempty"`
	CertRef     string            `cbor:"cert_ref,omitempty"`
	Attestation *AttestationRef   `cbor:"attestation,omitempty"`
	Composite   []MachineIdentity `cbor:"composite,omitempty"`
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
