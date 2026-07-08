package xap

import "github.com/Vidimuslabs/xap-go/canonical"

// RuntimeContext holds the current values of machine and operational state
// variables against which execution constraints are evaluated (¶0009, ¶0047).
// It is obtained at the time the operation is requested — not at session
// establishment (claim 1). Its canonical digest is bound into the receipt so an
// independent verifier can recompute it from reproduced inputs (¶0010, ¶0095).
//
// A verifier presented with the reproduced context recomputes Digest and
// compares it to the receipt's context digest; a receipt may instead omit raw
// context and carry only the digest for privacy-preserving verification
// (¶0079).
type RuntimeContext struct {
	// Time is the RFC3339 UTC instant at which context was captured.
	Time string `cbor:"time" json:"time"`
	// NetworkZone is the current network zone identifier.
	NetworkZone string `cbor:"network_zone,omitempty" json:"network_zone,omitempty"`
	// Params holds numeric operational parameters keyed by name (param_bound).
	Params map[string]float64 `cbor:"params,omitempty" json:"params,omitempty"`
	// ResourceState holds the current state of dependent resources
	// (resource_state predicate).
	ResourceState map[string]string `cbor:"resource_state,omitempty" json:"resource_state,omitempty"`
	// RiskScore is the current runtime risk score (¶0072 step-up trigger).
	RiskScore int `cbor:"risk_score,omitempty" json:"risk_score,omitempty"`
	// Rate holds the current observed rate keyed by rate_limit constraint ID.
	Rate map[string]int64 `cbor:"rate,omitempty" json:"rate,omitempty"`
}

// Digest returns the canonical runtime context digest (¶0018, ¶0085). Because
// the canonicalization function is field-order and encoding independent, any
// party reproducing the same semantic context computes the same digest.
func (r RuntimeContext) Digest() ([]byte, error) {
	return canonical.DigestBytes(r)
}
