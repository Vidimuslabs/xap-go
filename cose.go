package xap

import (
	"crypto"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"github.com/Vidimuslabs/xap-spec/constants"
	cose "github.com/veraison/go-cose"
)

// This file is the verification side of the COSE_Sign1 envelope (technology
// decision: COSE_Sign1 via go-cose). It holds no signing keys and constructs no
// signers — issuance and enforcement signing live in the private engine and
// server. A verifier here selects a trust anchor by the envelope's key
// identifier and validates the signature over the enclosed payload.

// TrustAnchor is a single verification key with its signature algorithm and key
// identifier (FIG. 14, ¶0066). The KID matches the COSE protected-header key id
// set by the signer.
type TrustAnchor struct {
	KID       []byte
	Algorithm constants.SignatureAlg
	PublicKey crypto.PublicKey
}

// TrustAnchorSet is the configured set of trust anchors distributed to a
// verifier (¶0066, FIG. 14). Anchors are looked up by key identifier.
type TrustAnchorSet struct {
	byKID map[string]TrustAnchor
}

// NewTrustAnchorSet returns an empty anchor set.
func NewTrustAnchorSet() *TrustAnchorSet {
	return &TrustAnchorSet{byKID: make(map[string]TrustAnchor)}
}

// AddEd25519 registers an Ed25519 verification key under the given key id.
func (s *TrustAnchorSet) AddEd25519(kid []byte, pub ed25519.PublicKey) {
	s.byKID[hex.EncodeToString(kid)] = TrustAnchor{
		KID:       kid,
		Algorithm: constants.SigEd25519,
		PublicKey: pub,
	}
}

// Get returns the anchor registered under kid, if any.
func (s *TrustAnchorSet) Get(kid []byte) (TrustAnchor, bool) {
	a, ok := s.byKID[hex.EncodeToString(kid)]
	return a, ok
}

// Len reports the number of registered anchors.
func (s *TrustAnchorSet) Len() int { return len(s.byKID) }

// coseVerifierFor builds a go-cose Verifier for an anchor.
func coseVerifierFor(a TrustAnchor) (cose.Verifier, error) {
	switch a.Algorithm {
	case constants.SigEd25519:
		pub, ok := a.PublicKey.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("anchor %x: algorithm ed25519 but key is %T", a.KID, a.PublicKey)
		}
		return cose.NewVerifier(cose.AlgorithmEd25519, pub)
	default:
		// ECDSA P-256 and HSM-backed verification are registered but not wired in
		// the reference build (¶0066).
		return nil, fmt.Errorf("anchor %x: unsupported signature algorithm %q", a.KID, a.Algorithm)
	}
}

// verifyEnvelope decodes a COSE_Sign1 envelope, selects a trust anchor by the
// protected-header key id, validates the signature, and returns the enclosed
// payload. It is the common signature-verification primitive for MATs,
// receipts, and commitment objects. Signature failure returns an error, which
// callers translate into an unconditional-denial path (¶0045, ¶0095A).
func verifyEnvelope(envelope []byte, anchors *TrustAnchorSet) (payload []byte, kid []byte, err error) {
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(envelope); err != nil {
		return nil, nil, fmt.Errorf("decode COSE_Sign1: %w", err)
	}
	rawKID, ok := msg.Headers.Protected[cose.HeaderLabelKeyID]
	if !ok {
		return nil, nil, fmt.Errorf("envelope missing key id in protected header")
	}
	kid, ok = rawKID.([]byte)
	if !ok {
		return nil, nil, fmt.Errorf("envelope key id is %T, want bytes", rawKID)
	}
	anchor, ok := anchors.Get(kid)
	if !ok {
		return nil, nil, fmt.Errorf("no trust anchor for key id %x", kid)
	}
	verifier, err := coseVerifierFor(anchor)
	if err != nil {
		return nil, nil, err
	}
	if err := msg.Verify(nil, verifier); err != nil {
		return nil, nil, fmt.Errorf("signature verification failed for key id %x: %w", kid, err)
	}
	return msg.Payload, kid, nil
}

// ParseMAT decodes and signature-verifies a COSE_Sign1 MAT envelope against the
// trust anchor set. Signature failure is an unconditional-denial condition
// (¶0045); callers map the error to ARTIFACT_SIGNATURE_FAILURE.
func ParseMAT(envelope []byte, anchors *TrustAnchorSet) (*SignedMAT, error) {
	payload, _, err := verifyEnvelope(envelope, anchors)
	if err != nil {
		return nil, err
	}
	m, err := UnmarshalMAT(payload)
	if err != nil {
		return nil, err
	}
	if err := m.ValidateStructure(); err != nil {
		return nil, err
	}
	return &SignedMAT{Envelope: envelope, MAT: *m}, nil
}

// ParseReceipt decodes and signature-verifies a COSE_Sign1 receipt envelope
// against the trust anchor set (enforcement point signature, ¶0050).
func ParseReceipt(envelope []byte, anchors *TrustAnchorSet) (*SignedReceipt, error) {
	payload, _, err := verifyEnvelope(envelope, anchors)
	if err != nil {
		return nil, err
	}
	r, err := UnmarshalReceipt(payload)
	if err != nil {
		return nil, err
	}
	return &SignedReceipt{Envelope: envelope, Receipt: *r}, nil
}

// ParseCommitment decodes and signature-verifies a COSE_Sign1 commitment object
// envelope against the agent's key in the anchor set. Signature failure maps to
// COMMITMENT_OBJECT_SIGNATURE_FAILURE (¶0095A).
func ParseCommitment(envelope []byte, anchors *TrustAnchorSet) (*SignedCommitment, error) {
	payload, _, err := verifyEnvelope(envelope, anchors)
	if err != nil {
		return nil, err
	}
	c, err := UnmarshalCommitment(payload)
	if err != nil {
		return nil, err
	}
	return &SignedCommitment{Envelope: envelope, Commitment: *c}, nil
}
