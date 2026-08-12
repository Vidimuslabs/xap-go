package xap

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/Vidimuslabs/xap-spec/constants"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	cose "github.com/veraison/go-cose"
)

// This file is the verification side of the COSE_Sign1 envelope (technology
// decision: COSE_Sign1 via go-cose). It holds no signing keys and constructs no
// signers — issuance and enforcement signing live in the private engine and
// server. A verifier here selects a trust anchor by the envelope's key
// identifier and validates the signature over the enclosed payload.

// SignerRole names an artifact kind a key is trusted to sign. The protocol has
// three distinct signing roles and they are not interchangeable: an issuer
// grants authority (MAT, ¶0041 field 136), an enforcement point attests to a
// decision it made under that authority (receipt, ¶0050), and an agent commits
// in advance to what it will propose (commitment object, ¶0095B).
//
// The anchor set used to be a flat map from key id to key, consulted
// identically by all three parsers, so any trusted key could sign any artifact
// kind — an agent's key could mint the very authority grant the agent operates
// under. Nothing in a raw public key says what it is for, so the role has to be
// recorded when the operator registers it.
type SignerRole string

const (
	// RoleIssuer may sign Machine Authority Tokens.
	RoleIssuer SignerRole = "issuer"
	// RoleEnforcementPoint may sign execution receipts.
	RoleEnforcementPoint SignerRole = "enforcement_point"
	// RoleAgent may sign commitment objects.
	RoleAgent SignerRole = "agent"
)

// TrustAnchor is a single verification key with its signature algorithm, key
// identifier, and the roles it is trusted for (FIG. 14, ¶0066). The KID matches
// the COSE protected-header key id set by the signer.
type TrustAnchor struct {
	KID       []byte
	Algorithm constants.SignatureAlg
	PublicKey crypto.PublicKey
	// Roles are the artifact kinds this key may sign. An anchor with no roles
	// may sign nothing: registration requires the operator to say what the key
	// is for, because the alternative default — "anything" — is the most
	// permissive grant available and would arise from saying nothing.
	Roles []SignerRole
}

// Permits reports whether this anchor is trusted to sign the given artifact kind.
func (a TrustAnchor) Permits(role SignerRole) bool {
	for _, r := range a.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// ErrAnchorRoleMismatch reports that an envelope verified against a key the
// operator did not register for that artifact kind.
var ErrAnchorRoleMismatch = errors.New("xap: trust anchor is not registered for this artifact kind")

// validRoles checks that a registration names at least one role and no unknown one.
func validRoles(roles []SignerRole) error {
	if len(roles) == 0 {
		return errNoRoles
	}
	for _, r := range roles {
		switch r {
		case RoleIssuer, RoleEnforcementPoint, RoleAgent:
		default:
			return fmt.Errorf("%w: %q", errUnknownRole, r)
		}
	}
	return nil
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

// Anchor registration rejects a malformed key instead of storing it.
//
// The verification path hands an anchor's key to the underlying primitive, and
// crypto/ed25519.Verify panics on a public key that is not exactly
// ed25519.PublicKeySize bytes. An operator who registers the wrong bytes — an
// SPKI blob where a raw key belongs, or a zero value from an ignored decode
// error — therefore arms a panic that an attacker fires by sending an envelope
// naming that key id. Registration is where the operator can still act on the
// mistake; a request arriving hours later is not. Verification validates again
// anyway (see coseVerifierFor): this is the early gate, not the only one.
// ErrNoTrustAnchor reports that an envelope named a key id the verifier has no
// anchor for. It is distinct from a signature failure: the artifact may be
// perfectly well-formed and correctly signed by an issuer this verifier has not
// been configured to trust. Callers that conflate the two cannot tell "forged"
// from "unknown issuer", which are different operational problems.
var ErrNoTrustAnchor = errors.New("xap: no trust anchor for key id")

var (
	errNoKID       = errors.New("xap: trust anchor key id must not be empty")
	errNilKey      = errors.New("xap: trust anchor public key must not be nil")
	errKeyLen      = errors.New("xap: ed25519 trust anchor key must be 32 bytes")
	errWrongCurve  = errors.New("xap: trust anchor key is on the wrong curve")
	errNoRoles     = errors.New("xap: trust anchor must name at least one signer role")
	errUnknownRole = errors.New("xap: unknown signer role")
)

// AddEd25519 registers an Ed25519 verification key under the given key id, for
// the given signer roles. It returns an error if kid is empty, roles is empty or
// names an unknown role, or pub is not ed25519.PublicKeySize bytes.
func (s *TrustAnchorSet) AddEd25519(kid []byte, roles []SignerRole, pub ed25519.PublicKey) error {
	if len(kid) == 0 {
		return errNoKID
	}
	if err := validRoles(roles); err != nil {
		return err
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: got %d", errKeyLen, len(pub))
	}
	s.byKID[hex.EncodeToString(kid)] = TrustAnchor{
		KID:       kid,
		Algorithm: constants.SigEd25519,
		PublicKey: pub,
		Roles:     append([]SignerRole(nil), roles...),
	}
	return nil
}

// AddECDSAP256 registers an ECDSA P-256 verification key under the given key id.
// It demonstrates the algorithm agility the trust anchor set is built for
// (¶0066): the same verification path admits a second signature algorithm
// selected per key, so an HSM-backed ECDSA issuer verifies identically. It
// returns an error if kid is empty, pub is nil, or pub is not on P-256.
func (s *TrustAnchorSet) AddECDSAP256(kid []byte, roles []SignerRole, pub *ecdsa.PublicKey) error {
	if len(kid) == 0 {
		return errNoKID
	}
	if err := validRoles(roles); err != nil {
		return err
	}
	if pub == nil || pub.Curve == nil {
		return errNilKey
	}
	if pub.Curve != elliptic.P256() {
		return fmt.Errorf("%w: want P-256", errWrongCurve)
	}
	// Bytes reports an error for a point that is not on its curve, which is the
	// check we want — but it dereferences X and Y without guarding them and
	// segfaults on a partially-populated key, so the nil guard has to come
	// first. Reading the coordinates is deprecated as of Go 1.26 in favour of
	// Bytes; there is no non-deprecated way to ask whether they are set, and the
	// deprecation targets modifying them and hand-rolling encodings, neither of
	// which this does.
	//lint:ignore SA1019 nil-guard for Bytes, which panics on nil coordinates
	if pub.X == nil || pub.Y == nil {
		return errNilKey
	}
	if _, err := pub.Bytes(); err != nil {
		return fmt.Errorf("%w: %v", errNilKey, err)
	}
	s.byKID[hex.EncodeToString(kid)] = TrustAnchor{
		KID:       kid,
		Algorithm: constants.SigECDSAP256,
		PublicKey: pub,
		Roles:     append([]SignerRole(nil), roles...),
	}
	return nil
}

// HybridPublicKey is the pair of verification keys for a hybrid-ecdsa-p384-ml-dsa-65
// anchor: the classical ECDSA P-384 key and the post-quantum ML-DSA-65 key. Both
// must verify for the composite signature to be accepted (¶0066).
type HybridPublicKey struct {
	ECDSA *ecdsa.PublicKey
	MLDSA *mldsa65.PublicKey
}

// AddHybrid registers a post-quantum hybrid verification key (ECDSA P-384 +
// ML-DSA-65) under the given key id. A receipt signed by the corresponding issuer
// is accepted only if both signature halves verify — an attacker must forge both
// the classical and the post-quantum scheme. This gives XAP the same
// quantum-resistance posture as the rest of the portfolio's authority artifacts.
// It returns an error if kid is empty, either half is nil, or the classical
// half is not on P-384. A nil half would defeat both-must-pass by panicking
// rather than denying.
func (s *TrustAnchorSet) AddHybrid(kid []byte, roles []SignerRole, ec *ecdsa.PublicKey, ml *mldsa65.PublicKey) error {
	if len(kid) == 0 {
		return errNoKID
	}
	if err := validRoles(roles); err != nil {
		return err
	}
	if ec == nil || ec.Curve == nil || ml == nil {
		return errNilKey
	}
	if ec.Curve != elliptic.P384() {
		return fmt.Errorf("%w: want P-384", errWrongCurve)
	}
	//lint:ignore SA1019 nil-guard for Bytes, which panics on nil coordinates
	if ec.X == nil || ec.Y == nil {
		return errNilKey
	}
	if _, err := ec.Bytes(); err != nil {
		return fmt.Errorf("%w: %v", errNilKey, err)
	}
	s.byKID[hex.EncodeToString(kid)] = TrustAnchor{
		KID:       kid,
		Algorithm: constants.SigHybridECDSAP384MLDSA65,
		PublicKey: &HybridPublicKey{ECDSA: ec, MLDSA: ml},
		Roles:     append([]SignerRole(nil), roles...),
	}
	return nil
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
		// Independently of what registration allowed: ed25519.Verify panics on
		// a key of the wrong length, and this is the last point before the key
		// reaches it. An anchor set built by any other means than Add* — a
		// zero-valued struct, a future constructor — must not turn an
		// attacker-chosen key id into a crash.
		if len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("anchor %x: %w: got %d", a.KID, errKeyLen, len(pub))
		}
		// AlgorithmEdDSA is COSE alg -8 (the value formerly named AlgorithmEd25519).
		return cose.NewVerifier(cose.AlgorithmEdDSA, pub)
	case constants.SigECDSAP256:
		pub, ok := a.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("anchor %x: algorithm ecdsa-p256 but key is %T", a.KID, a.PublicKey)
		}
		// AlgorithmES256 is COSE alg -7 (ECDSA w/ SHA-256 on P-256).
		return cose.NewVerifier(cose.AlgorithmES256, pub)
	case constants.SigHybridECDSAP384MLDSA65:
		pub, ok := a.PublicKey.(*HybridPublicKey)
		if !ok {
			return nil, fmt.Errorf("anchor %x: algorithm %s but key is %T", a.KID, a.Algorithm, a.PublicKey)
		}
		return &hybridCOSEVerifier{pub: pub}, nil
	default:
		// HSM-backed verification uses one of the above algorithms with a key
		// whose private half lives in the HSM (¶0066); further algorithms are
		// added here as the registry grows.
		return nil, fmt.Errorf("anchor %x: unsupported signature algorithm %q", a.KID, a.Algorithm)
	}
}

// hybridCOSEVerifier verifies the composite hybrid signature as a cose.Verifier.
// The signature is the 96-byte ECDSA P-384 half (raw r‖s over SHA-384 of the
// signed content) followed by the ML-DSA-65 signature over the same content. Both
// halves must verify — the classical result is never trusted alone, nor the
// post-quantum one alone (both-must-pass, ¶0066).
type hybridCOSEVerifier struct{ pub *HybridPublicKey }

func (hybridCOSEVerifier) Algorithm() cose.Algorithm {
	return cose.Algorithm(constants.COSEAlgHybridECDSAP384MLDSA65)
}

func (v hybridCOSEVerifier) Verify(content, signature []byte) error {
	const ecLen = constants.HybridECDSAP384SigLen
	if len(signature) != ecLen+mldsa65.SignatureSize {
		return cose.ErrVerification
	}
	// Classical half: ECDSA P-384 over SHA-384(content), raw r‖s (48 bytes each).
	d := sha512.Sum384(content)
	r := new(big.Int).SetBytes(signature[:ecLen/2])
	s := new(big.Int).SetBytes(signature[ecLen/2 : ecLen])
	ecOK := ecdsa.Verify(v.pub.ECDSA, d[:], r, s)
	// Post-quantum half: ML-DSA-65 over content (empty context).
	mlOK := mldsa65.Verify(v.pub.MLDSA, content, nil, signature[ecLen:])
	if !ecOK || !mlOK {
		return cose.ErrVerification
	}
	return nil
}

// verifyEnvelope decodes a COSE_Sign1 envelope, selects a trust anchor by the
// protected-header key id, validates the signature, and returns the enclosed
// payload. It is the common signature-verification primitive for MATs,
// receipts, and commitment objects. Signature failure returns an error, which
// callers translate into an unconditional-denial path (¶0045, ¶0095A).
func verifyEnvelope(envelope []byte, anchors *TrustAnchorSet, role SignerRole) (payload []byte, kid []byte, err error) {
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
		return nil, nil, fmt.Errorf("%w: key id %x", ErrNoTrustAnchor, kid)
	}
	// Checked before the signature, not after: a key registered only to sign
	// receipts is not trusted to grant authority, and whether its signature is
	// arithmetically valid does not change that.
	if !anchor.Permits(role) {
		return nil, nil, fmt.Errorf("%w: key id %x is registered for %v, not %q",
			ErrAnchorRoleMismatch, kid, anchor.Roles, role)
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

// ErrIssuerKeyMismatch reports that a MAT's signed issuer identity names a key
// id other than the one that actually verified it.
var ErrIssuerKeyMismatch = errors.New("xap: MAT issuer key id does not match the verifying anchor")

// ParseMAT decodes and signature-verifies a COSE_Sign1 MAT envelope against the
// trust anchor set. Signature failure is an unconditional-denial condition
// (¶0045); callers map the error to ARTIFACT_SIGNATURE_FAILURE.
//
// It also binds the issuer identity the MAT *claims* to the key that actually
// signed it. verifyEnvelope has always known which anchor verified, and every
// caller discarded it, so IssuerIdentity.KID — documented as matching the
// envelope's key id — was signed, carried, and never read. In a deployment
// trusting more than one issuer, which is the deployment TrustAnchorSet exists
// for (¶0066, FIG. 14), that let any trusted issuer mint an artifact naming
// another: B signs, the body says A, and a verifier reports it as A's.
//
// The key id is required rather than checked-when-present. An artifact that
// declines to name its issuing key is not thereby more trustworthy, and the
// alternative reading — absence excuses the check — is the same "absence is not
// a statement" defect ExecutionScope.Unconstrained exists to prevent.
func ParseMAT(envelope []byte, anchors *TrustAnchorSet) (*SignedMAT, error) {
	payload, kid, err := verifyEnvelope(envelope, anchors, RoleIssuer)
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
	if len(m.Issuer.KID) == 0 {
		return nil, fmt.Errorf("%w: MAT %s names no issuer key id", ErrIssuerKeyMismatch, m.ID)
	}
	if !bytes.Equal(m.Issuer.KID, kid) {
		return nil, fmt.Errorf("%w: MAT %s claims issuer key %x but was signed by %x",
			ErrIssuerKeyMismatch, m.ID, m.Issuer.KID, kid)
	}
	return &SignedMAT{Envelope: envelope, MAT: *m, SigningKID: kid}, nil
}

// ParseReceipt decodes and signature-verifies a COSE_Sign1 receipt envelope
// against the trust anchor set (enforcement point signature, ¶0050).
func ParseReceipt(envelope []byte, anchors *TrustAnchorSet) (*SignedReceipt, error) {
	payload, kid, err := verifyEnvelope(envelope, anchors, RoleEnforcementPoint)
	if err != nil {
		return nil, err
	}
	r, err := UnmarshalReceipt(payload)
	if err != nil {
		return nil, err
	}
	return &SignedReceipt{Envelope: envelope, Receipt: *r, SigningKID: kid}, nil
}

// ParseCommitment decodes and signature-verifies a COSE_Sign1 commitment object
// envelope against the agent's key in the anchor set. Signature failure maps to
// COMMITMENT_OBJECT_SIGNATURE_FAILURE (¶0095A).
func ParseCommitment(envelope []byte, anchors *TrustAnchorSet) (*SignedCommitment, error) {
	payload, kid, err := verifyEnvelope(envelope, anchors, RoleAgent)
	if err != nil {
		return nil, err
	}
	c, err := UnmarshalCommitment(payload)
	if err != nil {
		return nil, err
	}
	return &SignedCommitment{Envelope: envelope, Commitment: *c, SigningKID: kid}, nil
}
