package xap_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	xap "github.com/Vidimuslabs/xap-go"
	cose "github.com/veraison/go-cose"
)

// This round attacks the envelope layer with inputs the byte-mutation sweeps
// cannot reach: every artifact here is CORRECTLY SIGNED by a key the verifier
// is configured to trust, so rejection has to come from the headers, the
// payload discipline, or the algorithm agreement — never from a broken
// signature. A verifier that only holds up under mutation is a verifier that
// assumes the attacker has no key; the interesting attacker has one.

// signEd25519 is a test-only signer (the SDK itself never signs): it produces
// an EdDSA COSE_Sign1 envelope over the given payload with the given kid.
func signEd25519(t *testing.T, kid []byte, priv ed25519.PrivateKey, payload []byte) []byte {
	t.Helper()
	s, err := cose.NewSigner(cose.AlgorithmEdDSA, priv)
	if err != nil {
		t.Fatal(err)
	}
	env, err := cose.Sign1(rand.Reader, s, cose.Headers{
		Protected: cose.ProtectedHeader{
			cose.HeaderLabelAlgorithm: cose.AlgorithmEdDSA,
			cose.HeaderLabelKeyID:     kid,
		},
	}, payload, nil)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// edTestKey mints a key pair and registers its public half under kid with the
// given roles, returning the anchor set and private key.
func edTestKey(t *testing.T, kid []byte, roles ...xap.SignerRole) (*xap.TrustAnchorSet, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	anchors := xap.NewTrustAnchorSet()
	if err := anchors.AddEd25519(kid, roles, pub); err != nil {
		t.Fatal(err)
	}
	return anchors, priv
}

// newECKey and edKeyPair mint throwaway keys for the algorithm-confusion
// cases, where the key never needs to be registered at all.
func newECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func edKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// minimalReceipt is a structurally sound receipt payload the hostile variants
// mutate. Signed canonically, it verifies and passes every receipt-only check.
func minimalReceipt() xap.Receipt {
	return xap.Receipt{
		Version:       xap.ProtocolVersion,
		ID:            "r-adversarial",
		ArtifactID:    "mat-adversarial",
		Decision:      "permit",
		ContextDigest: bytes.Repeat([]byte{0x11}, 32),
		Timing: xap.Timing{
			Start: "2026-08-17T00:00:00Z", Complete: "2026-08-17T00:00:01Z", ElapsedMS: 1000,
		},
	}
}

// A signature over a padded payload is a VALID signature — the attack removes
// the trust the signature would otherwise carry, not the signature itself. The
// payload is attacker-controlled even under a key the verifier trusts (an
// issuer's signing service will sign what it is handed), so the decode has to
// reject trailing data rather than parse up to the first well-formed item.
func TestSignatureValidPaddedPayloadIsRejected(t *testing.T) {
	anchors, priv := edTestKey(t, []byte("ep-pad"), xap.RoleEnforcementPoint)
	rc := minimalReceipt()
	payload, err := rc.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	for _, pad := range [][]byte{{0x00}, {0xff}, []byte("pad"), {0x00, 0x00}} {
		env := signEd25519(t, []byte("ep-pad"), priv, append(append([]byte{}, payload...), pad...))
		if _, err := xap.ParseReceipt(env, anchors); err == nil {
			t.Fatalf("signature-valid envelope with %d trailing payload byte(s) was accepted", len(pad))
		}
	}
}

// The unprotected header bucket is by construction not covered by the
// signature (verify.go documents this exact malleability). Anchor selection
// must therefore read the PROTECTED kid only: an attacker who can influence
// the unprotected bucket must not be able to steer verification onto a
// different — possibly more permissive — anchor of the verifier's own set.
func TestKeyIDInUnprotectedHeaderNeverSelectsAnchor(t *testing.T) {
	// Two trusted keys: the one that actually signed, and a decoy.
	goodKID := []byte("ep-real")
	anchors, priv := edTestKey(t, goodKID, xap.RoleEnforcementPoint)
	decoyPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := anchors.AddEd25519([]byte("ep-decoy"), []xap.SignerRole{xap.RoleEnforcementPoint}, decoyPub); err != nil {
		t.Fatal(err)
	}
	rc := minimalReceipt()
	payload, err := rc.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cose.NewSigner(cose.AlgorithmEdDSA, priv)
	if err != nil {
		t.Fatal(err)
	}

	// kid present ONLY in the unprotected bucket: no anchor may be selected.
	msg := cose.NewSign1Message()
	msg.Payload = payload
	msg.Headers.Protected = cose.ProtectedHeader{cose.HeaderLabelAlgorithm: cose.AlgorithmEdDSA}
	msg.Headers.Unprotected = cose.UnprotectedHeader{cose.HeaderLabelKeyID: goodKID}
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		t.Fatal(err)
	}
	env, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := xap.ParseReceipt(env, anchors); err == nil {
		t.Fatal("envelope with kid only in the unsigned header bucket selected an anchor")
	}

	// Protected kid names the real key, unprotected kid names the decoy: the
	// signature is over the protected bucket, and the decoy must be ignored.
	msg2 := cose.NewSign1Message()
	msg2.Payload = payload
	msg2.Headers.Protected = cose.ProtectedHeader{
		cose.HeaderLabelAlgorithm: cose.AlgorithmEdDSA,
		cose.HeaderLabelKeyID:     goodKID,
	}
	msg2.Headers.Unprotected = cose.UnprotectedHeader{cose.HeaderLabelKeyID: []byte("ep-decoy")}
	if err := msg2.Sign(rand.Reader, nil, signer); err != nil {
		t.Fatal(err)
	}
	env2, err := msg2.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := xap.ParseReceipt(env2, anchors); err != nil {
		t.Fatalf("valid envelope rejected because its UNSIGNED bucket named another kid: %v", err)
	}
}

// Algorithm confusion: a correctly signed ES256 envelope naming a kid the
// verifier registers as an Ed25519 anchor (or the reverse) must fail at
// algorithm agreement, not fall through to verification under the wrong
// primitive. The kid is the only anchor selector, so a kid whose algorithm the
// operator mis-registered is exactly the confusion an attacker arranges via a
// stolen issuer key id.
func TestEnvelopeAlgorithmMustAgreeWithAnchorAlgorithm(t *testing.T) {
	rc := minimalReceipt()
	payload, err := rc.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	// ES256-signed envelope, kid registered as Ed25519.
	ecPriv := newECKey(t)
	kid := []byte("ep-confused")
	env := signES256(t, kid, ecPriv, payload)
	edAnchors := xap.NewTrustAnchorSet()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := edAnchors.AddEd25519(kid, []xap.SignerRole{xap.RoleEnforcementPoint}, pub); err != nil {
		t.Fatal(err)
	}
	if _, err := xap.ParseReceipt(env, edAnchors); err == nil {
		t.Fatal("ES256 envelope verified against an Ed25519-registered anchor")
	} else if errors.Is(err, xap.ErrNoTrustAnchor) {
		t.Fatalf("kid confusion reported as a missing anchor rather than an algorithm disagreement: %v", err)
	}

	// EdDSA-signed envelope, kid registered as ES256.
	_, edPriv := edKeyPair(t)
	env2 := signEd25519(t, kid, edPriv, payload)
	ecAnchors := xap.NewTrustAnchorSet()
	if err := ecAnchors.AddECDSAP256(kid, []xap.SignerRole{xap.RoleEnforcementPoint}, &ecPriv.PublicKey); err != nil {
		t.Fatal(err)
	}
	if _, err := xap.ParseReceipt(env2, ecAnchors); err == nil {
		t.Fatal("EdDSA envelope verified against an ES256-registered anchor")
	}
}

// A valid signature over an empty payload, and over a correctly encoded MAT
// payload presented through the receipt entry point: both must be rejected by
// payload discipline, since neither is a canonical receipt.
func TestForeignAndEmptyPayloadsAreRejected(t *testing.T) {
	anchors, priv := edTestKey(t, []byte("ep-foreign"), xap.RoleEnforcementPoint, xap.RoleIssuer)

	// go-cose refuses to sign a nil payload outright; CBOR null (0xf6) is the
	// closest a signer will ever produce, and it is not a canonical receipt.
	nullEnv := signEd25519(t, []byte("ep-foreign"), priv, []byte{0xf6})
	if _, err := xap.ParseReceipt(nullEnv, anchors); err == nil {
		t.Fatal("signature-valid envelope over CBOR null was accepted as a receipt")
	}

	mat := xap.MAT{
		Version: xap.ProtocolVersion, ID: "mat-foreign", Issuer: xap.IssuerIdentity{ID: "iss"},
		Replay: xap.ReplayProtection{
			NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z",
			Nonce: []byte{1}, InstanceID: "mat-foreign",
		},
	}
	matPayload, err := mat.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	env := signEd25519(t, []byte("ep-foreign"), priv, matPayload)
	if _, err := xap.ParseReceipt(env, anchors); err == nil {
		t.Fatal("a MAT payload was accepted through the receipt entry point")
	}
}
