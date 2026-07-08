package xap_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	xap "github.com/Vidimuslabs/xap-go"
	cose "github.com/veraison/go-cose"
)

// signES256 is a test-only helper: it produces an ES256 COSE_Sign1 envelope. The
// SDK itself never signs; this stands in for an ECDSA/HSM issuer so the
// verify-side agility path can be exercised in the SDK's own tests.
func signES256(t *testing.T, kid []byte, priv *ecdsa.PrivateKey, payload []byte) []byte {
	t.Helper()
	s, err := cose.NewSigner(cose.AlgorithmES256, priv)
	if err != nil {
		t.Fatal(err)
	}
	env, err := cose.Sign1(rand.Reader, s, cose.Headers{
		Protected: cose.ProtectedHeader{
			cose.HeaderLabelAlgorithm: cose.AlgorithmES256,
			cose.HeaderLabelKeyID:     kid,
		},
	}, payload, nil)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// The trust anchor set admits ECDSA P-256 alongside Ed25519 (¶0066 agility): a
// receipt signed with ES256 verifies when the matching ECDSA anchor is
// registered, and fails when it is not.
func TestECDSAP256VerificationAgility(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kid := []byte("es-issuer")

	rc := xap.Receipt{
		Version: xap.ProtocolVersion, ID: "r1", ArtifactID: "mat-1",
		Decision: "permit", ContextDigest: []byte{1, 2, 3},
		Timing: xap.Timing{Start: "2026-07-01T00:00:00Z", Complete: "2026-07-01T00:00:00Z"},
	}
	payload, err := rc.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	env := signES256(t, kid, priv, payload)

	// With the ECDSA anchor registered, the ES256 receipt verifies.
	anchors := xap.NewTrustAnchorSet()
	anchors.AddECDSAP256(kid, &priv.PublicKey)
	if _, err := xap.ParseReceipt(env, anchors); err != nil {
		t.Fatalf("ES256 receipt failed to verify with ECDSA anchor: %v", err)
	}

	// A different ECDSA key under the same kid must fail signature verification.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrong := xap.NewTrustAnchorSet()
	wrong.AddECDSAP256(kid, &other.PublicKey)
	if _, err := xap.ParseReceipt(env, wrong); err == nil {
		t.Fatal("ES256 receipt verified against the wrong ECDSA key")
	}
}
