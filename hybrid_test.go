package xap_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"io"
	"testing"

	xap "github.com/Vidimuslabs/xap-go"
	"github.com/Vidimuslabs/xap-spec/constants"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	cose "github.com/veraison/go-cose"
)

// hybridTestSigner is a test-only composite signer (ECDSA P-384 over SHA-384,
// raw r‖s, followed by ML-DSA-65). The SDK itself never signs; this stands in for
// a hybrid issuer so the verify-side both-must-pass path can be exercised.
type hybridTestSigner struct {
	ec *ecdsa.PrivateKey
	ml *mldsa65.PrivateKey
}

func (hybridTestSigner) Algorithm() cose.Algorithm {
	return cose.Algorithm(constants.COSEAlgHybridECDSAP384MLDSA65)
}

func (s hybridTestSigner) Sign(_ io.Reader, content []byte) ([]byte, error) {
	d := sha512.Sum384(content)
	r, ss, err := ecdsa.Sign(rand.Reader, s.ec, d[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, constants.HybridECDSAP384SigLen, constants.HybridECDSAP384SigLen+mldsa65.SignatureSize)
	r.FillBytes(out[:48])
	ss.FillBytes(out[48:96])
	ml := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(s.ml, content, nil, false, ml); err != nil {
		return nil, err
	}
	return append(out, ml...), nil
}

func signHybrid(t *testing.T, kid []byte, ec *ecdsa.PrivateKey, ml *mldsa65.PrivateKey, payload []byte) []byte {
	t.Helper()
	env, err := cose.Sign1(rand.Reader, hybridTestSigner{ec: ec, ml: ml}, cose.Headers{
		Protected: cose.ProtectedHeader{
			cose.HeaderLabelAlgorithm: cose.Algorithm(constants.COSEAlgHybridECDSAP384MLDSA65),
			cose.HeaderLabelKeyID:     kid,
		},
	}, payload, nil)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// The hybrid anchor verifies a composite ECDSA-P384 + ML-DSA-65 signature and
// must enforce BOTH-must-pass: it accepts only when both halves verify, and
// rejects when EITHER half is wrong. The conformance vectors cover all-pass and
// all-fail; these cases pin the AND semantics that all-fail alone cannot (a
// buggy OR verifier would still pass the vectors).
func TestHybridBothMustPass(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mlPub, mlPriv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kid := []byte("hybrid-issuer")

	rc := xap.Receipt{
		Version: xap.ProtocolVersion, ID: "r1", ArtifactID: "mat-1",
		Decision: "permit", ContextDigest: []byte{1, 2, 3},
		Timing: xap.Timing{Start: "2026-07-01T00:00:00Z", Complete: "2026-07-01T00:00:00Z"},
	}
	payload, err := rc.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	env := signHybrid(t, kid, ec, mlPriv, payload)

	// Both halves correct -> accept.
	good := xap.NewTrustAnchorSet()
	good.AddHybrid(kid, &ec.PublicKey, mlPub)
	if _, err := xap.ParseReceipt(env, good); err != nil {
		t.Fatalf("hybrid receipt failed to verify with correct anchor: %v", err)
	}

	// ECDSA half wrong, ML-DSA half correct -> reject (proves AND, not OR).
	otherEC, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	badEC := xap.NewTrustAnchorSet()
	badEC.AddHybrid(kid, &otherEC.PublicKey, mlPub)
	if _, err := xap.ParseReceipt(env, badEC); err == nil {
		t.Fatal("hybrid receipt verified with a WRONG ECDSA half (both-must-pass broken)")
	}

	// ML-DSA half wrong, ECDSA half correct -> reject (proves AND, not OR).
	otherML, _, _ := mldsa65.GenerateKey(rand.Reader)
	badML := xap.NewTrustAnchorSet()
	badML.AddHybrid(kid, &ec.PublicKey, otherML)
	if _, err := xap.ParseReceipt(env, badML); err == nil {
		t.Fatal("hybrid receipt verified with a WRONG ML-DSA half (both-must-pass broken)")
	}
}
