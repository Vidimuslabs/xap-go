package xap_test

import (
	"encoding/hex"
	"strings"
	"testing"

	xap "github.com/Vidimuslabs/xap-go"
	"github.com/Vidimuslabs/xap-go/conformance"
	"github.com/Vidimuslabs/xap-spec/vectors"
)

// anchorsFromManifest builds a trust anchor set from the embedded vector
// manifest, so adversarial tests can exercise real signature verification
// without holding any signing key.
//
// It delegates to conformance.BuildAnchors rather than walking m.Anchors
// itself. A hand-rolled loop here previously registered EVERY anchor with
// AddEd25519 regardless of its declared alg, which silently filed the hybrid
// anchor's 120-byte ECDSA SPKI as an Ed25519 key — a bogus anchor that only
// failed to matter because no test in this file loaded a hybrid artifact.
// There is one correct way to turn a manifest into an anchor set; this is it.
func anchorsFromManifest(t *testing.T) *xap.TrustAnchorSet {
	t.Helper()
	m, err := vectors.Load()
	if err != nil {
		t.Fatal(err)
	}
	set, err := conformance.BuildAnchors(m)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func loadEnvelope(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := vectors.File(name)
	if err != nil {
		t.Fatal(err)
	}
	env, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// Tamper-evidence property (¶0010, ¶0088): a validly signed receipt is bound to
// every one of its fields by the enforcement point signature. Flipping ANY
// single byte of the signed envelope must cause verification to fail — the
// receipt must never silently verify after mutation. This is the field-level
// adversarial sweep expressed at the byte level, which subsumes "tamper each
// field one at a time" because every field's bytes live in the signed region.
func TestReceiptByteMutationNeverVerifies(t *testing.T) {
	anchors := anchorsFromManifest(t)
	orig := loadEnvelope(t, "receipt_permit.hex")

	// Baseline: the unmutated receipt verifies its signature.
	if _, err := xap.ParseReceipt(orig, anchors); err != nil {
		t.Fatalf("baseline receipt failed to verify: %v", err)
	}

	verifier := xap.NewVerifier(anchors)
	mutations := 0
	for i := 0; i < len(orig); i++ {
		mutated := make([]byte, len(orig))
		copy(mutated, orig)
		mutated[i] ^= 0xFF
		mutations++

		// The receipt must not verify: either the COSE parse/signature fails, or
		// (for a mutation that happens to keep valid CBOR) the overall verification
		// result is invalid. It must never come back Valid.
		res := verifier.Verify(xap.VerifyInput{ReceiptEnvelope: mutated})
		if res.Valid {
			t.Fatalf("mutation at byte %d produced a VALID verification — tamper evidence broken", i)
		}
	}
	if mutations == 0 {
		t.Fatal("no mutations exercised")
	}
}

// A MAT whose payload was tampered under a known key id must fail signature
// verification (¶0045 — unconditional denial path).
func TestTamperedMATSignatureRejected(t *testing.T) {
	anchors := anchorsFromManifest(t)
	env := loadEnvelope(t, "mat_bad_sig.hex")
	if _, err := xap.ParseMAT(env, anchors); err == nil {
		t.Fatal("tampered MAT verified — signature check bypassed")
	}
}

// A receipt signed by a key with no configured trust anchor must be rejected
// (there is no anchor to verify against).
func TestUnknownAnchorRejected(t *testing.T) {
	empty := xap.NewTrustAnchorSet()
	env := loadEnvelope(t, "receipt_permit.hex")
	if _, err := xap.ParseReceipt(env, empty); err == nil {
		t.Fatal("receipt verified against empty anchor set")
	}
}
