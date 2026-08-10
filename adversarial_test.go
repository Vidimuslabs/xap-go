package xap_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	xap "github.com/Vidimuslabs/xap-go"
	"github.com/Vidimuslabs/xap-go/conformance"
	"github.com/Vidimuslabs/xap-spec/vectors"
	cose "github.com/veraison/go-cose"
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

// acceptFunc reports whether an envelope of a given artifact kind is accepted:
// parsed AND signature-verified against the anchor set. Tamper-evidence is a
// property of the signed envelope, so each kind is checked through its own
// entry point rather than forcing every artifact through the receipt path.
type acceptFunc func(env []byte, anchors *xap.TrustAnchorSet) bool

func acceptsReceipt(env []byte, anchors *xap.TrustAnchorSet) bool {
	if _, err := xap.ParseReceipt(env, anchors); err != nil {
		return false
	}
	return xap.NewVerifier(anchors).Verify(xap.VerifyInput{ReceiptEnvelope: env}).Valid
}

func acceptsMAT(env []byte, anchors *xap.TrustAnchorSet) bool {
	_, err := xap.ParseMAT(env, anchors)
	return err == nil
}

func acceptsCommitment(env []byte, anchors *xap.TrustAnchorSet) bool {
	_, err := xap.ParseCommitment(env, anchors)
	return err == nil
}

// signedEnvelopes are the validly signed artifacts the sweeps run over. Proving
// tamper-evidence for one permit receipt under one algorithm proves it for that
// receipt under that algorithm; the property is claimed for every artifact kind
// and every registered signature algorithm, so the sweep covers both. The hybrid
// entry matters most: hybrid is the production default, and until the anchor
// loader was fixed this file could not verify a hybrid artifact at all.
var signedEnvelopes = []struct {
	name   string
	accept acceptFunc
}{
	{"receipt_permit.hex", acceptsReceipt},
	{"receipt_deny.hex", acceptsReceipt},
	{"receipt_compact.hex", acceptsReceipt},
	{"mat_root.hex", acceptsMAT},
	{"mat_child_valid.hex", acceptsMAT},
	{"mat_hybrid_valid.hex", acceptsMAT},
	{"commitment_A.hex", acceptsCommitment},
}

// Tamper-evidence property (¶0010, ¶0088): a validly signed artifact is bound to
// every one of its fields by the issuer's signature. Flipping ANY single byte of
// the signed envelope must cause verification to fail — it must never silently
// verify after mutation. This is the field-level adversarial sweep expressed at
// the byte level, which subsumes "tamper each field one at a time" because every
// field's bytes live in the signed region.
func TestSignedEnvelopeByteMutationNeverVerifies(t *testing.T) {
	for _, tc := range signedEnvelopes {
		t.Run(tc.name, func(t *testing.T) {
			anchors := anchorsFromManifest(t)
			orig := loadEnvelope(t, tc.name)

			// Baseline: the unmutated artifact is accepted. Without this a sweep
			// over an artifact that never verified would pass vacuously.
			if !tc.accept(orig, anchors) {
				t.Fatalf("baseline %s was not accepted; the sweep below would be vacuous", tc.name)
			}

			for i := 0; i < len(orig); i++ {
				mutated := make([]byte, len(orig))
				copy(mutated, orig)
				mutated[i] ^= 0xFF
				if tc.accept(mutated, anchors) {
					t.Fatalf("mutation at byte %d produced an ACCEPTED artifact — tamper evidence broken", i)
				}
			}
			if len(orig) == 0 {
				t.Fatal("no mutations exercised")
			}
		})
	}
}

// Byte flipping preserves length and structure. These mutation classes do not,
// and none of them is reachable by flipping one byte: truncation at every
// boundary, extension with trailing bytes after a complete envelope, and
// zeroing a run. An envelope that is a strict prefix of a valid one, or a valid
// one with bytes appended, must be rejected rather than parsed up to the point
// where it still looks well-formed.
func TestSignedEnvelopeReshapingNeverVerifies(t *testing.T) {
	for _, tc := range signedEnvelopes {
		t.Run(tc.name, func(t *testing.T) {
			anchors := anchorsFromManifest(t)
			orig := loadEnvelope(t, tc.name)

			t.Run("truncation", func(t *testing.T) {
				for n := 0; n < len(orig); n++ {
					if tc.accept(orig[:n], anchors) {
						t.Fatalf("a %d-byte prefix of a %d-byte envelope was accepted", n, len(orig))
					}
				}
			})

			t.Run("trailing bytes", func(t *testing.T) {
				for _, suffix := range [][]byte{
					{0x00}, {0xff}, {0xa0}, {0x00, 0x00, 0x00, 0x00},
					[]byte("trailing garbage"),
				} {
					extended := append(append([]byte{}, orig...), suffix...)
					if tc.accept(extended, anchors) {
						t.Fatalf("envelope with %d trailing byte(s) was accepted", len(suffix))
					}
				}
			})

			t.Run("zeroed run", func(t *testing.T) {
				for _, runLen := range []int{2, 8, 32} {
					for i := 0; i+runLen <= len(orig); i += runLen {
						mutated := make([]byte, len(orig))
						copy(mutated, orig)
						for j := i; j < i+runLen; j++ {
							mutated[j] = 0
						}
						// A run that was already zero is not a mutation, and
						// accepting the unchanged envelope is correct. Skipping
						// these keeps the assertion about tampering rather than
						// about the vector's byte values.
						if bytes.Equal(mutated, orig) {
							continue
						}
						if tc.accept(mutated, anchors) {
							t.Fatalf("zeroing %d bytes at offset %d was accepted", runLen, i)
						}
					}
				}
			})
		})
	}
}

// A MAT whose payload was tampered under a known key id must fail signature
// verification (¶0045 — unconditional denial path).
//
// The assertion is on the reason, not merely on rejection. "Some error
// occurred" would also be satisfied by a CBOR parse failure or a missing
// anchor, so a regression that stopped checking signatures entirely could still
// leave this test green as long as something else happened to reject the input.
func TestTamperedMATSignatureRejected(t *testing.T) {
	anchors := anchorsFromManifest(t)
	env := loadEnvelope(t, "mat_bad_sig.hex")
	_, err := xap.ParseMAT(env, anchors)
	if err == nil {
		t.Fatal("tampered MAT verified — signature check bypassed")
	}
	if !errors.Is(err, cose.ErrVerification) {
		t.Fatalf("rejected for the wrong reason: want a signature failure, got %v", err)
	}
	if errors.Is(err, xap.ErrNoTrustAnchor) {
		t.Fatalf("rejected as an unknown anchor, not as a bad signature: %v", err)
	}
}

// A receipt signed by a key with no configured trust anchor must be rejected
// (there is no anchor to verify against) — and specifically for that reason,
// not because the envelope failed to parse.
func TestUnknownAnchorRejected(t *testing.T) {
	empty := xap.NewTrustAnchorSet()
	env := loadEnvelope(t, "receipt_permit.hex")
	_, err := xap.ParseReceipt(env, empty)
	if err == nil {
		t.Fatal("receipt verified against empty anchor set")
	}
	if !errors.Is(err, xap.ErrNoTrustAnchor) {
		t.Fatalf("rejected for the wrong reason: want a missing anchor, got %v", err)
	}
}
