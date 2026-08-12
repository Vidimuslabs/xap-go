package xap_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	xap "github.com/Vidimuslabs/xap-go"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	cose "github.com/veraison/go-cose"
)

// hybridKeys generates a throwaway hybrid issuer key pair.
func hybridKeys(t *testing.T) (*ecdsa.PrivateKey, *mldsa65.PublicKey, *mldsa65.PrivateKey) {
	t.Helper()
	ec, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mlPub, mlPriv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return ec, mlPub, mlPriv
}

// chainFixture returns two receipts, B chained to A, both signed by one hybrid
// anchor, plus the anchor set.
func chainFixture(t *testing.T) (anchors *xap.TrustAnchorSet, envA, envB []byte, mlPriv *mldsa65.PrivateKey) {
	t.Helper()
	ec, mlPub, mlPriv := hybridKeys(t)
	kid := []byte("ep-chain")
	anchors = xap.NewTrustAnchorSet()
	if err := anchors.AddHybrid(kid, &ec.PublicKey, mlPub); err != nil {
		t.Fatal(err)
	}

	rcA := xap.Receipt{
		Version: xap.ProtocolVersion, ID: "A", ArtifactID: "mat-1",
		Decision: "permit", ContextDigest: []byte{1},
		Timing: xap.Timing{Start: "2026-01-01T00:00:00Z", Complete: "2026-01-01T00:00:00Z"},
	}
	pa, err := rcA.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	envA = signHybrid(t, kid, ec, mlPriv, pa)

	link, err := rcA.Digest()
	if err != nil {
		t.Fatal(err)
	}
	rcB := xap.Receipt{
		Version: xap.ProtocolVersion, ID: "B", ArtifactID: "mat-1",
		Decision: "permit", ContextDigest: []byte{2},
		PriorReceiptHash: link,
		Timing:           xap.Timing{Start: "2026-01-01T00:00:01Z", Complete: "2026-01-01T00:00:01Z"},
	}
	pb, err := rcB.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	envB = signHybrid(t, kid, ec, mlPriv, pb)
	return anchors, envA, envB, mlPriv
}

// The corpus pins only a BROKEN chain (receipt_broken_chain expects invalid), so
// a verifier that reported chain_link as failed unconditionally would satisfy
// every vector. This pins the other side.
func TestChainLinkVerifies(t *testing.T) {
	anchors, envA, envB, _ := chainFixture(t)
	srA, err := xap.ParseReceipt(envA, anchors)
	if err != nil {
		t.Fatal(err)
	}
	res := xap.NewVerifier(anchors).Verify(xap.VerifyInput{ReceiptEnvelope: envB, PriorReceipt: srA})
	if !res.Valid {
		t.Fatalf("honest chain rejected: %v", res.Failed())
	}
	var seen bool
	for _, c := range res.Checks {
		if c.Name == "chain_link" {
			seen = true
			if c.Status != xap.CheckPassed {
				t.Fatalf("chain_link status = %q, want passed", c.Status)
			}
		}
	}
	if !seen {
		t.Fatal("no chain_link check was emitted for a verification given a prior receipt")
	}
}

// The link must survive every rewrite of the envelope that leaves the signature
// valid, because those rewrites are available to anyone — they need no key.
// Both are exercised here; each one defeated the previous envelope-hash link.
func TestChainLinkSurvivesEnvelopeMalleability(t *testing.T) {
	anchors, envA, envB, _ := chainFixture(t)

	rewrites := []struct {
		name string
		fn   func(*testing.T, []byte) []byte
	}{
		{
			// ECDSA admits (r, s) and (r, n-s); nothing restricts s to the low
			// half, so the classical signature half can be rewritten in place.
			name: "ecdsa low-s flip",
			fn: func(t *testing.T, env []byte) []byte {
				var msg cose.Sign1Message
				if err := msg.UnmarshalCBOR(env); err != nil {
					t.Fatal(err)
				}
				sig := append([]byte(nil), msg.Signature...)
				n := elliptic.P384().Params().N
				s := new(big.Int).SetBytes(sig[48:96])
				s.Sub(n, s)
				s.FillBytes(sig[48:96])
				msg.Signature = sig
				out, err := msg.MarshalCBOR()
				if err != nil {
					t.Fatal(err)
				}
				return out
			},
		},
		{
			// The COSE unprotected header bucket is not covered by the
			// signature at all, so entries may be added freely. This one is
			// independent of the signature algorithm, which is why low-s
			// canonicalization alone could not have fixed the envelope link.
			name: "unprotected header added",
			fn: func(t *testing.T, env []byte) []byte {
				var msg cose.Sign1Message
				if err := msg.UnmarshalCBOR(env); err != nil {
					t.Fatal(err)
				}
				msg.Headers.RawUnprotected = nil
				msg.Headers.Unprotected["x-anything"] = "added by a third party"
				out, err := msg.MarshalCBOR()
				if err != nil {
					t.Fatal(err)
				}
				return out
			},
		},
	}

	for _, rw := range rewrites {
		t.Run(rw.name, func(t *testing.T) {
			envAprime := rw.fn(t, envA)
			if bytes.Equal(envAprime, envA) {
				t.Fatal("rewrite produced identical bytes; the case proves nothing")
			}
			srAprime, err := xap.ParseReceipt(envAprime, anchors)
			if err != nil {
				t.Fatalf("rewritten envelope no longer verifies, so the case proves nothing: %v", err)
			}
			res := xap.NewVerifier(anchors).Verify(xap.VerifyInput{
				ReceiptEnvelope: envB, PriorReceipt: srAprime,
			})
			if !res.Valid {
				t.Fatalf("chain broke against a rewritten but equally valid predecessor: %v", res.Failed())
			}
		})
	}
}

// A receipt's link is a digest over what the signature covers, so changing any
// signed field changes the link.
func TestChainLinkTracksPayloadNotEnvelope(t *testing.T) {
	a := xap.Receipt{
		Version: xap.ProtocolVersion, ID: "A", ArtifactID: "mat-1",
		Decision: "permit", ContextDigest: []byte{1},
		Timing: xap.Timing{Start: "2026-01-01T00:00:00Z", Complete: "2026-01-01T00:00:00Z"},
	}
	d1, err := a.Digest()
	if err != nil {
		t.Fatal(err)
	}
	b := a
	b.Decision = "deny"
	d2, err := b.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(d1, d2) {
		t.Fatal("changing the decision left the receipt digest unchanged")
	}

	// And it is stable: the same receipt digests identically however it was
	// obtained, which is what lets issuer and verifier agree without contact.
	payload, err := a.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	back, err := xap.UnmarshalReceipt(payload)
	if err != nil {
		t.Fatal(err)
	}
	d3, err := back.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(d1, d3) {
		t.Fatal("digest of a decoded receipt differs from the original")
	}
}
