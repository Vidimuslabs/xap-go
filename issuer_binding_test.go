package xap_test

import (
	"errors"
	"testing"

	xap "github.com/Vidimuslabs/xap-go"
)

// pocIssuerMAT is a structurally valid MAT naming the given issuer.
func issuerMAT(id, issuerID string, kid []byte) xap.MAT {
	return xap.MAT{
		Version: xap.ProtocolVersion,
		ID:      id,
		Issuer:  xap.IssuerIdentity{ID: issuerID, KID: kid},
		Scope: xap.ExecutionScope{
			Unconstrained: []string{xap.ScopeDimensionActions, xap.ScopeDimensionResources},
		},
		Replay: xap.ReplayProtection{
			NotBefore:  "2026-01-01T00:00:00Z",
			NotAfter:   "2030-01-01T00:00:00Z",
			InstanceID: "inst-1",
		},
	}
}

// A trust anchor set with more than one issuer is the deployment the set exists
// for (¶0066, FIG. 14) — and it is the deployment in which an unbound issuer
// identity is an escalation: any trusted issuer could mint an artifact naming
// any other, because verifyEnvelope's answer to "which key signed this" was
// discarded by every caller.
func TestMATIssuerMustMatchTheVerifyingKey(t *testing.T) {
	ecA, mlPubA, _ := hybridKeys(t)
	ecB, mlPubB, mlPrivB := hybridKeys(t)
	kidA, kidB := []byte("kid-issuer-A"), []byte("kid-issuer-B")

	anchors := xap.NewTrustAnchorSet()
	if err := anchors.AddHybrid(kidA, &ecA.PublicKey, mlPubA); err != nil {
		t.Fatal(err)
	}
	if err := anchors.AddHybrid(kidB, &ecB.PublicKey, mlPubB); err != nil {
		t.Fatal(err)
	}

	// B signs a MAT whose signed body claims A issued it.
	impersonating := issuerMAT("mat-claiming-A", "issuer-A", kidA)
	payload, err := impersonating.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	_, err = xap.ParseMAT(signHybrid(t, kidB, ecB, mlPrivB, payload), anchors)
	if err == nil {
		t.Fatal("a MAT claiming issuer A was accepted while signed by issuer B")
	}
	if !errors.Is(err, xap.ErrIssuerKeyMismatch) {
		t.Fatalf("rejected, but not as an issuer mismatch: %v", err)
	}

	// The honest case must still pass, or the check above proves nothing.
	honest := issuerMAT("mat-b", "issuer-B", kidB)
	hp, err := honest.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	sm, err := xap.ParseMAT(signHybrid(t, kidB, ecB, mlPrivB, hp), anchors)
	if err != nil {
		t.Fatalf("MAT correctly naming its own signing key was rejected: %v", err)
	}
	if string(sm.SigningKID) != string(kidB) {
		t.Fatalf("SigningKID = %x, want %x", sm.SigningKID, kidB)
	}
}

// Absence is not an excuse. A MAT that names no issuing key cannot have the
// binding checked, and treating "unstated" as "fine" is the same defect
// ExecutionScope.Unconstrained exists to prevent.
func TestMATWithoutIssuerKeyIDIsRejected(t *testing.T) {
	ec, mlPub, mlPriv := hybridKeys(t)
	kid := []byte("kid-issuer")
	anchors := xap.NewTrustAnchorSet()
	if err := anchors.AddHybrid(kid, &ec.PublicKey, mlPub); err != nil {
		t.Fatal(err)
	}

	m := issuerMAT("mat-silent", "issuer", nil)
	payload, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	_, err = xap.ParseMAT(signHybrid(t, kid, ec, mlPriv, payload), anchors)
	if err == nil {
		t.Fatal("a MAT naming no issuer key id was accepted")
	}
	if !errors.Is(err, xap.ErrIssuerKeyMismatch) {
		t.Fatalf("rejected, but not as an issuer mismatch: %v", err)
	}
}
