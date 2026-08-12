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
	if err := anchors.AddHybrid(kidA, []xap.SignerRole{xap.RoleIssuer}, &ecA.PublicKey, mlPubA); err != nil {
		t.Fatal(err)
	}
	if err := anchors.AddHybrid(kidB, []xap.SignerRole{xap.RoleIssuer}, &ecB.PublicKey, mlPubB); err != nil {
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
	if err := anchors.AddHybrid(kid, []xap.SignerRole{xap.RoleIssuer}, &ec.PublicKey, mlPub); err != nil {
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

// The protocol's three signing roles are distinct — an issuer grants authority,
// an enforcement point attests to a decision made under it, an agent commits in
// advance to what it will propose. The anchor set used to be a flat map
// consulted identically by all three parsers, so one trusted key could sign any
// artifact kind: an agent's key could mint the authority grant it operates
// under.
func TestSignerRolesAreEnforcedPerArtifactKind(t *testing.T) {
	ec, mlPub, mlPriv := hybridKeys(t)
	kid := []byte("kid-agent")

	agentOnly := xap.NewTrustAnchorSet()
	if err := agentOnly.AddHybrid(kid, []xap.SignerRole{xap.RoleAgent}, &ec.PublicKey, mlPub); err != nil {
		t.Fatal(err)
	}

	m := issuerMAT("mat-by-agent", "agent-pretending", kid)
	matPayload, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	matEnv := signHybrid(t, kid, ec, mlPriv, matPayload)
	if _, err := xap.ParseMAT(matEnv, agentOnly); !errors.Is(err, xap.ErrAnchorRoleMismatch) {
		t.Fatalf("agent key minted a MAT: err = %v", err)
	}

	rc := xap.Receipt{
		Version: xap.ProtocolVersion, ID: "r-by-agent", ArtifactID: "mat-1",
		Decision: "permit", ContextDigest: []byte{1},
		Timing: xap.Timing{Start: "2026-01-01T00:00:00Z", Complete: "2026-01-01T00:00:00Z"},
	}
	rp, err := rc.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := xap.ParseReceipt(signHybrid(t, kid, ec, mlPriv, rp), agentOnly); !errors.Is(err, xap.ErrAnchorRoleMismatch) {
		t.Fatalf("agent key minted a receipt: err = %v", err)
	}

	// Registered for the role it actually plays, the same key works — otherwise
	// the two cases above would pass for the wrong reason.
	issuerSet := xap.NewTrustAnchorSet()
	if err := issuerSet.AddHybrid(kid, []xap.SignerRole{xap.RoleIssuer}, &ec.PublicKey, mlPub); err != nil {
		t.Fatal(err)
	}
	if _, err := xap.ParseMAT(matEnv, issuerSet); err != nil {
		t.Fatalf("MAT rejected by an anchor registered for issuing: %v", err)
	}
}

// An anchor registered for nothing may sign nothing. Registration is where the
// operator states intent, and "unstated means unrestricted" is the reading the
// roles exist to remove — so it is refused at registration rather than silently
// becoming the most permissive grant available.
func TestAnchorMustNameARole(t *testing.T) {
	ec, mlPub, _ := hybridKeys(t)
	s := xap.NewTrustAnchorSet()
	if err := s.AddHybrid([]byte("k"), nil, &ec.PublicKey, mlPub); err == nil {
		t.Fatal("an anchor with no roles was registered")
	}
	if err := s.AddHybrid([]byte("k"), []xap.SignerRole{"auditor"}, &ec.PublicKey, mlPub); err == nil {
		t.Fatal("an anchor with an unknown role was registered")
	}
	if s.Len() != 0 {
		t.Fatalf("anchor set has %d entries after refused registrations", s.Len())
	}
}

// Nothing in a COSE_Sign1 envelope states which KIND of artifact its payload
// is. There is no `typ` in the protected header, and verifyEnvelope is shared
// by all three parsers, so the only thing standing between a MAT envelope and
// ParseReceipt is that the strict decoder rejects fields the target struct does
// not declare.
//
// That defence holds, and it holds by consequence of a decoder option rather
// than by intent — which is exactly the kind of property that survives until
// someone relaxes ExtraDecErrorUnknownField for an unrelated reason. Pinned
// here so that change fails a test instead of opening a substitution.
func TestArtifactKindsAreNotInterchangeable(t *testing.T) {
	ec, mlPub, mlPriv := hybridKeys(t)
	kid := []byte("kid-all-roles")
	anchors := xap.NewTrustAnchorSet()
	all := []xap.SignerRole{xap.RoleIssuer, xap.RoleEnforcementPoint, xap.RoleAgent}
	if err := anchors.AddHybrid(kid, all, &ec.PublicKey, mlPub); err != nil {
		t.Fatal(err)
	}
	sign := func(payload []byte) []byte { return signHybrid(t, kid, ec, mlPriv, payload) }

	mat := issuerMAT("mat-kind", "issuer", kid)
	matPayload, err := mat.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	rc := xap.Receipt{
		Version: xap.ProtocolVersion, ID: "r-kind", ArtifactID: "mat-kind",
		Decision: "permit", ContextDigest: []byte{1},
		Timing: xap.Timing{Start: "2026-01-01T00:00:00Z", Complete: "2026-01-01T00:00:00Z"},
	}
	rcPayload, err := rc.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	cm := xap.CommitmentObject{
		Version: xap.ProtocolVersion, ID: "c-kind",
		AgentIdentity:    xap.MachineIdentity{Kind: "public_key", PublicKey: []byte{1}},
		SessionID:        "s",
		DeclaredActions:  xap.DeclaredActionSet{ActionTypes: []string{"read"}},
		TemporalValidity: xap.TemporalValidity{NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2030-01-01T00:00:00Z"},
		Binding:          xap.CommitmentBinding{ArtifactID: "mat-kind", ConstraintDigest: []byte{2}},
	}
	cmPayload, err := cm.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	// Every parser must reject both artifact kinds that are not its own, even
	// though all three envelopes carry a valid signature by a trusted key that
	// is registered for all three roles.
	for _, tc := range []struct {
		name    string
		payload []byte
		parse   func([]byte, *xap.TrustAnchorSet) error
	}{
		{"MAT as receipt", matPayload, func(e []byte, a *xap.TrustAnchorSet) error {
			_, err := xap.ParseReceipt(e, a)
			return err
		}},
		{"MAT as commitment", matPayload, func(e []byte, a *xap.TrustAnchorSet) error {
			_, err := xap.ParseCommitment(e, a)
			return err
		}},
		{"receipt as MAT", rcPayload, func(e []byte, a *xap.TrustAnchorSet) error {
			_, err := xap.ParseMAT(e, a)
			return err
		}},
		{"receipt as commitment", rcPayload, func(e []byte, a *xap.TrustAnchorSet) error {
			_, err := xap.ParseCommitment(e, a)
			return err
		}},
		{"commitment as MAT", cmPayload, func(e []byte, a *xap.TrustAnchorSet) error {
			_, err := xap.ParseMAT(e, a)
			return err
		}},
		{"commitment as receipt", cmPayload, func(e []byte, a *xap.TrustAnchorSet) error {
			_, err := xap.ParseReceipt(e, a)
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.parse(sign(tc.payload), anchors); err == nil {
				t.Fatal("one artifact kind parsed as another")
			}
		})
	}

	// Controls: each parser accepts its own kind, or the six cases above pass
	// for the wrong reason.
	if _, err := xap.ParseMAT(sign(matPayload), anchors); err != nil {
		t.Fatalf("ParseMAT rejected a MAT: %v", err)
	}
	if _, err := xap.ParseReceipt(sign(rcPayload), anchors); err != nil {
		t.Fatalf("ParseReceipt rejected a receipt: %v", err)
	}
	if _, err := xap.ParseCommitment(sign(cmPayload), anchors); err != nil {
		t.Fatalf("ParseCommitment rejected a commitment: %v", err)
	}
}
