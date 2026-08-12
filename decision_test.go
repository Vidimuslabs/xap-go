package xap_test

import (
	"testing"

	xap "github.com/Vidimuslabs/xap-go"
)

// decisionFixture builds a MAT with two constraints and a context violating
// both, plus a signer for minting receipts under it. One key, registered for
// the roles it actually plays here.
func decisionFixture(t *testing.T) (matEnv []byte, anchors *xap.TrustAnchorSet, ctx xap.RuntimeContext, sign func(xap.Receipt) []byte) {
	t.Helper()
	ec, mlPub, mlPriv := hybridKeys(t)
	kid := []byte("decision-key")
	anchors = xap.NewTrustAnchorSet()
	err := anchors.AddHybrid(kid, []xap.SignerRole{xap.RoleIssuer, xap.RoleEnforcementPoint}, &ec.PublicKey, mlPub)
	if err != nil {
		t.Fatal(err)
	}

	mat := xap.MAT{
		Version: xap.ProtocolVersion,
		ID:      "mat-decision",
		Issuer:  xap.IssuerIdentity{ID: "issuer", KID: kid},
		Scope: xap.ExecutionScope{
			Unconstrained: []string{xap.ScopeDimensionActions, xap.ScopeDimensionResources},
		},
		Constraints: []xap.Constraint{
			{ID: "c-zone", Type: "network_zone", Zones: []string{"trusted"}},
			{ID: "c-state", Type: "resource_state", Key: "db", Equals: "healthy"},
		},
		Replay: xap.ReplayProtection{
			NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2030-01-01T00:00:00Z",
			InstanceID: "inst-1",
		},
	}
	mp, err := mat.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	matEnv = signHybrid(t, kid, ec, mlPriv, mp)

	ctx = xap.RuntimeContext{
		Time:          "2026-06-01T00:00:00Z",
		NetworkZone:   "hostile",
		ResourceState: map[string]string{"db": "degraded"},
	}
	for _, c := range mat.Constraints {
		if c.Evaluate(ctx) {
			t.Fatalf("fixture is wrong: constraint %q holds", c.ID)
		}
	}

	return matEnv, anchors, ctx, func(rc xap.Receipt) []byte {
		t.Helper()
		p, err := rc.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return signHybrid(t, kid, ec, mlPriv, p)
	}
}

func decisionReceipt(t *testing.T, ctx xap.RuntimeContext) xap.Receipt {
	t.Helper()
	cd, err := ctx.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return xap.Receipt{
		Version: xap.ProtocolVersion, ID: "r-decision", ArtifactID: "mat-decision",
		ContextDigest: cd, Action: "read", Resource: "db/x",
		Timing: xap.Timing{
			Start: "2026-06-01T00:00:00Z", Complete: "2026-06-01T00:00:00Z", MaxMS: 1000,
		},
	}
}

// permit_with_controls is the one decision that may permit an operation whose
// constraints did not all hold, because the controls compensate (¶0049). Naming
// no control claims the exemption without the thing that earns it.
//
// Two gaps composed here: decision_consistent returned true for every decision
// that was not exactly "permit", and constraint_outcomes only re-evaluated the
// outcomes a receipt chose to record — so a receipt recording none was checked
// against nothing. With the full reproduced context supplied, the maximum
// information a verifier can be given, this verified.
func TestPermitWithControlsNeedsControls(t *testing.T) {
	matEnv, anchors, ctx, sign := decisionFixture(t)
	v := xap.NewVerifier(anchors)

	rc := decisionReceipt(t, ctx)
	rc.Decision = "permit_with_controls"
	rc.Controls = nil
	rc.ConstraintOutcomes = nil

	res := v.Verify(xap.VerifyInput{
		ReceiptEnvelope: sign(rc), MATEnvelope: matEnv, ReproducedContext: &ctx,
	})
	if res.Valid {
		t.Fatal("permit_with_controls with no controls, over a context violating every constraint, verified")
	}
	if c := checkNamed(t, res, "controls_declared"); c.Pass {
		t.Errorf("controls_declared passed: %s", c.Detail)
	}
	if c := checkNamed(t, res, "decision_consistent"); c.Pass {
		t.Errorf("decision_consistent passed: %s", c.Detail)
	}
}

// The compensating case must still verify, or the test above proves only that
// permit_with_controls is unusable.
func TestPermitWithControlsVerifiesWhenControlsAreNamed(t *testing.T) {
	matEnv, anchors, ctx, sign := decisionFixture(t)
	v := xap.NewVerifier(anchors)

	rc := decisionReceipt(t, ctx)
	rc.Decision = "permit_with_controls"
	rc.Controls = []string{"rate_limit_applied"}
	rc.ConstraintOutcomes = []xap.ConstraintOutcome{
		{ConstraintID: "c-zone", Satisfied: false},
		{ConstraintID: "c-state", Satisfied: false},
	}

	res := v.Verify(xap.VerifyInput{
		ReceiptEnvelope: sign(rc), MATEnvelope: matEnv, ReproducedContext: &ctx,
	})
	if !res.Valid {
		t.Fatalf("a compensated permit_with_controls was rejected: %v", res.Failed())
	}
}

// Controls on a plain permit contradict the decision they belong to.
func TestControlsOnPlainPermitAreInconsistent(t *testing.T) {
	matEnv, anchors, ctx, sign := decisionFixture(t)
	rc := decisionReceipt(t, ctx)
	rc.Decision = "permit"
	rc.Controls = []string{"rate_limit_applied"}

	res := xap.NewVerifier(anchors).Verify(xap.VerifyInput{
		ReceiptEnvelope: sign(rc), MATEnvelope: matEnv, ReproducedContext: &ctx,
	})
	if c := checkNamed(t, res, "controls_declared"); c.Pass {
		t.Errorf("a plain permit naming controls passed controls_declared: %s", c.Detail)
	}
}

// Withholding a constraint outcome is legitimate (¶0071, ¶0079) and is not the
// same as having it checked. The distinction has to reach the verifier's output
// rather than being absorbed into a pass.
func TestWithheldOutcomesAreNotPerformedRatherThanPassed(t *testing.T) {
	matEnv, anchors, ctx, sign := decisionFixture(t)

	rc := decisionReceipt(t, ctx)
	rc.Decision = "deny" // a denial, so the missing outcomes are the only question
	rc.ConstraintOutcomes = nil

	res := xap.NewVerifier(anchors).Verify(xap.VerifyInput{
		ReceiptEnvelope: sign(rc), MATEnvelope: matEnv, ReproducedContext: &ctx,
	})
	c := checkNamed(t, res, "constraint_outcomes")
	if c.Status != xap.CheckNotPerformed {
		t.Fatalf("constraint_outcomes status = %q, want %q; detail=%q", c.Status, xap.CheckNotPerformed, c.Detail)
	}
	if !res.Valid {
		t.Errorf("a not-performed check must not invalidate the receipt: %v", res.Failed())
	}

	// Recording every outcome, correctly, is what a pass takes.
	rc.ConstraintOutcomes = []xap.ConstraintOutcome{
		{ConstraintID: "c-zone", Satisfied: false},
		{ConstraintID: "c-state", Satisfied: false},
	}
	res = xap.NewVerifier(anchors).Verify(xap.VerifyInput{
		ReceiptEnvelope: sign(rc), MATEnvelope: matEnv, ReproducedContext: &ctx,
	})
	if c := checkNamed(t, res, "constraint_outcomes"); c.Status != xap.CheckPassed {
		t.Fatalf("fully-recorded outcomes gave status %q: %s", c.Status, c.Detail)
	}
}
