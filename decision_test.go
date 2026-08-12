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

// The MAT's latency_bound constraint is the authorized evaluation budget
// (¶0051, ¶0088). timing_within_bound compares the receipt's elapsed time to
// the receipt's OWN max_ms — both sides from the artifact under judgement — so
// the bound the artifact was granted went unread. max_ms is omitempty and 0
// means unbounded, which made the most permissive latency grant the one
// requiring the least typing.
func TestAuthorizedLatencyBoundIsEnforced(t *testing.T) {
	matEnv, anchors, ctx, sign := latencyFixture(t, 100)
	v := xap.NewVerifier(anchors)

	for _, tc := range []struct {
		name             string
		maxMS, elapsedMS int64
		want             xap.CheckStatus
	}{
		{"declares no bound at all", 0, 60000, xap.CheckFailed},
		{"declares a wider bound than authorized", 90000, 30000, xap.CheckFailed},
		{"within the authorized bound", 100, 12, xap.CheckPassed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rc := decisionReceipt(t, ctx)
			rc.ArtifactID = "mat-latency"
			rc.Decision = "permit"
			rc.Timing = xap.Timing{
				Start: "2026-06-01T00:00:00Z", Complete: "2026-06-01T00:00:00Z",
				ElapsedMS: tc.elapsedMS, MaxMS: tc.maxMS,
			}
			res := v.Verify(xap.VerifyInput{ReceiptEnvelope: sign(rc), MATEnvelope: matEnv})
			c := checkNamed(t, res, "timing_within_authorized_bound")
			if c.Status != tc.want {
				t.Fatalf("status = %q, want %q; detail=%q", c.Status, tc.want, c.Detail)
			}
		})
	}
}

// A MAT stating no latency_bound authorizes no budget, so there is nothing to
// check against — not performed, not passed.
func TestUnstatedLatencyBoundIsNotPerformed(t *testing.T) {
	matEnv, anchors, ctx, sign := latencyFixture(t, 0)
	rc := decisionReceipt(t, ctx)
	rc.ArtifactID = "mat-latency"
	rc.Decision = "permit"

	res := xap.NewVerifier(anchors).Verify(xap.VerifyInput{ReceiptEnvelope: sign(rc), MATEnvelope: matEnv})
	if c := checkNamed(t, res, "timing_within_authorized_bound"); c.Status != xap.CheckNotPerformed {
		t.Fatalf("status = %q, want not_performed; detail=%q", c.Status, c.Detail)
	}
}

// The strictest of several latency bounds is the one in force: satisfying an
// artifact means satisfying every constraint it states, not the loosest.
func TestStrictestLatencyBoundWins(t *testing.T) {
	ec, mlPub, mlPriv := hybridKeys(t)
	kid := []byte("lat-key")
	anchors := xap.NewTrustAnchorSet()
	if err := anchors.AddHybrid(kid, []xap.SignerRole{xap.RoleIssuer, xap.RoleEnforcementPoint}, &ec.PublicKey, mlPub); err != nil {
		t.Fatal(err)
	}
	mat := xap.MAT{
		Version: xap.ProtocolVersion, ID: "mat-latency",
		Issuer: xap.IssuerIdentity{ID: "issuer", KID: kid},
		Scope:  xap.ExecutionScope{Unconstrained: []string{xap.ScopeDimensionActions, xap.ScopeDimensionResources}},
		Constraints: []xap.Constraint{
			{ID: "lat-a", Type: "latency_bound", MaxMS: 500},
			{ID: "lat-b", Type: "latency_bound", MaxMS: 50},
		},
		Replay: xap.ReplayProtection{NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2030-01-01T00:00:00Z", InstanceID: "i"},
	}
	mp, err := mat.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	matEnv := signHybrid(t, kid, ec, mlPriv, mp)

	rc := xap.Receipt{
		Version: xap.ProtocolVersion, ID: "r", ArtifactID: "mat-latency",
		Decision: "permit", ContextDigest: []byte{1},
		Timing: xap.Timing{Start: "2026-06-01T00:00:00Z", Complete: "2026-06-01T00:00:00Z", ElapsedMS: 10, MaxMS: 200},
	}
	p, err := rc.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	res := xap.NewVerifier(anchors).Verify(xap.VerifyInput{
		ReceiptEnvelope: signHybrid(t, kid, ec, mlPriv, p), MATEnvelope: matEnv,
	})
	// 200ms sits inside the loosest bound and outside the strictest.
	if c := checkNamed(t, res, "timing_within_authorized_bound"); c.Pass {
		t.Fatalf("the loosest latency bound was treated as the one in force: %s", c.Detail)
	}
}

// latencyFixture builds a MAT whose only constraint is a latency bound of
// boundMS (or none at all when boundMS is 0).
func latencyFixture(t *testing.T, boundMS int64) (matEnv []byte, anchors *xap.TrustAnchorSet, ctx xap.RuntimeContext, sign func(xap.Receipt) []byte) {
	t.Helper()
	ec, mlPub, mlPriv := hybridKeys(t)
	kid := []byte("lat-key")
	anchors = xap.NewTrustAnchorSet()
	if err := anchors.AddHybrid(kid, []xap.SignerRole{xap.RoleIssuer, xap.RoleEnforcementPoint}, &ec.PublicKey, mlPub); err != nil {
		t.Fatal(err)
	}
	mat := xap.MAT{
		Version: xap.ProtocolVersion, ID: "mat-latency",
		Issuer: xap.IssuerIdentity{ID: "issuer", KID: kid},
		Scope:  xap.ExecutionScope{Unconstrained: []string{xap.ScopeDimensionActions, xap.ScopeDimensionResources}},
		Replay: xap.ReplayProtection{NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2030-01-01T00:00:00Z", InstanceID: "i"},
	}
	if boundMS > 0 {
		mat.Constraints = []xap.Constraint{{ID: "c-lat", Type: "latency_bound", MaxMS: boundMS}}
	}
	mp, err := mat.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	matEnv = signHybrid(t, kid, ec, mlPriv, mp)
	ctx = xap.RuntimeContext{Time: "2026-06-01T00:00:00Z"}
	return matEnv, anchors, ctx, func(rc xap.Receipt) []byte {
		t.Helper()
		p, err := rc.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return signHybrid(t, kid, ec, mlPriv, p)
	}
}

// The receipt's signed evaluation time and the MAT's signed validity interval
// are both in hand, so placing one inside the other asks no clock anything.
// VerifyExpiry sits outside Verify because expiry depends on "now" — sound, and
// it never covered this case, so a receipt evaluated years after its governing
// authority expired verified as valid (¶0065).
func TestEvaluationMustFallInsideTheMATValidityWindow(t *testing.T) {
	ec, mlPub, mlPriv := hybridKeys(t)
	kid := []byte("val-key")
	anchors := xap.NewTrustAnchorSet()
	if err := anchors.AddHybrid(kid, []xap.SignerRole{xap.RoleIssuer, xap.RoleEnforcementPoint}, &ec.PublicKey, mlPub); err != nil {
		t.Fatal(err)
	}
	mat := xap.MAT{
		Version: xap.ProtocolVersion, ID: "mat-window",
		Issuer: xap.IssuerIdentity{ID: "issuer", KID: kid},
		Scope:  xap.ExecutionScope{Unconstrained: []string{xap.ScopeDimensionActions, xap.ScopeDimensionResources}},
		Replay: xap.ReplayProtection{
			NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2026-01-02T00:00:00Z", InstanceID: "i",
		},
	}
	mp, err := mat.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	matEnv := signHybrid(t, kid, ec, mlPriv, mp)

	sign := func(rc xap.Receipt) []byte {
		p, err := rc.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return signHybrid(t, kid, ec, mlPriv, p)
	}

	for _, tc := range []struct {
		name  string
		start string
		want  xap.CheckStatus
	}{
		{"years after expiry", "2030-06-01T00:00:00Z", xap.CheckFailed},
		{"before it became valid", "2025-06-01T00:00:00Z", xap.CheckFailed},
		{"inside the window", "2026-01-01T12:00:00Z", xap.CheckPassed},
		{"unparseable", "not-a-time", xap.CheckFailed},
		{"absent", "", xap.CheckFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rc := xap.Receipt{
				Version: xap.ProtocolVersion, ID: "r", ArtifactID: "mat-window",
				Decision: "permit", ContextDigest: []byte{1},
				Timing: xap.Timing{Start: tc.start, Complete: tc.start},
			}
			res := xap.NewVerifier(anchors).Verify(xap.VerifyInput{
				ReceiptEnvelope: sign(rc), MATEnvelope: matEnv,
			})
			c := checkNamed(t, res, "evaluation_within_validity")
			if c.Status != tc.want {
				t.Fatalf("status = %q, want %q; detail=%q", c.Status, tc.want, c.Detail)
			}
		})
	}
}

// elapsed_ms is the value both latency gates are applied to, and it was taken
// on faith while the two timestamps that refute it sat signed in the same
// struct. Start and Complete were never parsed at all.
func TestTimingMustAgreeWithItself(t *testing.T) {
	ec, mlPub, mlPriv := hybridKeys(t)
	kid := []byte("timing-key")
	anchors := xap.NewTrustAnchorSet()
	if err := anchors.AddHybrid(kid, []xap.SignerRole{xap.RoleEnforcementPoint}, &ec.PublicKey, mlPub); err != nil {
		t.Fatal(err)
	}
	sign := func(tm xap.Timing) []byte {
		rc := xap.Receipt{
			Version: xap.ProtocolVersion, ID: "r", ArtifactID: "mat-1",
			Decision: "permit", ContextDigest: []byte{1}, Timing: tm,
		}
		p, err := rc.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return signHybrid(t, kid, ec, mlPriv, p)
	}

	for _, tc := range []struct {
		name string
		tm   xap.Timing
		want xap.CheckStatus
	}{
		{"elapsed understates a 60s window",
			xap.Timing{Start: "2026-01-01T00:00:00Z", Complete: "2026-01-01T00:01:00Z", ElapsedMS: 5},
			xap.CheckFailed},
		{"elapsed overstates the window",
			xap.Timing{Start: "2026-01-01T00:00:00Z", Complete: "2026-01-01T00:00:01Z", ElapsedMS: 600000},
			xap.CheckFailed},
		{"completion precedes start",
			xap.Timing{Start: "2026-01-01T00:01:00Z", Complete: "2026-01-01T00:00:00Z", ElapsedMS: 0},
			xap.CheckFailed},
		{"negative elapsed",
			xap.Timing{Start: "2026-01-01T00:00:00Z", Complete: "2026-01-01T00:00:00Z", ElapsedMS: -1},
			xap.CheckFailed},
		{"agrees within second-granularity truncation",
			xap.Timing{Start: "2026-01-01T00:00:00Z", Complete: "2026-01-01T00:00:01Z", ElapsedMS: 640},
			xap.CheckPassed},
		{"timestamps withheld",
			xap.Timing{ElapsedMS: 12},
			xap.CheckNotPerformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := xap.NewVerifier(anchors).Verify(xap.VerifyInput{ReceiptEnvelope: sign(tc.tm)})
			c := checkNamed(t, res, "timing_self_consistent")
			if c.Status != tc.want {
				t.Fatalf("status = %q, want %q; detail=%q", c.Status, tc.want, c.Detail)
			}
		})
	}
}

// A speculative evaluation is pending confirmation (¶0078) — a record of
// reasoning, not an authorization. The flag was signed and the verification
// result never mentioned it, so a speculative receipt was indistinguishable
// from a committed one to anyone reading Valid.
func TestSpeculativeReceiptIsNotAFinalAuthorization(t *testing.T) {
	ec, mlPub, mlPriv := hybridKeys(t)
	kid := []byte("spec-key")
	anchors := xap.NewTrustAnchorSet()
	if err := anchors.AddHybrid(kid, []xap.SignerRole{xap.RoleEnforcementPoint}, &ec.PublicKey, mlPub); err != nil {
		t.Fatal(err)
	}
	build := func(spec bool) []byte {
		rc := xap.Receipt{
			Version: xap.ProtocolVersion, ID: "r", ArtifactID: "mat-1",
			Decision: "permit", ContextDigest: []byte{1}, Speculative: spec,
			Timing: xap.Timing{Start: "2026-01-01T00:00:00Z", Complete: "2026-01-01T00:00:00Z"},
		}
		p, err := rc.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return signHybrid(t, kid, ec, mlPriv, p)
	}

	res := xap.NewVerifier(anchors).Verify(xap.VerifyInput{ReceiptEnvelope: build(true)})
	if res.Valid {
		t.Error("a speculative receipt verified as a final authorization")
	}
	if !res.Speculative {
		t.Error("VerificationResult.Speculative is false for a speculative receipt")
	}
	if c := checkNamed(t, res, "receipt_final"); c.Pass {
		t.Errorf("receipt_final passed for a speculative receipt: %s", c.Detail)
	}

	// A settled receipt is unaffected, or the check above says nothing.
	res = xap.NewVerifier(anchors).Verify(xap.VerifyInput{ReceiptEnvelope: build(false)})
	if !res.Valid {
		t.Fatalf("a settled receipt was rejected: %v", res.Failed())
	}
	if res.Speculative {
		t.Error("VerificationResult.Speculative is true for a settled receipt")
	}
}
