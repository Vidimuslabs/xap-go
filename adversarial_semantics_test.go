package xap_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	xap "github.com/Vidimuslabs/xap-go"
)

// This round drives hostile artifacts through the full Verify state machine.
// Everything here is correctly signed by a trusted key, so every failure below
// must come from a semantic check — the state machine refusing to be lied to
// about timing, controls, identities, replay, or scope — rather than from
// cryptography. That is the property a relying party actually depends on: the
// signature proves WHO spoke, and only these checks prove the statement is
// internally consistent.

// adversarialKit mints one enforcement-point key (subject "ep-alpha") and one
// issuer key, so hostile receipts and hostile MATs can both be signed and
// trusted simultaneously.
type adversarialKit struct {
	anchors *xap.TrustAnchorSet
	epPriv  ed25519.PrivateKey
	issPriv ed25519.PrivateKey
	epKID   []byte
	issKID  []byte
}

func newAdversarialKit(t *testing.T) *adversarialKit {
	t.Helper()
	anchors := xap.NewTrustAnchorSet()

	epKID := []byte("ep-alpha")
	epPub, epPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := anchors.AddEd25519(epKID, []xap.SignerRole{xap.RoleEnforcementPoint}, epPub); err != nil {
		t.Fatal(err)
	}
	if err := anchors.SetSubject(epKID, "ep-alpha"); err != nil {
		t.Fatal(err)
	}

	issKID := []byte("iss-adhoc")
	issPub, issPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := anchors.AddEd25519(issKID, []xap.SignerRole{xap.RoleIssuer}, issPub); err != nil {
		t.Fatal(err)
	}
	return &adversarialKit{anchors: anchors, epPriv: epPriv, issPriv: issPriv, epKID: epKID, issKID: issKID}
}

func (k *adversarialKit) signReceipt(t *testing.T, rc xap.Receipt) []byte {
	t.Helper()
	payload, err := rc.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return signEd25519(t, k.epKID, k.epPriv, payload)
}

func (k *adversarialKit) signMAT(t *testing.T, m xap.MAT) []byte {
	t.Helper()
	m.Issuer.KID = k.issKID
	payload, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return signEd25519(t, k.issKID, k.issPriv, payload)
}

// baselineReceipt is a minimalReceipt bound to the kit's enforcement point, so
// the baseline verifies clean through the subject-checked anchor.
func (k *adversarialKit) baselineReceipt() xap.Receipt {
	rc := minimalReceipt()
	rc.EnforcementPoint = "ep-alpha"
	rc.EnforcementPointKID = k.epKID
	return rc
}

// hostileMAT is a structurally valid MAT the hostile receipts govern under.
func hostileMAT() xap.MAT {
	return xap.MAT{
		Version: xap.ProtocolVersion, ID: "mat-adversarial",
		Issuer: xap.IssuerIdentity{ID: "iss-adhoc"},
		Replay: xap.ReplayProtection{
			NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z",
			Nonce: []byte{0xA, 0xD}, InstanceID: "mat-adversarial",
		},
	}
}

// mustFailNamed asserts the verification refuted the receipt and names the
// expected check among its failures.
func mustFailNamed(t *testing.T, res xap.VerificationResult, want string) {
	t.Helper()
	if res.Valid {
		t.Fatalf("hostile receipt verified; wanted %q among the failures", want)
	}
	for _, f := range res.Failed() {
		if f == want {
			return
		}
	}
	t.Fatalf("verification failed but not via %q; failures: %v", want, res.Failed())
}

func TestHostileReceiptSemanticSweep(t *testing.T) {
	k := newAdversarialKit(t)
	ok := k.baselineReceipt()
	okEnv := signReceiptFrom(t, k, ok)
	if _, err := xap.ParseReceipt(okEnv, k.anchors); err != nil {
		t.Fatalf("baseline receipt does not parse: %v", err)
	}
	if res := xap.NewVerifier(k.anchors).Verify(xap.VerifyInput{ReceiptEnvelope: okEnv}); !res.Valid {
		t.Fatalf("baseline receipt failed before mutation: %v", res.Failed())
	}

	// Unknown rationale code under a permit.
	h := ok
	h.RationaleCodes = []string{"CONSTRAINT_EVALUATION_FAILURE", "XAP_MADE_UP_CODE"}
	mustFailNamed(t, k.verify(t, h), "rationale_codes_known")

	// permit_with_controls with no controls: the exemption without the thing
	// that earns it.
	h = ok
	h.Decision = "permit_with_controls"
	mustFailNamed(t, k.verify(t, h), "controls_declared")

	// A denial that names controls it never needed.
	h = ok
	h.Decision = "deny"
	h.Controls = []string{"human_approval"}
	mustFailNamed(t, k.verify(t, h), "controls_declared")

	// Unrecognized decision value.
	h = ok
	h.Decision = "abstain"
	mustFailNamed(t, k.verify(t, h), "decision_valid")

	// Wrong protocol version.
	h = ok
	h.Version = "xap-0.0.0-preview"
	mustFailNamed(t, k.verify(t, h), "receipt_version")

	// Negative elapsed time.
	h = ok
	h.Timing.ElapsedMS = -1
	mustFailNamed(t, k.verify(t, h), "timing_self_consistent")

	// Completion before start.
	h = ok
	h.Timing.Start, h.Timing.Complete = "2026-08-17T00:00:01Z", "2026-08-17T00:00:00Z"
	mustFailNamed(t, k.verify(t, h), "timing_self_consistent")

	// Elapsed contradicting the declared window by more than the 1s tolerance.
	h = ok
	h.Timing.ElapsedMS = 60_000
	mustFailNamed(t, k.verify(t, h), "timing_self_consistent")

	// Elapsed exceeding the receipt's own declared bound.
	h = ok
	h.Timing.MaxMS = 100
	mustFailNamed(t, k.verify(t, h), "timing_within_bound")

	// A negative declared bound, which no elapsed value can satisfy.
	h = ok
	h.Timing.MaxMS = -1
	mustFailNamed(t, k.verify(t, h), "timing_within_bound")

	// Enforcement point name contradicting the operator's anchor subject.
	h = ok
	h.EnforcementPoint = "ep-impersonated"
	h.EnforcementPointKID = k.epKID
	mustFailNamed(t, k.verify(t, h), "enforcement_point_binding")

	// A receipt naming a DIFFERENT key as its enforcement point than the one
	// that signed it.
	h = ok
	h.EnforcementPoint = "ep-alpha"
	h.EnforcementPointKID = []byte("some-other-key")
	mustFailNamed(t, k.verify(t, h), "enforcement_point_binding")

	// Speculative evaluation presented as an authorization.
	h = ok
	h.Speculative = true
	res := k.verify(t, h)
	mustFailNamed(t, res, "receipt_final")
	if !res.Speculative {
		t.Fatal("result did not surface the speculative flag")
	}

	// A reproduced context that does not hash to the carried digest.
	h = ok
	ctx := xap.RuntimeContext{Time: "2026-08-17T00:00:00Z"}
	mustFailNamed(t, k.verifyCtx(t, h, &ctx), "context_digest")

	// A resource-state digest whose named keys the reproduced context does not
	// carry: not-performed, never a pass or a quiet fail.
	h = ok
	h.ResourceStateDigest = bytes.Repeat([]byte{7}, 32)
	h.ResourceKeys = []string{"absent"}
	res = k.verifyCtx(t, h, &ctx)
	if !notPerformedIncludes(res, "resource_state_digest") {
		t.Fatalf("wanted resource_state_digest reported not-performed; got failures %v not-performed %v",
			res.Failed(), res.NotPerformed)
	}
}

func notPerformedIncludes(res xap.VerificationResult, name string) bool {
	for _, n := range res.NotPerformed {
		if n == name {
			return true
		}
	}
	return false
}

// seenSet is the caller's record of receipts already acted on.
type seenSet map[string]bool

func (s seenSet) Seen(digest []byte) bool { return s[string(digest)] }

func TestHostileReplayAndConfirmation(t *testing.T) {
	k := newAdversarialKit(t)
	ok := k.baselineReceipt()
	env := signReceiptFrom(t, k, ok)

	seen := seenSet{}
	res := xap.NewVerifier(k.anchors).Verify(xap.VerifyInput{ReceiptEnvelope: env, Replay: seen})
	if !res.Valid {
		t.Fatalf("first presentation failed: %v", res.Failed())
	}

	// The caller records having ACTED ON the receipt, then the same receipt is
	// presented again: the second look must be refused.
	d, err := ok.Digest()
	if err != nil {
		t.Fatal(err)
	}
	seen[string(d)] = true
	res = xap.NewVerifier(k.anchors).Verify(xap.VerifyInput{ReceiptEnvelope: env, Replay: seen})
	mustFailNamed(t, res, "replay_receipt_unseen")

	// Confirmation: a receipt claiming to settle a speculative evaluation it
	// does not name.
	spec := ok
	spec.ID = "r-spec"
	spec.Speculative = true
	conf := ok
	conf.ID = "r-confirms"
	conf.Confirms = bytes.Repeat([]byte{9}, 32)
	confEnv := signReceiptFrom(t, k, conf)
	specSigned := parseSigned(t, k, signReceiptFrom(t, k, spec))
	res = xap.NewVerifier(k.anchors).Verify(xap.VerifyInput{
		ReceiptEnvelope: confEnv, ConfirmedReceipt: specSigned,
	})
	mustFailNamed(t, res, "confirmation_link")

	// A receipt claiming to settle the RIGHT speculative receipt confirms
	// cleanly: the check is a comparison, not a refusal.
	want, werr := spec.Digest()
	if werr != nil {
		t.Fatal(werr)
	}
	conf.Confirms = want
	confEnv = signReceiptFrom(t, k, conf)
	res = xap.NewVerifier(k.anchors).Verify(xap.VerifyInput{
		ReceiptEnvelope: confEnv, ConfirmedReceipt: specSigned,
	})
	for _, f := range res.Failed() {
		if f == "confirmation_link" {
			t.Fatalf("correct confirmation rejected: %v", res.Failed())
		}
	}
}

// TestHostileMATBoundReceipts drives receipt+MAT pairs where the receipt is
// internally fine and the PAIR is the lie.
func TestHostileMATBoundReceipts(t *testing.T) {
	k := newAdversarialKit(t)
	matEnv := k.signMAT(t, hostileMAT())

	ok := k.baselineReceipt()

	// A receipt permitting outside the MAT's (empty) scope.
	res := xap.NewVerifier(k.anchors).Verify(xap.VerifyInput{ReceiptEnvelope: signReceiptFrom(t, k, ok), MATEnvelope: matEnv})
	mustFailNamed(t, res, "scope_check")

	// Unconstrained scope, but a resource carrying a traversal segment.
	m := hostileMAT()
	m.Scope = xap.ExecutionScope{Actions: []string{"write"}, Resources: []string{"db/*"}}
	env2 := k.signMAT(t, m)
	h := ok
	h.Action, h.Resource = "write", "db/users"
	res = xap.NewVerifier(k.anchors).Verify(xap.VerifyInput{ReceiptEnvelope: signReceiptFrom(t, k, h), MATEnvelope: env2})
	if !res.Valid {
		t.Fatalf("in-scope permit failed unexpectedly: %v", res.Failed())
	}
	h.Resource = "db/../secrets"
	res = xap.NewVerifier(k.anchors).Verify(xap.VerifyInput{ReceiptEnvelope: signReceiptFrom(t, k, h), MATEnvelope: env2})
	if res.Valid {
		t.Fatal("traversal resource permitted under a db/* scope")
	}

	// A latency bound the receipt widens.
	m = hostileMAT()
	m.Scope = xap.ExecutionScope{Actions: []string{"write"}, Resources: []string{"db/*"}}
	m.Constraints = []xap.Constraint{{ID: "lat", Type: "latency_bound", MaxMS: 100}}
	env3 := k.signMAT(t, m)
	h = ok
	h.Action, h.Resource = "write", "db/users"
	h.Timing.MaxMS = 10_000
	res = xap.NewVerifier(k.anchors).Verify(xap.VerifyInput{ReceiptEnvelope: signReceiptFrom(t, k, h), MATEnvelope: env3})
	mustFailNamed(t, res, "timing_within_authorized_bound")

	// Evaluation outside the MAT's validity window.
	h = ok
	h.Timing = xap.Timing{Start: "2028-01-01T00:00:00Z", Complete: "2028-01-01T00:00:01Z", ElapsedMS: 1000}
	res = xap.NewVerifier(k.anchors).Verify(xap.VerifyInput{ReceiptEnvelope: signReceiptFrom(t, k, h), MATEnvelope: matEnv})
	mustFailNamed(t, res, "evaluation_within_validity")

	// A constraint outcome naming a constraint the MAT does not state.
	m = hostileMAT()
	m.Scope = xap.ExecutionScope{Actions: []string{"write"}, Resources: []string{"db/*"}}
	m.Constraints = []xap.Constraint{{ID: "zone", Type: "network_zone", Zones: []string{"dmz"}}}
	env4 := k.signMAT(t, m)
	h = ok
	h.Action, h.Resource = "write", "db/users"
	h.ConstraintOutcomes = []xap.ConstraintOutcome{{ConstraintID: "ghost-constraint", Satisfied: true}}
	ctx := xap.RuntimeContext{Time: "2026-08-17T00:00:00Z", NetworkZone: "dmz"}
	res = xap.NewVerifier(k.anchors).Verify(xap.VerifyInput{
		ReceiptEnvelope: signReceiptFrom(t, k, h), MATEnvelope: env4, ReproducedContext: &ctx,
	})
	mustFailNamed(t, res, "constraint_outcomes")

	// Permitting while the reproduced context refutes the constraint.
	h = ok
	h.Action, h.Resource = "write", "db/users"
	h.ConstraintOutcomes = []xap.ConstraintOutcome{{ConstraintID: "zone", Satisfied: true}}
	ctx.NetworkZone = "internet"
	res = xap.NewVerifier(k.anchors).Verify(xap.VerifyInput{
		ReceiptEnvelope: signReceiptFrom(t, k, h), MATEnvelope: env4, ReproducedContext: &ctx,
	})
	mustFailNamed(t, res, "decision_consistent")

	// Permitting while disclosing evidence that misses the obliged category:
	// disclosure makes the claim readable, and partial disclosure is not a pass.
	// (Zero references is selective disclosure — not-performed — by design.)
	m = hostileMAT()
	m.Scope = xap.ExecutionScope{Actions: []string{"write"}, Resources: []string{"db/*"}}
	m.ProofObligations = []xap.ProofObligation{{Category: "tpm_quote", MaxAgeSeconds: 300}}
	env5 := k.signMAT(t, m)
	h = ok
	h.Action, h.Resource = "write", "db/users"
	h.EvidenceRefs = []xap.EvidenceRef{{Category: "tee_report", Digest: bytes.Repeat([]byte{2}, 32), Fresh: true}}
	res = xap.NewVerifier(k.anchors).Verify(xap.VerifyInput{ReceiptEnvelope: signReceiptFrom(t, k, h), MATEnvelope: env5})
	mustFailNamed(t, res, "evidence_covers_obligations")

	// Evidence referenced but recorded not-fresh under a permit.
	h.EvidenceRefs = []xap.EvidenceRef{{Category: "tpm_quote", Digest: bytes.Repeat([]byte{3}, 32), Fresh: false}}
	res = xap.NewVerifier(k.anchors).Verify(xap.VerifyInput{ReceiptEnvelope: signReceiptFrom(t, k, h), MATEnvelope: env5})
	mustFailNamed(t, res, "evidence_asserted_fresh")
}

// TestMixedSeparatorTraversalIsCoveredByNothing pins the traversal predicate
// against separator mixing. hasTraversal's contract says ".." on EITHER
// separator is a traversal; a string that mixes them ("db/..\x") hides the
// segment from a split on either separator alone, and on consumers that
// normalise both (every Windows path consumer), it escapes. Every mixed form
// must be treated as a traversal everywhere the predicate is consulted:
// enumerated scopes, unconstrained scopes, parent-pattern coverage, and the
// resource-only variant.
func TestMixedSeparatorTraversalIsCoveredByNothing(t *testing.T) {
	mixed := []string{`db/..\x`, `db\../x`, `db/..\..\x`, `db\x/..`, `..\db/x`}

	enumerated := xap.MAT{Scope: xap.ExecutionScope{
		Actions: []string{"write"}, Resources: []string{"db/*"},
	}}
	unconstrained := xap.MAT{Scope: xap.ExecutionScope{
		Actions:       []string{"write"},
		Unconstrained: []string{xap.ScopeDimensionResources},
	}}
	star := xap.MAT{Scope: xap.ExecutionScope{
		Actions: []string{"write"}, Resources: []string{"db/*", "*"},
	}}

	for _, r := range mixed {
		for name, m := range map[string]xap.MAT{"enumerated": enumerated, "unconstrained": unconstrained, "star-pattern": star} {
			if err := m.CoversOperation("write", r); err == nil {
				t.Errorf("%s scope accepted mixed-separator traversal %q", name, r)
			}
		}
	}

	// The delegation parent-coverage path consults the same predicate.
	for _, r := range mixed {
		parent := &xap.MAT{ID: "p", Delegation: xap.DelegationRights{Allowed: true, MaxDepth: 2},
			Scope: xap.ExecutionScope{Resources: []string{"db/*"}}}
		child := &xap.MAT{ID: "c", Scope: xap.ExecutionScope{Resources: []string{r}}}
		if err := xap.ValidateDerivation(parent, child); err == nil {
			t.Errorf("delegation accepted child resource %q under db/* parent", r)
		}
	}
}

// --- helpers ---------------------------------------------------------------

func signReceiptFrom(t *testing.T, k *adversarialKit, rc xap.Receipt) []byte {
	t.Helper()
	return k.signReceipt(t, rc)
}

func (k *adversarialKit) verify(t *testing.T, rc xap.Receipt) xap.VerificationResult {
	t.Helper()
	return xap.NewVerifier(k.anchors).Verify(xap.VerifyInput{ReceiptEnvelope: k.signReceipt(t, rc)})
}

func (k *adversarialKit) verifyCtx(t *testing.T, rc xap.Receipt, ctx *xap.RuntimeContext) xap.VerificationResult {
	t.Helper()
	return xap.NewVerifier(k.anchors).Verify(xap.VerifyInput{
		ReceiptEnvelope: k.signReceipt(t, rc), ReproducedContext: ctx,
	})
}

func parseSigned(t *testing.T, k *adversarialKit, env []byte) *xap.SignedReceipt {
	t.Helper()
	sr, err := xap.ParseReceipt(env, k.anchors)
	if err != nil {
		t.Fatal(err)
	}
	return sr
}
