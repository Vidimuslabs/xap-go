// Package conformance runs the embedded XAP conformance vectors against the
// reference SDK and reports, per vector, whether the SDK reproduces the
// manifest's expected outcome. The same runner backs the `xap vectors run` CLI
// command and the SDK's conformance test. When the engine lands, it reuses
// these same vectors so that engine-generated receipts verify against this SDK
// verifier — the two-implementation cross-check that proves independent
// verifiability.
package conformance

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	xap "github.com/Vidimuslabs/xap-go"
	"github.com/Vidimuslabs/xap-spec/constants"
	"github.com/Vidimuslabs/xap-spec/vectors"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// Result is the outcome of running one vector.
type Result struct {
	Name   string
	Kind   string
	Pass   bool
	Detail string
}

// BuildAnchors constructs a trust anchor set from the manifest's anchors,
// including the roles each key is registered for. A manifest anchor that names
// no role is an error rather than a key trusted for everything: the corpus has
// to configure a verifier the way an operator would, and "unstated means
// unrestricted" is the reading the role separation exists to remove.
func BuildAnchors(m *vectors.Manifest) (*xap.TrustAnchorSet, error) {
	set := xap.NewTrustAnchorSet()
	for _, a := range m.Anchors {
		roles, err := rolesOf(a)
		if err != nil {
			return nil, err
		}
		kid, err := hex.DecodeString(a.KIDHex)
		if err != nil {
			return nil, fmt.Errorf("anchor kid %q: %w", a.KIDHex, err)
		}
		pub, err := hex.DecodeString(a.PubHex)
		if err != nil {
			return nil, fmt.Errorf("anchor pub %q: %w", a.KIDHex, err)
		}
		switch a.Alg {
		case string(constants.SigEd25519):
			if err := set.AddEd25519(kid, roles, pub); err != nil {
				return nil, fmt.Errorf("anchor %q: %w", a.KIDHex, err)
			}
		case string(constants.SigHybridECDSAP384MLDSA65):
			ec, ml, err := parseHybridPub(pub, a.MLDSAPubHex)
			if err != nil {
				return nil, fmt.Errorf("anchor %q: %w", a.KIDHex, err)
			}
			if err := set.AddHybrid(kid, roles, ec, ml); err != nil {
				return nil, fmt.Errorf("anchor %q: %w", a.KIDHex, err)
			}
		default:
			return nil, fmt.Errorf("anchor %q: unsupported alg %q", a.KIDHex, a.Alg)
		}
		if a.Subject != "" {
			if err := set.SetSubject(kid, a.Subject); err != nil {
				return nil, fmt.Errorf("anchor %q subject: %w", a.KIDHex, err)
			}
		}
	}
	return set, nil
}

// rolesOf maps a manifest anchor's declared roles onto the SDK's role type.
func rolesOf(a vectors.Anchor) ([]xap.SignerRole, error) {
	if len(a.Roles) == 0 {
		return nil, fmt.Errorf("anchor %q declares no signer roles", a.KIDHex)
	}
	out := make([]xap.SignerRole, 0, len(a.Roles))
	for _, r := range a.Roles {
		switch xap.SignerRole(r) {
		case xap.RoleIssuer, xap.RoleEnforcementPoint, xap.RoleAgent:
			out = append(out, xap.SignerRole(r))
		default:
			return nil, fmt.Errorf("anchor %q: unknown signer role %q", a.KIDHex, r)
		}
	}
	return out, nil
}

// parseHybridPub decodes a hybrid anchor's two public keys: the ECDSA P-384 key
// from SPKI DER (pub_hex) and the ML-DSA-65 key from raw bytes (mldsa_pub_hex).
func parseHybridPub(spki []byte, mldsaPubHex string) (*ecdsa.PublicKey, *mldsa65.PublicKey, error) {
	anyPub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ECDSA SPKI: %w", err)
	}
	ec, ok := anyPub.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("ECDSA anchor key is %T, want *ecdsa.PublicKey", anyPub)
	}
	mlBytes, err := hex.DecodeString(mldsaPubHex)
	if err != nil {
		return nil, nil, fmt.Errorf("decode ML-DSA pub: %w", err)
	}
	ml := new(mldsa65.PublicKey)
	if err := ml.UnmarshalBinary(mlBytes); err != nil {
		return nil, nil, fmt.Errorf("parse ML-DSA-65 pub: %w", err)
	}
	return ec, ml, nil
}

// RunAll loads the embedded manifest and runs every vector.
func RunAll() ([]Result, error) {
	m, err := vectors.Load()
	if err != nil {
		return nil, err
	}
	anchors, err := BuildAnchors(m)
	if err != nil {
		return nil, err
	}
	results := make([]Result, 0, len(m.Vectors))
	for _, v := range m.Vectors {
		results = append(results, run(v, anchors))
	}
	return results, nil
}

func run(v vectors.Vector, anchors *xap.TrustAnchorSet) Result {
	pass, detail := dispatch(v, anchors)
	return Result{Name: v.Name, Kind: v.Kind, Pass: pass, Detail: detail}
}

// dispatch interprets a vector by kind and reports whether the SDK reproduces
// the expected outcome (v.Expect is "valid" or "invalid").
func dispatch(v vectors.Vector, anchors *xap.TrustAnchorSet) (bool, string) {
	wantValid := v.Expect == "valid"
	switch v.Kind {
	case "mat":
		return checkExpect(wantValid, matAccepts(v, anchors))
	case "delegation":
		return checkExpect(wantValid, delegationAccepts(v, anchors))
	case "delegation_chain":
		return checkExpect(wantValid, delegationChainAccepts(v, anchors))
	case "canon":
		return canonMatches(v)
	case "receipt":
		return receiptVerifies(v, anchors, wantValid)
	case "commitment_binding":
		return checkExpect(wantValid, commitmentBinds(v, anchors))
	case "provenance":
		return checkExpect(wantValid, provenanceReconstructs(v, anchors))
	default:
		return false, fmt.Sprintf("unknown vector kind %q", v.Kind)
	}
}

// checkExpect turns an accept/err pair into a pass/detail against wantValid.
func checkExpect(wantValid bool, err error) (bool, string) {
	accepted := err == nil
	if accepted == wantValid {
		return true, ""
	}
	if wantValid {
		return false, fmt.Sprintf("expected accept, got error: %v", err)
	}
	return false, "expected rejection, but the vector was accepted"
}

func matAccepts(v vectors.Vector, anchors *xap.TrustAnchorSet) error {
	env, err := loadHex(v.MATFile)
	if err != nil {
		return err
	}
	sm, err := xap.ParseMAT(env, anchors)
	if err != nil {
		return err // signature/structure failure
	}
	if v.At != "" {
		at, err := time.Parse(time.RFC3339, v.At)
		if err != nil {
			return err
		}
		if err := sm.MAT.ValidateAt(at); err != nil {
			return err // lifecycle (e.g. expired)
		}
	}
	return nil
}

func delegationAccepts(v vectors.Vector, anchors *xap.TrustAnchorSet) error {
	penv, err := loadHex(v.ParentMATFile)
	if err != nil {
		return err
	}
	cenv, err := loadHex(v.MATFile)
	if err != nil {
		return err
	}
	parent, err := xap.ParseMAT(penv, anchors)
	if err != nil {
		return err
	}
	child, err := xap.ParseMAT(cenv, anchors)
	if err != nil {
		return err
	}
	return xap.ValidateDerivation(&parent.MAT, &child.MAT)
}

// delegationChainAccepts walks a whole delegation chain, root-first. A chain is
// not the concatenation of its steps: depth allowance is measured against the
// root rather than the immediate parent, acyclicity is a property of the set of
// identities visited, and "chain[0] is a root" is a statement about the sequence
// itself. delegationAccepts can express none of them, so ValidateChain was
// covered by the reference SDK's own tests and by nothing an independent
// implementation could reproduce.
func delegationChainAccepts(v vectors.Vector, anchors *xap.TrustAnchorSet) error {
	if len(v.MATFiles) == 0 {
		return fmt.Errorf("delegation_chain vector %q carries no mat_files", v.Name)
	}
	chain := make([]*xap.MAT, 0, len(v.MATFiles))
	for _, f := range v.MATFiles {
		env, err := loadHex(f)
		if err != nil {
			return err
		}
		sm, err := xap.ParseMAT(env, anchors)
		if err != nil {
			return err
		}
		m := sm.MAT
		chain = append(chain, &m)
	}
	return xap.ValidateChain(chain)
}

func canonMatches(v vectors.Vector) (bool, string) {
	raw, err := vectors.File(v.ContextFile)
	if err != nil {
		return false, err.Error()
	}
	var ctx xap.RuntimeContext
	if err := json.Unmarshal(raw, &ctx); err != nil {
		return false, err.Error()
	}
	got, err := ctx.Digest()
	if err != nil {
		return false, err.Error()
	}
	if hex.EncodeToString(got) != v.ExpectDigestHex {
		return false, fmt.Sprintf("digest %s != expected %s", hex.EncodeToString(got), v.ExpectDigestHex)
	}
	return true, ""
}

// VerifierChecks is every check name xap.Verify can emit. It is the contract
// the completeness gate enforces in both directions: no check may exist without
// a vector that fails it, and no check may be emitted without appearing here.
// Adding a check to the verifier and forgetting the vector is the failure this
// list exists to make impossible — a suite only certifies what a wrong
// implementation fails.
var VerifierChecks = []string{
	"receipt_signature",
	"receipt_version",
	"decision_valid",
	"rationale_codes_known",
	"controls_declared",
	"receipt_final",
	"enforcement_point_binding",
	"policy_digest",
	"replay_receipt_unseen",
	"resource_state_digest",
	"timing_self_consistent",
	"timing_within_bound",
	"timing_within_authorized_bound",
	"mat_signature",
	"artifact_binding",
	"evaluation_within_validity",
	"scope_check",
	"evidence_covers_obligations",
	"evidence_asserted_fresh",
	"context_digest",
	"constraint_outcomes",
	"decision_consistent",
	"chain_link",
	"confirmation_link",
	"commitment_signature",
	"commitment_binding",
	"agent_identity_binding",
	"commitment_scope",
	"compliance_commitment_check",
	"compliance_scope_check",
	"compliance_boundary_check",
	"provenance_agreement",
	"commitment_digest",
	"commitment_temporal",
	"commitment_action_window",
}

// NotPerformedCapableChecks are the checks that can legitimately report
// CheckNotPerformed, because the inputs may not permit re-evaluating them.
// Every one must be pinned as not_performed by some vector's expect_checks:
// the distinction between "not performed" and "passed" produces a receipt that
// verifies either way, so nothing else can hold an implementation to it.
var NotPerformedCapableChecks = []string{
	"scope_check",
	"evidence_covers_obligations",
	"evidence_asserted_fresh",
	"constraint_outcomes",
	"timing_within_authorized_bound",
	"commitment_action_window",
	"timing_self_consistent",
	"agent_identity_binding",
	"enforcement_point_binding",
	"policy_digest",
	"replay_receipt_unseen",
	"resource_state_digest",
	"confirmation_link",
	// The commitment checks that reproduce a claim against the GOVERNING MAT.
	// Before 2026-08-13 these were emitted only when a MAT envelope happened to
	// be supplied and were absent otherwise, which let whoever presents a
	// receipt delete them by omission.
	"commitment_binding",
	"commitment_scope",
	"compliance_scope_check",
	"compliance_boundary_check",
	// Receipt-carried checks that need a caller-supplied input to reproduce.
	// Before 2026-08-13 each was emitted only when its input happened to be
	// present and was silently absent otherwise; xap.receiptCarriedChecks now
	// reconciles them, so each can report not_performed and each needs pinning.
	"artifact_binding",
	"evaluation_within_validity",
	"context_digest",
	"decision_consistent",
	"chain_link",
}

// memorySeenSet is the runner's record of receipts already acted upon. Vectors
// select whether one is supplied and whether it already holds this receipt,
// because freshness is the one property the artifact files cannot express.
type memorySeenSet struct{ seen map[string]bool }

func newSeenSet() *memorySeenSet { return &memorySeenSet{seen: map[string]bool{}} }

func (m *memorySeenSet) Seen(receiptDigest []byte) bool {
	return m.seen[string(receiptDigest)]
}

func (m *memorySeenSet) record(receiptDigest []byte) {
	m.seen[string(receiptDigest)] = true
}

// Coverage records, for each check the verifier emits, which outcomes some
// vector actually drove it to.
//
// Both directions matter and for different reasons. A check no vector drives to
// FAILURE is a check an implementation may simply not perform while reproducing
// every expected outcome — measured before this gate existed, a verifier with
// nine checks removed passed 37/37. A check no vector drives to PASS is the
// mirror image: an implementation that hard-codes it to failed also reproduces
// every expected outcome, because a vector expecting "invalid" cannot tell which
// check made it invalid. That is not hypothetical either. When the chain link
// was redefined in 2026-08-12, the corpus carried only receipt_broken_chain and
// the change went unnoticed at 82/82.
//
// A suite certifies a check only when it pins both answers.
type Coverage struct {
	// Emitted is every check name the verifier produced for some vector.
	Emitted map[string]bool
	// Passed, Failed and NotPerformed record which statuses were observed.
	Passed       map[string]bool
	Failed       map[string]bool
	NotPerformed map[string]bool
}

// CheckCoverage runs every receipt vector through the verifier and records which
// outcomes each check was driven to.
func CheckCoverage(anchors *xap.TrustAnchorSet, m *vectors.Manifest) (Coverage, error) {
	cov := Coverage{
		Emitted:      map[string]bool{},
		Passed:       map[string]bool{},
		Failed:       map[string]bool{},
		NotPerformed: map[string]bool{},
	}
	for _, v := range m.Vectors {
		if v.Kind != "receipt" || v.ReceiptFile == "" {
			continue
		}
		in, err := buildVerifyInput(v, anchors)
		if err != nil {
			return Coverage{}, fmt.Errorf("vector %q: %w", v.Name, err)
		}
		for _, c := range xap.NewVerifier(anchors).Verify(in).Checks {
			cov.Emitted[c.Name] = true
			switch c.Status {
			case xap.CheckPassed:
				cov.Passed[c.Name] = true
			case xap.CheckFailed:
				cov.Failed[c.Name] = true
			case xap.CheckNotPerformed:
				cov.NotPerformed[c.Name] = true
			}
		}
	}
	return cov, nil
}

// buildVerifyInput assembles the optional inputs a receipt vector supplies.
func buildVerifyInput(v vectors.Vector, anchors *xap.TrustAnchorSet) (xap.VerifyInput, error) {
	in := xap.VerifyInput{}
	var err error
	if in.ReceiptEnvelope, err = loadHex(v.ReceiptFile); err != nil {
		return in, err
	}
	switch v.Replay {
	case "":
		// No seen-set: the replay checks report not performed.
	case "fresh":
		in.Replay = newSeenSet()
	case "seen":
		set := newSeenSet()
		if err := preloadSeen(set, v); err != nil {
			return in, err
		}
		in.Replay = set
	default:
		return in, fmt.Errorf("unknown replay mode %q", v.Replay)
	}
	if v.MATFile != "" {
		if in.MATEnvelope, err = loadHex(v.MATFile); err != nil {
			return in, err
		}
	}
	if v.CommitmentFile != "" {
		if in.CommitmentEnvelope, err = loadHex(v.CommitmentFile); err != nil {
			return in, err
		}
	}
	if v.ContextFile != "" {
		ctx, err := loadContext(v.ContextFile)
		if err != nil {
			return in, err
		}
		in.ReproducedContext = ctx
	}
	if v.ConfirmedReceiptFile != "" {
		env, err := loadHex(v.ConfirmedReceiptFile)
		if err != nil {
			return in, err
		}
		cr, err := xap.ParseReceipt(env, anchors)
		if err != nil {
			return in, fmt.Errorf("confirmed receipt: %w", err)
		}
		in.ConfirmedReceipt = cr
	}
	if v.PriorReceiptFile != "" {
		penv, err := loadHex(v.PriorReceiptFile)
		if err != nil {
			return in, err
		}
		pr, err := xap.ParseReceipt(penv, anchors)
		if err != nil {
			return in, fmt.Errorf("prior receipt: %w", err)
		}
		in.PriorReceipt = pr
	}
	return in, nil
}

func receiptVerifies(v vectors.Vector, anchors *xap.TrustAnchorSet, wantValid bool) (bool, string) {
	// Through buildVerifyInput, not a second copy of the same assembly. There
	// were two, and they drifted the moment a vector gained an input the
	// coverage walk knew about and the vector run did not — the replay seen-set
	// was read by one and silently ignored by the other, so a vector could pin a
	// check the run never exercised.
	in, err := buildVerifyInput(v, anchors)
	if err != nil {
		return false, err.Error()
	}

	res := xap.NewVerifier(anchors).Verify(in)
	if res.Valid != wantValid {
		return false, fmt.Sprintf("verify.Valid=%v want %v (failed: %s)", res.Valid, wantValid, strings.Join(res.Failed(), ","))
	}

	// When the vector pins individual check statuses, confirm each one. This is
	// how a vector states WHY it reached its outcome rather than only that it
	// did — and the only way to pin "not performed", which produces a receipt
	// that verifies exactly as a spurious pass would.
	for name, want := range v.ExpectChecks {
		got, ok := namedCheck(res, name)
		if !ok {
			return false, fmt.Sprintf("expected check %q was not emitted at all", name)
		}
		if string(got.Status) != want {
			return false, fmt.Sprintf("check %q status=%q want %q (%s)",
				name, got.Status, want, got.Detail)
		}
	}

	// When the vector names an expected rationale/error code, confirm the
	// signature-bound record carries it.
	if v.ExpectCode != "" {
		sr, err := xap.ParseReceipt(in.ReceiptEnvelope, anchors)
		if err != nil {
			return false, err.Error()
		}
		if !hasCode(sr.Receipt, v.ExpectCode) {
			return false, fmt.Sprintf("receipt does not carry expected code %q", v.ExpectCode)
		}
	}
	return true, ""
}

func commitmentBinds(v vectors.Vector, anchors *xap.TrustAnchorSet) error {
	cenv, err := loadHex(v.CommitmentFile)
	if err != nil {
		return err
	}
	menv, err := loadHex(v.MATFile)
	if err != nil {
		return err
	}
	sc, err := xap.ParseCommitment(cenv, anchors)
	if err != nil {
		return err
	}
	sm, err := xap.ParseMAT(menv, anchors)
	if err != nil {
		return err
	}
	return sc.Commitment.VerifyBinding(&sm.MAT)
}

func provenanceReconstructs(v vectors.Vector, anchors *xap.TrustAnchorSet) error {
	receipts := make([]*xap.Receipt, 0, len(v.ReceiptFiles))
	for _, f := range v.ReceiptFiles {
		env, err := loadHex(f)
		if err != nil {
			return err
		}
		sr, err := xap.ParseReceipt(env, anchors)
		if err != nil {
			return err
		}
		r := sr.Receipt
		receipts = append(receipts, &r)
	}
	_, err := xap.ReconstructProvenance(receipts)
	return err
}

func hasCode(r xap.Receipt, code string) bool {
	for _, c := range r.RationaleCodes {
		if c == code {
			return true
		}
	}
	if r.CommitmentCompliance != nil && r.CommitmentCompliance.Code == code {
		return true
	}
	return false
}

func loadHex(name string) ([]byte, error) {
	raw, err := vectors.File(name)
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(strings.TrimSpace(string(raw)))
}

func loadContext(name string) (*xap.RuntimeContext, error) {
	raw, err := vectors.File(name)
	if err != nil {
		return nil, err
	}
	var ctx xap.RuntimeContext
	if err := json.Unmarshal(raw, &ctx); err != nil {
		return nil, err
	}
	return &ctx, nil
}

// namedCheck returns the check with the given name, if the verifier emitted it.
func namedCheck(res xap.VerificationResult, name string) (xap.Check, bool) {
	for _, c := range res.Checks {
		if c.Name == name {
			return c, true
		}
	}
	return xap.Check{}, false
}

// DerivationPaths is every named failure path a delegation or delegation_chain
// vector can hold an implementation to. It plays the role VerifierChecks plays
// for the receipt-verification surface, and for the same measured reason: with
// only the four invariant sentinels to aim at, six delegation strictness paths
// could be deleted from the SDK while the corpus and the completeness gate both
// stayed green.
//
// chain.empty is deliberately absent: a vector expressing it would carry no
// mat_files, which the runner rejects before ValidateChain ever sees it.
var DerivationPaths = []string{
	xap.FaultScopeUnconstrainedEscalation,
	xap.FaultScopeActionsUnstated,
	xap.FaultScopeResourcesUnstated,
	xap.FaultScopeActionNotCovered,
	xap.FaultScopeResourceNotCovered,
	xap.FaultScopeTraversalUnconstrained,

	xap.FaultBoundaryMaxImpact,
	xap.FaultBoundaryMaxPrivilegeDelta,
	xap.FaultBoundaryQuotaDropped,
	xap.FaultBoundaryQuotaExceeded,
	xap.FaultBoundaryQuotaNotInParent,
	xap.FaultBoundaryExclusionDropped,

	xap.FaultConstraintDropped,
	xap.FaultConstraintTypeMismatch,
	xap.FaultConstraintLooserPrefix + "temporal",
	xap.FaultConstraintLooserPrefix + "network_zone",
	xap.FaultConstraintLooserPrefix + "rate_limit",
	xap.FaultConstraintLooserPrefix + "latency_bound",
	xap.FaultConstraintLooserPrefix + "param_bound",
	xap.FaultConstraintLooserPrefix + "resource_state",

	xap.FaultObligationMissing,
	xap.FaultObligationLoosened,

	xap.FaultDelegationNotAllowed,

	xap.FaultChainNotRoot,
	xap.FaultChainLinkBreak,
	xap.FaultChainCycle,
	xap.FaultChainDepthUnstated,
	xap.FaultChainDepthExceeded,
}

// DerivationCoverage runs every delegation and delegation_chain vector that
// expects a rejection and reports which named failure paths were reached.
func DerivationCoverage(anchors *xap.TrustAnchorSet, m *vectors.Manifest) (map[string]bool, error) {
	reached := map[string]bool{}
	for _, v := range m.Vectors {
		if v.Expect != "invalid" {
			continue
		}
		var err error
		switch v.Kind {
		case "delegation":
			err = delegationAccepts(v, anchors)
		case "delegation_chain":
			err = delegationChainAccepts(v, anchors)
		default:
			continue
		}
		if err == nil {
			return nil, fmt.Errorf("vector %q expects a rejection but was accepted", v.Name)
		}
		if p := xap.FaultPath(err); p != "" {
			reached[p] = true
		} else {
			return nil, fmt.Errorf("vector %q was rejected without a named fault path: %v", v.Name, err)
		}
	}
	return reached, nil
}

// preloadSeen marks the vector's own receipt as already acted upon, so the
// verifier meets it as a replay.
func preloadSeen(set *memorySeenSet, v vectors.Vector) error {
	env, err := loadHex(v.ReceiptFile)
	if err != nil {
		return err
	}
	payload, err := xap.UnverifiedPayload(env)
	if err != nil {
		return err
	}
	r, err := xap.UnmarshalReceipt(payload)
	if err != nil {
		return err
	}
	d, err := r.Digest()
	if err != nil {
		return err
	}
	set.record(d)
	return nil
}
