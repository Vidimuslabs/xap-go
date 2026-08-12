package xap

import (
	"bytes"
	"fmt"
	"time"

	"github.com/Vidimuslabs/xap-go/canonical"
	"github.com/Vidimuslabs/xap-spec/constants"
)

// Verifier performs independent verification of a cryptographic proof structure
// (¶0095 Execution Receipt Verification State Machine). It is constructed with a
// trust anchor set and nothing else: verification succeeds — or fails — using
// only the receipt, optionally the governing MAT and reproduced context, and
// the public anchors, with zero access to enforcement point internal state
// (¶0017). This zero-state property is why the type lives in the public SDK.
type Verifier struct {
	Anchors *TrustAnchorSet
}

// NewVerifier returns a Verifier over the given anchor set.
func NewVerifier(anchors *TrustAnchorSet) *Verifier {
	return &Verifier{Anchors: anchors}
}

// VerifyInput carries the receipt under verification plus whatever optional
// inputs the caller can reproduce. The verifier does as much as the inputs
// allow: with only the receipt envelope it checks signature, structure, codes,
// and timing; with the governing MAT it binds the receipt to the artifact and
// (with a reproduced context) recomputes the context digest and per-constraint
// outcomes (¶0095); with a prior receipt it checks the chain link (¶0063); with
// a commitment object it checks commitment binding and digest (¶0084A).
type VerifyInput struct {
	// ReceiptEnvelope is the COSE_Sign1 receipt (required).
	ReceiptEnvelope []byte
	// MATEnvelope is the COSE_Sign1 governing MAT (optional).
	MATEnvelope []byte
	// ReproducedContext is the runtime context reproduced by the verifier
	// (optional). When present, the context digest and constraint outcomes are
	// recomputed and compared.
	ReproducedContext *RuntimeContext
	// PriorReceipt is the immediately preceding receipt in the chain (optional).
	PriorReceipt *SignedReceipt
	// ConfirmedReceipt is the speculative receipt this one claims to settle
	// (optional, ¶0078). Supplying it lets the verifier check the claim rather
	// than read it.
	ConfirmedReceipt *SignedReceipt
	// CommitmentEnvelope is the COSE_Sign1 governing commitment object (optional).
	CommitmentEnvelope []byte
	// Replay is an optional record of receipts this relying party has already
	// ACTED ON, consulted to detect a receipt presented twice.
	//
	// Freshness is the one property that cannot be established from signed
	// artifacts alone: deciding whether something has been seen before means
	// remembering. ¶0017 forbids depending on ENFORCEMENT-POINT state and says
	// nothing about the verifier's own, so a relying party that remembers what
	// it accepted learns nothing from the issuer by doing so.
	//
	// Absent, the check reports NOT PERFORMED — the honest answer for a caller
	// that kept no record.
	Replay ReplaySeenSet
}

// ReplaySeenSet reports whether a receipt has already been acted upon.
//
// The interface is deliberately query-only, and the unit is deliberately the
// RECEIPT. Both were wrong in the first version of this API and the reasons are
// worth keeping.
//
// Query-only: Verify used to record what it saw, which made verification a
// mutation. Verifying the same receipt twice — auditing your own log, or two
// components checking one artifact — then reported the second look as a replay.
// A replay guard should be updated when a receipt is ACTED ON, which only the
// caller knows, not when it is inspected.
//
// Per-receipt: the MAT's replay nonce identifies the ARTIFACT, and one artifact
// authorizes many operations, each producing its own receipt. Keying replay on
// it flagged every receipt after the first under the same MAT — so walking an
// append-only log, the ordinary auditing case, failed from the second entry
// onward. A commitment's session id has the same shape: a session has many
// actions. The receipt is the only unit whose second presentation is
// necessarily a replay rather than ordinary use.
type ReplaySeenSet interface {
	// Seen reports whether a receipt with this digest has already been acted on.
	Seen(receiptDigest []byte) bool
}

// CheckStatus is the outcome of one verification step. A check is not a
// boolean. "Not performed" is a third answer, and §9 spends a paragraph on why
// it must not be collapsed into the first: reporting an unavailable check as
// passed asserts a gate that was never applied. Pass carried both meanings, so
// the distinction the spec insists on existed only in the detail string.
type CheckStatus string

const (
	// CheckPassed: the check ran and the receipt satisfied it.
	CheckPassed CheckStatus = "passed"
	// CheckFailed: the check ran and the receipt did not satisfy it.
	CheckFailed CheckStatus = "failed"
	// CheckNotPerformed: the inputs did not permit re-evaluating this check.
	// The receipt is not refuted by it and is not vouched for by it either.
	CheckNotPerformed CheckStatus = "not_performed"
)

// Check is one named verification step and its outcome. JSON tags match the
// VerificationResult schema in the xap-spec OpenAPI.
type Check struct {
	Name string `json:"name"`
	// Pass is false only for CheckFailed. A not-performed check does not
	// invalidate a receipt, so it reports true here — which is exactly why
	// Status exists alongside it.
	Pass   bool        `json:"pass"`
	Status CheckStatus `json:"status"`
	Detail string      `json:"detail,omitempty"`
}

// VerificationResult is the output of the verification state machine. JSON tags
// match the xap-spec OpenAPI VerificationResult schema (lowercase), so the
// server's /verify response is contract-accurate.
type VerificationResult struct {
	Valid      bool   `json:"valid"`
	ArtifactID string `json:"artifact_id"`
	Decision   string `json:"decision"`
	// NotPerformed names every check the inputs did not permit re-evaluating.
	//
	// Valid answers "was anything refuted", not "how much was established", and
	// those diverge: a receipt disclosing almost nothing is Valid because
	// nothing contradicted it. Round 3 found the sharper form — where the party
	// who benefits from a check not running is the party who controls whether it
	// can run, not-performed is a downgrade they select. Individual cases are
	// fixed by making the obligation-bearing ones fail instead (see
	// identitiesAgree), but a relying party still needs to see the shape of what
	// went unchecked without walking Checks itself, and to be able to require a
	// minimum before acting.
	NotPerformed []string `json:"not_performed,omitempty"`
	// Speculative reports that the receipt records a speculative evaluation
	// pending confirmation (¶0078) rather than a settled authorization. It is
	// surfaced as its own field, not left to a caller to dig out of the receipt,
	// because the difference between "this was authorized" and "this was being
	// considered" is the difference a verification result exists to state.
	Speculative bool    `json:"speculative"`
	Checks      []Check `json:"checks"`
}

// Failed returns the names of the checks that did not pass.
func (v VerificationResult) Failed() []string {
	var out []string
	for _, c := range v.Checks {
		if !c.Pass {
			out = append(out, c.Name)
		}
	}
	return out
}

// The chain link (¶0063, FIG. 11) is Receipt.Digest — a digest over the
// canonical receipt payload. It was SHA-256 over the COSE envelope bytes, which
// cannot carry the property the chain needs.
//
// A COSE_Sign1 envelope has no unique encoding for a given signed receipt. Two
// separate mechanisms give an attacker holding no key material a second,
// byte-distinct envelope that verifies identically:
//
//   - ECDSA admits both (r, s) and (r, n-s), and neither Go's ecdsa.Verify nor
//     the composite hybrid verifier restricts s to the low half. Rewriting s
//     leaves both signature halves valid.
//   - The COSE unprotected header bucket is by construction not covered by the
//     signature, so entries may be added or removed freely.
//
// Either rewrite changes the envelope hash while leaving a fully valid receipt,
// which turns "the chain broke" into a statement a log holder can manufacture
// about receipts nobody tampered with — and makes envelope-hash equality
// useless as a dedup or replay key. Low-s canonicalization alone does not fix
// it; the header bucket is malleable independently.
//
// So the link is defined over content the signature actually covers. The
// payload is canonical by construction (¶0085) and now canonical by
// verification (see canonical.Unmarshal), so one receipt has exactly one link
// hash, and it is the same value whether computed from the decoded receipt or
// from the payload bytes as signed.

// Verify runs the verification state machine over the given input and returns a
// structured result. It never panics on malformed input; every failure is a
// non-passing Check with Valid=false.
func (v *Verifier) Verify(in VerifyInput) VerificationResult {
	res := VerificationResult{Valid: true}
	addStatus := func(name string, status CheckStatus, detail string) {
		res.Checks = append(res.Checks, Check{
			Name: name, Pass: status != CheckFailed, Status: status, Detail: detail,
		})
		switch status {
		case CheckFailed:
			res.Valid = false
		case CheckNotPerformed:
			res.NotPerformed = append(res.NotPerformed, name)
		}
	}
	add := func(name string, pass bool, detail string) {
		if pass {
			addStatus(name, CheckPassed, detail)
			return
		}
		addStatus(name, CheckFailed, detail)
	}
	notPerformed := func(name, detail string) { addStatus(name, CheckNotPerformed, detail) }

	// (1) Receipt signature (¶0095: validate cryptographic signatures).
	sr, err := ParseReceipt(in.ReceiptEnvelope, v.Anchors)
	if err != nil {
		add("receipt_signature", false, err.Error())
		return res // nothing further is meaningful without a verified receipt
	}
	add("receipt_signature", true, "")
	rc := sr.Receipt
	res.ArtifactID = rc.ArtifactID
	res.Decision = rc.Decision

	// (2) Structural sanity: version, ternary decision, known codes.
	add("receipt_version", rc.Version == ProtocolVersion,
		fmt.Sprintf("version=%q", rc.Version))
	add("decision_valid", constants.Decision(rc.Decision).Valid(),
		fmt.Sprintf("decision=%q", rc.Decision))
	codesOK, badCode := allKnownCodes(rc.RationaleCodes)
	add("rationale_codes_known", codesOK, badCode)

	// permit_with_controls is the only decision that may permit an operation
	// whose constraints did not all hold: the controls are what compensate
	// (¶0049). A receipt claiming that decision while naming no control claims
	// the exemption without the thing that earns it — and nothing looked, since
	// Controls had no reader in the SDK at all.
	//
	// Checked here rather than beside the reproduced context because it is a
	// property of the receipt alone: it holds or fails with no MAT, no context
	// and no other artifact, which is the strongest form the check can take.
	controlled := constants.Decision(rc.Decision) == constants.DecisionPermitWithControls
	switch {
	case controlled && len(rc.Controls) == 0:
		add("controls_declared", false,
			"decision is permit_with_controls but the receipt names no control")
	case !controlled && len(rc.Controls) > 0:
		add("controls_declared", false, fmt.Sprintf(
			"decision is %q but the receipt names controls %v", rc.Decision, rc.Controls))
	default:
		add("controls_declared", true,
			fmt.Sprintf("decision=%q controls=%d", rc.Decision, len(rc.Controls)))
	}

	// Replay: has this exact receipt already been acted upon? Consulted, never
	// updated — see VerifyInput.Replay for why verification must not mutate.
	if in.Replay == nil {
		notPerformed("replay_receipt_unseen", "caller supplied no record of accepted receipts")
	} else if d, derr := rc.Digest(); derr != nil {
		add("replay_receipt_unseen", false, fmt.Sprintf("digest receipt: %v", derr))
	} else if in.Replay.Seen(d) {
		add("replay_receipt_unseen", false, fmt.Sprintf("receipt %s has already been acted on", rc.ID))
	} else {
		add("replay_receipt_unseen", true, "receipt not previously acted on")
	}

	// A speculative evaluation is pending confirmation (¶0078) — a record of
	// reasoning, not an authorization to act on. The flag is signed, and the
	// verification result never mentioned it, so a speculative receipt was
	// indistinguishable from a committed one to anyone reading Valid.
	//
	// It fails rather than reporting not-performed: nothing is missing here, the
	// receipt says plainly what it is. A caller that wants speculative receipts
	// reads the Speculative field and ignores this one check, which is a
	// decision it has to take deliberately — the direction a fail-closed
	// protocol should make easy.
	res.Speculative = rc.Speculative
	if rc.Speculative {
		add("receipt_final", false,
			"receipt is a speculative evaluation pending confirmation (¶0078)")
	} else {
		add("receipt_final", true, "receipt records a settled decision")
	}

	// The receipt names its enforcement point. Binding that NAME needs a
	// statement from someone other than the enforcement point, because it
	// chooses both the name it writes and the key it signs with — comparing its
	// declared kid against its own signing key compares two values it picked,
	// and can only catch a signer harming itself. The operator's anchor set is
	// the outside statement: where an anchor records a subject, a receipt naming
	// a different enforcement point is refused.
	//
	// One emission, in precedence order. A kid that contradicts the signing key
	// is definite and settles it; otherwise an unpinned anchor means the missing
	// input is the OPERATOR's rather than something the artifact withheld, which
	// is not-performed under the rule in §9.1.
	anchor, haveAnchor := v.Anchors.Get(sr.SigningKID)
	switch {
	case len(rc.EnforcementPointKID) > 0 && !bytes.Equal(rc.EnforcementPointKID, sr.SigningKID):
		add("enforcement_point_binding", false, fmt.Sprintf(
			"receipt declares enforcement point key %x but was signed by %x",
			rc.EnforcementPointKID, sr.SigningKID))
	case !haveAnchor || anchor.Subject == "":
		notPerformed("enforcement_point_binding",
			"the verifying anchor records no subject, so the receipt's enforcement point name is unverifiable")
	case rc.EnforcementPoint == "":
		add("enforcement_point_binding", false, fmt.Sprintf(
			"the signing key is registered to %q and the receipt names no enforcement point", anchor.Subject))
	case rc.EnforcementPoint != anchor.Subject:
		add("enforcement_point_binding", false, fmt.Sprintf(
			"receipt claims enforcement point %q but was signed by the key registered to %q",
			rc.EnforcementPoint, anchor.Subject))
	default:
		add("enforcement_point_binding", true, fmt.Sprintf(
			"enforcement point %q signed by the key the operator registered to it", rc.EnforcementPoint))
	}

	// (3) Timing against the bound the receipt declares (¶0053, ¶0088). This is
	// self-consistency only: both sides come from the receipt. The bound the
	// MAT actually authorized is checked in (4d), where the MAT is available.
	add("timing_within_bound", rc.Timing.MaxMS == 0 || rc.Timing.ElapsedMS <= rc.Timing.MaxMS,
		fmt.Sprintf("elapsed=%dms max=%dms", rc.Timing.ElapsedMS, rc.Timing.MaxMS))

	// elapsed_ms is the number every latency gate is applied to, and it was
	// taken on faith while the two values that would refute it sat signed in the
	// same struct. A receipt could claim 5ms across a window an hour wide.
	status, detail := timingSelfConsistent(rc.Timing)
	addStatus("timing_self_consistent", status, detail)

	// (4) Governing MAT: signature, structure, artifact binding.
	var mat *MAT
	if in.MATEnvelope != nil {
		sm, err := ParseMAT(in.MATEnvelope, v.Anchors)
		if err != nil {
			add("mat_signature", false, err.Error())
		} else {
			add("mat_signature", true, "")
			mat = &sm.MAT
			add("artifact_binding", rc.ArtifactID == mat.ID,
				fmt.Sprintf("receipt.artifact_id=%q mat.id=%q", rc.ArtifactID, mat.ID))
		}
	}

	// (4b) Scope & boundary, recomputed (¶0046). This is pipeline step 2 — the
	// gate whose exceedance denies unconditionally regardless of every constraint
	// outcome — so leaving it to the enforcement point's assertion would leave the
	// strongest check in the protocol unverifiable. It is reproducible only when
	// the receipt names the operation; receipts that omit action and resource
	// (selective disclosure, ¶0079, or issuers predating those fields) are
	// reported as not checked rather than silently passing.
	if mat != nil {
		switch {
		case !mat.ScopeReproducible(rc.Action, rc.Resource):
			// Not merely "both absent": a receipt naming an action while
			// withholding the resource cannot have its resource evaluated
			// either, and reporting that as passed would assert a gate that was
			// never applied to the dimension in question.
			notPerformed("scope_check", fmt.Sprintf(
				"receipt discloses action=%q resource=%q, insufficient to re-evaluate the scope this MAT constrains",
				rc.Action, rc.Resource))
		default:
			err := mat.CoversOperation(rc.Action, rc.Resource)
			permitted := constants.Decision(rc.Decision) != constants.DecisionDeny
			// An out-of-scope operation must have been denied. A denial of an
			// in-scope operation is legitimate — some other gate fired.
			if err != nil && permitted {
				add("scope_check", false,
					fmt.Sprintf("receipt permits an operation outside scope: %v", err))
			} else if err != nil {
				add("scope_check", true,
					fmt.Sprintf("denied, and outside scope: %v", err))
			} else {
				add("scope_check", true,
					fmt.Sprintf("action=%q resource=%q within scope", rc.Action, rc.Resource))
			}
		}
	}

	// (4c) Integrity evidence — the two reproducible parts, and only those
	// (§9, ¶0048). Pipeline step 4 validates evidence against the MAT's proof
	// obligations at execution time, and most of that is not re-observable: the
	// receipt carries a digest of the evidence rather than the evidence, and
	// EvidenceRef has no timestamp, so max_age_seconds has nothing to evaluate
	// against and the freshness determination itself cannot be reproduced.
	//
	// Two things can. Every category the MAT obliges must appear among the
	// receipt's evidence references, and each such reference must record
	// fresh = true. Neither says the evidence was good — they say the receipt's
	// own account of it is internally consistent with the artifact governing
	// it. The check names avoid claiming otherwise: nothing here reports
	// integrity as verified, which §9 forbids in as many words.
	//
	// Disclosure follows the same rule as the scope check. A receipt that
	// discloses no evidence references at all has exercised selective
	// disclosure (¶0071, ¶0079), and the checks are reported NOT PERFORMED
	// rather than failed. Once it discloses any, it is making a claim about
	// coverage that can be read, and partial disclosure is not a pass.
	//
	// And the same asymmetry as scope_check and commitment_scope: a receipt
	// that DENIES on uncovered or stale evidence is the enforcement point doing
	// exactly what ¶0048 requires. Only a receipt that permitted anyway is
	// self-inconsistent.
	if mat != nil && len(mat.ProofObligations) > 0 {
		permitted := constants.Decision(rc.Decision) != constants.DecisionDeny
		if len(rc.EvidenceRefs) == 0 {
			notPerformed("evidence_covers_obligations",
				"receipt discloses no evidence references")
			notPerformed("evidence_asserted_fresh",
				"receipt discloses no evidence references")
		} else {
			byCategory := make(map[string]EvidenceRef, len(rc.EvidenceRefs))
			for _, e := range rc.EvidenceRefs {
				byCategory[e.Category] = e
			}
			var uncovered, stale []string
			for _, o := range mat.ProofObligations {
				e, ok := byCategory[o.Category]
				if !ok {
					uncovered = append(uncovered, o.Category)
					continue
				}
				if !e.Fresh {
					stale = append(stale, o.Category)
				}
			}
			switch {
			case len(uncovered) == 0:
				add("evidence_covers_obligations", true, "every obliged category is referenced")
			case !permitted:
				add("evidence_covers_obligations", true,
					fmt.Sprintf("denied, and obligations unreferenced: %v", uncovered))
			default:
				add("evidence_covers_obligations", false, fmt.Sprintf(
					"receipt permits without referencing obliged evidence: %v", uncovered))
			}
			switch {
			case len(stale) == 0:
				add("evidence_asserted_fresh", true, "every referenced obligation records fresh=true")
			case !permitted:
				add("evidence_asserted_fresh", true,
					fmt.Sprintf("denied, and evidence records fresh=false: %v", stale))
			default:
				add("evidence_asserted_fresh", false, fmt.Sprintf(
					"receipt permits on evidence its own reference records as not fresh: %v", stale))
			}
		}
	}

	// (4d) The latency bound the MAT actually authorized (¶0051, ¶0053, ¶0088).
	//
	// timing_within_bound above compares the receipt's elapsed time to the
	// receipt's own max_ms — both sides supplied by the artifact under
	// judgement, which makes it a self-consistency check and nothing more. The
	// authorized bound lives in the MAT, as a latency_bound constraint, and
	// Constraint.MaxMS's own documentation says it is "consumed by the engine's
	// latency path and by the verifier's timing check". Nothing read it.
	//
	// The gap had the shape the rest of this review keeps finding: max_ms is
	// omitempty and 0 means unbounded, so the most permissive latency grant was
	// the one requiring the least typing. Note the asymmetry it produced —
	// delegation goes to real trouble to stop a CHILD MAT widening this bound
	// (constraintAtLeastAsStrict, which refuses a child that sets MaxMS to 0),
	// and then a receipt could ignore the bound outright by declaring none.
	if mat != nil {
		switch bound, ok := authorizedLatencyBound(mat); {
		case !ok:
			notPerformed("timing_within_authorized_bound",
				"the governing MAT states no latency_bound constraint")
		case rc.Timing.MaxMS == 0:
			add("timing_within_authorized_bound", false, fmt.Sprintf(
				"receipt declares no latency bound under a MAT authorizing %dms", bound))
		case rc.Timing.MaxMS > bound:
			add("timing_within_authorized_bound", false, fmt.Sprintf(
				"receipt declares max_ms=%dms, wider than the %dms its MAT authorizes",
				rc.Timing.MaxMS, bound))
		case rc.Timing.ElapsedMS > bound:
			add("timing_within_authorized_bound", false, fmt.Sprintf(
				"evaluation took %dms against an authorized bound of %dms",
				rc.Timing.ElapsedMS, bound))
		default:
			add("timing_within_authorized_bound", true, fmt.Sprintf(
				"elapsed=%dms within the %dms the MAT authorizes", rc.Timing.ElapsedMS, bound))
		}
	}

	// (4d2) The constraint-compilation digest (¶0076), now that it is defined
	// over the portable constraint representation rather than an engine's
	// internal form. It binds the receipt to the exact constraint set it was
	// evaluated under, which a receipt naming a different compilation cannot
	// satisfy.
	if mat != nil {
		if len(rc.PolicyDigest) == 0 {
			notPerformed("policy_digest", "receipt discloses no policy digest")
		} else if want, err := mat.ConstraintDigest(); err != nil {
			add("policy_digest", false, fmt.Sprintf("compute constraint digest: %v", err))
		} else {
			add("policy_digest", bytes.Equal(rc.PolicyDigest, want),
				"receipt.policy_digest vs the governing MAT's constraint set")
		}
	}

	// (4f) The evaluation happened while the authority was valid (¶0065).
	//
	// VerifyExpiry exists but sits outside Verify, on the stated grounds that
	// expiry depends on "now", which is the verifier's clock and not part of the
	// signed receipt. That reasoning is sound and does not cover this: the
	// receipt's own Timing.Start is signed, the MAT's validity interval is
	// signed, and comparing them asks no clock anything. A receipt evaluated
	// four years after its governing MAT expired verified as valid.
	//
	// This is the pipeline's lifecycle gate (¶0065 makes expired artifacts an
	// unconditional rejection), so an unparseable evaluation time fails rather
	// than excusing itself — the same fail-closed reading MAT.Expired already
	// takes on its own timestamps.
	if mat != nil {
		status, detail := withinWindow(rc.Timing.Start,
			mat.Replay.NotBefore, mat.Replay.NotAfter, "MAT "+mat.ID)
		addStatus("evaluation_within_validity", status, detail)
	}

	// (5) Runtime context digest + reproduced constraint outcomes (¶0010,
	// ¶0095: recompute and compare).
	if in.ReproducedContext != nil {
		got, err := in.ReproducedContext.Digest()
		if err != nil {
			add("context_digest", false, err.Error())
		} else {
			add("context_digest", bytes.Equal(got, rc.ContextDigest),
				"recomputed context digest vs receipt")
		}
		// The optimistic-concurrency digest (¶0054) is reproducible now that the
		// receipt names the keys it was computed over. Without them a verifier
		// holding the whole context still could not select the same subset.
		switch {
		case len(rc.ResourceStateDigest) == 0:
			notPerformed("resource_state_digest", "receipt discloses no resource state digest")
		case len(rc.ResourceKeys) == 0:
			notPerformed("resource_state_digest",
				"receipt carries a resource state digest but does not name the keys it covers")
		default:
			// A key the reproduced context does not carry cannot be
			// reproduced, and quietly dropping it would recompute over a
			// SMALLER set than the receipt names — reporting pass or fail on a
			// set neither side agreed to.
			selected := make(map[string]string, len(rc.ResourceKeys))
			var absent []string
			for _, k := range rc.ResourceKeys {
				v, ok := in.ReproducedContext.ResourceState[k]
				if !ok {
					absent = append(absent, k)
					continue
				}
				selected[k] = v
			}
			if len(absent) > 0 {
				notPerformed("resource_state_digest", fmt.Sprintf(
					"reproduced context does not carry %v, so the digest cannot be recomputed over the keys the receipt names", absent))
			} else if got, err := canonical.DigestBytes(selected); err != nil {
				add("resource_state_digest", false, err.Error())
			} else {
				add("resource_state_digest", bytes.Equal(got, rc.ResourceStateDigest),
					fmt.Sprintf("recomputed over %d disclosed key(s)", len(rc.ResourceKeys)))
			}
		}

		if mat != nil {
			status, detail := recomputeOutcomes(mat, *in.ReproducedContext, rc)
			addStatus("constraint_outcomes", status, detail)
			consistent, why := decisionConsistent(mat, *in.ReproducedContext, rc)
			add("decision_consistent", consistent, fmt.Sprintf("decision=%q: %s", rc.Decision, why))
		}
	}

	// Confirmation of a speculative evaluation (¶0078). A receipt naming what it
	// settles is making a checkable claim, so it is checked rather than read —
	// otherwise `confirms` joins the fields that are signed, carried, and
	// evaluated by nobody, which is the defect this review started from.
	switch {
	case len(rc.Confirms) == 0 && in.ConfirmedReceipt == nil:
		notPerformed("confirmation_link", "receipt does not claim to confirm a speculative evaluation")
	case in.ConfirmedReceipt == nil:
		notPerformed("confirmation_link",
			"receipt claims to confirm a speculative evaluation, but the confirmed receipt was not supplied")
	case len(rc.Confirms) == 0:
		add("confirmation_link", false,
			"a confirmed receipt was supplied but this receipt claims to confirm nothing")
	case rc.Speculative:
		add("confirmation_link", false,
			"a speculative receipt cannot itself be a confirmation")
	case !in.ConfirmedReceipt.Receipt.Speculative:
		add("confirmation_link", false, fmt.Sprintf(
			"receipt %s is presented as confirmed but is not speculative",
			in.ConfirmedReceipt.Receipt.ID))
	default:
		want, derr := in.ConfirmedReceipt.Receipt.Digest()
		switch {
		case derr != nil:
			add("confirmation_link", false, fmt.Sprintf("digest confirmed receipt: %v", derr))
		case !bytes.Equal(rc.Confirms, want):
			add("confirmation_link", false, fmt.Sprintf(
				"receipt.confirms does not name receipt %s", in.ConfirmedReceipt.Receipt.ID))
		default:
			add("confirmation_link", true, fmt.Sprintf(
				"settles the speculative evaluation recorded by receipt %s",
				in.ConfirmedReceipt.Receipt.ID))
		}
	}

	// (6) Chain link to the prior receipt (¶0063).
	if in.PriorReceipt != nil {
		want, err := in.PriorReceipt.Receipt.Digest()
		if err != nil {
			add("chain_link", false, fmt.Sprintf("digest prior receipt: %v", err))
		} else {
			add("chain_link", bytes.Equal(rc.PriorReceiptHash, want),
				"receipt.prior_hash vs digest(prior receipt)")
		}
	}

	// (7) Commitment binding + digest (¶0084A).
	if in.CommitmentEnvelope != nil {
		sc, err := ParseCommitment(in.CommitmentEnvelope, v.Anchors)
		if err != nil {
			add("commitment_signature", false, err.Error())
		} else {
			add("commitment_signature", true, "")
			if mat != nil {
				add("commitment_binding", sc.Commitment.VerifyBinding(mat) == nil,
					"commitment constraint digest vs governing MAT")

				// A commitment narrows the authority it binds to; it may declare
				// less than the MAT granted, never more. Nothing reproduced that,
				// so COMMITMENT_SCOPE_VIOLATION was an assertion a verifier could
				// read but not reach. Same asymmetry as scope_check: an
				// over-claiming commitment invalidates a receipt that PERMITTED
				// under it, while a denial is the enforcement point doing exactly
				// what ¶0095A requires and stays consistent.
				switch err := sc.Commitment.WithinScopeOf(mat); {
				case err == nil:
					add("commitment_scope", true, "declared action set within the governing MAT")
				case constants.Decision(rc.Decision) == constants.DecisionDeny:
					add("commitment_scope", true, fmt.Sprintf("denied, and commitment over-claims: %v", err))
				default:
					add("commitment_scope", false, fmt.Sprintf(
						"receipt permits under a commitment that exceeds its governing MAT: %v", err))
				}
			}
			// commitment_compliance is a set of booleans the enforcement point
			// asserts about checks it says it ran. Three of them are things an
			// independent party can recompute from the commitment and the MAT,
			// and until now none was: a receipt could claim scope_check = true
			// for an action plainly outside its MAT's scope and nothing looked.
			// An assertion about a reproducible fact is either right or it is a
			// lie, so this is symmetric — unlike scope_check, a denial does not
			// excuse a false claim.
			if ac := rc.CommitmentCompliance; ac != nil && ac.Action != "" && mat != nil {
				wantCommitment := sc.Commitment.DeclaredActions.Covers(ac.Action, "") == nil
				add("compliance_commitment_check", ac.CommitmentCheck == wantCommitment,
					fmt.Sprintf("claimed %v, recomputed %v for action %q",
						ac.CommitmentCheck, wantCommitment, ac.Action))

				wantScope := mat.CoversOperation(ac.Action, "") == nil
				add("compliance_scope_check", ac.ScopeCheck == wantScope,
					fmt.Sprintf("claimed %v, recomputed %v for action %q",
						ac.ScopeCheck, wantScope, ac.Action))

				wantBoundary := !contains(mat.Boundary.Exclusions, ac.Action)
				add("compliance_boundary_check", ac.BoundaryCheck == wantBoundary,
					fmt.Sprintf("claimed %v, recomputed %v for action %q",
						ac.BoundaryCheck, wantBoundary, ac.Action))
			}
			// A receipt's provenance and its governing commitment's provenance
			// name the same parent, or one of them is wrong. Verify() referenced
			// the receipt's provenance nowhere at all: the field was signed,
			// carried, and checked only by ReconstructProvenance, which a caller
			// has to know to invoke separately. Anyone verifying a receipt the
			// ordinary way learned nothing about the chain it claims.
			if rp := rc.Provenance; rp != nil {
				cp := sc.Commitment.Provenance
				switch {
				case cp == nil:
					add("provenance_agreement", false,
						"receipt claims provenance but the governing commitment declares none")
				case rp.ParentArtifactID != cp.ParentArtifactID:
					add("provenance_agreement", false, fmt.Sprintf(
						"receipt names parent artifact %q, commitment names %q",
						rp.ParentArtifactID, cp.ParentArtifactID))
				case !bytes.Equal(rp.ParentCommitmentDigest, cp.ParentCommitmentDigest):
					add("provenance_agreement", false,
						"receipt and commitment disagree on the parent commitment digest")
				default:
					add("provenance_agreement", true, "receipt provenance matches the governing commitment")
				}
			}
			// The commitment declares when it may be presented (¶0095B), and
			// ValidateTemporal existed to check it while Verify never called it —
			// the same gap as the MAT's interval, in a second artifact. Where the
			// commitment also declares an action window, that is the narrower
			// statement about when the action itself may occur, and it had no
			// reader anywhere in the SDK.
			// temporal_validity is a REQUIRED field of a commitment (¶0095B), so
			// an absent one is a malformed commitment rather than an undisclosed
			// one. That distinction is what stops not-performed becoming a
			// downgrade the agent selects: an agent signs its own commitment, so
			// leaving out the window it is bound by would otherwise remove the
			// check rather than fail it. Same rule as identitiesAgree.
			cs, cd := withinWindow(rc.Timing.Start,
				sc.Commitment.TemporalValidity.NotBefore, sc.Commitment.TemporalValidity.NotAfter,
				"commitment "+sc.Commitment.ID)
			if cs == CheckNotPerformed {
				cs, cd = CheckFailed, fmt.Sprintf(
					"commitment %s declares no temporal validity, which ¶0095B requires of it",
					sc.Commitment.ID)
			}
			addStatus("commitment_temporal", cs, cd)
			if w := sc.Commitment.ActionWindow; w != nil {
				ws, wd := withinWindow(rc.Timing.Start, w.NotBefore, w.NotAfter,
					"commitment "+sc.Commitment.ID+"'s action window")
				addStatus("commitment_action_window", ws, wd)
			} else {
				notPerformed("commitment_action_window", "the commitment declares no action window")
			}

			// The MAT names the machine or agent identity it grants authority
			// TO (field 122, ¶0041); the commitment names the agent it was
			// generated BY (¶0095B). If those disagree, the commitment is not
			// the one this artifact governs — an agent presenting a commitment
			// under someone else's authority. Both are signed and both were
			// carried; neither was ever compared to the other.
			if mat != nil {
				as, ad := identitiesAgree(sc.Commitment.AgentIdentity, mat.MachineIdentity)
				addStatus("agent_identity_binding", as, ad)
			}

			if len(rc.CommitmentDigest) > 0 {
				cd, derr := sc.Commitment.Digest()
				add("commitment_digest", derr == nil && bytes.Equal(cd, rc.CommitmentDigest),
					"receipt.commitment_digest vs commitment object")
			}
		}
	}

	return res
}

func allKnownCodes(codes []string) (bool, string) {
	for _, c := range codes {
		if !constants.KnownCode(c) {
			return false, fmt.Sprintf("unknown code %q", c)
		}
	}
	return true, ""
}

// recomputeOutcomes recomputes each recorded constraint outcome from the
// reproduced context and the MAT's constraint set, confirming the receipt's
// recorded outcome matches an independent evaluation (¶0095). Outcomes are
// matched by constraint ID.
//
// It reports a status rather than a boolean because "every outcome the receipt
// recorded was right" and "every constraint the MAT states was checked" are
// different claims, and the loop only ever established the first. A receipt
// recording no outcomes at all satisfied it vacuously — the check passed by
// having nothing to disagree with, which is the reading CheckNotPerformed
// exists to prevent.
//
// Silence about a constraint is legitimate (selective disclosure, ¶0071,
// ¶0079). It is simply not a pass.
func recomputeOutcomes(mat *MAT, ctx RuntimeContext, rc Receipt) (CheckStatus, string) {
	byID := make(map[string]Constraint, len(mat.Constraints))
	for _, c := range mat.Constraints {
		byID[c.ID] = c
	}
	recorded := make(map[string]bool, len(rc.ConstraintOutcomes))
	for _, rec := range rc.ConstraintOutcomes {
		c, ok := byID[rec.ConstraintID]
		if !ok {
			return CheckFailed, fmt.Sprintf("receipt references unknown constraint %q", rec.ConstraintID)
		}
		if got := c.Evaluate(ctx); got != rec.Satisfied {
			return CheckFailed, fmt.Sprintf("constraint %q recomputed=%v recorded=%v", rec.ConstraintID, got, rec.Satisfied)
		}
		recorded[rec.ConstraintID] = true
	}
	var missing []string
	for _, c := range mat.Constraints {
		if !recorded[c.ID] {
			missing = append(missing, c.ID)
		}
	}
	if len(missing) > 0 {
		return CheckNotPerformed, fmt.Sprintf(
			"receipt records no outcome for %v, so those constraints were not re-evaluated", missing)
	}
	if len(mat.Constraints) == 0 {
		return CheckNotPerformed, "the governing MAT states no constraints"
	}
	return CheckPassed, fmt.Sprintf("all %d recorded outcomes match an independent evaluation", len(mat.Constraints))
}

// decisionConsistent checks that the recorded decision is consistent with an
// independent evaluation of the constraint set against the reproduced context
// (¶0047, ¶0049).
//
// A permit requires every constraint to hold. A deny is consistent with
// anything — it may arise from any unconditional-denial path. A
// permit_with_controls permits an operation whose constraints did not all hold,
// but only because the controls compensate, so it is consistent exactly when
// controls are named; the earlier form returned true for every decision that
// was not exactly "permit", which handed the same exemption to a receipt that
// named none.
func decisionConsistent(mat *MAT, ctx RuntimeContext, rc Receipt) (bool, string) {
	switch constants.Decision(rc.Decision) {
	case constants.DecisionDeny:
		return true, "denials are consistent with any constraint state"
	case constants.DecisionPermitWithControls:
		if len(rc.Controls) == 0 {
			return false, "permit_with_controls excuses a failing constraint only through the controls it applies, and none are named"
		}
		return true, fmt.Sprintf("permitted under %d compensating control(s)", len(rc.Controls))
	}
	for _, c := range mat.Constraints {
		if !c.Evaluate(ctx) {
			return false, fmt.Sprintf("permit, but constraint %q does not hold in the reproduced context", c.ID)
		}
	}
	return true, "permit, and every constraint holds"
}

// VerifyExpiry is a convenience lifecycle check the caller may run against the
// governing MAT before Verify; expired artifacts are unconditionally rejected
// (¶0065). It is separate from Verify because expiry depends on "now", which is
// the verifier's clock, not part of the signed receipt.
func VerifyExpiry(mat *MAT, at time.Time) error {
	return mat.ValidateAt(at)
}

// authorizedLatencyBound returns the evaluation latency budget the MAT grants,
// in milliseconds, and whether it states one at all.
//
// A MAT may carry more than one latency_bound constraint; the budget in force is
// the strictest of them, since satisfying the artifact means satisfying every
// constraint it states rather than the most generous one. A constraint with
// MaxMS == 0 states no bound and is skipped rather than read as "unbounded" —
// the same reading delegation already refuses when a child tries it.
func authorizedLatencyBound(mat *MAT) (int64, bool) {
	var bound int64
	for _, c := range mat.Constraints {
		if c.Type != "latency_bound" || c.MaxMS <= 0 {
			continue
		}
		if bound == 0 || c.MaxMS < bound {
			bound = c.MaxMS
		}
	}
	return bound, bound > 0
}

// withinWindow reports whether an RFC3339 instant falls inside an RFC3339
// validity interval, for the two comparisons a verifier can make between one
// signed artifact's evaluation time and another's declared lifetime.
//
// Both values are signed, so no verifier clock is involved and the answer is
// the same for everyone who ever checks it. An absent interval is NOT
// PERFORMED — there is nothing to compare against, and reporting that as a pass
// would assert a lifetime gate that was never applied. An absent or malformed
// instant fails: this is ¶0065's lifecycle gate, where an artifact that cannot
// be shown to be in force is treated as out of force.
func withinWindow(instant, notBefore, notAfter, subject string) (CheckStatus, string) {
	if notBefore == "" && notAfter == "" {
		return CheckNotPerformed, subject + " declares no validity interval"
	}
	if instant == "" {
		return CheckFailed, "receipt records no evaluation start time to place against " + subject
	}
	at, err := time.Parse(time.RFC3339, instant)
	if err != nil {
		return CheckFailed, fmt.Sprintf("evaluation start %q is not RFC3339: %v", instant, err)
	}
	if notBefore != "" {
		nb, err := time.Parse(time.RFC3339, notBefore)
		if err != nil {
			return CheckFailed, fmt.Sprintf("%s not_before %q is not RFC3339: %v", subject, notBefore, err)
		}
		if at.Before(nb) {
			return CheckFailed, fmt.Sprintf("evaluated %s, before %s becomes valid at %s", instant, subject, notBefore)
		}
	}
	if notAfter != "" {
		na, err := time.Parse(time.RFC3339, notAfter)
		if err != nil {
			return CheckFailed, fmt.Sprintf("%s not_after %q is not RFC3339: %v", subject, notAfter, err)
		}
		if at.After(na) {
			return CheckFailed, fmt.Sprintf("evaluated %s, after %s expired at %s", instant, subject, notAfter)
		}
	}
	return CheckPassed, fmt.Sprintf("evaluated %s, inside %s's validity interval", instant, subject)
}

// timingClockSkewToleranceMS is how far ElapsedMS may sit from the Start..Complete
// span before the two are treated as contradicting each other.
//
// RFC3339 permits second granularity, so a signer recording whole-second
// timestamps and a sub-second elapsed measurement disagrees by up to a second
// through truncation alone, with nothing wrong. Anything wider is the receipt
// disagreeing with itself.
const timingClockSkewToleranceMS = 1000

// timingSelfConsistent checks the receipt's timing against itself: completion
// does not precede start, elapsed is not negative, and elapsed agrees with the
// window the same receipt declares.
//
// Start and Complete were never parsed. ElapsedMS is the value both latency
// gates are applied to, so a receipt understating it escaped a bound it had
// visibly exceeded — while carrying, signed, the two timestamps that refute the
// claim. Timestamps are optional under selective disclosure (¶0079), so their
// absence is not performed rather than failed; what is present must agree.
func timingSelfConsistent(t Timing) (CheckStatus, string) {
	if t.ElapsedMS < 0 {
		return CheckFailed, fmt.Sprintf("elapsed_ms is negative (%d)", t.ElapsedMS)
	}
	if t.Start == "" || t.Complete == "" {
		return CheckNotPerformed, "receipt does not disclose both start and complete"
	}
	start, err := time.Parse(time.RFC3339, t.Start)
	if err != nil {
		return CheckFailed, fmt.Sprintf("timing.start %q is not RFC3339: %v", t.Start, err)
	}
	complete, err := time.Parse(time.RFC3339, t.Complete)
	if err != nil {
		return CheckFailed, fmt.Sprintf("timing.complete %q is not RFC3339: %v", t.Complete, err)
	}
	if complete.Before(start) {
		return CheckFailed, fmt.Sprintf("evaluation completed %s, before it started %s", t.Complete, t.Start)
	}
	span := complete.Sub(start).Milliseconds()
	diff := span - t.ElapsedMS
	if diff < 0 {
		diff = -diff
	}
	if diff > timingClockSkewToleranceMS {
		return CheckFailed, fmt.Sprintf(
			"elapsed_ms=%d contradicts a start..complete window of %dms", t.ElapsedMS, span)
	}
	return CheckPassed, fmt.Sprintf("elapsed_ms=%d agrees with a %dms window", t.ElapsedMS, span)
}

// identitiesAgree compares a commitment's agent identity with the machine
// identity its governing MAT authorizes.
//
// Comparison is by canonical digest rather than field by field: MachineIdentity
// nests (a composite identity carries a list of them), and a hand-written
// comparison would silently ignore whichever nested field it forgot.
//
// Absence is where this gets interesting, and the first version got it wrong.
// Reporting NOT PERFORMED whenever either side is silent handed the agent a
// downgrade: an agent signs its own commitment, so an agent operating under a
// MAT that authorizes SOMEONE ELSE could omit its identity and the binding
// simply would not run. Naming the wrong agent failed; naming nobody passed.
//
// The rule that separates the two cases: NOT PERFORMED is for a VERIFIER
// lacking inputs, not for an artifact withholding what it was obliged to
// provide. When the MAT names the identity it authorizes, it has imposed an
// obligation, and a commitment that declines to answer has not left the binding
// unavailable — it has defeated it. That fails. Only when the MAT itself names
// no identity is there genuinely nothing to bind.
func identitiesAgree(agent, authorized MachineIdentity) (CheckStatus, string) {
	if identityUnset(authorized) {
		return CheckNotPerformed,
			"the governing MAT names no machine identity, so there is nothing to bind to"
	}
	if identityUnset(agent) {
		return CheckFailed,
			"the governing MAT authorizes a specific machine identity and the commitment names none"
	}
	a, err := canonical.DigestBytes(agent)
	if err != nil {
		return CheckFailed, fmt.Sprintf("digest commitment agent identity: %v", err)
	}
	b, err := canonical.DigestBytes(authorized)
	if err != nil {
		return CheckFailed, fmt.Sprintf("digest MAT machine identity: %v", err)
	}
	if !bytes.Equal(a, b) {
		return CheckFailed,
			"the commitment's agent identity is not the identity its governing MAT authorizes"
	}
	return CheckPassed, "commitment agent identity matches the governing MAT's machine identity"
}

// identityUnset reports whether a machine identity carries no identifying
// material at all. Kind alone does not identify anything.
func identityUnset(m MachineIdentity) bool {
	return len(m.PublicKey) == 0 && m.CertRef == "" && m.Attestation == nil && len(m.Composite) == 0
}
