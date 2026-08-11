package xap

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"time"

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
	// CommitmentEnvelope is the COSE_Sign1 governing commitment object (optional).
	CommitmentEnvelope []byte
}

// Check is one named verification step and its outcome. JSON tags match the
// VerificationResult schema in the xap-spec OpenAPI.
type Check struct {
	Name   string `json:"name"`
	Pass   bool   `json:"pass"`
	Detail string `json:"detail,omitempty"`
}

// VerificationResult is the output of the verification state machine. JSON tags
// match the xap-spec OpenAPI VerificationResult schema (lowercase), so the
// server's /verify response is contract-accurate.
type VerificationResult struct {
	Valid      bool    `json:"valid"`
	ArtifactID string  `json:"artifact_id"`
	Decision   string  `json:"decision"`
	Checks     []Check `json:"checks"`
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

// ReceiptEnvelopeHash is the canonical chain-link hash: SHA-256 over the COSE
// signed receipt envelope bytes. A receipt's PriorReceiptHash carries this hash
// of the immediately preceding receipt (¶0063, FIG. 11), so an append-only log
// cannot delete or reorder receipts without breaking the chain.
func ReceiptEnvelopeHash(envelope []byte) []byte {
	h := sha256.Sum256(envelope)
	return h[:]
}

// Verify runs the verification state machine over the given input and returns a
// structured result. It never panics on malformed input; every failure is a
// non-passing Check with Valid=false.
func (v *Verifier) Verify(in VerifyInput) VerificationResult {
	res := VerificationResult{Valid: true}
	add := func(name string, pass bool, detail string) {
		res.Checks = append(res.Checks, Check{Name: name, Pass: pass, Detail: detail})
		if !pass {
			res.Valid = false
		}
	}

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

	// (3) Timing within the authorized latency bound (¶0053, ¶0088).
	add("timing_within_bound", rc.Timing.MaxMS == 0 || rc.Timing.ElapsedMS <= rc.Timing.MaxMS,
		fmt.Sprintf("elapsed=%dms max=%dms", rc.Timing.ElapsedMS, rc.Timing.MaxMS))

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
			add("scope_check", true, fmt.Sprintf(
				"not checked: receipt discloses action=%q resource=%q, insufficient to re-evaluate the scope this MAT constrains",
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
			add("evidence_covers_obligations", true,
				"not checked: receipt discloses no evidence references")
			add("evidence_asserted_fresh", true,
				"not checked: receipt discloses no evidence references")
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
		if mat != nil {
			ok, detail := recomputeOutcomes(mat, *in.ReproducedContext, rc)
			add("constraint_outcomes", ok, detail)
			add("decision_consistent", decisionConsistent(mat, *in.ReproducedContext, rc),
				fmt.Sprintf("decision=%q", rc.Decision))
		}
	}

	// (6) Chain link to the prior receipt (¶0063).
	if in.PriorReceipt != nil {
		want := ReceiptEnvelopeHash(in.PriorReceipt.Envelope)
		add("chain_link", bytes.Equal(rc.PriorReceiptHash, want),
			"receipt.prior_hash vs hash(prior receipt envelope)")
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
func recomputeOutcomes(mat *MAT, ctx RuntimeContext, rc Receipt) (bool, string) {
	byID := make(map[string]Constraint, len(mat.Constraints))
	for _, c := range mat.Constraints {
		byID[c.ID] = c
	}
	for _, rec := range rc.ConstraintOutcomes {
		c, ok := byID[rec.ConstraintID]
		if !ok {
			return false, fmt.Sprintf("receipt references unknown constraint %q", rec.ConstraintID)
		}
		if got := c.Evaluate(ctx); got != rec.Satisfied {
			return false, fmt.Sprintf("constraint %q recomputed=%v recorded=%v", rec.ConstraintID, got, rec.Satisfied)
		}
	}
	return true, ""
}

// decisionConsistent checks that the recorded decision is consistent with an
// independent evaluation of the constraint set against the reproduced context
// (¶0047, ¶0049). A permit requires every constraint to hold; a deny or
// permit-with-controls is permitted regardless (a deny may arise from any
// unconditional-denial path, and controls may compensate for a soft failure).
func decisionConsistent(mat *MAT, ctx RuntimeContext, rc Receipt) bool {
	if constants.Decision(rc.Decision) != constants.DecisionPermit {
		return true
	}
	for _, c := range mat.Constraints {
		if !c.Evaluate(ctx) {
			return false
		}
	}
	return true
}

// VerifyExpiry is a convenience lifecycle check the caller may run against the
// governing MAT before Verify; expired artifacts are unconditionally rejected
// (¶0065). It is separate from Verify because expiry depends on "now", which is
// the verifier's clock, not part of the signed receipt.
func VerifyExpiry(mat *MAT, at time.Time) error {
	return mat.ValidateAt(at)
}
