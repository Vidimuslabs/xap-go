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
