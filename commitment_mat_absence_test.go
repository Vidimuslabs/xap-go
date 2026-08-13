package xap_test

// A check that depends on the governing MAT must DEGRADE when the MAT is
// absent, never disappear (¶0084A, ¶0095A; SPEC.md §9 step 5).
//
// The MAT envelope is a verifier INPUT, chosen by whoever presents the receipt.
// Until 2026-08-13 the commitment block emitted its MAT-dependent checks only
// when a MAT happened to be supplied, and emitted nothing at all otherwise —
// so omitting the MAT deleted the gate instead of failing it, and the result
// carried no trace that anything had been skipped. Measured at the time, on
// corpus artifacts:
//
//	receipt_permit_overclaim + commitment_overclaim, with MAT    -> Valid=false, commitment_scope=failed
//	receipt_permit_overclaim + commitment_overclaim, without MAT -> Valid=true,  commitment_scope=ABSENT
//	receipt_compliance_lie   + commitment_A,         without MAT -> Valid=true   (the lie escaped entirely)
//
// The vectors commitment_overclaim_no_mat and commitment_compliance_no_mat pin
// the statuses. This pins the rule they are instances of, because a vector
// proves an artifact is judged correctly today while a test survives someone
// rewriting the check.

import (
	"encoding/hex"
	"strings"
	"testing"

	xap "github.com/Vidimuslabs/xap-go"
	"github.com/Vidimuslabs/xap-go/conformance"
	"github.com/Vidimuslabs/xap-spec/vectors"
)

// matDependentChecks are the checks whose claim is reproduced against the
// governing MAT. Each must be reported either way.
var matDependentChecks = []string{
	"commitment_binding",
	"commitment_scope",
	"compliance_scope_check",
	"compliance_boundary_check",
}

func TestMATDependentChecksDegradeRatherThanDisappear(t *testing.T) {
	m, err := vectors.Load()
	if err != nil {
		t.Fatal(err)
	}
	anchors, err := conformance.BuildAnchors(m)
	if err != nil {
		t.Fatal(err)
	}
	load := func(n string) []byte {
		raw, err := vectors.File(n)
		if err != nil {
			t.Fatal(err)
		}
		b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	statuses := func(res xap.VerificationResult) map[string]xap.CheckStatus {
		out := make(map[string]xap.CheckStatus, len(res.Checks))
		for _, c := range res.Checks {
			out[c.Name] = c.Status
		}
		return out
	}

	v := xap.NewVerifier(anchors)

	// The receipt carrying compliance claims exercises all four checks; the
	// over-claim receipt exercises the two commitment ones and is the case that
	// actually changes verdict when the MAT is present.
	for _, tc := range []struct {
		name              string
		receipt, commit   string
		want              []string
		validWithMAT      bool
		validWithoutMAT   bool
		withoutMATComment string
	}{
		{
			name: "over-claiming commitment", receipt: "receipt_permit_overclaim.hex",
			commit: "commitment_overclaim.hex",
			want:   []string{"commitment_binding", "commitment_scope"},
			// With the MAT the over-claim is caught. Without it the claim is
			// genuinely unreproducible, so the receipt verifies — but the result
			// must SAY the scope check did not run.
			validWithMAT: false, validWithoutMAT: true,
			withoutMATComment: "unreproducible, so disclosed rather than failed",
		},
		{
			name: "false compliance claims", receipt: "receipt_compliance_lie.hex",
			commit: "commitment_A.hex",
			want:   matDependentChecks,
			// compliance_commitment_check recomputes against the commitment's own
			// declared set, so it needs no MAT and still catches the lie. If this
			// ever flips to true, the MAT has again become a way to escape a
			// check that never needed it.
			validWithMAT: false, validWithoutMAT: false,
			withoutMATComment: "commitment-only recomputation still fails the lie",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withMAT := v.Verify(xap.VerifyInput{
				ReceiptEnvelope:    load(tc.receipt),
				MATEnvelope:        load("mat_root.hex"),
				CommitmentEnvelope: load(tc.commit),
			})
			withoutMAT := v.Verify(xap.VerifyInput{
				ReceiptEnvelope:    load(tc.receipt),
				CommitmentEnvelope: load(tc.commit),
			})

			if withMAT.Valid != tc.validWithMAT {
				t.Errorf("with MAT: Valid=%v want %v (failed: %v)",
					withMAT.Valid, tc.validWithMAT, withMAT.Failed())
			}
			if withoutMAT.Valid != tc.validWithoutMAT {
				t.Errorf("without MAT: Valid=%v want %v — %s (failed: %v)",
					withoutMAT.Valid, tc.validWithoutMAT, tc.withoutMATComment, withoutMAT.Failed())
			}

			with, without := statuses(withMAT), statuses(withoutMAT)
			for _, name := range tc.want {
				if _, ok := with[name]; !ok {
					t.Errorf("check %q absent even WITH a MAT; the vector no longer exercises it", name)
					continue
				}
				st, ok := without[name]
				if !ok {
					t.Errorf("check %q is emitted with a MAT and ABSENT without one: omitting the "+
						"MAT deletes the gate, and Valid=%v reads as full assurance",
						name, withoutMAT.Valid)
					continue
				}
				if st != xap.CheckNotPerformed {
					t.Errorf("check %q without a MAT reports %q, want %q: the claim is not "+
						"reproducible without the artifact it is made against",
						name, st, xap.CheckNotPerformed)
				}
			}

			// Not-performed is only meaningful if a caller can enumerate it
			// without walking every check.
			listed := make(map[string]bool, len(withoutMAT.NotPerformed))
			for _, n := range withoutMAT.NotPerformed {
				listed[n] = true
			}
			for _, name := range tc.want {
				if !listed[name] {
					t.Errorf("check %q reported not_performed but is missing from Result.NotPerformed", name)
				}
			}
		})
	}
}
