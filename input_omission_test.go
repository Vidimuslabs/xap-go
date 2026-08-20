package xap_test

// Removing a caller-supplied input must never remove a CHECK (§9.1).
//
// Every guard in Verify tests an input the caller supplies — the governing MAT,
// the reproduced context, the prior receipt — while the claim under examination
// is carried by the receipt, which is always present. A guard that skips
// silently converts a missing input into a missing check, and a missing check
// is indistinguishable from a passed one: Valid answers "was anything refuted",
// so nothing refuted by a check that never ran still reads as valid.
//
// Found in the commitment block and then measured across the rest:
// a bare receipt emitted 11 of 35 checks and said nothing about the other 24.
//
// The test below is differential rather than a list of expected statuses,
// because the list is what the vectors already pin. What this pins is the rule:
// drop an input, and every check that was reported before is still reported —
// with a different status, which is the point. The one legitimate exception is
// dropping the artifact whose own claim a check examines; a receipt presented
// without a commitment makes no commitment claims to report on, which SPEC §9.1
// permits in as many words.

import (
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	xap "github.com/Vidimuslabs/xap-go"
	"github.com/Vidimuslabs/xap-go/conformance"
	"github.com/Vidimuslabs/xap-spec/vectors"
)

func TestDroppingAnInputNeverDropsACheck(t *testing.T) {
	m, err := vectors.Load()
	if err != nil {
		t.Fatal(err)
	}
	anchors, err := conformance.BuildAnchors(m)
	if err != nil {
		t.Fatal(err)
	}
	blob := func(n string) []byte {
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
	ctx := func(n string) *xap.RuntimeContext {
		raw, err := vectors.File(n)
		if err != nil {
			t.Fatal(err)
		}
		var c xap.RuntimeContext
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatal(err)
		}
		return &c
	}
	names := func(res xap.VerificationResult) map[string]xap.CheckStatus {
		out := make(map[string]xap.CheckStatus, len(res.Checks))
		for _, c := range res.Checks {
			out[c.Name] = c.Status
		}
		return out
	}

	v := xap.NewVerifier(anchors)

	// Baseline: as many inputs as this receipt has artifacts for.
	full := xap.VerifyInput{
		ReceiptEnvelope:   blob("receipt_permit.hex"),
		MATEnvelope:       blob("mat_root.hex"),
		ReproducedContext: ctx("ctx_permit.json"),
	}
	base := names(v.Verify(full))
	if len(base) == 0 {
		t.Fatal("baseline produced no checks")
	}

	for _, tc := range []struct {
		dropped string
		in      xap.VerifyInput
		// mayVanish are the checks whose claim the DROPPED artifact carries
		// rather than the receipt. Withholding the artifact withholds the
		// claim, so there is nothing left to report — the §9.1 exception. Kept
		// as an explicit list, not a loosened assertion: every name here is a
		// case someone had to justify.
		mayVanish []string
	}{
		{dropped: "the governing MAT", in: xap.VerifyInput{
			ReceiptEnvelope: full.ReceiptEnvelope, ReproducedContext: full.ReproducedContext},
			// The MAT's own signature is the MAT's claim about itself. No MAT,
			// no such claim. Every OTHER MAT-reading check tests something the
			// receipt asserted, and must still be reported.
			mayVanish: []string{"mat_signature"}},
		{dropped: "the reproduced context", in: xap.VerifyInput{
			ReceiptEnvelope: full.ReceiptEnvelope, MATEnvelope: full.MATEnvelope}},
		{dropped: "both", in: xap.VerifyInput{ReceiptEnvelope: full.ReceiptEnvelope},
			mayVanish: []string{"mat_signature"}},
	} {
		t.Run("without "+tc.dropped, func(t *testing.T) {
			allowed := make(map[string]bool, len(tc.mayVanish))
			for _, n := range tc.mayVanish {
				allowed[n] = true
			}
			got := names(v.Verify(tc.in))
			var vanished []string
			for name := range base {
				if _, ok := got[name]; !ok && !allowed[name] {
					vanished = append(vanished, name)
				}
			}
			sort.Strings(vanished)
			if len(vanished) > 0 {
				t.Errorf("dropping %s removed %d check(s) instead of degrading them: %v\n"+
					"an absent check is indistinguishable from a passed one, so this is a "+
					"gate the presenting party can delete by withholding an input",
					tc.dropped, len(vanished), vanished)
			}
			// Degraded, not silently passed: whatever no longer has its input
			// must say so rather than claim it ran.
			for name, wasStatus := range base {
				now, ok := got[name]
				if !ok || now == wasStatus {
					continue
				}
				if now != xap.CheckNotPerformed {
					t.Errorf("dropping %s changed %q from %q to %q; the only honest "+
						"change is to %q", tc.dropped, name, wasStatus, now, xap.CheckNotPerformed)
				}
			}
		})
	}
}
