package xap_test

// Timeout receipt semantics (¶0052; SPEC.md §5), ratified 2026-08-10.
//
// A timeout receipt records elapsed_ms EQUAL to max_ms, never greater.
// Evaluation is abandoned at the bound, so the bound is reached and not
// exceeded; the timeout is signalled by the CONSTRAINT_EVALUATION_TIMEOUT
// rationale code and the disposition. The alternative — elapsed beyond the
// bound — is unverifiable by construction, because a verifier checks
// elapsed_ms <= max_ms and such a receipt could never verify, leaving the
// protocol unable to express a truthful timeout at all.
//
// This is a protocol ruling, so it is pinned here rather than left to the
// golden vector alone: a vector proves the artifact is well-formed today, a
// test proves the rule still holds if someone changes the check.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	xap "github.com/Vidimuslabs/xap-go"
	"github.com/Vidimuslabs/xap-go/conformance"
	"github.com/Vidimuslabs/xap-spec/constants"
	"github.com/Vidimuslabs/xap-spec/vectors"
)

func TestTimeoutReceiptRecordsElapsedEqualToBound(t *testing.T) {
	m, err := vectors.Load()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := vectors.File("receipt_timeout.hex")
	if err != nil {
		t.Fatal(err)
	}
	env, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	anchors, err := conformance.BuildAnchors(m)
	if err != nil {
		t.Fatal(err)
	}
	sr, err := xap.ParseReceipt(env, anchors)
	if err != nil {
		t.Fatalf("timeout vector failed to verify: %v", err)
	}
	rc := sr.Receipt

	var carriesTimeout bool
	for _, c := range rc.RationaleCodes {
		if c == constants.CodeConstraintEvaluationTimeout {
			carriesTimeout = true
		}
	}
	if !carriesTimeout {
		t.Fatalf("vector does not carry %s; it is not a timeout receipt",
			constants.CodeConstraintEvaluationTimeout)
	}
	if rc.Timing.ElapsedMS != rc.Timing.MaxMS {
		t.Fatalf("timeout receipt records elapsed_ms=%d max_ms=%d; the ruling is that a "+
			"timeout is abandoned AT the bound, so these must be equal",
			rc.Timing.ElapsedMS, rc.Timing.MaxMS)
	}
}

// The other half of the ruling: a receipt claiming elapsed beyond its own bound
// is malformed regardless of which codes it carries, and verification must say
// so. If this ever passes, the timeout representation above has become
// ambiguous — two different encodings would both verify.
func TestReceiptExceedingItsLatencyBoundNeverVerifies(t *testing.T) {
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

	// The signed timeout vector is at the bound and verifies.
	base := xap.NewVerifier(anchors).Verify(xap.VerifyInput{
		ReceiptEnvelope: load("receipt_timeout.hex"),
		MATEnvelope:     load("mat_root.hex"),
	})
	if !base.Valid {
		t.Fatalf("baseline timeout receipt did not verify: %v", base.Failed())
	}

	var sawTiming bool
	for _, c := range base.Checks {
		if c.Name == "timing_within_bound" {
			sawTiming = true
			if !c.Pass {
				t.Fatalf("timing_within_bound failed on a receipt at its bound: %s", c.Detail)
			}
		}
	}
	if !sawTiming {
		t.Fatal("no timing_within_bound check ran; elapsed_ms > max_ms would go unnoticed " +
			"and the timeout ruling would lose the property that makes it unambiguous")
	}

	// Now the rule itself, signed rather than asserted: an otherwise valid
	// receipt claiming one millisecond beyond its own bound must not verify.
	// This is what makes elapsed == max the only expressible timeout encoding.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kid := []byte("timeout-issuer")
	set := xap.NewTrustAnchorSet()
	if err := set.AddECDSAP256(kid, []xap.SignerRole{xap.RoleIssuer, xap.RoleEnforcementPoint}, &priv.PublicKey); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name         string
		elapsed, max int64
		wantVerifies bool
	}{
		{"at the bound", 50, 50, true},
		{"one past the bound", 51, 50, false},
		{"far past the bound", 5000, 50, false},
		{"no bound declared", 5000, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The completion timestamp has to follow the elapsed time it is
			// paired with, or the receipt contradicts itself and this case
			// stops being about the latency bound at all.
			start := mustParse(t, "2026-07-01T00:00:00Z")
			rc := xap.Receipt{
				Version: xap.ProtocolVersion, ID: "rcpt-timing", ArtifactID: "mat-root",
				Decision:       string(constants.DecisionDeny),
				ContextDigest:  make([]byte, 32),
				RationaleCodes: []string{constants.CodeConstraintEvaluationTimeout},
				Timing: xap.Timing{
					Start:     start.Format(time.RFC3339),
					Complete:  start.Add(time.Duration(tc.elapsed) * time.Millisecond).Format(time.RFC3339),
					ElapsedMS: tc.elapsed, MaxMS: tc.max,
				},
			}
			payload, err := rc.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			res := xap.NewVerifier(set).Verify(xap.VerifyInput{
				ReceiptEnvelope: signES256(t, kid, priv, payload),
			})
			if res.Valid != tc.wantVerifies {
				t.Fatalf("elapsed=%d max=%d: Valid=%v want %v (failed: %v)",
					tc.elapsed, tc.max, res.Valid, tc.wantVerifies, res.Failed())
			}
		})
	}
}

func mustParse(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return ts
}
