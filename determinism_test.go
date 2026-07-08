package xap

import (
	"testing"

	"github.com/Vidimuslabs/xap-go/canonical"
)

// Reproducible constraint evaluation (¶0016): the same constraint set and
// runtime context must produce the same evaluation outcome and the same digest
// on every invocation. A probabilistic evaluator would fail this and could not
// support independent reproduced verification.
func TestConstraintDeterminism(t *testing.T) {
	constraints := []Constraint{
		{ID: "c-time", Type: "temporal", NotBefore: "2026-06-30T00:00:00Z", NotAfter: "2026-07-10T00:00:00Z"},
		{ID: "c-zone", Type: "network_zone", Zones: []string{"prod", "staging"}},
		{ID: "c-rate", Type: "rate_limit", MaxRate: ptrI64(100)},
		{ID: "c-param", Type: "param_bound", Param: "cpu", Min: ptrF64(0), Max: ptrF64(0.9)},
		{ID: "c-res", Type: "resource_state", Key: "db", Equals: "healthy"},
	}
	ctx := RuntimeContext{
		Time:          "2026-07-01T00:00:00Z",
		NetworkZone:   "prod",
		Params:        map[string]float64{"cpu": 0.5},
		ResourceState: map[string]string{"db": "healthy"},
		Rate:          map[string]int64{"c-rate": 10},
	}

	// Establish the reference outcome vector and context digest.
	want := make([]bool, len(constraints))
	for i, c := range constraints {
		want[i] = c.Evaluate(ctx)
	}
	refDigest, err := canonical.DigestBytes(ctx)
	if err != nil {
		t.Fatal(err)
	}

	const iterations = 10000
	for n := 0; n < iterations; n++ {
		for i, c := range constraints {
			if got := c.Evaluate(ctx); got != want[i] {
				t.Fatalf("iteration %d: constraint %q outcome %v != %v", n, c.ID, got, want[i])
			}
		}
		d, err := canonical.DigestBytes(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if string(d) != string(refDigest) {
			t.Fatalf("iteration %d: context digest drifted", n)
		}
	}

	// Every constraint above is satisfied for this context.
	for i, c := range constraints {
		if !want[i] {
			t.Errorf("expected constraint %q satisfied for the given context", c.ID)
		}
	}
}

func ptrI64(v int64) *int64     { return &v }
func ptrF64(v float64) *float64 { return &v }
