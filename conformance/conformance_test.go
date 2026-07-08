package conformance

import "testing"

// The whole point of the conformance suite: the reference SDK must reproduce
// every expected outcome in the embedded manifest. When the engine lands, it
// runs these same vectors, and engine-issued receipts verify against this SDK —
// the two-implementation cross-check for independent verifiability.
func TestConformanceVectors(t *testing.T) {
	results, err := RunAll()
	if err != nil {
		t.Fatalf("run vectors: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("no vectors ran")
	}
	for _, r := range results {
		if !r.Pass {
			t.Errorf("vector %q (%s) failed: %s", r.Name, r.Kind, r.Detail)
		}
	}
}
