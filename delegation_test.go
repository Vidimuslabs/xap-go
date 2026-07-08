package xap

import (
	"errors"
	"math/rand"
	"testing"
)

func baseParent() MAT {
	return MAT{
		Version: ProtocolVersion, ID: "parent",
		Scope:            ExecutionScope{Actions: []string{"deploy", "read"}, Resources: []string{"svc/*"}},
		Boundary:         PermissionBoundary{MaxImpact: 100, MaxPrivilegeDelta: 10, ResourceQuotas: map[string]int64{"api": 1000}, Exclusions: []string{"delete"}},
		ProofObligations: []ProofObligation{{Category: "software_attestation", MaxAgeSeconds: 3600}},
		Constraints: []Constraint{
			{ID: "c-rate", Type: "rate_limit", MaxRate: ptrI64(100)},
			{ID: "c-zone", Type: "network_zone", Zones: []string{"prod", "staging"}},
		},
		Delegation: DelegationRights{Allowed: true, MaxDepth: 3},
	}
}

func baseChild() MAT {
	return MAT{
		Version: ProtocolVersion, ID: "child", ParentID: "parent",
		Scope:            ExecutionScope{Actions: []string{"read"}, Resources: []string{"svc/api"}},
		Boundary:         PermissionBoundary{MaxImpact: 50, MaxPrivilegeDelta: 5, ResourceQuotas: map[string]int64{"api": 500}, Exclusions: []string{"delete", "drop"}},
		ProofObligations: []ProofObligation{{Category: "software_attestation", MaxAgeSeconds: 1800}},
		Constraints: []Constraint{
			{ID: "c-rate", Type: "rate_limit", MaxRate: ptrI64(50)},
			{ID: "c-zone", Type: "network_zone", Zones: []string{"prod"}},
		},
		Delegation: DelegationRights{Allowed: true, MaxDepth: 1},
	}
}

func TestValidDerivationAccepted(t *testing.T) {
	p, c := baseParent(), baseChild()
	if err := ValidateDerivation(&p, &c); err != nil {
		t.Fatalf("expected valid derivation, got %v", err)
	}
}

func TestDerivationInvariantViolations(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(child *MAT)
		wantErr error
	}{
		{"scope not subset", func(c *MAT) { c.Scope.Actions = append(c.Scope.Actions, "delete") }, ErrScopeNotSubset},
		{"scope resource outside parent", func(c *MAT) { c.Scope.Resources = []string{"other/x"} }, ErrScopeNotSubset},
		{"boundary max impact", func(c *MAT) { c.Boundary.MaxImpact = 200 }, ErrBoundaryExceeded},
		{"boundary quota", func(c *MAT) { c.Boundary.ResourceQuotas["api"] = 2000 }, ErrBoundaryExceeded},
		{"boundary drops exclusion", func(c *MAT) { c.Boundary.Exclusions = nil }, ErrBoundaryExceeded},
		{"constraint looser rate", func(c *MAT) { c.Constraints[0].MaxRate = ptrI64(500) }, ErrConstraintNotStricter},
		{"constraint zone widened", func(c *MAT) { c.Constraints[1].Zones = []string{"prod", "staging", "dev"} }, ErrConstraintNotStricter},
		{"constraint dropped", func(c *MAT) { c.Constraints = c.Constraints[:1] }, ErrConstraintNotStricter},
		{"obligation dropped", func(c *MAT) { c.ProofObligations = nil }, ErrObligationsNotSuperset},
		{"obligation freshness looser", func(c *MAT) { c.ProofObligations[0].MaxAgeSeconds = 7200 }, ErrObligationsNotSuperset},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, c := baseParent(), baseChild()
			tc.mutate(&c)
			err := ValidateDerivation(&p, &c)
			if err == nil {
				t.Fatalf("expected rejection, got nil")
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected %v, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestDelegationNotAllowed(t *testing.T) {
	p, c := baseParent(), baseChild()
	p.Delegation.Allowed = false
	if err := ValidateDerivation(&p, &c); !errors.Is(err, ErrDelegationNotAllowed) {
		t.Fatalf("expected ErrDelegationNotAllowed, got %v", err)
	}
}

// Property: a randomly loosened child must always be rejected. We start from a
// valid child and apply one random loosening mutation; ValidateDerivation must
// never accept it.
func TestDerivationFuzzLooseningRejected(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	mutations := []func(*MAT){
		func(c *MAT) { c.Boundary.MaxImpact = 100 + int64(rng.Intn(1000)+1) },
		func(c *MAT) { c.Boundary.MaxPrivilegeDelta = 10 + int64(rng.Intn(100)+1) },
		func(c *MAT) { c.Scope.Actions = append(c.Scope.Actions, "admin") },
		func(c *MAT) { c.Constraints[0].MaxRate = ptrI64(100 + int64(rng.Intn(500)+1)) },
		func(c *MAT) { c.ProofObligations[0].MaxAgeSeconds = 3600 + int64(rng.Intn(10000)+1) },
		func(c *MAT) { c.Constraints[1].Zones = []string{"prod", "staging", "dev", "test"} },
	}
	for i := 0; i < 2000; i++ {
		p, c := baseParent(), baseChild()
		mutations[rng.Intn(len(mutations))](&c)
		if err := ValidateDerivation(&p, &c); err == nil {
			t.Fatalf("iteration %d: loosened child was accepted", i)
		}
	}
}

func TestChainValidationAndDepth(t *testing.T) {
	root := baseParent()
	root.Delegation.MaxDepth = 1
	child := baseChild()
	if err := ValidateChain([]*MAT{&root, &child}); err != nil {
		t.Fatalf("valid 1-deep chain rejected: %v", err)
	}

	// A grandchild pushes depth to 2, exceeding the root allowance of 1.
	grand := baseChild()
	grand.ID = "grand"
	grand.ParentID = "child"
	grand.Boundary.MaxImpact = 25
	grand.Constraints[0].MaxRate = ptrI64(25)
	grand.ProofObligations[0].MaxAgeSeconds = 900
	err := ValidateChain([]*MAT{&root, &child, &grand})
	if !errors.Is(err, ErrDelegationDepthExceeded) {
		t.Fatalf("expected depth exceeded, got %v", err)
	}
}

func TestChainCycleRejected(t *testing.T) {
	// Build a chain whose links are all consistent but whose IDs revisit the
	// root: x(root) -> y(parent x) -> x(parent y). The repeated ID "x" is a cycle
	// even though every parent reference resolves.
	root := baseParent()
	root.ID = "x"
	root.ParentID = ""
	root.Delegation.MaxDepth = 0 // unlimited depth, so depth does not fire first

	mid := baseChild()
	mid.ID = "y"
	mid.ParentID = "x"

	loop := baseChild()
	loop.ID = "x" // revisits the root id
	loop.ParentID = "y"

	err := ValidateChain([]*MAT{&root, &mid, &loop})
	if !errors.Is(err, ErrDelegationCycle) {
		t.Fatalf("expected cycle rejection, got %v", err)
	}
}
