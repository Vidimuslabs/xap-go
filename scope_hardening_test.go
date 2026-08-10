package xap_test

// Three findings from an adversarial pass over the categories SECURITY.md
// invites, 2026-08-10. All three share a root: "unset" was being read as
// "unconstrained" in a protocol whose whole claim is bounded authority.

import (
	"testing"

	xap "github.com/Vidimuslabs/xap-go"
)

func parentMAT() xap.MAT {
	return xap.MAT{
		Scope:      xap.ExecutionScope{Actions: []string{"deploy", "read"}, Resources: []string{"svc/*"}},
		Delegation: xap.DelegationRights{Allowed: true, MaxDepth: 2},
	}
}

// FINDING 1 — a child that omits a dimension the parent constrained held MORE
// authority than its parent while satisfying invariant (i). An empty list means
// "unconstrained" to CoversOperation, but iterating the child's entries read an
// empty child list as the empty set — vacuously a subset. Monotonic delegation
// inverted by the encoding of "unset".
func TestChildCannotWidenByLeavingScopeUnset(t *testing.T) {
	parent := parentMAT()
	for _, tc := range []struct {
		name    string
		actions []string
		res     []string
		wantErr bool
	}{
		{"narrower on both", []string{"read"}, []string{"svc/api"}, false},
		{"equal on both", []string{"deploy", "read"}, []string{"svc/*"}, false},
		{"actions unset", nil, []string{"svc/api"}, true},
		{"resources unset", []string{"read"}, nil, true},
		{"both unset", nil, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			child := parentMAT()
			child.Scope = xap.ExecutionScope{Actions: tc.actions, Resources: tc.res}
			err := xap.ValidateDerivation(&parent, &child)
			if tc.wantErr && err == nil {
				t.Fatalf("child with actions=%v resources=%v was accepted; it is broader than its parent",
					tc.actions, tc.res)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("legitimate narrowing rejected: %v", err)
			}
		})
	}
}

// FINDING 2 — a receipt naming an action while withholding the resource had its
// resource skipped and the scope check reported as PASSED. Selective disclosure
// makes such receipts legitimate; it does not make them checkable, and reporting
// a gate as passed when it was never applied is the failure the not-performed
// branch exists to prevent.
func TestScopeCheckIsNotReproducibleFromPartialDisclosure(t *testing.T) {
	m := parentMAT()
	for _, tc := range []struct {
		action, resource string
		reproducible     bool
	}{
		{"deploy", "svc/api", true},
		{"deploy", "", false}, // resource withheld — was silently "passing"
		{"", "svc/api", false},
		{"", "", false},
	} {
		if got := m.ScopeReproducible(tc.action, tc.resource); got != tc.reproducible {
			t.Fatalf("ScopeReproducible(%q,%q) = %v, want %v",
				tc.action, tc.resource, got, tc.reproducible)
		}
	}

	// A MAT that constrains neither dimension can still be evaluated from a
	// partial disclosure, because there is nothing to evaluate on the other one.
	open := xap.MAT{Scope: xap.ExecutionScope{Actions: []string{"deploy"}}}
	if !open.ScopeReproducible("deploy", "") {
		t.Fatal("a MAT that does not constrain resources should be reproducible without one")
	}
}

// FINDING 3 — prefix matching on an un-normalized string is not containment:
// "svc/*" textually covered "svc/../db/main", which resolves outside svc.
func TestTraversalIsNotCoveredByAPrefixPattern(t *testing.T) {
	m := parentMAT()
	for _, r := range []string{
		"svc/../db/main",
		"svc/../../etc/passwd",
		"svc/a/../../db",
		`svc\..\db`,
	} {
		if err := m.CoversOperation("deploy", r); err == nil {
			t.Fatalf("resource %q escaped the scope via traversal and was accepted", r)
		}
	}
	// Legitimate names containing dots must still work — the check matches whole
	// segments, not the substring "..".
	for _, r := range []string{"svc/my..app", "svc/a.b.c", "svc/api"} {
		if err := m.CoversOperation("deploy", r); err != nil {
			t.Fatalf("legitimate resource %q rejected: %v", r, err)
		}
	}
	// And a child pattern cannot escape its parent by traversal either.
	parent := parentMAT()
	child := parentMAT()
	child.Scope.Resources = []string{"svc/../db/*"}
	if err := xap.ValidateDerivation(&parent, &child); err == nil {
		t.Fatal("child escaped parent scope via a traversal pattern")
	}
}
