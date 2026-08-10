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

// SECOND ADVERSARIAL PASS, same day. The first fix turned out to be local: the
// identical "unset means unconstrained" inversion lived in three more bounds.
// Notably boundaryWithin already handled exclusions correctly — parent
// exclusions must survive into the child — so the correct and the inverted
// pattern sat in the same function.

// FINDING 4 — a child that dropped a quota key, or the whole map, was compared
// against nothing. An absent quota is not a smaller quota.
func TestChildCannotDropResourceQuotas(t *testing.T) {
	parent := parentMAT()
	parent.Boundary = xap.PermissionBoundary{
		MaxImpact: 100, MaxPrivilegeDelta: 10,
		ResourceQuotas: map[string]int64{"api": 1000},
	}
	base := func() xap.MAT {
		c := parentMAT()
		c.Scope = xap.ExecutionScope{Actions: []string{"read"}, Resources: []string{"svc/api"}}
		c.Boundary = parent.Boundary
		return c
	}
	for _, tc := range []struct {
		name    string
		quotas  map[string]int64
		wantErr bool
	}{
		{"same quota", map[string]int64{"api": 1000}, false},
		{"lower quota", map[string]int64{"api": 500}, false},
		{"higher quota", map[string]int64{"api": 2000}, true},
		{"map emptied", map[string]int64{}, true},
		{"map dropped", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			c.Boundary.ResourceQuotas = tc.quotas
			err := xap.ValidateDerivation(&parent, &c)
			if tc.wantErr != (err != nil) {
				t.Fatalf("quotas=%v -> err=%v, wantErr=%v", tc.quotas, err, tc.wantErr)
			}
		})
	}
}

// FINDING 5 — a child could keep a constraint's ID while emptying its zone
// list, neutralising it and still satisfying invariant (iii), because the empty
// set is trivially a subset.
func TestChildCannotNeutraliseAConstraint(t *testing.T) {
	parent := parentMAT()
	parent.Constraints = []xap.Constraint{{ID: "c-zone", Type: "network_zone", Zones: []string{"prod", "staging"}}}
	base := func() xap.MAT {
		c := parentMAT()
		c.Scope = xap.ExecutionScope{Actions: []string{"read"}, Resources: []string{"svc/api"}}
		return c
	}
	for _, tc := range []struct {
		name    string
		zones   []string
		wantErr bool
	}{
		{"narrowed", []string{"prod"}, false},
		{"identical", []string{"prod", "staging"}, false},
		{"widened", []string{"prod", "staging", "dev"}, true},
		{"emptied", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			c.Constraints = []xap.Constraint{{ID: "c-zone", Type: "network_zone", Zones: tc.zones}}
			err := xap.ValidateDerivation(&parent, &c)
			if tc.wantErr != (err != nil) {
				t.Fatalf("zones=%v -> err=%v, wantErr=%v", tc.zones, err, tc.wantErr)
			}
		})
	}
}

// FINDING 6 — a root that permitted delegation without stating a depth granted
// chains of any length: the shallowest possible statement produced the deepest
// possible grant.
func TestRootMustStateADelegationDepth(t *testing.T) {
	mk := func(id, parentID string, depth int) *xap.MAT {
		m := parentMAT()
		m.ID, m.ParentID = id, parentID
		m.Delegation = xap.DelegationRights{Allowed: true, MaxDepth: depth}
		if parentID != "" {
			m.Scope = xap.ExecutionScope{Actions: []string{"read"}, Resources: []string{"svc/api"}}
		}
		return &m
	}
	root := mk("r", "", 0) // depth unstated
	chain := []*xap.MAT{root, mk("a", "r", 0), mk("b", "a", 0), mk("c", "b", 0)}
	if err := xap.ValidateChain(chain); err == nil {
		t.Fatal("a root with no stated depth granted an unbounded delegation chain")
	}
	// Stating a depth works, and is still enforced.
	root2 := mk("r", "", 2)
	ok := []*xap.MAT{root2, mk("a", "r", 2), mk("b", "a", 2)}
	if err := xap.ValidateChain(ok); err != nil {
		t.Fatalf("chain within a stated depth was rejected: %v", err)
	}
	tooDeep := []*xap.MAT{root2, mk("a", "r", 2), mk("b", "a", 2), mk("c", "b", 2)}
	if err := xap.ValidateChain(tooDeep); err == nil {
		t.Fatal("chain exceeding the stated depth was accepted")
	}
}

// FINDING 7 (pass 3) and the durable fix. Passes 1–2 stopped a CHILD widening
// by omission, but an issuer's own ROOT still permitted everything by saying
// nothing — absence was still the most permissive statement available, and the
// cheapest to write. ExecutionScope.Unconstrained inverts that: absence denies,
// and opening a whole dimension requires naming it.
func TestAbsentScopeDeniesUnlessDeclaredUnconstrained(t *testing.T) {
	empty := xap.MAT{}
	if err := empty.CoversOperation("anything", "anywhere"); err == nil {
		t.Fatal("a MAT that says nothing about scope permitted everything")
	}
	// Actions enumerated, resources silent: resources permit nothing.
	partial := xap.MAT{Scope: xap.ExecutionScope{Actions: []string{"read"}}}
	if err := partial.CoversOperation("read", "svc/api"); err == nil {
		t.Fatal("a silent resource dimension permitted a resource")
	}
	// Declaring the dimension unconstrained is what opens it.
	open := xap.MAT{Scope: xap.ExecutionScope{
		Actions:       []string{"read"},
		Unconstrained: []string{xap.ScopeDimensionResources},
	}}
	if err := open.CoversOperation("read", "any/resource"); err != nil {
		t.Fatalf("declared-unconstrained resources still denied: %v", err)
	}
	if err := open.CoversOperation("delete", "any/resource"); err == nil {
		t.Fatal("declaring resources unconstrained also opened actions")
	}
}

// The marker must not become an escalation primitive: a child may declare a
// dimension unconstrained only where its parent already did.
func TestChildCannotDeclareItselfUnconstrained(t *testing.T) {
	parent := parentMAT()
	child := parentMAT()
	child.Scope = xap.ExecutionScope{
		Actions:       []string{"read"},
		Unconstrained: []string{xap.ScopeDimensionResources},
	}
	if err := xap.ValidateDerivation(&parent, &child); err == nil {
		t.Fatal("child declared resources unconstrained while its parent enumerated them")
	}

	// Where the parent did declare it, the child may inherit it.
	openParent := parentMAT()
	openParent.Scope = xap.ExecutionScope{
		Actions:       []string{"deploy", "read"},
		Unconstrained: []string{xap.ScopeDimensionResources},
	}
	okChild := parentMAT()
	okChild.Scope = xap.ExecutionScope{
		Actions:       []string{"read"},
		Unconstrained: []string{xap.ScopeDimensionResources},
	}
	if err := xap.ValidateDerivation(&openParent, &okChild); err != nil {
		t.Fatalf("child inheriting a declared-unconstrained dimension was rejected: %v", err)
	}
	// And narrowing it back to an enumeration is always allowed.
	narrowing := parentMAT()
	narrowing.Scope = xap.ExecutionScope{Actions: []string{"read"}, Resources: []string{"svc/api"}}
	if err := xap.ValidateDerivation(&openParent, &narrowing); err != nil {
		t.Fatalf("child narrowing an unconstrained dimension was rejected: %v", err)
	}
}

// FINDING 8 (pass 4) — the commitment's declared action set was signed, carried,
// and never evaluated. A commitment declaring "delete" — outside its governing
// MAT's scope AND named in that MAT's boundary exclusions — bound successfully,
// so the bounded-enumeration claim rested entirely on the issuer's word and
// COMMITMENT_SCOPE_VIOLATION was a code a verifier could read but never reach.
func TestCommitmentCannotOverclaimItsGoverningMAT(t *testing.T) {
	gov := parentMAT() // actions [deploy read] over svc/*
	gov.Boundary.Exclusions = []string{"delete"}

	within := xap.CommitmentObject{DeclaredActions: xap.DeclaredActionSet{
		ActionTypes: []string{"read"}, Resources: []string{"svc/api"},
	}}
	if err := within.WithinScopeOf(&gov); err != nil {
		t.Fatalf("a commitment narrower than its MAT was rejected: %v", err)
	}

	for _, tc := range []struct {
		name string
		set  xap.DeclaredActionSet
	}{
		{"action outside scope", xap.DeclaredActionSet{ActionTypes: []string{"deploy", "delete"}}},
		{"resource outside scope", xap.DeclaredActionSet{ActionTypes: []string{"read"}, Resources: []string{"db/main"}}},
		{"resource via traversal", xap.DeclaredActionSet{ActionTypes: []string{"read"}, Resources: []string{"svc/../db"}}},
		{"declares itself unconstrained", xap.DeclaredActionSet{Unconstrained: []string{xap.ScopeDimensionActions}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := xap.CommitmentObject{DeclaredActions: tc.set}
			if err := c.WithinScopeOf(&gov); err == nil {
				t.Fatalf("commitment %+v exceeded its governing MAT and was accepted", tc.set)
			}
		})
	}
}

// FINDING 9 — there was no membership predicate at all, so nothing could ask
// whether an action fell inside the declared set. Absence must deny here too.
func TestDeclaredActionSetAbsenceDenies(t *testing.T) {
	empty := xap.DeclaredActionSet{}
	if err := empty.Covers("anything", "anywhere"); err == nil {
		t.Fatal("an empty declared action set admitted an operation")
	}
	bounded := xap.DeclaredActionSet{ActionTypes: []string{"read"}, Resources: []string{"svc/*"}}
	if err := bounded.Covers("read", "svc/api"); err != nil {
		t.Fatalf("declared operation rejected: %v", err)
	}
	if err := bounded.Covers("delete", "svc/api"); err == nil {
		t.Fatal("undeclared action admitted")
	}
	if err := bounded.Covers("read", "db/main"); err == nil {
		t.Fatal("undeclared resource admitted")
	}
	open := xap.DeclaredActionSet{
		ActionTypes:   []string{"read"},
		Unconstrained: []string{xap.ScopeDimensionResources},
	}
	if err := open.Covers("read", "any/resource"); err != nil {
		t.Fatalf("declared-unconstrained resources still denied: %v", err)
	}
}

// FINDING 10/11 (pass 5) — the two remaining fields on the commitment that were
// declared and never evaluated. resource_targets is a SECOND resource list,
// separate from declared_actions.resources: two places to state resources with
// only one checked is worse than either alone, because the unchecked one is
// where an over-claim goes. param_ranges are constraints the agent commits to,
// and a range looser than the governing MAT's constraint of the same id is an
// over-claim wearing the costume of a self-restriction.
func TestCommitmentResourceTargetsAndParamRangesMustNarrow(t *testing.T) {
	gov := parentMAT() // actions [deploy read] over svc/*
	gov.Constraints = []xap.Constraint{{ID: "c-zone", Type: "network_zone", Zones: []string{"prod"}}}

	ok := xap.CommitmentObject{
		DeclaredActions: xap.DeclaredActionSet{
			ActionTypes: []string{"read"}, Resources: []string{"svc/api"},
			ParamRanges: []xap.Constraint{{ID: "c-zone", Type: "network_zone", Zones: []string{"prod"}}},
		},
		ResourceTargets: []string{"svc/api"},
	}
	if err := ok.WithinScopeOf(&gov); err != nil {
		t.Fatalf("a narrowing commitment was rejected: %v", err)
	}

	for _, tc := range []struct {
		name string
		mut  func(*xap.CommitmentObject)
	}{
		{"resource_target outside scope", func(c *xap.CommitmentObject) {
			c.ResourceTargets = []string{"db/main"}
		}},
		{"resource_target via traversal", func(c *xap.CommitmentObject) {
			c.ResourceTargets = []string{"svc/../db/main"}
		}},
		{"param_range widened", func(c *xap.CommitmentObject) {
			c.DeclaredActions.ParamRanges = []xap.Constraint{
				{ID: "c-zone", Type: "network_zone", Zones: []string{"prod", "dev"}}}
		}},
		{"param_range neutralised", func(c *xap.CommitmentObject) {
			c.DeclaredActions.ParamRanges = []xap.Constraint{
				{ID: "c-zone", Type: "network_zone"}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := ok
			c.DeclaredActions.ParamRanges = append([]xap.Constraint(nil), ok.DeclaredActions.ParamRanges...)
			c.ResourceTargets = append([]string(nil), ok.ResourceTargets...)
			tc.mut(&c)
			if err := c.WithinScopeOf(&gov); err == nil {
				t.Fatal("commitment exceeded its governing MAT and was accepted")
			}
		})
	}

	// A param range with no counterpart in the MAT is an extra self-restriction.
	extra := ok
	extra.DeclaredActions.ParamRanges = []xap.Constraint{{ID: "agent-only", Type: "rate_limit"}}
	if err := extra.WithinScopeOf(&gov); err != nil {
		t.Fatalf("an additional self-restriction was rejected: %v", err)
	}
}
