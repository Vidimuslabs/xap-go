package xap

import (
	"errors"
	"fmt"
	"strings"
)

// Monotonic delegation invariants (FIG. 5, ¶0057). Derivation of a Child MAT
// from a Parent MAT is governed by four cryptographically enforced invariants,
// each with its own error type so a caller (or an adversarial test) can assert
// exactly which invariant a derived artifact violates. Enforcement points
// unconditionally reject derived artifacts failing derivation proof validation.
var (
	// ErrScopeNotSubset: child scope is not a subset of parent scope
	// (invariant i).
	ErrScopeNotSubset = errors.New("delegation: child scope exceeds parent scope")
	// ErrBoundaryExceeded: child permission boundary is not equal to or more
	// restrictive than parent (invariant ii).
	ErrBoundaryExceeded = errors.New("delegation: child boundary exceeds parent boundary")
	// ErrConstraintNotStricter: some child constraint is looser than the
	// corresponding parent constraint (invariant iii).
	ErrConstraintNotStricter = errors.New("delegation: child constraint looser than parent")
	// ErrObligationsNotSuperset: child proof obligations do not include all
	// parent obligations (invariant iv).
	ErrObligationsNotSuperset = errors.New("delegation: child proof obligations omit a parent obligation")
	// ErrDelegationDepthExceeded: the derivation depth exceeds the parent's
	// delegation depth allowance (¶0041 field 134).
	ErrDelegationDepthExceeded = errors.New("delegation: depth exceeds parent allowance")
	// ErrDelegationNotAllowed: the parent does not permit delegation.
	ErrDelegationNotAllowed = errors.New("delegation: parent does not permit delegation")
	// ErrDelegationCycle: the delegation graph contains a cycle (¶0073).
	ErrDelegationCycle = errors.New("delegation: cyclic authorization graph")
)

// ValidateDerivation checks the four monotonic invariants for a single
// parent→child derivation step, plus delegation permission and depth (¶0057,
// ¶0041 field 134). It does not walk a chain; see ValidateChain.
func ValidateDerivation(parent, child *MAT) error {
	if !parent.Delegation.Allowed {
		return ErrDelegationNotAllowed
	}
	if err := scopeSubset(child.Scope, parent.Scope); err != nil {
		return fmt.Errorf("%w: %v", ErrScopeNotSubset, err)
	}
	if err := boundaryWithin(child.Boundary, parent.Boundary); err != nil {
		return fmt.Errorf("%w: %v", ErrBoundaryExceeded, err)
	}
	if err := constraintsStricter(child.Constraints, parent.Constraints); err != nil {
		return fmt.Errorf("%w: %v", ErrConstraintNotStricter, err)
	}
	if err := obligationsSuperset(child.ProofObligations, parent.ProofObligations); err != nil {
		return fmt.Errorf("%w: %v", ErrObligationsNotSuperset, err)
	}
	return nil
}

// scopeSubset checks child scope ⊆ parent scope (invariant i). Child actions
// and resource patterns must each be covered by the parent; an exclusion added
// by the child only narrows and is always permitted.
func scopeSubset(child, parent ExecutionScope) error {
	// An absent list means "unconstrained on this dimension" — CoversOperation
	// skips a dimension whose list is empty. Iterating the child's entries
	// therefore reads an EMPTY child list as the empty set (vacuously a subset)
	// when it actually denotes the universal set. A child that simply omits a
	// dimension the parent constrained would pass invariant (i) while holding
	// strictly more authority than its parent, which inverts monotonic
	// delegation. Narrowing may only ever go one way: if the parent constrained
	// a dimension, the child must constrain it too.
	if len(parent.Actions) > 0 && len(child.Actions) == 0 {
		return fmt.Errorf("child leaves actions unconstrained while parent constrains them")
	}
	if len(parent.Resources) > 0 && len(child.Resources) == 0 {
		return fmt.Errorf("child leaves resources unconstrained while parent constrains them")
	}
	for _, a := range child.Actions {
		if !contains(parent.Actions, a) {
			return fmt.Errorf("action %q not in parent scope", a)
		}
	}
	for _, r := range child.Resources {
		if !patternCovered(r, parent.Resources) {
			return fmt.Errorf("resource %q not covered by parent scope", r)
		}
	}
	return nil
}

// patternCovered reports whether child resource pattern r is covered by some
// parent pattern. A parent pattern "p*" covers any child pattern sharing prefix
// "p"; an exact parent pattern covers only an equal child pattern.
func patternCovered(r string, parents []string) bool {
	// A prefix match on an un-normalized string is not containment. "svc/*"
	// textually covers "svc/../db/main", which resolves outside svc entirely, so
	// a traversal segment turns a narrowing pattern into an escape. Resources
	// are opaque to this package — it cannot know whether the consumer resolves
	// them as paths — so the safe reading is that a resource carrying a
	// traversal segment is covered by nothing and fails closed.
	if hasTraversal(r) {
		return false
	}
	for _, p := range parents {
		if p == r {
			return true
		}
		if n := len(p); n > 0 && p[n-1] == '*' {
			prefix := p[:n-1]
			if len(r) >= len(prefix) && r[:len(prefix)] == prefix {
				return true
			}
		}
	}
	return false
}

// hasTraversal reports whether s contains a ".." path segment, on either
// separator. Matching whole segments rather than the substring ".." keeps
// legitimate names such as "svc/my..app" usable.
func hasTraversal(s string) bool {
	for _, sep := range []string{"/", "\\"} {
		for _, seg := range strings.Split(s, sep) {
			if seg == ".." {
				return true
			}
		}
	}
	return s == ".."
}

// boundaryWithin checks child boundary ≤ parent boundary (invariant ii): every
// child ceiling is equal to or lower than the parent's, child quotas do not
// exceed parent quotas, and child exclusions include all parent exclusions.
func boundaryWithin(child, parent PermissionBoundary) error {
	if child.MaxImpact > parent.MaxImpact {
		return fmt.Errorf("max_impact %d > parent %d", child.MaxImpact, parent.MaxImpact)
	}
	if child.MaxPrivilegeDelta > parent.MaxPrivilegeDelta {
		return fmt.Errorf("max_privilege_delta %d > parent %d", child.MaxPrivilegeDelta, parent.MaxPrivilegeDelta)
	}
	// Iterating the CHILD's quotas only compares the keys the child chose to
	// mention, so a child that drops a quota key — or the whole map — is
	// compared against nothing and passes. That is the same inversion as an
	// omitted scope dimension: an absent quota is not a smaller quota, it is an
	// unstated one, and an enforcement point reading a missing key as "no limit"
	// would grant the child more than its parent held. Every parent quota must
	// survive into the child.
	for k, pq := range parent.ResourceQuotas {
		cq, ok := child.ResourceQuotas[k]
		if !ok {
			return fmt.Errorf("parent quota %q dropped by child", k)
		}
		if cq > pq {
			return fmt.Errorf("quota %q %d > parent %d", k, cq, pq)
		}
	}
	for k := range child.ResourceQuotas {
		if _, ok := parent.ResourceQuotas[k]; !ok {
			return fmt.Errorf("quota %q not present in parent", k)
		}
	}
	for _, pe := range parent.Exclusions {
		if !contains(child.Exclusions, pe) {
			return fmt.Errorf("parent exclusion %q dropped by child", pe)
		}
	}
	return nil
}

// constraintsStricter checks each child constraint is equal to or stricter than
// the corresponding parent constraint (invariant iii). Child constraints are
// matched to parent constraints by ID. A parent constraint with no
// corresponding child constraint is a loosening (the child dropped it) and
// fails; a child constraint with no parent counterpart is an added restriction
// and is always permitted.
func constraintsStricter(child, parent []Constraint) error {
	childByID := make(map[string]Constraint, len(child))
	for _, c := range child {
		childByID[c.ID] = c
	}
	for _, p := range parent {
		c, ok := childByID[p.ID]
		if !ok {
			return fmt.Errorf("parent constraint %q dropped by child", p.ID)
		}
		if !constraintAtLeastAsStrict(c, p) {
			return fmt.Errorf("constraint %q looser than parent", p.ID)
		}
	}
	return nil
}

// constraintAtLeastAsStrict reports whether child is at least as strict as
// parent for constraints of the same type. Differing types are treated as not
// comparable and therefore not stricter (fail closed).
func constraintAtLeastAsStrict(child, parent Constraint) bool {
	if child.Type != parent.Type {
		return false
	}
	switch parent.Type {
	case "temporal":
		// Child window must be within parent window.
		return withinTemporal(child, parent)
	case "network_zone":
		// Child zones ⊆ parent zones — but an EMPTY child zone list is not the
		// smallest set, it is no restriction at all, matching how an empty scope
		// list means unconstrained. Read as a set it is trivially a subset, which
		// would let a child keep a constraint's ID while neutralising it and still
		// satisfy invariant (iii).
		if len(parent.Zones) > 0 && len(child.Zones) == 0 {
			return false
		}
		return subsetOf(child.Zones, parent.Zones)
	case "param_bound":
		return tighterBound(child, parent)
	case "resource_state":
		// Child must constrain the same key at least as tightly: if parent uses
		// an In-set, child's In-set (or Equals) must be a subset; if parent uses
		// Equals, child must pin the same value.
		return tighterResourceState(child, parent)
	case "rate_limit":
		if parent.MaxRate == nil {
			return true
		}
		return child.MaxRate != nil && *child.MaxRate <= *parent.MaxRate
	case "latency_bound":
		// A shorter (or equal) latency budget is stricter.
		if parent.MaxMS == 0 {
			return true
		}
		return child.MaxMS != 0 && child.MaxMS <= parent.MaxMS
	default:
		return false
	}
}

func withinTemporal(child, parent Constraint) bool {
	// Child not_before >= parent not_before and child not_after <= parent
	// not_after. Empty parent bound means unbounded on that side.
	if parent.NotBefore != "" {
		if child.NotBefore == "" || child.NotBefore < parent.NotBefore {
			return false
		}
	}
	if parent.NotAfter != "" {
		if child.NotAfter == "" || child.NotAfter > parent.NotAfter {
			return false
		}
	}
	return true
}

func tighterBound(child, parent Constraint) bool {
	if child.Param != parent.Param {
		return false
	}
	// Child min must be >= parent min; child max must be <= parent max.
	if parent.Min != nil {
		if child.Min == nil || *child.Min < *parent.Min {
			return false
		}
	}
	if parent.Max != nil {
		if child.Max == nil || *child.Max > *parent.Max {
			return false
		}
	}
	return true
}

func tighterResourceState(child, parent Constraint) bool {
	if child.Key != parent.Key {
		return false
	}
	parentSet := parent.In
	if len(parentSet) == 0 && parent.Equals != "" {
		parentSet = []string{parent.Equals}
	}
	childSet := child.In
	if len(childSet) == 0 && child.Equals != "" {
		childSet = []string{child.Equals}
	}
	if len(parentSet) == 0 {
		return true // parent unconstrained on value
	}
	if len(childSet) == 0 {
		return false // child dropped the value constraint
	}
	return subsetOf(childSet, parentSet)
}

func subsetOf(sub, super []string) bool {
	for _, s := range sub {
		if !contains(super, s) {
			return false
		}
	}
	return true
}

// obligationsSuperset checks child obligations ⊇ parent obligations (invariant
// iv): for every parent obligation category the child must carry an obligation
// of the same category with an equal-or-shorter (stricter) freshness window.
func obligationsSuperset(child, parent []ProofObligation) error {
	childByCat := make(map[string]ProofObligation, len(child))
	for _, o := range child {
		childByCat[o.Category] = o
	}
	for _, p := range parent {
		c, ok := childByCat[p.Category]
		if !ok {
			return fmt.Errorf("parent obligation %q missing from child", p.Category)
		}
		if c.MaxAgeSeconds > p.MaxAgeSeconds {
			return fmt.Errorf("obligation %q freshness %ds looser than parent %ds", p.Category, c.MaxAgeSeconds, p.MaxAgeSeconds)
		}
	}
	return nil
}

// ValidateChain validates a delegation chain from a root MAT down to a leaf,
// enforcing per-step derivation invariants, acyclicity (¶0073), and depth
// (¶0041 field 134). The chain is ordered root-first; chain[0] must be a root
// (no ParentID) and each subsequent element's ParentID must equal the previous
// element's ID.
func ValidateChain(chain []*MAT) error {
	if len(chain) == 0 {
		return fmt.Errorf("delegation: empty chain")
	}
	if chain[0].ParentID != "" {
		return fmt.Errorf("delegation: chain[0] %s is not a root (has parent %s)", chain[0].ID, chain[0].ParentID)
	}
	seen := map[string]bool{chain[0].ID: true}
	for i := 1; i < len(chain); i++ {
		parent, child := chain[i-1], chain[i]
		if child.ParentID != parent.ID {
			return fmt.Errorf("delegation: chain break at %d: %s parent is %q, expected %q", i, child.ID, child.ParentID, parent.ID)
		}
		if seen[child.ID] {
			return fmt.Errorf("%w: %s repeats", ErrDelegationCycle, child.ID)
		}
		seen[child.ID] = true
		// Depth: the i-th derivation (1-based) must not exceed the root's
		// declared MaxDepth. An unstated depth is not an unlimited one — guarding
		// with `md > 0` turned a root that omitted MaxDepth into a root granting
		// chains of any length, which is the deepest possible grant arising from
		// the shallowest possible statement. A root that permits delegation must
		// say how far.
		if md := chain[0].Delegation.MaxDepth; md <= 0 {
			return fmt.Errorf("%w: root %s permits delegation without stating a depth", ErrDelegationDepthExceeded, chain[0].ID)
		} else if i > md {
			return fmt.Errorf("%w: depth %d > allowed %d", ErrDelegationDepthExceeded, i, md)
		}
		if err := ValidateDerivation(parent, child); err != nil {
			return fmt.Errorf("delegation step %d (%s→%s): %w", i, parent.ID, child.ID, err)
		}
	}
	return nil
}
