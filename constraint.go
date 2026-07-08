package xap

import (
	"time"
)

// Constraint is one element of the portable constraint representation (MAT
// field 132, ¶0041; ¶0087). A constraint encodes a runtime condition evaluated
// against the runtime context at execution time with consistent, reproducible
// outcomes (¶0016, ¶0047). Only the fields relevant to Type are populated; the
// canonical encoding (Core Deterministic CBOR) drops empty fields so the
// on-the-wire form is stable regardless of which type a constraint is.
//
// The verifier evaluates constraints with the same deterministic Evaluate
// method the engine uses, so an independent party recomputes the identical
// per-constraint outcome from the same context (¶0095).
type Constraint struct {
	// ID uniquely identifies the constraint within an artifact; it labels the
	// per-constraint rationale in the receipt and pairs parent/child constraints
	// during delegation strictness checks.
	ID string `cbor:"id"`
	// Type is one of: "temporal", "network_zone", "rate_limit", "param_bound",
	// "resource_state", "latency_bound". Unknown types evaluate as unsatisfied.
	Type string `cbor:"type"`

	// temporal: execution permitted only within [NotBefore, NotAfter] (RFC3339).
	NotBefore string `cbor:"not_before,omitempty"`
	NotAfter  string `cbor:"not_after,omitempty"`

	// network_zone: context network zone must be a member of Zones.
	Zones []string `cbor:"zones,omitempty"`

	// param_bound: context parameter Param must satisfy Min<=v and v<=Max.
	Param string   `cbor:"param,omitempty"`
	Min   *float64 `cbor:"min,omitempty"`
	Max   *float64 `cbor:"max,omitempty"`

	// resource_state: context resource state at Key must equal Equals, or be a
	// member of In when In is non-empty.
	Key    string   `cbor:"key,omitempty"`
	Equals string   `cbor:"equals,omitempty"`
	In     []string `cbor:"in,omitempty"`

	// rate_limit: context rate for this constraint ID must not exceed MaxRate.
	MaxRate *int64 `cbor:"max_rate,omitempty"`

	// latency_bound: maximum evaluation latency in milliseconds (¶0077). This is
	// an evaluation budget, not a context predicate; it always evaluates as
	// satisfied and is consumed by the engine's latency path and by the
	// verifier's timing check.
	MaxMS int64 `cbor:"max_ms,omitempty"`
}

// ConstraintOutcome is the binary evaluation result for one constraint,
// recorded in the receipt with an optional rationale/error code (¶0047).
type ConstraintOutcome struct {
	ConstraintID string `cbor:"id"`
	Satisfied    bool   `cbor:"satisfied"`
	// Code is a rationale/error code from xap-spec/constants when Satisfied is
	// false (typically CONSTRAINT_EVALUATION_FAILURE).
	Code string `cbor:"code,omitempty"`
}

// Evaluate evaluates the constraint against a runtime context with a
// deterministic, reproducible outcome (¶0016). The same (constraint, context)
// pair always yields the same result on any implementation.
func (c Constraint) Evaluate(ctx RuntimeContext) bool {
	switch c.Type {
	case "temporal":
		return c.evalTemporal(ctx)
	case "network_zone":
		return contains(c.Zones, ctx.NetworkZone)
	case "param_bound":
		return c.evalParamBound(ctx)
	case "resource_state":
		return c.evalResourceState(ctx)
	case "rate_limit":
		return c.evalRateLimit(ctx)
	case "latency_bound":
		// An evaluation budget, not a predicate over context; satisfied here and
		// enforced by the engine's latency path / verifier timing check.
		return true
	default:
		// Unknown constraint types fail closed (¶0064 fail-closed principle).
		return false
	}
}

func (c Constraint) evalTemporal(ctx RuntimeContext) bool {
	now, err := time.Parse(time.RFC3339, ctx.Time)
	if err != nil {
		return false
	}
	if c.NotBefore != "" {
		nb, err := time.Parse(time.RFC3339, c.NotBefore)
		if err != nil || now.Before(nb) {
			return false
		}
	}
	if c.NotAfter != "" {
		na, err := time.Parse(time.RFC3339, c.NotAfter)
		if err != nil || now.After(na) {
			return false
		}
	}
	return true
}

func (c Constraint) evalParamBound(ctx RuntimeContext) bool {
	v, ok := ctx.Params[c.Param]
	if !ok {
		return false
	}
	if c.Min != nil && v < *c.Min {
		return false
	}
	if c.Max != nil && v > *c.Max {
		return false
	}
	return true
}

func (c Constraint) evalResourceState(ctx RuntimeContext) bool {
	v, ok := ctx.ResourceState[c.Key]
	if !ok {
		return false
	}
	if len(c.In) > 0 {
		return contains(c.In, v)
	}
	return v == c.Equals
}

func (c Constraint) evalRateLimit(ctx RuntimeContext) bool {
	if c.MaxRate == nil {
		return false
	}
	return ctx.Rate[c.ID] <= *c.MaxRate
}

func contains(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}
