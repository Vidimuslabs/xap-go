package conformance

import (
	"sort"
	"testing"

	xap "github.com/Vidimuslabs/xap-go"

	"github.com/Vidimuslabs/xap-spec/constants"
	"github.com/Vidimuslabs/xap-spec/vectors"
)

// The suite asserted only that every vector in the manifest reproduces its
// expected outcome, and that at least one vector ran. Whatever the manifest
// happened to contain was therefore the definition of conforming, and a corpus
// that lost vectors — to a stale tag, a bad merge, a dropped file — still
// reported a clean run. That is not a hypothetical: a spec tag 20 commits
// behind HEAD published 19 of 66 vectors and printed "19/19 passed".
//
// These gates make coverage a property the suite checks rather than a property
// someone remembers to maintain.

func load(t *testing.T) *vectors.Manifest {
	t.Helper()
	m, err := vectors.Load()
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	return m
}

// A check no vector can drive to failure is a check an implementation may
// simply not perform while reproducing every expected outcome. Measured before
// this gate existed: a verifier with nine checks removed passed 37/37, and one
// that never verified a receipt's signature passed 37/37 as well.
func TestEveryVerifierCheckIsPinnedByAVector(t *testing.T) {
	m := load(t)
	anchors, err := BuildAnchors(m)
	if err != nil {
		t.Fatalf("build anchors: %v", err)
	}
	cov, err := CheckCoverage(anchors, m)
	if err != nil {
		t.Fatalf("check coverage: %v", err)
	}
	emitted, failed, notPerformed := cov.Emitted, cov.Failed, cov.NotPerformed

	declared := make(map[string]bool, len(VerifierChecks))
	for _, c := range VerifierChecks {
		declared[c] = true
	}

	var unpinned []string
	for _, c := range VerifierChecks {
		if !failed[c] {
			unpinned = append(unpinned, c)
		}
	}
	sort.Strings(unpinned)
	for _, c := range unpinned {
		t.Errorf("check %q is never driven to failure by any vector: an implementation "+
			"that omits it reproduces every expected outcome", c)
	}

	// The mirror image, and the one the corpus was missing. A vector expecting
	// "invalid" cannot say WHICH check made it invalid, so a check no vector
	// ever drives to PASS is satisfied by an implementation that hard-codes it
	// to failed. That is how redefining the chain link in 2026-08-12 went
	// unnoticed at 82/82: receipt_broken_chain pinned the failure and nothing
	// pinned the success.
	var neverPassed []string
	for _, c := range VerifierChecks {
		if !cov.Passed[c] {
			neverPassed = append(neverPassed, c)
		}
	}
	sort.Strings(neverPassed)
	for _, c := range neverPassed {
		t.Errorf("check %q is never driven to PASS by any vector: an implementation "+
			"that reports it as failed unconditionally reproduces every expected "+
			"outcome, because a vector expecting \"invalid\" does not say which "+
			"check failed", c)
	}

	// A check that reports not-performed must say so in the declared list, or
	// nobody was ever asked to pin the distinction for it.
	var undeclaredNP []string
	npCapable := make(map[string]bool, len(NotPerformedCapableChecks))
	for _, c := range NotPerformedCapableChecks {
		npCapable[c] = true
	}
	for c := range notPerformed {
		if !npCapable[c] {
			undeclaredNP = append(undeclaredNP, c)
		}
	}
	sort.Strings(undeclaredNP)
	for _, c := range undeclaredNP {
		t.Errorf("check %q reports not_performed but is not in NotPerformedCapableChecks", c)
	}

	// The other direction, which is what catches a check added later. An
	// emitted-but-undeclared check has no entry above, so nobody was ever
	// asked to pin it.
	var undeclared []string
	for c := range emitted {
		if !declared[c] {
			undeclared = append(undeclared, c)
		}
	}
	sort.Strings(undeclared)
	for _, c := range undeclared {
		t.Errorf("verifier emits check %q, which is not in VerifierChecks: add it there "+
			"and mint a vector that fails it", c)
	}
}

// §12 says a conforming implementation reproduces every expected outcome, and
// §10 is a closed registry. A registered code that appears in no vector leaves
// conformance silent on part of the registry — which was true of five of the
// nine codes until 2026-08-10.
func TestEveryRegisteredCodeAppearsInAVector(t *testing.T) {
	m := load(t)
	seen := make(map[string]bool)
	for _, v := range m.Vectors {
		if v.ExpectCode != "" {
			seen[v.ExpectCode] = true
		}
	}
	for _, code := range constants.Codes() {
		if !seen[code] {
			t.Errorf("registered code %q is the expected code of no vector: conformance "+
				"says nothing about how an implementation must treat it", code)
		}
	}
}

// Every vector kind the manifest uses must be one the runner interprets.
// dispatch reports an unknown kind as a failure, so this cannot silently pass,
// but the failure would name the vector rather than the omission — and a kind
// added to the manifest with no runner support is the omission.
func TestEveryVectorKindIsInterpreted(t *testing.T) {
	known := map[string]bool{
		"mat": true, "delegation": true, "delegation_chain": true, "canon": true,
		"receipt": true, "commitment_binding": true, "provenance": true,
	}
	for _, v := range load(t).Vectors {
		if !known[v.Kind] {
			t.Errorf("vector %q has kind %q, which no runner branch interprets", v.Name, v.Kind)
		}
	}
}

// "Not performed" and "passed" both produce a receipt that verifies, so the
// overall expectation of a vector cannot distinguish them. An implementation
// that reports an unavailable check as passed — asserting a gate it never
// applied, which is what §9 step 5 forbids in as many words — reproduces every
// expected outcome unless a vector pins the status itself.
func TestNotPerformedIsPinnedForEveryCapableCheck(t *testing.T) {
	pinned := make(map[string]bool)
	for _, v := range load(t).Vectors {
		for name, want := range v.ExpectChecks {
			if want == string(xap.CheckNotPerformed) {
				pinned[name] = true
			}
		}
	}
	for _, c := range NotPerformedCapableChecks {
		if !pinned[c] {
			t.Errorf("check %q can report not_performed and no vector pins it: an "+
				"implementation reporting it as passed still reproduces every expected outcome", c)
		}
	}
}

// The delegation surface is reached by direct calls rather than by the receipt
// verification state machine, so TestEveryVerifierCheckIsPinnedByAVector says
// nothing about it. Measured before this gate: six strictness paths could be
// deleted from ValidateDerivation with the corpus at 72/72 and the verifier
// gate green — MaxPrivilegeDelta, an oversized child quota, constraint type
// mismatch, and the param_bound, resource_state and latency_bound comparisons.
// Two of those comparisons had never executed at all, the corpus minting no
// constraint of either type.
func TestEveryDerivationPathIsPinnedByAVector(t *testing.T) {
	m := load(t)
	anchors, err := BuildAnchors(m)
	if err != nil {
		t.Fatalf("build anchors: %v", err)
	}
	reached, err := DerivationCoverage(anchors, m)
	if err != nil {
		t.Fatalf("derivation coverage: %v", err)
	}

	declared := make(map[string]bool, len(DerivationPaths))
	var unpinned []string
	for _, p := range DerivationPaths {
		declared[p] = true
		if !reached[p] {
			unpinned = append(unpinned, p)
		}
	}
	sort.Strings(unpinned)
	for _, p := range unpinned {
		t.Errorf("derivation path %q is reached by no vector: an implementation that "+
			"omits the rule reproduces every expected outcome", p)
	}

	var undeclared []string
	for p := range reached {
		if !declared[p] {
			undeclared = append(undeclared, p)
		}
	}
	sort.Strings(undeclared)
	for _, p := range undeclared {
		t.Errorf("vector reaches derivation path %q, which is not in DerivationPaths", p)
	}
}
