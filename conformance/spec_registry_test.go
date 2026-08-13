package conformance

import (
	"sort"
	"strings"
	"testing"

	"github.com/Vidimuslabs/xap-spec/docs"
)

// TestVerifierChecksMatchTheSpecRegistry holds the verifier's check vocabulary
// to SPEC.md §9.2, in both directions.
//
// The names are protocol vocabulary, not internal labels: they are the `name`
// field of every entry in a verification result, and the entries a relying party
// names when it requires a minimum before acting. A second implementation is
// written against the specification, not against this package — so a check this
// verifier emits under a name §9.2 does not list is a name nothing else knows,
// and a name §9.2 lists that nothing emits is a check a reader is entitled to
// require and will never see.
//
// The registry was written after both lists already existed, which is the
// weakest moment for a document: it agreed with the code on the day it was
// typed and had nothing holding it there.
func TestVerifierChecksMatchTheSpecRegistry(t *testing.T) {
	registry, err := docs.VerificationChecks()
	if err != nil {
		t.Fatalf("read the §9.2 check registry: %v", err)
	}

	inSpec := map[string]bool{}
	for _, c := range registry {
		inSpec[c.Name] = true
	}
	emitted := map[string]bool{}
	for _, name := range VerifierChecks {
		emitted[name] = true
	}

	if missing := difference(emitted, inSpec); len(missing) > 0 {
		t.Errorf("the verifier emits checks SPEC.md §9.2 does not list — a second "+
			"implementation has no way to know these names:\n  %s", strings.Join(missing, "\n  "))
	}
	if unimplemented := difference(inSpec, emitted); len(unimplemented) > 0 {
		t.Errorf("SPEC.md §9.2 lists checks the verifier never emits — a relying party "+
			"may require them and never see them:\n  %s", strings.Join(unimplemented, "\n  "))
	}
}

// TestNotPerformedCapabilityMatchesTheSpecRegistry holds the ✓ column of §9.2 to
// the list the conformance gate enforces.
//
// This column is the one a reader acts on. It tells a relying party which checks
// can come back without a verdict, and therefore which absences to treat as
// something to satisfy rather than something to accept — the whole reason
// not-performed is a distinct answer. A column that says a check always reaches
// a verdict, over a verifier that can return not-performed for it, describes
// assurance the implementation does not provide.
func TestNotPerformedCapabilityMatchesTheSpecRegistry(t *testing.T) {
	registry, err := docs.VerificationChecks()
	if err != nil {
		t.Fatalf("read the §9.2 check registry: %v", err)
	}

	specCapable := map[string]bool{}
	for _, c := range registry {
		if c.MayReportNotPerformed {
			specCapable[c.Name] = true
		}
	}
	codeCapable := map[string]bool{}
	for _, name := range NotPerformedCapableChecks {
		codeCapable[name] = true
	}

	if missing := difference(codeCapable, specCapable); len(missing) > 0 {
		t.Errorf("these checks can report not_performed but §9.2 does not mark them — "+
			"the document promises a verdict the verifier may not reach:\n  %s",
			strings.Join(missing, "\n  "))
	}
	if overclaimed := difference(specCapable, codeCapable); len(overclaimed) > 0 {
		t.Errorf("§9.2 marks these as able to report not_performed but the conformance "+
			"gate does not require them pinned — either the mark or the list is "+
			"wrong:\n  %s", strings.Join(overclaimed, "\n  "))
	}
}

// difference returns the sorted members of a absent from b.
func difference(a, b map[string]bool) []string {
	var out []string
	for k := range a {
		if !b[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
