package xap

import (
	"encoding/hex"
	"fmt"
)

// Multi-agent commitment provenance reconstruction (¶0084A Commitment
// Provenance Field). When a second agent operates under the authorization of a
// first, its derived commitment carries a provenance reference to the first
// agent's authority artifact and commitment digest, and each of its receipts
// carries the same reference. An independent verifier can therefore reconstruct
// the complete multi-agent derivation chain from cryptographic proof structures
// alone — no access to any agent's or controller's internal state.

// ChainLink is one edge in a reconstructed provenance chain: a receipt and the
// commitment digest that governed it, plus its parent commitment digest (empty
// for the root agent).
type ChainLink struct {
	ReceiptID        string
	ArtifactID       string
	CommitmentDigest []byte
	ParentDigest     []byte // nil/empty at the root
}

// ReconstructProvenance orders a set of receipts into a single provenance chain,
// root first, following each receipt's provenance parent digest back to the
// commitment it derives from (¶0084A). It fails if the receipts do not form a
// single connected chain, if a referenced parent is missing (a broken link), or
// if a cycle is present.
//
// Each input receipt must carry a CommitmentDigest; a receipt's Provenance,
// when present, must reference the CommitmentDigest of exactly one other receipt
// in the set.
func ReconstructProvenance(receipts []*Receipt) ([]ChainLink, error) {
	if len(receipts) == 0 {
		return nil, fmt.Errorf("provenance: no receipts")
	}

	// Index receipts by their governing commitment digest.
	byDigest := make(map[string]*Receipt, len(receipts))
	var roots []*Receipt
	for _, r := range receipts {
		if len(r.CommitmentDigest) == 0 {
			return nil, fmt.Errorf("provenance: receipt %s has no commitment digest", r.ID)
		}
		key := hex.EncodeToString(r.CommitmentDigest)
		if _, dup := byDigest[key]; dup {
			return nil, fmt.Errorf("provenance: two receipts share commitment digest %s", short(key))
		}
		byDigest[key] = r
		if r.Provenance == nil || len(r.Provenance.ParentCommitmentDigest) == 0 {
			roots = append(roots, r)
		}
	}

	if len(roots) != 1 {
		return nil, fmt.Errorf("provenance: expected exactly one root, found %d", len(roots))
	}

	// Verify every non-root parent reference resolves (detect broken links).
	for _, r := range receipts {
		if r.Provenance == nil || len(r.Provenance.ParentCommitmentDigest) == 0 {
			continue
		}
		pk := hex.EncodeToString(r.Provenance.ParentCommitmentDigest)
		if _, ok := byDigest[pk]; !ok {
			return nil, fmt.Errorf("provenance: broken link — receipt %s references missing parent commitment %s", r.ID, short(pk))
		}
	}

	// Walk from the root, following children, producing an ordered chain and
	// detecting cycles / disconnected members.
	chain := make([]ChainLink, 0, len(receipts))
	visited := make(map[string]bool, len(receipts))
	cur := roots[0]
	for {
		key := hex.EncodeToString(cur.CommitmentDigest)
		if visited[key] {
			return nil, fmt.Errorf("%w in provenance chain at %s", ErrDelegationCycle, cur.ID)
		}
		visited[key] = true

		link := ChainLink{
			ReceiptID:        cur.ID,
			ArtifactID:       cur.ArtifactID,
			CommitmentDigest: cur.CommitmentDigest,
		}
		if cur.Provenance != nil {
			link.ParentDigest = cur.Provenance.ParentCommitmentDigest
		}
		chain = append(chain, link)

		// Find the unique child whose provenance points at cur.
		next := childOf(cur, receipts)
		if next == nil {
			break
		}
		cur = next
	}

	if len(chain) != len(receipts) {
		return nil, fmt.Errorf("provenance: %d receipts do not form a single connected chain (linked %d)", len(receipts), len(chain))
	}
	return chain, nil
}

// childOf returns the unique receipt whose provenance parent digest equals
// parent's commitment digest, or nil if there is none. It errs toward nil on
// ambiguity; a fan-out (two children) is caught by the final length check.
func childOf(parent *Receipt, receipts []*Receipt) *Receipt {
	var found *Receipt
	for _, r := range receipts {
		if r.Provenance == nil {
			continue
		}
		if hexEqual(r.Provenance.ParentCommitmentDigest, parent.CommitmentDigest) {
			if found != nil {
				return nil // ambiguous fan-out; length check will flag it
			}
			found = r
		}
	}
	return found
}

func hexEqual(a, b []byte) bool {
	return hex.EncodeToString(a) == hex.EncodeToString(b)
}

// short truncates a hex key for readable error messages without assuming a
// minimum length.
func short(hexKey string) string {
	if len(hexKey) <= 16 {
		return hexKey
	}
	return hexKey[:16]
}
