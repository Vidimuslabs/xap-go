// Example: validate a delegation chain against the four monotonic invariants
// (¶0057). Prints whether the child MAT is a valid derivation of the parent.
package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"strings"

	xap "github.com/Vidimuslabs/xap-go"
	"github.com/Vidimuslabs/xap-go/conformance"
	"github.com/Vidimuslabs/xap-spec/vectors"
)

func main() {
	m, err := vectors.Load()
	if err != nil {
		log.Fatal(err)
	}
	// BuildAnchors dispatches on each anchor's declared algorithm. Registering
	// them by hand with AddEd25519 would mis-file the manifest's hybrid anchor,
	// whose public key is an ECDSA SPKI rather than a raw Ed25519 key.
	anchors, err := conformance.BuildAnchors(m)
	if err != nil {
		log.Fatal(err)
	}

	parent, err := xap.ParseMAT(load("mat_root.hex"), anchors)
	if err != nil {
		log.Fatal(err)
	}
	child, err := xap.ParseMAT(load("mat_child_valid.hex"), anchors)
	if err != nil {
		log.Fatal(err)
	}

	if err := xap.ValidateDerivation(&parent.MAT, &child.MAT); err != nil {
		fmt.Printf("child %s is NOT a valid derivation: %v\n", child.MAT.ID, err)
		return
	}
	fmt.Printf("child %s is a valid derivation of %s\n", child.MAT.ID, parent.MAT.ID)
}

func load(name string) []byte {
	raw, err := vectors.File(name)
	if err != nil {
		log.Fatal(err)
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		log.Fatal(err)
	}
	return b
}
