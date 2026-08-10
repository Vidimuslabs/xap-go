// Example: verify a receipt in ~20 lines, using only public keys — the
// third-party verification the protocol is built for (¶0017, ¶0095).
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

	receipt := mustHex(vectors.File("receipt_permit.hex"))
	mat := mustHex(vectors.File("mat_root.hex"))

	res := xap.NewVerifier(anchors).Verify(xap.VerifyInput{
		ReceiptEnvelope: receipt,
		MATEnvelope:     mat,
	})
	fmt.Printf("artifact=%s decision=%s valid=%v\n", res.ArtifactID, res.Decision, res.Valid)
}

func mustHex(raw []byte, err error) []byte {
	if err != nil {
		log.Fatal(err)
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		log.Fatal(err)
	}
	return b
}
