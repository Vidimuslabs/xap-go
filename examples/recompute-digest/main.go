// Example: recompute a runtime context digest from reproduced inputs and
// compare it to the value a receipt would carry (¶0018, ¶0095). This is the
// heart of independent verification: identical semantic inputs canonicalize to
// identical bytes, so any party computes the same digest.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"

	xap "github.com/Vidimuslabs/xap-go"
	"github.com/Vidimuslabs/xap-spec/vectors"
)

func main() {
	raw, err := vectors.File("ctx_permit.json")
	if err != nil {
		log.Fatal(err)
	}
	var ctx xap.RuntimeContext
	if err := json.Unmarshal(raw, &ctx); err != nil {
		log.Fatal(err)
	}
	digest, err := ctx.Digest()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("runtime context digest: %s\n", hex.EncodeToString(digest))

	// Reorder the JSON and confirm the digest is unchanged (order independence).
	reordered := xap.RuntimeContext{Rate: ctx.Rate, NetworkZone: ctx.NetworkZone, Time: ctx.Time}
	again, _ := reordered.Digest()
	fmt.Printf("same context, different field order: %s\n", hex.EncodeToString(again))
	fmt.Printf("digests match: %v\n", hex.EncodeToString(digest) == hex.EncodeToString(again))
}
