package main

import (
	"encoding/hex"
	"testing"

	xap "github.com/Vidimuslabs/xap-go"
)

// This is the test whose absence let a verifier that cannot start reach
// production. `go build ./...` covers this command and stayed green throughout,
// because every way it was broken was a runtime failure in main() and nothing
// ran main(). Compiling a binary is not evidence that it starts.
func TestEmbeddedAnchorsBuild(t *testing.T) {
	anchors, err := buildAnchors()
	if err != nil {
		t.Fatalf("the demo's embedded anchors do not build: %v\n"+
			"main() panics on this, so the wasm exports nothing and the verify page is dead on load", err)
	}
	if anchors == nil {
		t.Fatal("buildAnchors returned no anchor set and no error")
	}
}

// Building the anchor set is necessary and not sufficient: the page's whole
// claim is that this receipt verifies against these anchors. A manifest that
// builds but no longer matches the embedded receipt would load fine and tell
// every visitor the signature is invalid.
func TestEmbeddedReceiptVerifiesAgainstEmbeddedAnchors(t *testing.T) {
	anchors, err := buildAnchors()
	if err != nil {
		t.Fatalf("buildAnchors: %v", err)
	}
	env, err := hex.DecodeString(prodReceiptHex)
	if err != nil {
		t.Fatalf("embedded receipt is not valid hex: %v", err)
	}
	if _, err := xap.ParseReceipt(env, anchors); err != nil {
		t.Fatalf("the demo receipt no longer verifies against the demo anchors: %v", err)
	}
}

// The inverse, because a verifier that accepts everything would pass the test
// above. One flipped byte in the middle of the envelope must be rejected.
func TestTamperedReceiptIsRejected(t *testing.T) {
	anchors, err := buildAnchors()
	if err != nil {
		t.Fatalf("buildAnchors: %v", err)
	}
	env, err := hex.DecodeString(prodReceiptHex)
	if err != nil {
		t.Fatal(err)
	}
	env[len(env)/2] ^= 0x01
	if _, err := xap.ParseReceipt(env, anchors); err == nil {
		t.Fatal("a tampered receipt verified — the page would tell a visitor that tampering is undetectable")
	}
}

// Every anchor must name what it is trusted to sign. An anchor with no role is
// exactly the defect that broke the deployed build, and it is invisible until
// something constructs the set.
func TestEveryEmbeddedAnchorDeclaresItsRoles(t *testing.T) {
	for _, a := range anchorManifest.Anchors {
		if len(a.Roles) == 0 {
			t.Errorf("anchor %q declares no signer roles", a.KIDHex)
		}
	}
}
