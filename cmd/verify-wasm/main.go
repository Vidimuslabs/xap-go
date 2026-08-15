//go:build js && wasm

// Command verify-wasm exposes xap-go's verify-only path to the browser as a
// WebAssembly module, so the public verifier demo runs entirely client-side
// (no backend). It verifies a real, production-flavored permit receipt issued
// by the engine (network_isolation on host:prod-web-17) against its embedded
// hybrid trust anchors — the same verify code the CLI and conformance use.
package main

import (
	"encoding/hex"
	"strings"
	"syscall/js"

	xap "github.com/Vidimuslabs/xap-go"
)

var anchors *xap.TrustAnchorSet

// demoReceiptHex returns the raw hex of the real, valid production receipt.
func demoReceiptHex(js.Value, []js.Value) any { return prodReceiptHex }

// verify runs xap-go's signature verification over the given receipt hex.
func verify(_ js.Value, args []js.Value) any {
	if len(args) < 1 {
		return map[string]any{"valid": false, "message": "No receipt provided."}
	}
	env, err := hex.DecodeString(strings.TrimSpace(args[0].String()))
	if err != nil {
		return map[string]any{"valid": false, "message": "Malformed receipt encoding — not valid hex."}
	}
	if _, err := xap.ParseReceipt(env, anchors); err != nil {
		return map[string]any{"valid": false, "message": "Signature verification FAILED — " + err.Error()}
	}
	return map[string]any{"valid": true, "message": "Hybrid signature verified: ECDSA P-384 + ML-DSA-65 (both halves)."}
}

// exportNames are the globals the page calls. Named here rather than written
// inline at the Set calls so a test can assert the page's contract by the same
// list the code registers from: a rename that misses one is otherwise a working
// build and a dead button.
var exportNames = []string{"xapDemoReceiptHex", "xapVerify"}

// register builds the anchor set and installs the exported functions on the JS
// global. Separated from main so a test can drive it — main blocks forever on
// purpose, and a test cannot call something that never returns.
func register() error {
	a, err := buildAnchors()
	if err != nil {
		return err
	}
	anchors = a
	js.Global().Set("xapDemoReceiptHex", js.FuncOf(demoReceiptHex))
	js.Global().Set("xapVerify", js.FuncOf(verify))
	return nil
}

func main() {
	if err := register(); err != nil {
		panic(err)
	}
	select {} // keep the instance alive so exported funcs stay callable
}
