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

// exports are the globals the page calls, keyed by the exact names it calls them
// by. register loops over this map, so each name is written once in the code.
//
// The previous arrangement wrote the names inline at the Set calls and kept a
// second list beside them, with a comment claiming a test could assert the
// contract "by the same list the code registers from" — which it could not,
// because registration did not read that list.
//
// The test deliberately does NOT read this map to decide what to look for. It
// carries its own literals, since a test that asks the code what it exports and
// then checks that it exports it agrees by construction and passes for any pair
// of names, renamed included. See exports_js_test.go.
var exports = map[string]func(js.Value, []js.Value) any{
	"xapDemoReceiptHex": demoReceiptHex,
	"xapVerify":         verify,
}

// register builds the anchor set and installs the exported functions on the JS
// global. Separated from main so a test can drive it — main blocks forever on
// purpose, and a test cannot call something that never returns.
func register() error {
	a, err := buildAnchors()
	if err != nil {
		return err
	}
	anchors = a
	for name, fn := range exports {
		js.Global().Set(name, js.FuncOf(fn))
	}
	return nil
}

func main() {
	if err := register(); err != nil {
		panic(err)
	}
	select {} // keep the instance alive so exported funcs stay callable
}
