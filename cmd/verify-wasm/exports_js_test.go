//go:build js && wasm

// The JS-side contract, exercised under a real JS host.
//
// anchors_test.go covers what the Go code does with the embedded artifacts; it
// runs anywhere and is the cheaper gate. This file covers the part that only
// exists under GOOS=js: that register() installs the globals the page actually
// calls, under the names it calls them by, and that invoking them through JS
// values returns the shape the page reads.
//
// That seam has no compile-time checking at all. js.Global().Set takes a string,
// the page calls a string, and nothing relates the two — so a rename, a typo, or
// a changed result field is a green build serving a dead button. Run with:
//
//	PATH=$(go env GOROOT)/lib/wasm:$PATH GOOS=js GOARCH=wasm go test ./cmd/verify-wasm/
package main

import (
	"strings"
	"syscall/js"
	"testing"
)

func registerForTest(t *testing.T) {
	t.Helper()
	if err := register(); err != nil {
		t.Fatalf("register: %v\n"+
			"main() panics on this, so the wasm exports nothing and the page is dead on load", err)
	}
}

// pageContract is what vidimus-labs-site actually calls, written out here as
// literals rather than read from main.go's `exports` map.
//
// That distinction is the whole point. A test that asks the code which names it
// registers and then checks it registered them agrees by construction — it passes
// for any pair of names, including a renamed pair, which is exactly the case that
// leaves a working build serving a dead button. These literals are this
// repository's copy of the page's side of the contract, so a rename in main.go
// fails here instead of shipping.
//
// What it still cannot catch, stated because the gap is real: a rename applied to
// main.go and to this list together. Nothing inside xap-go can — the caller is in
// another repository and cannot be edited in the same commit. That is what
// scripts/verify-page.mjs in vidimus-labs-site is for, driving the served page in
// a browser.
var pageContract = []string{"xapDemoReceiptHex", "xapVerify"}

// The page calls these by name. If one is missing the wasm still loads, still
// reports no error, and the button does nothing.
func TestRegisterInstallsEveryExport(t *testing.T) {
	registerForTest(t)
	for _, name := range pageContract {
		v := js.Global().Get(name)
		if v.Type() != js.TypeFunction {
			t.Errorf("global %q is %s, want a function — the page calls this name", name, v.Type())
		}
	}
}

// The code must export the page's contract and nothing more. Compared as sets in
// both directions, because the two failures differ: an export the page does not
// call is dead weight that reads as supported surface, and a name the page calls
// that the code does not export is a dead button.
func TestExportSetMatchesThePageContract(t *testing.T) {
	inContract := make(map[string]bool, len(pageContract))
	for _, name := range pageContract {
		inContract[name] = true
	}
	for name := range exports {
		if !inContract[name] {
			t.Errorf("the code exports %q, which the page contract does not list", name)
		}
	}
	for _, name := range pageContract {
		if _, ok := exports[name]; !ok {
			t.Errorf("the page contract lists %q, which the code does not export", name)
		}
	}
}

// The full round trip the page performs: fetch the demo receipt, verify it, and
// read `valid` off the result.
func TestExportedVerifyAcceptsTheDemoReceipt(t *testing.T) {
	registerForTest(t)

	hex := js.Global().Call("xapDemoReceiptHex")
	if hex.Type() != js.TypeString || hex.String() == "" {
		t.Fatalf("xapDemoReceiptHex returned %s, want a non-empty string", hex.Type())
	}

	res := js.Global().Call("xapVerify", hex.String())
	if got := res.Get("valid"); got.Type() != js.TypeBoolean {
		t.Fatalf("result.valid is %s, want a boolean — the page branches on this field", got.Type())
	} else if !got.Bool() {
		t.Fatalf("the demo receipt did not verify: %s", res.Get("message").String())
	}
	if msg := res.Get("message"); msg.Type() != js.TypeString || msg.String() == "" {
		t.Error("result.message is empty — the page displays it")
	}
}

// The inverse. A verifier that accepts everything passes the test above, and the
// page's entire demonstration is that tampering is detectable.
func TestExportedVerifyRejectsATamperedReceipt(t *testing.T) {
	registerForTest(t)

	orig := js.Global().Call("xapDemoReceiptHex").String()
	i := len(orig) / 2
	swap := "a"
	if orig[i] == 'a' {
		swap = "b"
	}
	tampered := orig[:i] + swap + orig[i+1:]

	res := js.Global().Call("xapVerify", tampered)
	if res.Get("valid").Bool() {
		t.Fatal("a tampered receipt verified — the page would be demonstrating the opposite of its claim")
	}
	if !strings.Contains(res.Get("message").String(), "FAILED") {
		t.Errorf("rejection message does not read as a failure: %q", res.Get("message").String())
	}
}

// Bad input from the page must come back as a result, not as a panic. A panic
// here kills the Go instance, so every later click on the page does nothing —
// one malformed paste and the demo is over until reload.
func TestExportedVerifySurvivesBadInput(t *testing.T) {
	registerForTest(t)

	for _, tc := range []struct {
		name string
		args []any
	}{
		{"no arguments", nil},
		{"not hex", []any{"zzzz"}},
		{"empty string", []any{""}},
		{"odd-length hex", []any{"abc"}},
		{"valid hex, not a receipt", []any{"deadbeef"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := js.Global().Call("xapVerify", tc.args...)
			if res.Get("valid").Type() != js.TypeBoolean {
				t.Fatalf("result.valid is %s, want a boolean", res.Get("valid").Type())
			}
			if res.Get("valid").Bool() {
				t.Fatal("bad input reported as a valid receipt")
			}
		})
	}
}
