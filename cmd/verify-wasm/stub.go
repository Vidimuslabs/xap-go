//go:build !js || !wasm

// Stub so `go build ./...` on non-wasm targets doesn't fail on this directory.
// The real entrypoint (main.go) builds only under GOOS=js GOARCH=wasm.
package main

func main() {}
