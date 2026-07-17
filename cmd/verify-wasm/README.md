# verify-wasm — build provenance

`verify-wasm` compiles xap-go's verify-only path to WebAssembly so the public
verifier at `vidimuslabs.com/verify` runs entirely client-side. Because the whole
point of that page is *"don't trust it, verify it,"* the shipped `.wasm` must be
reproducible from this source. This note is the recipe.

## Reproducible build

Toolchain: **Go 1.26.4** (matches the `go` directive in `go.mod`).

```sh
GOOS=js GOARCH=wasm go build -trimpath -buildvcs=false -o xap-verify.wasm ./cmd/verify-wasm
```

`-trimpath` strips absolute build paths and `-buildvcs=false` strips the git
revision stamp, so the output is byte-identical regardless of who builds it, from
which directory, or at which commit. Expected digest:

```
sha256(xap-verify.wasm) = cfea85d70e5c17107bf12ad1d053c89e210e96658b5e130a9c463be2bad19a6f
```

The JS loader shim is Go's own, copied verbatim:

```sh
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" wasm_exec.js
```

## Embedded receipt and trust anchors

`main.go` embeds a real hybrid-signed (ECDSA-P384 + ML-DSA-65) permit receipt and
its EP/issuer trust anchors. They are regenerated deterministically by xap-engine:

```sh
go test ./engine -run TestGenProdReceipt -v   # in the xap-engine repo
```

The anchors are **demo keys**, not the production Vidimus trust root — correct for
a public demonstration. The receipt is genuinely hybrid-signed; only the signing
keys are demo.

## Deployment note

The artifact currently live on `vidimuslabs.com/verify`
(`sha256 = 676052c5dd96ec3b22b63789993ed8d9e35c0e2439bc0a3368e209d6fbac8891`) was
built before this source was committed (from a dirty tree, so it carries a VCS
"modified" stamp) and therefore predates the reproducible recipe above. The next
deploy should ship the deterministic `cfea85d7…` build so the live bytes match a
clean rebuild exactly.
