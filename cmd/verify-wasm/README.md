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

The artifact live on `vidimuslabs.com/verify` matches the reproducible build above
(`sha256 = cfea85d70e5c17107bf12ad1d053c89e210e96658b5e130a9c463be2bad19a6f`,
deployed 2026-07-17), so the served bytes are byte-identical to a clean rebuild
from this source. Re-run the recipe and diff the digest to confirm.
