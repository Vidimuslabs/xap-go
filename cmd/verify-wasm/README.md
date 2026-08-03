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
sha256(xap-verify.wasm) = f1ac6e81ec471c33fbe7c292c72823f7c77e09ef1d5f2381a4c8be6876f206e6
```

Neither flag strips dependency versions: Go records them in the binary's build
info, so the digest is a function of the resolved module graph as well as the
source. Bumping a `require` changes it. The previous digest,
`cfea85d7…d19a6f`, was the same source against `xap-spec v0.0.0`, and is what
vidimuslabs.com currently serves — the site's copy is rebuilt and redeployed from
this recipe as part of publication, at which point the served bytes match the
digest above.

The JS loader shim is Go's own, copied verbatim:

```sh
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" wasm_exec.js
```

## Embedded receipt and trust anchors

`main.go` embeds a real hybrid-signed (ECDSA-P384 + ML-DSA-65) permit receipt and
its issuer/enforcement-point trust anchors, produced by the enforcement engine and
checked in as source so the demo is fully self-contained.

The anchors are **demo keys**, not the production Vidimus trust root — correct for
a public demonstration. The receipt is genuinely hybrid-signed; only the signing
keys are demo. What the page proves is verification, and verification needs only
public keys — so the embedded artifact is all that is required to reproduce it.

## Deployment note

The artifact live on `vidimuslabs.com/verify` matches the reproducible build above
(`sha256 = cfea85d70e5c17107bf12ad1d053c89e210e96658b5e130a9c463be2bad19a6f`,
deployed 2026-07-17), so the served bytes are byte-identical to a clean rebuild
from this source. Re-run the recipe and diff the digest to confirm.
