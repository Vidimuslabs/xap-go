# verify-wasm — build provenance

`verify-wasm` compiles xap-go's verify-only path to WebAssembly so the public
verifier at `vidimuslabs.com/verify` runs entirely client-side. Because the whole
point of that page is *"don't trust it, verify it,"* the shipped `.wasm` must be
reproducible from this source. This note is the recipe.

## Reproducible build

Toolchain: **Go 1.26.5** (matches the `go` directive in `go.mod`).

```sh
GOOS=js GOARCH=wasm go build -trimpath -buildvcs=false -o xap-verify.wasm ./cmd/verify-wasm
```

`-trimpath` strips absolute build paths and `-buildvcs=false` strips the git
revision stamp, so the output is byte-identical regardless of who builds it, from
which directory, or at which commit. Expected digest:

```
sha256(xap-verify.wasm) = 0d47ef75321aeddb516d0f3f5aae635a522ad52875f4879abe936fbf2d682e08
```

Neither flag strips dependency versions: Go records them in the binary's build
info, so the digest is a function of the resolved module graph and the toolchain
as well as the source. Bumping a `require` changes it, and so does bumping the
`go` directive.

Digest history, since each entry is a claim someone may want to check:

| digest | what it was |
|---|---|
| `cfea85d7…d19a6f` | same source against `xap-spec v0.0.0`, Go 1.26.4 |
| `f1ac6e81…f206e6` | against `xap-spec v0.1.0`, Go 1.26.4 |
| `0d47ef75…d682e08` | **current** — Go 1.26.5, `x/sys` v0.44.0, and the trust-anchor validation added in `cose.go` |

The current digest is what vidimuslabs.com serves. Rebuild and redeploy the
site's copy from this recipe whenever the module graph or toolchain moves,
otherwise the page invites people to verify a binary that no longer corresponds
to any published source.

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
