# verify-wasm — build provenance

`verify-wasm` compiles xap-go's verify-only path to WebAssembly so the public
verifier at `vidimuslabs.com/verify` runs entirely client-side. Because the whole
point of that page is *"don't trust it, verify it,"* the shipped `.wasm` must be
reproducible from this source. This note is the recipe.

## Reproducible build

Toolchain: **Go 1.26.6** (matches the `go` directive in `go.mod`).

```sh
GOOS=js GOARCH=wasm go build -trimpath -buildvcs=false -o xap-verify.wasm ./cmd/verify-wasm
```

`-trimpath` strips absolute build paths and `-buildvcs=false` strips the git
revision stamp, so the output is byte-identical regardless of who builds it, from
which directory, or at which commit. Expected digest:

```
sha256(xap-verify.wasm) = e194d78aa7b9ccffe3d501f516f1b2cc0783679085183c6c1d99a13dac0e7387
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
| `0d47ef75…d682e08` | Go 1.26.5, `x/sys` v0.44.0, and the trust-anchor validation added in `cose.go` |
| `3de964ae…b1b8fe` | Go 1.26.6 — **never deployed; panics on startup.** Built before the anchors declared their signer roles, so `main` died in `BuildAnchors` before exporting anything |
| `e194d78a…0e7387` | **current** — Go 1.26.6, anchors declaring roles and the ep anchor's subject |

The move to 1.26.6 was not housekeeping. GO-2026-5972 / CVE-2026-33818 is a
missing recursion limit in `encoding/asn1`, and this target links it: `go list
-deps` on `./cmd/verify-wasm` pulls `encoding/asn1`, `crypto/x509` and this
module's `conformance` package, whose `parseHybridPub` is the reachable trace
`govulncheck` reported. So the binary built at 1.26.5 parses attacker-supplied
public keys with an unpatched stack-exhaustion bug, in the visitor's browser. The
blast radius is a crashed tab rather than anything reaching the host, but a page
whose entire proposition is *verify it yourself* is a bad place to serve a known
defect in the parser.

Rebuild and redeploy the site's copy from this recipe whenever the module graph
or toolchain moves, otherwise the page invites people to verify a binary that no
longer corresponds to any published source.

The loader shim did not change between 1.26.5 and 1.26.6 — `wasm_exec.js` is
byte-identical, checked rather than assumed, so a redeploy of the `.wasm` alone
is sufficient. Do not assume that holds for the next toolchain move.

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

Measured against the live site on 2026-08-15 rather than carried forward. The
artifact served is:

```
sha256(https://vidimuslabs.com/xap-verify.wasm) = 0d47ef75321aeddb516d0f3f5aae635a522ad52875f4879abe936fbf2d682e08
```

This note previously named `cfea85d7…d19a6f`, deployed 2026-07-17 — two
generations stale. It was not updated when the current artifact was deployed,
which is precisely the failure this section exists to prevent: a provenance note
that nobody re-measures is a claim rather than a record, and it is worse than no
note, because it reads as confirmation.

So re-measure it against the live URL when it changes, not against the table
above. The table says what the source produces; only a fetch says what is served.

**A redeploy is outstanding.** The served artifact is the 1.26.5 build. Until
the site is updated, it and this recipe disagree by design rather than by
accident, and the reproducibility claim this file makes does not hold. Update
this note by measurement once it ships.

The 1.26.6 build was deployed briefly on 2026-08-15 and rolled back within
minutes: it panicked in `BuildAnchors` before exporting `xapVerify`, so the page
loaded and did nothing. Bytes matching the recipe is not the same as a binary
that runs, and the rollback was decided by running the artifact rather than by
hashing it. `cmd/verify-wasm` now has host tests that catch that class, and the
recipe's digest is the build that passes them.

One trap worth naming, because it produces a confident wrong answer:
`/verify/xap-verify.wasm` also returns 200, but with the site's HTML fallback
rather than the binary. The asset is served from the root. Hashing the wrong path
yields a digest that matches nothing and looks like tampering.
