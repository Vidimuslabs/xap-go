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
sha256(xap-verify.wasm) = 4482a4370f5d83bd17922618e02b120946801e7a4c7b80a2b2b2fba5e4be082e
```

**Production serves a different artifact**, one source generation behind this
one. That is a real gap rather than bookkeeping — the deployment note below says
what it is, how it drifted, and what it costs.

Neither flag strips dependency versions: Go records them in the binary's build
info, so the digest is a function of the resolved module graph and the toolchain
as well as the source. Bumping a `require` changes it, so does bumping the `go`
directive, and so does editing this command's own source.

One caveat governs every row below, and it is the reason the rows are keyed the
way they are. `go.mod` has carried `replace github.com/Vidimuslabs/xap-spec =>
../xap-spec` since this module's first commit, so **no build in this history ever
resolved `xap-spec` from the module proxy** — the `require` line was overridden
by whatever the sibling checkout held at build time, and that state is recorded
nowhere. Naming a row by its `xap-spec` version would therefore invite someone to
reproduce it against a published version and get a different digest, so each row
names an xap-go commit it can be rebuilt from instead: from there `go.mod`, the
`go` directive and this command's source are all recoverable. The caveat disappears
when the `replace` drops at publication (CF-xap-36), and the digest changes when
it does.

Digest history, since each entry is a claim someone may want to check:

| digest | rebuild from | what it was |
|---|---|---|
| `cfea85d7…d19a6f` | `a3937c9` | first recorded digest, Go 1.26.4. `require` named `xap-spec v0.0.0` — a version that has never existed in `xap-spec`, which built only because the `replace` overrode it and which made the module uninstallable (CF-xap-19, fixed in `f689ec4`) |
| `f1ac6e81…f206e6` | `410adb6` | Go 1.26.4, after the embedded receipt changed; `require` moved to `xap-spec v0.1.0` |
| `0d47ef75…d682e08` | `a3522af` | Go 1.26.5, `x/sys` v0.44.0, and the trust-anchor validation added in `cose.go` |
| `3de964ae…b1b8fe` | `76fd083` | Go 1.26.6 — **never deployed; panics on startup.** Built before the anchors declared their signer roles, so `main` died in `BuildAnchors` before exporting anything |
| `e194d78a…0e7387` | `189d7cd` | Go 1.26.6, anchors declaring roles and the ep anchor's subject — **the artifact production still serves** |
| `4482a437…be082e` | `4315460` | **current source; never deployed.** Neither the graph nor the toolchain moved: `main()` was split into `register()` so a host test could drive it, and that changed the binary |

Both ends of that last step were rebuilt on 2026-08-17 rather than taken on
trust: `189d7cd` produces `e194d78a…`, `4315460` produces `4482a437…`, and every
commit from `4315460` to the tip produces the latter. Each row's commit is
therefore a reproduction point, not merely a citation.

The move to 1.26.6 was not housekeeping. GO-2026-5972 / CVE-2026-33818 is a
missing recursion limit in `encoding/asn1`, and this target links it: `go list
-deps` on `./cmd/verify-wasm` pulls `encoding/asn1`, `crypto/x509` and this
module's `conformance` package, whose `parseHybridPub` is the reachable trace
`govulncheck` reported. So the binary built at 1.26.5 parses attacker-supplied
public keys with an unpatched stack-exhaustion bug, in the visitor's browser. The
blast radius is a crashed tab rather than anything reaching the host, but a page
whose entire proposition is *verify it yourself* is a bad place to serve a known
defect in the parser.

Rebuild and redeploy the site's copy from this recipe whenever the module graph,
the toolchain, **or this command's own source** moves — the third is what actually
drifted, and the original wording of this rule omitted it. Otherwise the page
invites people to verify a binary that no longer corresponds to any published
source.

The loader shim did not change between 1.26.5 and 1.26.6 — `wasm_exec.js` is
byte-identical, checked rather than assumed, so a redeploy of the `.wasm` alone
is sufficient. Do not assume that holds for the next toolchain move.

The JS loader shim is Go's own, copied verbatim:

```sh
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" wasm_exec.js
```

## Embedded receipt and trust anchors

`anchors.go` embeds a real hybrid-signed (ECDSA-P384 + ML-DSA-65) permit receipt
and its issuer/enforcement-point trust anchors, produced by the enforcement engine
and checked in as source so the demo is fully self-contained. They sit there
rather than in `main.go` — moved in `711957f` — because `main.go` carries
`//go:build js && wasm` and a file only `GOOS=js` compiles is a file no ordinary
`go test ./...` can reach. That is the whole reason the missing signer roles
reached production: nothing host-side could see them.

The anchors are **demo keys**, not the production Vidimus trust root — correct for
a public demonstration. The receipt is genuinely hybrid-signed; only the signing
keys are demo. What the page proves is verification, and verification needs only
public keys — so the embedded artifact is all that is required to reproduce it.

## Deployment note

Measured against the live site on 2026-08-17 rather than carried forward. The
artifact served is:

```
sha256(https://vidimuslabs.com/xap-verify.wasm) = e194d78aa7b9ccffe3d501f516f1b2cc0783679085183c6c1d99a13dac0e7387
```

This note previously named `cfea85d7…d19a6f`, deployed 2026-07-17 — two
generations stale. It was not updated when the current artifact was deployed,
which is precisely the failure this section exists to prevent: a provenance note
that nobody re-measures is a claim rather than a record, and it is worse than no
note, because it reads as confirmation.

So re-measure it against the live URL when it changes, not against the table
above. The table says what the source produces; only a fetch says what is served.

**Served as of 2026-08-17, and one source generation behind.** Re-measured that
day: the live artifact is still `e194d78a…`, which is byte-identical to a clean
build at `189d7cd` — verified by rebuilding at that commit, not by reading the
table above — and it was checked by running it as well as hashing it: the demo
receipt returns `valid: true` and a receipt with one byte flipped returns
`valid: false`. So the deployed binary is sound and reproducible. It is simply no
longer what this module's tip produces, and the "Expected digest" above is the
tip's output, not the deployment's.

**How it drifted, since the mechanism matters more than the fact.** `4315460`
split `main()` into `register()` so a host test could reach it. That was the right
change — it is part of the three-layer check this file describes — but it changed
the binary, and the rule above named only the module graph and the toolchain, so
nothing flagged it. The three commits after it added a `_test.go`, a `.mjs`
harness and a CI step that builds the wasm and runs it; **none of them compares
the built digest to the one published here**, so CI was green across the entire
divergence. The gap closed on 2026-08-15 was "nothing runs the artifact." The gap
still open is "nothing checks the artifact against its own published digest" —
which is the same shape as the failure this file was written to prevent, one level
further out.

Redeploying is a production action and Papa's to trigger: `npm run ship` from
`vidimus-labs-site`, then re-measure the live URL and update this note. Until
then the honest reading is the one above — what is served corresponds to
`189d7cd`, not to the tip.

That distinction is not pedantry — it is what this deploy cost. An earlier 1.26.6
build (`3de964ae…b1b8fe`) went out the same day, matched its recipe digest
exactly, and could not start: the embedded anchors declared no signer roles, so
`BuildAnchors` rejected them and `main` panicked before exporting `xapVerify`.
The page loaded and did nothing. It was rolled back within minutes, on
measurement rather than on a report, and `cmd/verify-wasm` now has host tests for
that class. **A digest confirms provenance. It says nothing about whether the
binary runs, and this file should never be read as claiming otherwise.**

One trap worth naming, because it produces a confident wrong answer:
`/verify/xap-verify.wasm` also returns 200, but with the site's HTML fallback
rather than the binary. The asset is served from the root. Hashing the wrong path
yields a digest that matches nothing and looks like tampering.
