# xap-go

[![ci](https://img.shields.io/github/actions/workflow/status/Vidimuslabs/xap-go/ci.yml?branch=main&style=flat-square&logo=github&logoColor=C9A961&labelColor=475569&label=ci)](https://github.com/Vidimuslabs/xap-go/actions/workflows/ci.yml)
[![pkg.go.dev](https://img.shields.io/badge/pkg.go.dev-reference-2D5F4F?style=flat-square&logo=go&logoColor=C9A961&labelColor=475569)](https://pkg.go.dev/github.com/Vidimuslabs/xap-go)
[![protocol](https://img.shields.io/badge/protocol-xap--1.0.0-2D5F4F?style=flat-square&labelColor=475569)](https://github.com/Vidimuslabs/xap-spec)
[![scope](https://img.shields.io/badge/scope-verify--only-2D5F4F?style=flat-square&labelColor=475569)](#what-it-does)
[![signatures](https://img.shields.io/badge/signatures-hybrid_post--quantum-2D5F4F?style=flat-square&labelColor=475569)](#what-it-does)
[![license](https://img.shields.io/badge/license-Apache--2.0-2D5F4F?style=flat-square&labelColor=475569)](LICENSE)

The reference **verifier** for the Execution Authority Protocol (XAP), protocol
version `xap-1.0.0`. Go, standard-library first, holds no signing keys.

> **Don't trust an execution receipt — verify it.** `xap-go` reproduces a
> receipt's digests and constraint outcomes from public keys alone, with no
> access to the enforcement point that issued it (¶0017).

## What it does

`xap-go` is the **verification side** of XAP. It validates Machine Authority
Tokens (MATs), verifies execution receipts, validates delegation chains, checks
commitment bindings, and reconstructs multi-agent provenance — entirely from
public keys and trust anchors. It performs no issuance and no enforcement: those
are the job of the licensed enforcement engine, and this SDK exists so that any
party can independently check that engine's output, now or years later.

Signatures are hybrid post-quantum by default — **ECDSA P-384 + ML-DSA-65** (NIST
FIPS 204), both halves must verify — with Ed25519 and ECDSA P-256 also supported.

## Packages

- root `xap` — protocol types (`MAT`, `Receipt`, `CommitmentObject`,
  `RuntimeContext`, `Constraint`), COSE_Sign1 verification, `TrustAnchorSet`,
  the `Verifier` (¶0095), delegation validation (¶0057), and provenance
  reconstruction (¶0084A).
- `canonical` — the canonicalization function (Core Deterministic CBOR) and
  SHA-256 digest (¶0018, ¶0085).
- `conformance` — runs the embedded conformance vectors.
- `cmd/xap` — the CLI.
- `cmd/verify-wasm` — the verify path compiled to WebAssembly (powers the
  in-browser verifier at [vidimuslabs.com/verify](https://www.vidimuslabs.com/verify)).
- `examples/` — verify a receipt; validate a delegation chain; recompute a digest.

## Verify a receipt

```go
anchors := xap.NewTrustAnchorSet()
anchors.AddEd25519(kid, pub)

res := xap.NewVerifier(anchors).Verify(xap.VerifyInput{
    ReceiptEnvelope:   receiptCBOR,
    MATEnvelope:       matCBOR,
    ReproducedContext: &ctx,
})
fmt.Println(res.Valid, res.Decision)
```

## CLI

```
xap verify  <receipt.hex> [--mat <mat.hex>] [--context <ctx.json>] \
            [--prior <receipt.hex>] [--commitment <c.hex>] --anchors <anchors.json>
xap inspect <mat.hex|receipt.hex|commitment.hex>
xap vectors run
xap digest  <context.json>
```

## Test

```
go test ./...            # unit, property, determinism, adversarial, conformance
go run ./cmd/xap vectors run
```

## Specification & conformance

The normative specification, the frozen `xap-1.0.0` wire schema, and the golden
conformance vectors live in **[xap-spec](https://github.com/Vidimuslabs/xap-spec)**;
`xap vectors run` replays them against this SDK. Paper: DOI
[10.5281/zenodo.21144476](https://doi.org/10.5281/zenodo.21144476).

## Status

Verify-only reference SDK · protocol `xap-1.0.0` (frozen) · hybrid post-quantum ·
patent-pending.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE). Free to use,
modify, and redistribute.

Apache 2.0 Section 3 carries a patent grant, made here by Yandeh Holdings Inc. as
assignee of the XAP portfolio. It reaches this Work — the verification side. The
licensed enforcement engine is a separate work under separate terms.

---

Protected by U.S. Patent No. [PENDING ISSUANCE — 19/570,167] and pending applications. [www.vidimuslabs.com/patents](https://www.vidimuslabs.com/patents)
