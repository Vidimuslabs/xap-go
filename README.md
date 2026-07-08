# xap-go

Reference SDK for the **Execution Authority Protocol (XAP)**, protocol version
`xap-1.0.0`. Go, standard-library first.

`xap-go` is **verification-side**. It validates Machine Authority Tokens (MATs),
verifies receipts, validates delegation chains, verifies commitment bindings, and
reconstructs multi-agent provenance — all using public keys and trust anchors,
recomputing digests and constraint outcomes with **no access to enforcement point
state** (¶0017). It holds no signing keys: issuance and enforcement signing live
in the private engine and server.

## Packages

- root `xap` — protocol types (`MAT`, `Receipt`, `CommitmentObject`,
  `RuntimeContext`, `Constraint`), COSE_Sign1 verification, `TrustAnchorSet`,
  the `Verifier` (¶0095), delegation validation (¶0057), and provenance
  reconstruction (¶0084A).
- `canonical` — the canonicalization function (Core Deterministic CBOR) and
  SHA-256 digest (¶0018, ¶0085).
- `conformance` — runs the embedded conformance vectors.
- `cmd/xap` — the CLI.
- `examples/` — verify a receipt; validate a delegation chain; recompute a digest.

## CLI

```
xap verify  <receipt.hex> [--mat <mat.hex>] [--context <ctx.json>] \
            [--prior <receipt.hex>] [--commitment <c.hex>] --anchors <anchors.json>
xap inspect <mat.hex|receipt.hex|commitment.hex>
xap vectors run
xap digest  <context.json>
```

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

## Test

```
go test ./...            # unit, property, determinism, adversarial, conformance
go run ./cmd/xap vectors run
```

## License

See [`LICENSE.md`](LICENSE.md). License terms pending; no rights granted.

---

Protected by U.S. Patent No. [PENDING ISSUANCE — 19/570,167] and pending applications. www.vidimuslabs.com/patents
