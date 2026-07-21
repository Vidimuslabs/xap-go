# Security Policy

Vidimus Labs takes the security of the Execution Authority Protocol (XAP) and its
reference verifier seriously.

## Reporting a vulnerability

Please report suspected security vulnerabilities **privately** to
**security@vidimuslabs.com**. Do **not** open a public issue, pull request, or
discussion for a security report.

Where possible, include:

- the affected package and the commit or release,
- a description of the issue and its security impact, and
- steps, inputs, or a proof-of-concept to reproduce it.

We aim to acknowledge reports within a few business days and will keep you
updated as we investigate. Please allow us reasonable time to remediate before
any public disclosure. Reporters who wish to be credited will be acknowledged.

## Scope

`xap-go` is the **verification-side** reference SDK. It holds no signing keys and
performs no issuance or enforcement. The security-relevant surface is the
verification path: parsing of **untrusted** MAT / receipt / commitment envelopes,
COSE_Sign1 signature verification (including the hybrid ECDSA-P384 + ML-DSA-65
both-must-pass check), CBOR canonicalization and digest recomputation, delegation
and commitment validation, and constraint evaluation. Reports of a forged or
malleable artifact that verifies, a malformed input that panics or hangs, or any
path that accepts what it should reject are especially welcome.

The untrusted-input parsers are continuously fuzzed (`go test -fuzz=...`, see
`fuzz_test.go`).
