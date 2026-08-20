# Security Policy

Vidimus Labs takes the security of the Execution Authority Protocol (XAP) and its
reference verifier seriously.

## We are asking you to break this

XAP's entire claim is that a receipt can be verified by someone with no access to
the system that issued it. A claim like that is worth exactly what independent
scrutiny says it is worth, so we would rather you find a flaw than take our word
for it. Engineers, cryptographers, and academic researchers are explicitly
invited to attack this SDK.

### How to run the target

You need **both** public-tier repos. Conformance vectors and the expected-outcome
manifest live in [xap-spec](https://github.com/Vidimuslabs/xap-spec); this repo is
the verifier that consumes them.

```sh
# from a checkout of this repo, with xap-spec available per go.mod
go test ./...
go run ./cmd/xap vectors run
# optional continuous fuzz (seeds replay under go test; this explores further)
go test -fuzz=FuzzParseReceipt -fuzztime=60s .
```

Build the WASM verifier locally from `cmd/verify-wasm/` (see that directory's
README). Do **not** probe the live page at `vidimuslabs.com/verify` — that host is
out of scope below.

### What we want broken

- **forge** — produce any byte string this verifier accepts as valid for an
  action that was never authorized;
- **downgrade the hybrid** — get a receipt accepted when only one of the two
  signature halves (ECDSA P-384, ML-DSA-65) is valid;
- **malleate** — find two distinct encodings that verify against one digest, or
  a re-encoding the strict decoder accepts that changes meaning;
- **escalate through delegation** — derive a child MAT that widens scope,
  boundary, constraints, or proof obligations relative to its parent;
- **bypass a commitment binding** — get an action outside a commitment's declared
  set to verify;
- **crash it** — make any parse or verify entry point panic, hang, or consume
  unbounded resources on attacker-controlled input;
- **lie with a valid signature** — mint correctly signed artifacts under a key
  the verifier is configured to trust, and still get a false accept (semantic
  hostility beats byte-flipping a sealed envelope).

### What we already test (read these first)

| Area | Files |
|------|--------|
| Envelope mutation / tamper | `adversarial_test.go` |
| Signed-hostile envelopes (trusted key, bad headers/payload) | `adversarial_envelope_test.go` |
| Full `Verify` semantics under signed lies | `adversarial_semantics_test.go` |
| Hybrid both-must-pass | `hybrid_test.go` |
| Canonical CBOR / digest identity | `canonical/canonical_test.go` |
| Fuzz seeds + targets | `fuzz_test.go` |
| Decision, controls, replay, timing | `decision_test.go`, `timeout_semantics_test.go` |
| Issuer / role / EP binding | `issuer_binding_test.go`, `anchor_validation_test.go` |
| Scope and path traversal | `scope_test.go`, `scope_hardening_test.go` |
| Delegation monotonicity | `delegation_test.go` |
| Input omission / NOT_PERFORMED | `input_omission_test.go`, `commitment_mat_absence_test.go` |
| Chain link vs envelope malleability | `chain_test.go` |
| Conformance completeness (every check/code pinned) | `conformance/` |

Prefer **signed-hostile** inputs over mutating sealed bytes. High-value residual
questions: does each check compare inputs from **independent** parties (or only
values the party under judgment chose)? What happens under **partial disclosure**
(`not_performed` vs `passed`)? What holds when **wall-clock** expiry and signed
validity windows disagree? Does the **WASM** build behave like the native path?

## Reporting a vulnerability

Please report suspected security vulnerabilities **privately** to
**security@vidimuslabs.com**. Do **not** open a public issue, pull request, or
discussion for a security report.

Where possible, include:

- the affected package and the commit or release,
- a description of the issue and its security impact, and
- steps, inputs, or a proof-of-concept to reproduce it.

We aim to acknowledge reports within a few business days and will keep you
updated as we investigate.

## Publication

**You may publish your findings.** We ask that you give us 90 days from the
acknowledgement of your report before doing so, or until a fix ships if that
comes sooner, and we will tell you as soon as a fix is out. If we have not fixed
an issue in 90 days, publish anyway — a deadline that moves whenever the vendor
finds it inconvenient is not a deadline, and research that cannot be published
is not research.

We will not ask you to sign a non-disclosure agreement as a condition of
reporting, and we will not treat a good-faith disclosure as a breach of any
term.

## Safe harbor

We consider good-faith security research on this software to be authorized
conduct. We will not initiate legal action against you, or refer you for
prosecution, for research that stays within this policy — specifically research
that respects the scope below, avoids privacy violations and service disruption,
and does not access or modify data that is not yours.

If a third party brings action against you for research conducted in good faith
under this policy, we will make that authorization clear.

Apache 2.0 §3 grants you a patent licence for this Work, which covers building
and running the analysis tooling you need to attack it. XAP is patent-pending;
see the licence footer below.

## Scope

**In scope:** this repository and [xap-spec](https://github.com/Vidimuslabs/xap-spec).
`xap-go` is the **verification-side** reference SDK — it holds no signing keys and
performs no issuance or enforcement. The security-relevant surface is the
verification path: parsing of **untrusted** MAT / receipt / commitment envelopes,
COSE_Sign1 signature verification (including the hybrid ECDSA-P384 + ML-DSA-65
both-must-pass check), CBOR canonicalization and digest recomputation, delegation
and commitment validation, constraint evaluation, the CLI, and the WASM build
built from this tree. Protocol and schema issues belong with xap-spec.

**Out of scope — do not test these (safe harbor does not cover them):**

- Any live Vidimus host: `vidimuslabs.com`, `api.vidimuslabs.com`,
  `*.vidimuslabs.com`, and DNS/edge configuration behind them. That includes the
  public `/verify` page. Attack a **local** build of this SDK (or local WASM)
  instead.
- The private enforcement engine and server (not published; not this invite).
- Volumetric denial of service, social engineering of Vidimus Labs staff or
  contractors, and physical attacks.

**Resource exhaustion — where the line sits, because the two sides of it look
alike.** A single input that makes a parse, decode or verify path allocate without
bound, recurse without bound, or hang **is in scope**, and the "crash it" invitation
above is exactly that ask: one envelope that costs this SDK unbounded work is a
defect and we want to fix it. Sending enough well-formed traffic to exhaust a
server **is not** — availability under load is a property of how a deployment is
provisioned, and no bound inside a process answers a distributed source. This SDK
runs no server of its own; the enforcement node's in-process bounds, and what they
deliberately do not cover, are documented for operators alongside the server
distribution.

## Recognition

Reporters who wish to be credited are acknowledged by name in the release notes
and, for findings that change the protocol or the schema, in the specification
itself. Where a finding warrants a CVE we will credit you in it. For substantive
protocol-level findings we are glad to offer formal acknowledgement in the next
revision of the specification and its Zenodo deposit, which is citable — tell us
how you would like to be named and whether you have an ORCID.

The untrusted-input parsers are continuously fuzzed (`go test -fuzz=...`, see
`fuzz_test.go`), against the manifest's configured anchors so that fuzzing
reaches the signature-verification paths rather than stopping at anchor lookup.
