# Security Policy

Vidimus Labs takes the security of the Execution Authority Protocol (XAP) and its
reference verifier seriously.

## We are asking you to break this

XAP's entire claim is that a receipt can be verified by someone with no access to
the system that issued it. A claim like that is worth exactly what independent
scrutiny says it is worth, so we would rather you find a flaw than take our word
for it. Engineers, cryptographers, and academic researchers are explicitly
invited to attack this SDK.

The conformance vectors and their expected-outcome manifest ship in
[xap-spec](https://github.com/Vidimuslabs/xap-spec), so the target is
self-service — `xap vectors run` replays every one against this verifier.
Concretely, we would like to know if you can:

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
  unbounded resources on attacker-controlled input.

What we already test is in `adversarial_test.go`, `fuzz_test.go`,
`hybrid_test.go`, and `canonical/canonical_test.go`. Reading those first will
tell you where the unexplored surface is; we would rather point you at it than
have you spend effort re-deriving it.

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

**In scope:** this repository. `xap-go` is the **verification-side** reference
SDK — it holds no signing keys and performs no issuance or enforcement. The
security-relevant surface is the verification path: parsing of **untrusted**
MAT / receipt / commitment envelopes, COSE_Sign1 signature verification
(including the hybrid ECDSA-P384 + ML-DSA-65 both-must-pass check), CBOR
canonicalization and digest recomputation, delegation and commitment validation,
constraint evaluation, the CLI, and the WASM build. Also in scope: the protocol
and schema themselves, reported at
[xap-spec](https://github.com/Vidimuslabs/xap-spec).

**Out of scope, and please do not test against them:** Vidimus Labs production
infrastructure, including `vidimuslabs.com`, `api.vidimuslabs.com`, any
`*.vidimuslabs.com` host, and the DNS and edge configuration behind them. These
are live systems serving real traffic; attacking them is not authorized by this
policy and the safe harbor above does not extend to them. The in-browser
verifier at `/verify` runs this SDK compiled to WASM — attack the SDK locally
instead, where you can also see more. The private enforcement engine and server
are not published and are not in scope.

Also out of scope: volumetric denial of service, social engineering of Vidimus
Labs staff or contractors, and physical attacks.

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
