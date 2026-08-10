package xap_test

import (
	"encoding/hex"
	"strings"
	"testing"

	xap "github.com/Vidimuslabs/xap-go"
	"github.com/Vidimuslabs/xap-go/conformance"
	"github.com/Vidimuslabs/xap-spec/vectors"
)

// The verifier ingests untrusted, attacker-controlled bytes — a receipt, MAT, or
// commitment arriving over the wire. None of these parse entry points may panic
// on any input; a malformed or hostile envelope must produce an error, never a
// crash. `go test` replays the seed corpus on every run; `go test -fuzz=FuzzX`
// explores further.

// fuzzAnchors is the manifest's real anchor set, including the hybrid anchor.
//
// The Parse* targets previously fuzzed against an EMPTY anchor set, which meant
// every input died at anchor lookup before a signature was ever checked: the
// COSE and CBOR structure was explored, and the cryptography behind it — the
// hybrid split, both-must-pass, the key-length guard — was unreachable. Fuzzing
// against configured anchors is what puts those paths in range.
func fuzzAnchors(tb testing.TB) *xap.TrustAnchorSet {
	tb.Helper()
	m, err := vectors.Load()
	if err != nil {
		tb.Fatal(err)
	}
	set, err := conformance.BuildAnchors(m)
	if err != nil {
		tb.Fatal(err)
	}
	return set
}

// realEnvelopes are the signed conformance vectors. A fuzzer that starts only
// from hand-written garbage spends its budget rediscovering that garbage is not
// CBOR; starting from valid signed envelopes means each mutation lands close to
// something the parser accepts, which is where the interesting rejections are.
var realEnvelopes = []string{
	"receipt_permit.hex", "receipt_deny.hex", "receipt_compact.hex",
	"receipt_tampered_ctx.hex", "receipt_broken_chain.hex",
	"mat_root.hex", "mat_child_valid.hex", "mat_bad_sig.hex",
	"mat_hybrid_valid.hex", "mat_hybrid_bad_sig.hex",
	"commitment_A.hex", "commitment_mismatch.hex",
}

func addParseSeeds(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Add([]byte("not cbor at all"))
	f.Add([]byte{0xa0})                                     // empty CBOR map
	f.Add([]byte{0x9f, 0xff})                               // indefinite-length empty array
	f.Add([]byte{0xd2, 0x84, 0x40, 0xa0, 0x40, 0x40})       // COSE_Sign1-shaped (tag 18, array of 4)
	f.Add([]byte{0xd2, 0x84, 0x43, 0xa1, 0x01, 0x27, 0xa0}) // COSE_Sign1 with a protected header

	for _, name := range realEnvelopes {
		raw, err := vectors.File(name)
		if err != nil {
			f.Fatalf("seed %s: %v", name, err)
		}
		env, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil {
			f.Fatalf("seed %s: %v", name, err)
		}
		f.Add(env)
	}
}

func FuzzUnverifiedPayload(f *testing.F) {
	addParseSeeds(f)
	f.Fuzz(func(_ *testing.T, data []byte) { _, _ = xap.UnverifiedPayload(data) })
}

func FuzzDecodeAny(f *testing.F) {
	addParseSeeds(f)
	f.Fuzz(func(_ *testing.T, data []byte) { _, _, _ = xap.DecodeAny(data) })
}

func FuzzUnmarshalReceipt(f *testing.F) {
	addParseSeeds(f)
	f.Fuzz(func(_ *testing.T, data []byte) { _, _ = xap.UnmarshalReceipt(data) })
}

func FuzzUnmarshalMAT(f *testing.F) {
	addParseSeeds(f)
	f.Fuzz(func(_ *testing.T, data []byte) { _, _ = xap.UnmarshalMAT(data) })
}

func FuzzUnmarshalCommitment(f *testing.F) {
	addParseSeeds(f)
	f.Fuzz(func(_ *testing.T, data []byte) { _, _ = xap.UnmarshalCommitment(data) })
}

func FuzzParseReceipt(f *testing.F) {
	addParseSeeds(f)
	anchors := fuzzAnchors(f)
	f.Fuzz(func(_ *testing.T, data []byte) { _, _ = xap.ParseReceipt(data, anchors) })
}

func FuzzParseMAT(f *testing.F) {
	addParseSeeds(f)
	anchors := fuzzAnchors(f)
	f.Fuzz(func(_ *testing.T, data []byte) { _, _ = xap.ParseMAT(data, anchors) })
}

func FuzzParseCommitment(f *testing.F) {
	addParseSeeds(f)
	anchors := fuzzAnchors(f)
	f.Fuzz(func(_ *testing.T, data []byte) { _, _ = xap.ParseCommitment(data, anchors) })
}
