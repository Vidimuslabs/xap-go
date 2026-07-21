package xap_test

import (
	"testing"

	xap "github.com/Vidimuslabs/xap-go"
)

// The verifier ingests untrusted, attacker-controlled bytes — a receipt, MAT, or
// commitment arriving over the wire. None of these parse entry points may panic
// on any input; a malformed or hostile envelope must produce an error, never a
// crash. `go test` replays the seed corpus on every run; `go test -fuzz=FuzzX`
// explores further.

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
	anchors := xap.NewTrustAnchorSet()
	f.Fuzz(func(_ *testing.T, data []byte) { _, _ = xap.ParseReceipt(data, anchors) })
}

func FuzzParseMAT(f *testing.F) {
	addParseSeeds(f)
	anchors := xap.NewTrustAnchorSet()
	f.Fuzz(func(_ *testing.T, data []byte) { _, _ = xap.ParseMAT(data, anchors) })
}

func FuzzParseCommitment(f *testing.F) {
	addParseSeeds(f)
	anchors := xap.NewTrustAnchorSet()
	f.Fuzz(func(_ *testing.T, data []byte) { _, _ = xap.ParseCommitment(data, anchors) })
}
