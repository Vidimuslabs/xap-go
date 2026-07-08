package xap

import (
	"fmt"

	cose "github.com/veraison/go-cose"
)

// UnverifiedPayload extracts the payload from a COSE_Sign1 envelope WITHOUT
// verifying the signature. It exists only for inspection tooling (`xap
// inspect`); every trust decision goes through the signature-verifying parse
// functions (ParseMAT/ParseReceipt/ParseCommitment). The name makes the absence
// of verification explicit at every call site.
func UnverifiedPayload(envelope []byte) ([]byte, error) {
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(envelope); err != nil {
		return nil, fmt.Errorf("decode COSE_Sign1: %w", err)
	}
	return msg.Payload, nil
}

// DecodeAny decodes a canonical payload into whichever protocol type it
// represents, discriminating by structure. Because the canonical decoder
// rejects unknown fields, exactly one of MAT / Receipt / CommitmentObject
// decodes cleanly for a well-formed payload.
func DecodeAny(payload []byte) (kind string, obj any, err error) {
	if m, err := UnmarshalMAT(payload); err == nil {
		return "mat", m, nil
	}
	if r, err := UnmarshalReceipt(payload); err == nil {
		return "receipt", r, nil
	}
	if c, err := UnmarshalCommitment(payload); err == nil {
		return "commitment", c, nil
	}
	return "", nil, fmt.Errorf("payload does not decode as MAT, receipt, or commitment object")
}
