// Package conformance runs the embedded XAP conformance vectors against the
// reference SDK and reports, per vector, whether the SDK reproduces the
// manifest's expected outcome. The same runner backs the `xap vectors run` CLI
// command and the SDK's conformance test. When the engine lands, it reuses
// these same vectors so that engine-generated receipts verify against this SDK
// verifier — the two-implementation cross-check that proves independent
// verifiability.
package conformance

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	xap "github.com/Vidimuslabs/xap-go"
	"github.com/Vidimuslabs/xap-spec/constants"
	"github.com/Vidimuslabs/xap-spec/vectors"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// Result is the outcome of running one vector.
type Result struct {
	Name   string
	Kind   string
	Pass   bool
	Detail string
}

// BuildAnchors constructs a trust anchor set from the manifest's anchors.
func BuildAnchors(m *vectors.Manifest) (*xap.TrustAnchorSet, error) {
	set := xap.NewTrustAnchorSet()
	for _, a := range m.Anchors {
		kid, err := hex.DecodeString(a.KIDHex)
		if err != nil {
			return nil, fmt.Errorf("anchor kid %q: %w", a.KIDHex, err)
		}
		pub, err := hex.DecodeString(a.PubHex)
		if err != nil {
			return nil, fmt.Errorf("anchor pub %q: %w", a.KIDHex, err)
		}
		switch a.Alg {
		case string(constants.SigEd25519):
			set.AddEd25519(kid, pub)
		case string(constants.SigHybridECDSAP384MLDSA65):
			ec, ml, err := parseHybridPub(pub, a.MLDSAPubHex)
			if err != nil {
				return nil, fmt.Errorf("anchor %q: %w", a.KIDHex, err)
			}
			set.AddHybrid(kid, ec, ml)
		default:
			return nil, fmt.Errorf("anchor %q: unsupported alg %q", a.KIDHex, a.Alg)
		}
	}
	return set, nil
}

// parseHybridPub decodes a hybrid anchor's two public keys: the ECDSA P-384 key
// from SPKI DER (pub_hex) and the ML-DSA-65 key from raw bytes (mldsa_pub_hex).
func parseHybridPub(spki []byte, mldsaPubHex string) (*ecdsa.PublicKey, *mldsa65.PublicKey, error) {
	anyPub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ECDSA SPKI: %w", err)
	}
	ec, ok := anyPub.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("ECDSA anchor key is %T, want *ecdsa.PublicKey", anyPub)
	}
	mlBytes, err := hex.DecodeString(mldsaPubHex)
	if err != nil {
		return nil, nil, fmt.Errorf("decode ML-DSA pub: %w", err)
	}
	ml := new(mldsa65.PublicKey)
	if err := ml.UnmarshalBinary(mlBytes); err != nil {
		return nil, nil, fmt.Errorf("parse ML-DSA-65 pub: %w", err)
	}
	return ec, ml, nil
}

// RunAll loads the embedded manifest and runs every vector.
func RunAll() ([]Result, error) {
	m, err := vectors.Load()
	if err != nil {
		return nil, err
	}
	anchors, err := BuildAnchors(m)
	if err != nil {
		return nil, err
	}
	results := make([]Result, 0, len(m.Vectors))
	for _, v := range m.Vectors {
		results = append(results, run(v, anchors))
	}
	return results, nil
}

func run(v vectors.Vector, anchors *xap.TrustAnchorSet) Result {
	pass, detail := dispatch(v, anchors)
	return Result{Name: v.Name, Kind: v.Kind, Pass: pass, Detail: detail}
}

// dispatch interprets a vector by kind and reports whether the SDK reproduces
// the expected outcome (v.Expect is "valid" or "invalid").
func dispatch(v vectors.Vector, anchors *xap.TrustAnchorSet) (bool, string) {
	wantValid := v.Expect == "valid"
	switch v.Kind {
	case "mat":
		return checkExpect(wantValid, matAccepts(v, anchors))
	case "delegation":
		return checkExpect(wantValid, delegationAccepts(v, anchors))
	case "canon":
		return canonMatches(v)
	case "receipt":
		return receiptVerifies(v, anchors, wantValid)
	case "commitment_binding":
		return checkExpect(wantValid, commitmentBinds(v, anchors))
	case "provenance":
		return checkExpect(wantValid, provenanceReconstructs(v, anchors))
	default:
		return false, fmt.Sprintf("unknown vector kind %q", v.Kind)
	}
}

// checkExpect turns an accept/err pair into a pass/detail against wantValid.
func checkExpect(wantValid bool, err error) (bool, string) {
	accepted := err == nil
	if accepted == wantValid {
		return true, ""
	}
	if wantValid {
		return false, fmt.Sprintf("expected accept, got error: %v", err)
	}
	return false, "expected rejection, but the vector was accepted"
}

func matAccepts(v vectors.Vector, anchors *xap.TrustAnchorSet) error {
	env, err := loadHex(v.MATFile)
	if err != nil {
		return err
	}
	sm, err := xap.ParseMAT(env, anchors)
	if err != nil {
		return err // signature/structure failure
	}
	if v.At != "" {
		at, err := time.Parse(time.RFC3339, v.At)
		if err != nil {
			return err
		}
		if err := sm.MAT.ValidateAt(at); err != nil {
			return err // lifecycle (e.g. expired)
		}
	}
	return nil
}

func delegationAccepts(v vectors.Vector, anchors *xap.TrustAnchorSet) error {
	penv, err := loadHex(v.ParentMATFile)
	if err != nil {
		return err
	}
	cenv, err := loadHex(v.MATFile)
	if err != nil {
		return err
	}
	parent, err := xap.ParseMAT(penv, anchors)
	if err != nil {
		return err
	}
	child, err := xap.ParseMAT(cenv, anchors)
	if err != nil {
		return err
	}
	return xap.ValidateDerivation(&parent.MAT, &child.MAT)
}

func canonMatches(v vectors.Vector) (bool, string) {
	raw, err := vectors.File(v.ContextFile)
	if err != nil {
		return false, err.Error()
	}
	var ctx xap.RuntimeContext
	if err := json.Unmarshal(raw, &ctx); err != nil {
		return false, err.Error()
	}
	got, err := ctx.Digest()
	if err != nil {
		return false, err.Error()
	}
	if hex.EncodeToString(got) != v.ExpectDigestHex {
		return false, fmt.Sprintf("digest %s != expected %s", hex.EncodeToString(got), v.ExpectDigestHex)
	}
	return true, ""
}

func receiptVerifies(v vectors.Vector, anchors *xap.TrustAnchorSet, wantValid bool) (bool, string) {
	in := xap.VerifyInput{}
	var err error
	if in.ReceiptEnvelope, err = loadHex(v.ReceiptFile); err != nil {
		return false, err.Error()
	}
	if v.MATFile != "" {
		if in.MATEnvelope, err = loadHex(v.MATFile); err != nil {
			return false, err.Error()
		}
	}
	if v.CommitmentFile != "" {
		if in.CommitmentEnvelope, err = loadHex(v.CommitmentFile); err != nil {
			return false, err.Error()
		}
	}
	if v.ContextFile != "" {
		ctx, err := loadContext(v.ContextFile)
		if err != nil {
			return false, err.Error()
		}
		in.ReproducedContext = ctx
	}
	if v.PriorReceiptFile != "" {
		penv, err := loadHex(v.PriorReceiptFile)
		if err != nil {
			return false, err.Error()
		}
		pr, err := xap.ParseReceipt(penv, anchors)
		if err != nil {
			return false, fmt.Sprintf("prior receipt: %v", err)
		}
		in.PriorReceipt = pr
	}

	res := xap.NewVerifier(anchors).Verify(in)
	if res.Valid != wantValid {
		return false, fmt.Sprintf("verify.Valid=%v want %v (failed: %s)", res.Valid, wantValid, strings.Join(res.Failed(), ","))
	}

	// When the vector names an expected rationale/error code, confirm the
	// signature-bound record carries it.
	if v.ExpectCode != "" {
		sr, err := xap.ParseReceipt(in.ReceiptEnvelope, anchors)
		if err != nil {
			return false, err.Error()
		}
		if !hasCode(sr.Receipt, v.ExpectCode) {
			return false, fmt.Sprintf("receipt does not carry expected code %q", v.ExpectCode)
		}
	}
	return true, ""
}

func commitmentBinds(v vectors.Vector, anchors *xap.TrustAnchorSet) error {
	cenv, err := loadHex(v.CommitmentFile)
	if err != nil {
		return err
	}
	menv, err := loadHex(v.MATFile)
	if err != nil {
		return err
	}
	sc, err := xap.ParseCommitment(cenv, anchors)
	if err != nil {
		return err
	}
	sm, err := xap.ParseMAT(menv, anchors)
	if err != nil {
		return err
	}
	return sc.Commitment.VerifyBinding(&sm.MAT)
}

func provenanceReconstructs(v vectors.Vector, anchors *xap.TrustAnchorSet) error {
	receipts := make([]*xap.Receipt, 0, len(v.ReceiptFiles))
	for _, f := range v.ReceiptFiles {
		env, err := loadHex(f)
		if err != nil {
			return err
		}
		sr, err := xap.ParseReceipt(env, anchors)
		if err != nil {
			return err
		}
		r := sr.Receipt
		receipts = append(receipts, &r)
	}
	_, err := xap.ReconstructProvenance(receipts)
	return err
}

func hasCode(r xap.Receipt, code string) bool {
	for _, c := range r.RationaleCodes {
		if c == code {
			return true
		}
	}
	if r.CommitmentCompliance != nil && r.CommitmentCompliance.Code == code {
		return true
	}
	return false
}

func loadHex(name string) ([]byte, error) {
	raw, err := vectors.File(name)
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(strings.TrimSpace(string(raw)))
}

func loadContext(name string) (*xap.RuntimeContext, error) {
	raw, err := vectors.File(name)
	if err != nil {
		return nil, err
	}
	var ctx xap.RuntimeContext
	if err := json.Unmarshal(raw, &ctx); err != nil {
		return nil, err
	}
	return &ctx, nil
}
