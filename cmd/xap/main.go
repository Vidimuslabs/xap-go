// Command xap is the reference command-line interface for the Execution
// Authority Protocol SDK. It verifies receipts, inspects artifacts, runs the
// conformance suite, and recomputes a runtime context digest — the operations
// an independent third party performs with no access to enforcement point
// state (¶0017). It holds no signing keys.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	xap "github.com/Vidimuslabs/xap-go"
	"github.com/Vidimuslabs/xap-go/conformance"
	"github.com/Vidimuslabs/xap-spec/vectors"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "inspect":
		err = cmdInspect(os.Args[2:])
	case "vectors":
		err = cmdVectors(os.Args[2:])
	case "digest":
		err = cmdDigest(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "xap:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `xap — Execution Authority Protocol reference CLI

usage:
  xap verify  <receipt.hex> [--mat <mat.hex>] [--context <ctx.json>] [--prior <receipt.hex>] [--commitment <c.hex>] --anchors <anchors.json>
  xap inspect <mat.hex|receipt.hex|commitment.hex>
  xap vectors run
  xap digest  <context.json>

Envelopes are CBOR hex (COSE_Sign1). Anchors JSON is [{"kid_hex","alg","pub_hex"}].
`)
}

// cmdVerify verifies a receipt, optionally against a governing MAT, reproduced
// context, prior receipt, and commitment object (¶0095).
func cmdVerify(args []string) error {
	fs := newFlags(args)
	receiptPath := fs.positional(0, "receipt.hex")
	if receiptPath == "" {
		return fmt.Errorf("verify: missing <receipt.hex>")
	}
	anchorsPath := fs.opt("anchors")
	if anchorsPath == "" {
		return fmt.Errorf("verify: --anchors <anchors.json> is required")
	}
	anchors, err := loadAnchors(anchorsPath)
	if err != nil {
		return err
	}

	in := xap.VerifyInput{}
	if in.ReceiptEnvelope, err = readHex(receiptPath); err != nil {
		return err
	}
	if p := fs.opt("mat"); p != "" {
		if in.MATEnvelope, err = readHex(p); err != nil {
			return err
		}
	}
	if p := fs.opt("commitment"); p != "" {
		if in.CommitmentEnvelope, err = readHex(p); err != nil {
			return err
		}
	}
	if p := fs.opt("context"); p != "" {
		ctx, err := readContext(p)
		if err != nil {
			return err
		}
		in.ReproducedContext = ctx
	}
	if p := fs.opt("prior"); p != "" {
		penv, err := readHex(p)
		if err != nil {
			return err
		}
		pr, err := xap.ParseReceipt(penv, anchors)
		if err != nil {
			return fmt.Errorf("prior receipt: %w", err)
		}
		in.PriorReceipt = pr
	}

	res := xap.NewVerifier(anchors).Verify(in)
	fmt.Printf("artifact:  %s\n", res.ArtifactID)
	fmt.Printf("decision:  %s\n", res.Decision)
	fmt.Println("checks:")
	for _, c := range res.Checks {
		mark := "PASS"
		if !c.Pass {
			mark = "FAIL"
		}
		line := fmt.Sprintf("  [%s] %s", mark, c.Name)
		if c.Detail != "" {
			line += "  — " + c.Detail
		}
		fmt.Println(line)
	}
	if res.Valid {
		fmt.Println("result:    VALID")
		return nil
	}
	return fmt.Errorf("result:    INVALID (%s)", strings.Join(res.Failed(), ", "))
}

// cmdInspect decodes and pretty-prints an artifact without verifying signatures
// (structure only), auto-detecting MAT vs receipt vs commitment.
func cmdInspect(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("inspect: missing <artifact.hex>")
	}
	env, err := readHex(args[0])
	if err != nil {
		return err
	}
	payload, err := xap.UnverifiedPayload(env)
	if err != nil {
		return err
	}
	kind, obj, err := xap.DecodeAny(payload)
	if err != nil {
		return err
	}
	fmt.Printf("kind: %s\n", kind)
	b, _ := json.MarshalIndent(obj, "", "  ")
	fmt.Println(string(b))
	return nil
}

// cmdVectors runs the embedded conformance suite (¶ two-implementation
// cross-check; def-of-done).
func cmdVectors(args []string) error {
	if len(args) < 1 || args[0] != "run" {
		return fmt.Errorf("usage: xap vectors run")
	}
	results, err := conformance.RunAll()
	if err != nil {
		return err
	}
	var failed int
	for _, r := range results {
		mark := "ok  "
		if !r.Pass {
			mark = "FAIL"
			failed++
		}
		line := fmt.Sprintf("%s  %-28s %s", mark, r.Name, r.Kind)
		if !r.Pass {
			line += "  — " + r.Detail
		}
		fmt.Println(line)
	}
	fmt.Printf("\n%d/%d passed\n", len(results)-failed, len(results))
	if failed > 0 {
		return fmt.Errorf("%d vector(s) failed", failed)
	}
	return nil
}

// cmdDigest recomputes a runtime context digest from a JSON file — the
// third-party verification demo (¶0018, ¶0095).
func cmdDigest(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("digest: missing <context.json>")
	}
	ctx, err := readContext(args[0])
	if err != nil {
		return err
	}
	d, err := ctx.Digest()
	if err != nil {
		return err
	}
	fmt.Println(hex.EncodeToString(d))
	return nil
}

// ---- small helpers ----

func readHex(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(strings.TrimSpace(string(raw)))
}

func readContext(path string) (*xap.RuntimeContext, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ctx xap.RuntimeContext
	if err := json.Unmarshal(raw, &ctx); err != nil {
		return nil, err
	}
	return &ctx, nil
}

func loadAnchors(path string) (*xap.TrustAnchorSet, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var list []vectors.Anchor
	if err := json.Unmarshal(raw, &list); err != nil {
		// Also accept a full manifest with an "anchors" field.
		var m vectors.Manifest
		if err2 := json.Unmarshal(raw, &m); err2 != nil {
			return nil, fmt.Errorf("parse anchors: %w", err)
		}
		list = m.Anchors
	}
	return conformance.BuildAnchors(&vectors.Manifest{Anchors: list})
}

// flags is a minimal positional+option parser (avoids a flag dependency and its
// ordering constraints).
type flags struct {
	pos  []string
	opts map[string]string
}

func newFlags(args []string) *flags {
	f := &flags{opts: map[string]string{}}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "--") {
			name := strings.TrimPrefix(a, "--")
			if i+1 < len(args) {
				f.opts[name] = args[i+1]
				i++
			} else {
				f.opts[name] = ""
			}
			continue
		}
		f.pos = append(f.pos, a)
	}
	return f
}

func (f *flags) positional(i int, _ string) string {
	if i < len(f.pos) {
		return f.pos[i]
	}
	return ""
}
func (f *flags) opt(name string) string { return f.opts[name] }
