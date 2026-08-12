package xap_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	xap "github.com/Vidimuslabs/xap-go"
)

// scopeFixture builds a signed MAT whose scope permits exactly one action over
// one resource prefix, and returns a signer for minting receipts under it. The
// enforcement point is not involved: these tests mint receipts directly so that
// a *correctly signed* receipt asserting an out-of-scope permit can be presented
// to the verifier. That is the case the scope check exists to catch — a signature
// check alone cannot, because the signature is valid.
func scopeFixture(t *testing.T) (mat []byte, anchors *xap.TrustAnchorSet, sign func(xap.Receipt) []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kid := []byte("scope-issuer")

	m := xap.MAT{
		Version: xap.ProtocolVersion,
		ID:      "mat-scope-1",
		Scope: xap.ExecutionScope{
			Actions:   []string{"restart_service"},
			Resources: []string{"host:prod-web-*"},
		},
		Boundary: xap.PermissionBoundary{
			MaxImpact:         10,
			MaxPrivilegeDelta: 1,
			Exclusions:        []string{"host:prod-web-db"},
		},
		Issuer: xap.IssuerIdentity{ID: "issuer-scope-test", KID: kid},
		Replay: xap.ReplayProtection{
			NotBefore:  "2026-01-01T00:00:00Z",
			NotAfter:   "2030-01-01T00:00:00Z",
			Nonce:      []byte("n1"),
			InstanceID: "mat-scope-1",
		},
	}
	mp, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	matEnv := signES256(t, kid, priv, mp)

	set := xap.NewTrustAnchorSet()
	if err := set.AddECDSAP256(kid, []xap.SignerRole{xap.RoleIssuer, xap.RoleEnforcementPoint}, &priv.PublicKey); err != nil {
		t.Fatal(err)
	}

	return matEnv, set, func(rc xap.Receipt) []byte {
		t.Helper()
		p, err := rc.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return signES256(t, kid, priv, p)
	}
}

func baseReceipt(action, resource, decision string) xap.Receipt {
	return xap.Receipt{
		Version:       xap.ProtocolVersion,
		ID:            "r-scope",
		ArtifactID:    "mat-scope-1",
		Action:        action,
		Resource:      resource,
		Decision:      decision,
		ContextDigest: []byte{9, 9, 9},
		Timing:        xap.Timing{Start: "2026-07-01T00:00:00Z", Complete: "2026-07-01T00:00:00Z"},
	}
}

func checkNamed(t *testing.T, res xap.VerificationResult, name string) xap.Check {
	t.Helper()
	for _, c := range res.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("verification result has no %q check; got %+v", name, res.Checks)
	return xap.Check{}
}

// A validly signed receipt that permits an operation outside the MAT's execution
// scope must fail verification. Before the receipt carried the operation this
// was unverifiable: the signature was good, the artifact bound, and an
// independent party had no way to tell what had been permitted (¶0046, ¶0097).
func TestVerifyRejectsOutOfScopePermit(t *testing.T) {
	matEnv, anchors, sign := scopeFixture(t)
	v := xap.NewVerifier(anchors)

	for _, tc := range []struct {
		name             string
		action, resource string
	}{
		{"action outside scope", "delete_database", "host:prod-web-17"},
		{"resource outside scope", "restart_service", "host:prod-payments-2"},
		{"resource excluded by boundary", "restart_service", "host:prod-web-db"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := sign(baseReceipt(tc.action, tc.resource, "permit"))
			res := v.Verify(xap.VerifyInput{ReceiptEnvelope: env, MATEnvelope: matEnv})

			if c := checkNamed(t, res, "receipt_signature"); !c.Pass {
				t.Fatalf("fixture is wrong — receipt signature failed: %s", c.Detail)
			}
			if c := checkNamed(t, res, "scope_check"); c.Pass {
				t.Errorf("verifier accepted an out-of-scope permit: %s", c.Detail)
			}
			if res.Valid {
				t.Error("overall result valid despite an out-of-scope permit")
			}
		})
	}
}

// The in-scope case must still pass, or the check above proves nothing.
func TestVerifyAcceptsInScopePermit(t *testing.T) {
	matEnv, anchors, sign := scopeFixture(t)
	v := xap.NewVerifier(anchors)

	env := sign(baseReceipt("restart_service", "host:prod-web-17", "permit"))
	res := v.Verify(xap.VerifyInput{ReceiptEnvelope: env, MATEnvelope: matEnv})

	if c := checkNamed(t, res, "scope_check"); !c.Pass {
		t.Errorf("in-scope permit rejected: %s", c.Detail)
	}
}

// Denying an out-of-scope operation is exactly what the enforcement point should
// do, so the scope check must not flag it. Only a *permit* outside scope is a
// contradiction.
func TestVerifyAcceptsOutOfScopeDenial(t *testing.T) {
	matEnv, anchors, sign := scopeFixture(t)
	v := xap.NewVerifier(anchors)

	env := sign(baseReceipt("delete_database", "host:prod-web-17", "deny"))
	res := v.Verify(xap.VerifyInput{ReceiptEnvelope: env, MATEnvelope: matEnv})

	if c := checkNamed(t, res, "scope_check"); !c.Pass {
		t.Errorf("a denial of an out-of-scope action was flagged: %s", c.Detail)
	}
}

// A receipt that discloses no operation (selective disclosure, ¶0079, or an
// issuer predating these fields) must report the scope check as not performed
// rather than silently passing it — the distinction between "checked and fine"
// and "could not check" has to survive to the verifier's output.
func TestVerifyReportsScopeNotCheckedWhenUndisclosed(t *testing.T) {
	matEnv, anchors, sign := scopeFixture(t)
	v := xap.NewVerifier(anchors)

	env := sign(baseReceipt("", "", "permit"))
	res := v.Verify(xap.VerifyInput{ReceiptEnvelope: env, MATEnvelope: matEnv})

	c := checkNamed(t, res, "scope_check")
	if !c.Pass {
		t.Errorf("undisclosed operation should not fail the scope check: %s", c.Detail)
	}
	// The distinction §9 insists on is now a value rather than a phrase in a
	// human-readable string. Asserting on the prose was asserting on wording.
	if c.Status != xap.CheckNotPerformed {
		t.Errorf("scope_check status = %q, want %q; detail=%q",
			c.Status, xap.CheckNotPerformed, c.Detail)
	}
}
