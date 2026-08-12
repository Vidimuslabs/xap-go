package xap

// Anchor registration and the verification-time key guard.
//
// crypto/ed25519.Verify PANICS on a public key that is not exactly 32 bytes,
// and ecdsa.Verify dereferences a nil key. Both are reachable with an
// attacker-chosen key id once an operator has registered a malformed anchor —
// pasting an SPKI where a raw key belongs, or storing the zero value from an
// ignored decode error. This package promises the opposite: a hostile envelope
// must produce an error, never a crash (see SECURITY.md and fuzz_test.go).
//
// This file is an internal test so it can bypass the Add* constructors and
// build a malformed TrustAnchorSet directly, which is the only way to reach the
// second guard in coseVerifierFor.

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/Vidimuslabs/xap-spec/constants"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func TestAddEd25519RejectsMalformedKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		kid  []byte
		n    int
	}{
		{"empty key", []byte("k"), 0},
		{"short key", []byte("k"), 16},
		{"spki-length key", []byte("k"), 120},
		{"one byte short", []byte("k"), ed25519.PublicKeySize - 1},
		{"one byte long", []byte("k"), ed25519.PublicKeySize + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewTrustAnchorSet()
			if err := s.AddEd25519(tc.kid, []SignerRole{RoleIssuer}, make([]byte, tc.n)); err == nil {
				t.Fatalf("registered a %d-byte ed25519 key", tc.n)
			}
			if s.Len() != 0 {
				t.Fatal("rejected key was still stored")
			}
		})
	}

	s := NewTrustAnchorSet()
	if err := s.AddEd25519(nil, []SignerRole{RoleIssuer}, make([]byte, ed25519.PublicKeySize)); err == nil {
		t.Fatal("registered an anchor under an empty key id")
	}
	if err := s.AddEd25519([]byte("k"), []SignerRole{RoleIssuer}, make([]byte, ed25519.PublicKeySize)); err != nil {
		t.Fatalf("rejected a well-formed anchor: %v", err)
	}
}

func TestAddECDSAP256RejectsMalformedKey(t *testing.T) {
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	s := NewTrustAnchorSet()
	if err := s.AddECDSAP256([]byte("k"), []SignerRole{RoleIssuer}, nil); err == nil {
		t.Fatal("registered a nil ECDSA key")
	}
	if err := s.AddECDSAP256([]byte("k"), []SignerRole{RoleIssuer}, &ecdsa.PublicKey{Curve: elliptic.P256()}); err == nil {
		t.Fatal("registered an ECDSA key with nil coordinates")
	}
	if err := s.AddECDSAP256([]byte("k"), []SignerRole{RoleIssuer}, &p384.PublicKey); err == nil {
		t.Fatal("registered a P-384 key as P-256")
	}
	if s.Len() != 0 {
		t.Fatal("a rejected key was still stored")
	}
	if err := s.AddECDSAP256([]byte("k"), []SignerRole{RoleIssuer}, &p256.PublicKey); err != nil {
		t.Fatalf("rejected a well-formed P-256 anchor: %v", err)
	}
}

func TestAddHybridRejectsMalformedKey(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mlPub, _, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	s := NewTrustAnchorSet()
	// A nil half must be refused outright: both-must-pass is meaningless if one
	// half cannot be evaluated, and a nil key crashes rather than denies.
	if err := s.AddHybrid([]byte("k"), []SignerRole{RoleIssuer}, nil, mlPub); err == nil {
		t.Fatal("registered a hybrid anchor with a nil classical half")
	}
	if err := s.AddHybrid([]byte("k"), []SignerRole{RoleIssuer}, &p384.PublicKey, nil); err == nil {
		t.Fatal("registered a hybrid anchor with a nil post-quantum half")
	}
	if err := s.AddHybrid([]byte("k"), []SignerRole{RoleIssuer}, &p256.PublicKey, mlPub); err == nil {
		t.Fatal("registered a hybrid anchor whose classical half is not P-384")
	}
	if s.Len() != 0 {
		t.Fatal("a rejected key was still stored")
	}
	if err := s.AddHybrid([]byte("k"), []SignerRole{RoleIssuer}, &p384.PublicKey, mlPub); err != nil {
		t.Fatalf("rejected a well-formed hybrid anchor: %v", err)
	}
}

// The second guard: even when a malformed key reaches the anchor set without
// passing through Add* — a zero-valued struct, a future constructor, a caller
// that ignored the registration error — selecting a verifier for it must
// return an error rather than hand the key to a primitive that panics.
func TestCOSEVerifierForRejectsMalformedKeyWithoutPanicking(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 120} {
		s := &TrustAnchorSet{byKID: map[string]TrustAnchor{
			hex.EncodeToString([]byte("k")): {
				KID:       []byte("k"),
				Algorithm: constants.SigEd25519,
				PublicKey: ed25519.PublicKey(make([]byte, n)),
			},
		}}
		a, ok := s.Get([]byte("k"))
		if !ok {
			t.Fatal("anchor not found")
		}

		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("coseVerifierFor panicked on a %d-byte ed25519 key: %v", n, r)
				}
			}()
			if _, err := coseVerifierFor(a); err == nil {
				t.Fatalf("built a verifier for a %d-byte ed25519 key", n)
			}
		}()
	}
}
