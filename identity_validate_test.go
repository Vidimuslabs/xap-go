package xap

import (
	"strings"
	"testing"
)

// MachineIdentity.Validate is the enforcement of SCHEMA.md field 122: a kind is
// a claim about which field carries the identity, so it must be a recognized
// discriminant AND agree with the material present. Before it, kind was unread
// anywhere in the SDK — an identity could say "attestation" over a bare key, or
// carry a kind outside the enum, and nothing objected.
func TestMachineIdentityValidate(t *testing.T) {
	att := &AttestationRef{Category: "tpm_quote"}
	cases := []struct {
		name    string
		id      MachineIdentity
		wantErr string // substring; "" means expect success
	}{
		{"public_key ok", MachineIdentity{Kind: "public_key", PublicKey: []byte{1}}, ""},
		{"cert_ref ok", MachineIdentity{Kind: "cert_ref", CertRef: "spiffe://x"}, ""},
		{"attestation ok", MachineIdentity{Kind: "attestation", Attestation: att}, ""},
		{"composite ok", MachineIdentity{Kind: "composite", Composite: []MachineIdentity{
			{Kind: "public_key", PublicKey: []byte{1}},
		}}, ""},

		{"unknown kind", MachineIdentity{Kind: "totp", PublicKey: []byte{1}}, "not a recognized identity kind"},
		{"empty kind", MachineIdentity{Kind: "", PublicKey: []byte{1}}, "not a recognized identity kind"},

		// The finding: kind claims one thing, material is another.
		{"attestation over a bare key", MachineIdentity{Kind: "attestation", PublicKey: []byte{1}}, "carries no attestation reference"},
		{"public_key with no key", MachineIdentity{Kind: "public_key", CertRef: "x"}, "carries no public key"},
		{"cert_ref with no ref", MachineIdentity{Kind: "cert_ref", PublicKey: []byte{1}}, "carries no cert ref"},
		{"composite with no members", MachineIdentity{Kind: "composite"}, "carries no composite members"},

		// A composite is only as sound as its members: an outer kind that agrees
		// with a non-empty list still lies if a member does not.
		{"composite with a lying member", MachineIdentity{Kind: "composite", Composite: []MachineIdentity{
			{Kind: "attestation", PublicKey: []byte{1}},
		}}, "composite member 0: machine identity kind \"attestation\" carries no attestation reference"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.id.Validate()
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("expected valid, got %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// A MAT that names a machine identity must name a well-formed one, but an unset
// identity remains the protocol's "open identity" — Validate is only reached
// through the identityUnset guard, so absence is not a validation failure.
func TestMATValidateStructureRejectsLyingIdentity(t *testing.T) {
	m := govMAT()
	m.MachineIdentity = MachineIdentity{Kind: "attestation", PublicKey: []byte{1, 2, 3}}
	if err := m.ValidateStructure(); err == nil {
		t.Fatal("MAT with an attestation-kind identity carrying only a key was accepted")
	} else if !strings.Contains(err.Error(), "machine identity") {
		t.Fatalf("unexpected error: %v", err)
	}

	// Open identity: unset, so the guard skips Validate and the MAT is well formed.
	open := govMAT()
	open.MachineIdentity = MachineIdentity{}
	if err := open.ValidateStructure(); err != nil {
		t.Fatalf("open-identity MAT rejected: %v", err)
	}

	// A well-formed identity is accepted.
	good := govMAT()
	good.MachineIdentity = MachineIdentity{Kind: "public_key", PublicKey: []byte{9}}
	if err := good.ValidateStructure(); err != nil {
		t.Fatalf("well-formed-identity MAT rejected: %v", err)
	}
}

// identityUnset is the boundary between "no identity" and "a malformed one": it
// must read presence of material, never the kind label. An attestation-kind
// identity carrying nothing is unset (open), not a lie; the same kind carrying
// a key is set, and then its material is judged.
func TestIdentityUnsetIgnoresKind(t *testing.T) {
	if !identityUnset(MachineIdentity{Kind: "attestation"}) {
		t.Fatal("an identity with a kind label but no material must be unset")
	}
	if identityUnset(MachineIdentity{Kind: "attestation", PublicKey: []byte{1}}) {
		t.Fatal("an identity carrying material must be set, whatever its kind says")
	}
}
