// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keys

import (
	"strings"
	"testing"
)

// canonicalMnemonic is the BIP-39 reference vector — abandon × 11 +
// about. Same value the bip39 test suite pins.
const canonicalMnemonic = "abandon abandon abandon abandon abandon abandon " +
	"abandon abandon abandon abandon abandon about"

// TestServiceIdentity_DeterministicNodeID — same (mnemonic, path) ↔
// same NodeID byte-for-byte. The whole consensus-native auth model
// depends on this property; a regression here silently changes every
// service's identity at deploy time.
func TestServiceIdentity_DeterministicNodeID(t *testing.T) {
	for _, path := range []string{
		"hanzo/kms-operator",
		"hanzo/commerce",
		"hanzo/paas",
		"lux/kms-operator",
	} {
		a, err := NewServiceIdentity(canonicalMnemonic, path)
		if err != nil {
			t.Fatalf("a %q: %v", path, err)
		}
		b, err := NewServiceIdentity(canonicalMnemonic, path)
		if err != nil {
			t.Fatalf("b %q: %v", path, err)
		}
		if a.NodeID != b.NodeID {
			t.Errorf("path=%q NodeID drift: %s vs %s", path, a.NodeID, b.NodeID)
		}
		if a.FullDigest != b.FullDigest {
			t.Errorf("path=%q FullDigest drift", path)
		}
		a.Wipe()
		b.Wipe()
	}
}

// TestServiceIdentity_DistinctPathsDistinctNodeIDs — same mnemonic,
// different paths → distinct NodeIDs. If a programmer accidentally
// passes the same path for two services they should see this in tests,
// not in production where two pods would collide.
func TestServiceIdentity_DistinctPathsDistinctNodeIDs(t *testing.T) {
	seen := make(map[string]string)
	for _, path := range []string{
		"hanzo/kms-operator",
		"hanzo/commerce",
		"hanzo/paas",
		"hanzo/base",
		"hanzo/playground",
		"lux/kms-operator",
		"zoo/registry",
	} {
		id, err := NewServiceIdentity(canonicalMnemonic, path)
		if err != nil {
			t.Fatalf("%q: %v", path, err)
		}
		key := id.NodeID.String()
		if prev, ok := seen[key]; ok {
			t.Errorf("NodeID collision: %q and %q both map to %s", prev, path, key)
		}
		seen[key] = path
		id.Wipe()
	}
}

// TestServiceIdentity_SignVerify — round-trip. The Sign output verifies
// under the matching public key + full digest; tampering anywhere
// (envelope, full digest, sig) rejects.
func TestServiceIdentity_SignVerify(t *testing.T) {
	id, err := NewServiceIdentity(canonicalMnemonic, "hanzo/kms-operator")
	if err != nil {
		t.Fatal(err)
	}
	defer id.Wipe()

	envelope := []byte(`{"op":64,"req":{"path":"hanzo/commerce","name":"stripe","env":"prod"}}`)
	sig, err := id.Sign(envelope)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := VerifyServiceEnvelope(id.PublicKey, id.FullDigest, envelope, sig); err != nil {
		t.Fatalf("Verify (clean): %v", err)
	}

	// Tamper envelope.
	tampered := []byte(`{"op":65,"req":{"path":"hanzo/commerce","name":"stripe","env":"prod"}}`)
	if err := VerifyServiceEnvelope(id.PublicKey, id.FullDigest, tampered, sig); err == nil {
		t.Errorf("Verify (tampered envelope) should fail")
	}

	// Tamper signature.
	tamperedSig := append([]byte(nil), sig...)
	tamperedSig[0] ^= 0xFF
	if err := VerifyServiceEnvelope(id.PublicKey, id.FullDigest, envelope, tamperedSig); err == nil {
		t.Errorf("Verify (tampered sig) should fail")
	}

	// Tamper full digest.
	tamperedFull := id.FullDigest
	tamperedFull[0] ^= 0xFF
	if err := VerifyServiceEnvelope(id.PublicKey, tamperedFull, envelope, sig); err == nil {
		t.Errorf("Verify (tampered fullDigest) should fail")
	}
}

// TestServiceIdentity_RejectsBadInput — empty path, invalid mnemonic.
func TestServiceIdentity_RejectsBadInput(t *testing.T) {
	if _, err := NewServiceIdentity("", "hanzo/foo"); err == nil {
		t.Error("empty mnemonic should fail")
	}
	if _, err := NewServiceIdentity(canonicalMnemonic, ""); err == nil {
		t.Error("empty path should fail")
	}
	if _, err := NewServiceIdentity(canonicalMnemonic, "   "); err == nil {
		t.Error("whitespace path should fail")
	}
	if _, err := NewServiceIdentity("not a valid bip39 phrase", "hanzo/foo"); err == nil {
		t.Error("invalid mnemonic should fail")
	}
}

// TestServiceIdentity_PathTrimming — leading/trailing slashes do not
// produce a different NodeID. Without this, "hanzo/foo" and "/hanzo/foo/"
// would be different services in a way the operator surely didn't intend.
func TestServiceIdentity_PathTrimming(t *testing.T) {
	a, err := NewServiceIdentity(canonicalMnemonic, "hanzo/foo")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Wipe()
	b, err := NewServiceIdentity(canonicalMnemonic, "/hanzo/foo/")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Wipe()
	if a.NodeID != b.NodeID {
		t.Errorf("path trimming failed: %s vs %s", a.NodeID, b.NodeID)
	}
}

// TestServiceIdentity_WipeIsIdempotent — wipe() can be called twice
// without panicking; Sign after Wipe fails fast.
func TestServiceIdentity_WipeIsIdempotent(t *testing.T) {
	id, err := NewServiceIdentity(canonicalMnemonic, "hanzo/foo")
	if err != nil {
		t.Fatal(err)
	}
	id.Wipe()
	id.Wipe() // must not panic
	if _, err := id.Sign([]byte("x")); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("Sign after Wipe: got %v, want 'empty' error", err)
	}
}

// TestServiceIdentity_NilSafeties — defensive zero-value semantics.
func TestServiceIdentity_NilSafeties(t *testing.T) {
	var id *ServiceIdentity
	id.Wipe() // must not panic on nil
	if _, err := id.Sign([]byte("x")); err == nil {
		t.Errorf("Sign on nil should fail")
	}
}
