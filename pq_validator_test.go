// Copyright (C) 2024-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keys

import (
	"bytes"
	"testing"

	mldsa "github.com/luxfi/crypto/mldsa"
	mlkem "github.com/luxfi/crypto/mlkem"
	"github.com/luxfi/ids"
)

// validMnemonic is the canonical BIP-39 all-zero-entropy English test vector.
const validMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

// Deterministic: same (mnemonic, index) → identical strict-PQ keys, every call.
// This is the invariant that makes a strict-PQ NodeID stable across restarts
// with nothing custodied on disk.
func TestDeriveValidatorPQ_Deterministic(t *testing.T) {
	a, err := DeriveValidatorPQ(validMnemonic, 0)
	if err != nil {
		t.Fatalf("derive a: %v", err)
	}
	b, err := DeriveValidatorPQ(validMnemonic, 0)
	if err != nil {
		t.Fatalf("derive b: %v", err)
	}
	if !bytes.Equal(a.MLDSAPriv, b.MLDSAPriv) || !bytes.Equal(a.MLDSAPub, b.MLDSAPub) {
		t.Fatal("ML-DSA-65 derivation is not deterministic")
	}
	if !bytes.Equal(a.MLKEMPriv, b.MLKEMPriv) || !bytes.Equal(a.MLKEMPub, b.MLKEMPub) {
		t.Fatal("ML-KEM-768 derivation is not deterministic")
	}
}

// The derived key material must be the real FIPS 204 / FIPS 203 keypairs: the
// public key parses and matches the one derivable from the private key.
func TestDeriveValidatorPQ_WellFormedKeys(t *testing.T) {
	k, err := DeriveValidatorPQ(validMnemonic, 7)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	// ML-DSA-65: pub derivable from priv must equal the stored pub.
	priv, err := mldsa.PrivateKeyFromBytes(mldsa.MLDSA65, k.MLDSAPriv)
	if err != nil {
		t.Fatalf("parse ML-DSA priv: %v", err)
	}
	if !bytes.Equal(priv.PublicKey.Bytes(), k.MLDSAPub) {
		t.Fatal("ML-DSA-65 stored pub != pub derived from priv")
	}
	// ML-DSA-65 sign/verify round-trip over the derived key.
	msg := []byte("strict-pq staking identity")
	sig, err := priv.Sign(nil, msg, nil)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	pub, err := mldsa.PublicKeyFromBytes(k.MLDSAPub, mldsa.MLDSA65)
	if err != nil {
		t.Fatalf("parse ML-DSA pub: %v", err)
	}
	if !pub.VerifySignature(msg, sig) {
		t.Fatal("ML-DSA-65 signature over derived key failed to verify")
	}
	// ML-KEM-768: both halves parse at the FIPS 203 sizes.
	if len(k.MLKEMPub) != mlkem.MLKEM768PublicKeySize {
		t.Fatalf("ML-KEM pub size = %d, want %d", len(k.MLKEMPub), mlkem.MLKEM768PublicKeySize)
	}
	if len(k.MLKEMPriv) != mlkem.MLKEM768PrivateKeySize {
		t.Fatalf("ML-KEM priv size = %d, want %d", len(k.MLKEMPriv), mlkem.MLKEM768PrivateKeySize)
	}
	if _, err := mlkem.PrivateKeyFromBytes(k.MLKEMPriv, mlkem.MLKEM768); err != nil {
		t.Fatalf("parse ML-KEM priv: %v", err)
	}
}

// The NodeID the derived key anchors matches the node's boot derivation exactly
// (ids.NodeIDSchemeMLDSA65.DeriveMLDSA(ids.Empty, MLDSAPub)) — a re-derived key
// yields the same NodeID, which is the whole point of custody-free stability.
func TestDeriveValidatorPQ_NodeIDRoundTrip(t *testing.T) {
	k, err := DeriveValidatorPQ(validMnemonic, 3)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	got, err := k.StrictPQNodeID(ids.Empty)
	if err != nil {
		t.Fatalf("NodeID: %v", err)
	}
	// Independently compute what node.StakingConfig.DeriveNodeID(ids.Empty)
	// would produce for a strict-PQ node holding this pub.
	want, _, err := ids.NodeIDSchemeMLDSA65.DeriveMLDSA(ids.Empty, k.MLDSAPub)
	if err != nil {
		t.Fatalf("reference DeriveMLDSA: %v", err)
	}
	if got != want {
		t.Fatalf("NodeID mismatch: helper=%s reference=%s", got, want)
	}
	// A freshly re-derived key from the same mnemonic+index yields the SAME
	// NodeID — the restart-stability guarantee.
	k2, err := DeriveValidatorPQ(validMnemonic, 3)
	if err != nil {
		t.Fatalf("re-derive: %v", err)
	}
	got2, _ := k2.StrictPQNodeID(ids.Empty)
	if got != got2 {
		t.Fatal("re-derived key produced a different NodeID (custody-free stability broken)")
	}
}

// Distinct validator indices produce distinct keys and distinct NodeIDs — a
// fleet derived from one mnemonic must not collapse onto one identity.
func TestDeriveValidatorPQ_IndexSeparation(t *testing.T) {
	k0, _ := DeriveValidatorPQ(validMnemonic, 0)
	k1, _ := DeriveValidatorPQ(validMnemonic, 1)
	if bytes.Equal(k0.MLDSAPub, k1.MLDSAPub) {
		t.Fatal("different indices produced the same ML-DSA public key")
	}
	if bytes.Equal(k0.MLKEMPub, k1.MLKEMPub) {
		t.Fatal("different indices produced the same ML-KEM public key")
	}
	n0, _ := k0.StrictPQNodeID(ids.Empty)
	n1, _ := k1.StrictPQNodeID(ids.Empty)
	if n0 == n1 {
		t.Fatal("different indices produced the same NodeID")
	}
}

// Domain separation: the validator ML-DSA key must NEVER equal the service-auth
// ML-DSA key derived from the same mnemonic (distinct derivation strings + tree
// positions). A collision would let a KMS-auth credential masquerade as a
// staking key, or vice versa.
func TestDeriveValidatorPQ_DomainSeparatedFromServiceIdentity(t *testing.T) {
	vk, err := DeriveValidatorPQ(validMnemonic, 0)
	if err != nil {
		t.Fatalf("derive validator pq: %v", err)
	}
	svc, err := NewServiceIdentity(validMnemonic, "luxd/staking-bootstrap")
	if err != nil {
		t.Fatalf("derive service identity: %v", err)
	}
	if bytes.Equal(vk.MLDSAPub, svc.PublicKey) {
		t.Fatal("validator ML-DSA key collides with service-auth ML-DSA key")
	}
}

// An invalid BIP-39 phrase is rejected before any derivation.
func TestDeriveValidatorPQ_InvalidMnemonic(t *testing.T) {
	if _, err := DeriveValidatorPQ("not a valid bip39 phrase at all", 0); err == nil {
		t.Fatal("expected error for invalid mnemonic")
	}
}

// An out-of-range index is rejected (misconfiguration guard).
func TestDeriveValidatorPQ_IndexBounds(t *testing.T) {
	if _, err := DeriveValidatorPQ(validMnemonic, maxValidatorIndex+1); err == nil {
		t.Fatal("expected ErrInvalidAccountIndex for out-of-range index")
	}
}

// Wipe zeroes the private material.
func TestPQValidatorKey_Wipe(t *testing.T) {
	k, err := DeriveValidatorPQ(validMnemonic, 0)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	// Snapshot pub before wipe (pub must survive).
	pub := append([]byte(nil), k.MLDSAPub...)
	k.Wipe()
	if k.MLDSAPriv != nil || k.MLKEMPriv != nil {
		t.Fatal("Wipe did not nil the private slices")
	}
	if !bytes.Equal(k.MLDSAPub, pub) {
		t.Fatal("Wipe destroyed the public key (should be preserved)")
	}
	k.Wipe() // idempotent
}
