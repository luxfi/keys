// Copyright (C) 2024-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keys

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
)

// sample returns a fully-populated StakingIdentity with recognisable field
// bytes so a round-trip can assert exact preservation.
func sample() *StakingIdentity {
	return &StakingIdentity{
		TLSCertPEM: []byte("-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----"),
		TLSKeyPEM:  []byte("-----BEGIN PRIVATE KEY-----\ntlskey\n-----END PRIVATE KEY-----"),
		BLSSigner:  bytes.Repeat([]byte{0xB1}, 32),
		MLDSAPriv:  bytes.Repeat([]byte{0xD5}, 4032),
		MLDSAPub:   bytes.Repeat([]byte{0xD6}, 1952),
		MLKEMPriv:  bytes.Repeat([]byte{0xE7}, 2400),
		MLKEMPub:   bytes.Repeat([]byte{0xE8}, 1184),
		NodeLabel:  []byte("luxd-validator-2"),
	}
}

func equalIdentity(a, b *StakingIdentity) bool {
	return bytes.Equal(a.TLSCertPEM, b.TLSCertPEM) &&
		bytes.Equal(a.TLSKeyPEM, b.TLSKeyPEM) &&
		bytes.Equal(a.BLSSigner, b.BLSSigner) &&
		bytes.Equal(a.MLDSAPriv, b.MLDSAPriv) &&
		bytes.Equal(a.MLDSAPub, b.MLDSAPub) &&
		bytes.Equal(a.MLKEMPriv, b.MLKEMPriv) &&
		bytes.Equal(a.MLKEMPub, b.MLKEMPub) &&
		bytes.Equal(a.NodeLabel, b.NodeLabel)
}

// Marshal → Unmarshal preserves every field byte-for-byte, and Marshal is
// deterministic (same identity → identical blob).
func TestStakingIdentity_RoundTrip(t *testing.T) {
	in := sample()
	blob, err := in.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	blob2, err := in.Marshal()
	if err != nil {
		t.Fatalf("marshal 2: %v", err)
	}
	if !bytes.Equal(blob, blob2) {
		t.Fatal("Marshal is not deterministic")
	}
	out, err := UnmarshalStakingIdentity(blob)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !equalIdentity(in, out) {
		t.Fatal("round-trip did not preserve all fields")
	}
	if !out.HasClassical() || !out.HasStrictPQ() {
		t.Fatal("expected both profiles present")
	}
}

// The v2 NodeLabel field round-trips verbatim, is covered by the integrity
// checksum, and an empty label (the DERIVE case) round-trips too.
func TestStakingIdentity_NodeLabel(t *testing.T) {
	in := sample()
	in.NodeLabel = []byte("luxd-mainnet-node-07")
	blob, err := in.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out, err := UnmarshalStakingIdentity(blob)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if string(out.NodeLabel) != "luxd-mainnet-node-07" {
		t.Fatalf("NodeLabel not preserved: %q", out.NodeLabel)
	}

	// Tampering with the label bytes is rejected by the checksum — the label
	// cannot be swapped to point one node's blob at another node's label
	// without failing integrity. The label lives just before the 32-byte tail.
	bad := append([]byte(nil), blob...)
	bad[len(bad)-sha256.Size-1] ^= 0xFF
	if _, err := UnmarshalStakingIdentity(bad); err == nil {
		t.Fatal("tampered NodeLabel was not rejected")
	}

	// Empty label (DERIVE identities carry none) round-trips.
	noLabel := sample()
	noLabel.NodeLabel = nil
	nb, err := noLabel.Marshal()
	if err != nil {
		t.Fatalf("marshal no-label: %v", err)
	}
	back, err := UnmarshalStakingIdentity(nb)
	if err != nil {
		t.Fatalf("unmarshal no-label: %v", err)
	}
	if len(back.NodeLabel) != 0 {
		t.Fatalf("expected empty NodeLabel, got %q", back.NodeLabel)
	}
}

// Empty fields (classical-only, strict-PQ-only) round-trip exactly.
func TestStakingIdentity_PartialProfiles(t *testing.T) {
	classicalOnly := &StakingIdentity{
		TLSCertPEM: []byte("cert"), TLSKeyPEM: []byte("key"), BLSSigner: []byte("bls"),
	}
	pqOnly := &StakingIdentity{
		MLDSAPriv: []byte("dp"), MLDSAPub: []byte("dP"),
		MLKEMPriv: []byte("kp"), MLKEMPub: []byte("kP"),
	}
	for name, in := range map[string]*StakingIdentity{"classical": classicalOnly, "pq": pqOnly} {
		blob, err := in.Marshal()
		if err != nil {
			t.Fatalf("%s marshal: %v", name, err)
		}
		out, err := UnmarshalStakingIdentity(blob)
		if err != nil {
			t.Fatalf("%s unmarshal: %v", name, err)
		}
		if !equalIdentity(in, out) {
			t.Fatalf("%s round-trip mismatch", name)
		}
	}
	if !classicalOnly.HasClassical() || classicalOnly.HasStrictPQ() {
		t.Fatal("classicalOnly profile flags wrong")
	}
	if pqOnly.HasClassical() || !pqOnly.HasStrictPQ() {
		t.Fatal("pqOnly profile flags wrong")
	}
}

// A single flipped byte anywhere in the blob is rejected by the integrity
// checksum — the node fails closed rather than boot a half-parsed identity.
func TestStakingIdentity_TamperRejected(t *testing.T) {
	blob, err := sample().Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, pos := range []int{0, 11, 20, len(blob) / 2, len(blob) - 1} {
		bad := append([]byte(nil), blob...)
		bad[pos] ^= 0xFF
		if _, err := UnmarshalStakingIdentity(bad); err == nil {
			t.Fatalf("flip at %d was not rejected", pos)
		} else if !errors.Is(err, ErrStakingIdentityCodec) {
			t.Fatalf("flip at %d: wrong error type: %v", pos, err)
		}
	}
}

// Truncation is rejected (short blob and body cut before the checksum).
func TestStakingIdentity_TruncationRejected(t *testing.T) {
	blob, _ := sample().Marshal()
	for _, cut := range []int{0, 5, len(blob) - 40, len(blob) - 1} {
		if cut < 0 {
			continue
		}
		if _, err := UnmarshalStakingIdentity(blob[:cut]); err == nil {
			t.Fatalf("truncation to %d bytes was not rejected", cut)
		}
	}
}

// Trailing garbage after a valid blob is rejected (checksum covers exact body).
func TestStakingIdentity_TrailingGarbageRejected(t *testing.T) {
	blob, _ := sample().Marshal()
	if _, err := UnmarshalStakingIdentity(append(blob, 0x00)); err == nil {
		t.Fatal("trailing byte was not rejected")
	}
}

// A hostile oversize length prefix is rejected before allocation.
func TestStakingIdentity_OversizeFieldRejected(t *testing.T) {
	big := &StakingIdentity{TLSCertPEM: bytes.Repeat([]byte{1}, maxStakingField+1)}
	if _, err := big.Marshal(); err == nil {
		t.Fatal("Marshal accepted an oversize field")
	}
}

// A blob with the wrong magic is rejected even if its checksum is valid.
func TestStakingIdentity_BadMagicRejected(t *testing.T) {
	blob, _ := sample().Marshal()
	// Corrupt magic, then re-checksum so only the magic check can catch it.
	bad := append([]byte(nil), blob...)
	bad[0] = 'X'
	// Recompute checksum over the tampered body so integrity passes.
	body := bad[:len(bad)-32]
	if _, err := UnmarshalStakingIdentity(reChecksum(body)); err == nil {
		t.Fatal("bad magic with valid checksum was not rejected")
	}
}

// Wipe zeroes secrets, preserves public materials.
func TestStakingIdentity_Wipe(t *testing.T) {
	in := sample()
	pub := append([]byte(nil), in.MLDSAPub...)
	in.Wipe()
	if in.TLSKeyPEM != nil || in.BLSSigner != nil || in.MLDSAPriv != nil || in.MLKEMPriv != nil {
		t.Fatal("Wipe left a secret slice non-nil")
	}
	if !bytes.Equal(in.MLDSAPub, pub) || len(in.TLSCertPEM) == 0 || len(in.MLKEMPub) == 0 {
		t.Fatal("Wipe destroyed public material")
	}
	in.Wipe() // idempotent
}

// StakingIdentityFromValidatorKey copies source bytes (wiping the source after
// does not corrupt the bundle).
func TestStakingIdentityFromValidatorKey_Copies(t *testing.T) {
	pq, err := DeriveValidatorPQ(validMnemonic, 0)
	if err != nil {
		t.Fatalf("derive pq: %v", err)
	}
	vk := &ValidatorKey{
		StakerCert:   []byte("cert"),
		StakerKey:    []byte("key"),
		BLSSecretKey: []byte("bls"),
	}
	bundle := StakingIdentityFromValidatorKey(vk, pq)
	pqPub := append([]byte(nil), pq.MLDSAPub...)
	pq.Wipe()
	if !bytes.Equal(bundle.MLDSAPub, pqPub) {
		t.Fatal("bundle shares memory with source (source wipe leaked)")
	}
	if !bundle.HasClassical() || !bundle.HasStrictPQ() {
		t.Fatal("bundle missing a profile")
	}
}

// reChecksum recomputes the SHA-256 tail for a hand-tampered body so a test can
// isolate a non-integrity check (e.g. magic/version) from the checksum guard.
func reChecksum(body []byte) []byte {
	sum := sha256.Sum256(body)
	return append(append([]byte(nil), body...), sum[:]...)
}
