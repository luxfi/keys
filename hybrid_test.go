// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keys

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	mldsa "github.com/luxfi/crypto/mldsa"
	secp "github.com/luxfi/crypto/secp256k1"
	"golang.org/x/crypto/sha3"
)

// freshHybridKey returns a deterministic-from-mnemonic HybridPrivateKey
// at the canonical test service path. Same input → same key, so tests
// can pin attack vectors against a known keypair.
func freshHybridKey(t *testing.T, path string) (*HybridIdentity, func()) {
	t.Helper()
	h, err := DeriveHybridIdentity(canonicalMnemonic, path)
	if err != nil {
		t.Fatalf("DeriveHybridIdentity(%q): %v", path, err)
	}
	return h, h.Wipe
}

// freshClassicalOnly returns a fresh secp256k1 keypair — used to forge
// component-substitution attack candidates without sharing the
// hybrid's classical key.
func freshClassicalOnly(t *testing.T) *secp.PrivateKey {
	t.Helper()
	k, err := secp.NewPrivateKey()
	if err != nil {
		t.Fatalf("secp256k1 keygen: %v", err)
	}
	return k
}

// freshPQOnly returns a fresh ML-DSA-65 keypair — same role as
// freshClassicalOnly for the PQ side.
func freshPQOnly(t *testing.T) *mldsa.PrivateKey {
	t.Helper()
	id, err := NewServiceIdentity(canonicalMnemonic, "test/scratch/pq-only-"+t.Name())
	if err != nil {
		t.Fatalf("NewServiceIdentity: %v", err)
	}
	pk, err := mldsa.PrivateKeyFromBytes(mldsa.MLDSA65, id.privateKey)
	if err != nil {
		t.Fatalf("PrivateKeyFromBytes: %v", err)
	}
	id.Wipe()
	return pk
}

// TestHybridSign_RoundTrip — the basic property: HybridSign emits a
// signature that HybridVerify accepts under the matching joint key.
func TestHybridSign_RoundTrip(t *testing.T) {
	h, wipe := freshHybridKey(t, "lux/validator/0")
	defer wipe()

	msg := []byte("validator-stake-anchor: blockHeight=1000000, weight=2000")
	sig, err := h.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := HybridVerify(h.PublicKey, msg, sig); err != nil {
		t.Fatalf("Verify (clean): %v", err)
	}
}

// TestHybridSign_BothVerifyRequired — a hybrid signature where ONLY
// the classical or ONLY the PQ component is present (or where one of
// the two has been tampered) MUST fail verification.
//
// This is the AND-mode binding test: the construction is broken if a
// half-signature would ever be accepted.
func TestHybridSign_BothVerifyRequired(t *testing.T) {
	h, wipe := freshHybridKey(t, "lux/validator/1")
	defer wipe()

	msg := []byte("test message")
	sig, err := h.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// (1) Tamper classical component — PQ stays valid, hybrid MUST fail.
	tampered := &HybridSignature{
		Classical: bytes.Clone(sig.Classical),
		PQ:        sig.PQ,
	}
	tampered.Classical[0] ^= 0xFF
	if err := HybridVerify(h.PublicKey, msg, tampered); !errors.Is(err, ErrHybridClassicalVerify) {
		t.Errorf("tampered classical: got %v, want ErrHybridClassicalVerify", err)
	}

	// (2) Tamper PQ component — classical stays valid, hybrid MUST fail.
	tampered2 := &HybridSignature{
		Classical: sig.Classical,
		PQ:        bytes.Clone(sig.PQ),
	}
	tampered2.PQ[0] ^= 0xFF
	if err := HybridVerify(h.PublicKey, msg, tampered2); !errors.Is(err, ErrHybridPQVerify) {
		t.Errorf("tampered PQ: got %v, want ErrHybridPQVerify", err)
	}

	// (3) Empty classical — typed nil-sig error.
	empty1 := &HybridSignature{Classical: nil, PQ: sig.PQ}
	if err := HybridVerify(h.PublicKey, msg, empty1); !errors.Is(err, ErrHybridNilSig) {
		t.Errorf("empty classical: got %v, want ErrHybridNilSig", err)
	}

	// (4) Empty PQ — typed nil-sig error.
	empty2 := &HybridSignature{Classical: sig.Classical, PQ: nil}
	if err := HybridVerify(h.PublicKey, msg, empty2); !errors.Is(err, ErrHybridNilSig) {
		t.Errorf("empty PQ: got %v, want ErrHybridNilSig", err)
	}

	// (5) Nil sig — typed nil-sig error.
	if err := HybridVerify(h.PublicKey, msg, nil); !errors.Is(err, ErrHybridNilSig) {
		t.Errorf("nil sig: got %v, want ErrHybridNilSig", err)
	}
}

// TestHybridSign_MsgBoundIncludesJointPubkey — different pubkey pair
// → different m_bound → different signature. This is the CDFFJ23
// strengthening: an adversary cannot reuse a signature under one
// (pk_c, pk_pq) under a different (pk_c', pk_pq').
//
// Test technique: take a valid (msg, sig) pair under hybrid A, then
// attempt to verify it under hybrid B (which differs in PUBLIC KEY
// only). The verifier MUST reject.
func TestHybridSign_MsgBoundIncludesJointPubkey(t *testing.T) {
	hA, wipeA := freshHybridKey(t, "lux/validator/A")
	defer wipeA()
	hB, wipeB := freshHybridKey(t, "lux/validator/B")
	defer wipeB()

	msg := []byte("cross-identity replay attack candidate")
	sigA, err := hA.Sign(msg)
	if err != nil {
		t.Fatalf("Sign A: %v", err)
	}

	// Sanity: A's signature verifies under A.
	if err := HybridVerify(hA.PublicKey, msg, sigA); err != nil {
		t.Fatalf("Verify A under A: %v", err)
	}

	// Attack: A's signature must NOT verify under B (different
	// joint pubkey → different m_bound → both components reject).
	if err := HybridVerify(hB.PublicKey, msg, sigA); err == nil {
		t.Error("A's signature verified under B — CDFFJ23 binding is broken")
	}

	// Sanity: m_bound differs between identities.
	mBoundA, err := HybridBoundDigest(hA.PublicKey, msg)
	if err != nil {
		t.Fatalf("boundDigest A: %v", err)
	}
	mBoundB, err := HybridBoundDigest(hB.PublicKey, msg)
	if err != nil {
		t.Fatalf("boundDigest B: %v", err)
	}
	if bytes.Equal(mBoundA, mBoundB) {
		t.Fatal("m_bound matched across distinct identities — joint pubkey not bound into digest")
	}
}

// TestHybridSign_NoComponentSubstitution — the headline BBF21
// property. Given a valid hybrid signature (sig_c, sig_pq) under
// identity (pk_c, pk_pq), an adversary holding a *different* PQ key
// pk_pq' CANNOT produce a valid hybrid signature under the joint
// pubkey (pk_c, pk_pq').
//
// Attack model:
//   - The adversary has sig_c (the classical half of the original).
//   - The adversary holds sk_pq' (their own ML-DSA-65 key).
//   - The adversary wants a valid (sig_c, sig_pq') under (pk_c, pk_pq').
//
// Defense: m_bound depends on the JOINT pubkey, so the adversary's
// sig_c is bound to the ORIGINAL m_bound (which references pk_pq, not
// pk_pq'). Under the new joint pubkey (pk_c, pk_pq') the verifier
// computes m_bound', and sig_c does NOT verify on m_bound'.
//
// This is the attack raw concat enables and BBF prevents.
func TestHybridSign_NoComponentSubstitution(t *testing.T) {
	hOriginal, wipe := freshHybridKey(t, "lux/validator/original")
	defer wipe()

	msg := []byte("validator stake delegation: 100 LUX")
	sigOriginal, err := hOriginal.Sign(msg)
	if err != nil {
		t.Fatalf("Sign original: %v", err)
	}

	// Adversary stands up a new ML-DSA-65 key, attempts to re-attribute
	// the classical signature to the new joint pubkey.
	advPQ := freshPQOnly(t)
	defer advPQ.Zeroize()
	advJointPK := &HybridPublicKey{
		Classical: hOriginal.PublicKey.Classical, // same classical
		PQ:        advPQ.PublicKey,               // adversary's PQ
	}

	// Adversary signs the same msg with their PQ key under the new
	// joint pubkey's m_bound — which references ADV's pk_pq, not the
	// original.
	advMBound, err := HybridBoundDigest(advJointPK, msg)
	if err != nil {
		t.Fatalf("boundDigest adv: %v", err)
	}
	advPQSig, err := advPQ.SignCtx(nil, advMBound, []byte(HybridSigDomain))
	if err != nil {
		t.Fatalf("adv PQ sign: %v", err)
	}

	// Forgery candidate: classical from the original, PQ from the
	// adversary, under the adversary's joint pubkey.
	forgery := &HybridSignature{
		Classical: sigOriginal.Classical,
		PQ:        advPQSig,
	}

	err = HybridVerify(advJointPK, msg, forgery)
	if err == nil {
		t.Fatal("component substitution succeeded — BBF binding is broken")
	}
	// The classical signature MUST be the failing component because
	// it was bound to the ORIGINAL m_bound, not the adversary's.
	if !errors.Is(err, ErrHybridClassicalVerify) {
		t.Errorf("component substitution: got %v, want ErrHybridClassicalVerify", err)
	}

	// Symmetric attack: adversary holds the classical side instead.
	advClassical := freshClassicalOnly(t)
	advJointPK2 := &HybridPublicKey{
		Classical: advClassical.PublicKey(),    // adversary's classical
		PQ:        hOriginal.PublicKey.PQ,      // same PQ
	}
	advMBound2, err := HybridBoundDigest(advJointPK2, msg)
	if err != nil {
		t.Fatalf("boundDigest adv2: %v", err)
	}
	advClassicalSig, err := advClassical.SignHash(advMBound2[:32])
	if err != nil {
		t.Fatalf("adv classical sign: %v", err)
	}
	forgery2 := &HybridSignature{
		Classical: advClassicalSig,
		PQ:        sigOriginal.PQ,
	}
	err = HybridVerify(advJointPK2, msg, forgery2)
	if err == nil {
		t.Fatal("symmetric component substitution succeeded — BBF binding is broken")
	}
	if !errors.Is(err, ErrHybridPQVerify) {
		t.Errorf("symmetric substitution: got %v, want ErrHybridPQVerify", err)
	}
}

// TestHybridSign_DomainSeparation — a signature produced with the
// HybridSigDomain context must not verify if the domain string is
// altered. This guards against cross-protocol replay of the same key
// against a different (hypothetical v2) hybrid scheme.
//
// Implementation: we forge a "v2-style" m_bound that differs only in
// the domain prefix and check that a v1-bound signature does NOT
// verify under it.
func TestHybridSign_DomainSeparation(t *testing.T) {
	h, wipe := freshHybridKey(t, "lux/validator/domsep")
	defer wipe()

	msg := []byte("domain-sep canary")
	sig, err := h.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Sanity check: valid under v1 domain.
	if err := HybridVerify(h.PublicKey, msg, sig); err != nil {
		t.Fatalf("Verify v1: %v", err)
	}

	// Compute the v1 m_bound for reference.
	v1Bound, err := HybridBoundDigest(h.PublicKey, msg)
	if err != nil {
		t.Fatalf("v1 bound: %v", err)
	}

	// Construct a "v2-style" m_bound by hand with a different domain
	// prefix. The classical component of the v1 signature is bound to
	// v1Bound[:32]; if domain separation works, v2Bound[:32] must
	// differ.
	v2DomainCandidate := "lux-hybrid-sig-v2" // hypothetical future scheme
	v2Bound := func() []byte {
		// Manually replicate boundDigest with v2 prefix.
		pkC := h.PublicKey.Classical.CompressedBytes()
		pkPQ := h.PublicKey.PQ.Bytes()
		buf := bytes.Buffer{}
		buf.Write(leftEncode(uint64(len(v2DomainCandidate)) * 8))
		buf.WriteString(v2DomainCandidate)
		buf.Write(leftEncode(uint64(len(pkC)) * 8))
		buf.Write(pkC)
		buf.Write(leftEncode(uint64(len(pkPQ)) * 8))
		buf.Write(pkPQ)
		buf.Write(leftEncode(uint64(len(msg)) * 8))
		buf.Write(msg)

		// Apply SHAKE256-384 to buf.
		out := make([]byte, HybridBoundDigestLen)
		import_sha3_into(out, buf.Bytes())
		return out
	}()

	if bytes.Equal(v1Bound, v2Bound) {
		t.Fatal("v1 and v2 m_bounds collided — domain separation failed")
	}

	// The classical component of the v1 sig MUST NOT verify on v2's prefix.
	if h.PublicKey.Classical.VerifyHash(v2Bound[:32], sig.Classical) {
		t.Error("v1 classical signature verified against v2 prefix — domain separation broken")
	}
}

// TestHybridSign_MsgTampering — modifying the message after signing
// must invalidate both components (because msg is bound into m_bound).
func TestHybridSign_MsgTampering(t *testing.T) {
	h, wipe := freshHybridKey(t, "lux/validator/msgtamp")
	defer wipe()

	msg := []byte("original message")
	sig, err := h.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	tampered := []byte("Original message") // capital 'O'
	err = HybridVerify(h.PublicKey, tampered, sig)
	if err == nil {
		t.Error("tampered message verified — msg-binding broken")
	}
	// Classical fails first (the verifier short-circuits on the first
	// component to fail; classical is checked first in our impl).
	if !errors.Is(err, ErrHybridClassicalVerify) {
		t.Errorf("tampered msg: got %v, want ErrHybridClassicalVerify", err)
	}
}

// TestHybridSign_DeterministicIdentity — same (mnemonic, path) →
// same hybrid identity byte-for-byte. The hybrid analog of
// TestServiceIdentity_DeterministicNodeID.
func TestHybridSign_DeterministicIdentity(t *testing.T) {
	for _, path := range []string{
		"lux/validator/0",
		"lux/validator/1",
		"hanzo/kms-operator",
	} {
		a, err := DeriveHybridIdentity(canonicalMnemonic, path)
		if err != nil {
			t.Fatalf("DeriveHybridIdentity a %q: %v", path, err)
		}
		b, err := DeriveHybridIdentity(canonicalMnemonic, path)
		if err != nil {
			t.Fatalf("DeriveHybridIdentity b %q: %v", path, err)
		}

		if a.NodeID != b.NodeID {
			t.Errorf("path=%q NodeID drift: %s vs %s", path, a.NodeID, b.NodeID)
		}
		if a.FullDigest != b.FullDigest {
			t.Errorf("path=%q FullDigest drift", path)
		}
		if !bytes.Equal(a.PublicKeyBytes, b.PublicKeyBytes) {
			t.Errorf("path=%q PublicKeyBytes drift", path)
		}
		if !bytes.Equal(
			a.PublicKey.Classical.CompressedBytes(),
			b.PublicKey.Classical.CompressedBytes(),
		) {
			t.Errorf("path=%q classical pubkey drift", path)
		}
		if !bytes.Equal(a.PublicKey.PQ.Bytes(), b.PublicKey.PQ.Bytes()) {
			t.Errorf("path=%q PQ pubkey drift", path)
		}

		a.Wipe()
		b.Wipe()
	}
}

// TestHybridSign_DistinctPathsDistinctIdentities — same mnemonic,
// different paths → distinct NodeIDs and distinct joint pubkeys.
func TestHybridSign_DistinctPathsDistinctIdentities(t *testing.T) {
	seenNode := make(map[string]string)
	seenPk := make(map[string]string)
	for _, path := range []string{
		"lux/validator/0",
		"lux/validator/1",
		"lux/validator/2",
		"hanzo/kms-operator",
		"hanzo/commerce",
	} {
		id, err := DeriveHybridIdentity(canonicalMnemonic, path)
		if err != nil {
			t.Fatalf("%q: %v", path, err)
		}
		nodeKey := id.NodeID.String()
		if prev, ok := seenNode[nodeKey]; ok {
			t.Errorf("NodeID collision: %q and %q both map to %s", prev, path, nodeKey)
		}
		seenNode[nodeKey] = path

		pkKey := string(id.PublicKeyBytes)
		if prev, ok := seenPk[pkKey]; ok {
			t.Errorf("PublicKey collision: %q and %q produce same pubkey bytes", prev, path)
		}
		seenPk[pkKey] = path

		id.Wipe()
	}
}

// TestHybridSign_LegacyServiceIdentityIsDistinct — a legacy
// ML-DSA-only ServiceIdentity at "lux/validator/0" does NOT share its
// PQ key with the hybrid identity at the same path. Without this,
// rolling a validator from legacy to hybrid would silently re-use the
// same PQ key (which is a CDFFJ23-class leak: the legacy pubkey is
// the same in both contexts).
func TestHybridSign_LegacyServiceIdentityIsDistinct(t *testing.T) {
	legacy, err := NewServiceIdentity(canonicalMnemonic, "lux/validator/0")
	if err != nil {
		t.Fatalf("legacy: %v", err)
	}
	defer legacy.Wipe()

	hybrid, err := DeriveHybridIdentity(canonicalMnemonic, "lux/validator/0")
	if err != nil {
		t.Fatalf("hybrid: %v", err)
	}
	defer hybrid.Wipe()

	if bytes.Equal(legacy.PublicKey, hybrid.PublicKey.PQ.Bytes()) {
		t.Fatal("legacy ML-DSA pubkey == hybrid PQ pubkey at same path — domain separation between v1 and hybrid is broken")
	}
}

// TestHybridSign_BackwardCompatPath — legacy ECDSA-only validators
// can still produce a stand-alone secp256k1 signature during the
// transition window. The hybrid path is GATED separately (chain
// profile check, not API-level) so the legacy primitive remains
// callable.
//
// This test certifies the API split: the classical sub-key of a
// HybridIdentity is reachable as a plain secp256k1 PrivateKey when
// needed for a legacy signing surface (e.g. a P-Chain re-anchor tx
// signed under the OLD primitive to authorise the re-anchor itself).
func TestHybridSign_BackwardCompatPath(t *testing.T) {
	h, wipe := freshHybridKey(t, "lux/validator/transition")
	defer wipe()

	// Legacy path: extract classical sub-key, sign a P-Chain-style
	// payload with secp256k1 alone.
	msg := []byte("re-anchor tx: from ecdsa(0xABCD…) to hybrid(0xWXYZ…)")
	legacySig, err := h.PublicKey.Classical.Verify, error(nil)
	_ = legacySig
	_ = err
	// Sign with the classical sub-key (note: HybridIdentity owns the
	// joint private key; legacy callers reach the classical component
	// via the private API only — this test demonstrates the seam).
	// We re-derive the legacy key from the same path to certify that
	// the classical sub-key is reachable.
	classicalSig, err := h.privateKey.Classical.SignHash(legacyHash(msg))
	if err != nil {
		t.Fatalf("legacy classical sign: %v", err)
	}
	if !h.PublicKey.Classical.VerifyHash(legacyHash(msg), classicalSig) {
		t.Fatal("legacy classical roundtrip failed")
	}

	// Critical: this legacy classical signature is NOT a valid hybrid
	// signature. A verifier on the hybrid surface MUST refuse it.
	bogusHybrid := &HybridSignature{
		Classical: classicalSig,
		PQ:        nil,
	}
	if err := HybridVerify(h.PublicKey, msg, bogusHybrid); !errors.Is(err, ErrHybridNilSig) {
		t.Errorf("legacy classical sig accepted as hybrid: got %v, want ErrHybridNilSig", err)
	}
}

// TestHybridSign_NilSafeties — defensive zero-value semantics.
func TestHybridSign_NilSafeties(t *testing.T) {
	var h *HybridIdentity
	h.Wipe() // must not panic on nil
	if _, err := h.Sign([]byte("x")); err == nil {
		t.Error("Sign on nil HybridIdentity should fail")
	}

	if _, err := HybridSign(nil, []byte("x"), nil); !errors.Is(err, ErrHybridNilKey) {
		t.Errorf("HybridSign(nil, …): got %v, want ErrHybridNilKey", err)
	}

	half := &HybridPrivateKey{Classical: nil, PQ: nil}
	if _, err := HybridSign(half, []byte("x"), nil); !errors.Is(err, ErrHybridNilKey) {
		t.Errorf("HybridSign(empty, …): got %v, want ErrHybridNilKey", err)
	}

	if err := HybridVerify(nil, []byte("x"), &HybridSignature{Classical: []byte("a"), PQ: []byte("b")}); !errors.Is(err, ErrHybridNilKey) {
		t.Errorf("HybridVerify(nil, …): got %v, want ErrHybridNilKey", err)
	}

	if _, err := DeriveHybridIdentity("", "x"); err == nil {
		t.Error("DeriveHybridIdentity with empty mnemonic should fail")
	}
	if _, err := DeriveHybridIdentity(canonicalMnemonic, ""); err == nil {
		t.Error("DeriveHybridIdentity with empty path should fail")
	}
}

// TestHybridSign_RejectsBadInput — validation of inputs to the
// constructor.
func TestHybridSign_RejectsBadInput(t *testing.T) {
	if _, err := DeriveHybridIdentity("not a valid bip39 phrase", "lux/validator/0"); err == nil {
		t.Error("invalid mnemonic should fail")
	}
	if _, err := DeriveHybridIdentity(canonicalMnemonic, "   "); err == nil {
		t.Error("whitespace path should fail")
	}
}

// TestHybridSign_WipeIsIdempotent — Wipe can be called twice; Sign
// after Wipe fails fast.
func TestHybridSign_WipeIsIdempotent(t *testing.T) {
	h, err := DeriveHybridIdentity(canonicalMnemonic, "lux/validator/wipe")
	if err != nil {
		t.Fatal(err)
	}
	h.Wipe()
	h.Wipe()
	if _, err := h.Sign([]byte("x")); err == nil {
		t.Error("Sign after Wipe should fail")
	}
}

// legacyHash is the SHA-256 used by the existing secp256k1 SignArray
// path. Exposed here purely so the backward-compat test certifies the
// legacy verification path against the same hash convention.
func legacyHash(msg []byte) []byte {
	sum := sha256.Sum256(msg)
	return sum[:]
}

// import_sha3_into is a tiny helper used by TestHybridSign_DomainSeparation
// to compute a SHAKE256-384 digest over arbitrary bytes. Kept local so
// the test file imports stay small.
func import_sha3_into(out []byte, in []byte) {
	h := sha3.NewShake256()
	_, _ = h.Write(in)
	_, _ = h.Read(out)
}
