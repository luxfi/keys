// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// hybrid.go — Bindel-Brendel-Fischlin (CCS 2021) + Cremers-Düzlü-Fiedler-
// Fischlin-Janson (Asiacrypt 2023) stronger-binding hybrid signature
// scheme for Lux validator identity.
//
// Construction (BBF21 N-Sig with CDFFJ23 joint-pk binding):
//
//	m_bound = H_bind(pk_c, pk_pq, msg)
//	        = SHAKE256-384( "lux-hybrid-sig-v1"
//	                        || left_encode(8·|pk_c|)  || pk_c
//	                        || left_encode(8·|pk_pq|) || pk_pq
//	                        || left_encode(8·|msg|)   || msg )
//	sig_c   = secp256k1.SignHash(sk_c, m_bound)
//	sig_pq  = mldsa65.SignCtx(sk_pq, m_bound, "lux-hybrid-sig-v1")
//	Verify  = AND( secp256k1.VerifyHash(pk_c, m_bound, sig_c),
//	               mldsa65.VerifyCtx(pk_pq, m_bound, sig_pq, "lux-hybrid-sig-v1") )
//
// Why this construction (vs raw concat):
//
//   Raw concat `pk_c || pk_pq` and per-component signatures over `msg`
//   reduces to MIN security under a non-honest-sign adversary
//   (CDFFJ23 §4): an adversary that registers a malformed pk_pq can
//   force the hybrid to drop to classical security only. By hashing
//   BOTH pubkeys into m_bound, every signature is *cryptographically
//   bound to the joint identity* — substituting either component
//   invalidates the binding. This is BBF21 §3.2 Cons. 2 "Combined
//   Concatenated" with the CDFFJ23 strengthening: m_bound includes
//   both pubkeys so component swap is detectable.
//
// Why secp256k1 as classical (not ed25519 or X25519):
//
//   (a) X25519 is a KEM, not a signature scheme — disqualified.
//   (b) Lux P/X validator identity already anchors on secp256k1
//       (see keys.ValidatorKey.ECPrivateKey + .PChainAddr). Picking
//       secp256k1 means the hybrid is a pure superset — every existing
//       validator's classical key continues to play the same role.
//   (c) ed25519 would add a third primitive with no existing
//       infrastructure: no NodeID derivation, no stake record format.
//   secp256k1 is the only choice that preserves the one-and-only-one
//   way of identifying a P/X validator.
//
// Security claim (BBF21 Thm. 1 + CDFFJ23 Thm. 3 corollary):
//
//   The scheme is EUF-CMA under
//      max( EUF-CMA_secp256k1, sEUF-CMA_MLDSA65 )
//   in the chosen-message model where the adversary may submit
//   adversarial pk_pq's during registration. This is strictly
//   stronger than min(·, ·) which is all raw concatenation buys.
//
// Domain separation:
//
//   The string "lux-hybrid-sig-v1" appears verbatim TWICE: once as
//   the prefix of m_bound (binds the hash), once as the ML-DSA-65
//   context (binds the PQ signature). This is intentional — a future
//   v2 of the scheme (say, with ML-DSA-87 or different prefix bytes)
//   would replace both occurrences atomically; no cross-version
//   replay is possible.

package keys

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	mldsa "github.com/luxfi/crypto/mldsa"
	secp "github.com/luxfi/crypto/secp256k1"
	"golang.org/x/crypto/sha3"
)

// HybridSigDomain is the canonical domain-separation string for the
// Lux hybrid signature scheme. Pinned at v1; bumping invalidates every
// prior hybrid signature, which is the correct behaviour for a hardfork
// of the binding encoding. The same string is used both as the H_bind
// prefix and as the ML-DSA-65 context.
const HybridSigDomain = "lux-hybrid-sig-v1"

// HybridBoundDigestLen is the byte length of the m_bound digest the
// scheme uses internally. 48 bytes = SHAKE256-384, the same hash size
// as ids.FullDigest — matches the Lux convention for identity digests.
const HybridBoundDigestLen = 48

// Typed errors. errors.Is friendly.
var (
	// ErrHybridNilKey — either component of the hybrid key is nil.
	// Refused early; we never want a half-hybrid signing path.
	ErrHybridNilKey = errors.New("keys: hybrid key has nil component")

	// ErrHybridClassicalSign — secp256k1 signing failed. The error
	// wraps the underlying secp256k1 error.
	ErrHybridClassicalSign = errors.New("keys: hybrid classical sign failed")

	// ErrHybridPQSign — ML-DSA-65 signing failed. The error wraps
	// the underlying mldsa error.
	ErrHybridPQSign = errors.New("keys: hybrid PQ sign failed")

	// ErrHybridClassicalVerify — secp256k1 verification failed.
	// A valid hybrid signature requires BOTH components to verify.
	ErrHybridClassicalVerify = errors.New("keys: hybrid classical verification failed")

	// ErrHybridPQVerify — ML-DSA-65 verification failed. A valid
	// hybrid signature requires BOTH components to verify.
	ErrHybridPQVerify = errors.New("keys: hybrid PQ verification failed")

	// ErrHybridNilSig — signature struct or one of its components is
	// nil/empty. Refused before any expensive verification.
	ErrHybridNilSig = errors.New("keys: hybrid signature has nil component")
)

// HybridPublicKey is the joint pubkey of the BBF-bound hybrid scheme.
// Both components are required for any verification; a half-hybrid is
// a programmer error.
type HybridPublicKey struct {
	// Classical is the secp256k1 verification key. 33-byte compressed
	// SEC1 encoding on the wire. This is the same primitive the
	// existing Lux validator set uses for P/X identity.
	Classical *secp.PublicKey

	// PQ is the ML-DSA-65 verification key (FIPS 204). Bytes-on-the-
	// wire form is the standard ML-DSA-65 public key encoding.
	PQ *mldsa.PublicKey
}

// HybridPrivateKey is the joint signing key of the BBF-bound hybrid
// scheme. Owns both private components; the only legal use is internal
// Sign(). Call Wipe() when done.
type HybridPrivateKey struct {
	// Classical is the secp256k1 signing key (32 bytes scalar).
	Classical *secp.PrivateKey

	// PQ is the ML-DSA-65 signing key (FIPS 204).
	PQ *mldsa.PrivateKey
}

// HybridSignature is the joint signature of the BBF-bound hybrid
// scheme. BOTH components are required for verification. Neither is
// independently useful — that is the binding the scheme provides.
type HybridSignature struct {
	// Classical is the secp256k1 recoverable signature (65 bytes).
	Classical []byte

	// PQ is the ML-DSA-65 signature (FIPS 204 standard size).
	PQ []byte
}

// HybridPublic extracts the joint public key from the joint private
// key. Pure function: no allocation other than the returned struct.
func (sk *HybridPrivateKey) Public() *HybridPublicKey {
	if sk == nil {
		return nil
	}
	return &HybridPublicKey{
		Classical: sk.Classical.PublicKey(),
		PQ:        sk.PQ.PublicKey,
	}
}

// Wipe zeroes both private components in place. Idempotent. Safe to
// call from a defer on a nil receiver.
func (sk *HybridPrivateKey) Wipe() {
	if sk == nil {
		return
	}
	if sk.PQ != nil {
		sk.PQ.Zeroize()
		sk.PQ = nil
	}
	// secp256k1.PrivateKey holds key bytes in an unexported field;
	// the canonical wipe is to drop the pointer reference and let the
	// GC reclaim — luxfi/crypto/secp256k1 does not export a Zeroize
	// (the scalar is consumed by SignHash internally and the bytes
	// live in the heap). Dropping the reference is the best we can
	// portably do without forking the upstream API.
	sk.Classical = nil
}

// boundDigest computes m_bound — the canonical SHAKE256-384 commitment
// the scheme binds. This is the joint message every signature is
// computed over and every verifier reconstructs.
//
// Wire shape (SP 800-185 left_encode framed):
//
//	left_encode(8·|domain|)         || domain          (= HybridSigDomain)
//	left_encode(8·|pk_classical|)   || pk_classical    (33 bytes SEC1)
//	left_encode(8·|pk_pq|)          || pk_pq           (ML-DSA-65 pubkey)
//	left_encode(8·|msg|)            || msg
//
// 48-byte SHAKE256-384 output. The encoding is unambiguous: an
// adversary cannot smuggle field bytes across boundaries because each
// field's length is prepended.
func boundDigest(pk *HybridPublicKey, msg []byte) ([]byte, error) {
	if pk == nil || pk.Classical == nil || pk.PQ == nil {
		return nil, ErrHybridNilKey
	}
	pkClassical := pk.Classical.CompressedBytes() // 33 bytes
	pkPQ := pk.PQ.Bytes()                          // ML-DSA-65 pubkey bytes

	h := sha3.NewShake256()
	_, _ = h.Write(leftEncode(uint64(len(HybridSigDomain)) * 8))
	_, _ = h.Write([]byte(HybridSigDomain))
	_, _ = h.Write(leftEncode(uint64(len(pkClassical)) * 8))
	_, _ = h.Write(pkClassical)
	_, _ = h.Write(leftEncode(uint64(len(pkPQ)) * 8))
	_, _ = h.Write(pkPQ)
	_, _ = h.Write(leftEncode(uint64(len(msg)) * 8))
	_, _ = h.Write(msg)

	out := make([]byte, HybridBoundDigestLen)
	_, _ = h.Read(out)
	return out, nil
}

// HybridBoundDigest is the exported helper computing m_bound. Same
// algorithm as the internal boundDigest; exported so an out-of-band
// verifier (e.g. an on-chain precompile or a different language's
// implementation) can reconstruct the bound message verbatim.
//
// Pure function: no I/O, no randomness.
func HybridBoundDigest(pk *HybridPublicKey, msg []byte) ([]byte, error) {
	return boundDigest(pk, msg)
}

// HybridSign produces a BBF-bound joint signature over msg under the
// given joint signing key. The classical signature uses secp256k1
// SignHash over m_bound; the PQ signature uses ML-DSA-65 SignCtx with
// HybridSigDomain as the context.
//
// Why two domain-separated bindings:
//
//   (1) m_bound's prefix binds the SHAKE256 input to this scheme.
//   (2) The ML-DSA context binds the FIPS 204 signature itself to
//       this scheme — preventing cross-protocol replay of a future
//       hybrid signature against any other ML-DSA-65 surface (KMS
//       envelope, P-Chain block, etc.).
//
// rand is the randomness source for ML-DSA-65 hedged signing. If nil,
// crypto/rand is used. The secp256k1 signature uses RFC 6979
// deterministic-k — no randomness needed.
func HybridSign(sk *HybridPrivateKey, msg []byte, randSource io.Reader) (*HybridSignature, error) {
	if sk == nil || sk.Classical == nil || sk.PQ == nil {
		return nil, ErrHybridNilKey
	}
	if randSource == nil {
		randSource = rand.Reader
	}

	pk := sk.Public()
	mBound, err := boundDigest(pk, msg)
	if err != nil {
		return nil, err
	}

	// Classical: secp256k1 SignHash(m_bound). SignHash expects a
	// 32-byte hash, but m_bound is 48 bytes (SHAKE256-384). The
	// canonical thing to do is sign the first 32 bytes of the digest
	// — keep the full SHAKE256-384 output for the PQ side (which
	// can absorb arbitrary length via SignCtx), and use the prefix
	// for the classical side which requires a 32-byte hash.
	//
	// This is sound: the SHAKE256-384 output is uniform random under
	// the random-oracle assumption, so its 32-byte prefix is also
	// uniform random — exactly what secp256k1 SignHash expects.
	sigC, err := sk.Classical.SignHash(mBound[:32])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHybridClassicalSign, err)
	}

	// PQ: ML-DSA-65 SignCtx with full 48-byte m_bound + domain
	// context. FIPS 204 hedged signing reads randomness from
	// randSource. SignCtx absorbs the full digest.
	sigPQ, err := sk.PQ.SignCtx(randSource, mBound, []byte(HybridSigDomain))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHybridPQSign, err)
	}

	return &HybridSignature{
		Classical: sigC,
		PQ:        sigPQ,
	}, nil
}

// HybridVerify checks a BBF-bound joint signature. Returns nil on
// success; returns a typed error identifying which component failed
// (or ErrHybridNilKey/ErrHybridNilSig for input errors).
//
// BOTH components MUST verify. This is the AND-mode binding: a
// signature where only one component verifies is a forgery (or a
// substitution attempt) and MUST be refused.
//
// The verification is order-independent: classical-first matches the
// natural reading of the construction, but a verifier could equally
// check PQ first. Either way, BOTH must pass.
func HybridVerify(pk *HybridPublicKey, msg []byte, sig *HybridSignature) error {
	if pk == nil || pk.Classical == nil || pk.PQ == nil {
		return ErrHybridNilKey
	}
	if sig == nil || len(sig.Classical) == 0 || len(sig.PQ) == 0 {
		return ErrHybridNilSig
	}

	mBound, err := boundDigest(pk, msg)
	if err != nil {
		return err
	}

	// Classical: secp256k1 VerifyHash over m_bound[:32]. Mirrors the
	// signing path's 32-byte prefix choice.
	if !pk.Classical.VerifyHash(mBound[:32], sig.Classical) {
		return ErrHybridClassicalVerify
	}

	// PQ: ML-DSA-65 VerifySignatureCtx over full m_bound + domain
	// context. Mirrors the signing-side SignCtx call.
	if !pk.PQ.VerifySignatureCtx(mBound, sig.PQ, []byte(HybridSigDomain)) {
		return ErrHybridPQVerify
	}

	return nil
}

// HybridPublicKeyBytes returns the canonical wire encoding of the
// joint public key:
//
//	left_encode(8·|pk_classical|) || pk_classical
//	left_encode(8·|pk_pq|)        || pk_pq
//
// This is the same framing m_bound uses for the joint pubkey, minus
// the domain prefix and msg. The encoding is unambiguous and can be
// reversed (each field's length is recoverable from its left_encode
// header).
//
// Used to compute a hybrid NodeID via the existing ids.NodeIDScheme
// derivation — the scheme produces NodeID = SHAKE256-384("NODE_ID_V1"
// || chainID || scheme_byte || pubkey)[:20], so passing the wire-form
// hybrid pubkey here yields a NodeID committed to BOTH components.
func HybridPublicKeyBytes(pk *HybridPublicKey) ([]byte, error) {
	if pk == nil || pk.Classical == nil || pk.PQ == nil {
		return nil, ErrHybridNilKey
	}
	pkClassical := pk.Classical.CompressedBytes()
	pkPQ := pk.PQ.Bytes()

	// Pre-size: header bytes for two left_encodes (<= 9 each) plus
	// the two field payloads. The actual headers are typically 2-3
	// bytes, but worst-case sizing keeps the allocation single.
	out := make([]byte, 0, 18+len(pkClassical)+len(pkPQ))
	out = append(out, leftEncode(uint64(len(pkClassical))*8)...)
	out = append(out, pkClassical...)
	out = append(out, leftEncode(uint64(len(pkPQ))*8)...)
	out = append(out, pkPQ...)
	return out, nil
}
