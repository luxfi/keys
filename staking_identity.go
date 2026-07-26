// Copyright (C) 2024-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// staking_identity.go — the portable, complete staking identity of one node,
// plus its deterministic wire codec.
//
// A StakingIdentity bundles BOTH ChainSecurityProfiles' materials:
//
//	classical : TLS cert/key (NodeID anchor + transport) + BLS signer (consensus)
//	strict-PQ : ML-DSA-65 (NodeID anchor + sign) + ML-KEM-768 (handshake KEM)
//
// It is the unit a node CUSTODIES in KMS so a restart or replacement pod
// recovers the SAME NodeID under whichever profile the chain runs. Two ways to
// obtain the same stable identity:
//
//	1. derive it   — StakingIdentityFromValidatorKey(DeriveValidatorFromMnemonic,
//	                 DeriveValidatorPQ). Nothing to persist; re-derivable from the
//	                 mnemonic. This is the canonical Lux "one seed, N paths" model.
//	2. custody it  — generate once, Marshal, store the blob in KMS, Unmarshal on
//	                 the next boot. For nodes that hold a unique, non-derived key.
//
// SEPARATION OF CONCERNS: this type owns ONLY (de)serialization — pure
// functions, no I/O, no KMS, no network. The KMS transport that carries a
// marshalled blob lives in the consumer (luxd staking-init), so luxfi/keys
// keeps NO edge to luxfi/kms. The module graph stays acyclic: kms → keys, never
// keys → kms. (kms/pkg/mnemonic already composes keys with the ZAP client on
// the far side of that edge.)
//
// INTEGRITY: Marshal appends a SHA-256 checksum over the framed body. This is a
// framing/corruption guard (truncation, bit-rot, wrong-blob) — NOT a keyed MAC
// and NOT confidentiality. The authenticated-encryption boundary is KMS itself
// (AES-256-GCM payload + ML-KEM-wrapped DEK, AAD-bound to path/name/env). The
// checksum is defense-in-depth on top of that, so a mangled blob is rejected
// rather than mis-parsed into a wrong (and unusable) NodeID.

package keys

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
)

// stakingIdentityMagic tags the wire format so a blob from another producer (or
// a raw mnemonic accidentally routed here) is rejected at byte 0.
var stakingIdentityMagic = []byte("LUXSTAKEID")

// stakingIdentityVersion is the only supported codec version. Bump on any wire
// change; Unmarshal refuses unknown versions rather than guessing. v2 adds the
// NodeLabel field (index 7) — an operator-supplied label bound INTO the
// integrity-checksummed blob so a stored custody identity is tied to one node
// and a second node pointed at the same KMS path detects the mismatch on load
// (equivocation tripwire; the primary control is server-side path-scoped write
// authz). Forward-only: there is no v1 fallback.
const stakingIdentityVersion byte = 2

// stakingIdentityFieldCount is the fixed number of length-prefixed fields.
const stakingIdentityFieldCount = 8

// maxStakingField caps any single field at 64 KiB. ML-DSA-65 private keys are
// ~4 KB and TLS PEM a few KB, so 64 KiB is generous; the cap turns a hostile or
// corrupt length prefix into a bounded rejection instead of a huge allocation.
const maxStakingField = 64 * 1024

// ErrStakingIdentityCodec is the base error for every malformed-blob rejection.
// Wrapped with a specific cause; match with errors.Is.
var ErrStakingIdentityCodec = errors.New("keys: staking identity codec")

// StakingIdentity is the complete staking identity of one node. Any field may
// be empty (a classical-only or strict-PQ-only custody); Marshal preserves
// exactly what is set and Unmarshal restores it byte-for-byte.
type StakingIdentity struct {
	// Classical.
	TLSCertPEM []byte // PEM-encoded staking certificate (public — NodeID anchor)
	TLSKeyPEM  []byte // PEM-encoded staking private key (SECRET)
	BLSSigner  []byte // raw BLS secret key bytes (SECRET)

	// Strict-PQ.
	MLDSAPriv []byte // ML-DSA-65 private key (SECRET)
	MLDSAPub  []byte // ML-DSA-65 public key (public — strict-PQ NodeID anchor)
	MLKEMPriv []byte // ML-KEM-768 private key (SECRET)
	MLKEMPub  []byte // ML-KEM-768 public key (public — handshake)

	// Custody binding. NodeLabel is an operator-supplied label (e.g. the
	// node's hostname or fleet index) bound into the blob so a CUSTODY load
	// can reject an identity minted for a DIFFERENT node — the equivocation
	// tripwire for two nodes accidentally sharing one KMS identity path.
	// Public, not secret; empty for DERIVE identities (which are re-derivable,
	// never stored, and so carry no shared-path risk). Preserved verbatim by
	// the codec.
	NodeLabel []byte
}

// fields returns the seven field slices in canonical, fixed order. The order is
// the wire order and MUST never be reordered without a version bump.
func (s *StakingIdentity) fields() [][]byte {
	return [][]byte{
		s.TLSCertPEM,
		s.TLSKeyPEM,
		s.BLSSigner,
		s.MLDSAPriv,
		s.MLDSAPub,
		s.MLKEMPriv,
		s.MLKEMPub,
		s.NodeLabel,
	}
}

// HasClassical reports whether the classical materials needed to run a
// classical-compat validator are present (TLS cert + key + BLS signer).
func (s *StakingIdentity) HasClassical() bool {
	return len(s.TLSCertPEM) > 0 && len(s.TLSKeyPEM) > 0 && len(s.BLSSigner) > 0
}

// HasStrictPQ reports whether the strict-PQ materials needed to run a strict-PQ
// validator are present (ML-DSA-65 pair + ML-KEM-768 pair).
func (s *StakingIdentity) HasStrictPQ() bool {
	return len(s.MLDSAPriv) > 0 && len(s.MLDSAPub) > 0 &&
		len(s.MLKEMPriv) > 0 && len(s.MLKEMPub) > 0
}

// Marshal serializes the identity into the canonical wire blob:
//
//	magic("LUXSTAKEID") || version(1) || fieldCount(1) ||
//	  { u32 len || bytes } × 8 (canonical order, NodeLabel last) ||
//	  sha256(everything above)          // 32-byte integrity tail
//
// Deterministic: the same StakingIdentity always marshals to identical bytes,
// so a save→load round-trip and a hash-compare are stable.
func (s *StakingIdentity) Marshal() ([]byte, error) {
	fields := s.fields()
	if len(fields) != stakingIdentityFieldCount {
		return nil, fmt.Errorf("%w: field count %d != %d",
			ErrStakingIdentityCodec, len(fields), stakingIdentityFieldCount)
	}
	body := make([]byte, 0, 64)
	body = append(body, stakingIdentityMagic...)
	body = append(body, stakingIdentityVersion, byte(stakingIdentityFieldCount))
	var lenBuf [4]byte
	for _, f := range fields {
		if len(f) > maxStakingField {
			return nil, fmt.Errorf("%w: field length %d exceeds cap %d",
				ErrStakingIdentityCodec, len(f), maxStakingField)
		}
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(f)))
		body = append(body, lenBuf[:]...)
		body = append(body, f...)
	}
	sum := sha256.Sum256(body)
	return append(body, sum[:]...), nil
}

// UnmarshalStakingIdentity parses a blob produced by Marshal, verifying the
// magic, version, field count, per-field length caps, and the trailing SHA-256
// checksum (constant-time compare) before returning any field. A checksum
// mismatch, truncation, trailing garbage, or oversize field is a hard error —
// the node fails closed rather than boot with a half-parsed identity.
func UnmarshalStakingIdentity(blob []byte) (*StakingIdentity, error) {
	if len(blob) < len(stakingIdentityMagic)+2+sha256.Size {
		return nil, fmt.Errorf("%w: blob too short (%d bytes)", ErrStakingIdentityCodec, len(blob))
	}
	// Split body || checksum and verify integrity FIRST (constant-time).
	body := blob[:len(blob)-sha256.Size]
	got := blob[len(blob)-sha256.Size:]
	want := sha256.Sum256(body)
	if subtle.ConstantTimeCompare(got, want[:]) != 1 {
		return nil, fmt.Errorf("%w: integrity checksum mismatch", ErrStakingIdentityCodec)
	}

	off := 0
	if subtle.ConstantTimeCompare(body[:len(stakingIdentityMagic)], stakingIdentityMagic) != 1 {
		return nil, fmt.Errorf("%w: bad magic", ErrStakingIdentityCodec)
	}
	off += len(stakingIdentityMagic)
	if body[off] != stakingIdentityVersion {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrStakingIdentityCodec, body[off])
	}
	off++
	if body[off] != byte(stakingIdentityFieldCount) {
		return nil, fmt.Errorf("%w: field count %d != %d", ErrStakingIdentityCodec, body[off], stakingIdentityFieldCount)
	}
	off++

	out := make([][]byte, stakingIdentityFieldCount)
	for i := 0; i < stakingIdentityFieldCount; i++ {
		if off+4 > len(body) {
			return nil, fmt.Errorf("%w: truncated length prefix (field %d)", ErrStakingIdentityCodec, i)
		}
		n := binary.BigEndian.Uint32(body[off : off+4])
		off += 4
		if n > maxStakingField {
			return nil, fmt.Errorf("%w: field %d length %d exceeds cap %d", ErrStakingIdentityCodec, i, n, maxStakingField)
		}
		if off+int(n) > len(body) {
			return nil, fmt.Errorf("%w: truncated field %d (need %d bytes)", ErrStakingIdentityCodec, i, n)
		}
		// Copy out of the caller's buffer so the returned identity owns its
		// memory (and the caller can wipe/reuse the input blob).
		out[i] = append([]byte(nil), body[off:off+int(n)]...)
		off += int(n)
	}
	if off != len(body) {
		return nil, fmt.Errorf("%w: %d trailing bytes after last field", ErrStakingIdentityCodec, len(body)-off)
	}

	return &StakingIdentity{
		TLSCertPEM: out[0],
		TLSKeyPEM:  out[1],
		BLSSigner:  out[2],
		MLDSAPriv:  out[3],
		MLDSAPub:   out[4],
		MLKEMPriv:  out[5],
		MLKEMPub:   out[6],
		NodeLabel:  out[7],
	}, nil
}

// Wipe zeroes every SECRET field in place (TLS key, BLS signer, ML-DSA private,
// ML-KEM private). Public materials are left intact — they are not sensitive
// and the caller may still need the NodeID anchors for logging. Idempotent;
// safe on nil.
func (s *StakingIdentity) Wipe() {
	if s == nil {
		return
	}
	zero(s.TLSKeyPEM)
	zero(s.BLSSigner)
	zero(s.MLDSAPriv)
	zero(s.MLKEMPriv)
	s.TLSKeyPEM = nil
	s.BLSSigner = nil
	s.MLDSAPriv = nil
	s.MLKEMPriv = nil
}

// StakingIdentityFromValidatorKey assembles a StakingIdentity from the classical
// ValidatorKey (DeriveValidatorFromMnemonic / GenerateValidatorKey) and, when
// non-nil, the strict-PQ PQValidatorKey (DeriveValidatorPQ). Pure — it copies
// the referenced key bytes; the sources may be wiped afterward.
func StakingIdentityFromValidatorKey(vk *ValidatorKey, pq *PQValidatorKey) *StakingIdentity {
	s := &StakingIdentity{}
	if vk != nil {
		s.TLSCertPEM = append([]byte(nil), vk.StakerCert...)
		s.TLSKeyPEM = append([]byte(nil), vk.StakerKey...)
		s.BLSSigner = append([]byte(nil), vk.BLSSecretKey...)
	}
	if pq != nil {
		s.MLDSAPriv = append([]byte(nil), pq.MLDSAPriv...)
		s.MLDSAPub = append([]byte(nil), pq.MLDSAPub...)
		s.MLKEMPriv = append([]byte(nil), pq.MLKEMPriv...)
		s.MLKEMPub = append([]byte(nil), pq.MLKEMPub...)
	}
	return s
}
