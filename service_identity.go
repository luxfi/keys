// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// service_identity.go — mnemonic-derived service identity for in-cluster auth.
//
// Every Lux-derived service (kms-operator, hanzo-paas, hanzo-base,
// hanzo-commerce, …) authenticates to its peers by producing a signed
// envelope. Identity is derived from a BIP-39 mnemonic plus a stable
// servicePath — same mnemonic + path → same NodeID byte-for-byte across
// pods, reboots, machines.
//
// Pure-function derivation:
//
//	seed       = BIP-39 PBKDF2(mnemonic, "")
//	master     = BIP-32 master(seed)
//	hardenedi  = master · m/44'/9000'/serviceIndex'/0'/0'
//	signing    = ML-DSA-65(seed = SHAKE256(hardened-key || "lux-svc-mldsa-v1"))
//	NodeID     = SHAKE256-384("NODE_ID_V1" || chainID || 0x42 || pub)[:20]
//
// 9000 is the SLIP-0044 coin-type for Lux P/X (same value the wallet
// uses for staking and platform-chain HD derivation — see ~/work/lux/wallet
// /apps/web/src/lib/derive.ts and ~/work/lux/cli/cmd/keycmd). 0x42 is the
// canonical ML-DSA-65 NodeID scheme byte from luxfi/ids — the same scheme
// validator NodeIDs use under strict-PQ.
//
// serviceIndex is BIP-32-hardened from servicePath:
//
//	serviceIndex = SHAKE256(servicePath)[:4] mod 2^31
//
// 31-bit space leaves the hardened-child top bit clear; collisions are
// astronomically unlikely for the few-hundred services any one cluster
// runs, but two distinct paths producing the same NodeID is a verifiable
// programmer error (NewServiceIdentity returns the same key — the caller
// chose colliding paths).
//
// Production:
//
//	bootstrap = keys.NewServiceIdentity(bootstrapMnemonic, "luxd/staking-bootstrap")
//	mnemonic  = keys.LoadMnemonic(ctx, kmsAddr, "main", "/mnemonic", bootstrap)
//	id, err   = keys.NewServiceIdentity(mnemonic, "hanzo/kms-operator")
//	if err != nil { … }
//	defer id.Wipe()
//	sig, err := id.Sign(envelope)
//
// Identity is exclusively a value type plus a pure-function constructor.
// It owns no I/O. The KMS/operator wires it to a `keys.LoadMnemonic` call;
// tests pass a known mnemonic and assert determinism.

package keys

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	mldsa "github.com/luxfi/crypto/mldsa"
	secp "github.com/luxfi/crypto/secp256k1"
	bip32 "github.com/luxfi/go-bip32"
	bip39 "github.com/luxfi/go-bip39"
	"github.com/luxfi/ids"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

// HybridClassicalLeafIndex is the BIP-32 leaf index for the secp256k1
// (classical) component of a hybrid validator identity. Pinned at 0 so
// it coincides with the existing ML-DSA-65-only service identity leaf
// — a hybrid identity is a superset, never a different tree position.
const HybridClassicalLeafIndex uint32 = 0

// HybridPQLeafIndex is the BIP-32 leaf index for the ML-DSA-65 (PQ)
// component of a hybrid validator identity. Pinned at 1 so the PQ key
// derives at a sibling sub-path m/44'/9000'/serviceIndex'/0'/1' —
// distinct from the classical leaf and from the legacy ML-DSA-only
// leaf at index 0. The legacy path is preserved exactly; the new PQ
// leaf is purely additive.
const HybridPQLeafIndex uint32 = 1

// HybridClassicalDomain is the SHAKE256 customisation string for the
// secp256k1 component's scalar derivation. Pinned at v1.
const HybridClassicalDomain = "lux-hybrid-classical-secp256k1-v1"

// HybridPQDomain is the SHAKE256 customisation string for the ML-DSA-65
// component's seed derivation. Pinned at v1. Distinct from
// serviceIdentityDomain so a hybrid identity's PQ key is NEVER the same
// byte-string as the legacy ML-DSA-only identity at the same path —
// the two derivations are cryptographically separated.
const HybridPQDomain = "lux-hybrid-pq-mldsa65-v1"

// CoinTypeUTXO is the SLIP-0044 coin_type for the UTXO-layout DAG-like
// chains — X-Chain (AVM) + P-Chain. Service identities derive under
// m/44'/9000'/<serviceIndex>'/0'/0' so they share the coin-type tree
// with X/P staking keys but never collide with account-zero derivations
// (serviceIndex is hashed from servicePath, never 0 in practice for
// any well-formed path).
const CoinTypeUTXO = 9000

// BIP44Purpose is the BIP-44 purpose constant. Pinned to 44 even though
// service identities don't carry funds — staying inside the BIP-44
// purpose tree keeps the same mnemonic interoperable with the Lux
// wallet's existing derivation tree.
const BIP44Purpose = 44

// serviceIdentityDomain is the SHAKE256 customisation string for the
// ML-DSA-65 seed derivation. Pinned at v1; bumping invalidates every
// prior service NodeID, which is the correct behaviour for a hardfork
// of the derivation encoding.
const serviceIdentityDomain = "lux-svc-mldsa-v1"

// EnvelopeDomain is the customisation prefix mixed into every envelope
// signature so signatures from one envelope shape (a KMS opcode call)
// cannot be replayed against another (e.g. a future RPC over the same
// wire). Pinned at v1.
const EnvelopeDomain = "lux-svc-envelope-v1"

// ServiceChainID is the well-known chain identifier under which all
// service NodeIDs are derived. Distinct from any L1 chain ID so a
// service NodeID never accidentally validates against a chain's
// validator-set commitment. Set once and never bumped — the empty
// "service" string is the canonical seed.
//
// Use the helper ServiceChainIDForCluster if a deployment ever needs
// per-cluster service NodeID separation. The default (empty seed) is
// what every Hanzo cluster uses today.
var ServiceChainID = mustHashChainID("lux-service-identity")

// ErrInvalidServicePath is returned when the servicePath argument is
// empty after trim. Empty paths would collapse every service to the
// same NodeID, which would silently mask configuration drift.
var ErrInvalidServicePath = errors.New("keys: service path is required")

// ServiceIdentity binds a mnemonic-derived ML-DSA-65 signing key to
// its canonical NodeID. The struct owns the private key bytes; call
// Wipe() when done.
//
// Safe for concurrent use after construction — every field is read-only
// after NewServiceIdentity returns. Wipe is the only mutating method
// and the caller serialises it (typically a single defer).
type ServiceIdentity struct {
	// ServicePath is the canonical path string (verbatim) used to derive
	// the BIP-32 hardened index. Stored for diagnostics; the
	// authoritative input is the derived NodeID.
	ServicePath string

	// NodeID is the 20-byte canonical NodeID derived under
	// NodeIDSchemeMLDSA65. Map-key safe.
	NodeID ids.NodeID

	// TypedNodeID is the wire-form NodeID (scheme byte || NodeID).
	// Travels in envelope headers so the receiver knows which verifier
	// to dispatch.
	TypedNodeID ids.TypedNodeID

	// FullDigest is the 48-byte SHAKE256-384 commitment to the
	// identity. Bound into envelope signatures to prevent cross-scheme
	// confusion attacks.
	FullDigest ids.FullDigest

	// PublicKey is the ML-DSA-65 public key bytes.
	PublicKey []byte

	// privateKey is the ML-DSA-65 private key bytes. Never exposed via
	// a getter; the only legal use is internal Sign().
	privateKey []byte
}

// NewServiceIdentity is the canonical constructor. mnemonic must be a
// valid BIP-39 phrase; servicePath must be non-empty. Returns the
// derived ServiceIdentity ready to Sign().
//
// Pure function: given the same (mnemonic, servicePath) you get the
// same NodeID, byte-for-byte. No I/O, no randomness, no clock reads.
func NewServiceIdentity(mnemonic, servicePath string) (*ServiceIdentity, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, errors.New("keys: invalid BIP-39 mnemonic")
	}
	servicePath = trimServicePath(servicePath)
	if servicePath == "" {
		return nil, ErrInvalidServicePath
	}

	seed := bip39.NewSeed(mnemonic, "")
	master, err := bip32.NewMasterKey(seed)
	if err != nil {
		return nil, fmt.Errorf("keys: bip32 master: %w", err)
	}

	// m/44' / 9000' / serviceIndex' / 0' / 0'
	purpose, err := master.NewChildKey(bip32.FirstHardenedChild + BIP44Purpose)
	if err != nil {
		return nil, fmt.Errorf("keys: derive purpose: %w", err)
	}
	coin, err := purpose.NewChildKey(bip32.FirstHardenedChild + CoinTypeUTXO)
	if err != nil {
		return nil, fmt.Errorf("keys: derive coin: %w", err)
	}
	account, err := coin.NewChildKey(bip32.FirstHardenedChild + serviceIndex(servicePath))
	if err != nil {
		return nil, fmt.Errorf("keys: derive account: %w", err)
	}
	role, err := account.NewChildKey(bip32.FirstHardenedChild + 0)
	if err != nil {
		return nil, fmt.Errorf("keys: derive role: %w", err)
	}
	leaf, err := role.NewChildKey(bip32.FirstHardenedChild + 0)
	if err != nil {
		return nil, fmt.Errorf("keys: derive leaf: %w", err)
	}

	// ML-DSA-65 keygen is deterministic in its randomness stream: the
	// same HKDF-Expand output drives circl's keygen to the same
	// keypair byte-for-byte. We seed HKDF with the hardened BIP-32
	// key plus a domain string + servicePath; if an attacker ever
	// recovered the HKDF seed they still need the mnemonic to walk
	// back the BIP-32 chain.
	mldsaSeed := mldsaSeedFor(leaf.Key, servicePath)
	reader := hkdf.New(sha3.New256, mldsaSeed, nil, []byte(serviceIdentityDomain))
	priv, err := mldsa.GenerateKey(reader, mldsa.MLDSA65)
	if err != nil {
		return nil, fmt.Errorf("keys: mldsa keygen: %w", err)
	}
	pubBytes := priv.PublicKey.Bytes()
	privBytes := append([]byte(nil), priv.Bytes()...)

	scheme := ids.NodeIDSchemeMLDSA65
	typed, full, err := ids.TypedNodeIDFromMLDSA(scheme, ServiceChainID, pubBytes)
	if err != nil {
		return nil, fmt.Errorf("keys: derive node id: %w", err)
	}

	return &ServiceIdentity{
		ServicePath: servicePath,
		NodeID:      typed.NodeID,
		TypedNodeID: typed,
		FullDigest:  full,
		PublicKey:   pubBytes,
		privateKey:  privBytes,
	}, nil
}

// Sign produces a deterministic ML-DSA-65 signature over the envelope
// digest. The caller is responsible for serialising the envelope into
// canonical bytes before calling Sign — see SignEnvelope for the
// canonical (method, path, payload, timestamp, nonce) shape.
//
// The signed bytes are the SHAKE256 digest of:
//
//	left_encode(|domain|·8) || EnvelopeDomain ||
//	left_encode(|full_digest|·8) || FullDigest ||
//	left_encode(|envelope|·8) || envelope
//
// Binding the FullDigest into the prehash means a verifier always
// rejects an envelope signed by a different identity — even a key with
// the same NodeID prefix.
func (s *ServiceIdentity) Sign(envelope []byte) ([]byte, error) {
	if s == nil || len(s.privateKey) == 0 {
		return nil, errors.New("keys: service identity is empty (wiped?)")
	}
	digest := envelopeDigest(s.FullDigest, envelope)
	priv, err := mldsa.PrivateKeyFromBytes(mldsa.MLDSA65, s.privateKey)
	if err != nil {
		return nil, fmt.Errorf("keys: parse private key: %w", err)
	}
	// FIPS 204 §5.2 hedged sign — circl reads its own randomness
	// internally. The EnvelopeDomain context byte string is bound
	// into the signature so a cross-protocol replay of the same key
	// against a different envelope shape rejects.
	sig, err := priv.SignCtx(nil, digest, []byte(EnvelopeDomain))
	if err != nil {
		return nil, fmt.Errorf("keys: sign: %w", err)
	}
	return sig, nil
}

// VerifyServiceEnvelope verifies an ML-DSA-65 signature against an
// envelope produced by Sign. The caller supplies the signer's
// FullDigest (the 48-byte commitment carried in the envelope header)
// and public key bytes — both authenticated by the consensus layer.
//
// Pure function: no I/O, no time dependency.
func VerifyServiceEnvelope(pubKey []byte, fullDigest ids.FullDigest, envelope, sig []byte) error {
	if len(pubKey) == 0 {
		return errors.New("keys: empty public key")
	}
	if len(sig) == 0 {
		return errors.New("keys: empty signature")
	}
	pub, err := mldsa.PublicKeyFromBytes(pubKey, mldsa.MLDSA65)
	if err != nil {
		return fmt.Errorf("keys: parse public key: %w", err)
	}
	digest := envelopeDigest(fullDigest, envelope)
	if !pub.VerifySignatureCtx(digest, sig, []byte(EnvelopeDomain)) {
		return errors.New("keys: envelope signature verification failed")
	}
	return nil
}

// Wipe zeroes the private key in place. Idempotent. Safe to call from
// a defer.
func (s *ServiceIdentity) Wipe() {
	if s == nil {
		return
	}
	for i := range s.privateKey {
		s.privateKey[i] = 0
	}
	s.privateKey = nil
}

// envelopeDigest computes the canonical SHAKE256 digest a signature
// binds. Exported so a hand-rolled verifier (the kmsd consensus_auth
// path) can call the same helper.
func envelopeDigest(fullDigest ids.FullDigest, envelope []byte) []byte {
	h := sha3.NewShake256()
	_, _ = h.Write(leftEncode(uint64(len(EnvelopeDomain)) * 8))
	_, _ = h.Write([]byte(EnvelopeDomain))
	_, _ = h.Write(leftEncode(uint64(ids.FullDigestLen) * 8))
	_, _ = h.Write(fullDigest[:])
	_, _ = h.Write(leftEncode(uint64(len(envelope)) * 8))
	_, _ = h.Write(envelope)
	out := make([]byte, 32)
	_, _ = h.Read(out)
	return out
}

// mldsaSeedFor returns the 32-byte deterministic seed for ML-DSA-65
// key generation. SHAKE256 absorbs the BIP-32 hardened child key, the
// domain string, and the servicePath so the seed is unique per
// (mnemonic, path) tuple.
func mldsaSeedFor(hardenedKey []byte, servicePath string) []byte {
	h := sha3.NewShake256()
	_, _ = h.Write(leftEncode(uint64(len(serviceIdentityDomain)) * 8))
	_, _ = h.Write([]byte(serviceIdentityDomain))
	_, _ = h.Write(leftEncode(uint64(len(hardenedKey)) * 8))
	_, _ = h.Write(hardenedKey)
	_, _ = h.Write(leftEncode(uint64(len(servicePath)) * 8))
	_, _ = h.Write([]byte(servicePath))
	out := make([]byte, 32)
	_, _ = h.Read(out)
	return out
}

// serviceIndex hashes a servicePath into a hardened-safe BIP-32 child
// index. The top bit is masked off so adding bip32.FirstHardenedChild
// in the caller stays inside the hardened space without overflowing.
func serviceIndex(servicePath string) uint32 {
	sum := sha256.Sum256([]byte(servicePath))
	v := binary.BigEndian.Uint32(sum[:4])
	return v & 0x7FFFFFFF
}

// trimServicePath collapses whitespace and leading/trailing slashes
// without rewriting embedded slashes. Empty input returns "".
func trimServicePath(p string) string {
	// strip ASCII whitespace
	out := make([]byte, 0, len(p))
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		out = append(out, c)
	}
	// trim leading/trailing '/'
	for len(out) > 0 && out[0] == '/' {
		out = out[1:]
	}
	for len(out) > 0 && out[len(out)-1] == '/' {
		out = out[:len(out)-1]
	}
	return string(out)
}

// mustHashChainID seeds the package-level ServiceChainID. Panics on
// the impossible (sha256 always succeeds); the panic surfaces a
// programmer error at init time rather than a runtime nil.
func mustHashChainID(seed string) ids.ID {
	sum := sha256.Sum256([]byte(seed))
	var id ids.ID
	copy(id[:], sum[:])
	return id
}

// leftEncode is the SP 800-185 §2.3.1 left_encode operation. Kept
// local so service_identity.go has no cross-package dependency on
// luxfi/ids's private helpers — same byte-for-byte algorithm.
func leftEncode(x uint64) []byte {
	if x == 0 {
		return []byte{0x01, 0x00}
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], x)
	i := 0
	for i < 7 && buf[i] == 0 {
		i++
	}
	out := make([]byte, 0, 9-i)
	out = append(out, byte(8-i))
	out = append(out, buf[i:]...)
	return out
}

// ServiceChainIDForCluster is a future hook for per-cluster NodeID
// separation. Today every Hanzo cluster shares ServiceChainID; if a
// future deployment ever needs to isolate two clusters' NodeID spaces
// (e.g. lux-mainnet vs hanzo-prod), the operator can override
// ServiceChainID at boot via this helper. Pure function — no global
// state mutated on call.
func ServiceChainIDForCluster(clusterSeed string) ids.ID {
	if clusterSeed == "" {
		return ServiceChainID
	}
	return mustHashChainID("lux-service-identity:" + clusterSeed)
}

// HybridIdentity binds a mnemonic-derived BBF-bound hybrid signing key
// (secp256k1 + ML-DSA-65) to its canonical NodeID. The struct owns the
// joint private key; call Wipe() when done.
//
// The NodeID is committed to the wire-form joint pubkey via the
// existing ids.NodeIDSchemeMLDSA65 derivation — chosen because the
// PQ component is the binding primitive (an adversary that holds only
// the classical key cannot mint a NodeID's matching FullDigest). Per
// cryptographer review the single-SHAKE-256-384 derivation is sound;
// no BTC-style double-hash is added.
type HybridIdentity struct {
	// ServicePath is the canonical path string (verbatim) used to
	// derive both hybrid components. Stored for diagnostics.
	ServicePath string

	// NodeID is the 20-byte canonical NodeID derived under
	// NodeIDSchemeMLDSA65 over the wire-form hybrid public key.
	NodeID ids.NodeID

	// TypedNodeID is the wire-form NodeID (scheme byte || NodeID).
	TypedNodeID ids.TypedNodeID

	// FullDigest is the 48-byte SHAKE256-384 commitment to the
	// hybrid identity. Bound into envelope signatures.
	FullDigest ids.FullDigest

	// PublicKey is the joint public key value. Both components are
	// always populated.
	PublicKey *HybridPublicKey

	// PublicKeyBytes is the canonical wire encoding of the joint
	// pubkey — useful for logging, storage, and on-chain commitment.
	// Same value HybridPublicKeyBytes(PublicKey) returns.
	PublicKeyBytes []byte

	// privateKey is the joint signing key. Never exposed via a
	// getter; the only legal use is internal Sign().
	privateKey *HybridPrivateKey
}

// DeriveHybridIdentity is the canonical constructor for a BBF-bound
// hybrid validator identity. mnemonic must be a valid BIP-39 phrase;
// servicePath must be non-empty. Returns the derived HybridIdentity
// ready to Sign().
//
// Derivation tree:
//
//	classical: m/44' / 9000' / serviceIndex' / 0' / 0'   (secp256k1)
//	pq:        m/44' / 9000' / serviceIndex' / 0' / 1'   (ML-DSA-65)
//
// The two leaves share the same hardened branches up to the role
// node; the only branch that distinguishes them is the leaf index
// (0 vs 1). Both leaves are hardened. The classical leaf at index 0
// COINCIDES with the legacy ML-DSA-only service identity path — this
// is intentional: a hybrid identity is a superset that adds a PQ
// component, never a different tree position. The classical leaf is
// then KDF-mixed with HybridClassicalDomain so the secp256k1 scalar
// is cryptographically separated from any ML-DSA-only seed at the
// same BIP-32 leaf — they share the leaf but not the seed.
//
// Pure function: given the same (mnemonic, servicePath) you get the
// same HybridIdentity, byte-for-byte. No I/O, no randomness, no clock
// reads.
func DeriveHybridIdentity(mnemonic, servicePath string) (*HybridIdentity, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, errors.New("keys: invalid BIP-39 mnemonic")
	}
	servicePath = trimServicePath(servicePath)
	if servicePath == "" {
		return nil, ErrInvalidServicePath
	}

	seed := bip39.NewSeed(mnemonic, "")
	master, err := bip32.NewMasterKey(seed)
	if err != nil {
		return nil, fmt.Errorf("keys: bip32 master: %w", err)
	}

	// Walk to the shared role node: m/44'/9000'/serviceIndex'/0'.
	purpose, err := master.NewChildKey(bip32.FirstHardenedChild + BIP44Purpose)
	if err != nil {
		return nil, fmt.Errorf("keys: derive purpose: %w", err)
	}
	coin, err := purpose.NewChildKey(bip32.FirstHardenedChild + CoinTypeUTXO)
	if err != nil {
		return nil, fmt.Errorf("keys: derive coin: %w", err)
	}
	account, err := coin.NewChildKey(bip32.FirstHardenedChild + serviceIndex(servicePath))
	if err != nil {
		return nil, fmt.Errorf("keys: derive account: %w", err)
	}
	role, err := account.NewChildKey(bip32.FirstHardenedChild + 0)
	if err != nil {
		return nil, fmt.Errorf("keys: derive role: %w", err)
	}

	// Classical leaf: m/44'/9000'/serviceIndex'/0'/0' (hardened).
	classicalLeaf, err := role.NewChildKey(bip32.FirstHardenedChild + HybridClassicalLeafIndex)
	if err != nil {
		return nil, fmt.Errorf("keys: derive classical leaf: %w", err)
	}
	classicalKey, err := classicalScalarFor(classicalLeaf.Key, servicePath)
	if err != nil {
		return nil, fmt.Errorf("keys: classical keygen: %w", err)
	}

	// PQ leaf: m/44'/9000'/serviceIndex'/0'/1' (hardened).
	pqLeaf, err := role.NewChildKey(bip32.FirstHardenedChild + HybridPQLeafIndex)
	if err != nil {
		return nil, fmt.Errorf("keys: derive pq leaf: %w", err)
	}
	pqKey, err := pqKeyFor(pqLeaf.Key, servicePath)
	if err != nil {
		return nil, fmt.Errorf("keys: pq keygen: %w", err)
	}

	sk := &HybridPrivateKey{
		Classical: classicalKey,
		PQ:        pqKey,
	}
	pk := sk.Public()
	pkBytes, err := HybridPublicKeyBytes(pk)
	if err != nil {
		return nil, fmt.Errorf("keys: marshal hybrid pubkey: %w", err)
	}

	// NodeID derivation: SHAKE256-384("NODE_ID_V1" || ServiceChainID
	// || 0x42 || wire-form hybrid pubkey)[:20]. The 0x42 scheme byte
	// matches the existing ML-DSA-65 scheme — the FullDigest is bound
	// to the WHOLE hybrid pubkey (both components) so a hybrid NodeID
	// is never the same as either component's NodeID-on-its-own.
	scheme := ids.NodeIDSchemeMLDSA65
	typed, full, err := ids.TypedNodeIDFromMLDSA(scheme, ServiceChainID, pkBytes)
	if err != nil {
		return nil, fmt.Errorf("keys: derive node id: %w", err)
	}

	return &HybridIdentity{
		ServicePath:    servicePath,
		NodeID:         typed.NodeID,
		TypedNodeID:    typed,
		FullDigest:     full,
		PublicKey:      pk,
		PublicKeyBytes: pkBytes,
		privateKey:     sk,
	}, nil
}

// Sign produces a BBF-bound joint signature over msg. Delegates to
// HybridSign — the identity owns the joint private key.
func (h *HybridIdentity) Sign(msg []byte) (*HybridSignature, error) {
	if h == nil || h.privateKey == nil {
		return nil, errors.New("keys: hybrid identity is empty (wiped?)")
	}
	// nil randSource → crypto/rand inside HybridSign.
	return HybridSign(h.privateKey, msg, nil)
}

// Wipe zeroes the joint private key in place. Idempotent. Safe to call
// from a defer on a nil receiver.
func (h *HybridIdentity) Wipe() {
	if h == nil {
		return
	}
	if h.privateKey != nil {
		h.privateKey.Wipe()
		h.privateKey = nil
	}
}

// classicalScalarFor returns a deterministic secp256k1 private key
// derived from a BIP-32 hardened leaf key + servicePath. SHAKE256
// absorbs the leaf key, the HybridClassicalDomain string, and the
// servicePath; the resulting 32-byte digest is reduced mod the
// secp256k1 group order by secp.ToPrivateKey, which rejects 0 and
// scalars >= n.
//
// Pure function: same (leafKey, servicePath) → same private key.
func classicalScalarFor(leafKey []byte, servicePath string) (*secp.PrivateKey, error) {
	h := sha3.NewShake256()
	_, _ = h.Write(leftEncode(uint64(len(HybridClassicalDomain)) * 8))
	_, _ = h.Write([]byte(HybridClassicalDomain))
	_, _ = h.Write(leftEncode(uint64(len(leafKey)) * 8))
	_, _ = h.Write(leafKey)
	_, _ = h.Write(leftEncode(uint64(len(servicePath)) * 8))
	_, _ = h.Write([]byte(servicePath))

	// secp256k1 group order n ≈ 2^256 - 2^32 - 977. The probability
	// that a uniform 32-byte sample is >= n is ~2^-128 — astronomical.
	// secp.ToPrivateKey rejects >= n and == 0; the loop below
	// re-samples by extending the SHAKE squeeze. In practice the loop
	// body runs exactly once for every well-formed input.
	for {
		var scalar [32]byte
		_, _ = h.Read(scalar[:])
		priv, err := secp.ToPrivateKey(scalar[:])
		if err == nil {
			return priv, nil
		}
		// Loop: SHAKE continues squeezing fresh bytes — this is the
		// canonical resample idiom for rejection-sampled scalars.
	}
}

// pqKeyFor returns a deterministic ML-DSA-65 private key derived from
// a BIP-32 hardened leaf key + servicePath. The PQ derivation mirrors
// the ML-DSA-only service identity: HKDF-Expand seeds circl's keygen
// to the same keypair byte-for-byte. The HybridPQDomain string is
// distinct from serviceIdentityDomain so a hybrid identity's PQ key
// is NEVER the same byte-string as a legacy ML-DSA-only identity at
// the same leaf.
//
// Pure function: same (leafKey, servicePath) → same private key.
func pqKeyFor(leafKey []byte, servicePath string) (*mldsa.PrivateKey, error) {
	h := sha3.NewShake256()
	_, _ = h.Write(leftEncode(uint64(len(HybridPQDomain)) * 8))
	_, _ = h.Write([]byte(HybridPQDomain))
	_, _ = h.Write(leftEncode(uint64(len(leafKey)) * 8))
	_, _ = h.Write(leafKey)
	_, _ = h.Write(leftEncode(uint64(len(servicePath)) * 8))
	_, _ = h.Write([]byte(servicePath))
	seed := make([]byte, 32)
	_, _ = h.Read(seed)

	reader := hkdf.New(sha3.New256, seed, nil, []byte(HybridPQDomain))
	return mldsa.GenerateKey(reader, mldsa.MLDSA65)
}
