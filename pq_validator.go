// Copyright (C) 2024-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// pq_validator.go — deterministic strict-PQ validator identity derivation.
//
// A strict-PQ validator's identity is two FIPS-standard keys:
//
//	ML-DSA-65 (FIPS 204)  the staking-signature key that ANCHORS the NodeID
//	                      (ids.NodeIDSchemeMLDSA65.DeriveMLDSA over its pubkey)
//	ML-KEM-768 (FIPS 203) the handshake KEM key peers encapsulate to
//
// Both are derived DETERMINISTICALLY from the one BIP-39 deploy mnemonic and
// a validator index, exactly like the classical TLS+BLS keys that
// DeriveValidatorFromMnemonic produces. Determinism is the whole point: a
// restarted or replacement pod re-derives the SAME NodeID with nothing
// custodied on disk. Without it, staking/pq.go's mldsa.GenerateKey(rand.Reader,
// …) mints a fresh key — hence a DIFFERENT validator — on every boot.
//
// Derivation tree (coin type 60, the same tree DeriveValidatorFromMnemonic
// funds — accounts 0=EC, 1=TLS, 2=BLS are taken; the strict-PQ keys take the
// next free accounts):
//
//	ML-DSA-65 : m/44'/60'/3'/0/<index>
//	ML-KEM-768: m/44'/60'/4'/0/<index>
//
// The 32-byte BIP-32 leaf key is domain-separated and HKDF-expanded into the
// deterministic keygen stream — the identical idiom service_identity.go uses
// (cryptographer-reviewed: same HKDF-Expand output drives keygen to the same
// keypair byte-for-byte). The domain strings below are DISTINCT from every
// other derivation string in this package so a validator staking key is never
// the same byte-string as a service-auth key, even at a colliding BIP-32 leaf.
//
// ENTROPY CEILING (I1). These are FIPS 204/203 keys at NIST Level 3, but when
// derived here their effective root entropy is bounded by the BIP-39 mnemonic
// that seeds the whole tree. A 12-word (128-bit) deploy mnemonic caps the
// unpredictability of every derived ML-DSA-65 / ML-KEM-768 key at 128 bits: an
// adversary who can brute-force the 2^128 mnemonic space recovers ALL derived
// validator keys, regardless of the primitives' nominal ~192-bit strength. The
// 128-bit floor is acceptable for the classical-adversary threat model, but a
// deployment that wants the PQ keys' full nominal strength as its root-secret
// floor must seed the tree from a 24-word (256-bit) mnemonic. GenerateValidatorPQ
// (CSPRNG) has no such ceiling — its keys carry the primitives' full entropy.

package keys

import (
	"crypto/rand"
	"errors"
	"fmt"

	mldsa "github.com/luxfi/crypto/mldsa"
	mlkem "github.com/luxfi/crypto/mlkem"
	"github.com/luxfi/ids"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

// BIP-44 account indices for the strict-PQ validator keys. Chosen to sit
// immediately after the classical accounts (0=EC, 1=TLS, 2=BLS) in the same
// coin-type-60 tree so one mnemonic covers a validator's whole identity.
const (
	pqMLDSAAccount uint32 = 3
	pqMLKEMAccount uint32 = 4
)

// Domain-separation strings for the deterministic keygen seeds. Pinned at v1;
// bumping either invalidates every strict-PQ NodeID derived under it (a
// hardfork of the derivation encoding — the correct behaviour for a change).
// DISTINCT from serviceIdentityDomain / HybridPQDomain so a validator key and
// a service-auth key derived from the same mnemonic never coincide.
const (
	validatorMLDSADomain = "lux-validator-mldsa65-v1"
	validatorMLKEMDomain = "lux-validator-mlkem768-v1"
)

// ErrInvalidAccountIndex is returned when the validator index is out of the
// supported range. The cap mirrors DeriveValidatorsFromMnemonic's 1..100
// convention: a validator index far above the plausible fleet size is almost
// always a misconfiguration, and refusing it early beats silently deriving an
// unexpected NodeID.
var ErrInvalidAccountIndex = errors.New("keys: validator account index out of range (0..9999)")

// maxValidatorIndex bounds the non-hardened BIP-32 leaf index. Generous
// (10k validators) but finite — a uint32 typo (e.g. reading an address as an
// index) is caught rather than pointing the node at a silent, wrong NodeID.
const maxValidatorIndex uint32 = 9999

// PQValidatorKey is the strict-PQ staking identity material for one validator,
// derived deterministically from a BIP-39 mnemonic. The private fields hold
// live key material — call Wipe() when the derived node.StakingConfig no longer
// needs them.
type PQValidatorKey struct {
	// MLDSAPriv / MLDSAPub — FIPS 204 ML-DSA-65. MLDSAPub is the NodeID anchor
	// under ids.NodeIDSchemeMLDSA65; MLDSAPriv signs blocks/handshakes.
	MLDSAPriv []byte
	MLDSAPub  []byte

	// MLKEMPriv / MLKEMPub — FIPS 203 ML-KEM-768. MLKEMPub is published in the
	// validator-set entry so peers encapsulate to it; MLKEMPriv stays local.
	MLKEMPriv []byte
	MLKEMPub  []byte
}

// DeriveValidatorPQ derives the strict-PQ staking identity (ML-DSA-65 +
// ML-KEM-768) for a validator at accountIndex from a BIP-39 mnemonic.
//
// Pure function: given the same (mnemonic, accountIndex) it returns the same
// keys, byte-for-byte, on every call and every machine. No randomness, no I/O,
// no clock reads. This is what makes a strict-PQ NodeID stable across restarts
// without custody.
func DeriveValidatorPQ(mnemonic string, accountIndex uint32) (*PQValidatorKey, error) {
	if accountIndex > maxValidatorIndex {
		return nil, ErrInvalidAccountIndex
	}
	// deriveMnemonicKeyForPath validates the mnemonic (BIP-39) internally and
	// walks m/44'/60'/<account>'/0/<index>.
	mldsaLeaf, err := deriveMnemonicKeyForPath(mnemonic, pqMLDSAAccount, accountIndex)
	if err != nil {
		return nil, fmt.Errorf("keys: derive ML-DSA leaf: %w", err)
	}
	defer zero(mldsaLeaf)
	mlkemLeaf, err := deriveMnemonicKeyForPath(mnemonic, pqMLKEMAccount, accountIndex)
	if err != nil {
		return nil, fmt.Errorf("keys: derive ML-KEM leaf: %w", err)
	}
	defer zero(mlkemLeaf)

	// ML-DSA-65: HKDF-expand the domain-separated leaf into the FIPS 204 keygen
	// stream. Deterministic — same seed → same keypair.
	mldsaReader := hkdf.New(sha3.New256, pqSeed(mldsaLeaf, validatorMLDSADomain), nil, []byte(validatorMLDSADomain))
	mldsaPriv, err := mldsa.GenerateKey(mldsaReader, mldsa.MLDSA65)
	if err != nil {
		return nil, fmt.Errorf("keys: ML-DSA-65 keygen: %w", err)
	}

	// ML-KEM-768: same deterministic construction, distinct domain.
	mlkemReader := hkdf.New(sha3.New256, pqSeed(mlkemLeaf, validatorMLKEMDomain), nil, []byte(validatorMLKEMDomain))
	mlkemPub, mlkemPriv, err := mlkem.GenerateKeyPair(mlkemReader, mlkem.MLKEM768)
	if err != nil {
		return nil, fmt.Errorf("keys: ML-KEM-768 keygen: %w", err)
	}

	return &PQValidatorKey{
		MLDSAPriv: append([]byte(nil), mldsaPriv.Bytes()...),
		MLDSAPub:  append([]byte(nil), mldsaPriv.PublicKey.Bytes()...),
		MLKEMPriv: append([]byte(nil), mlkemPriv.Bytes()...),
		MLKEMPub:  append([]byte(nil), mlkemPub.Bytes()...),
	}, nil
}

// GenerateValidatorPQ mints a FRESH strict-PQ validator identity from the system
// CSPRNG (crypto/rand). It is the orthogonal sibling of DeriveValidatorPQ — use
// it for the custody model, where a node holds a UNIQUE, non-derived identity
// that is then persisted to KMS (StakingIdentity.Marshal → SaveAt). A fresh key
// has NO stable NodeID across restarts on its own; custody in KMS is what makes
// it stable. Prefer DeriveValidatorPQ (one seed, N paths) unless a per-node
// unique key is specifically required.
func GenerateValidatorPQ() (*PQValidatorKey, error) {
	mldsaPriv, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	if err != nil {
		return nil, fmt.Errorf("keys: ML-DSA-65 keygen: %w", err)
	}
	mlkemPub, mlkemPriv, err := mlkem.GenerateKeyPair(rand.Reader, mlkem.MLKEM768)
	if err != nil {
		return nil, fmt.Errorf("keys: ML-KEM-768 keygen: %w", err)
	}
	return &PQValidatorKey{
		MLDSAPriv: append([]byte(nil), mldsaPriv.Bytes()...),
		MLDSAPub:  append([]byte(nil), mldsaPriv.PublicKey.Bytes()...),
		MLKEMPriv: append([]byte(nil), mlkemPriv.Bytes()...),
		MLKEMPub:  append([]byte(nil), mlkemPub.Bytes()...),
	}, nil
}

// StrictPQNodeID returns the NodeID this key anchors, under the SAME derivation
// the node applies at boot (node.StakingConfig.DeriveNodeID):
// ids.NodeIDSchemeMLDSA65.DeriveMLDSA(chainID, MLDSAPub). Pass ids.Empty for
// the primary-network validator identity (the node uses ids.Empty).
func (k *PQValidatorKey) StrictPQNodeID(chainID ids.ID) (ids.NodeID, error) {
	if k == nil || len(k.MLDSAPub) == 0 {
		return ids.EmptyNodeID, errors.New("keys: PQ validator key has no ML-DSA public key")
	}
	id, _, err := ids.NodeIDSchemeMLDSA65.DeriveMLDSA(chainID, k.MLDSAPub)
	return id, err
}

// Wipe zeroes the private key material in place. Idempotent; safe on nil.
func (k *PQValidatorKey) Wipe() {
	if k == nil {
		return
	}
	zero(k.MLDSAPriv)
	zero(k.MLKEMPriv)
	k.MLDSAPriv = nil
	k.MLKEMPriv = nil
}

// pqSeed compresses a BIP-32 leaf key into a 32-byte deterministic seed under
// a domain string. SHAKE256 with SP 800-185 left_encode framing on each field
// so the (domain, leaf) concatenation is unambiguous.
func pqSeed(leafKey []byte, domain string) []byte {
	h := sha3.NewShake256()
	_, _ = h.Write(leftEncode(uint64(len(domain)) * 8))
	_, _ = h.Write([]byte(domain))
	_, _ = h.Write(leftEncode(uint64(len(leafKey)) * 8))
	_, _ = h.Write(leafKey)
	out := make([]byte, 32)
	_, _ = h.Read(out)
	return out
}

// zero overwrites a byte slice in place. Best-effort — Go's GC offers no
// harder guarantee, but it shortens the window a private key sits readable in
// process memory.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
