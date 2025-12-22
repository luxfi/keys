// Copyright (C) 2024-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package keys provides validator key management for Lux networks.
// It handles generation, loading, and storage of:
// - TLS staking keys (for node identity)
// - BLS signer keys (for validator consensus)
// - EC private keys (for P/X/C-chain addresses)
package keys

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/crypto/bls/signer/localsigner"
	luxcrypto "github.com/luxfi/crypto/secp256k1"
	"github.com/luxfi/ids"
	"github.com/luxfi/node/staking"
	"github.com/luxfi/node/vms/platformvm/signer"
	"golang.org/x/crypto/sha3"
)

// ValidatorKey contains all keys needed for a validator node
type ValidatorKey struct {
	// NodeID is the unique identifier for the node (derived from TLS cert)
	NodeID ids.NodeID

	// TLS keys for node identity
	StakerKey  []byte // PEM-encoded private key
	StakerCert []byte // PEM-encoded certificate

	// BLS keys for consensus
	BLSSecretKey []byte // Raw BLS secret key bytes
	BLSPublicKey []byte // Compressed BLS public key
	BLSPoP       []byte // Proof of Possession signature

	// EC key for addresses
	ECPrivateKey []byte // Raw 32-byte secp256k1 private key

	// Derived addresses
	PChainAddr ids.ShortID // P/X chain address (20 bytes)
	CChainAddr ids.ShortID // C-chain address (20 bytes, Ethereum format)
}

// KeyStore manages validator keys with filesystem persistence
type KeyStore struct {
	baseDir string
}

// NewKeyStore creates a new key store at the given directory
func NewKeyStore(baseDir string) *KeyStore {
	if baseDir == "" {
		home, _ := os.UserHomeDir()
		baseDir = filepath.Join(home, ".lux", "keys")
	}
	return &KeyStore{baseDir: baseDir}
}

// BaseDir returns the base directory for the key store
func (ks *KeyStore) BaseDir() string {
	return ks.baseDir
}

// GenerateValidatorKey creates a complete set of validator keys
func GenerateValidatorKey() (*ValidatorKey, error) {
	vk := &ValidatorKey{}

	// 1. Generate TLS staking key
	certPEM, keyPEM, err := staking.NewCertAndKeyBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to generate TLS cert: %w", err)
	}

	vk.StakerCert = certPEM
	vk.StakerKey = keyPEM

	// Parse cert to derive NodeID
	tlsCert, err := staking.LoadTLSCertFromBytes(keyPEM, certPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TLS cert: %w", err)
	}
	stakingCert := &ids.Certificate{
		Raw:       tlsCert.Leaf.Raw,
		PublicKey: tlsCert.Leaf.PublicKey,
	}
	vk.NodeID = ids.NodeIDFromCert(stakingCert)

	// 2. Generate BLS signer key
	blsKey, err := localsigner.New()
	if err != nil {
		return nil, fmt.Errorf("failed to generate BLS key: %w", err)
	}
	vk.BLSSecretKey = blsKey.ToBytes()

	pop, err := signer.NewProofOfPossession(blsKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate BLS PoP: %w", err)
	}
	vk.BLSPublicKey = pop.PublicKey[:]
	vk.BLSPoP = pop.ProofOfPossession[:]

	// 3. Generate EC private key for addresses
	ecKey, err := luxcrypto.NewPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate EC key: %w", err)
	}
	vk.ECPrivateKey = ecKey.Bytes()

	// Derive P-chain address
	pubKey := ecKey.PublicKey()
	vk.PChainAddr = ids.ShortID(pubKey.Address())

	// Derive C-chain (Ethereum) address
	ecdsaPubKey := pubKey.ToECDSA()
	vk.CChainAddr = pubkeyToAddress(ecdsaPubKey)

	return vk, nil
}

// pubkeyToAddress derives an Ethereum address from an ECDSA public key
func pubkeyToAddress(pub *ecdsa.PublicKey) ids.ShortID {
	// Ethereum address is last 20 bytes of Keccak256(uncompressed pubkey without prefix)
	pubBytes := make([]byte, 64)
	copy(pubBytes[:32], pub.X.Bytes())
	copy(pubBytes[32:], pub.Y.Bytes())

	h := sha3.NewLegacyKeccak256()
	h.Write(pubBytes)
	hash := h.Sum(nil)

	var addr ids.ShortID
	copy(addr[:], hash[12:32])
	return addr
}

// Save persists a validator key to the filesystem
func (ks *KeyStore) Save(name string, vk *ValidatorKey) error {
	nodeDir := filepath.Join(ks.baseDir, name)

	// Create directory structure
	dirs := []string{
		nodeDir,
		filepath.Join(nodeDir, "staking"),
		filepath.Join(nodeDir, "bls"),
		filepath.Join(nodeDir, "ec"),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Save TLS staking key and cert
	if err := os.WriteFile(filepath.Join(nodeDir, "staking", "staker.key"), vk.StakerKey, 0600); err != nil {
		return fmt.Errorf("failed to write staker.key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(nodeDir, "staking", "staker.crt"), vk.StakerCert, 0644); err != nil {
		return fmt.Errorf("failed to write staker.crt: %w", err)
	}

	// Also save to legacy paths for backward compatibility
	if err := os.WriteFile(filepath.Join(nodeDir, "staker.key"), vk.StakerKey, 0600); err != nil {
		return fmt.Errorf("failed to write staker.key (legacy): %w", err)
	}
	if err := os.WriteFile(filepath.Join(nodeDir, "staker.crt"), vk.StakerCert, 0644); err != nil {
		return fmt.Errorf("failed to write staker.crt (legacy): %w", err)
	}

	// Save BLS signer key
	if err := os.WriteFile(filepath.Join(nodeDir, "bls", "signer.key"), vk.BLSSecretKey, 0600); err != nil {
		return fmt.Errorf("failed to write signer.key: %w", err)
	}

	// Save EC private key (hex encoded)
	ecKeyHex := hex.EncodeToString(vk.ECPrivateKey)
	if err := os.WriteFile(filepath.Join(nodeDir, "ec", "private.key"), []byte(ecKeyHex), 0600); err != nil {
		return fmt.Errorf("failed to write private.key: %w", err)
	}

	// Save key info JSON for reference
	info := fmt.Sprintf(`{
  "nodeID": "%s",
  "pChainAddr": "%s",
  "cChainAddr": "0x%s",
  "blsPublicKey": "0x%s"
}
`, vk.NodeID.String(),
		vk.PChainAddr.String(),
		hex.EncodeToString(vk.CChainAddr[:]),
		hex.EncodeToString(vk.BLSPublicKey))
	if err := os.WriteFile(filepath.Join(nodeDir, "info.json"), []byte(info), 0644); err != nil {
		return fmt.Errorf("failed to write info.json: %w", err)
	}

	return nil
}

// Load reads a validator key from the filesystem
func (ks *KeyStore) Load(name string) (*ValidatorKey, error) {
	nodeDir := filepath.Join(ks.baseDir, name)
	return LoadFromDir(nodeDir)
}

// LoadFromDir loads a validator key from a specific directory
func LoadFromDir(nodeDir string) (*ValidatorKey, error) {
	vk := &ValidatorKey{}

	// Load TLS cert - try modern path first
	certPath := filepath.Join(nodeDir, "staking", "staker.crt")
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		certPath = filepath.Join(nodeDir, "staker.crt")
		certPEM, err = os.ReadFile(certPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read staker.crt: %w", err)
		}
	}
	vk.StakerCert = certPEM

	// Load TLS key
	keyPath := filepath.Join(nodeDir, "staking", "staker.key")
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		keyPath = filepath.Join(nodeDir, "staker.key")
		keyPEM, err = os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read staker.key: %w", err)
		}
	}
	vk.StakerKey = keyPEM

	// Derive NodeID from TLS cert
	tlsCert, err := staking.LoadTLSCertFromBytes(keyPEM, certPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS cert: %w", err)
	}
	stakingCert := &ids.Certificate{
		Raw:       tlsCert.Leaf.Raw,
		PublicKey: tlsCert.Leaf.PublicKey,
	}
	vk.NodeID = ids.NodeIDFromCert(stakingCert)

	// Load BLS signer key (optional)
	signerPath := filepath.Join(nodeDir, "bls", "signer.key")
	signerBytes, err := os.ReadFile(signerPath)
	if err != nil {
		signerPath = filepath.Join(nodeDir, "signer.key")
		signerBytes, _ = os.ReadFile(signerPath)
	}
	if len(signerBytes) > 0 {
		vk.BLSSecretKey = signerBytes
		// Derive public key and PoP
		sk, err := bls.SecretKeyFromBytes(signerBytes)
		if err == nil {
			pk := bls.PublicFromSecretKey(sk)
			vk.BLSPublicKey = bls.PublicKeyToCompressedBytes(pk)
			sig := bls.Sign(sk, vk.BLSPublicKey)
			vk.BLSPoP = bls.SignatureToBytes(sig)
		}
	}

	// Load EC private key (optional)
	ecPath := filepath.Join(nodeDir, "ec", "private.key")
	ecKeyHex, err := os.ReadFile(ecPath)
	if err != nil {
		ecPath = filepath.Join(nodeDir, "private.key")
		ecKeyHex, _ = os.ReadFile(ecPath)
	}
	if len(ecKeyHex) > 0 {
		privKeyBytes, err := hex.DecodeString(strings.TrimSpace(string(ecKeyHex)))
		if err == nil && len(privKeyBytes) == 32 {
			vk.ECPrivateKey = privKeyBytes

			// Derive addresses
			luxPrivKey, err := luxcrypto.ToPrivateKey(privKeyBytes)
			if err == nil {
				pubKey := luxPrivKey.PublicKey()
				vk.PChainAddr = ids.ShortID(pubKey.Address())
				vk.CChainAddr = pubkeyToAddress(pubKey.ToECDSA())
			}
		}
	}

	// Fallback: derive addresses from NodeID if EC key not available
	if vk.PChainAddr == (ids.ShortID{}) {
		copy(vk.PChainAddr[:], vk.NodeID[:20])
		copy(vk.CChainAddr[:], vk.NodeID[:20])
	}

	return vk, nil
}

// List returns all validator keys in the store
func (ks *KeyStore) List() ([]string, error) {
	entries, err := os.ReadDir(ks.baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var names []string
	for _, entry := range entries {
		if entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	return names, nil
}

// GenerateMultiple generates multiple validator keys
func (ks *KeyStore) GenerateMultiple(count int, prefix string) ([]*ValidatorKey, error) {
	keys := make([]*ValidatorKey, count)
	for i := 0; i < count; i++ {
		vk, err := GenerateValidatorKey()
		if err != nil {
			return nil, fmt.Errorf("failed to generate key %d: %w", i, err)
		}
		keys[i] = vk

		name := fmt.Sprintf("%s%d", prefix, i+1)
		if err := ks.Save(name, vk); err != nil {
			return nil, fmt.Errorf("failed to save key %s: %w", name, err)
		}
	}
	return keys, nil
}

// LoadAll loads all validator keys from the store
func (ks *KeyStore) LoadAll() ([]*ValidatorKey, error) {
	names, err := ks.List()
	if err != nil {
		return nil, err
	}

	keys := make([]*ValidatorKey, 0, len(names))
	for _, name := range names {
		vk, err := ks.Load(name)
		if err != nil {
			continue // Skip invalid entries
		}
		keys = append(keys, vk)
	}
	return keys, nil
}

// BLSKeyBase64 returns the BLS secret key as base64 (for node config)
func (vk *ValidatorKey) BLSKeyBase64() string {
	return base64.StdEncoding.EncodeToString(vk.BLSSecretKey)
}

// BLSPublicKeyHex returns the BLS public key as hex with 0x prefix
func (vk *ValidatorKey) BLSPublicKeyHex() string {
	return "0x" + hex.EncodeToString(vk.BLSPublicKey)
}

// BLSPoPHex returns the BLS proof of possession as hex with 0x prefix
func (vk *ValidatorKey) BLSPoPHex() string {
	return "0x" + hex.EncodeToString(vk.BLSPoP)
}

// CChainAddrHex returns the C-chain address as hex with 0x prefix
func (vk *ValidatorKey) CChainAddrHex() string {
	return "0x" + hex.EncodeToString(vk.CChainAddr[:])
}
