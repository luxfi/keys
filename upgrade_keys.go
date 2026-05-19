// Copyright (C) 2024-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build ignore

// This tool upgrades existing node keys to add BLS signer and EC private keys.
// Run with: go run upgrade_keys.go
package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/luxfi/crypto/bls/signer/localsigner"
	luxcrypto "github.com/luxfi/crypto/secp256k1"
	"github.com/luxfi/ids"
	"github.com/luxfi/proto/p/signer"
	luxtls "github.com/luxfi/tls"
)

func main() {
	home, _ := os.UserHomeDir()
	keysDir := filepath.Join(home, "work", "lux", "keys")

	if len(os.Args) > 1 {
		keysDir = os.Args[1]
	}

	fmt.Printf("Upgrading keys in: %s\n\n", keysDir)

	entries, err := os.ReadDir(keysDir)
	if err != nil {
		fmt.Printf("Error reading directory: %v\n", err)
		os.Exit(1)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		name := entry.Name()
		nodeDir := filepath.Join(keysDir, name)

		// Check if this is a valid node directory (has staker.crt)
		certPath := filepath.Join(nodeDir, "staker.crt")
		if _, err := os.Stat(certPath); os.IsNotExist(err) {
			continue
		}

		fmt.Printf("Processing %s...\n", name)

		if err := upgradeNode(nodeDir); err != nil {
			fmt.Printf("  Error: %v\n", err)
			continue
		}

		fmt.Printf("  Done!\n")
	}
}

func upgradeNode(nodeDir string) error {
	// Load existing TLS cert to get NodeID
	certPath := filepath.Join(nodeDir, "staker.crt")
	keyPath := filepath.Join(nodeDir, "staker.key")

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to read staker.crt: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read staker.key: %w", err)
	}

	tlsCert, err := luxtls.LoadTLSCertFromBytes(keyPEM, certPEM)
	if err != nil {
		return fmt.Errorf("failed to load TLS cert: %w", err)
	}

	stakingCert := &ids.Certificate{
		Raw:       tlsCert.Leaf.Raw,
		PublicKey: tlsCert.Leaf.PublicKey,
	}
	nodeID := ids.NodeIDFromCert(stakingCert)
	fmt.Printf("  NodeID: %s\n", nodeID.String())

	// Create directories
	blsDir := filepath.Join(nodeDir, "bls")
	ecDir := filepath.Join(nodeDir, "ec")
	if err := os.MkdirAll(blsDir, 0700); err != nil {
		return fmt.Errorf("failed to create bls directory: %w", err)
	}
	if err := os.MkdirAll(ecDir, 0700); err != nil {
		return fmt.Errorf("failed to create ec directory: %w", err)
	}

	// Check/Generate BLS signer key
	blsPath := filepath.Join(blsDir, "signer.key")
	if _, err := os.Stat(blsPath); os.IsNotExist(err) {
		fmt.Printf("  Generating BLS signer key...\n")
		blsKey, err := localsigner.New()
		if err != nil {
			return fmt.Errorf("failed to generate BLS key: %w", err)
		}
		if err := os.WriteFile(blsPath, blsKey.ToBytes(), 0600); err != nil {
			return fmt.Errorf("failed to write BLS key: %w", err)
		}

		// Also write public key info
		pop, err := signer.NewProofOfPossession(blsKey)
		if err != nil {
			return fmt.Errorf("failed to generate PoP: %w", err)
		}
		info := fmt.Sprintf(`{
  "publicKey": "0x%s",
  "proofOfPossession": "0x%s"
}
`, hex.EncodeToString(pop.PublicKey[:]), hex.EncodeToString(pop.ProofOfPossession[:]))
		if err := os.WriteFile(filepath.Join(blsDir, "info.json"), []byte(info), 0644); err != nil {
			return fmt.Errorf("failed to write BLS info: %w", err)
		}
		fmt.Printf("  BLS public key: 0x%s...\n", hex.EncodeToString(pop.PublicKey[:])[:20])
	} else {
		fmt.Printf("  BLS key already exists\n")
	}

	// Check/Generate EC private key
	ecPath := filepath.Join(ecDir, "private.key")
	if _, err := os.Stat(ecPath); os.IsNotExist(err) {
		fmt.Printf("  Generating EC private key...\n")
		privKey, err := luxcrypto.NewPrivateKey()
		if err != nil {
			return fmt.Errorf("failed to generate EC key: %w", err)
		}

		// Write as hex
		if err := os.WriteFile(ecPath, []byte(hex.EncodeToString(privKey.Bytes())), 0600); err != nil {
			return fmt.Errorf("failed to write EC key: %w", err)
		}

		// Also write address info
		pubKey := privKey.PublicKey()
		shortID := pubKey.Address()
		info := fmt.Sprintf(`{
  "shortID": "%s",
  "ethAddress": "0x%s"
}
`, shortID.String(), hex.EncodeToString(shortID[:]))
		if err := os.WriteFile(filepath.Join(ecDir, "info.json"), []byte(info), 0644); err != nil {
			return fmt.Errorf("failed to write EC info: %w", err)
		}
		fmt.Printf("  P-Chain addr: %s\n", shortID.String())
	} else {
		fmt.Printf("  EC key already exists\n")
	}

	return nil
}
