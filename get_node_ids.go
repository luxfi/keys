//go:build ignore

// Deprecated: Use get_correct_node_ids.go instead - this uses incorrect NodeID derivation
package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mr-tron/base58"
)

func main() {
	keysDir := "/Users/z/work/lux/keys"

	for i := 1; i <= 5; i++ {
		certPath := filepath.Join(keysDir, fmt.Sprintf("node%d", i), "staker.crt")
		nodeID, err := getNodeID(certPath)
		if err != nil {
			fmt.Printf("Error getting node%d ID: %v\n", i, err)
			continue
		}
		fmt.Printf("Node%d: %s\n", i, nodeID)
	}
}

func getNodeID(certPath string) (string, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}

	// NodeID is SHA256 of the raw public key bytes
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(pubKeyBytes)

	// Add checksum (last 4 bytes of double SHA256)
	hashWithChecksum := append(hash[:], checksum(hash[:])...)

	encoded := base58.Encode(hashWithChecksum)
	return "NodeID-" + encoded, nil
}

func checksum(data []byte) []byte {
	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])
	return second[:4]
}
