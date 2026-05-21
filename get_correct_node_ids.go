//go:build ignore

// This tool prints NodeIDs for node1-5 key directories.
// Run with: go run get_correct_node_ids.go
package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/luxfi/ids"
)

func main() {
	keysDir := os.ExpandEnv("$HOME/work/lux/keys")

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

	// Use the ids package to get the correct NodeID
	idsCert := &ids.Certificate{
		Raw:       cert.Raw,
		PublicKey: cert.PublicKey,
	}
	nodeID := ids.NodeIDFromCert(idsCert)

	return nodeID.String(), nil
}
