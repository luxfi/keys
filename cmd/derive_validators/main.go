//go:build ignore

// derive_validators derives validator keys from mnemonic and saves them to disk.
// Usage: LUX_MNEMONIC="..." go run main.go [count] [output-dir]
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/luxfi/keys"
)

func main() {
	mnemonic := os.Getenv("LUX_MNEMONIC")
	if mnemonic == "" {
		fmt.Fprintln(os.Stderr, "LUX_MNEMONIC not set")
		os.Exit(1)
	}

	count := 5
	outputDir := ""
	if len(os.Args) > 1 {
		fmt.Sscanf(os.Args[1], "%d", &count)
	}
	if len(os.Args) > 2 {
		outputDir = os.Args[2]
	}
	if outputDir == "" {
		home, _ := os.UserHomeDir()
		outputDir = filepath.Join(home, ".lux", "keys")
	}

	fmt.Printf("Deriving %d validators from mnemonic...\n", count)
	fmt.Printf("Output dir: %s\n\n", outputDir)

	ks := keys.NewKeyStore(outputDir)

	validators := make([]*keys.ValidatorKey, count)
	for i := 0; i < count; i++ {
		vk, err := keys.DeriveValidatorFromMnemonic(mnemonic, uint32(i))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error deriving validator %d: %v\n", i, err)
			os.Exit(1)
		}
		validators[i] = vk

		name := fmt.Sprintf("node%d", i)
		if err := ks.Save(name, vk); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving %s: %v\n", name, err)
			os.Exit(1)
		}

		fmt.Printf("node%d:\n", i)
		fmt.Printf("  NodeID:     %s\n", vk.NodeID.String())
		fmt.Printf("  P-Chain:    %s\n", vk.PChainAddr.String())
		fmt.Printf("  C-Chain:    %s\n", vk.CChainAddrHex())
		fmt.Printf("  BLS PubKey: %s...\n", vk.BLSPublicKeyHex()[:30])
		fmt.Println()
	}

	// Output a JSON summary
	type NodeSummary struct {
		Name      string `json:"name"`
		NodeID    string `json:"nodeID"`
		PChain    string `json:"pChainAddr"`
		CChain    string `json:"cChainAddr"`
		BLSPubKey string `json:"blsPublicKey"`
		BLSPoP    string `json:"blsProofOfPossession"`
	}
	var summary []NodeSummary
	for i, vk := range validators {
		summary = append(summary, NodeSummary{
			Name:      fmt.Sprintf("node%d", i),
			NodeID:    vk.NodeID.String(),
			PChain:    vk.PChainAddr.String(),
			CChain:    vk.CChainAddrHex(),
			BLSPubKey: "0x" + hex.EncodeToString(vk.BLSPublicKey),
			BLSPoP:    "0x" + hex.EncodeToString(vk.BLSPoP),
		})
	}

	summaryJSON, _ := json.MarshalIndent(summary, "", "  ")
	summaryPath := filepath.Join(outputDir, "validators.json")
	os.WriteFile(summaryPath, summaryJSON, 0644)
	fmt.Printf("Summary written to: %s\n", summaryPath)
}
