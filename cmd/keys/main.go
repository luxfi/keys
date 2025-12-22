// Copyright (C) 2024-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command keys manages validator keys for Lux networks.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/luxfi/keys"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	home, _ := os.UserHomeDir()
	defaultDir := filepath.Join(home, ".lux", "keys")

	// Check for --dir flag
	keyDir := defaultDir
	args := os.Args[1:]
	for i, arg := range args {
		if arg == "--dir" && i+1 < len(args) {
			keyDir = args[i+1]
			args = append(args[:i], args[i+2:]...)
			break
		}
	}

	if len(args) < 1 {
		printUsage()
		os.Exit(1)
	}

	ks := keys.NewKeyStore(keyDir)

	switch args[0] {
	case "generate", "gen":
		if len(args) < 2 {
			fmt.Println("Usage: keys generate <count> [prefix]")
			os.Exit(1)
		}
		count, err := strconv.Atoi(args[1])
		if err != nil {
			fmt.Printf("Invalid count: %s\n", args[1])
			os.Exit(1)
		}
		prefix := "node"
		if len(args) > 2 {
			prefix = args[2]
		}
		generateKeys(ks, count, prefix)

	case "list", "ls":
		listKeys(ks)

	case "show":
		if len(args) < 2 {
			fmt.Println("Usage: keys show <name>")
			os.Exit(1)
		}
		showKey(ks, args[1])

	case "allocations", "alloc":
		if len(args) < 2 {
			fmt.Println("Usage: keys allocations <network-id> [amount-per-key]")
			os.Exit(1)
		}
		networkID, err := strconv.ParseUint(args[1], 10, 32)
		if err != nil {
			fmt.Printf("Invalid network ID: %s\n", args[1])
			os.Exit(1)
		}
		amount := keys.DefaultValidatorStake
		if len(args) > 2 {
			amount, err = strconv.ParseUint(args[2], 10, 64)
			if err != nil {
				fmt.Printf("Invalid amount: %s\n", args[2])
				os.Exit(1)
			}
		}
		generateAllocations(ks, uint32(networkID), amount)

	case "upgrade":
		// Upgrade existing keys to add BLS and EC keys if missing
		upgradeKeys(ks)

	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`Usage: keys [--dir <keys-dir>] <command> [args]

Commands:
  generate <count> [prefix]    Generate new validator keys
  list                         List all keys
  show <name>                  Show key details
  allocations <network-id>     Generate P-chain allocations JSON
  upgrade                      Add BLS/EC keys to existing staking keys

Options:
  --dir <path>                 Key store directory (default: ~/.lux/keys)

Examples:
  keys generate 5 node         Generate 5 keys named node1-node5
  keys list                    List all keys
  keys show node1              Show node1 key details
  keys allocations 1337        Generate local network allocations`)
}

func generateKeys(ks *keys.KeyStore, count int, prefix string) {
	fmt.Printf("Generating %d validator keys with prefix '%s'...\n", count, prefix)

	vkeys, err := ks.GenerateMultiple(count, prefix)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\nGenerated keys:")
	for i, vk := range vkeys {
		name := fmt.Sprintf("%s%d", prefix, i+1)
		fmt.Printf("  %s:\n", name)
		fmt.Printf("    NodeID:     %s\n", vk.NodeID.String())
		fmt.Printf("    P-Chain:    %s\n", vk.PChainAddr.String())
		fmt.Printf("    C-Chain:    %s\n", vk.CChainAddrHex())
		if len(vk.BLSPublicKey) > 0 {
			fmt.Printf("    BLS PubKey: %s...\n", vk.BLSPublicKeyHex()[:20])
		}
	}
}

func listKeys(ks *keys.KeyStore) {
	names, err := ks.List()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if len(names) == 0 {
		fmt.Println("No keys found.")
		return
	}

	fmt.Println("Validator keys:")
	for _, name := range names {
		vk, err := ks.Load(name)
		if err != nil {
			fmt.Printf("  %s: (error loading: %v)\n", name, err)
			continue
		}
		hasBLS := "✓"
		if len(vk.BLSPublicKey) == 0 {
			hasBLS = "✗"
		}
		hasEC := "✓"
		if len(vk.ECPrivateKey) == 0 {
			hasEC = "✗"
		}
		fmt.Printf("  %s: NodeID=%s BLS=%s EC=%s\n", name, vk.NodeID.String(), hasBLS, hasEC)
	}
}

func showKey(ks *keys.KeyStore, name string) {
	vk, err := ks.Load(name)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Key: %s\n", name)
	fmt.Printf("  NodeID:        %s\n", vk.NodeID.String())
	fmt.Printf("  P-Chain Addr:  %s\n", vk.PChainAddr.String())
	fmt.Printf("  C-Chain Addr:  %s\n", vk.CChainAddrHex())

	if len(vk.BLSPublicKey) > 0 {
		fmt.Printf("  BLS Public:    %s\n", vk.BLSPublicKeyHex())
		fmt.Printf("  BLS PoP:       %s\n", vk.BLSPoPHex())
	} else {
		fmt.Printf("  BLS Keys:      (not available)\n")
	}

	if len(vk.ECPrivateKey) > 0 {
		fmt.Printf("  EC Key:        (available)\n")
	} else {
		fmt.Printf("  EC Key:        (not available)\n")
	}
}

func generateAllocations(ks *keys.KeyStore, networkID uint32, amountPerKey uint64) {
	vkeys, err := ks.LoadAll()
	if err != nil {
		fmt.Printf("Error loading keys: %v\n", err)
		os.Exit(1)
	}

	if len(vkeys) == 0 {
		fmt.Println("No keys found. Generate keys first with 'keys generate'.")
		os.Exit(1)
	}

	allocs, err := keys.NewAllocationBuilder(networkID, vkeys).
		WithAmount(amountPerKey).
		WithFeeAccount(0, 10*keys.MegaLux). // First validator gets extra
		WithImmediateUnlock().
		Build()
	if err != nil {
		fmt.Printf("Error generating allocations: %v\n", err)
		os.Exit(1)
	}

	// Output P-chain allocations
	fmt.Println("// P-Chain allocations (pchain.json)")
	pchainJSON, _ := json.MarshalIndent(map[string]interface{}{
		"allocations":        allocs.PChainAllocations,
		"initialStakedFunds": allocs.InitialStakedFunds,
		"initialStakers":     allocs.InitialStakers,
	}, "", "  ")
	fmt.Println(string(pchainJSON))

	fmt.Println("\n// C-Chain allocations (for cchain.json alloc field)")
	cchainJSON, _ := json.MarshalIndent(allocs.CChainAllocations, "", "  ")
	fmt.Println(string(cchainJSON))
}

func upgradeKeys(ks *keys.KeyStore) {
	names, err := ks.List()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	for _, name := range names {
		vk, err := ks.Load(name)
		if err != nil {
			fmt.Printf("  %s: error loading - %v\n", name, err)
			continue
		}

		needsUpgrade := false

		// Check if BLS keys are missing
		if len(vk.BLSSecretKey) == 0 {
			fmt.Printf("  %s: generating BLS keys...\n", name)
			// We need to generate new keys since we can't add to existing
			newKey, err := keys.GenerateValidatorKey()
			if err != nil {
				fmt.Printf("  %s: error generating - %v\n", name, err)
				continue
			}
			// Copy BLS keys
			vk.BLSSecretKey = newKey.BLSSecretKey
			vk.BLSPublicKey = newKey.BLSPublicKey
			vk.BLSPoP = newKey.BLSPoP
			needsUpgrade = true
		}

		// Check if EC key is missing
		if len(vk.ECPrivateKey) == 0 {
			fmt.Printf("  %s: generating EC key...\n", name)
			newKey, err := keys.GenerateValidatorKey()
			if err != nil {
				fmt.Printf("  %s: error generating - %v\n", name, err)
				continue
			}
			// Copy EC key and addresses
			vk.ECPrivateKey = newKey.ECPrivateKey
			vk.PChainAddr = newKey.PChainAddr
			vk.CChainAddr = newKey.CChainAddr
			needsUpgrade = true
		}

		if needsUpgrade {
			if err := ks.Save(name, vk); err != nil {
				fmt.Printf("  %s: error saving - %v\n", name, err)
				continue
			}
			fmt.Printf("  %s: upgraded successfully\n", name)
		} else {
			fmt.Printf("  %s: already up to date\n", name)
		}
	}
}
