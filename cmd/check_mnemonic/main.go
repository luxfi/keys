//go:build ignore

package main

import (
	"fmt"
	"os"

	"github.com/luxfi/keys"
)

func main() {
	mnemonic := os.Getenv("LUX_MNEMONIC")
	if mnemonic == "" {
		mnemonic = "REDACTED_USE_KMS"
	}

	fmt.Println("Deriving 5 validators from mnemonic using DeriveValidatorFromMnemonic...")
	fmt.Println("(TLS path: m/44'/60'/1'/0/{i}, BLS path: m/44'/60'/2'/0/{i})")
	fmt.Println()

	for i := 0; i < 5; i++ {
		vk, err := keys.DeriveValidatorFromMnemonic(mnemonic, uint32(i))
		if err != nil {
			fmt.Printf("Error deriving validator %d: %v\n", i, err)
			continue
		}
		fmt.Printf("validator %d: %s  P-addr=%s  C-addr=%s\n", i, vk.NodeID.String(), vk.PChainAddr.String(), vk.CChainAddrHex())
	}

	fmt.Println()
	fmt.Println("Genesis validators to match:")
	fmt.Println("  NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg")
	fmt.Println("  NodeID-MFrZFVCXPv5iCn6M9K6XduxGTYp891xXZ")
	fmt.Println("  NodeID-NFBbbJ4qCmNaCzeW7sxErhvWqvEQMnYcN")
	fmt.Println("  NodeID-GWPcbFJZFfZreETSoWjPimr846mXEKCtu")
	fmt.Println("  NodeID-P7oB2McjBGgW2NXXWVYjV8JEDFoW9xDE5")
}
