module github.com/luxfi/keys

go 1.26.3

require (
	github.com/luxfi/address v1.0.1
	github.com/luxfi/constants v1.4.7
	github.com/luxfi/crypto v1.19.0
	github.com/luxfi/go-bip32 v1.0.2
	github.com/luxfi/go-bip39 v1.1.2
	github.com/luxfi/ids v1.2.9
	github.com/luxfi/proto v0.0.0-proto-rename
	github.com/luxfi/tls v1.0.3
	golang.org/x/crypto v0.49.0
)

require (
	github.com/ProjectZKM/Ziren/crates/go-runtime/zkvm_runtime v0.0.0-20260311194731-d5b7577c683d // indirect
	github.com/btcsuite/btcd/btcutil v1.1.6 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 // indirect
	github.com/gorilla/rpc v1.2.1 // indirect
	github.com/holiman/uint256 v1.3.2 // indirect
	github.com/luxfi/accel v1.0.7 // indirect
	github.com/luxfi/cache v1.2.1 // indirect
	github.com/luxfi/container v0.0.4 // indirect
	github.com/luxfi/formatting v1.0.1 // indirect
	github.com/luxfi/geth v1.16.79 // indirect
	github.com/luxfi/math v1.4.0 // indirect
	github.com/luxfi/math/big v0.1.0 // indirect
	github.com/luxfi/metric v1.5.1 // indirect
	github.com/luxfi/mock v0.1.1 // indirect
	github.com/luxfi/sampler v1.0.0 // indirect
	github.com/luxfi/vm v1.0.40 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/supranational/blst v0.3.16 // indirect
	go.uber.org/mock v0.6.0 // indirect
	golang.org/x/exp v0.0.0-20260312153236-7ab1446f8b90 // indirect
	golang.org/x/sys v0.42.0 // indirect
	gonum.org/v1/gonum v0.17.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

// Local-dev overlay for the protocol → proto rename.
// Strip once GitHub admin renames luxfi/protocol → luxfi/proto and a real tag exists.
replace github.com/luxfi/proto => ../protocol
