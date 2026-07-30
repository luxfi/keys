// Copyright (C) 2019-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keys

import (
	"errors"

	"github.com/luxfi/crypto/bls"
)

var errInvalidProofOfPossession = errors.New("invalid proof of possession")

// ProofOfPossession is a BLS public key together with a signature over that key,
// proving the holder has the matching secret. It is the shape a validator
// registration carries.
//
// Built here rather than imported: the only other copy lives in
// github.com/luxfi/node, and this module sits below the node in the stack — it
// manages keys, so it should not need a VM to make one. Everything below comes
// from crypto/bls, which this module already depends on.
type ProofOfPossession struct {
	PublicKey         [bls.PublicKeyLen]byte `serialize:"true" json:"publicKey"`
	ProofOfPossession [bls.SignatureLen]byte `serialize:"true" json:"proofOfPossession"`
}

// NewProofOfPossession signs the signer's own compressed public key with it. The
// signed message being the key itself is what makes the signature a proof of
// possession rather than an ordinary signature.
func NewProofOfPossession(sk bls.Signer) (*ProofOfPossession, error) {
	pkBytes := bls.PublicKeyToCompressedBytes(sk.PublicKey())
	sig, err := sk.SignProofOfPossession(pkBytes)
	if err != nil {
		return nil, err
	}
	pop := &ProofOfPossession{}
	copy(pop.PublicKey[:], pkBytes)
	copy(pop.ProofOfPossession[:], bls.SignatureToBytes(sig))
	return pop, nil
}

// Verify checks the proof against the key it carries.
func (p *ProofOfPossession) Verify() error {
	pk, err := bls.PublicKeyFromCompressedBytes(p.PublicKey[:])
	if err != nil {
		return err
	}
	sig, err := bls.SignatureFromBytes(p.ProofOfPossession[:])
	if err != nil {
		return err
	}
	if !bls.VerifyProofOfPossession(pk, sig, p.PublicKey[:]) {
		return errInvalidProofOfPossession
	}
	return nil
}
