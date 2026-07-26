// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keys

import (
	"runtime"
	"testing"
	"time"
)

// svcMnemonic is the canonical BIP-39 all-zero-entropy English test vector.
const svcMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

// NewServiceIdentity is a pure function: same (mnemonic, path) → same NodeID.
func TestServiceIdentity_Deterministic(t *testing.T) {
	a, err := NewServiceIdentity(svcMnemonic, "luxd/staking-bootstrap")
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	defer a.Wipe()
	b, err := NewServiceIdentity(svcMnemonic, "luxd/staking-bootstrap")
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	defer b.Wipe()
	if a.NodeID != b.NodeID {
		t.Fatal("service identity NodeID is not deterministic")
	}
}

// L1 regression: Sign must NOT re-parse s.privateKey into a transient
// mldsa.PrivateKey on every call. That transient aliases s.privateKey and arms
// a Zeroize GC finalizer; when it goes unreachable the finalizer zeroes the
// SHARED key mid-run, so the NEXT Sign signs with (or over) a corrupted key.
// This is exactly the CUSTODY+Save boot path, which signs two envelopes (GetAt
// then PutAt) from one identity.
//
// The test signs, then aggressively drives GC + finalizers between signs, then
// signs again. With the cached-signer fix BOTH signatures are produced over the
// intact key and verify. With the aliasing regression, the second Sign operates
// on a zeroed key and the check fails.
func TestServiceIdentity_SignSurvivesGCBetweenCalls(t *testing.T) {
	id, err := NewServiceIdentity(svcMnemonic, "hanzo/kms-operator")
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer id.Wipe()

	env1 := []byte("envelope-one: OpSecretGet")
	sig1, err := id.Sign(env1)
	if err != nil {
		t.Fatalf("first sign: %v", err)
	}

	// Force any finalizer-bearing transient created during the first Sign to be
	// collected and its finalizer to run. Under the regression this zeroes the
	// shared key; under the fix there is no such transient.
	forceFinalizers()

	env2 := []byte("envelope-two: OpSecretPut")
	sig2, err := id.Sign(env2)
	if err != nil {
		t.Fatalf("second sign after GC failed (key zeroed by aliased transient finalizer?): %v", err)
	}

	if err := VerifyServiceEnvelope(id.PublicKey, id.FullDigest, env1, sig1); err != nil {
		t.Fatalf("first signature did not verify (key corrupted mid-run): %v", err)
	}
	if err := VerifyServiceEnvelope(id.PublicKey, id.FullDigest, env2, sig2); err != nil {
		t.Fatalf("second signature did not verify (key corrupted mid-run): %v", err)
	}

	// Signing many more times across GC pressure must all verify — the cached
	// signer is stable for the identity's whole lifetime.
	for i := 0; i < 8; i++ {
		forceFinalizers()
		msg := []byte{byte(i), 'x'}
		sig, serr := id.Sign(msg)
		if serr != nil {
			t.Fatalf("sign %d: %v", i, serr)
		}
		if verr := VerifyServiceEnvelope(id.PublicKey, id.FullDigest, msg, sig); verr != nil {
			t.Fatalf("sign %d did not verify: %v", i, verr)
		}
	}
}

// After Wipe the identity fails closed: Sign returns an error rather than
// signing with a zeroed key, and the cached signer is dropped.
func TestServiceIdentity_WipeFailsClosed(t *testing.T) {
	id, err := NewServiceIdentity(svcMnemonic, "luxd/staking-bootstrap")
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if _, err := id.Sign([]byte("pre-wipe")); err != nil {
		t.Fatalf("pre-wipe sign: %v", err)
	}
	id.Wipe()
	if id.signer != nil {
		t.Fatal("Wipe did not drop the cached signer")
	}
	if _, err := id.Sign([]byte("post-wipe")); err == nil {
		t.Fatal("Sign after Wipe must fail closed")
	}
	id.Wipe() // idempotent
}

// forceFinalizers drives the GC and gives the finalizer goroutine a window to
// run. runtime.GC identifies unreachable objects; finalizers run asynchronously
// on a dedicated goroutine, so we loop with a brief yield to make their
// execution overwhelmingly likely within the test.
func forceFinalizers() {
	for i := 0; i < 4; i++ {
		runtime.GC()
		time.Sleep(time.Millisecond)
	}
}
