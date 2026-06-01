// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keys

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const validBIP39 = "abandon abandon abandon abandon abandon abandon " +
	"abandon abandon abandon abandon abandon about"

type fakeKMS struct {
	value   string
	getErr  error
	gotPath string
	gotName string
	gotEnv  string
	closed  bool
}

func (f *fakeKMS) GetAt(_ context.Context, path, name, env string) (string, error) {
	f.gotPath, f.gotName, f.gotEnv = path, name, env
	if f.getErr != nil {
		return "", f.getErr
	}
	return f.value, nil
}
func (f *fakeKMS) Close() { f.closed = true }

// gotIdent captures the identity threaded into the dial seam so the
// per-call-site identity-wiring test can assert it reached zapclient.
type gotIdent struct {
	called   bool
	identity *ServiceIdentity
}

func withDial(t *testing.T, f *fakeKMS, err error) *gotIdent {
	t.Helper()
	prev := dialKMS
	g := &gotIdent{}
	dialKMS = func(_ context.Context, _ string, id *ServiceIdentity) (MnemonicReader, error) {
		g.called = true
		g.identity = id
		if err != nil {
			return nil, err
		}
		return f, nil
	}
	t.Cleanup(func() { dialKMS = prev })
	return g
}

// MNEMONIC env wins when set + valid. KMS is not dialed.
func TestLoadMnemonic_EnvWins(t *testing.T) {
	t.Setenv("MNEMONIC", validBIP39+"\n")
	f := &fakeKMS{value: "ignored"}
	g := withDial(t, f, nil)
	got, err := LoadMnemonic(context.Background(), "addr", "main", "/mnemonic", nil)
	if err != nil {
		t.Fatalf("LoadMnemonic: %v", err)
	}
	if got != validBIP39 {
		t.Errorf("got %q want %q", got, validBIP39)
	}
	if f.closed || g.called {
		t.Error("KMS should NOT be dialed when MNEMONIC env is set")
	}
}

// Invalid MNEMONIC env fails fast — does NOT silently fall through to KMS.
func TestLoadMnemonic_EnvInvalid(t *testing.T) {
	t.Setenv("MNEMONIC", "not a bip39 phrase")
	_, err := LoadMnemonic(context.Background(), "addr", "main", "/mnemonic", nil)
	if err == nil || !strings.Contains(err.Error(), "MNEMONIC env") {
		t.Fatalf("expected MNEMONIC-env error, got %v", err)
	}
}

// Empty MNEMONIC → KMS path runs.
func TestLoadMnemonic_FallsThroughToKMS(t *testing.T) {
	t.Setenv("MNEMONIC", "")
	f := &fakeKMS{value: validBIP39}
	withDial(t, f, nil)
	got, err := LoadMnemonic(context.Background(), "addr", "main", "/mnemonic", nil)
	if err != nil {
		t.Fatalf("LoadMnemonic: %v", err)
	}
	if got != validBIP39 {
		t.Errorf("got %q want %q", got, validBIP39)
	}
	if !f.closed {
		t.Error("KMS reader should have been closed")
	}
	if f.gotPath != "" || f.gotName != "mnemonic" || f.gotEnv != "main" {
		t.Errorf("GetAt args: path=%q name=%q env=%q", f.gotPath, f.gotName, f.gotEnv)
	}
}

func TestLoadMnemonicFromKMS_RequiredArgs(t *testing.T) {
	t.Setenv("MNEMONIC", "")
	cases := []struct {
		addr, env, path, wantMsg string
	}{
		{"", "main", "/m", "addr is required"},
		{"a", "", "/m", "env is required"},
		{"a", "main", "", "path is required"},
	}
	for _, c := range cases {
		_, err := LoadMnemonicFromKMS(context.Background(), c.addr, c.env, c.path, nil)
		if err == nil || !strings.Contains(err.Error(), c.wantMsg) {
			t.Errorf("addr=%q env=%q path=%q → %v, want %q",
				c.addr, c.env, c.path, err, c.wantMsg)
		}
	}
}

func TestLoadMnemonicFromKMS_InvalidValue(t *testing.T) {
	t.Setenv("MNEMONIC", "")
	withDial(t, &fakeKMS{value: "not a bip39"}, nil)
	_, err := LoadMnemonicFromKMS(context.Background(), "a", "main", "/m", nil)
	if err == nil || !strings.Contains(err.Error(), "not a valid BIP-39") {
		t.Fatalf("got %v", err)
	}
}

func TestLoadMnemonicFromKMS_EmptyValue(t *testing.T) {
	t.Setenv("MNEMONIC", "")
	withDial(t, &fakeKMS{value: ""}, nil)
	_, err := LoadMnemonicFromKMS(context.Background(), "a", "main", "/m", nil)
	if err == nil || !strings.Contains(err.Error(), "is empty") {
		t.Fatalf("got %v", err)
	}
}

func TestLoadMnemonicFromKMS_DialError(t *testing.T) {
	t.Setenv("MNEMONIC", "")
	withDial(t, nil, errors.New("dial timeout"))
	_, err := LoadMnemonicFromKMS(context.Background(), "a", "main", "/m", nil)
	if err == nil || !strings.Contains(err.Error(), "dial timeout") {
		t.Fatalf("got %v", err)
	}
}

func TestLoadMnemonicFromKMS_GetError(t *testing.T) {
	t.Setenv("MNEMONIC", "")
	f := &fakeKMS{getErr: errors.New("kms 403")}
	withDial(t, f, nil)
	_, err := LoadMnemonicFromKMS(context.Background(), "a", "main", "/m", nil)
	if err == nil || !strings.Contains(err.Error(), "kms 403") {
		t.Fatalf("got %v", err)
	}
	if !f.closed {
		t.Error("reader should be closed even when GetAt fails")
	}
}

// TestLoadMnemonicFromKMS_ThreadsIdentity asserts the *ServiceIdentity
// argument reaches the dial seam unchanged. Without this guarantee
// the production dial would silently drop identity and the KMS
// server's consensus-auth gate would refuse the envelope at runtime.
func TestLoadMnemonicFromKMS_ThreadsIdentity(t *testing.T) {
	t.Setenv("MNEMONIC", "")
	id, err := NewServiceIdentity(validBIP39, "luxd/staking-bootstrap")
	if err != nil {
		t.Fatalf("NewServiceIdentity: %v", err)
	}
	defer id.Wipe()
	f := &fakeKMS{value: validBIP39}
	g := withDial(t, f, nil)
	if _, err := LoadMnemonicFromKMS(context.Background(), "a", "main", "/m", id); err != nil {
		t.Fatalf("LoadMnemonicFromKMS: %v", err)
	}
	if !g.called {
		t.Fatal("dial seam not called")
	}
	if g.identity != id {
		t.Fatalf("identity not threaded: got %p want %p", g.identity, id)
	}
}

func TestSplitSecretPath(t *testing.T) {
	cases := []struct {
		in, dir, name string
	}{
		{"/mnemonic", "", "mnemonic"},
		{"mnemonic", "", "mnemonic"},
		{"/foo/bar", "/foo/", "bar"},
		{"/foo/bar/baz", "/foo/bar/", "baz"},
		{"", "", ""},
		{"  /a/b  ", "/a/", "b"},
	}
	for _, c := range cases {
		d, n := SplitSecretPath(c.in)
		if d != c.dir || n != c.name {
			t.Errorf("SplitSecretPath(%q) = (%q,%q), want (%q,%q)",
				c.in, d, n, c.dir, c.name)
		}
	}
}
