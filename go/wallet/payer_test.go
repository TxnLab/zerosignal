/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package wallet

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/keystore"
)

type staticKeys []keystore.MnemonicEntry

func (s staticKeys) Mnemonics(context.Context) ([]keystore.MnemonicEntry, error) { return s, nil }

// fileWallet creates a testnet wallet on the encrypted file in a fresh dir.
func fileWallet(t *testing.T) (dir, addr string) {
	t.Helper()
	dir = t.TempDir()
	w, err := Open(dir, fileOpts())
	if err != nil {
		t.Fatal(err)
	}
	meta, err := w.Generate("testnet", false)
	if err != nil {
		t.Fatal(err)
	}
	return dir, meta.Address
}

// envKey is a phrase standing in for a *_MNEMONIC, and its address.
func envKey(t *testing.T) (staticKeys, string) {
	t.Helper()
	w := newTestWallet(t)
	meta, err := w.Generate("mainnet", false)
	if err != nil {
		t.Fatal(err)
	}
	phrase, err := w.Export()
	if err != nil {
		t.Fatal(err)
	}
	return staticKeys{{Name: "TEST", Mnemonic: phrase}}, meta.Address
}

func TestLoadPayer(t *testing.T) {
	walletDir, walletAddr := fileWallet(t)
	env, envAddr := envKey(t)

	w, err := Open(walletDir, fileOpts())
	if err != nil {
		t.Fatal(err)
	}
	walletPhrase, err := w.Export()
	if err != nil {
		t.Fatal(err)
	}
	sameKey := staticKeys{{Name: "SAME", Mnemonic: walletPhrase}}

	brokenDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(brokenDir, metaFile), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		dir         string
		env         staticKeys
		address     string
		wantAddr    string
		wantNetwork string
		wantErr     string
	}{
		{name: "wallet only", dir: walletDir, wantAddr: walletAddr, wantNetwork: "testnet"},
		{name: "env only", dir: t.TempDir(), env: env, wantAddr: envAddr},
		{name: "both, unchosen", dir: walletDir, env: env, wantErr: "2 keys loaded"},
		{name: "both, wallet chosen", dir: walletDir, env: env, address: walletAddr, wantAddr: walletAddr, wantNetwork: "testnet"},
		// The wallet's network says nothing about a key it does not hold.
		{name: "both, env chosen", dir: walletDir, env: env, address: envAddr, wantAddr: envAddr},
		{name: "chosen not loaded", dir: walletDir, address: envAddr, wantErr: "not among the loaded keys"},
		// The wallet's own phrase in the environment is still the wallet's key.
		{name: "wallet key also in env", dir: walletDir, env: sameKey, wantAddr: walletAddr, wantNetwork: "testnet"},
		// A wallet that will not open must not hand payment to another key.
		{name: "broken wallet", dir: brokenDir, env: env, wantErr: "open wallet"},
		{name: "none", dir: t.TempDir(), wantErr: "no keys"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// noBackend: a wallet the test did not create must not open.
			kr := KeyringOptions{Backend: noBackend, Passphrase: fixedPassphrase}
			p, err := loadPayer(context.Background(), PayerOptions{Address: tt.address, Dir: tt.dir},
				kr, []keystore.SecretProvider{tt.env})
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := p.Signer.Address(); got != tt.wantAddr {
				t.Errorf("address = %s, want %s", got, tt.wantAddr)
			}
			if p.Network != tt.wantNetwork {
				t.Errorf("network = %q, want %q", p.Network, tt.wantNetwork)
			}
		})
	}
}

// LoadPayer itself: the caller's Passphrase unlocks the file, and without one
// EnvPassphrase does. The address is named because the machine's own
// *_MNEMONIC keys may load too.
func TestLoadPayer_Passphrase(t *testing.T) {
	dir, addr := fileWallet(t)
	t.Setenv(EnvBackend, "")
	t.Setenv(keystore.MnemonicURLsEnv, "")

	t.Run("caller's", func(t *testing.T) {
		t.Setenv(EnvPassphrase, "")
		os.Unsetenv(EnvPassphrase) // stdin is no terminal: the default fails
		p, err := LoadPayer(context.Background(), PayerOptions{Address: addr, Dir: dir, Passphrase: fixedPassphrase})
		if err != nil {
			t.Fatal(err)
		}
		if p.Signer.Address() != addr || p.Network != "testnet" {
			t.Errorf("got %s on %q, want %s on testnet", p.Signer.Address(), p.Network, addr)
		}
	})
	t.Run("environment's", func(t *testing.T) {
		t.Setenv(EnvPassphrase, "test passphrase")
		p, err := LoadPayer(context.Background(), PayerOptions{Address: addr, Dir: dir})
		if err != nil {
			t.Fatal(err)
		}
		if p.Signer.Address() != addr {
			t.Errorf("address = %s, want %s", p.Signer.Address(), addr)
		}
	})
}

type deadlineProbe struct{ deadline *time.Time }

func (d deadlineProbe) Mnemonics(ctx context.Context) ([]keystore.MnemonicEntry, error) {
	if dl, ok := ctx.Deadline(); ok {
		*d.deadline = dl
	}
	return nil, nil
}

func TestTimedProvider_BoundsTheLoad(t *testing.T) {
	var got time.Time
	start := time.Now()
	if _, err := (timedProvider{deadlineProbe{&got}}).Mnemonics(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d := got.Sub(start); got.IsZero() || d < keystore.LoadTimeout-time.Second || d > keystore.LoadTimeout+time.Second {
		t.Errorf("deadline %v after start, want about %v", got.Sub(start), keystore.LoadTimeout)
	}
}
