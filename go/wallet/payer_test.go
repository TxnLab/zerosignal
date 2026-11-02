/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package wallet

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/mnemonic"
	"github.com/tyler-smith/go-bip39"

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

	// A phrase spaced by newlines also loads its legacy address, signable but
	// unlisted, which a config written before the canonical spacing names.
	legacyPhrase := strings.ReplaceAll(env[0].Mnemonic, " ", "\n")
	legacyAddr, ok := keystore.LegacySpacingAddress(legacyPhrase)
	if !ok || legacyAddr == envAddr {
		t.Fatalf("no legacy address for the newline-spaced phrase: %q", legacyAddr)
	}
	legacyEnv := staticKeys{{Name: "LEGACY", Mnemonic: legacyPhrase}}

	tests := []struct {
		name        string
		dir         string
		env         staticKeys
		address     string
		wantAddr    string
		wantNetwork string
		wantErr     string
		wantIs      error
	}{
		{name: "wallet only", dir: walletDir, wantAddr: walletAddr, wantNetwork: "testnet"},
		{name: "env only", dir: t.TempDir(), env: env, wantAddr: envAddr},
		{name: "both, unchosen", dir: walletDir, env: env, wantErr: "2 keys loaded", wantIs: ErrPayerUnchosen},
		{name: "both, wallet chosen", dir: walletDir, env: env, address: walletAddr, wantAddr: walletAddr, wantNetwork: "testnet"},
		// The wallet's network says nothing about a key it does not hold.
		{name: "both, env chosen", dir: walletDir, env: env, address: envAddr, wantAddr: envAddr},
		{name: "chosen not loaded", dir: walletDir, address: envAddr, wantErr: "not among the loaded keys", wantIs: ErrPayerNotLoaded},
		{name: "a legacy address chosen", dir: t.TempDir(), env: legacyEnv, address: legacyAddr, wantAddr: legacyAddr},
		{name: "the legacy phrase unchosen pays canonically", dir: t.TempDir(), env: legacyEnv, wantAddr: envAddr},
		// The wallet's own phrase in the environment is still the wallet's key.
		{name: "wallet key also in env", dir: walletDir, env: sameKey, wantAddr: walletAddr, wantNetwork: "testnet"},
		// A wallet that will not open must not hand payment to another key.
		{name: "broken wallet", dir: brokenDir, env: env, wantErr: "open wallet"},
		{name: "none", dir: t.TempDir(), wantErr: "no keys loaded: none from a wallet in", wantIs: ErrNoKeys},
		// Nothing loaded says so, rather than that the one asked for is missing.
		{name: "none, one asked for", dir: t.TempDir(), address: envAddr, wantErr: "no keys loaded", wantIs: ErrNoKeys},
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
				if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
					t.Errorf("err = %v, want it to match %v", err, tt.wantIs)
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

// solanaAddr is the address a phrase pays as on Solana.
func solanaAddr(t *testing.T, phrase string) string {
	t.Helper()
	priv, err := keystore.SolanaKeyFromPhrase(phrase)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := keystore.SolanaAddress(priv)
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

// The Solana loader opens the same wallet and environment as LoadPayer and
// chooses among the same phrases' Solana keys.
func TestLoadSolanaPayer(t *testing.T) {
	walletDir, walletAlgoAddr := fileWallet(t)
	w, err := Open(walletDir, fileOpts())
	if err != nil {
		t.Fatal(err)
	}
	walletPhrase, err := w.Export()
	if err != nil {
		t.Fatal(err)
	}
	walletAddr := solanaAddr(t, walletPhrase)
	env, _ := envKey(t)
	envAddr := solanaAddr(t, env[0].Mnemonic)
	sameKey := staticKeys{{Name: "SAME", Mnemonic: walletPhrase}}
	// A Phantom export: 12 words, which only the Solana store takes.
	phantom, err := bip39.NewMnemonic(bytes.Repeat([]byte{0x3c}, 16))
	if err != nil {
		t.Fatal(err)
	}
	phantomEnv := staticKeys{{Name: "PHANTOM", Mnemonic: phantom}}
	phantomAddr := solanaAddr(t, phantom)

	algoDir, _ := algoWallet(t)

	brokenDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(brokenDir, metaFile), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		dir      string
		env      staticKeys
		address  string
		wantAddr string
		wantErr  string
		wantIs   error
	}{
		{name: "wallet only", dir: walletDir, wantAddr: walletAddr},
		{name: "env only", dir: t.TempDir(), env: env, wantAddr: envAddr},
		{name: "both, unchosen", dir: walletDir, env: env, wantErr: "2 keys loaded", wantIs: ErrPayerUnchosen},
		{name: "both, env chosen", dir: walletDir, env: env, address: envAddr, wantAddr: envAddr},
		// The Algorand address of the same phrase is not a Solana key.
		{name: "chosen by its Algorand address", dir: walletDir, address: walletAlgoAddr, wantErr: "is not a Solana address", wantIs: ErrPayerNotLoaded},
		{name: "a Solana address not loaded", dir: walletDir, address: envAddr, wantErr: "not among the loaded keys", wantIs: ErrPayerNotLoaded},
		{name: "wallet key also in env", dir: walletDir, env: sameKey, wantAddr: walletAddr},
		{name: "a 12-word env phrase beside the wallet", dir: walletDir, env: phantomEnv, address: phantomAddr, wantAddr: phantomAddr},
		{name: "broken wallet", dir: brokenDir, env: env, wantErr: "open wallet"},
		{name: "an Algorand wallet has no Solana key", dir: algoDir, wantErr: "the wallet holds a 25-word Algorand mnemonic, which has no Solana key", wantIs: ErrWalletNoSolanaKey},
		{name: "an Algorand wallet beside an env key", dir: algoDir, env: env, wantAddr: envAddr},
		{name: "none", dir: t.TempDir(), wantErr: "no keys loaded", wantIs: ErrNoKeys},
		// An Algorand address with nothing loaded is told nothing loaded.
		{name: "none, an Algorand address asked for", dir: t.TempDir(), address: walletAlgoAddr, wantErr: "no keys loaded", wantIs: ErrNoKeys},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kr := KeyringOptions{Backend: noBackend, Passphrase: fixedPassphrase}
			p, err := loadSolanaPayer(context.Background(), PayerOptions{Address: tt.address, Dir: tt.dir},
				kr, []keystore.SecretProvider{tt.env})
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, tt.wantErr)
				}
				if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
					t.Errorf("err = %v, want it to match %v", err, tt.wantIs)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := p.Signer.Address(); got != tt.wantAddr {
				t.Errorf("address = %s, want %s", got, tt.wantAddr)
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

// LoadSolanaPayer itself, through the public path: the environment's
// passphrase unlocks the wallet, whose phrase pays as its Solana address.
func TestLoadSolanaPayer_Public(t *testing.T) {
	dir, _ := fileWallet(t)
	w, err := Open(dir, fileOpts())
	if err != nil {
		t.Fatal(err)
	}
	phrase, err := w.Export()
	if err != nil {
		t.Fatal(err)
	}
	addr := solanaAddr(t, phrase)
	t.Setenv(EnvBackend, "")
	t.Setenv(keystore.MnemonicURLsEnv, "")
	t.Setenv(EnvPassphrase, "test passphrase")
	p, err := LoadSolanaPayer(context.Background(), PayerOptions{Address: addr, Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if p.Signer.Address() != addr {
		t.Errorf("address = %s, want %s", p.Signer.Address(), addr)
	}
}

// algoWallet is a wallet holding a 25-word Algorand mnemonic, and that phrase.
func algoWallet(t *testing.T) (dir, phrase string) {
	t.Helper()
	dir = t.TempDir()
	w, err := Open(dir, fileOpts())
	if err != nil {
		t.Fatal(err)
	}
	phrase, err = mnemonic.FromPrivateKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Import(phrase, "testnet", false); err != nil {
		t.Fatal(err)
	}
	return dir, phrase
}

// A 25-word wallet with nothing else to load is ErrNoSolanaKey with the
// advice to back it up; the same phrase from the environment is
// ErrNoSolanaKey without it, since there is no wallet to replace.
func TestLoadSolanaKeys_NoSolanaKey(t *testing.T) {
	dir, phrase := algoWallet(t)
	kr := KeyringOptions{Backend: noBackend, Passphrase: fixedPassphrase}

	_, _, err := loadSolanaKeys(context.Background(), PayerOptions{Dir: dir}, kr, nil)
	if !errors.Is(err, ErrWalletNoSolanaKey) || !errors.Is(err, ErrNoSolanaKey) || !strings.Contains(err.Error(), "Back it up first") {
		t.Errorf("25-word wallet: %v, want ErrWalletNoSolanaKey with the backup advice", err)
	}
	_, _, err = loadSolanaKeys(context.Background(), PayerOptions{Dir: t.TempDir()}, kr,
		[]keystore.SecretProvider{staticKeys{{Name: "ALGO", Mnemonic: phrase}}})
	if !errors.Is(err, ErrNoSolanaKey) || errors.Is(err, ErrWalletNoSolanaKey) || strings.Contains(err.Error(), "Back it up") {
		t.Errorf("25-word env phrase: %v, want ErrNoSolanaKey without the wallet's error or advice", err)
	}
	// A 24-word wallet beside a 25-word env phrase: the env phrase is skipped
	// and the wallet loads.
	walletDir, _ := fileWallet(t)
	_, sk, err := loadSolanaKeys(context.Background(), PayerOptions{Dir: walletDir}, kr,
		[]keystore.SecretProvider{staticKeys{{Name: "ALGO", Mnemonic: phrase}}})
	if err != nil || len(sk.Addresses()) != 1 {
		t.Errorf("24-word wallet beside a 25-word env phrase: %v %v", sk, err)
	}
}

// fakeKeys lists listed and can also sign for unlisted.
type fakeKeys struct{ listed, unlisted []string }

func (k fakeKeys) Addresses() []string { return k.listed }
func (k fakeKeys) HasAccount(a string) bool {
	return slices.Contains(k.listed, a) || slices.Contains(k.unlisted, a)
}

func TestChoosePayer(t *testing.T) {
	const a, b, twin = "AAAA", "BBBB", "TWIN"
	tests := []struct {
		name    string
		want    string
		keys    fakeKeys
		got     string
		wantErr error
	}{
		{name: "the one asked for", want: b, keys: fakeKeys{listed: []string{a, b}}, got: b},
		{name: "the only one", keys: fakeKeys{listed: []string{a}}, got: a},
		// A signable, unlisted address is honored when asked for, and never
		// taken unasked.
		{name: "an unlisted twin asked for", want: twin, keys: fakeKeys{listed: []string{a}, unlisted: []string{twin}}, got: twin},
		{name: "an unlisted twin unasked", keys: fakeKeys{listed: []string{a}, unlisted: []string{twin}}, got: a},
		{name: "asked for, not loaded", want: b, keys: fakeKeys{listed: []string{a}}, wantErr: ErrPayerNotLoaded},
		{name: "two, none asked for", keys: fakeKeys{listed: []string{a, b}}, wantErr: ErrPayerUnchosen},
		{name: "none", wantErr: ErrNoKeys},
		{name: "none, one asked for", want: a, wantErr: ErrNoKeys},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ChoosePayer(tt.want, tt.keys)
			if !errors.Is(err, tt.wantErr) || got != tt.got {
				t.Errorf("ChoosePayer = %q, %v; want %q, %v", got, err, tt.got, tt.wantErr)
			}
			// A host branches on these, so a refusal matches its own alone.
			for _, other := range []error{ErrNoKeys, ErrPayerNotLoaded, ErrPayerUnchosen} {
				if other != tt.wantErr && errors.Is(err, other) {
					t.Errorf("%v also matches %v", err, other)
				}
			}
		})
	}
}

func TestChooseSolanaPayer(t *testing.T) {
	sol := "11111111111111111111111111111111"
	other := "SysvarC1ock11111111111111111111111111111111"
	algo := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	one := fakeKeys{listed: []string{sol}}

	got, err := ChooseSolanaPayer(sol, fakeKeys{listed: []string{other, sol}})
	if err != nil || got != sol {
		t.Errorf("a loaded Solana address: %q, %v", got, err)
	}
	// An Algorand address is refused as one, naming the keys to choose from.
	_, err = ChooseSolanaPayer(algo, one)
	if !errors.Is(err, ErrPayerNotLoaded) || !strings.Contains(err.Error(), "not a Solana address") || !strings.Contains(err.Error(), sol) {
		t.Errorf("an Algorand address: %v", err)
	}
	_, err = ChooseSolanaPayer(other, one)
	if !errors.Is(err, ErrPayerNotLoaded) || strings.Contains(err.Error(), "not a Solana address") {
		t.Errorf("a Solana address not loaded: %v", err)
	}
	if got, err := ChooseSolanaPayer("", one); err != nil || got != sol {
		t.Errorf("none asked for: %q, %v", got, err)
	}
	if _, err := ChooseSolanaPayer(algo, fakeKeys{}); !errors.Is(err, ErrNoKeys) {
		t.Errorf("an Algorand address with nothing loaded: %v, want ErrNoKeys", err)
	}
}

// A wallet the host opened is loaded in place of Dir's, which is never
// opened: here Dir's descriptor is broken, so opening it would fail.
func TestLoadPayer_OpenedWallet(t *testing.T) {
	walletDir, walletAddr := fileWallet(t)
	w, err := Open(walletDir, fileOpts())
	if err != nil {
		t.Fatal(err)
	}
	brokenDir := t.TempDir()
	writeDescriptor(t, brokenDir, "{not json")
	kr := KeyringOptions{Backend: noBackend, Passphrase: fixedPassphrase}

	p, err := loadPayer(context.Background(), PayerOptions{Dir: brokenDir, Wallet: w}, kr, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Signer.Address() != walletAddr || p.Network != "testnet" {
		t.Errorf("got %s on %q, want %s on testnet", p.Signer.Address(), p.Network, walletAddr)
	}
	// The environment's keys load beside it, as beside a wallet in Dir.
	env, envAddr := envKey(t)
	_, _, ks, err := loadKeys(context.Background(), PayerOptions{Wallet: w}, kr, []keystore.SecretProvider{env})
	if err != nil {
		t.Fatal(err)
	}
	if got := ks.Addresses(); !slices.Contains(got, walletAddr) || !slices.Contains(got, envAddr) {
		t.Errorf("opened wallet beside an env key loaded %v, want %s and %s", got, walletAddr, envAddr)
	}
	// An opened wallet that holds nothing is an error, not an env-only load.
	empty, err := Open(t.TempDir(), fileOpts())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadPayer(context.Background(), PayerOptions{Wallet: empty}, kr, []keystore.SecretProvider{env}); err == nil {
		t.Error("an empty opened wallet loaded the env key")
	}
}

// EnvKeys stand in for the environment, which is not read again, and
// LoadKeys returns every key unchosen.
func TestLoadKeys_EnvKeys(t *testing.T) {
	walletDir, walletAddr := fileWallet(t)
	set, setAddr := envKey(t)
	passed, passedAddr := envKey(t)
	t.Setenv(EnvBackend, "")
	t.Setenv(keystore.MnemonicURLsEnv, "")
	t.Setenv(EnvPassphrase, "test passphrase")
	t.Setenv("ZSTEST_MNEMONIC", set[0].Mnemonic)
	// The keystore drops only an exactly-empty mnemonic; a whitespace one is
	// no key either, so it must not count toward the keys a host sees.
	t.Setenv("ZSTEST_BLANK_MNEMONIC", "  \t")

	read, err := ReadEnvKeys(context.Background())
	if err != nil || len(read.Entries) != 1 || read.Entries[0].Mnemonic != set[0].Mnemonic {
		t.Fatalf("ReadEnvKeys = %+v, %v; want the one ZSTEST_MNEMONIC", read, err)
	}

	ks, err := LoadKeys(context.Background(), PayerOptions{Dir: walletDir, EnvKeys: &EnvKeys{Entries: passed}})
	if err != nil {
		t.Fatal(err)
	}
	got := ks.Addresses()
	if !slices.Contains(got, walletAddr) || !slices.Contains(got, passedAddr) || slices.Contains(got, setAddr) || len(got) != 2 {
		t.Errorf("loaded %v; want the wallet's %s and the passed %s, not the environment's %s", got, walletAddr, passedAddr, setAddr)
	}
	// Empty is no environment keys, not a reason to read it.
	ks, err = LoadKeys(context.Background(), PayerOptions{Dir: walletDir, EnvKeys: &EnvKeys{}})
	if err != nil || !slices.Equal(ks.Addresses(), []string{walletAddr}) {
		t.Errorf("empty EnvKeys loaded %v, %v; want the wallet's alone", ks.Addresses(), err)
	}
	// nil reads the environment.
	ks, err = LoadKeys(context.Background(), PayerOptions{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(ks.Addresses(), setAddr) {
		t.Errorf("nil EnvKeys loaded %v, want the environment's %s", ks.Addresses(), setAddr)
	}
}

type deadlineProbe struct{ deadline *time.Time }

func (d deadlineProbe) Mnemonics(ctx context.Context) ([]keystore.MnemonicEntry, error) {
	if dl, ok := ctx.Deadline(); ok {
		*d.deadline = dl
	}
	return nil, nil
}

// ReadEnvKeys bounds each source as the load does, so a hung cloud secret
// fails the read rather than block the host.
func TestReadEnvKeys_BoundsEachSource(t *testing.T) {
	var got time.Time
	start := time.Now()
	if _, err := readEnvKeys(context.Background(), []keystore.SecretProvider{deadlineProbe{&got}}); err != nil {
		t.Fatal(err)
	}
	if d := got.Sub(start); got.IsZero() || d < keystore.LoadTimeout-time.Second || d > keystore.LoadTimeout+time.Second {
		t.Errorf("deadline %v after start, want about %v", d, keystore.LoadTimeout)
	}
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
