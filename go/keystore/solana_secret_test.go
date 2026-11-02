/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package keystore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/mnemonic"

	"github.com/TxnLab/zerosignal/go/solana"
)

// solanaSecretFixture is one key in each of Solana's own forms: a
// solana-keygen file's array, compact and as the tool writes it, and the
// base58 secret key a wallet exports.
type solanaSecretFixture struct {
	key      ed25519.PrivateKey
	addr     string
	array    string
	spaced   string
	exported string
}

func newSolanaSecretFixture(t *testing.T, seed byte) solanaSecretFixture {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	ints := make([]int, len(key))
	for i, b := range key {
		ints[i] = int(b)
	}
	raw, err := json.Marshal(ints)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := SolanaAddress(key)
	if err != nil {
		t.Fatal(err)
	}
	var sig solana.Signature
	copy(sig[:], key)
	return solanaSecretFixture{
		key:      key,
		addr:     addr,
		array:    string(raw),
		spaced:   "\n" + strings.ReplaceAll(string(raw), ",", ", ") + "\n",
		exported: sig.String(),
	}
}

// Each form loads the key itself, from any provider, beside a phrase.
func TestNewSolanaKeys_SecretKeyForms(t *testing.T) {
	ctx := context.Background()
	f := newSolanaSecretFixture(t, 3)
	for name, secret := range map[string]string{"array": f.array, "spaced array": f.spaced, "exported": f.exported} {
		ks, err := NewSolanaKeys(ctx, staticProvider{entries: []MnemonicEntry{{Name: "K", Mnemonic: secret}, {Name: "P", Mnemonic: keygen24}}})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !ks.HasAccount(f.addr) || !ks.HasAccount(keygen24Addr) || len(ks.Addresses()) != 2 {
			t.Fatalf("%s: addresses %v, want %s and %s", name, ks.Addresses(), f.addr, keygen24Addr)
		}
		msg := []byte("a message")
		sig, err := ks.Signer(f.addr).SignTransactionMessage(ctx, f.addr, msg)
		if err != nil || !bytes.Equal(sig, ed25519.Sign(f.key, msg)) {
			t.Fatalf("%s: signature %x, %v", name, sig, err)
		}
	}
}

// The forms reach the keystore as a phrase does: an env var, or a file the
// URL provider reads.
func TestLoadSolanaFromEnv_SecretKeyForms(t *testing.T) {
	isolateKeystoreEnv(t)
	f, g := newSolanaSecretFixture(t, 4), newSolanaSecretFixture(t, 5)
	path := filepath.Join(t.TempDir(), "node.json")
	if err := os.WriteFile(path, []byte(g.spaced), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NODE_SIGNING_MNEMONIC", f.exported)
	t.Setenv(MnemonicURLsEnv, "file=file://"+path+"?decoder=string")
	ks, err := LoadSolanaFromEnv(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !ks.HasAccount(f.addr) || !ks.HasAccount(g.addr) {
		t.Fatalf("addresses %v, want %s and %s", ks.Addresses(), f.addr, g.addr)
	}
}

// A malformed key fails the load naming its entry, and never quotes it.
func TestNewSolanaKeys_MalformedSecretKey(t *testing.T) {
	f := newSolanaSecretFixture(t, 6)
	other := newSolanaSecretFixture(t, 7)
	mismatched := append(append([]byte{}, f.key[:ed25519.SeedSize]...), other.key[ed25519.SeedSize:]...)
	var mismatchedExport solana.Signature
	copy(mismatchedExport[:], mismatched)
	mismatchedInts := make([]int, len(mismatched))
	for i, b := range mismatched {
		mismatchedInts[i] = int(b)
	}
	mismatchedArray, err := json.Marshal(mismatchedInts)
	if err != nil {
		t.Fatal(err)
	}
	short := f.array[:strings.LastIndex(f.array, ",")] + "]"
	for name, tc := range map[string]struct{ secret, want string }{
		"not json":          {"[1, 2, oops]", "not a keypair file's JSON array"},
		"out of range":      {"[" + strings.Repeat("1,", 63) + "256]", "is not a keypair file"},
		"short array":       {short, "holds 63 bytes"},
		"mismatched export": {mismatchedExport.String(), "not the seed's"},
		"mismatched array":  {string(mismatchedArray), "not the seed's"},
		"long array":        {"[0," + f.array[1:], "holds 65 bytes"},
		"cut export":        {f.exported[:60], "is base58 but not a 64-byte secret key"},
	} {
		_, err := NewSolanaKeys(context.Background(), staticProvider{entries: []MnemonicEntry{{Name: "BAD", Mnemonic: tc.secret}}})
		if err == nil || !strings.Contains(err.Error(), `"BAD"`) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want the entry and %q", name, err, tc.want)
			continue
		}
		if strings.Contains(err.Error(), tc.secret) || strings.Contains(err.Error(), "oops") {
			t.Errorf("%s: the error quotes the secret: %v", name, err)
		}
	}
}

// The Algorand keystore leaves a Solana key to NewSolanaKeys, as it leaves a
// Solana-only phrase, and names it when it is all there was.
func TestNew_SkipsSolanaSecretKeys(t *testing.T) {
	ctx := context.Background()
	f := newSolanaSecretFixture(t, 8)
	algo, err := mnemonic.FromPrivateKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	ks, err := New(ctx, staticProvider{entries: []MnemonicEntry{{Name: "A", Mnemonic: algo}, {Name: "J", Mnemonic: f.spaced}, {Name: "X", Mnemonic: f.exported}}})
	if err != nil || len(ks.Addresses()) != 1 {
		t.Fatalf("beside an Algorand mnemonic: %v, %v", ks, err)
	}
	_, err = New(ctx, staticProvider{entries: []MnemonicEntry{{Name: "ONLY", Mnemonic: f.exported}}})
	if err == nil || !strings.Contains(err.Error(), `"ONLY"`) || !strings.Contains(err.Error(), "Solana secret key") || strings.Contains(err.Error(), f.exported) {
		t.Fatalf("only a Solana key: %v", err)
	}
	// A malformed one is a typo, not a key for the other rail: it fails the
	// load beside a good mnemonic too, naming itself, not the skipped-key line.
	cut := f.exported[:60]
	_, err = New(ctx, staticProvider{entries: []MnemonicEntry{{Name: "A", Mnemonic: algo}, {Name: "CUT", Mnemonic: cut}}})
	if err == nil || !strings.Contains(err.Error(), `"CUT"`) || !strings.Contains(err.Error(), "not a 64-byte") || strings.Contains(err.Error(), cut) {
		t.Fatalf("a cut export: %v", err)
	}
}

// isolateKeystoreEnv blanks the caller's keys, which ProvidersFromEnv would
// otherwise load beside the test's.
func isolateKeystoreEnv(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasSuffix(name, "_MNEMONIC") {
			t.Setenv(name, "")
		}
	}
	t.Setenv(MnemonicURLsEnv, "")
}
