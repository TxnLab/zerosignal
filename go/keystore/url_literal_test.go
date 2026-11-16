/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package keystore

import (
	"context"
	"strings"
	"testing"

	"github.com/tyler-smith/go-bip39"
)

// solanaPhrase12 is a fresh 12-word phrase, which only the Solana keystore
// takes, and the address it loads as.
func solanaPhrase12(t *testing.T) (phrase, addr string) {
	t.Helper()
	entropy, err := bip39.NewEntropy(128)
	if err != nil {
		t.Fatal(err)
	}
	phrase, err = bip39.NewMnemonic(entropy)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := SolanaKeyFromPhrase(phrase)
	if err != nil {
		t.Fatal(err)
	}
	if addr, err = SolanaAddress(priv); err != nil {
		t.Fatal(err)
	}
	return phrase, addr
}

// One variable carries a node's keys for both rails, each rail's keystore
// taking its own and skipping the other's.
func TestURLProvider_LiteralCarriesEachRailsKey(t *testing.T) {
	algoMn, algoAddr := freshMnemonic(t)
	solMn, solAddr := solanaPhrase12(t)
	exported := newSolanaSecretFixture(t, 7)
	t.Setenv(MnemonicURLsEnv, "algo=literal:"+algoMn+", sol=literal:"+solMn+",solb=literal: "+exported.exported+" ")

	ks, err := LoadFromEnv(context.Background())
	if err != nil {
		t.Fatalf("LoadFromEnv: %v", err)
	}
	if !ks.HasAccount(algoAddr) {
		t.Errorf("the Algorand key is not loaded; addresses %v", ks.Addresses())
	}
	sol, err := LoadSolanaFromEnv(context.Background())
	if err != nil {
		t.Fatalf("LoadSolanaFromEnv: %v", err)
	}
	for _, addr := range []string{solAddr, exported.addr} {
		if !sol.HasAccount(addr) {
			t.Errorf("Solana key %s is not loaded; addresses %v", addr, sol.Addresses())
		}
	}
}

// Every backend's URL is fetched and named in errors; only what matches none
// is refused unread. A URL left off the list would refuse a working config.
func TestURLProvider_EveryBackendIsRecognized(t *testing.T) {
	for _, url := range []string{
		"awssecretsmanager://arn?region=us-east-1",
		"awsparamstore://path?region=us-east-1",
		"gcpsecretmanager://projects/p/secrets/s/versions/1",
		"azurekeyvault://v/s",
		"file:///etc/zs/key?decoder=string",
	} {
		if got := describe(url); got != url {
			t.Errorf("describe(%q) = %q; want the URL, as a backend's", url, got)
		}
	}
}

// The near misses an operator types load as the literal they meant.
func TestURLProvider_LiteralForgivesQuotesCaseAndSlashes(t *testing.T) {
	solMn, solAddr := solanaPhrase12(t)
	for _, entry := range []string{
		`"literal:` + solMn + `"`,
		`'literal:` + solMn + `'`,
		"Literal:" + solMn,
		"LITERAL: " + solMn,
		"literal://" + solMn,
	} {
		sol, err := NewSolanaKeys(context.Background(), NewURLProviderFromEnv("k="+entry))
		if err != nil {
			t.Errorf("%.12s…: %v", entry, err)
			continue
		}
		if !sol.HasAccount(solAddr) {
			t.Errorf("%.12s… loaded %v, want %s", entry, sol.Addresses(), solAddr)
		}
	}
}

// A literal entry is the secret, so a refusal names the entry and never
// prints its value.
func TestURLProvider_LiteralRefusalsNameTheEntryOnly(t *testing.T) {
	keypair := newSolanaSecretFixture(t, 9)
	algoMn, _ := freshMnemonic(t)
	words := strings.Fields(algoMn)
	for _, w := range words { // any other word breaks the checksum
		if w != words[24] {
			words[24] = w
			break
		}
	}
	badPhrase := strings.Join(words, " ")
	solMn, _ := solanaPhrase12(t)

	for _, tc := range []struct {
		name, env, want string
		solana          bool
		secret          string
	}{
		{name: "empty", env: "k=literal:  ", want: "empty"},
		// The array's commas split it, and its first piece must be refused,
		// not loaded.
		{name: "a keypair file's array", env: "k=literal:" + keypair.array, want: "base58", solana: true, secret: keypair.array},
		{name: "a keypair file's array after a space", env: "k=literal: " + keypair.array, want: "base58", solana: true, secret: keypair.array},
		{name: "a bad phrase", env: "k=literal:" + badPhrase, secret: badPhrase},
		// Long enough to read as base58 rather than as a one-word phrase.
		{name: "a bad secret key", env: "k=literal:" + keypair.exported[:60], want: "base58", solana: true, secret: keypair.exported[:60]},
		// Typos must not reach gocloud, whose error quotes the URL.
		{name: "a misspelt scheme", env: "k=literl:" + solMn, want: "neither a literal entry", solana: true, secret: solMn},
		{name: "a misspelt scheme with slashes", env: "k=lteral://" + solMn, want: "neither a literal entry", solana: true, secret: solMn},
		{name: "no scheme", env: "k=" + solMn, want: "neither a literal entry", solana: true, secret: solMn},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := NewURLProviderFromEnv(tc.env)
			var err error
			if tc.solana {
				_, err = NewSolanaKeys(context.Background(), p)
			} else {
				_, err = New(context.Background(), p)
			}
			if err == nil {
				t.Fatal("loaded")
			}
			msg := err.Error()
			if !strings.Contains(msg, `"k"`) && !strings.Contains(msg, "k (literal)") && !strings.Contains(msg, "k (unrecognized)") {
				t.Errorf("error %q does not name the entry", msg)
			}
			if tc.want != "" && !strings.Contains(msg, tc.want) {
				t.Errorf("error %q does not say %q", msg, tc.want)
			}
			// The URL is the secret: printing it at all prints the scheme.
			if leaks(msg, tc.secret) || strings.Contains(msg, LiteralScheme) {
				t.Errorf("error %q prints the secret", msg)
			}
		})
	}
}

// leaks reports whether msg carries any two adjacent words of secret, or for
// a one-word secret any 8 characters of it.
func leaks(msg, secret string) bool {
	w := strings.FieldsFunc(secret, func(r rune) bool { return r == ' ' || r == ',' || r == '[' || r == ']' })
	if len(w) == 1 {
		for i := 0; i+8 <= len(w[0]); i++ {
			if strings.Contains(msg, w[0][i:i+8]) {
				return true
			}
		}
		return false
	}
	for i := 0; i+1 < len(w); i++ {
		if strings.Contains(msg, w[i]+" "+w[i+1]) || strings.Contains(msg, w[i]+","+w[i+1]) {
			return true
		}
	}
	return false
}
