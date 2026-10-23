/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package keystore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/mnemonic"
	bip39 "github.com/tyler-smith/go-bip39"
)

type slip10Case struct {
	Seed      string   `json:"seed"`
	Path      []uint32 `json:"path"` // indices, each taken hardened
	ChainCode string   `json:"chain_code"`
	Private   string   `json:"private"`
}

// slip10SpecCases are SLIP-0010's Ed25519 test vectors, as published; the
// derivation must reproduce them before the file records them for TS. The
// last row gives an index with its hardened bit already set, which must
// derive the same child as without it.
func slip10SpecCases(t *testing.T) []slip10Case {
	const seed1 = "000102030405060708090a0b0c0d0e0f"
	const seed2 = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
	cases := []slip10Case{
		{seed1, nil, "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb", "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7"},
		{seed1, []uint32{0}, "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69", "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3"},
		{seed1, []uint32{0, 1}, "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14", "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2"},
		{seed1, []uint32{0, 1, 2}, "2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c", "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9"},
		{seed1, []uint32{0, 1, 2, 2}, "8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc", "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662"},
		{seed1, []uint32{0, 1, 2, 2, 1000000000}, "68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230", "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793"},
		{seed2, nil, "ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b", "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012"},
		{seed2, []uint32{0}, "0b78a3226f915c082bf118f83618a618ab6dec793752624cbeb622acb562862d", "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635"},
		{seed2, []uint32{0, 2147483647}, "138f0b2551bcafeca6ff2aa88ba8ed0ed8de070841f0c4ef0165df8181eaad7f", "ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4"},
		{seed2, []uint32{0, 2147483647, 1}, "73bd9fff1cfbde33a1b846c27085f711c0fe2d66fd32e139d3ebc28e5a4a6b90", "3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c"},
		{seed2, []uint32{0, 2147483647, 1, 2147483646}, "0902fe8a29f9140480a00ef244bd183e8a13288e4412d8389d140aac1794825a", "5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72"},
		{seed2, []uint32{0, 2147483647, 1, 2147483646, 2}, "5d70af781f3a37b829f0d060924d5e960bdc02e85423494afc0b1a41bbe196d4", "551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d"},
		{seed1, []uint32{hardened, hardened | 1}, "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14", "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2"},
	}
	for _, c := range cases {
		seed, err := hex.DecodeString(c.Seed)
		if err != nil {
			t.Fatal(err)
		}
		key, chain := Slip10Ed25519(seed, c.Path)
		if hex.EncodeToString(key[:]) != c.Private || hex.EncodeToString(chain[:]) != c.ChainCode {
			t.Fatalf("SLIP-0010 %s %v: key %x chain %x", c.Seed[:8], c.Path, key, chain)
		}
	}
	return cases
}

type solanaCase struct {
	Name       string             `json:"name"`
	Phrase     string             `json:"phrase"`
	Refused    bool               `json:"refused"`
	Seed       string             `json:"seed,omitempty"` // hex, the first 32 bytes of the 64-byte secret key a wallet exports
	Address    string             `json:"address,omitempty"`
	Signatures []accountSignature `json:"signatures,omitempty"`
}

// Addresses checked outside this code, at m/44'/501'/0'/0' with an empty
// passphrase: the keygen phrases, the client's phrase and the zero-entropy
// phrase by `solana-keygen pubkey 'prompt://?key=0/0'` (solana-keygen 4.3.0), which
// is what Phantom and Solflare show for them. Literals, so -update can't
// rewrite them.
const (
	keygen24     = "slide loan surge jeans hire list holiday patch unhappy essay lazy review undo vast oppose misery wisdom catalog student emotion liar relax turkey oyster"
	keygen24Addr = "7ypU3K9G87jxTuH7GmTixaqYicEEbxEfTPZKv5q2FYKi"
	keygen12     = "obey wheat crystal ramp when return crystal canvas ill stool bless pioneer"
	keygen12Addr = "AP1k11z7aJL7aibKqwkaNFpxBsSHRNReAxnToZeXqY2Q"
	zero12Addr   = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"
	clientAddr   = "5Pobwp6d9ihN9Nz38f87gVCEBFMgipFiSM2VtUhVit6w"
)

func swapLast(m, w string) string {
	f := strings.Fields(m)
	f[len(f)-1] = w
	return strings.Join(f, " ")
}

func solanaCases(t *testing.T, clientPhrase, algo25 string, fullWidth func(string) string, msgs [][]byte) []solanaCase {
	ofEntropy := func(n int) string {
		m, err := bip39.NewMnemonic(bytes.Repeat([]byte{0x5a}, n))
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	in := []solanaCase{
		{Name: "solana-keygen 24 words", Phrase: keygen24},
		{Name: "solana-keygen 12 words", Phrase: keygen12},
		// The phrase the client exports for its passkey wallet: its Solana
		// account is this one, beside the xHD Algorand account in cases.
		{Name: "client vector", Phrase: clientPhrase},
		{Name: "12 words all-zero entropy", Phrase: strings.Repeat("abandon ", 11) + "about"},
		{Name: "15 words", Phrase: ofEntropy(20)},
		{Name: "18 words", Phrase: ofEntropy(24)},
		{Name: "21 words", Phrase: ofEntropy(28)},
		{Name: "double space and newline", Phrase: strings.ReplaceAll(keygen24, " ", "  \n")},

		{Name: "bad checksum", Phrase: swapLast(keygen24, "zoo")},
		{Name: "unknown word", Phrase: swapLast(keygen12, "zzzz")},
		{Name: "13 words", Phrase: keygen12 + " abandon"},
		{Name: "algorand-25", Phrase: algo25},
		{Name: "upper case", Phrase: strings.ToUpper(keygen12)},
		{Name: "full-width letters", Phrase: fullWidth(keygen12)},
		{Name: "empty", Phrase: ""},
	}
	ctx := context.Background()
	for i := range in {
		c := &in[i]
		priv, err := SolanaKeyFromPhrase(c.Phrase)
		if err != nil {
			c.Refused = true
			continue
		}
		addr, err := SolanaAddress(priv)
		if err != nil {
			t.Fatal(err)
		}
		c.Seed, c.Address = hex.EncodeToString(priv.Seed()), addr
		ks, err := NewSolanaKeys(ctx, staticProvider{entries: []MnemonicEntry{{Name: "V", Mnemonic: c.Phrase}}})
		if err != nil {
			t.Fatalf("%s: NewSolanaKeys: %v", c.Name, err)
		}
		for _, m := range msgs {
			sig, err := ks.SignBytes(ctx, c.Address, m)
			if err != nil {
				t.Fatalf("%s: SignBytes: %v", c.Name, err)
			}
			c.Signatures = append(c.Signatures, accountSignature{Msg: hex.EncodeToString(m), Sig: hex.EncodeToString(sig)})
		}
	}
	for name, want := range map[string]string{
		"solana-keygen 24 words":    keygen24Addr,
		"solana-keygen 12 words":    keygen12Addr,
		"12 words all-zero entropy": zero12Addr,
		"client vector":             clientAddr,
	} {
		found := false
		for _, c := range in {
			if c.Name == name {
				found = true
				if c.Address != want {
					t.Fatalf("%s: %q, solana-keygen gives %q", c.Name, c.Address, want)
				}
			}
		}
		if !found {
			t.Fatalf("no %q row to pin", name)
		}
	}
	return in
}

// A Solana store skips Algorand's 25-word mnemonics, which no Solana wallet
// derives, and refuses a broken BIP-39 phrase without quoting it.
func TestNewSolanaKeys(t *testing.T) {
	ctx := context.Background()
	algo, err := mnemonic.FromPrivateKey(ed25519.NewKeyFromSeed(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	ks, err := NewSolanaKeys(ctx, staticProvider{entries: []MnemonicEntry{
		{Name: "A", Mnemonic: algo},
		{Name: "S", Mnemonic: keygen24},
		{Name: "S2", Mnemonic: "  " + keygen24},
		{Name: "E", Mnemonic: ""},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if got := ks.Addresses(); len(got) != 1 || got[0] != keygen24Addr || !ks.HasAccount(keygen24Addr) {
		t.Fatalf("addresses %v", got)
	}
	if _, err := ks.SignBytes(ctx, keygen12Addr, nil); err == nil {
		t.Fatal("signed for an address it doesn't hold")
	}
	if _, err := ks.SignTransactionMessage(ctx, keygen12Addr, nil); err == nil {
		t.Fatal("signed a transaction for an address it doesn't hold")
	}
	// A transaction's signature is the same raw Ed25519 over its message.
	priv, err := SolanaKeyFromPhrase(keygen24)
	if err != nil {
		t.Fatal(err)
	}
	signer := ks.Signer(keygen24Addr)
	msg := []byte("a message")
	sig, err := signer.SignTransactionMessage(ctx, signer.Address(), msg)
	if err != nil || !bytes.Equal(sig, ed25519.Sign(priv, msg)) {
		t.Fatalf("transaction signature %x, %v", sig, err)
	}

	// A chosen signer signs as its own address alone, even one the store holds.
	both, err := NewSolanaKeys(ctx, staticProvider{entries: []MnemonicEntry{{Name: "A", Mnemonic: keygen24}, {Name: "B", Mnemonic: keygen12}}})
	if err != nil {
		t.Fatal(err)
	}
	one := both.Signer(keygen24Addr)
	if _, err := one.SignTransactionMessage(ctx, keygen12Addr, msg); err == nil {
		t.Fatal("signed a transaction as another held account")
	}
	if _, err := one.SignBytes(ctx, keygen12Addr, msg); err == nil {
		t.Fatal("signed bytes as another held account")
	}
	if _, err := one.SignBytes(ctx, keygen24Addr, msg); err != nil {
		t.Fatal(err)
	}
	_, err = NewSolanaKeys(ctx, staticProvider{entries: []MnemonicEntry{{Name: "B", Mnemonic: swapLast(keygen12, "zoo")}}})
	if err == nil || strings.Contains(err.Error(), "obey") || strings.Count(err.Error(), "keystore:") != 1 {
		t.Fatalf("a bad phrase: %v", err)
	}

	// Algorand mnemonics and nothing else fail the load, naming the first, as
	// New fails on Solana phrases and nothing else.
	_, err = NewSolanaKeys(ctx, staticProvider{entries: []MnemonicEntry{{Name: "ALGO", Mnemonic: algo}, {Name: "E", Mnemonic: ""}}})
	if err == nil || !strings.Contains(err.Error(), `"ALGO"`) || !strings.Contains(err.Error(), "has no Solana key") {
		t.Fatalf("only an Algorand mnemonic: %v", err)
	}
	if ks, err := NewSolanaKeys(ctx); err != nil || len(ks.Addresses()) != 0 {
		t.Fatalf("no providers: %v %v", ks, err)
	}
}

// The Algorand store and the Solana store read one provider chain, so each
// leaves the other's phrases alone rather than failing the load: a 12-word
// Phantom phrase beside an Algorand mnemonic loads one account in each.
func TestStoresShareProviders(t *testing.T) {
	ctx := context.Background()
	algo, err := mnemonic.FromPrivateKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	p := staticProvider{entries: []MnemonicEntry{{Name: "ALGO", Mnemonic: algo}, {Name: "SOL", Mnemonic: keygen12}}}
	ks, err := New(ctx, p)
	if err != nil {
		t.Fatalf("New with a 12-word phrase: %v", err)
	}
	if len(ks.Addresses()) != 1 {
		t.Fatalf("Algorand addresses %v", ks.Addresses())
	}
	sol, err := NewSolanaKeys(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	if got := sol.Addresses(); len(got) != 1 || got[0] != keygen12Addr {
		t.Fatalf("Solana addresses %v", got)
	}
	for _, n := range []int{20, 24, 28} { // 15, 18 and 21 words
		m, err := bip39.NewMnemonic(bytes.Repeat([]byte{0x5a}, n))
		if err != nil {
			t.Fatal(err)
		}
		mixed := staticProvider{entries: []MnemonicEntry{{Name: "ALGO", Mnemonic: algo}, {Name: "SOL", Mnemonic: m}}}
		if ks, err := New(ctx, mixed); err != nil || len(ks.Addresses()) != 1 {
			t.Fatalf("New beside %d entropy bytes: %v", n, err)
		}
	}
	for name, m := range map[string]string{
		// A count that is neither form.
		"13 words": keygen12 + " abandon",
		// A Solana length that isn't valid BIP-39 is a typo, not a phrase to skip.
		"bad checksum": swapLast(keygen12, "zoo"),
		"12 × abandon": strings.TrimSpace(strings.Repeat("abandon ", 12)),
		"unknown word": swapLast(keygen12, "zzzz"),
	} {
		mixed := staticProvider{entries: []MnemonicEntry{{Name: "ALGO", Mnemonic: algo}, {Name: "X", Mnemonic: m}}}
		if _, err := New(ctx, mixed); err == nil {
			t.Fatalf("New accepted %s", name)
		}
	}
	// Only a Solana phrase where an Algorand key was wanted: a startup error
	// that names it, not an empty store.
	_, err = New(ctx, staticProvider{entries: []MnemonicEntry{{Name: "PAYMENT", Mnemonic: keygen12}}})
	if err == nil || !strings.Contains(err.Error(), `"PAYMENT"`) || !strings.Contains(err.Error(), "12-word") || strings.Contains(err.Error(), "obey") {
		t.Fatalf("New with only a Solana phrase: %v", err)
	}
}
