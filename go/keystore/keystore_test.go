/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package keystore

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/mnemonic"

	"github.com/TxnLab/zerosignal/go/ticket"
)

// staticProvider returns a fixed slice of MnemonicEntry — used to avoid
// any I/O in tests. Errors propagate through KeyStore.New.
type staticProvider struct {
	entries []MnemonicEntry
	err     error
}

func (s staticProvider) Mnemonics(_ context.Context) ([]MnemonicEntry, error) {
	return s.entries, s.err
}

// freshMnemonic generates a brand-new Algorand keypair and returns the
// 25-word mnemonic plus the derived address. A new mnemonic per call
// keeps tests independent.
func freshMnemonic(t *testing.T) (mn, addr string) {
	t.Helper()
	_, _, priv, err := ticket.GenerateAlgorandKeypair()
	if err != nil {
		t.Fatal(err)
	}
	mn, err = mnemonic.FromPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	account, err := crypto.AccountFromPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return mn, account.Address.String()
}

func TestKeyStore_LoadsAcrossProviders(t *testing.T) {
	mn1, addr1 := freshMnemonic(t)
	mn2, addr2 := freshMnemonic(t)

	ks, err := New(context.Background(),
		staticProvider{entries: []MnemonicEntry{{Name: "A", Mnemonic: mn1}}},
		staticProvider{entries: []MnemonicEntry{{Name: "B", Mnemonic: mn2}}},
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !ks.HasAccount(addr1) {
		t.Errorf("missing addr1 %s", addr1)
	}
	if !ks.HasAccount(addr2) {
		t.Errorf("missing addr2 %s", addr2)
	}
	if got := ks.Addresses(); len(got) != 2 {
		t.Errorf("Addresses() = %v, want 2", got)
	}
}

func TestKeyStore_SkipsEmptyAndNilProviders(t *testing.T) {
	mn, addr := freshMnemonic(t)
	ks, err := New(context.Background(),
		nil,
		staticProvider{entries: []MnemonicEntry{
			{Name: "EMPTY", Mnemonic: ""},
			{Name: "WHITESPACE", Mnemonic: "   "},
			{Name: "REAL", Mnemonic: mn},
		}},
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !ks.HasAccount(addr) {
		t.Fatalf("REAL not loaded")
	}
	if got := len(ks.Addresses()); got != 1 {
		t.Errorf("Addresses count = %d, want 1", got)
	}
}

func TestKeyStore_PropagatesProviderError(t *testing.T) {
	wantErr := errors.New("provider boom")
	_, err := New(context.Background(), staticProvider{err: wantErr})
	if err == nil || !strings.Contains(err.Error(), "provider boom") {
		t.Fatalf("err = %v, want wrapping of %v", err, wantErr)
	}
}

func TestKeyStore_RejectsBadMnemonic(t *testing.T) {
	_, err := New(context.Background(), staticProvider{entries: []MnemonicEntry{
		{Name: "BAD", Mnemonic: "this is not a real algorand mnemonic at all not even close"},
	}})
	if err == nil {
		t.Fatal("want error on bad mnemonic")
	}
}

func TestKeyStore_DuplicateAddressIsTolerated(t *testing.T) {
	mn, addr := freshMnemonic(t)
	ks, err := New(context.Background(), staticProvider{entries: []MnemonicEntry{
		{Name: "FIRST", Mnemonic: mn},
		{Name: "SECOND", Mnemonic: mn},
	}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := len(ks.Addresses()); got != 1 {
		t.Errorf("Addresses count = %d, want 1 (dup deduped)", got)
	}
	if !ks.HasAccount(addr) {
		t.Fatalf("addr missing")
	}
}

func TestKeyStore_SignBytes_VerifiesAgainstAddress(t *testing.T) {
	mn, addr := freshMnemonic(t)
	ks, err := New(context.Background(), staticProvider{entries: []MnemonicEntry{{Name: "X", Mnemonic: mn}}})
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello hayai")
	sig, err := ks.SignBytes(context.Background(), addr, msg)
	if err != nil {
		t.Fatalf("SignBytes: %v", err)
	}
	pub, err := ticket.DecodeAlgorandAddress(addr)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("signature did not verify under the address-derived pubkey")
	}
}

func TestKeyStore_SignBytes_UnknownAddress(t *testing.T) {
	mn, _ := freshMnemonic(t)
	ks, err := New(context.Background(), staticProvider{entries: []MnemonicEntry{{Name: "X", Mnemonic: mn}}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ks.SignBytes(context.Background(), "OTHER_ADDR_NOT_IN_KEYSTORE_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", []byte("x"))
	if err == nil {
		t.Fatal("want error for unknown address")
	}
}

func TestKeyStore_DrivesTicketSignVerify(t *testing.T) {
	// End-to-end: keystore → proto.Ticket.Sign(BytesSigner) → Verify
	// against the same address. This is the integration node uses.
	mn, addr := freshMnemonic(t)
	ks, err := New(context.Background(), staticProvider{entries: []MnemonicEntry{{Name: "SIGN", Mnemonic: mn}}})
	if err != nil {
		t.Fatal(err)
	}
	tk := &ticket.Ticket{
		TicketID:       "AAAAAAAAAAAAAAAAAAAAAA==",
		OperatorID:     1,
		InputCount:     1,
		MaxOutputCount: 1,
		InputRate:      1,
		OutputRate:     1,
		MaxPrice:       2,
		ExpiresAt:      1_700_000_000,
		Model:          "m",
		Stream:         false,
		CommitK:        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	}
	if err := tk.Sign(context.Background(), ks, addr); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	pub, err := ticket.DecodeAlgorandAddress(addr)
	if err != nil {
		t.Fatal(err)
	}
	if err := tk.Verify(pub); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestEnvProvider_StripsSuffixSkipsEmptyAndIgnoresOtherVars(t *testing.T) {
	mn, _ := freshMnemonic(t)
	t.Setenv("OPERATOR_SIGNING_MNEMONIC", mn)
	t.Setenv("EMPTY_MNEMONIC", "")
	t.Setenv("UNRELATED_VAR", "something")

	entries, err := EnvProvider{}.Mnemonics(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range entries {
		if e.Name == "OPERATOR_SIGNING" && e.Mnemonic == mn {
			found = true
		}
		if strings.HasSuffix(e.Name, "_MNEMONIC") {
			t.Errorf("name not stripped: %s", e.Name)
		}
		if e.Mnemonic == "" {
			t.Errorf("empty entry leaked: %s", e.Name)
		}
		// Without the suffix filter every env var in the process becomes a
		// candidate mnemonic, and KeyStore.New fails the whole load on the
		// first one that will not decode. UNRELATED_VAR stands in for the
		// hundred ambient vars that would arrive with it.
		if e.Name == "UNRELATED_VAR" {
			t.Errorf("non-mnemonic var leaked: %s", e.Name)
		}
	}
	if !found {
		t.Fatal("expected OPERATOR_SIGNING entry not found")
	}
}

func TestNewURLProviderFromEnv_ParsesMixedSchemes(t *testing.T) {
	p := NewURLProviderFromEnv("aws=awssecretsmanager://arn, gcp=gcpsecretmanager://projects/p/secrets/s/versions/latest, az=azurekeyvault://v/s")
	if p == nil {
		t.Fatal("got nil")
	}
	if got := len(p.URLs); got != 3 {
		t.Fatalf("URLs count = %d, want 3 (aws+gcp+az), got %v", got, p.URLs)
	}
	for _, name := range []string{"aws", "gcp", "az"} {
		if _, ok := p.URLs[name]; !ok {
			t.Errorf("URLs missing %q: %v", name, p.URLs)
		}
	}
}

func TestNewURLProviderFromEnv_Empty(t *testing.T) {
	if p := NewURLProviderFromEnv(""); p != nil {
		t.Fatal("want nil for empty input")
	}
	if p := NewURLProviderFromEnv("   "); p != nil {
		t.Fatal("want nil for whitespace input")
	}
	if p := NewURLProviderFromEnv("noequals"); p != nil {
		t.Fatal("want nil when no name=url pair parses")
	}
}

// ProvidersFromEnv collapses to {EnvProvider, URLProvider} now that
// the URL provider dispatches by scheme internally.
func TestProvidersFromEnv_ReturnsEnvAndURLChain(t *testing.T) {
	t.Setenv(MnemonicURLsEnv, "aws=awssecretsmanager://arn, az=azurekeyvault://v/s")
	chain := ProvidersFromEnv()
	if len(chain) != 2 {
		t.Fatalf("chain length = %d, want 2", len(chain))
	}
	if _, ok := chain[0].(EnvProvider); !ok {
		t.Errorf("chain[0] = %T, want EnvProvider", chain[0])
	}
	up, ok := chain[1].(*URLProvider)
	if !ok || up == nil {
		t.Fatalf("chain[1] = %T (nil=%v), want *URLProvider", chain[1], chain[1] == nil)
	}
	for _, name := range []string{"aws", "az"} {
		if _, has := up.URLs[name]; !has {
			t.Errorf("URLProvider missing %q: %v", name, up.URLs)
		}
	}
}

// File-backed runtimevar is a clean way to exercise the URL dispatch
// end-to-end without standing up a cloud client. Writing a mnemonic
// to a tempfile and pointing a "file://" URL at it should round-trip
// through Mnemonics → KeyStore → derived address.
func TestURLProvider_DispatchesFileScheme(t *testing.T) {
	mn, addr := freshMnemonic(t)
	dir := t.TempDir()
	path := dir + "/mnemonic"
	if err := os.WriteFile(path, []byte(mn), 0o600); err != nil {
		t.Fatal(err)
	}
	// runtimevar's filevar driver uses absolute paths after file://
	url := "file://" + path + "?decoder=string"
	p := &URLProvider{URLs: map[string]string{"local": url}}
	ks, err := New(context.Background(), p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !ks.HasAccount(addr) {
		t.Fatalf("addr not loaded; addresses=%v", ks.Addresses())
	}
}

func TestLoadFromEnv_EnvOnly(t *testing.T) {
	mn, addr := freshMnemonic(t)
	t.Setenv("LOADFROMENV_MNEMONIC", mn)
	t.Setenv(MnemonicURLsEnv, "")
	ks, err := LoadFromEnv(context.Background())
	if err != nil {
		t.Fatalf("LoadFromEnv: %v", err)
	}
	if !ks.HasAccount(addr) {
		t.Fatalf("addr not loaded; addresses=%v", ks.Addresses())
	}
}

func TestParseAzureKeyVaultURL(t *testing.T) {
	vault, name, err := parseAzureKeyVaultURL("azurekeyvault://my-vault/my-secret")
	if err != nil {
		t.Fatal(err)
	}
	if vault != "https://my-vault.vault.azure.net/" {
		t.Errorf("vault = %q", vault)
	}
	if name != "my-secret" {
		t.Errorf("name = %q", name)
	}

	cases := []string{
		"https://other-scheme",
		"azurekeyvault://onlyvault",
		"azurekeyvault:///onlysecret",
		"azurekeyvault://vault/",
	}
	for _, c := range cases {
		if _, _, err := parseAzureKeyVaultURL(c); err == nil {
			t.Errorf("want error for %q", c)
		}
	}
}
