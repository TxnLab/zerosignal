/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package wallet

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/99designs/keyring"

	"github.com/TxnLab/zerosignal/go/keystore"
)

func newTestWallet(t *testing.T) *Wallet {
	t.Helper()
	return New(NewMemStore(), t.TempDir())
}

func fixedPassphrase(string) (string, error) { return "test passphrase", nil }

// noBackend can never open, so a test that resolves to it by mistake fails
// rather than reaching the real OS keychain.
const noBackend = "no-such-backend"

func fileOpts() KeyringOptions {
	return KeyringOptions{Backend: BackendFile, Passphrase: fixedPassphrase}
}

func TestGenerate_ProducesImportableXHD(t *testing.T) {
	w := newTestWallet(t)
	meta, err := w.Generate("testnet", false)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Kind != KindXHD24 {
		t.Errorf("kind = %q, want %q (24-word, client-importable)", meta.Kind, KindXHD24)
	}
	if meta.Source != SourceGenerated || meta.Network != "testnet" || meta.Address == "" {
		t.Errorf("unexpected metadata: %+v", meta)
	}
	got, err := w.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	if got != meta {
		t.Errorf("metadata round-trip mismatch: %+v vs %+v", got, meta)
	}
}

// The exported phrase derives the stored address: the property that lets one
// wallet load in the browser client and here.
func TestGenerate_ExportRoundTrip_DerivesSameAddress(t *testing.T) {
	w := newTestWallet(t)
	meta, err := w.Generate("testnet", false)
	if err != nil {
		t.Fatal(err)
	}
	phrase, err := w.Export()
	if err != nil {
		t.Fatal(err)
	}
	if n := len(strings.Fields(phrase)); n != 24 {
		t.Fatalf("exported phrase has %d words, want 24", n)
	}
	addr, kind, err := DeriveAddress(phrase)
	if err != nil {
		t.Fatal(err)
	}
	if addr != meta.Address || kind != KindXHD24 {
		t.Errorf("re-derived %s (%s), stored %s", addr, kind, meta.Address)
	}
}

func TestProvider_FeedsKeystore_SameAddress(t *testing.T) {
	w := newTestWallet(t)
	meta, err := w.Generate("testnet", false)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := keystore.New(context.Background(), w.Provider())
	if err != nil {
		t.Fatal(err)
	}
	if !ks.HasAccount(meta.Address) {
		t.Errorf("keystore missing wallet address %s; has %v", meta.Address, ks.Addresses())
	}
}

func TestProvider_EmptyWhenNoWallet(t *testing.T) {
	entries, err := newTestWallet(t).Provider().Mnemonics(context.Background())
	if err != nil || len(entries) != 0 {
		t.Errorf("empty wallet: %d entries, %v; want none and no error", len(entries), err)
	}
}

func TestExport_NoWallet(t *testing.T) {
	if _, err := newTestWallet(t).Export(); !errors.Is(err, ErrNotFound) {
		t.Errorf("Export = %v, want ErrNotFound", err)
	}
}

func TestImport_RoundTripsThroughDerive(t *testing.T) {
	src := newTestWallet(t)
	srcMeta, err := src.Generate("testnet", false)
	if err != nil {
		t.Fatal(err)
	}
	phrase, err := src.Export()
	if err != nil {
		t.Fatal(err)
	}
	dstMeta, err := newTestWallet(t).Import(phrase, "mainnet", false)
	if err != nil {
		t.Fatal(err)
	}
	if dstMeta.Address != srcMeta.Address || dstMeta.Source != SourceImported || dstMeta.Network != "mainnet" {
		t.Errorf("imported %+v from %+v", dstMeta, srcMeta)
	}
}

func TestImport_RejectsBadPhrase(t *testing.T) {
	w := newTestWallet(t)
	for _, bad := range []string{
		"too few words",
		strings.Repeat("zoo ", 24), // 24 words, bad BIP-39 checksum
	} {
		if _, err := w.Import(bad, "testnet", false); err == nil {
			t.Errorf("imported %q", bad)
		}
	}
}

func TestPersist_RefusesClobberWithoutForce(t *testing.T) {
	w := newTestWallet(t)
	if _, err := w.Generate("testnet", false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Generate("testnet", false); !errors.Is(err, ErrExists) {
		t.Errorf("want ErrExists, got %v", err)
	}
	if _, err := w.Generate("testnet", true); err != nil {
		t.Errorf("force generate failed: %v", err)
	}
}

func TestImport_RollsBackSecretOnMetaFailure(t *testing.T) {
	store := NewMemStore()
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	w := New(store, filepath.Join(blocker, "dir")) // MkdirAll under a file fails
	if _, err := w.Import(mustPhrase(t), "testnet", false); err == nil {
		t.Fatal("expected metadata write to fail")
	}
	if _, err := store.Get(secretKey); !errors.Is(err, ErrNotFound) {
		t.Errorf("secret not rolled back after metadata failure: %v", err)
	}
}

// A wallet written on the encrypted file records it, and a program with
// another default opens it there anyway.
func TestOpen_UsesTheRecordedBackend(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir, fileOpts())
	if err != nil {
		t.Fatal(err)
	}
	meta, err := w.Generate("testnet", false)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Backend != BackendFile || w.Backend() != BackendFile {
		t.Fatalf("recorded %q, opened %q; want %q", meta.Backend, w.Backend(), BackendFile)
	}
	if _, err := os.Stat(filepath.Join(dir, "keystore", secretKey)); err != nil {
		t.Errorf("encrypted file not in dir/keystore: %v", err)
	}

	again, err := Open(dir, KeyringOptions{Backend: noBackend, Passphrase: fixedPassphrase})
	if err != nil {
		t.Fatal(err)
	}
	phrase, err := again.Export()
	if err != nil {
		t.Fatal(err)
	}
	if addr, _, _ := DeriveAddress(phrase); addr != meta.Address {
		t.Errorf("reopened wallet's phrase derives %s, want %s", addr, meta.Address)
	}
}

// A recorded backend that does not open here is an error naming the
// descriptor; an Override reaches past it, and force writes the wallet there
// and records it.
func TestOpen_OverrideBeatsTheRecordedBackend(t *testing.T) {
	dir := t.TempDir()
	writeDescriptor(t, dir, `{"address":"X","network":"testnet","kind":"xhd-24","source":"generated","backend":"`+noBackend+`"}`)

	_, err := Open(dir, fileOpts())
	if err == nil || !strings.Contains(err.Error(), metaFile) {
		t.Fatalf("Open on an unopenable recorded backend = %v, want an error naming %s", err, metaFile)
	}

	opts := fileOpts()
	opts.Override = BackendFile
	w, err := Open(dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	if w.Backend() != BackendFile {
		t.Errorf("opened on %q, want the override", w.Backend())
	}
	meta, err := w.Generate("testnet", true)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Backend != BackendFile {
		t.Errorf("force recorded %q, want the override %q", meta.Backend, BackendFile)
	}
	if _, err := Open(dir, KeyringOptions{Backend: noBackend, Passphrase: fixedPassphrase}); err != nil {
		t.Errorf("reopening after the move: %v", err)
	}
}

// Without an Override, force keeps the wallet on its recorded backend.
func TestPersist_ForceKeepsTheRecordedBackend(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir, fileOpts())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Generate("testnet", false); err != nil {
		t.Fatal(err)
	}
	again, err := Open(dir, KeyringOptions{Backend: noBackend, Passphrase: fixedPassphrase})
	if err != nil {
		t.Fatal(err)
	}
	meta, err := again.Generate("testnet", true)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Backend != BackendFile {
		t.Errorf("force recorded %q, want %q", meta.Backend, BackendFile)
	}
}

// A descriptor that exists but does not parse is an error, not a reason to
// open the caller's default, which may be another store.
func TestOpen_CorruptDescriptorIsAnError(t *testing.T) {
	dir := t.TempDir()
	writeDescriptor(t, dir, `{"backend":"file",`)
	if _, err := Open(dir, fileOpts()); err == nil {
		t.Error("opened a wallet whose descriptor does not parse")
	}
}

// A wallet written before backends were recorded records one the first time
// a store is shown to hold its phrase.
func TestReadPhrase_RecordsTheBackendOfALegacyWallet(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir, fileOpts())
	if err != nil {
		t.Fatal(err)
	}
	meta, err := w.Generate("testnet", false)
	if err != nil {
		t.Fatal(err)
	}
	writeDescriptor(t, dir, `{"address":"`+meta.Address+`","network":"testnet","kind":"xhd-24","source":"generated"}`)

	legacy, err := Open(dir, fileOpts())
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := legacy.Metadata(); got.Backend != "" {
		t.Fatalf("legacy descriptor already has backend %q", got.Backend)
	}
	if _, err := legacy.Export(); err != nil {
		t.Fatal(err)
	}
	if got, _ := legacy.Metadata(); got.Backend != BackendFile {
		t.Errorf("after a read the descriptor records %q, want %q", got.Backend, BackendFile)
	}
}

// A descriptor with no phrase behind it is an error to both readers, not an
// empty wallet: the program is looking in a store other than the one that
// wrote it.
func TestReadPhrase_DescriptorWithoutAPhraseIsAnError(t *testing.T) {
	w := newTestWallet(t)
	if _, err := w.Generate("testnet", false); err != nil {
		t.Fatal(err)
	}
	if err := w.store.Remove(secretKey); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Export(); !errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), metaFile) {
		t.Errorf("Export = %v, want ErrNotFound naming %s", err, metaFile)
	}
	if entries, err := w.Provider().Mnemonics(context.Background()); err == nil {
		t.Errorf("Provider supplied %d entries and no error", len(entries))
	}
}

// A phrase for another address than the descriptor names is refused, so a
// caller never signs as an address the user is not shown.
func TestReadPhrase_AddressMismatchIsAnError(t *testing.T) {
	w := newTestWallet(t)
	if _, err := w.Generate("testnet", false); err != nil {
		t.Fatal(err)
	}
	if err := w.store.Set(secretKey, mustPhrase(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Export(); err == nil {
		t.Error("Export returned a phrase for another address")
	}
	if _, err := w.Provider().Mnemonics(context.Background()); err == nil {
		t.Error("Provider supplied a phrase for another address")
	}
}

// Imported before phrases were normalized, a wallet stored the phrase as typed
// and named the address its spacing derived, where its funds are. It still
// opens, and pays as that address; the canonical one is signable alongside.
func TestReadPhrase_LegacySpacingWalletKeepsItsAddress(t *testing.T) {
	w := newTestWallet(t)
	if _, err := w.Generate("testnet", false); err != nil {
		t.Fatal(err)
	}
	canonical, err := w.Export()
	if err != nil {
		t.Fatal(err)
	}
	stored := strings.Join(strings.Fields(canonical), "\n")
	legacyAddr, ok := keystore.LegacySpacingAddress(stored)
	if !ok {
		t.Fatal("a newline-separated phrase derived no legacy address")
	}
	canonicalAddr, _, err := keystore.DeriveAddress(stored)
	if err != nil || canonicalAddr == legacyAddr {
		t.Fatalf("canonical %s, legacy %s, %v: the two must differ", canonicalAddr, legacyAddr, err)
	}
	if err := w.store.Set(secretKey, stored); err != nil {
		t.Fatal(err)
	}
	meta, err := w.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	meta.Address = legacyAddr
	if err := w.writeMeta(meta); err != nil {
		t.Fatal(err)
	}

	if got, err := w.Export(); err != nil || got != stored {
		t.Fatalf("Export = %q, %v; want the stored phrase", got, err)
	}
	ks, err := keystore.New(context.Background(), w.Provider())
	if err != nil {
		t.Fatal(err)
	}
	if got := ks.Addresses(); !slices.Equal(got, []string{legacyAddr}) {
		t.Errorf("Addresses = %v, want only the recorded %s", got, legacyAddr)
	}
	if !ks.HasAccount(canonicalAddr) {
		t.Errorf("canonical %s not signable", canonicalAddr)
	}

	// A descriptor naming the canonical address loads that one as the payer.
	meta.Address = canonicalAddr
	if err := w.writeMeta(meta); err != nil {
		t.Fatal(err)
	}
	ks, err = keystore.New(context.Background(), w.Provider())
	if err != nil {
		t.Fatal(err)
	}
	if got := ks.Addresses(); !slices.Equal(got, []string{canonicalAddr}) || !ks.HasAccount(legacyAddr) {
		t.Errorf("Addresses = %v (legacy signable %v), want only %s", got, ks.HasAccount(legacyAddr), canonicalAddr)
	}

	// Irregular spacing excuses only the old address it derives, never an
	// unrelated one.
	other, _, err := keystore.DeriveAddress(mustPhrase(t))
	if err != nil {
		t.Fatal(err)
	}
	meta.Address = other
	if err := w.writeMeta(meta); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Export(); err == nil || !strings.Contains(err.Error(), "holds the phrase for") {
		t.Errorf("Export = %v, want the address-mismatch error", err)
	}
}

// A wrong passphrase is typed, and the next read asks again instead of
// failing on the cached one.
func TestFileStore_WrongPassphraseAsksAgain(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir, fileOpts())
	if err != nil {
		t.Fatal(err)
	}
	meta, err := w.Generate("testnet", false)
	if err != nil {
		t.Fatal(err)
	}
	answers := []string{"wrong", "test passphrase"}
	var asked int
	again, err := Open(dir, KeyringOptions{Backend: BackendFile, Passphrase: func(string) (string, error) {
		asked++
		return answers[min(asked, len(answers))-1], nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := again.Export(); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("Export under a wrong passphrase = %v, want ErrWrongPassphrase", err)
	}
	phrase, err := again.Export()
	if err != nil {
		t.Fatalf("second Export: %v", err)
	}
	if addr, _, _ := DeriveAddress(phrase); addr != meta.Address || asked != 2 {
		t.Errorf("derived %s after %d prompts, want %s after 2", addr, asked, meta.Address)
	}
}

// Errors from the caller's passphrase func are its own, not a wrong
// passphrase.
func TestFileStore_PassphraseErrorsPassThrough(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir, fileOpts())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Generate("testnet", false); err != nil {
		t.Fatal(err)
	}
	cancelled := errors.New("dialog cancelled")
	again, err := Open(dir, KeyringOptions{Backend: BackendFile, Passphrase: func(string) (string, error) { return "", cancelled }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := again.Export(); !errors.Is(err, cancelled) || errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("Export = %v, want the passphrase func's error", err)
	}
}

// Without a Passphrase the file backend refuses rather than prompting from
// inside a library.
func TestFileStore_NoPassphraseRefuses(t *testing.T) {
	s, err := NewKeyringStore(KeyringOptions{Backend: BackendFile, FileDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Set("k", "v"); !errors.Is(err, ErrNoPassphrase) {
		t.Errorf("Set = %v, want ErrNoPassphrase", err)
	}
}

func TestNewKeyringStore_UnavailableBackend(t *testing.T) {
	if _, err := NewKeyringStore(KeyringOptions{Backend: noBackend}); err == nil {
		t.Error("opened a backend that does not exist")
	}
}

func TestMemStoreRecordsNoBackend(t *testing.T) {
	meta, err := newTestWallet(t).Generate("testnet", false)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Backend != "" {
		t.Errorf("MemStore wallet recorded backend %q", meta.Backend)
	}
}

// BackendOS tries every backend this build has, in keyring's order, so the
// one that opens can be recorded; a named backend is tried alone.
func TestCandidates(t *testing.T) {
	if got := candidates(BackendOS); !slices.Equal(got, keyring.AvailableBackends()) {
		t.Errorf("candidates(os) = %v, want %v", got, keyring.AvailableBackends())
	}
	for in, want := range map[string]keyring.BackendType{
		"":         keyring.FileBackend,
		"keychain": keyring.KeychainBackend,
		"wincred":  keyring.WinCredBackend,
	} {
		if got := candidates(normalizeBackend(in)); len(got) != 1 || got[0] != want {
			t.Errorf("candidates(%q) = %v, want [%s]", in, got, want)
		}
	}
}

func TestWriteMeta_LeavesNoTempFiles(t *testing.T) {
	w := newTestWallet(t)
	if _, err := w.Generate("testnet", false); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != metaFile {
		t.Errorf("dir holds %v, want only %s", entries, metaFile)
	}
	if fi, err := os.Stat(filepath.Join(w.dir, metaFile)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("descriptor mode %v, %v; want 0600", fi.Mode().Perm(), err)
	}
}

func TestEnvHelpers(t *testing.T) {
	t.Setenv(EnvBackend, "")
	if got := OverrideFromEnv(); got != "" {
		t.Errorf("unset: %q", got)
	}
	t.Setenv(EnvBackend, "keychain")
	if got := OverrideFromEnv(); got != "keychain" {
		t.Errorf("set: %q, want the env value", got)
	}

	t.Setenv(EnvPassphrase, "") // restores it after the Unsetenv below
	os.Unsetenv(EnvPassphrase)
	if !NeedsPassphrasePrompt("") || !NeedsPassphrasePrompt(BackendFile) || NeedsPassphrasePrompt("keychain") {
		t.Error("without the env var only the file backend prompts")
	}
	t.Setenv(EnvPassphrase, "")
	if NeedsPassphrasePrompt(BackendFile) {
		t.Error("an empty env passphrase is still a passphrase")
	}
	if p, err := EnvOrPromptPassphrase(""); err != nil || p != "" {
		t.Errorf("EnvOrPromptPassphrase = %q, %v; want the env value", p, err)
	}
}

func TestDefaultDir(t *testing.T) {
	base, err := os.UserConfigDir()
	if err != nil {
		t.Skip(err)
	}
	got, err := DefaultDir()
	if err != nil || got != filepath.Join(base, "zerosignal") {
		t.Errorf("DefaultDir = %q, %v", got, err)
	}
}

// solanaPayerOf is the address keystore.NewSolanaKeys pays as for w's phrase,
// the key LoadSolanaPayer would choose.
func solanaPayerOf(t *testing.T, w *Wallet) string {
	t.Helper()
	ks, err := keystore.NewSolanaKeys(context.Background(), w.Provider())
	if err != nil {
		t.Fatal(err)
	}
	addrs := ks.Addresses()
	if len(addrs) != 1 {
		t.Fatalf("Solana keys %v, want one", addrs)
	}
	return addrs[0]
}

// The descriptor names the key the wallet pays as on Solana, so a host can
// show it without unlocking the store.
func TestPersist_RecordsTheSolanaPayer(t *testing.T) {
	gen := newTestWallet(t)
	meta, err := gen.Generate("testnet", false)
	if err != nil {
		t.Fatal(err)
	}
	if want := solanaPayerOf(t, gen); meta.SolanaAddress != want {
		t.Errorf("generated: descriptor names %q, the wallet pays as %s", meta.SolanaAddress, want)
	}
	phrase, err := gen.Export()
	if err != nil {
		t.Fatal(err)
	}
	// Imported as a user might paste it: another spacing and case.
	imp := newTestWallet(t)
	meta, err = imp.Import("  "+strings.ToUpper(strings.ReplaceAll(phrase, " ", "\n  ")), "testnet", false)
	if err != nil {
		t.Fatal(err)
	}
	if want := solanaPayerOf(t, imp); meta.SolanaAddress != want {
		t.Errorf("imported: descriptor names %q, the wallet pays as %s", meta.SolanaAddress, want)
	}
}

func TestPersist_AlgorandMnemonicRecordsNoSolanaAddress(t *testing.T) {
	meta, err := newTestWallet(t).Import(keystoreTestMnemonic25(t), "testnet", false)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Kind != KindAlgorand25 || meta.SolanaAddress != "" {
		t.Errorf("25-word import: kind %q, Solana address %q; want %q and none", meta.Kind, meta.SolanaAddress, KindAlgorand25)
	}
}

// A wallet written before Solana addresses were recorded records its own the
// first time a store is shown to hold its phrase.
func TestReadPhrase_RecordsTheSolanaAddressOfALegacyWallet(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir, fileOpts())
	if err != nil {
		t.Fatal(err)
	}
	meta, err := w.Generate("testnet", false)
	if err != nil {
		t.Fatal(err)
	}
	writeDescriptor(t, dir, `{"address":"`+meta.Address+`","network":"testnet","kind":"xhd-24","source":"generated","backend":"file"}`)
	if _, err := w.Export(); err != nil {
		t.Fatal(err)
	}
	got, err := w.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	if want := solanaPayerOf(t, w); got.SolanaAddress != want {
		t.Errorf("after a read the descriptor names %q, the wallet pays as %s", got.SolanaAddress, want)
	}
}

func TestDeriveSolanaAddress(t *testing.T) {
	w := newTestWallet(t)
	meta, err := w.Generate("testnet", false)
	if err != nil {
		t.Fatal(err)
	}
	phrase, err := w.Export()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DeriveSolanaAddress(" " + strings.ToUpper(phrase) + "\n")
	if err != nil || got != meta.SolanaAddress {
		t.Errorf("DeriveSolanaAddress = %q, %v; want %s", got, err, meta.SolanaAddress)
	}
	if _, err := DeriveSolanaAddress(keystoreTestMnemonic25(t)); !errors.Is(err, ErrNoSolanaKey) {
		t.Errorf("a 25-word Algorand mnemonic: %v, want ErrNoSolanaKey", err)
	}
	// A bad phrase is its own error, not a missing Solana key.
	if _, err := DeriveSolanaAddress(strings.Repeat("abandon ", 23) + "zoo"); err == nil || errors.Is(err, ErrNoSolanaKey) {
		t.Errorf("a bad 24-word phrase: %v", err)
	}
}

func writeDescriptor(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, metaFile), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustPhrase(t *testing.T) string {
	t.Helper()
	m, err := newMnemonic24()
	if err != nil {
		t.Fatal(err)
	}
	return m
}
