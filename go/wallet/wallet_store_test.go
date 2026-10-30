/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package wallet

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/99designs/keyring"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/mnemonic"

	"github.com/TxnLab/zerosignal/go/keystore"
)

// An OS keychain is one namespace per account, so only DefaultDir's wallet
// keeps the plain key; any other directory's wallet must not write over it.
// The encrypted file is already per directory and keeps the plain key.
func TestKeyFor(t *testing.T) {
	def, err := DefaultDir()
	if err != nil {
		t.Fatal(err)
	}
	a, b := t.TempDir(), t.TempDir()
	if got := keyFor(def, "keychain"); got != secretKey {
		t.Errorf("DefaultDir on the keychain = %q, want %q (where existing wallets live)", got, secretKey)
	}
	if got := keyFor(a, BackendFile); got != secretKey {
		t.Errorf("another dir on the file = %q, want %q", got, secretKey)
	}
	ka, kb := keyFor(a, "keychain"), keyFor(b, "keychain")
	if ka == secretKey || kb == secretKey || ka == kb {
		t.Errorf("keychain keys %q and %q: want distinct, and neither the default's", ka, kb)
	}
	if again := keyFor(a+string(filepath.Separator), "keychain"); again != ka {
		t.Errorf("the same dir spelled differently = %q, want %q", again, ka)
	}
	if got := keyFor(def+string(filepath.Separator), "keychain"); got != secretKey {
		t.Errorf("DefaultDir with a trailing separator = %q, want %q", got, secretKey)
	}
}

// A second home is a second wallet: its keychain key is not the default
// wallet's, which an override of DefaultDir itself would have made it.
func TestHomeDir(t *testing.T) {
	def, err := DefaultDir()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(HomeEnv, "")
	if got, err := HomeDir(); err != nil || got != def {
		t.Errorf("unset: HomeDir = %q, %v; want DefaultDir %q", got, err, def)
	}
	home := t.TempDir()
	t.Chdir(filepath.Dir(home))
	t.Setenv(HomeEnv, filepath.Base(home))
	got, err := HomeDir()
	if err != nil || got != home {
		t.Fatalf("relative: HomeDir = %q, %v; want %q", got, err, home)
	}
	if after, _ := DefaultDir(); after != def {
		t.Errorf("DefaultDir moved to %q with %s set", after, HomeEnv)
	}
	if k := keyFor(got, "keychain"); k == secretKey {
		t.Errorf("the home's keychain key is the default wallet's %q", k)
	}
}

// The key is stored in the keychain: any change to its form, hash length
// included, loses every wallet already written outside DefaultDir.
func TestKeyFor_Golden(t *testing.T) {
	if filepath.Separator != '/' {
		t.Skip("the golden path is a Unix one")
	}
	if got, want := keyFor("/fixed/abs/dir", "keychain"), "mnemonic-bee60a252583f46a"; got != want {
		t.Errorf("keyFor = %q, want %q", got, want)
	}
}

// A relative directory is keyed by where it resolves, so the same name opened
// from two working directories is two wallets.
func TestKeyFor_RelativeDirIsResolved(t *testing.T) {
	tmp := t.TempDir()
	t.Chdir(tmp)
	abs, err := filepath.Abs("w") // tmp as the process sees it, symlinks and all
	if err != nil {
		t.Fatal(err)
	}
	if rel, full := keyFor("w", "keychain"), keyFor(abs, "keychain"); rel != full {
		t.Errorf("keyFor(%q) = %q, keyFor(%q) = %q; want the same key", "w", rel, abs, full)
	}
}

// Reading a wallet under an override records nothing: the descriptor keeps
// the backend that holds the phrase for every program without the override.
func TestReadUnderOverrideKeepsTheRecordedBackend(t *testing.T) {
	dir := t.TempDir()
	w := New(&keyringStore{backend: "keychain", kr: keyring.NewArrayKeyring(nil)}, dir)
	meta, err := w.Generate("testnet", false)
	if err != nil {
		t.Fatal(err)
	}
	meta.Backend = BackendFile
	if err := w.writeMeta(meta); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Export(); err != nil {
		t.Fatal(err)
	}
	if got, _ := ReadMetadata(dir); got.Backend != BackendFile {
		t.Errorf("recorded backend after a read on keychain = %q, want %q kept", got.Backend, BackendFile)
	}
}

// A caller's FileDir is where the encrypted file goes.
func TestOpen_KeepsTheCallersFileDir(t *testing.T) {
	dir, other := t.TempDir(), t.TempDir()
	opts := fileOpts()
	opts.FileDir = other
	w, err := Open(dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Generate("testnet", false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(other, secretKey)); err != nil {
		t.Errorf("no secret in the caller's FileDir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "keystore")); err == nil {
		t.Error("the secret went to the default keystore dir instead")
	}
}

// A damaged file is not a wrong passphrase: asking again would never help.
func TestFileStore_DamagedCiphertextIsNotAWrongPassphrase(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir, fileOpts())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Generate("testnet", false); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "keystore", secretKey)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// JWE compact form: header.key.iv.ciphertext.tag. Flip one ciphertext
	// character, leaving the key that unwraps intact.
	parts := strings.Split(string(raw), ".")
	if len(parts) != 5 || len(parts[3]) < 2 {
		t.Fatalf("not a compact JWE: %d parts", len(parts))
	}
	c := []byte(parts[3])
	c[1] = map[bool]byte{true: 'B', false: 'A'}[c[1] == 'A']
	parts[3] = string(c)
	if err := os.WriteFile(path, []byte(strings.Join(parts, ".")), 0o600); err != nil {
		t.Fatal(err)
	}
	again, err := Open(dir, fileOpts())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := again.Export(); err == nil || errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("Export of a damaged ciphertext = %v, want an error that is not ErrWrongPassphrase", err)
	}
}

type failingRemoveStore struct{ SecretStore }

func (failingRemoveStore) Remove(string) error { return errors.New("locked") }

// A replacement whose descriptor write fails and whose rollback fails too
// says the store and the descriptor now disagree, and on what.
func TestPersist_FailedRollbackIsReported(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes through the permission")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	w := New(failingRemoveStore{NewMemStore()}, dir)
	phrase := mustPhrase(t)
	addr, _, _ := DeriveAddress(phrase)
	_, err := w.Import(phrase, "testnet", false)
	if err == nil || !strings.Contains(err.Error(), "locked") || !strings.Contains(err.Error(), addr) {
		t.Errorf("Import with a failed rollback = %v, want the rollback error and the address left behind", err)
	}
}

// A descriptor that cannot be checked counts as a wallet, so the keystore
// reports it rather than falling through to the next key as if none existed.
func TestExistsIn_UncheckableDescriptorIsAWallet(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads through the permission")
	}
	dir := t.TempDir()
	w := New(NewMemStore(), dir)
	if _, err := w.Generate("testnet", false); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if !ExistsIn(dir) {
		t.Error("an unreadable wallet dir counts as no wallet")
	}
	if _, err := w.Provider().Mnemonics(t.Context()); err == nil {
		t.Error("Provider supplied nothing and no error for a wallet it cannot read")
	}
}

type failingGetStore struct {
	SecretStore
	sets int
}

var errDenied = errors.New("denied")

func (s *failingGetStore) Get(string) (string, error) { return "", errDenied }
func (s *failingGetStore) Set(string, string) error   { s.sets++; return nil }

// A store that cannot say what it holds is never written, even with force:
// the phrase it could not read may be the only copy.
func TestPersist_UnreadableStoreIsNotOverwritten(t *testing.T) {
	store := &failingGetStore{SecretStore: NewMemStore()}
	w := New(store, t.TempDir())
	for _, force := range []bool{false, true} {
		if _, err := w.Import(mustPhrase(t), "testnet", force); !errors.Is(err, errDenied) {
			t.Errorf("Import(force=%v) = %v, want the read error", force, err)
		}
	}
	if store.sets != 0 {
		t.Errorf("the store was written %d times", store.sets)
	}
}

// A phrase the store holds without a descriptor may be a wallet whose
// wallet.json was lost, still holding funds: creating a wallet over it needs
// force.
func TestPersist_RefusesAnUndescribedPhrase(t *testing.T) {
	store := NewMemStore()
	orphan := mustPhrase(t)
	_ = store.Set(secretKey, orphan)
	w := New(store, t.TempDir())

	if _, err := w.Generate("testnet", false); !errors.Is(err, ErrExists) {
		t.Fatalf("Generate over an undescribed phrase = %v, want ErrExists", err)
	}
	if got, _ := store.Get(secretKey); got != orphan {
		t.Fatal("the undescribed phrase was overwritten")
	}
	meta, err := w.Generate("testnet", true)
	if err != nil {
		t.Fatalf("Generate with force: %v", err)
	}
	if got, _ := store.Get(secretKey); got == orphan {
		t.Error("force did not replace the phrase")
	} else if addr, _, _ := DeriveAddress(got); addr != meta.Address {
		t.Errorf("stored phrase is for %s, descriptor names %s", addr, meta.Address)
	}
}

// With no descriptor nothing is served, whatever the store holds: a phrase
// is only ever used under an address the user can be shown.
func TestReadPhrase_NoDescriptorServesNothing(t *testing.T) {
	store := NewMemStore()
	_ = store.Set(secretKey, mustPhrase(t))
	w := New(store, t.TempDir())

	if _, err := w.Export(); !errors.Is(err, ErrNotFound) {
		t.Errorf("Export = %v, want ErrNotFound", err)
	}
	entries, err := w.Provider().Mnemonics(t.Context())
	if err != nil || len(entries) != 0 {
		t.Errorf("Provider = %v, %v; want nothing", entries, err)
	}
}

// A forced replacement that cannot write its descriptor puts the old phrase
// back, so the old descriptor still names the phrase the store holds.
func TestPersist_FailedForceRestoresThePhrase(t *testing.T) {
	store := NewMemStore()
	dir := t.TempDir()
	w := New(store, dir)
	old, err := w.Generate("testnet", false)
	if err != nil {
		t.Fatal(err)
	}
	// A directory where the temp file goes makes the descriptor write fail.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if _, err := w.Generate("testnet", true); err == nil {
		t.Skip("the descriptor write did not fail (running as root?)")
	}
	_ = os.Chmod(dir, 0o700)
	phrase, err := w.Export()
	if err != nil {
		t.Fatalf("Export after the failed replace: %v", err)
	}
	if addr, _, _ := DeriveAddress(phrase); addr != old.Address {
		t.Errorf("store holds %s, the descriptor still names %s", addr, old.Address)
	}
}

// An empty passphrase would leave the file readable by anyone who can read
// it.
func TestFileStore_RefusesAnEmptyPassphrase(t *testing.T) {
	w, err := Open(t.TempDir(), KeyringOptions{Backend: BackendFile, Passphrase: func(string) (string, error) { return "", nil }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Generate("testnet", false); !errors.Is(err, ErrEmptyPassphrase) {
		t.Errorf("Generate = %v, want ErrEmptyPassphrase", err)
	}
	if w.Exists() {
		t.Error("a wallet was created")
	}
}

// Earlier proxies encrypted the file under whatever was typed, an empty
// passphrase included. That wallet still opens; only a new passphrase must be
// non-empty.
func TestFileStore_EmptyPassphraseUnlocksAnExistingFile(t *testing.T) {
	dir := t.TempDir()
	phrase := mustPhrase(t)
	addr, _, err := DeriveAddress(phrase)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := keyring.Open(keyring.Config{
		AllowedBackends:  []keyring.BackendType{keyring.FileBackend},
		FileDir:          filepath.Join(dir, "keystore"),
		FilePasswordFunc: func(string) (string, error) { return "", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy.Set(keyring.Item{Key: secretKey, Data: []byte(phrase)}); err != nil {
		t.Fatal(err)
	}
	if err := New(NewMemStore(), dir).writeMeta(Metadata{Address: addr, Network: "testnet", Backend: BackendFile}); err != nil {
		t.Fatal(err)
	}

	w, err := Open(dir, KeyringOptions{Backend: BackendFile, Passphrase: func(string) (string, error) { return "", nil }})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := w.Export(); err != nil || got != phrase {
		t.Errorf("Export of a file encrypted under an empty passphrase: %v", err)
	}
}

// The browser client derives from the words, lowercased and single-spaced;
// so does import, and it stores that form. A phrase stored before then, with
// other spacing, keeps the address it was stored under.
func TestPhraseIsNormalizedOnImport(t *testing.T) {
	phrase := mustPhrase(t)
	want, _, err := DeriveAddress(phrase)
	if err != nil {
		t.Fatal(err)
	}
	words := strings.Fields(phrase)
	messy := "  " + strings.ToUpper(strings.Join(words[:12], "\n")) + "\t\n" + strings.Join(words[12:], "  ") + " \n"
	if got, _, err := DeriveAddress(messy); err != nil || got != want {
		t.Errorf("DeriveAddress(messy) = %s, %v; want %s", got, err, want)
	}

	store := NewMemStore()
	w := New(store, t.TempDir())
	meta, err := w.Import(messy, "testnet", false)
	if err != nil || meta.Address != want {
		t.Fatalf("Import(messy) = %+v, %v; want %s", meta, err, want)
	}
	if stored, _ := store.Get(secretKey); stored != phrase {
		t.Errorf("stored %q, want the normalized phrase", stored)
	}

	spaced := strings.Join(words, "  ")
	legacyAddr, _, err := keystore.DeriveAddress(spaced)
	if err != nil {
		t.Fatal(err)
	}
	_ = store.Set(secretKey, spaced)
	if err := w.writeMeta(Metadata{Address: legacyAddr, Network: "testnet"}); err != nil {
		t.Fatal(err)
	}
	if got, err := w.Export(); err != nil || got != spaced {
		t.Errorf("a phrase stored with other spacing: Export = %v", err)
	}
}

// Two directories' wallets on one OS keychain each keep their own phrase.
func TestKeychainWalletsInTwoDirsDoNotCollide(t *testing.T) {
	store := &keyringStore{backend: "keychain", kr: keyring.NewArrayKeyring(nil)}
	a, b := New(store, t.TempDir()), New(store, t.TempDir())
	ma, err := a.Generate("testnet", false)
	if err != nil {
		t.Fatal(err)
	}
	mb, err := b.Generate("testnet", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		w    *Wallet
		addr string
	}{{a, ma.Address}, {b, mb.Address}} {
		phrase, err := tc.w.Export()
		if err != nil {
			t.Fatalf("Export: %v", err)
		}
		if got, _, _ := DeriveAddress(phrase); got != tc.addr {
			t.Errorf("a wallet exports the phrase for %s, want its own %s", got, tc.addr)
		}
	}
}

// The first passphrase a file is encrypted under is asked for twice, and a
// mismatch writes nothing. An existing file is asked for once.
func TestFileStore_NewPassphraseIsAskedTwice(t *testing.T) {
	dir := t.TempDir()
	answers := []string{"one", "two"}
	var asked int
	w, err := Open(dir, KeyringOptions{Backend: BackendFile, Passphrase: func(string) (string, error) {
		asked++
		return answers[min(asked, len(answers))-1], nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Generate("testnet", false); !errors.Is(err, ErrPassphraseMismatch) {
		t.Fatalf("Generate with differing answers = %v, want ErrPassphraseMismatch", err)
	}
	if w.Exists() {
		t.Error("a wallet was created")
	}

	asked = 0
	w, err = Open(dir, fileOpts())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Generate("testnet", false); err != nil {
		t.Fatal(err)
	}
	again, err := Open(dir, KeyringOptions{Backend: BackendFile, Passphrase: func(p string) (string, error) {
		asked++
		return fixedPassphrase(p)
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := again.Export(); err != nil || asked != 1 {
		t.Errorf("unlocking an existing file: %v after %d prompts, want 1", err, asked)
	}
}

// Only a failed decrypt is a wrong passphrase; a file that is not an
// encrypted secret at all says what it is.
func TestFileStore_CorruptFileIsNotAWrongPassphrase(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir, fileOpts())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Generate("testnet", false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "keystore", secretKey), []byte("not a jwe"), 0o600); err != nil {
		t.Fatal(err)
	}
	again, err := Open(dir, fileOpts())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := again.Export(); err == nil || errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("Export of a corrupt file = %v, want an error that is not ErrWrongPassphrase", err)
	}
}

// BackendOS records the backend that opened, never "os": a wallet records
// where its phrase actually is. Opening alone, so no keychain is written.
func TestNewKeyringStore_OSResolvesToAConcreteBackend(t *testing.T) {
	s, err := NewKeyringStore(KeyringOptions{Backend: BackendOS, FileDir: t.TempDir(), Passphrase: fixedPassphrase})
	if err != nil {
		// The file always opens, so "os" must reach it when nothing earlier
		// does: a build without a keychain still has a wallet.
		if slices.Contains(keyring.AvailableBackends(), keyring.FileBackend) {
			t.Fatalf("BackendOS opened nothing although the file backend is built in: %v", err)
		}
		t.Skipf("no keyring backend opens here: %v", err)
	}
	w := New(s, t.TempDir())
	if b := w.Backend(); b == "" || b == BackendOS {
		t.Errorf("Backend = %q, want the concrete backend that opened", b)
	}
}

// A mistyped word is part of the secret; the error, which is logged, must
// not quote it.
func TestDeriveAddress_ErrorDoesNotQuoteTheWords(t *testing.T) {
	words := strings.Fields(keystoreTestMnemonic25(t))
	words[3] = "zzzqtypo"
	_, _, err := DeriveAddress(strings.Join(words, " "))
	if err == nil {
		t.Fatal("accepted a mistyped mnemonic")
	}
	if strings.Contains(err.Error(), "zzzqtypo") {
		t.Errorf("error quotes the mistyped word: %v", err)
	}
}

func keystoreTestMnemonic25(t *testing.T) string {
	t.Helper()
	m, err := mnemonic.FromPrivateKey(crypto.GenerateAccount().PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	return m
}
