/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Package wallet keeps a payer's Algorand recovery phrase on the local
// machine: generated or imported, held in the OS keychain or a
// passphrase-encrypted file, with a non-secret descriptor beside it. Every
// zerosignal program that opens the default directory shares one wallet.
//
// A 24-word phrase exported from the browser client derives the same address
// here, because derivation goes through keystore's decode path
// (m/44'/283'/0'/0/0, empty BIP-39 passphrase).
package wallet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/tyler-smith/go-bip39"

	"github.com/TxnLab/zerosignal/go/keystore"
)

// secretKey is the store key of the wallet in DefaultDir, and of any wallet
// on the encrypted file, whose store is already per directory.
const secretKey = "mnemonic"

// metaFile is the non-secret descriptor, in the wallet's directory.
const metaFile = "wallet.json"

// The forms a recovery phrase can take; see keystore.
const (
	KindXHD24      = "xhd-24"      // 24-word BIP-39 / ARC-52, the browser client's form
	KindAlgorand25 = "algorand-25" // 25-word standard Algorand
)

// Where a wallet's phrase came from.
const (
	SourceGenerated = "generated"
	SourceImported  = "imported"
)

// ErrExists is returned by Generate and Import when a wallet is already
// present and force is not set.
var ErrExists = errors.New("wallet: a wallet already exists")

// Metadata is the non-secret descriptor kept in wallet.json, so a program can
// show the wallet without unlocking the store.
type Metadata struct {
	Address string `json:"address"`
	Network string `json:"network"`
	Kind    string `json:"kind"`
	Source  string `json:"source"`
	// Backend is the keyring backend holding the phrase, so two programs
	// built with different defaults (a release binary on the OS keychain, a
	// plain `go build` on the encrypted file) open the same store. Empty in
	// a wallet written before it was recorded, until the phrase is next read.
	Backend string `json:"backend,omitempty"`
	// SolanaAddress is the address the phrase pays as on the Solana rail,
	// m/44'/501'/0'/0', so a host can show it without unlocking the store.
	// Empty for a 25-word Algorand mnemonic, which has no Solana key, and in
	// a 24-word wallet written before it was recorded, until the phrase is
	// next read.
	SolanaAddress string `json:"solana_address,omitempty"`
}

// Wallet is one directory's wallet: a secret store plus the descriptor.
type Wallet struct {
	store   SecretStore
	dir     string
	backend string
	key     string
}

// New builds a Wallet over store, with its descriptor in dir. A store from
// NewKeyringStore has its backend recorded in the descriptor; any other
// store records none.
func New(store SecretStore, dir string) *Wallet {
	w := &Wallet{store: store, dir: dir, key: secretKey}
	if ks, ok := store.(*keyringStore); ok {
		w.backend = ks.backend
		w.key = keyFor(dir, ks.backend)
	}
	return w
}

// keyFor is the store key of dir's wallet. An OS keychain is one namespace
// for the whole account, so a wallet outside DefaultDir gets a key of its
// own; otherwise creating one would overwrite the default wallet's phrase.
// DefaultDir keeps the plain key every earlier wallet was written under.
//
// The key follows the path as given, not symlinks or case, so DefaultDir
// reached another way finds no phrase rather than another wallet's.
func keyFor(dir, backend string) string {
	if UsesFileBackend(backend) {
		return secretKey
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = filepath.Clean(dir)
	}
	if def, err := DefaultDir(); err == nil && filepath.Clean(def) == abs {
		return secretKey
	}
	sum := sha256.Sum256([]byte(abs))
	return secretKey + "-" + hex.EncodeToString(sum[:8])
}

// DefaultDir is the directory zerosignal programs share a wallet in:
// os.UserConfigDir()/zerosignal.
func DefaultDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "zerosignal"), nil
}

// HomeEnv names a directory that holds a whole second set of state: wallet,
// config, journals, logs. It lets one machine run a payer independent of the
// one in DefaultDir, as a local test does beside the user's own.
const HomeEnv = "ZEROSIGNAL_HOME"

// HomeDir is the directory a program keeps its wallet and state in: HomeEnv's
// when set, else DefaultDir. It never changes DefaultDir, which keyFor
// compares against: a wallet in another home gets its own keychain item
// rather than the default wallet's.
func HomeDir() (string, error) {
	if dir := os.Getenv(HomeEnv); dir != "" {
		return filepath.Abs(dir)
	}
	return DefaultDir()
}

// Open opens the wallet in dir on a keyring store. The backend is
// opts.Override if set, else the one the descriptor records, else
// opts.Backend. Opening never prompts; the first read or write may. A
// descriptor that exists but cannot be read is an error rather than a reason
// to fall back to opts.Backend, which could be a different store.
func Open(dir string, opts KeyringOptions) (*Wallet, error) {
	meta, err := readMeta(dir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	recorded := meta.Backend
	if opts.Override == "" && recorded != "" {
		opts.Backend = recorded
	}
	if opts.FileDir == "" {
		opts.FileDir = filepath.Join(dir, "keystore")
	}
	store, err := NewKeyringStore(opts)
	if err != nil {
		if opts.Override == "" && recorded != "" {
			return nil, fmt.Errorf("%w; %s records it (the zerosignal CLIs open another with %s)", err, filepath.Join(dir, metaFile), EnvBackend)
		}
		return nil, err
	}
	return New(store, dir), nil
}

// ExistsIn reports whether dir holds a wallet, by its descriptor alone, so it
// never opens the store or prompts. A descriptor that cannot be checked counts
// as present, so creating a wallet over it is refused rather than allowed.
func ExistsIn(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, metaFile))
	return !errors.Is(err, fs.ErrNotExist)
}

// Exists reports whether this wallet's descriptor is present.
func (w *Wallet) Exists() bool { return ExistsIn(w.dir) }

// Backend is the keyring backend this wallet's store opened on, "" for a
// store not from NewKeyringStore.
func (w *Wallet) Backend() string { return w.backend }

// Generate creates a 24-word xHD wallet, the form the browser client imports,
// stores the phrase and writes the descriptor. It refuses to replace an
// existing wallet unless force is set.
func (w *Wallet) Generate(network string, force bool) (Metadata, error) {
	m, err := newMnemonic24()
	if err != nil {
		return Metadata{}, fmt.Errorf("generate mnemonic: %w", err)
	}
	return w.persist(m, network, SourceGenerated, force)
}

// Import validates and stores a 24-word client phrase or a 25-word Algorand
// mnemonic. A caller that shows the address for confirmation first gets it
// from DeriveAddress. It refuses to replace an existing wallet unless force is
// set. Replacing a wallet onto another backend (Override) leaves the old
// backend's copy of the old phrase where it was.
func (w *Wallet) Import(mnemonic, network string, force bool) (Metadata, error) {
	return w.persist(mnemonic, network, SourceImported, force)
}

func (w *Wallet) persist(mnemonic, network, source string, force bool) (Metadata, error) {
	if w.Exists() && !force {
		return Metadata{}, ErrExists
	}
	mnemonic = normalizePhrase(mnemonic)
	addr, kind, err := DeriveAddress(mnemonic)
	if err != nil {
		return Metadata{}, err
	}
	// What the store holds now, so a replacement that fails halfway puts it
	// back rather than leaving the descriptor naming a phrase that is gone.
	prev, err := w.store.Get(w.key)
	switch {
	case errors.Is(err, ErrNotFound):
		prev = ""
	case err != nil:
		return Metadata{}, fmt.Errorf("read the %s store: %w", w.storeName(), err)
	case !w.Exists() && !force:
		// A phrase no descriptor names: a wallet whose wallet.json was
		// deleted, possibly still holding funds. Overwriting it would lose
		// the only copy.
		return Metadata{}, fmt.Errorf("%w: the %s store holds a recovery phrase that %s, with no %s, does not name; replacing it loses that phrase unless it is the same one",
			ErrExists, w.storeName(), w.dir, metaFile)
	}
	meta := Metadata{Address: addr, Network: network, Kind: kind, Source: source, Backend: w.backend}
	if meta.SolanaAddress, err = solanaAddressOf(mnemonic, kind); err != nil {
		return Metadata{}, err
	}
	if err := w.store.Set(w.key, mnemonic); err != nil {
		return Metadata{}, fmt.Errorf("store secret: %w", err)
	}
	if err := w.writeMeta(meta); err != nil {
		err = fmt.Errorf("write metadata: %w", err)
		var rerr error
		if prev != "" {
			rerr = w.store.Set(w.key, prev)
		} else {
			// No descriptor points at the secret, so nothing would ever read
			// or remove it.
			rerr = w.store.Remove(w.key)
		}
		if rerr != nil {
			err = errors.Join(err, fmt.Errorf("restore the %s store: %w; it now holds the phrase for %s, which %s does not name", w.storeName(), rerr, addr, metaFile))
		}
		return Metadata{}, err
	}
	return meta, nil
}

// normalizePhrase is the text the browser client derives from: lowercase
// words, single-spaced. A 24-word seed hashes the phrase text itself, so the
// same words pasted across lines would otherwise be another account.
func normalizePhrase(m string) string {
	return strings.Join(strings.Fields(strings.ToLower(m)), " ")
}

// Export returns the stored phrase. On a keychain backend this is the read
// that can raise an OS access prompt. The caller confirms the reveal and never
// logs the result.
func (w *Wallet) Export() (string, error) {
	m, _, err := w.readPhrase()
	return m, err
}

// readPhrase reads the phrase and checks it against the descriptor. With no
// descriptor there is no wallet, whatever the store holds: a phrase is served
// only under an address the user can be shown. A descriptor with no phrase
// behind it, or with another address, means two programs disagree about the
// store, and the error says so. legacy reports a phrase stored before import
// normalized it whose descriptor names the address of its own spacing (see
// keystore.MnemonicEntry.LegacySpacing).
func (w *Wallet) readPhrase() (m string, legacy bool, err error) {
	meta, merr := readMeta(w.dir)
	if errors.Is(merr, fs.ErrNotExist) {
		return "", false, fmt.Errorf("no wallet in %s: %w", w.dir, ErrNotFound)
	}
	if merr != nil {
		return "", false, merr
	}
	m, err = w.store.Get(w.key)
	if errors.Is(err, ErrNotFound) {
		return "", false, fmt.Errorf("%w: %s names %s, but the %s store holds no phrase", ErrNotFound, metaFile, meta.Address, w.storeName())
	}
	if err != nil {
		return "", false, err
	}
	addr, kind, err := keystore.DeriveAddress(m)
	if err != nil {
		return "", false, err
	}
	if addr != meta.Address {
		// Imported between 2026-06-15 and 2026-10-03, a phrase was stored as
		// given and its descriptor named the address its spacing derived;
		// the keystore now rejoins the words. That address still holds the
		// wallet's funds, so the wallet keeps paying as it.
		if old, ok := keystore.LegacySpacingAddress(m); !ok || old != meta.Address {
			return "", false, fmt.Errorf("wallet: the %s store holds the phrase for %s, but %s names %s", w.storeName(), addr, metaFile, meta.Address)
		}
		legacy = true
	}
	stale := false
	if meta.Backend == "" && w.backend != "" {
		// A wallet from before backends were recorded gets one the first
		// time a store is shown to hold its phrase.
		meta.Backend = w.backend
		stale = true
	}
	if meta.SolanaAddress == "" {
		// Likewise a wallet from before Solana addresses were recorded.
		if sol, err := solanaAddressOf(m, kind); err == nil && sol != "" {
			meta.SolanaAddress = sol
			stale = true
		}
	}
	if stale {
		_ = w.writeMeta(meta)
	}
	return m, legacy, nil
}

func (w *Wallet) storeName() string {
	if w.backend == "" {
		return "secret"
	}
	return w.backend
}

// Metadata reads the descriptor.
func (w *Wallet) Metadata() (Metadata, error) { return readMeta(w.dir) }

// ReadMetadata reads dir's descriptor without opening its store, so it never
// prompts and works where the recorded backend does not open. It returns an
// fs.ErrNotExist error when dir holds no wallet.
func ReadMetadata(dir string) (Metadata, error) { return readMeta(dir) }

// Provider exposes the wallet as a keystore.SecretProvider. It reads the
// phrase when the keystore loads. With no wallet it supplies nothing, so a
// keystore built from several providers falls through to the next; a wallet
// whose phrase cannot be read is an error.
func (w *Wallet) Provider() keystore.SecretProvider { return walletProvider{w: w} }

type walletProvider struct{ w *Wallet }

func (p walletProvider) Mnemonics(context.Context) ([]keystore.MnemonicEntry, error) {
	if !p.w.Exists() {
		return nil, nil
	}
	m, legacy, err := p.w.readPhrase()
	if err != nil {
		return nil, err
	}
	return []keystore.MnemonicEntry{{Name: "zerosignal-wallet", Mnemonic: m, LegacySpacing: legacy}}, nil
}

func readMeta(dir string) (Metadata, error) {
	b, err := os.ReadFile(filepath.Join(dir, metaFile))
	if err != nil {
		return Metadata{}, err
	}
	var m Metadata
	if err := json.Unmarshal(b, &m); err != nil {
		return Metadata{}, fmt.Errorf("parse %s: %w", filepath.Join(dir, metaFile), err)
	}
	return m, nil
}

// writeMeta replaces the descriptor by rename, so another program reading it
// never sees half a file.
func (w *Wallet) writeMeta(m Metadata) error {
	if err := os.MkdirAll(w.dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(w.dir, metaFile+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(w.dir, metaFile))
}

// DeriveAddress validates a recovery phrase and returns its Algorand address
// and kind (KindXHD24 or KindAlgorand25). A 24-word phrase gives the address
// the browser client shows for it, however the words are spaced or cased, and
// Import stores the phrase in that same form.
func DeriveAddress(mnemonic string) (addr, kind string, err error) {
	return keystore.DeriveAddress(normalizePhrase(mnemonic))
}

// DeriveSolanaAddress validates a recovery phrase and returns the address it
// pays as on the Solana rail, the one Phantom shows for it. A 25-word Algorand
// mnemonic has none and is refused with ErrNoSolanaKey, so a host can refuse
// to import one for Solana before storing it.
func DeriveSolanaAddress(mnemonic string) (string, error) {
	m := normalizePhrase(mnemonic)
	// Counted first: DeriveAddress runs a full derivation on 24 words.
	if len(strings.Fields(m)) == 25 {
		if _, kind, err := keystore.DeriveAddress(m); err == nil && kind == KindAlgorand25 {
			return "", fmt.Errorf("%w; a wallet's Solana key comes from a 24-word phrase", ErrNoSolanaKey)
		}
	}
	return solanaAddress(m)
}

// solanaAddressOf is a stored phrase's Solana address, "" for a kind with no
// Solana key. The phrase is taken as stored, as keystore.NewSolanaKeys takes
// it, so the descriptor names the key LoadSolanaPayer pays with.
func solanaAddressOf(mnemonic, kind string) (string, error) {
	if kind != KindXHD24 {
		return "", nil
	}
	return solanaAddress(mnemonic)
}

func solanaAddress(phrase string) (string, error) {
	priv, err := keystore.SolanaKeyFromPhrase(phrase)
	if err != nil {
		return "", err
	}
	defer clear(priv)
	return keystore.SolanaAddress(priv)
}

// newMnemonic24 generates a 24-word BIP-39 phrase (256 bits of entropy).
func newMnemonic24() (string, error) {
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return "", err
	}
	return bip39.NewMnemonic(entropy)
}
