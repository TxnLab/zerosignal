/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package wallet

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/99designs/keyring"
)

var (
	// ErrNotFound is returned by SecretStore.Get when no secret is stored.
	ErrNotFound = errors.New("wallet: secret not found")
	// ErrNoPassphrase is returned when the encrypted file needs a passphrase
	// and KeyringOptions.Passphrase is nil. A caller with its own passphrase
	// dialog opens again with one.
	ErrNoPassphrase = errors.New("wallet: the encrypted file needs a passphrase")
	// ErrWrongPassphrase is returned when the encrypted file does not open
	// under the passphrase given. The store asks again on the next call.
	ErrWrongPassphrase = errors.New("wallet: wrong passphrase for the encrypted file")
	// ErrEmptyPassphrase refuses an empty new passphrase, which would leave
	// the encrypted file readable by anyone who can read the file.
	ErrEmptyPassphrase = errors.New("wallet: the passphrase is empty")
	// ErrPassphraseMismatch is returned when a new passphrase and its
	// repetition differ.
	ErrPassphraseMismatch = errors.New("wallet: the passphrases do not match")
)

// RepeatPassphrasePrompt is the prompt KeyringOptions.Passphrase gets when a
// new passphrase is asked for again, so a dialog can say it is a confirmation.
const RepeatPassphrasePrompt = "Repeat the passphrase"

// fileStoreEmpty reports whether dir holds no encrypted secret yet, so the
// next passphrase asked for is a new one. A directory that cannot be read
// counts as not empty, which skips the repeat rather than misreporting.
func fileStoreEmpty(dir string) bool {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return true
	}
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() {
			return false
		}
	}
	return true
}

// SecretStore holds the wallet's recovery phrase at rest. NewKeyringStore is
// the OS keychain or a passphrase-encrypted file; MemStore is for tests.
type SecretStore interface {
	Get(key string) (string, error) // ErrNotFound when absent
	Set(key, secret string) error
	Remove(key string) error // no-op when absent
}

// Backend names. Any other 99designs/keyring backend name ("keychain",
// "wincred", "secret-service", "kwallet", "pass") also works.
const (
	// BackendFile is a file encrypted under a passphrase.
	BackendFile = "file"
	// BackendOS is the first keyring backend that opens in this build, in
	// keyring's order: Windows Credential Manager, macOS Keychain, Secret
	// Service, KWallet, keyctl, pass, then the encrypted file. A store opened
	// with it reports, and a wallet records, the backend that opened.
	BackendOS = "os"
)

// KeyringOptions configures NewKeyringStore and Open.
type KeyringOptions struct {
	// Backend is the default: what a new wallet is created on, and what an
	// existing wallet that records no backend is opened on. "" is
	// BackendFile, because an unsigned binary reading the macOS Keychain
	// gets an access prompt on every read.
	Backend string
	// Override, when set, is used even for a wallet that records a different
	// backend: how a user reaches a wallet whose recorded backend does not
	// open here. Generate or Import with force records it as the wallet's
	// backend; importing the wallet's own phrase that way moves it there.
	Override string
	// FileDir holds the encrypted file. Open uses its directory's keystore
	// subdirectory when it is empty.
	FileDir string
	// Passphrase unlocks the encrypted file; prompt says what it is for. It
	// is called on the first read or write, not on open, and again after
	// ErrWrongPassphrase. EnvOrPromptPassphrase is the zerosignal CLIs'
	// choice.
	Passphrase func(prompt string) (string, error)
}

// keyringServiceName is the keychain service, and the file backend's
// collection, that every zerosignal program shares.
const keyringServiceName = "zerosignal"

type keyringStore struct {
	backend string
	cfg     keyring.Config

	mu sync.Mutex
	kr keyring.Keyring
}

// passphraseError marks an error from the caller's Passphrase func, so it is
// not mistaken for a passphrase that failed to decrypt.
type passphraseError struct{ err error }

func (e passphraseError) Error() string { return e.err.Error() }
func (e passphraseError) Unwrap() error { return e.err }

// NewKeyringStore opens the secret store opts names: Override if set, else
// Backend.
//
// The macOS item trusts the binary that wrote it (KeychainTrustApplication),
// so a background daemon reads it without a prompt for each signature. It is
// encrypted at rest under the login keychain.
func NewKeyringStore(opts KeyringOptions) (SecretStore, error) {
	pass := opts.Passphrase
	cfg := keyring.Config{
		ServiceName:                    keyringServiceName,
		KeychainName:                   "login",
		KeychainTrustApplication:       true,
		KeychainAccessibleWhenUnlocked: true,
		LibSecretCollectionName:        "login",
		WinCredPrefix:                  keyringServiceName,
		FileDir:                        opts.FileDir,
		FilePasswordFunc: func(prompt string) (string, error) {
			if pass == nil {
				return "", ErrNoPassphrase
			}
			p, err := pass(prompt)
			if err != nil {
				return "", passphraseError{err}
			}
			// A passphrase that has never encrypted anything is being set, so
			// it must be one, and a typo in it would lock the wallet: ask for
			// it twice. An existing file is unlocked with whatever encrypted
			// it, empty included, which earlier proxies accepted.
			if fileStoreEmpty(opts.FileDir) {
				if p == "" {
					return "", passphraseError{ErrEmptyPassphrase}
				}
				again, err := pass(RepeatPassphrasePrompt)
				if err != nil {
					return "", passphraseError{err}
				}
				if again != p {
					return "", passphraseError{ErrPassphraseMismatch}
				}
			}
			return p, nil
		},
	}
	backend := normalizeBackend(opts.Backend)
	if opts.Override != "" {
		backend = opts.Override
	}
	// keyring.Open with every backend allowed would pick the same one, but
	// would not say which: tried one at a time, the one that opens is known
	// and recorded.
	var errs []error
	for _, b := range candidates(backend) {
		cfg.AllowedBackends = []keyring.BackendType{b}
		kr, err := keyring.Open(cfg)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", b, err))
			continue
		}
		return &keyringStore{backend: string(b), cfg: cfg, kr: kr}, nil
	}
	err := fmt.Errorf("wallet: no %q keyring backend opens in this build (%w)", backend, errors.Join(errs...))
	if runtime.GOOS == "darwin" && (backend == BackendOS || backend == string(keyring.KeychainBackend)) {
		err = fmt.Errorf("%w; a macOS build without cgo has no Keychain", err)
	}
	return nil, err
}

func normalizeBackend(b string) string {
	if b == "" {
		return BackendFile
	}
	return b
}

func candidates(b string) []keyring.BackendType {
	if b == BackendOS {
		return keyring.AvailableBackends()
	}
	return []keyring.BackendType{keyring.BackendType(b)}
}

// UsesFileBackend reports whether backend is the encrypted file, which needs a
// passphrase. BackendOS can also end on the file; ask an opened Wallet's
// Backend to know.
func UsesFileBackend(backend string) bool {
	return normalizeBackend(backend) == BackendFile
}

func (s *keyringStore) Get(key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, err := s.kr.Get(key)
	if errors.Is(err, keyring.ErrKeyNotFound) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", s.classify(err)
	}
	return string(item.Data), nil
}

// classify names a decrypt failure on the encrypted file and reopens it,
// because the file backend keeps the first passphrase it was given and would
// fail every later call with it. Anything else — a truncated file, a missing
// directory — is returned as it is, not as a wrong passphrase.
func (s *keyringStore) classify(err error) error {
	if s.backend != BackendFile || !isDecryptFailure(err) {
		return err
	}
	if kr, oerr := keyring.Open(s.cfg); oerr == nil {
		s.kr = kr
	}
	return fmt.Errorf("%w (%v)", ErrWrongPassphrase, err)
}

// decryptFailures are the jose2go errors the file backend returns when the
// passphrase is wrong: the PBES2 key unwrap fails its integrity check. The
// content (A256GCM) is only decrypted under a key that unwrapped, so its tag
// failing means a damaged file, not a wrong passphrase. jose2go exports no
// sentinel, so the text is the only signal;
// TestFileStore_WrongPassphraseAsksAgain fails if a jose2go upgrade rewords it.
var decryptFailures = []string{
	"KeyUnwrap(): integrity check failed",
}

func isDecryptFailure(err error) bool {
	var pe passphraseError
	if errors.As(err, &pe) {
		return false
	}
	for _, s := range decryptFailures {
		if strings.Contains(err.Error(), s) {
			return true
		}
	}
	return false
}

func (s *keyringStore) Set(key, secret string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.kr.Set(keyring.Item{
		Key:         key,
		Data:        []byte(secret),
		Label:       "zerosignal wallet",
		Description: "Algorand recovery phrase",
	})
}

func (s *keyringStore) Remove(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.kr.Remove(key)
	if errors.Is(err, keyring.ErrKeyNotFound) {
		return nil
	}
	return err
}

// MemStore is an in-memory SecretStore for tests and ephemeral runs.
type MemStore struct {
	mu sync.Mutex
	m  map[string]string
}

// NewMemStore returns an empty in-memory store.
func NewMemStore() *MemStore { return &MemStore{m: map[string]string{}} }

func (s *MemStore) Get(key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[key]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}

func (s *MemStore) Set(key, secret string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[key] = secret
	return nil
}

func (s *MemStore) Remove(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, key)
	return nil
}
