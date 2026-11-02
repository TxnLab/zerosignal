/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package wallet

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/TxnLab/zerosignal/go/keystore"
	"github.com/TxnLab/zerosignal/go/solana"
)

// PayerOptions chooses the keys LoadKeys and LoadSolanaKeys load, and the one
// LoadPayer or LoadSolanaPayer pays with. The zero value loads the wallet in
// HomeDir and the environment's keys, and pays with the only one.
type PayerOptions struct {
	// Address is the paying address, base58 for LoadSolanaPayer; "" takes the
	// only key loaded. LoadKeys and LoadSolanaKeys don't read it.
	Address string
	// Dir holds the wallet; "" is HomeDir.
	Dir string
	// Backend opens a wallet whose descriptor records no backend; "" is
	// BackendFile (see KeyringOptions.Backend). A release zs-proxy passes
	// BackendOS here.
	Backend string
	// Passphrase unlocks a wallet on the encrypted file; nil is
	// EnvOrPromptPassphrase, which reads the terminal on stdin.
	Passphrase func(prompt string) (string, error)
	// Wallet is the wallet to load, already open, in place of opening the one
	// in Dir: a host that has just created it passes it so the store is not
	// unlocked twice. Dir, Backend and Passphrase are then unused.
	Wallet *Wallet
	// EnvKeys are the environment's keys as ReadEnvKeys read them; nil reads
	// them here. A host that read them first, say to decide whether to create
	// a wallet, passes what it read so a cloud secret is fetched once.
	EnvKeys *EnvKeys
}

// EnvKeys are the keys the environment held when ReadEnvKeys read it.
type EnvKeys struct {
	Entries []keystore.MnemonicEntry
}

// ReadEnvKeys reads the environment's keys (keystore.ProvidersFromEnv), each
// source bounded by keystore.LoadTimeout, dropping blank entries.
func ReadEnvKeys(ctx context.Context) (*EnvKeys, error) {
	return readEnvKeys(ctx, keystore.ProvidersFromEnv())
}

func readEnvKeys(ctx context.Context, providers []keystore.SecretProvider) (*EnvKeys, error) {
	keys := &EnvKeys{}
	for _, p := range providers {
		entries, err := (timedProvider{p}).Mnemonics(ctx)
		if err != nil {
			return nil, fmt.Errorf("load keys from the environment: %w", err)
		}
		for _, e := range entries {
			if strings.TrimSpace(e.Mnemonic) != "" {
				keys.Entries = append(keys.Entries, e)
			}
		}
	}
	return keys, nil
}

// Mnemonics serves the entries read, so the keystore loads them without
// asking the environment again.
func (k *EnvKeys) Mnemonics(context.Context) ([]keystore.MnemonicEntry, error) {
	return k.Entries, nil
}

// Payer is the key LoadPayer chose. Signer satisfies zs.Signer.
type Payer struct {
	Signer keystore.AccountSigner
	// Network is the network the wallet recorded when Signer is the wallet's
	// key, else "": an environment key records none.
	Network string
}

// SolanaPayer is the key LoadSolanaPayer chose. Signer satisfies
// zs.SolanaSigner. It carries no network; a host that wants the recorded
// network, or the wallet's Solana address without unlocking it, reads
// ReadMetadata.
type SolanaPayer struct {
	Signer keystore.SolanaAccountSigner
}

// ErrNoSolanaKey is a 25-word Algorand mnemonic asked for a Solana key:
// LoadSolanaKeys and LoadSolanaPayer return it when only 25-word mnemonics
// load (as ErrWalletNoSolanaKey when the wallet holds one), and
// DeriveSolanaAddress for a 25-word phrase.
var ErrNoSolanaKey = keystore.ErrNoSolanaKey

// ErrWalletNoSolanaKey is ErrNoSolanaKey from the wallet's own phrase, and
// matches it too. The load's error carries advice for the payer in plain
// sentences; a host with its own commands to back up and replace a wallet
// may show those instead.
var ErrWalletNoSolanaKey error = walletNoSolanaKey{}

type walletNoSolanaKey struct{}

func (walletNoSolanaKey) Error() string {
	return "the wallet holds a 25-word Algorand mnemonic, which has no Solana key"
}
func (walletNoSolanaKey) Is(target error) bool { return target == ErrNoSolanaKey }

// The payer choice's refusals, for a host to add how its own flags or config
// name the payer.
var (
	// ErrNoKeys: nothing loaded, whether or not an address was asked for.
	ErrNoKeys = errors.New("no keys loaded")
	// ErrPayerNotLoaded: the address asked for is not a loaded key, or on
	// Solana not an address at all.
	ErrPayerNotLoaded = errors.New("payer not among the loaded keys")
	// ErrPayerUnchosen: more than one key loaded and none asked for.
	ErrPayerUnchosen = errors.New("more than one key loaded")
)

// Keys is what the payer choice reads from a store: the addresses it lists,
// and whether it can sign for one it may not list, such as the legacy twin
// of a 24-word phrase with non-canonical spacing, which a config may still
// name. *keystore.KeyStore and *keystore.SolanaKeys satisfy it.
type Keys interface {
	Addresses() []string
	HasAccount(addr string) bool
}

// LoadPayer loads the wallet in opts.Dir, when one exists, and the
// environment's keys (keystore.ProvidersFromEnv, bounded by
// keystore.LoadTimeout), and picks the paying one. The wallet's backend
// honors OverrideFromEnv.
func LoadPayer(ctx context.Context, opts PayerOptions) (Payer, error) {
	kr, env := payerSources(opts)
	return loadPayer(ctx, opts, kr, env)
}

// LoadSolanaPayer is LoadPayer for the Solana rail: the same wallet and
// environment, each phrase derived at m/44'/501'/0'/0' (keystore.NewSolanaKeys),
// so a wallet's 24-word phrase pays as the address Phantom shows for it. A
// 25-word Algorand mnemonic has no Solana key and is skipped; when nothing
// else loads, the load fails as LoadSolanaKeys says.
func LoadSolanaPayer(ctx context.Context, opts PayerOptions) (SolanaPayer, error) {
	kr, env := payerSources(opts)
	return loadSolanaPayer(ctx, opts, kr, env)
}

// LoadKeys is LoadPayer's keys, unchosen, for a host that signs as several
// addresses or chooses the payer later (ChoosePayer).
func LoadKeys(ctx context.Context, opts PayerOptions) (*keystore.KeyStore, error) {
	kr, env := payerSources(opts)
	_, _, ks, err := loadKeys(ctx, opts, kr, env)
	return ks, err
}

// LoadSolanaKeys is LoadSolanaPayer's keys, unchosen (ChooseSolanaPayer).
// With only 25-word Algorand mnemonics to load it fails with ErrNoSolanaKey;
// when the wallet holds one, with ErrWalletNoSolanaKey and the advice to back
// it up before replacing it, since replacing it deletes the only copy of that
// account's phrase.
func LoadSolanaKeys(ctx context.Context, opts PayerOptions) (*keystore.SolanaKeys, error) {
	kr, env := payerSources(opts)
	_, sk, err := loadSolanaKeys(ctx, opts, kr, env)
	return sk, err
}

// ChoosePayer picks the paying address among keys: want when keys can sign
// for it, else the only one listed. Its refusals match ErrNoKeys,
// ErrPayerNotLoaded and ErrPayerUnchosen.
func ChoosePayer(want string, keys Keys) (string, error) {
	return choosePayer(want, keys, "")
}

// ChooseSolanaPayer is ChoosePayer on Solana, refusing a want that is not a
// Solana address before looking for it: a config shared with an Algorand run
// names an Algorand payer, which is never among the Solana keys.
func ChooseSolanaPayer(want string, keys Keys) (string, error) {
	return chooseSolanaPayer(want, keys, "")
}

func payerSources(opts PayerOptions) (KeyringOptions, []keystore.SecretProvider) {
	kr := KeyringOptions{
		Backend:    opts.Backend,
		Override:   OverrideFromEnv(),
		Passphrase: opts.Passphrase,
	}
	if kr.Passphrase == nil {
		kr.Passphrase = EnvOrPromptPassphrase
	}
	if opts.EnvKeys != nil {
		return kr, []keystore.SecretProvider{opts.EnvKeys}
	}
	var env []keystore.SecretProvider
	for _, p := range keystore.ProvidersFromEnv() {
		env = append(env, timedProvider{p})
	}
	return kr, env
}

// timedProvider bounds one environment provider by keystore.LoadTimeout, so a
// hung cloud-secret fetch fails instead of blocking. The wallet's provider is
// not bounded: it may be waiting on a person typing a passphrase.
type timedProvider struct{ p keystore.SecretProvider }

func (t timedProvider) Mnemonics(ctx context.Context) ([]keystore.MnemonicEntry, error) {
	if t.p == nil {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(ctx, keystore.LoadTimeout)
	defer cancel()
	return t.p.Mnemonics(ctx)
}

func loadKeys(ctx context.Context, opts PayerOptions, kr KeyringOptions, env []keystore.SecretProvider) (string, Metadata, *keystore.KeyStore, error) {
	dir, meta, providers, err := payerProviders(opts, kr, env)
	if err != nil {
		return "", Metadata{}, nil, err
	}
	ks, err := keystore.New(ctx, providers...)
	if err != nil {
		return "", Metadata{}, nil, fmt.Errorf("load keys: %w", err)
	}
	return dir, meta, ks, nil
}

func loadSolanaKeys(ctx context.Context, opts PayerOptions, kr KeyringOptions, env []keystore.SecretProvider) (string, *keystore.SolanaKeys, error) {
	dir, meta, providers, err := payerProviders(opts, kr, env)
	if err != nil {
		return "", nil, err
	}
	sk, err := keystore.NewSolanaKeys(ctx, providers...)
	if err != nil {
		// Only the wallet's kind tells this apart from a 25-word phrase in
		// the environment, which the payer fixes there instead.
		if errors.Is(err, ErrNoSolanaKey) && meta.Kind == KindAlgorand25 {
			return "", nil, fmt.Errorf("load keys: %w (%s). "+
				"Back it up first: replacing the wallet deletes its phrase, and with it the Algorand account. "+
				"Then replace it with a 24-word phrase, or keep it and set a 24-word phrase in a *_MNEMONIC environment variable",
				ErrWalletNoSolanaKey, dir)
		}
		return "", nil, fmt.Errorf("load keys: %w", err)
	}
	return dir, sk, nil
}

func loadPayer(ctx context.Context, opts PayerOptions, kr KeyringOptions, env []keystore.SecretProvider) (Payer, error) {
	dir, meta, ks, err := loadKeys(ctx, opts, kr, env)
	if err != nil {
		return Payer{}, err
	}
	addr, err := choosePayer(opts.Address, ks, dir)
	if err != nil {
		return Payer{}, err
	}
	p := Payer{Signer: ks.Signer(addr)}
	if addr == meta.Address {
		p.Network = meta.Network
	}
	return p, nil
}

func loadSolanaPayer(ctx context.Context, opts PayerOptions, kr KeyringOptions, env []keystore.SecretProvider) (SolanaPayer, error) {
	dir, sk, err := loadSolanaKeys(ctx, opts, kr, env)
	if err != nil {
		return SolanaPayer{}, err
	}
	addr, err := chooseSolanaPayer(opts.Address, sk, dir)
	if err != nil {
		return SolanaPayer{}, err
	}
	return SolanaPayer{Signer: sk.Signer(addr)}, nil
}

// payerProviders is opts.Wallet's provider, else that of the wallet in
// opts.Dir when one exists, ahead of env.
func payerProviders(opts PayerOptions, kr KeyringOptions, env []keystore.SecretProvider) (string, Metadata, []keystore.SecretProvider, error) {
	if w := opts.Wallet; w != nil {
		// A wallet the host opened is there by its own decision: no
		// ExistsIn check, so one that isn't is an error below, not no key.
		meta, err := w.Metadata()
		if err != nil {
			return "", Metadata{}, nil, fmt.Errorf("read wallet in %s: %w", w.dir, err)
		}
		return w.dir, meta, append([]keystore.SecretProvider{w.Provider()}, env...), nil
	}
	dir := opts.Dir
	if dir == "" {
		d, err := HomeDir()
		if err != nil {
			return "", Metadata{}, nil, err
		}
		dir = d
	}
	var providers []keystore.SecretProvider
	var meta Metadata
	// Checked through the descriptor, so a machine without a wallet never
	// touches a keychain. A wallet that is there but does not open is an
	// error, never a reason to pay with another key.
	if ExistsIn(dir) {
		w, err := Open(dir, kr)
		if err != nil {
			return "", Metadata{}, nil, fmt.Errorf("open wallet in %s: %w", dir, err)
		}
		if meta, err = w.Metadata(); err != nil {
			return "", Metadata{}, nil, fmt.Errorf("read wallet in %s: %w", dir, err)
		}
		providers = append(providers, w.Provider())
	}
	return dir, meta, append(providers, env...), nil
}

// choiceError is a payer-choice refusal: its own text, matching its sentinel
// under errors.Is.
type choiceError struct {
	sentinel error
	msg      string
}

func (e *choiceError) Error() string        { return e.msg }
func (e *choiceError) Is(target error) bool { return target == e.sentinel }

// choosePayer is ChoosePayer; dir, when set, is where the wallet was looked
// for, which the refusal for no keys names.
func choosePayer(want string, keys Keys, dir string) (string, error) {
	addrs := keys.Addresses()
	switch {
	// First, so a config naming its payer, left with nothing loaded, hears
	// where keys come from rather than that its one is missing.
	case len(addrs) == 0:
		where := "the wallet"
		if dir != "" {
			where = "a wallet in " + dir
		}
		return "", &choiceError{ErrNoKeys, fmt.Sprintf("no keys loaded: none from %s, and none from <NAME>_MNEMONIC or %s in the environment",
			where, keystore.MnemonicURLsEnv)}
	case want != "":
		// HasAccount, not addrs: a listed phrase's unlisted twin is signable.
		if !keys.HasAccount(want) {
			return "", &choiceError{ErrPayerNotLoaded, fmt.Sprintf("payer %s is not among the loaded keys %v", want, addrs)}
		}
		return want, nil
	case len(addrs) == 1:
		return addrs[0], nil
	default:
		return "", &choiceError{ErrPayerUnchosen, fmt.Sprintf("%d keys loaded (%s); name the paying address", len(addrs), strings.Join(addrs, ", "))}
	}
}

func chooseSolanaPayer(want string, keys Keys, dir string) (string, error) {
	if addrs := keys.Addresses(); want != "" && len(addrs) > 0 {
		if _, err := solana.ParsePublicKey(want); err != nil {
			return "", &choiceError{ErrPayerNotLoaded, fmt.Sprintf("payer %s is not a Solana address; the loaded Solana keys are %v", want, addrs)}
		}
	}
	return choosePayer(want, keys, dir)
}
