/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package wallet

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/TxnLab/zerosignal/go/keystore"
)

// PayerOptions chooses the key LoadPayer or LoadSolanaPayer pays with. The zero value loads the
// wallet in DefaultDir and the environment's keys, and pays with the only one.
type PayerOptions struct {
	// Address is the paying address, base58 for LoadSolanaPayer; "" takes the
	// only key loaded.
	Address string
	// Dir holds the wallet; "" is DefaultDir.
	Dir string
	// Backend opens a wallet whose descriptor records no backend; "" is
	// BackendFile (see KeyringOptions.Backend). A release zs-proxy passes
	// BackendOS here.
	Backend string
	// Passphrase unlocks a wallet on the encrypted file; nil is
	// EnvOrPromptPassphrase, which reads the terminal on stdin.
	Passphrase func(prompt string) (string, error)
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
// 25-word Algorand mnemonic has no Solana key and is skipped.
func LoadSolanaPayer(ctx context.Context, opts PayerOptions) (SolanaPayer, error) {
	kr, env := payerSources(opts)
	return loadSolanaPayer(ctx, opts, kr, env)
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

func loadPayer(ctx context.Context, opts PayerOptions, kr KeyringOptions, env []keystore.SecretProvider) (Payer, error) {
	dir, meta, providers, err := payerProviders(opts, kr, env)
	if err != nil {
		return Payer{}, err
	}
	ks, err := keystore.New(ctx, providers...)
	if err != nil {
		return Payer{}, fmt.Errorf("load keys: %w", err)
	}
	addr, err := choosePayer(opts.Address, ks.Addresses(), dir)
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
	dir, _, providers, err := payerProviders(opts, kr, env)
	if err != nil {
		return SolanaPayer{}, err
	}
	ks, err := keystore.NewSolanaKeys(ctx, providers...)
	if err != nil {
		return SolanaPayer{}, fmt.Errorf("load keys: %w", err)
	}
	addr, err := choosePayer(opts.Address, ks.Addresses(), dir)
	if err != nil {
		return SolanaPayer{}, err
	}
	return SolanaPayer{Signer: ks.Signer(addr)}, nil
}

// payerProviders opens the wallet in opts.Dir, when one exists, ahead of env.
func payerProviders(opts PayerOptions, kr KeyringOptions, env []keystore.SecretProvider) (string, Metadata, []keystore.SecretProvider, error) {
	dir := opts.Dir
	if dir == "" {
		d, err := DefaultDir()
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

func choosePayer(want string, addrs []string, dir string) (string, error) {
	switch {
	case want != "":
		if !slices.Contains(addrs, want) {
			return "", fmt.Errorf("payer %s is not among the loaded keys %v", want, addrs)
		}
		return want, nil
	case len(addrs) == 1:
		return addrs[0], nil
	case len(addrs) == 0:
		return "", fmt.Errorf("no keys loaded: none from a wallet in %s, and none from <NAME>_MNEMONIC or %s in the environment",
			dir, keystore.MnemonicURLsEnv)
	default:
		return "", fmt.Errorf("%d keys loaded (%s); name the paying address", len(addrs), strings.Join(addrs, ", "))
	}
}
