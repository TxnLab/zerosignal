/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package keystore

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	bip39 "github.com/tyler-smith/go-bip39"

	"github.com/TxnLab/zerosignal/go/solana"
)

// solanaPath is m/44'/501'/0'/0', the account Phantom and Solflare derive by
// default, and solana-keygen with `--derivation-path` (or `prompt://?key=0/0`).
// Plain `solana-keygen new` / `recover` use no path at all, so a phrase from
// those shows a different address here than in solana-keygen. An array, so
// no caller can change the path every later derivation takes.
var solanaPath = [...]uint32{44, 501, 0, 0}

const hardened = 0x80000000

// Slip10Ed25519 derives the SLIP-0010 Ed25519 key and chain code at path from
// seed. Ed25519 has only hardened children, so every index is taken hardened
// whatever its top bit.
func Slip10Ed25519(seed []byte, path []uint32) (key, chainCode [32]byte) {
	var data [37]byte
	step := func(hmacKey, msg []byte) {
		m := hmac.New(sha512.New, hmacKey)
		m.Write(msg)
		out := m.Sum(nil)
		copy(key[:], out[:32])
		copy(chainCode[:], out[32:])
		clear(out)
	}
	step([]byte("ed25519 seed"), seed)
	for _, i := range path {
		data[0] = 0
		copy(data[1:33], key[:])
		binary.BigEndian.PutUint32(data[33:], i|hardened)
		parentChain := chainCode
		step(parentChain[:], data[:])
		clear(parentChain[:])
	}
	clear(data[:])
	return key, chainCode
}

// solanaOnlyLength reports whether n words can only be a Solana phrase here:
// a valid BIP-39 length that is neither Algorand form.
func solanaOnlyLength(n int) bool {
	return n == 12 || n == 15 || n == 18 || n == 21
}

// SolanaKeyFromPhrase derives a phrase's Solana key at m/44'/501'/0'/0' from
// its BIP-39 seed with an empty passphrase. Any BIP-39 length loads, since
// Phantom and Solflare export 12 words; each word must be an English BIP-39
// word as written, and the checksum must hold, so a typo fails here rather
// than loading another account. Separators are not part of a phrase: the seed
// is PBKDF2 over the words rejoined by single spaces, as decodeMnemonic does.
// No error quotes a word of the phrase.
func SolanaKeyFromPhrase(phrase string) (ed25519.PrivateKey, error) {
	words := strings.Fields(phrase)
	if n := len(words); !solanaOnlyLength(n) && n != 24 {
		return nil, fmt.Errorf("unsupported word count %d for a Solana key (want a 12- to 24-word BIP-39 phrase)", n)
	}
	m := strings.Join(words, " ")
	if !bip39.IsMnemonicValid(m) {
		return nil, fmt.Errorf("invalid %d-word BIP-39 phrase (bad word or checksum)", len(words))
	}
	seed := bip39.NewSeed(m, "")
	key, chain := Slip10Ed25519(seed, solanaPath[:])
	clear(seed)
	clear(chain[:])
	priv := ed25519.NewKeyFromSeed(key[:])
	clear(key[:])
	return priv, nil
}

// SolanaAddress is the base58 address of a Solana key.
func SolanaAddress(priv ed25519.PrivateKey) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", errors.New("keystore: not an Ed25519 private key")
	}
	return solana.PublicKey(priv.Public().(ed25519.PublicKey)).String(), nil
}

// SolanaKeys is the Solana counterpart of KeyStore: the phrases the same
// providers hold, each derived at m/44'/501'/0'/0', keyed by base58 address.
// A 25-word Algorand mnemonic has no Solana derivation any wallet shares, so
// it is skipped rather than loaded as a key nobody else could recover, as New
// skips a phrase only Solana takes, unless it is all NewSolanaKeys was given.
type SolanaKeys struct {
	keys map[string]ed25519.PrivateKey
}

// NewSolanaKeys loads every BIP-39 phrase the providers hold. A phrase that
// fails to decode fails the load, as in New.
func NewSolanaKeys(ctx context.Context, providers ...SecretProvider) (*SolanaKeys, error) {
	ks := &SolanaKeys{keys: map[string]ed25519.PrivateKey{}}
	skippedName := ""
	for i, p := range providers {
		if p == nil {
			continue
		}
		entries, err := p.Mnemonics(ctx)
		if err != nil {
			return nil, fmt.Errorf("keystore: provider[%d] (%T): %w", i, p, err)
		}
		for _, e := range entries {
			n := len(strings.Fields(e.Mnemonic))
			if n == 0 {
				continue
			}
			if n == 25 {
				if skippedName == "" {
					skippedName = e.Name
				}
				continue
			}
			priv, err := SolanaKeyFromPhrase(e.Mnemonic)
			if err != nil {
				return nil, fmt.Errorf("keystore: mnemonic %q: %w", e.Name, err)
			}
			addr, err := SolanaAddress(priv)
			if err != nil {
				return nil, err
			}
			if _, dup := ks.keys[addr]; dup {
				slog.WarnContext(ctx, "keystore: duplicate Solana address skipped", slog.String("address", addr), slog.String("name", e.Name))
				continue
			}
			ks.keys[addr] = priv
			slog.InfoContext(ctx, "keystore: Solana address loaded", slog.String("address", addr), slog.String("name", e.Name))
		}
	}
	// Algorand mnemonics and nothing else, as New refuses Solana phrases and
	// nothing else: the startup error names the phrase instead of a later "no
	// key loaded".
	if len(ks.keys) == 0 && skippedName != "" {
		return nil, fmt.Errorf("keystore: mnemonic %q: a 25-word Algorand mnemonic has no Solana key; want a BIP-39 phrase of 12 to 24 words", skippedName)
	}
	return ks, nil
}

// HasAccount reports whether the store holds the key for addr.
func (k *SolanaKeys) HasAccount(addr string) bool {
	_, ok := k.keys[addr]
	return ok
}

// Addresses returns the loaded addresses in order.
func (k *SolanaKeys) Addresses() []string {
	out := make([]string, 0, len(k.keys))
	for a := range k.keys {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// SignBytes signs msg verbatim with addr's key, the ticket.BytesSigner
// contract the reserve request is signed through.
func (k *SolanaKeys) SignBytes(_ context.Context, addr string, msg []byte) ([]byte, error) {
	return k.sign(addr, msg)
}

// SignTransactionMessage signs a Solana transaction's message with addr's
// key, the solana.TransactionSigner contract. The signature is the same raw
// Ed25519 as SignBytes; the two stay separate methods so a host can keep its
// own policy on each.
func (k *SolanaKeys) SignTransactionMessage(_ context.Context, addr string, message []byte) ([]byte, error) {
	return k.sign(addr, message)
}

func (k *SolanaKeys) sign(addr string, msg []byte) ([]byte, error) {
	priv, ok := k.keys[addr]
	if !ok {
		return nil, fmt.Errorf("keystore: no Solana key for address %s", addr)
	}
	return ed25519.Sign(priv, msg), nil
}

// SolanaAccountSigner is a SolanaKeys with one of its addresses chosen as the
// signer, the shape zs.SolanaSigner takes. It signs as that address only, as
// the TS SDK's solanaSigner does: a spec naming another account the store
// holds would otherwise be signed with that account's key.
type SolanaAccountSigner struct {
	*SolanaKeys
	addr string
}

// Address is the chosen address. The store may not hold it: a caller checks
// with HasAccount.
func (s SolanaAccountSigner) Address() string { return s.addr }

// SignBytes is SolanaKeys.SignBytes for the chosen address alone.
func (s SolanaAccountSigner) SignBytes(_ context.Context, addr string, msg []byte) ([]byte, error) {
	return s.signAs(addr, msg)
}

// SignTransactionMessage is SolanaKeys.SignTransactionMessage for the chosen
// address alone.
func (s SolanaAccountSigner) SignTransactionMessage(_ context.Context, addr string, message []byte) ([]byte, error) {
	return s.signAs(addr, message)
}

func (s SolanaAccountSigner) signAs(addr string, msg []byte) ([]byte, error) {
	if addr != s.addr {
		return nil, fmt.Errorf("keystore: signer holds %s, asked to sign for %s", s.addr, addr)
	}
	return s.sign(addr, msg)
}

// Signer chooses addr as the signing address.
func (k *SolanaKeys) Signer(addr string) SolanaAccountSigner {
	return SolanaAccountSigner{SolanaKeys: k, addr: addr}
}
