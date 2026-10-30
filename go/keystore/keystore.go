/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package keystore

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	xhd "github.com/algonode/go-algorand-hd-wallet/XHDWalletAPI"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/mnemonic"
	"github.com/algorand/go-algorand-sdk/v2/types"
	bip39 "github.com/tyler-smith/go-bip39"
)

// KeyStore is an in-memory address → signer map populated from one or more
// SecretProviders at construction time. It satisfies proto.BytesSigner (so
// it can sign tickets via Ticket.Sign) and the proto/algo.MultipleWalletSigner
// interface (so it can drive raw transactions and AtomicTransactionComposer
// signers via algo's adapters).
//
// Each loaded address is backed by an accountKey, which is one of two
// concrete forms: a standard 25-word Algorand key (a seed-based ed25519
// private key) or a 24-word BIP-39 / ARC-52 xHD key (the recovery phrase the
// client exports). Both produce signatures that verify under standard ed25519
// against the derived address; they differ only in how the secret is held and
// used. See accountKey.
//
// KeyStore is read-only after New returns: there is no AddMnemonic at
// runtime. Adding a key means rebuilding the store — which in practice
// means restarting the process with new provider configuration. This
// keeps the lifecycle simple (no locking on the hot path) and matches
// the deployment model: mnemonics come from the environment / a secrets
// vault and don't change while the binary is running.
type KeyStore struct {
	keys map[string]accountKey
	// unlisted holds keys loaded only as the legacy twin of another entry's
	// phrase (see add): signable, but not offered by Addresses, so one
	// phrase doesn't read as two payers.
	unlisted map[string]bool
}

// accountKey is one loaded signing identity. Two concrete forms back it:
// stdKey (a 25-word Algorand mnemonic held as a seed-based ed25519 private
// key) and hdKey (a 24-word BIP-39 / ARC-52 xHD mnemonic). The two differ
// only in how they hold and use their secret: an xHD key's signing scalar is
// derived through BIP32-Ed25519 and is NOT representable as a 32-byte ed25519
// seed, so it must sign through the extended key rather than ed25519.Sign.
// Both produce signatures that verify under standard ed25519 against the
// derived address.
// There is exactly ONE byte-signing framing here, deliberately. An earlier
// third method signed under Algorand's "MX" sign-bytes domain tag; it had no
// production caller, and carrying two framings on one interface meant every
// key form had to implement both while only one was ever exercised. If an
// MX-framed signature is ever genuinely needed, add it back with the caller
// that needs it, not ahead of one.
type accountKey interface {
	// signTransaction signs tx and returns (txID, signedTxnBytes).
	signTransaction(tx types.Transaction) (string, []byte, error)
	// signBytesRaw signs msg verbatim: no domain tag, no hashing. This is
	// the proto.BytesSigner contract — callers hand it a precomputed
	// sha256 digest of a domain-tagged canonical body.
	signBytesRaw(msg []byte) ([]byte, error)
}

// stdKey is a standard 25-word Algorand mnemonic, decoded to a seed-based
// ed25519 private key. Its sign methods delegate to go-algorand-sdk crypto.
type stdKey struct {
	priv ed25519.PrivateKey
}

func (k stdKey) signTransaction(tx types.Transaction) (string, []byte, error) {
	return crypto.SignTransaction(k.priv, tx)
}

func (k stdKey) signBytesRaw(msg []byte) ([]byte, error) {
	if len(k.priv) != ed25519.PrivateKeySize {
		return nil, errors.New("keystore: stored private key has wrong length")
	}
	return ed25519.Sign(k.priv, msg), nil
}

// hdKey is a 24-word BIP-39 / ARC-52 xHD mnemonic. It signs through the
// extended key derived at m/44'/283'/0'/0/0 (Peikert variant) — the same
// path and account the client's passkey-derived wallet uses — so an exported
// recovery phrase loads the exact same address and signs identically.
//
// Tradeoff: AlgoPath holds the *xHD root* (it re-derives the leaf per sign),
// so an hdKey keeps the whole-tree secret in memory rather than just the leaf
// signing key a stdKey holds — a slightly larger blast radius. That's a
// constraint of the lib: its verbatim extended-key signer is unexported, so
// there's no public way to sign from a standalone 96-byte leaf. The proxy
// only ever needs this one leaf. Signing is concurrency-safe: DeriveKey
// copies the root and never mutates shared state (see the race test).
type hdKey struct {
	path xhd.AlgoPath
}

func (k hdKey) signTransaction(tx types.Transaction) (string, []byte, error) {
	return k.path.SignTransaction(tx)
}

func (k hdKey) signBytesRaw(msg []byte) ([]byte, error) {
	return k.path.SignBytes(msg)
}

// New aggregates mnemonics across providers and returns a KeyStore. Each
// provider is consulted exactly once. Empty-mnemonic entries are
// skipped; entries that fail to decode (bad checksum, wrong word count)
// fail the build with a wrapped error so misconfiguration surfaces at
// startup rather than at first sign. A valid 12- to 21-word BIP-39 phrase
// is a Solana wallet's and is skipped, unless it is all New was given.
//
// New is safe to call with no providers — the resulting KeyStore has no
// addresses and HasAccount returns false for everything. This is the
// "feature-disabled" mode for binaries that may run without signing
// (the proxy with admission disabled, for example).
func New(ctx context.Context, providers ...SecretProvider) (*KeyStore, error) {
	ks := &KeyStore{keys: map[string]accountKey{}, unlisted: map[string]bool{}}
	skippedName, skippedWords := "", 0
	skippedKey := ""
	for i, p := range providers {
		if p == nil {
			continue
		}
		entries, err := p.Mnemonics(ctx)
		if err != nil {
			return nil, fmt.Errorf("keystore: provider[%d] (%T): %w", i, p, err)
		}
		for _, e := range entries {
			if strings.TrimSpace(e.Mnemonic) == "" {
				continue
			}
			// A Solana keypair file's array or base58 secret key is the
			// Solana keystore's, as a Solana-only phrase is below. A malformed
			// one is a typo either way and fails, named as the key it looks
			// like: no Algorand form starts with "[" or is one long word.
			if _, isKey, err := solanaSecretKey(e.Mnemonic); isKey {
				if err != nil {
					return nil, fmt.Errorf("keystore: secret %q %w", e.Name, err)
				}
				slog.WarnContext(ctx, "keystore: Solana secret key skipped; the Algorand keystore takes 25 words or a 24-word BIP-39 phrase",
					slog.String("name", e.Name))
				if skippedKey == "" {
					skippedKey = e.Name
				}
				continue
			}
			// A valid 12- to 21-word BIP-39 phrase is a Solana wallet's
			// (Phantom and Solflare export 12 words): no Algorand form takes
			// it, and one provider chain may hold keys for both rails, so it
			// is left to NewSolanaKeys rather than failing this load. One
			// that isn't valid BIP-39 is a typo either way and still fails.
			if words := strings.Fields(e.Mnemonic); solanaOnlyLength(len(words)) && bip39.IsMnemonicValid(strings.Join(words, " ")) {
				slog.WarnContext(ctx, "keystore: Solana-length phrase skipped; the Algorand keystore takes 25 words or a 24-word BIP-39 phrase",
					slog.String("name", e.Name), slog.Int("words", len(words)))
				if skippedWords == 0 {
					skippedName, skippedWords = e.Name, len(words)
				}
				continue
			}
			if err := ks.add(ctx, e); err != nil {
				return nil, err
			}
		}
	}
	// Skipped phrases and nothing else: a Solana phrase where an Algorand
	// key was wanted. Failing here keeps the startup error naming the phrase
	// instead of a later "no mnemonic loaded".
	if len(ks.keys) == 0 && skippedWords != 0 {
		return nil, fmt.Errorf("keystore: mnemonic %q: a %d-word phrase is a Solana wallet's; want a 25-word Algorand mnemonic or a 24-word BIP-39 phrase", skippedName, skippedWords)
	}
	if len(ks.keys) == 0 && skippedKey != "" {
		return nil, fmt.Errorf("keystore: secret %q is a Solana secret key; want a 25-word Algorand mnemonic or a 24-word BIP-39 phrase", skippedKey)
	}
	slog.InfoContext(ctx, "keystore loaded", slog.Int("addresses", len(ks.keys)))
	return ks, nil
}

func (k *KeyStore) add(ctx context.Context, entry MnemonicEntry) error {
	m := strings.TrimSpace(entry.Mnemonic)
	addr, signer, kind, err := decodeMnemonic(m, fmt.Sprintf("mnemonic %q", entry.Name))
	if err != nil {
		return err
	}
	// A 24-word phrase whose spacing isn't canonical loaded another account
	// before decodeMnemonic rejoined the words, and funds may sit there. Load
	// that key too, so nothing that named it breaks, and say where to move
	// them. Addresses lists only the entry's own address of the pair.
	if legacyAddr, legacyKey, ok := legacySpacingKey(m); ok && legacyAddr != addr {
		slog.WarnContext(ctx, "keystore: this phrase's spacing derives a second, legacy address; both are loaded. Move any funds at the legacy address to the canonical one",
			slog.String("canonical_address", addr),
			slog.String("legacy_address", legacyAddr),
			slog.String("name", entry.Name))
		other, otherKey := legacyAddr, legacyKey
		if entry.LegacySpacing {
			other, otherKey = addr, signer
			addr, signer = legacyAddr, legacyKey
		}
		if _, taken := k.keys[other]; !taken {
			k.keys[other] = otherKey
			k.unlisted[other] = true
		}
	}
	if _, exists := k.keys[addr]; exists {
		if k.unlisted[addr] {
			// Loaded as another entry's legacy twin; this entry names it.
			delete(k.unlisted, addr)
			return nil
		}
		// Two providers handed us the same key. Not fatal — log and skip
		// the duplicate so a fallback chain (env → cloud) doesn't blow up
		// when both are populated for the same address.
		slog.WarnContext(ctx, "keystore: duplicate address skipped",
			slog.String("address", addr),
			slog.String("name", entry.Name))
		return nil
	}
	k.keys[addr] = signer
	slog.InfoContext(ctx, "keystore: address loaded",
		slog.String("address", addr),
		slog.String("name", entry.Name),
		slog.String("kind", kind))
	return nil
}

// decodeMnemonic turns a mnemonic into its derived address and an accountKey,
// dispatching on word count:
//
//   - 25 words → a standard Algorand mnemonic (seed-based ed25519 key).
//   - 24 words → a BIP-39 / ARC-52 xHD recovery phrase. The checksum is
//     validated first (so a typo fails at startup rather than silently
//     loading a different address), then the first indexed account
//     m/44'/283'/0'/0/0 is derived with the Peikert variant — matching the
//     client's keyGen(KeyContext.Address, 0, 0). Note the derived scalar is
//     not seed-representable, so an hdKey signs through the extended key.
//
// Any other word count is a configuration error. kind is a short label for
// logs ("algorand-25" / "xhd-24"). what names the phrase in errors.
func decodeMnemonic(m, what string) (addr string, key accountKey, kind string, err error) {
	words := strings.Fields(m)
	// BIP-39 seeds PBKDF2 with the sentence string itself, words joined by
	// single spaces, and go-bip39 hashes whatever it is given. A phrase with
	// a double space or line breaks would validate word by word and then
	// load a different account. Rejoin the words first, for both forms.
	m = strings.Join(words, " ")
	switch n := len(words); n {
	case 25:
		priv, err := mnemonic.ToPrivateKey(m)
		if err != nil {
			// Not wrapped: the SDK's error quotes a word it does not know,
			// which is a mistyped word of the secret, and this error is logged.
			return "", nil, "", fmt.Errorf("keystore: %s: invalid 25-word Algorand mnemonic (bad word or checksum)", what)
		}
		account, err := crypto.AccountFromPrivateKey(priv)
		if err != nil {
			return "", nil, "", fmt.Errorf("keystore: derive address from %s: %w", what, err)
		}
		return account.Address.String(), stdKey{priv: priv}, "algorand-25", nil
	case 24:
		if !bip39.IsMnemonicValid(m) {
			return "", nil, "", fmt.Errorf("keystore: %s: invalid 24-word BIP-39 phrase (bad word or checksum)", what)
		}
		w, err := xhd.NewWallet(bip39.NewSeed(m, "")) // Peikert (g=9), matching the client
		if err != nil {
			return "", nil, "", fmt.Errorf("keystore: derive xHD root from %s: %w", what, err)
		}
		path := w.Path00(0) // m/44'/283'/0'/0/0
		account, err := path.AlgorandAddress()
		if err != nil {
			return "", nil, "", fmt.Errorf("keystore: derive address from %s: %w", what, err)
		}
		return account.String(), hdKey{path: path}, "xhd-24", nil
	default:
		return "", nil, "", fmt.Errorf("keystore: %s: unsupported word count %d (want 25-word Algorand or 24-word BIP-39)", what, n)
	}
}

// DeriveAddress returns the address and kind ("algorand-25" / "xhd-24") a
// mnemonic loads as, without building a KeyStore, which logs every address it
// loads.
func DeriveAddress(mnemonic string) (addr, kind string, err error) {
	addr, _, kind, err = decodeMnemonic(strings.TrimSpace(mnemonic), "recovery phrase")
	return addr, kind, err
}

// LegacySpacingAddress returns the address a valid 24-word phrase loaded as
// before its words were rejoined, when its spacing makes that differ from
// DeriveAddress's.
func LegacySpacingAddress(mnemonic string) (string, bool) {
	addr, _, ok := legacySpacingKey(strings.TrimSpace(mnemonic))
	return addr, ok
}

// legacySpacingKey derives a 24-word phrase from its text as given, which is
// what decodeMnemonic did before it rejoined the words: BIP-39 seeds PBKDF2
// with the sentence, so other separators gave another account. ok is false
// for a phrase already single-spaced, or one that isn't a valid 24 words.
func legacySpacingKey(m string) (string, accountKey, bool) {
	words := strings.Fields(m)
	if len(words) != 24 || strings.Join(words, " ") == m || !bip39.IsMnemonicValid(m) {
		return "", nil, false
	}
	w, err := xhd.NewWallet(bip39.NewSeed(m, ""))
	if err != nil {
		return "", nil, false
	}
	path := w.Path00(0)
	account, err := path.AlgorandAddress()
	if err != nil {
		return "", nil, false
	}
	return account.String(), hdKey{path: path}, true
}

// HasAccount reports whether the keystore holds a private key for addr.
func (k *KeyStore) HasAccount(addr string) bool {
	_, ok := k.keys[addr]
	return ok
}

// Addresses returns the loaded addresses in deterministic order. Useful
// for startup logs and validation ("does the configured signing address
// match anything we loaded?").
//
// A phrase whose spacing also derives a legacy address contributes one entry:
// its canonical address, or for an entry marked LegacySpacing the legacy one.
// The other is signable (HasAccount) but not listed, so one phrase never
// reads as two payers.
func (k *KeyStore) Addresses() []string {
	out := make([]string, 0, len(k.keys))
	for a := range k.keys {
		if !k.unlisted[a] {
			out = append(out, a)
		}
	}
	sort.Strings(out)
	return out
}

// AccountSigner is a KeyStore with one of its addresses chosen as the signer,
// which is the shape zs.Signer takes.
type AccountSigner struct {
	*KeyStore
	addr string
}

// Address is the chosen address. The KeyStore may not hold it: a caller
// checks with HasAccount.
func (s AccountSigner) Address() string { return s.addr }

// Signer chooses addr as the signing address.
func (k *KeyStore) Signer(addr string) AccountSigner {
	return AccountSigner{KeyStore: k, addr: addr}
}

// SignWithAccount signs tx with the key for publicAddress and returns
// (txID, signedTxnBytes, error). Satisfies the transaction half of
// proto/algo.MultipleWalletSigner.
func (k *KeyStore) SignWithAccount(_ context.Context, tx types.Transaction, publicAddress string) (string, []byte, error) {
	key, ok := k.keys[publicAddress]
	if !ok {
		return "", nil, fmt.Errorf("keystore: no key for address %s", publicAddress)
	}
	return key.signTransaction(tx)
}

// SignBytes signs msg verbatim with the key for addr — no domain prefix,
// no hashing. Satisfies proto.BytesSigner so the keystore can back
// proto.Ticket.Sign and any other sign-bytes call site that wants to
// control its own framing.
func (k *KeyStore) SignBytes(_ context.Context, addr string, msg []byte) ([]byte, error) {
	key, ok := k.keys[addr]
	if !ok {
		return nil, fmt.Errorf("keystore: no key for address %s", addr)
	}
	return key.signBytesRaw(msg)
}
