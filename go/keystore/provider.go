/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Package keystore loads Algorand mnemonics from one or more secret
// backends (the OS environment, AWS Secrets Manager, GCP Secret Manager,
// Azure Key Vault) and exposes a single signer surface that handles raw
// transactions, AtomicTransactionComposer-shaped signing, and raw
// sign-bytes payloads (the form hayai tickets / receipts use — see
// proto/ticket/ticket.go and proto/ticket/receipt.go, where the caller
// hands the signer a precomputed sha256 digest of a domain-tagged
// canonical body).
//
// Two mnemonic forms are accepted, dispatched on word count:
//   - 25 words: a standard Algorand mnemonic (seed-based ed25519 key).
//   - 24 words: a BIP-39 / ARC-52 xHD recovery phrase (the form the client
//     exports). The first indexed account m/44'/283'/0'/0/0 is derived with
//     the Peikert variant, matching the client's keyGen(KeyContext.Address,
//     0, 0), so an exported phrase loads the same address the client uses.
//
// Loading is eager: New iterates each provider once at startup, derives
// the Algorand address from each mnemonic, and stores a per-address signer.
// Subsequent SignWithAccount / SignBytes calls are constant-time map
// lookups — no provider re-fetch on the request hot path. Add new mnemonics
// by reconfiguring providers and rebuilding the keystore (typically restart,
// since providers are constructed at boot).
package keystore

import "context"

// MnemonicEntry is a single mnemonic plus a human-readable label. The
// mnemonic is either a 25-word Algorand mnemonic or a 24-word BIP-39 /
// ARC-52 xHD recovery phrase (see the package doc). The label is
// informational only — it does NOT influence which Algorand address the
// mnemonic derives to and is not used for lookups (KeyStore is keyed by the
// derived address). It exists so logs and error messages can name the
// mnemonic source without leaking the mnemonic itself.
//
// An entry whose Mnemonic is the empty string is treated as "not found"
// by KeyStore.New and silently skipped — this lets providers report
// "asked for foo, didn't have it" without erroring out the whole load.
type MnemonicEntry struct {
	Name     string
	Mnemonic string
}

// SecretProvider is the seam between the keystore and an arbitrary
// secret-storage backend. A provider returns every mnemonic it can
// supply for this process; KeyStore.New aggregates across providers.
//
// Implementations are expected to do their I/O inside Mnemonics — the
// keystore calls this exactly once per provider during startup. A
// provider that wraps a remote service (Secrets Manager, Key Vault) MUST
// honor the supplied context for cancellation; a misconfigured backend
// should not stall startup indefinitely.
//
// Returning an error fails the whole keystore build. If a provider can
// distinguish "configured but unreachable" from "no entries configured",
// it SHOULD return nil + empty slice for the second case so the keystore
// remains buildable in environments where this provider is unused.
type SecretProvider interface {
	Mnemonics(ctx context.Context) ([]MnemonicEntry, error)
}
