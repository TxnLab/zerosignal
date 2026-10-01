/*
 * Copyright (c) 2021-2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Package algo adapts a custody backend to the Algorand SDK's transaction
// signer. It is deliberately the whole surface: one interface a keystore
// implements, and one adapter that turns it into a
// transaction.TransactionSigner for an atomic transaction composer.
//
// This package used to carry a general signing toolkit — group signers, a
// frontend JSON encoding, logic-sig and raw-key signers, an unsigned
// "simulate" signer, and an address blocklist. None of it had a caller, and
// the blocklist in particular read like an active safety control while being
// reachable only from another dead symbol. Signing that nothing exercises is
// worse than absent: it has no feedback loop, and a reader auditing the
// signing path has to prove each piece dead before trusting the one piece
// that isn't.
package algo

import (
	"context"

	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// MultipleWalletSigner is a custody backend holding zero or more Algorand
// accounts — the seam between proto/go/keystore (or a proxy wallet) and the
// SDK. Both methods are transaction signing; raw-byte signing over a ticket,
// receipt, or advertisement is ticket.BytesSigner, a deliberately separate
// contract so an implementer cannot conflate the two framings.
type MultipleWalletSigner interface {
	// HasAccount reports whether this backend can sign for publicAddress.
	HasAccount(publicAddress string) bool
	// SignWithAccount signs tx under publicAddress, returning the transaction
	// ID and the msgpack-encoded SignedTxn.
	SignWithAccount(ctx context.Context, tx types.Transaction, publicAddress string) (string, []byte, error)
}

// SignWithAccountForATC adapts a MultipleWalletSigner to the SDK's
// TransactionSigner so an atomic transaction composer can sign under
// publicAddress.
func SignWithAccountForATC(keyManager MultipleWalletSigner, publicAddress string) transaction.TransactionSigner {
	return &kmdSigner{
		keyManager: keyManager,
		address:    publicAddress,
	}
}

type kmdSigner struct {
	keyManager MultipleWalletSigner
	address    string
}

func (k *kmdSigner) SignTransactions(txGroup []types.Transaction, indexesToSign []int) ([][]byte, error) {
	stxs := make([][]byte, len(indexesToSign))
	for i, pos := range indexesToSign {
		_, stxBytes, err := k.keyManager.SignWithAccount(context.Background(), txGroup[pos], k.address)
		if err != nil {
			return nil, err
		}

		stxs[i] = stxBytes
	}

	return stxs, nil
}

func (k *kmdSigner) Equals(other transaction.TransactionSigner) bool {
	if castedSigner, ok := other.(*kmdSigner); ok {
		return castedSigner.address == k.address
	}
	return false
}
