/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package solana

import (
	"context"
	"fmt"
	"slices"
)

// TransactionSigner is the custody seam for a Solana transaction signature,
// as algo.MultipleWalletSigner is for an Algorand one: the key stays with the
// host (a keystore, a wallet worker), which signs whatever message it is
// handed. A Solana signature is raw Ed25519 over the message bytes, the same
// primitive ticket.BytesSigner exposes, but it is a separate method so a host
// can route each to its own custody path and so neither framing is mistaken
// for the other. An off-chain message signer that prefixes its input, or
// refuses bytes that parse as a transaction, cannot implement it.
//
// It signs blindly. A message someone else built must pass its verifier
// first, which zsescrow's Complete functions do before they call it.
type TransactionSigner interface {
	// SignTransactionMessage returns the 64-byte Ed25519 signature of message
	// under address's key. address is base58.
	SignTransactionMessage(ctx context.Context, address string, message []byte) ([]byte, error)
}

// SignWith has signer sign t's message as key and puts the signature in key's
// slot among the message's signers, leaving the other slots as they are. The
// signature must verify under key as the runtime checks it, so a host that
// signs with another key (the payer's Algorand key, say) fails here rather
// than on chain.
func (t *Transaction) SignWith(ctx context.Context, key PublicKey, signer TransactionSigner) error {
	// Sanitized first, so the header's signer count fits the keys.
	msg, err := t.Message.MarshalBinary()
	if err != nil {
		return err
	}
	n := int(t.Message.Header.NumRequiredSignatures)
	if len(t.Signatures) != n {
		return malformed("%d signatures for %d signers", len(t.Signatures), n)
	}
	i := slices.Index(t.Message.AccountKeys[:n], key)
	if i < 0 {
		return fmt.Errorf("solana: %s is not a signer of this message", key)
	}
	sig, err := signer.SignTransactionMessage(ctx, key.String(), msg)
	if err != nil {
		return fmt.Errorf("solana: sign as %s: %w", key, err)
	}
	s, err := SignatureFromBytes(sig)
	if err != nil {
		return fmt.Errorf("solana: signer returned %d bytes for %s, want a 64-byte signature", len(sig), key)
	}
	if !VerifyStrict(key, msg, s) {
		return fmt.Errorf("solana: signer's signature does not verify under %s", key)
	}
	t.Signatures[i] = s
	return nil
}
