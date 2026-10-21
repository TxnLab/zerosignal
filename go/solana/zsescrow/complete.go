/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zsescrow

import (
	"context"
	"fmt"

	"github.com/TxnLab/zerosignal/go/solana"
)

// The payer's signature on a transaction someone else built, behind that
// transaction's verifier, as go/escrow's CompletePresignedOpenGroup and
// CompletePresignedSettleGroup put Algorand's: the signer port signs blindly,
// so these are the only places a counterparty's message reaches it. A
// transaction the payer builds itself has nothing foreign to check and is
// signed with Transaction.SignWith directly.
//
// Each signs the message it verified: both come from one parse of the
// transaction, and the result is that message with the payer's signature in
// its slot, the other slots as given. Nothing is submitted.

// CompleteOpenOffer checks a node's open offer, a wire transaction, against
// spec, and has signer sign it as spec.Payer. A refusal is the verifier's
// *OfferRejectedError, returned before the signer is called; an offer that
// does not decode, or a signer that fails, is another error and no evidence
// against the node.
func CompleteOpenOffer(ctx context.Context, d Deployment, offer []byte, spec OpenOfferSpec, signer solana.TransactionSigner) ([]byte, error) {
	return cosign(ctx, "open offer", offer, spec.Payer, signer, func(message []byte) error {
		return VerifyOpenOffer(d, message, spec)
	})
}

// CompleteRelayedAck checks an ack transaction a relayer built against spec,
// and has signer sign it as spec.Payer. A refusal is the verifier's
// *AckRejectedError, returned before the signer is called; an ack that does
// not decode, or a signer that fails, is another error.
func CompleteRelayedAck(ctx context.Context, d Deployment, ack []byte, spec AckSpec, signer solana.TransactionSigner) ([]byte, error) {
	return cosign(ctx, "relayed ack", ack, spec.Payer, signer, func(message []byte) error {
		return VerifyRelayedAck(d, message, spec)
	})
}

func cosign(ctx context.Context, what string, wire []byte, payer solana.PublicKey, signer solana.TransactionSigner, verify func([]byte) error) ([]byte, error) {
	tx, err := solana.ParseTransaction(wire)
	if err != nil {
		return nil, fmt.Errorf("zsescrow: decode %s: %w", what, err)
	}
	message, err := tx.Message.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("zsescrow: decode %s: %w", what, err)
	}
	if err := verify(message); err != nil {
		return nil, err
	}
	if err := tx.SignWith(ctx, payer, signer); err != nil {
		return nil, fmt.Errorf("zsescrow: %s: %w", what, err)
	}
	return tx.MarshalBinary()
}
