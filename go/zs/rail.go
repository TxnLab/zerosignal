/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/TxnLab/zerosignal/go/escrow"
	"github.com/TxnLab/zerosignal/go/selection"
	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
	"github.com/TxnLab/zerosignal/go/ticket"
)

// The values a reserve and a settle carry for the wallet, which differ by
// rail (SPEC.md § 3a). Dispatch reads them only to drop a malformed one
// early; the wallet decodes them again to use them. A zero rail is Algorand,
// as a zero Network.Rail is.

// checkOpenOffer reports whether presigned, a reserve's presigned_open_txn,
// decodes as the rail's open: Algorand's open group, or Solana's offer
// transaction.
func checkOpenOffer(rail ticket.Rail, presigned string) error {
	if rail == ticket.RailSolana {
		b, err := zsescrow.DecodeOpenOffer(presigned)
		if err != nil {
			return fmt.Errorf("decode presigned open offer: %w", err)
		}
		if _, err := solana.ParseTransaction(b); err != nil {
			return fmt.Errorf("decode presigned open offer: %w", err)
		}
		return nil
	}
	if _, err := escrow.DecodeOpenGroup(presigned); err != nil {
		return fmt.Errorf("decode presigned open group: %w", err)
	}
	return nil
}

// checkSettleSlot reports whether slot, the settle-group header or frame,
// decodes as the rail's: Algorand's settle group, or Solana's open_seq.
func checkSettleSlot(rail ticket.Rail, slot string) error {
	if rail == ticket.RailSolana {
		_, err := zsescrow.ParseOpenSeq(slot)
		return err
	}
	_, err := escrow.DecodeSettleGroup(slot)
	return err
}

// opensOnChain reports whether a turn on t opens on chain. A Solana turn at
// max_price 0 doesn't: the program refuses a zero-price open, so a free
// Solana turn has no open, no ack and nothing for the watchdog (SPEC.md § 3a
// "Free turns on Solana").
func opensOnChain(rail ticket.Rail, t *ticket.Ticket) bool {
	return rail != ticket.RailSolana || t.MaxPrice > 0
}

// requestTicketID returns the ticket id a reserve on rail asks the node to
// issue, or "" to let the node choose. A Solana payer chooses a fresh random
// id for every reserve, so it never signs two opens with one id at a node:
// the node's open_seq it acks is then unable to fit another of its tickets
// (SPEC.md § 3a "The open and the ack on Solana").
func requestTicketID(rail ticket.Rail) (string, error) {
	if rail != ticket.RailSolana {
		return "", nil
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", fmt.Errorf("ticket id: %w", err)
	}
	return base64.StdEncoding.EncodeToString(id[:]), nil
}

// signerFloorText is the signing-account floor as a no_funded_operator
// refusal names it, in the rail's own unit.
func signerFloorText(rail ticket.Rail) string {
	if rail == ticket.RailSolana {
		return fmt.Sprintf("%d lamports", selection.MinSignerSpendableLamports)
	}
	return fmt.Sprintf("%d ALGO", selection.MinSignerSpendableMicroAlgos/1_000_000)
}
