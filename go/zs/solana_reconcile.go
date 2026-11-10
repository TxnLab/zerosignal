/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// solanaChain is the reconciler's sweepChain over a Solana wallet: each call
// is the payer's own transaction on a ticket known only from its journal row
// and, where it has one, its ticket account. walletChain is Algorand's.
type solanaChain struct{ w *SolanaWallet }

func (c solanaChain) read(ctx context.Context, rec TicketRecord) (sweptTicket, error) {
	id, err := solanaTicketID("reconcile", rec.TicketID)
	if err != nil {
		return nil, err
	}
	t, err := c.w.readTicket(ctx, rec.Target.Op, rec.Target.Node, id)
	if err != nil {
		return nil, err
	}
	return sweptSolana(t), nil
}

// handle is an OpenHandle for rec, whose settle paths each read the ticket
// account afresh.
func (c solanaChain) handle(rec TicketRecord) *OpenHandle {
	return &OpenHandle{TicketID: rec.TicketID, Operator: Operator{ID: rec.Target.Op, NodeID: rec.Target.Node}, MaxPrice: rec.MaxPrice, solana: c.w}
}

func (c solanaChain) refund(ctx context.Context, rec TicketRecord) (string, error) {
	return c.handle(rec).RefundInactive(ctx)
}

func (c solanaChain) lapse(ctx context.Context, rec TicketRecord, _ sweptTicket) (string, error) {
	return c.handle(rec).SettleLapsed(ctx)
}

func (c solanaChain) resettle(ctx context.Context, rec TicketRecord, t sweptTicket) (string, error) {
	if rec.Settle == nil {
		return "", errors.New("wallet: re-settle without a recorded receipt")
	}
	sig, err := c.ack(ctx, rec, t, *rec.Settle)
	if err != nil {
		return sig, fmt.Errorf("wallet: re-settle: %w", err)
	}
	return sig, nil
}

// freeze is the payer's ack at a, which the program answers with a freeze
// against a node claim that differs from it.
func (c solanaChain) freeze(ctx context.Context, rec TicketRecord, t sweptTicket, a SettleArgs) (string, error) {
	sig, err := c.ack(ctx, rec, t, a)
	if err != nil {
		return sig, fmt.Errorf("wallet: freeze: %w", err)
	}
	return sig, nil
}

// accept is the payer's ack at t's own pending claim, which the program
// answers by settling at once. Reached only with a ticket read.
func (c solanaChain) accept(ctx context.Context, rec TicketRecord, t sweptTicket) (string, error) {
	a, err := zeroClaimArgs(t)
	if err != nil {
		return "", err
	}
	sig, err := c.ack(ctx, rec, t, a)
	if err != nil {
		return sig, fmt.Errorf("wallet: accept claim: %w", err)
	}
	return sig, nil
}

// ack sends the payer's half at a over the ticket account the sweep read.
func (c solanaChain) ack(ctx context.Context, rec TicketRecord, t sweptTicket, a SettleArgs) (string, error) {
	id, err := solanaTicketID("ack", rec.TicketID)
	if err != nil {
		return "", err
	}
	st, _ := t.(solanaSweptTicket)
	r, err := c.w.sendAck(ctx, st.Ticket, rec.Target.Op, rec.Target.Node, id, a)
	return r.Sig, err
}

// freezes is always true: the program has resolve_frozen.
func (solanaChain) freezes() bool { return true }

// submitTimeout is the refund watchdog's: a Solana submit waits for its
// confirmation, and one cut short that landed late would be read as a ticket
// gone, never counted refunded.
func (solanaChain) submitTimeout() time.Duration { return solanaEndingTimeout }
