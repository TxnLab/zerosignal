/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/rpc"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/wire"
)

// solanaAck is the payer's own ack transaction once sent.
type solanaAck struct {
	Sig string
	// FeeLamports is what the payer paid for it. A transaction that landed
	// and failed paid its fee too, so it is set beside that error.
	FeeLamports uint64
	// TxErr is the TransactionError a landed failure carries, whose custom
	// code tells a deadline the ack lost to apart from a refund it couldn't
	// route.
	TxErr json.RawMessage
}

// solanaAckSettle is AckSettle on a Solana ticket, through Algorand's decision
// (ackSettle). slot is the node's open_seq, or "" for none. The node's half is
// its settle_cooperative, which only it can submit, so the payer hands it the
// ack: its signature over the receipt's ack digest, as payment_settle. With no
// slot, or no relay to carry the ack, the payer sends its own ack transaction
// instead, as Algorand's standalone settle: over the node's claim it settles
// the ticket or freezes it, and on an open ticket it is the payer's first
// half. The ticket account read for the claim is the one that ack names.
func (h *OpenHandle) solanaAckSettle(ctx context.Context, receipt *ticket.UsageReceipt, slot string) (AckResult, error) {
	w := h.solana
	raw, err := decodeTicketID(h.TicketID)
	if err != nil {
		return AckResult{}, fmt.Errorf("wallet: ack-settle: decode ticket id: %w", err)
	}
	id := [16]byte(raw)
	opID, nodeID := h.Operator.ID, h.Operator.NodeID
	a := settleArgsOf(receipt)
	// As on Algorand: what follows a failed delivery runs on a budget of its
	// own.
	followCtx, cancelFollow := ctx, context.CancelFunc(func() {})
	defer func() { cancelFollow() }()
	var (
		tk     *zsescrow.Ticket
		readOK bool
	)
	read := func() (ClaimVerdict, error) {
		var err error
		if tk, err = w.readTicket(followCtx, opID, nodeID, id); err != nil {
			return ClaimUnreadable, err
		}
		readOK = true
		return judgeSolanaClaim(a, tk), nil
	}
	ack := func() (ackSubmission, error) {
		// An unreadable claim is acked anyway, as on Algorand, which needs the
		// account it couldn't read.
		if !readOK {
			if _, err := read(); err != nil {
				return ackSubmission{}, err
			}
		}
		r, err := w.sendAck(followCtx, tk, opID, nodeID, id, a)
		return ackSubmission{TxID: r.Sig, Fee: r.FeeLamports}, err
	}
	return ackSettle(slot != "", ackSettleDeps[uint64]{
		// The caller checked that it parses (checkSettleSlot).
		spec: func() (uint64, error) { return zsescrow.ParseOpenSeq(slot) },
		submitGroup: func(openSeq uint64) (_ ackSubmission, err error) {
			// With no route nothing was sent, so the standalone ack keeps the
			// caller's budget, as with no slot.
			defer func() {
				if err != nil && !errors.Is(err, errNoSettleAckRoute) {
					followCtx, cancelFollow = followUpCtx(ctx)
				}
			}()
			if h.deliverAck == nil {
				return ackSubmission{}, errNoSettleAckRoute
			}
			sig, err := zsescrow.SignReceiptAck(ctx, w.signer, w.payer, w.deployment, w.genesis, opID, nodeID, id, openSeq, receipt)
			if err != nil {
				return ackSubmission{}, err
			}
			// The node submits its settle with the ack and pays its fee.
			return ackSubmission{}, h.deliverAck(ctx, wire.SettleAck{TicketID: h.TicketID, SettleGroup: sig})
		},
		claim:      read,
		standalone: ack,
		freeze:     ack,
		half:       ack,
		// The program always has resolve_frozen.
		freezes: true,
		log:     w.logger().With("operator_id", opID, "node_id", nodeID),
	})
}

// readTicket reads the ticket account for id at the node, nil when there is
// none: never opened, or ended and closed. An account the program doesn't own
// is no ticket either, since only the program can write one at the address.
func (w *SolanaWallet) readTicket(ctx context.Context, operatorID, nodeID uint64, id [16]byte) (*zsescrow.Ticket, error) {
	addr := w.deployment.Ticket(w.deployment.Node(operatorID, nodeID), id)
	acct, err := getAccount(ctx, w.rpc, addr)
	if err != nil {
		return nil, fmt.Errorf("solana wallet: read ticket: %w", err)
	}
	if acct == nil || acct.Owner != w.deployment.Program {
		return nil, nil
	}
	t, err := zsescrow.DecodeTicket(acct.Data)
	if err != nil {
		return nil, fmt.Errorf("solana wallet: read ticket: %w", err)
	}
	return t, nil
}

// sendAck sends the payer's half at a on t, the ticket account for id at the
// node, and waits for it to confirm: Algorand's standalone settle. On a node's
// claim it settles the ticket when a matches and freezes it when not; on an
// open ticket it is the first half, which the node answers or
// refund_inactive refunds. What to send is the caller's decision; this only
// refuses a ticket that isn't the payer's before asking the signer, since the
// program refuses it. A transaction sent but not confirmed returns its
// signature beside the error, so a caller can look before it sends another;
// rpc.ErrExpired in the chain says it never can land.
func (w *SolanaWallet) sendAck(ctx context.Context, t *zsescrow.Ticket, operatorID, nodeID uint64, id [16]byte, a SettleArgs) (solanaAck, error) {
	if t == nil {
		return solanaAck{}, errors.New("solana wallet: ack: no ticket account")
	}
	if t.Payer != w.payer {
		return solanaAck{}, fmt.Errorf("solana wallet: ack: the ticket's payer is %s, not this wallet's %s", t.Payer, w.payer)
	}
	e := zsescrow.Ending{
		Submitter:  w.payer,
		OperatorID: operatorID,
		NodeID:     nodeID,
		TicketID:   id,
		RentPayer:  t.RentPayer,
		Payer:      w.payer,
	}
	if err := w.refundFallback(ctx, &e); err != nil {
		return solanaAck{}, err
	}
	bh, err := w.rpc.GetLatestBlockhash(ctx, rentCommitment)
	if err != nil {
		return solanaAck{}, fmt.Errorf("solana wallet: ack: blockhash: %w", err)
	}
	msg, err := solana.Compile(w.payer, bh.Hash, []solana.Instruction{w.deployment.Ack(e, solanaClaimFields(a))}, solana.Legacy)
	if err != nil {
		return solanaAck{}, fmt.Errorf("solana wallet: ack: %w", err)
	}
	tx := solana.NewTransaction(msg)
	if err := tx.SignWith(ctx, w.payer, w.signer); err != nil {
		return solanaAck{}, fmt.Errorf("solana wallet: ack: %w", err)
	}
	raw, err := tx.MarshalBinary()
	if err != nil {
		return solanaAck{}, fmt.Errorf("solana wallet: ack: %w", err)
	}
	// Preflight at the commitment the ticket was read at, which the RPC's
	// finalized default may not have reached.
	sig, err := w.rpc.SendTransaction(ctx, raw, rpc.SendOptions{PreflightCommitment: rentCommitment})
	if err != nil {
		return solanaAck{}, fmt.Errorf("solana wallet: send ack: %w", err)
	}
	r, err := rpc.Confirm(ctx, w.rpc, sig, bh.LastValidBlockHeight, rentCommitment, w.confirm)
	if err != nil {
		return solanaAck{Sig: sig.String()}, fmt.Errorf("solana wallet: ack %s: %w", sig, err)
	}
	// The payer's signature is the transaction's only one, and it sets no
	// priority fee.
	res := solanaAck{Sig: sig.String(), FeeLamports: solanaSignatureFee}
	if r.Err != nil {
		res.TxErr = r.Err
		return res, fmt.Errorf("solana wallet: ack %s failed: %s %s", sig, rpc.TxErrName(r.Err), r.Err)
	}
	return res, nil
}

// refundFallback passes the treasury's USDC account, writable, when the
// payer's own token account can't take a refund the ack may pay, so the refund
// is forfeited to it as Algorand's payOrForfeit forfeits it. Otherwise the ack
// leaves it out: a write lock on the one protocol-wide account would put every
// settle in one lane. The treasury comes from the Config, which set_config can
// change.
func (w *SolanaWallet) refundFallback(ctx context.Context, e *zsescrow.Ending) error {
	acct, err := getAccount(ctx, w.rpc, w.payerUSDC)
	if err != nil {
		return fmt.Errorf("solana wallet: ack: read the payer's token account: %w", err)
	}
	if canReceiveRefund(acct, w.deployment.Mint, w.payer) {
		return nil
	}
	cfg, err := getAccount(ctx, w.rpc, w.deployment.Config())
	if err != nil {
		return fmt.Errorf("solana wallet: ack: read config: %w", err)
	}
	if cfg == nil || cfg.Owner != w.deployment.Program {
		return fmt.Errorf("solana wallet: ack: program %s has no Config", w.deployment.Program)
	}
	c, err := zsescrow.DecodeConfig(cfg.Data)
	if err != nil {
		return fmt.Errorf("solana wallet: ack: %w", err)
	}
	e.Treasury, e.Fallback = c.Treasury, zsescrow.FallbackWritable
	return nil
}

// canReceiveRefund is the program's can_receive: a token account of mint,
// owned by owner and not frozen, which the token program owns.
func canReceiveRefund(acct *rpc.Account, mint, owner solana.PublicKey) bool {
	if acct == nil || acct.Owner != solana.TokenProgramID {
		return false
	}
	t, err := zsescrow.DecodeTokenAccount(acct.Data)
	return err == nil && t.Mint == mint && t.Owner == owner && t.State == zsescrow.TokenInitialized
}
