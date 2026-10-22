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

// readTicket reads the ticket account for id at the node, nil when there is
// none: never opened, or ended and closed. An account the program doesn't own
// is no ticket either, since only the program can write one at the address.
func (w *SolanaWallet) readTicket(ctx context.Context, operatorID, nodeID uint64, id [16]byte) (*zsescrow.Ticket, error) {
	addr := w.deployment.Ticket(w.deployment.Node(operatorID, nodeID), id)
	acct, err := w.rpc.GetAccountInfo(ctx, addr, rentCommitment)
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
	acct, err := w.rpc.GetAccountInfo(ctx, w.payerUSDC, rentCommitment)
	if err != nil {
		return fmt.Errorf("solana wallet: ack: read the payer's token account: %w", err)
	}
	if canReceiveRefund(acct, w.deployment.Mint, w.payer) {
		return nil
	}
	cfg, err := w.rpc.GetAccountInfo(ctx, w.deployment.Config(), rentCommitment)
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
