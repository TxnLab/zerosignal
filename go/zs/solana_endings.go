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
	"time"

	"github.com/TxnLab/zerosignal/go/escrow"
	"github.com/TxnLab/zerosignal/go/settle"
	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/rpc"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
	"github.com/TxnLab/zerosignal/go/ticket"
)

// protestComputeUnits caps a protest's compute, the limit the program's own
// tests send it under. A protest uses about a quarter of it; with no
// priority fee the limit costs nothing.
const protestComputeUnits = 60_000

// solanaRefundInactive is RefundInactive on a Solana ticket: the payer's own
// refund_inactive, which refunds the whole escrow of a ticket the node never
// claimed once the deadline has passed. Anyone may send it, so it races the
// node's own sweep, and whichever lands second fails on the closed ticket.
func (h *OpenHandle) solanaRefundInactive(ctx context.Context) (string, error) {
	r, err := h.solanaEnd(ctx, "refund-inactive", h.solana.deployment.RefundInactive)
	return r.Sig, err
}

// solanaSettleLapsed is SettleLapsed on a Solana ticket: the payer's own
// settle_lapsed, which pays the node's claim the ticket holds once the
// deadline has passed. Anyone may send it, so it races the node's own, and
// whichever lands second fails on the closed ticket.
func (h *OpenHandle) solanaSettleLapsed(ctx context.Context) (string, error) {
	r, err := h.solanaEnd(ctx, "settle-lapsed", h.solana.deployment.SettleLapsed)
	return r.Sig, err
}

// solanaEnd sends the ending ix builds for the handle's ticket, read first
// for the rent payer the ending returns its rent to.
func (h *OpenHandle) solanaEnd(ctx context.Context, what string, ix func(zsescrow.Ending) solana.Instruction) (solanaAck, error) {
	w := h.solana
	id, err := solanaTicketID(what, h.TicketID)
	if err != nil {
		return solanaAck{}, err
	}
	opID, nodeID := h.Operator.ID, h.Operator.NodeID
	t, err := w.readTicket(ctx, opID, nodeID, id)
	if err != nil {
		return solanaAck{}, err
	}
	return w.endRead(ctx, what, t, opID, nodeID, id, ix)
}

// endRead sends the ending ix builds for t, the ticket account read for id at
// the node.
func (w *SolanaWallet) endRead(ctx context.Context, what string, t *zsescrow.Ticket, opID, nodeID uint64, id [16]byte, ix func(zsescrow.Ending) solana.Instruction) (solanaAck, error) {
	e, err := w.ending(ctx, what, t, opID, nodeID, id)
	if err != nil {
		return solanaAck{}, err
	}
	return w.send(ctx, what, []solana.Instruction{ix(e)}, solanaSignatureFee)
}

// solanaProtest is Protest on a Solana ticket: the receipt, with the node's
// signature over its digest in an Ed25519 precompile instruction before the
// protest, by the key the ticket took at open. The program has no dispute
// excerpt. A protest the program refuses because the settle window has
// closed wraps escrow.ErrProtestAfterDeadline, as Algorand's does.
func (h *OpenHandle) solanaProtest(ctx context.Context, receipt *ticket.UsageReceipt, reason escrow.ProtestReasonCode) (string, uint64, error) {
	w := h.solana
	id, err := solanaTicketID("protest", h.TicketID)
	if err != nil {
		return "", 0, err
	}
	sig, err := decodeReceiptSig(receipt.Sig)
	if err != nil {
		return "", 0, fmt.Errorf("solana wallet: protest: decode receipt sig: %w", err)
	}
	// Go's types allow a reason the program's u8 can't carry.
	if reason > 0xff {
		return "", 0, fmt.Errorf("solana wallet: protest: reason %d is past the program's 255", reason)
	}
	opID, nodeID := h.Operator.ID, h.Operator.NodeID
	t, err := w.readTicket(ctx, opID, nodeID, id)
	if err != nil {
		return "", 0, err
	}
	if err := w.ownsTicket("protest", t); err != nil {
		return "", 0, err
	}
	digest := ticket.ReceiptSigDigest(receipt)
	r, err := w.send(ctx, "protest", []solana.Instruction{
		solana.SetComputeUnitLimit(protestComputeUnits),
		solana.Ed25519Verify(t.NodeSigning, solana.Signature(sig), digest[:]),
		w.deployment.Protest(w.payer, opID, nodeID, id, receipt.CanonicalBytes(), uint8(reason)),
	}, 2*solanaSignatureFee) // the payer's signature and the precompile's
	if refusedAs(err, r.TxErr, zsescrow.ErrPastDeadline) {
		err = fmt.Errorf("%w: %w", escrow.ErrProtestAfterDeadline, err)
	}
	return r.Sig, r.FeeLamports, err
}

// solanaFreezeOverclaim is freezeOverclaim on a Solana ticket: when the
// node's claim on the ticket takes more than the receipt charges, the payer's
// ack at the receipt, which freezes it; nothing otherwise. The program always
// has resolve_frozen.
func (h *OpenHandle) solanaFreezeOverclaim(ctx context.Context, receipt *ticket.UsageReceipt) (string, uint64, ClaimVerdict, error) {
	w := h.solana
	id, err := solanaTicketID("freeze", h.TicketID)
	if err != nil {
		return "", 0, ClaimUnreadable, err
	}
	opID, nodeID := h.Operator.ID, h.Operator.NodeID
	a := settleArgsOf(receipt)
	t, err := w.readTicket(ctx, opID, nodeID, id)
	if err != nil {
		return "", 0, ClaimUnreadable, err
	}
	claim := judgeSolanaClaim(a, t)
	if claim != ClaimOverclaims {
		return "", 0, claim, nil
	}
	r, err := w.sendAck(ctx, t, opID, nodeID, id, a)
	if err != nil {
		return r.Sig, r.FeeLamports, claim, fmt.Errorf("wallet: freeze: %w", err)
	}
	return r.Sig, r.FeeLamports, claim, nil
}

// solanaEndingTimeout bounds the refund watchdog's refund_inactive or
// settle_lapsed, which waits for its transaction to confirm. A blockhash
// lives about 150 blocks, a minute or so, and the wait ends once the
// confirmed height passes it, so this outlasts it: cut short, a refund that
// landed late would read as a ticket gone and the watchdog would never report
// it refunded, where Algorand's returns once algod accepts it.
const solanaEndingTimeout = 3 * time.Minute

// solanaRefundSource is how the refund watchdog reads a Solana handle's
// ticket. The payer's open sends grace 0, so the ticket takes the Config's
// default_grace, as it stood when the wallet read it; the ticket's own
// deadline, which the watchdog re-arms to, is the one that counts.
func (h *OpenHandle) solanaRefundSource() refundSource {
	w := h.solana
	opID, nodeID := h.Operator.ID, h.Operator.NodeID
	return refundSource{
		callTimeout: solanaEndingTimeout,
		grace:       time.Duration(w.defaultGrace) * time.Second,
		read: func(ctx context.Context, ticketIDRaw []byte) (*settle.Ticket, uint64, error) {
			t, err := w.readTicket(ctx, opID, nodeID, [16]byte(ticketIDRaw))
			if err != nil || t == nil {
				return nil, 0, err
			}
			v := t.View()
			return &v, t.Pending.Amount, nil
		},
	}
}

func solanaTicketID(what, ticketID string) ([16]byte, error) {
	raw, err := decodeTicketID(ticketID)
	if err != nil {
		return [16]byte{}, fmt.Errorf("solana wallet: %s: decode ticket id: %w", what, err)
	}
	return [16]byte(raw), nil
}

// refusedAs reports whether a transaction failed on the program's error code:
// in its simulation, which sendTransaction's preflight runs, or once landed.
func refusedAs(err error, landed json.RawMessage, code uint32) bool {
	if err == nil {
		return false
	}
	var rpcErr *rpc.Error
	if landed == nil && errors.As(err, &rpcErr) {
		landed = rpcErr.TxErr()
	}
	got, ok := rpc.TxCustomError(landed)
	return ok && got == code
}
