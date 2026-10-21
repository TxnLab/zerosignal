/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zsescrow

import (
	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/ticket"
)

// A payer acks a ticket's claim in one of two ways. Off chain, it signs the
// ack digest, which the node puts in an Ed25519 precompile instruction before
// its settle_cooperative. On chain, it signs an ack instruction as its
// submitter; a payer holds no SOL, so a relayer (the node, say) builds that
// transaction and pays for it. The program counts the payer's signature on
// the transaction as its ack of every settle_cooperative of the payer's
// tickets in it, so a relayer that put one beside the ack would settle a
// ticket of its choosing at a claim of its choosing.

// AckRejectedError is the error VerifyRelayedAck and ReceiptAckDigest return.
// Field is a stable slug naming the check that refused, shared with the TS
// twin and with OfferRejectedError's slugs where the check is the same.
type AckRejectedError struct {
	Field  string
	Detail string
}

func (e *AckRejectedError) Error() string { return e.Detail }

func ackRejected(what string, r *refusal) error {
	return &AckRejectedError{Field: r.field, Detail: "zsescrow: " + what + ": " + r.detail}
}

// AckSpec is what the payer knows before it signs a relayed ack, all from its
// own state: the ticket it opened, and the receipt it verified for it.
type AckSpec struct {
	Payer      solana.PublicKey
	OperatorID uint64
	NodeID     uint64
	// TicketID is the payer's own record of the ticket, never the receipt's,
	// which the node writes.
	TicketID [16]byte
	Receipt  *ticket.UsageReceipt
	// Treasury is the Config's treasury, whose USDC account the ack may pass
	// for a refund the payer's account can't take. Zero accepts only an ack
	// that passes none.
	Treasury solana.PublicKey
}

// VerifyRelayedAck checks the message of an ack transaction someone else
// built before the payer signs it. In order:
//
//  1. The message parses, and loads no address lookup table.
//  2. Exactly two signers: any fee payer, then the payer, read-only. Who
//     pays doesn't matter to the payer, since the checks below leave the fee
//     payer's signature nothing to authorize but the compute budget and the
//     ack.
//  3. Compute-budget instructions lead, at most one of each allowed kind,
//     with no accounts.
//  4. The rest is one ack: no other program, and no other escrow
//     instruction, a settle_cooperative or a second ack above all.
//  5. The receipt names the payer's ticket, and the ack posts the payer's
//     half of that ticket at exactly the receipt's claim.
func VerifyRelayedAck(d Deployment, message []byte, spec AckSpec) error {
	if r := verifyRelayedAck(d, message, spec); r != nil {
		return ackRejected("relayed ack", r)
	}
	return nil
}

func verifyRelayedAck(d Deployment, message []byte, spec AckSpec) *refusal {
	anyFeePayer := func(solana.PublicKey) *refusal { return nil }
	kind := func(i int, ix solana.Instruction) (string, *refusal) {
		if ix.ProgramID != d.Program {
			return "", refuse("instruction.program", "instruction %d: program %s, outside compute budget and the escrow", i, ix.ProgramID)
		}
		if !hasDiscriminator(ix.Data, "ack") {
			return "", refuse("escrow.instruction", "instruction %d: an escrow instruction other than ack", i)
		}
		return "ack", nil
	}
	ixs, rest, r := payerMessage(message, spec.Payer, anyFeePayer, kind)
	if r != nil {
		return r
	}
	if len(rest) != 1 {
		return refuse("instructions.shape", "%d acks after compute budget, want one", len(rest))
	}
	claim, r := receiptClaim("ack.receipt", spec.TicketID, spec.Receipt)
	if r != nil {
		return r
	}
	e := Ending{Submitter: spec.Payer, OperatorID: spec.OperatorID, NodeID: spec.NodeID, TicketID: spec.TicketID, Payer: spec.Payer, Treasury: spec.Treasury}
	return matchEnding("ack", ixs[len(ixs)-1], d.Ack, e, claim)
}

// ReceiptAckDigest is the ack digest the payer signs off chain for its
// ticket: the receipt's claim, once the receipt names the ticket, never a
// claim the node proposes. openSeq is the ticket account's, which tells a
// reopened ticket id apart. genesis is the cluster's, the Config's
// genesis_hash.
func ReceiptAckDigest(d Deployment, genesis solana.Hash, operatorID, nodeID uint64, ticketID [16]byte, openSeq uint64, r *ticket.UsageReceipt) ([32]byte, error) {
	claim, rf := receiptClaim("ack.receipt", ticketID, r)
	if rf != nil {
		return [32]byte{}, ackRejected("ack digest", rf)
	}
	return d.AckDigest(genesis, d.Ticket(d.Node(operatorID, nodeID), ticketID), openSeq, ClaimHash(claim)), nil
}
