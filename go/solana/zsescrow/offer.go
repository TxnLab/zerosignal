/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zsescrow

import (
	"strings"

	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/ticket"
)

// The open offer is a transaction the node composes, signs as fee payer and
// hands the payer to co-sign: compute budget, the payer's TransferChecked
// into the node's vault, and open, with the payer's previous ticket's
// settle_cooperative optionally folded in ahead of the transfer. The payer's
// signature covers the whole message, so VerifyOpenOffer checks the whole
// message: every instruction must be one the payer's own values rebuild.
// The program checks much of the same, but only for the instructions it is
// handed; an instruction beside them (an Approve of the payer's token
// account, a second transfer) runs under the payer's signature unchecked.

// OfferRejectedError is the error VerifyOpenOffer returns. Field is a stable
// slug naming the check that refused, shared with the TS twin, so callers and
// vectors agree on the reason without matching message text.
type OfferRejectedError struct {
	Field  string
	Detail string
}

func (e *OfferRejectedError) Error() string { return e.Detail }

// OpenOfferSpec is what the payer knows before it signs a node's open offer.
// Every value comes from the payer's own state (its reserve, the ticket the
// node signed, the node's account on chain), never from the offer.
type OpenOfferSpec struct {
	// NodeSigning is the node's signing key, read from its Node account: the
	// offer's fee payer, and open's signer.
	NodeSigning solana.PublicKey
	OperatorID  uint64
	NodeID      uint64
	Payer       solana.PublicKey
	// PayerUSDC is the payer's token account the transfer draws from.
	PayerUSDC solana.PublicKey
	// Decimals is the mint's, Config.usdc_decimals.
	Decimals  uint8
	TicketID  [16]byte
	MaxPrice  uint64
	ExpiresAt int64
	// Fold is the payer's previous ticket, whose cooperative settle the node
	// may fold into the offer. Nil refuses an offer that carries one.
	Fold *FoldSpec
}

// FoldSpec names a ticket the payer holds a verified receipt for. A
// settle_cooperative signed by the payer's own transaction signature is the
// payer's ack, so the claim it settles must be the receipt's, for the ticket
// the payer opened.
type FoldSpec struct {
	OperatorID uint64
	NodeID     uint64
	// TicketID is the payer's own record of the ticket, never the receipt's:
	// the node writes the receipt's ticket id, and the program accepts the
	// payer's signature as the ack of any of its tickets the settle names.
	TicketID [16]byte
	Receipt  *ticket.UsageReceipt
	// Treasury is the Config's treasury, whose USDC account the folded
	// settle may pass for a refund the payer's account can't take. Zero
	// accepts only a fold that passes none. Its account is accepted writable
	// too, so the payer's signature can ack a settle that forfeits the
	// refund: the program forfeits a refund the payer's account can't take on
	// every ending, so refusing the fold changes only which settle does it.
	Treasury solana.PublicKey
}

// VerifyOpenOffer checks the message of a node's open offer against spec
// before the payer signs it. In order:
//
//  1. The message parses, and loads no address lookup table.
//  2. Exactly two signers: the node's signing key as fee payer, then the
//     payer, read-only.
//  3. Compute-budget instructions lead, at most one of each allowed kind,
//     with no accounts.
//  4. The rest is [settle_cooperative,] TransferChecked, open: no other
//     program, no other token or escrow instruction, open last, so the
//     transfer sits right before it as the program requires.
//  5. The transfer moves MaxPrice of the deployment's mint from PayerUSDC
//     to the node's vault, authorized by the payer.
//  6. open names the node, the ticket, the payer, MaxPrice and ExpiresAt,
//     with grace 0: the program's default, the one rule both rails share.
//     Its rent comes from the payer's own rent pool, which the payer's
//     signature on the transfer authorizes the program to draw.
//  7. A folded settle_cooperative is allowed only with spec.Fold, and must
//     settle the payer's ticket for exactly the receipt's claim, the
//     receipt naming that ticket.
func VerifyOpenOffer(d Deployment, message []byte, spec OpenOfferSpec) error {
	if r := verifyOpenOffer(d, message, spec); r != nil {
		return &OfferRejectedError{Field: r.field, Detail: "zsescrow: open offer: " + r.detail}
	}
	return nil
}

func verifyOpenOffer(d Deployment, message []byte, spec OpenOfferSpec) *refusal {
	feePayer := func(k solana.PublicKey) *refusal {
		if k != spec.NodeSigning {
			return refuse("header.feePayer", "fee payer %s, want the node's signing key %s", k, spec.NodeSigning)
		}
		return nil
	}
	kind := func(i int, ix solana.Instruction) (string, *refusal) {
		switch ix.ProgramID {
		case solana.TokenProgramID:
			if len(ix.Data) == 0 || ix.Data[0] != solana.TokenTransferChecked {
				return "", refuse("token.instruction", "instruction %d: a token instruction other than TransferChecked", i)
			}
			return "transfer", nil
		case d.Program:
			switch {
			case hasDiscriminator(ix.Data, "open"):
				return "open", nil
			case hasDiscriminator(ix.Data, "settle_cooperative"):
				return "settle", nil
			}
			return "", refuse("escrow.instruction", "instruction %d: an escrow instruction other than open or settle_cooperative", i)
		}
		return "", refuse("instruction.program", "instruction %d: program %s, outside compute budget, SPL Token and the escrow", i, ix.ProgramID)
	}
	ixs, rest, r := payerMessage(message, spec.Payer, feePayer, kind)
	if r != nil {
		return r
	}
	var fold *solana.Instruction
	switch strings.Join(rest, ",") {
	case "transfer,open":
	case "settle,transfer,open":
		fold = &ixs[len(ixs)-3]
	default:
		return refuse("instructions.shape", "instructions [%s] after compute budget, want [settle,]transfer,open", strings.Join(rest, ","))
	}
	transfer, open := ixs[len(ixs)-2], ixs[len(ixs)-1]

	node := d.Node(spec.OperatorID, spec.NodeID)
	if r := sameInstruction(transfer, solana.TransferChecked(spec.PayerUSDC, d.Mint, d.Vault(node), spec.Payer, spec.MaxPrice, spec.Decimals), "transfer"); r != nil {
		return r
	}
	want := d.Open(spec.NodeSigning, spec.OperatorID, spec.NodeID, OpenArgs{TicketID: spec.TicketID, Payer: spec.Payer, MaxPrice: spec.MaxPrice, ExpiresAt: spec.ExpiresAt})
	if r := sameInstruction(open, want, "open"); r != nil {
		return r
	}
	if fold != nil {
		return verifyFold(d, *fold, spec)
	}
	return nil
}

func verifyFold(d Deployment, ix solana.Instruction, spec OpenOfferSpec) *refusal {
	f := spec.Fold
	if f == nil {
		return refuse("fold.unexpected", "a folded settle_cooperative, and no ticket to fold")
	}
	claim, r := receiptClaim("fold.receipt", f.TicketID, f.Receipt)
	if r != nil {
		return r
	}
	e := Ending{Submitter: spec.NodeSigning, OperatorID: f.OperatorID, NodeID: f.NodeID, TicketID: f.TicketID, Payer: spec.Payer, Treasury: f.Treasury}
	return matchEnding("fold", ix, d.SettleCooperative, e, claim)
}
