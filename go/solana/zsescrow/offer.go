/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zsescrow

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
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

func offerReject(field, format string, a ...any) error {
	return &OfferRejectedError{Field: field, Detail: "zsescrow: open offer: " + fmt.Sprintf(format, a...)}
}

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
}

// ClaimFromReceipt is the claim a payer acks for a receipt: the values the
// node signed, and the digest of the receipt's canonical bytes. A receipt
// whose timings or aux count overflow the claim's u32 fields has no claim
// the program can carry, so no settle of it can be the payer's ack.
func ClaimFromReceipt(r *ticket.UsageReceipt) (ClaimFields, error) {
	if r.TtftMs > math.MaxUint32 || r.DecodeMs > math.MaxUint32 || r.AuxOutputCount > math.MaxUint32 {
		return ClaimFields{}, errors.New("zsescrow: receipt timings or aux count exceed a claim's u32 fields")
	}
	return ClaimFields{
		Amount:          r.AmountCharged,
		ReceiptDigest:   ticket.ReceiptSigDigest(r),
		TTFTMs:          uint32(r.TtftMs),
		DecodeMs:        uint32(r.DecodeMs),
		InputUnits:      r.ActualInputCount,
		OutputUnits:     r.ActualOutputCount,
		OutputUsageType: uint8(r.OutputUsageType),
		AuxUsageType:    uint8(r.AuxOutputUsageType),
		AuxCount:        uint32(r.AuxOutputCount),
	}, nil
}

// The compute-budget instructions an offer may carry, by tag, with their
// data length: SetComputeUnitLimit and SetComputeUnitPrice. The fee payer
// pays for both; the others size heap and loaded data, which an offer never
// needs.
var offerComputeBudget = map[byte]int{solana.ComputeBudgetSetComputeUnitLimit: 5, solana.ComputeBudgetSetComputeUnitPrice: 9}

// VerifyOpenOffer checks the message of a node's open offer against spec
// before the payer signs it. In order:
//
//  1. The message parses, and loads no address lookup table: a looked-up
//     account is one the payer cannot see in the bytes it signs.
//  2. Exactly two signers: the node's signing key as fee payer, then the
//     payer, read-only, so the payer's signature grants no write lock on
//     its wallet and pays nothing.
//  3. Compute-budget instructions lead, at most one of each allowed kind,
//     with no accounts.
//  4. The rest is [settle_cooperative,] TransferChecked, open: no other
//     program, no other token or escrow instruction, open last, so the
//     transfer sits right before it as the program requires.
//  5. The transfer moves MaxPrice of the deployment's mint from PayerUSDC
//     to the node's vault, authorized by the payer.
//  6. open names the node, the ticket, the payer, MaxPrice and ExpiresAt,
//     with grace 0: the program's default, the one rule both rails share.
//  7. A folded settle_cooperative is allowed only with spec.Fold, and must
//     settle the payer's ticket for exactly the receipt's claim, the
//     receipt naming that ticket.
func VerifyOpenOffer(d Deployment, message []byte, spec OpenOfferSpec) error {
	m, err := solana.ParseMessage(message)
	if err != nil {
		return offerReject("message.parse", "%v", err)
	}
	if len(m.AddressTableLookups) != 0 {
		return offerReject("message.lookups", "%d address lookup tables, want none", len(m.AddressTableLookups))
	}
	if n := m.Header.NumRequiredSignatures; n != 2 {
		return offerReject("header.signers", "%d signers, want the node and the payer", n)
	}
	if m.AccountKeys[0] != spec.NodeSigning {
		return offerReject("header.feePayer", "fee payer %s, want the node's signing key %s", m.AccountKeys[0], spec.NodeSigning)
	}
	if m.AccountKeys[1] != spec.Payer {
		return offerReject("header.payer", "second signer %s, want the payer %s", m.AccountKeys[1], spec.Payer)
	}
	if m.IsWritable(1) {
		return offerReject("header.payerWritable", "the payer's key is writable")
	}

	ixs := make([]solana.Instruction, len(m.Instructions))
	kinds := make([]string, len(m.Instructions))
	budget := map[byte]bool{}
	for i, ci := range m.Instructions {
		ix := solana.Instruction{ProgramID: m.AccountKeys[ci.ProgramIDIndex], Data: ci.Data}
		for _, a := range ci.Accounts {
			ix.Accounts = append(ix.Accounts, solana.AccountMeta{PublicKey: m.AccountKeys[a]})
		}
		ixs[i] = ix
		switch ix.ProgramID {
		case solana.ComputeBudgetProgramID:
			kinds[i] = "computeBudget"
			if i > 0 && kinds[i-1] != "computeBudget" {
				return offerReject("computeBudget.order", "instruction %d: compute budget after another program's instruction", i)
			}
			if len(ix.Data) == 0 || len(ix.Accounts) != 0 || offerComputeBudget[ix.Data[0]] != len(ix.Data) {
				return offerReject("computeBudget.instruction", "instruction %d: compute-budget data %x with %d accounts", i, ix.Data, len(ix.Accounts))
			}
			if budget[ix.Data[0]] {
				return offerReject("computeBudget.duplicate", "instruction %d: a second compute-budget instruction of tag %d", i, ix.Data[0])
			}
			budget[ix.Data[0]] = true
		case solana.TokenProgramID:
			if len(ix.Data) == 0 || ix.Data[0] != solana.TokenTransferChecked {
				return offerReject("token.instruction", "instruction %d: a token instruction other than TransferChecked", i)
			}
			kinds[i] = "transfer"
		case d.Program:
			switch {
			case hasDiscriminator(ix.Data, "open"):
				kinds[i] = "open"
			case hasDiscriminator(ix.Data, "settle_cooperative"):
				kinds[i] = "settle"
			default:
				return offerReject("escrow.instruction", "instruction %d: an escrow instruction other than open or settle_cooperative", i)
			}
		default:
			return offerReject("instruction.program", "instruction %d: program %s, outside compute budget, SPL Token and the escrow", i, ix.ProgramID)
		}
	}
	rest := kinds[len(budget):]
	var fold *solana.Instruction
	switch strings.Join(rest, ",") {
	case "transfer,open":
	case "settle,transfer,open":
		fold = &ixs[len(budget)]
	default:
		return offerReject("instructions.shape", "instructions [%s] after compute budget, want [settle,]transfer,open", strings.Join(rest, ","))
	}
	transfer, open := ixs[len(ixs)-2], ixs[len(ixs)-1]

	node := d.Node(spec.OperatorID, spec.NodeID)
	if err := sameInstruction(transfer, solana.TransferChecked(spec.PayerUSDC, d.Mint, d.Vault(node), spec.Payer, spec.MaxPrice, spec.Decimals), "transfer"); err != nil {
		return err
	}
	want := d.Open(spec.NodeSigning, spec.OperatorID, spec.NodeID, OpenArgs{TicketID: spec.TicketID, Payer: spec.Payer, MaxPrice: spec.MaxPrice, ExpiresAt: spec.ExpiresAt})
	if err := sameInstruction(open, want, "open"); err != nil {
		return err
	}
	if fold != nil {
		return verifyFold(d, *fold, spec)
	}
	return nil
}

func verifyFold(d Deployment, ix solana.Instruction, spec OpenOfferSpec) error {
	f := spec.Fold
	if f == nil {
		return offerReject("fold.unexpected", "a folded settle_cooperative, and no ticket to fold")
	}
	if f.Receipt == nil {
		return offerReject("fold.receipt", "no receipt for the ticket to fold")
	}
	// Compared as the string the node signed, so no base64 decoder's
	// leniency can make two spellings of one id agree.
	if want := base64.StdEncoding.EncodeToString(f.TicketID[:]); f.Receipt.TicketID != want {
		return offerReject("fold.receipt", "the receipt names ticket %q, not the payer's %q", f.Receipt.TicketID, want)
	}
	claim, err := ClaimFromReceipt(f.Receipt)
	if err != nil {
		return offerReject("fold.receipt", "%v", err)
	}
	// The rent payer is whoever funded the ticket, which the program checks
	// against the ticket itself, so the offer's own is taken. Each fallback
	// shape is one the program may be handed for the same settle.
	const rentPayerAt = 5
	if len(ix.Accounts) <= rentPayerAt {
		return offerReject("fold.accounts", "settle_cooperative names %d accounts", len(ix.Accounts))
	}
	e := Ending{Submitter: spec.NodeSigning, OperatorID: f.OperatorID, NodeID: f.NodeID, TicketID: f.TicketID,
		RentPayer: ix.Accounts[rentPayerAt].PublicKey, Payer: spec.Payer}
	for _, fb := range []RefundFallback{NoFallback, FallbackReadonly} {
		e.Fallback = fb
		want := d.SettleCooperative(e, claim)
		if sameKeys(ix.Accounts, want.Accounts) {
			return sameInstruction(ix, want, "fold")
		}
	}
	return offerReject("fold.accounts", "settle_cooperative's accounts are not the payer's ticket %x at node %d/%d", f.TicketID, f.OperatorID, f.NodeID)
}

func hasDiscriminator(data []byte, name string) bool {
	disc := discriminator("global", name)
	return len(data) >= 8 && bytes.Equal(data[:8], disc[:])
}

// sameInstruction compares the program, the account keys in order and the
// data. Privileges are the message's, checked once in the header.
func sameInstruction(got, want solana.Instruction, field string) error {
	if got.ProgramID != want.ProgramID || !sameKeys(got.Accounts, want.Accounts) {
		return offerReject(field+".accounts", "%s's accounts are not the payer's", field)
	}
	if !bytes.Equal(got.Data, want.Data) {
		return offerReject(field+".data", "%s's data %x, want %x", field, got.Data, want.Data)
	}
	return nil
}

func sameKeys(a, b []solana.AccountMeta) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].PublicKey != b[i].PublicKey {
			return false
		}
	}
	return true
}
