/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zsescrow

import (
	"bytes"
	"encoding/base64"
	"fmt"

	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/ticket"
)

// The checks every transaction a payer co-signs for someone else must pass,
// shared by the open offer and the relayed ack. The payer's signature covers
// the whole message, and the program accepts it as the ack of any
// settle_cooperative of the payer's tickets in the same transaction, so each
// verifier rebuilds every instruction from the payer's own values rather
// than judge only the one it expects.

// refusal is a failed check: the field slug shared with the TS twin, and what
// the check found. Each verifier wraps it in its own error type.
type refusal struct{ field, detail string }

func refuse(field, format string, a ...any) *refusal {
	return &refusal{field: field, detail: fmt.Sprintf(format, a...)}
}

// The compute-budget instructions a co-signed transaction may carry, by tag,
// with their data length: SetComputeUnitLimit and SetComputeUnitPrice. The
// fee payer pays for both; the others size heap and loaded data, which
// neither transaction needs.
var signedComputeBudget = map[byte]int{solana.ComputeBudgetSetComputeUnitLimit: 5, solana.ComputeBudgetSetComputeUnitPrice: 9}

// payerMessage parses a message the payer is asked to sign as its second
// signer and checks, in order:
//
//  1. It parses, and loads no address lookup table: a looked-up account is
//     one the payer cannot see in the bytes it signs.
//  2. Exactly two signers: a fee payer feePayer accepts, then the payer,
//     read-only, so the payer's signature grants no write lock on its
//     wallet and pays nothing.
//  3. Compute-budget instructions lead, at most one of each allowed kind,
//     with no accounts.
//  4. kind names every other instruction, or refuses it.
//
// It returns every instruction, with account keys but no privileges (those
// are the message's, checked once here), and the kinds of those after the
// compute budget.
func payerMessage(message []byte, payerKey solana.PublicKey, feePayer func(solana.PublicKey) *refusal,
	kind func(i int, ix solana.Instruction) (string, *refusal)) ([]solana.Instruction, []string, *refusal) {
	m, err := solana.ParseMessage(message)
	if err != nil {
		return nil, nil, refuse("message.parse", "%v", err)
	}
	if len(m.AddressTableLookups) != 0 {
		return nil, nil, refuse("message.lookups", "%d address lookup tables, want none", len(m.AddressTableLookups))
	}
	if n := m.Header.NumRequiredSignatures; n != 2 {
		return nil, nil, refuse("header.signers", "%d signers, want a fee payer and the payer", n)
	}
	if r := feePayer(m.AccountKeys[0]); r != nil {
		return nil, nil, r
	}
	if m.AccountKeys[1] != payerKey {
		return nil, nil, refuse("header.payer", "second signer %s, want the payer %s", m.AccountKeys[1], payerKey)
	}
	if m.IsWritable(1) {
		return nil, nil, refuse("header.payerWritable", "the payer's key is writable")
	}

	ixs := make([]solana.Instruction, len(m.Instructions))
	var rest []string
	budget := map[byte]bool{}
	for i, ci := range m.Instructions {
		ix := solana.Instruction{ProgramID: m.AccountKeys[ci.ProgramIDIndex], Data: ci.Data}
		for _, a := range ci.Accounts {
			ix.Accounts = append(ix.Accounts, solana.AccountMeta{PublicKey: m.AccountKeys[a]})
		}
		ixs[i] = ix
		if ix.ProgramID != solana.ComputeBudgetProgramID {
			k, r := kind(i, ix)
			if r != nil {
				return nil, nil, r
			}
			rest = append(rest, k)
			continue
		}
		if len(rest) != 0 {
			return nil, nil, refuse("computeBudget.order", "instruction %d: compute budget after another program's instruction", i)
		}
		if len(ix.Data) == 0 || len(ix.Accounts) != 0 || signedComputeBudget[ix.Data[0]] != len(ix.Data) {
			return nil, nil, refuse("computeBudget.instruction", "instruction %d: compute-budget data %x with %d accounts", i, ix.Data, len(ix.Accounts))
		}
		if budget[ix.Data[0]] {
			return nil, nil, refuse("computeBudget.duplicate", "instruction %d: a second compute-budget instruction of tag %d", i, ix.Data[0])
		}
		budget[ix.Data[0]] = true
	}
	return ixs, rest, nil
}

// receiptClaim is the claim the payer acks for its ticket ticketID: the
// receipt's, once the receipt names that ticket. Compared as the string the
// node signed, so no base64 decoder's leniency can make two spellings of one
// id agree.
func receiptClaim(field string, ticketID [16]byte, r *ticket.UsageReceipt) (ClaimFields, *refusal) {
	if r == nil {
		return ClaimFields{}, refuse(field, "no receipt for the ticket")
	}
	if want := base64.StdEncoding.EncodeToString(ticketID[:]); r.TicketID != want {
		return ClaimFields{}, refuse(field, "the receipt names ticket %q, not the payer's %q", r.TicketID, want)
	}
	return ClaimFromReceipt(r), nil
}

// ClaimFromReceipt is the claim a payer acks for a receipt: the values the
// node signed, and the digest of the receipt's canonical bytes.
func ClaimFromReceipt(r *ticket.UsageReceipt) ClaimFields {
	return ClaimFields{
		Amount:          r.AmountCharged,
		ReceiptDigest:   ticket.ReceiptSigDigest(r),
		TTFTMs:          r.TtftMs,
		DecodeMs:        r.DecodeMs,
		InputUnits:      r.ActualInputCount,
		OutputUnits:     r.ActualOutputCount,
		OutputUsageType: uint8(r.OutputUsageType),
		AuxUsageType:    uint8(r.AuxOutputUsageType),
		AuxCount:        r.AuxOutputCount,
	}
}

// matchEnding checks that ix is build's ending of e's ticket at claim. The
// rent payer is whoever funded the ticket, which the program checks against
// the ticket itself, so ix's own is taken. Each fallback shape is one the
// program may be handed for the same settle; a zero e.Treasury accepts only
// the one that passes none. The treasury's USDC account passes writable as
// well as read-only, because sameInstruction compares keys and not
// privileges, and that must stay so: the program forfeits a refund the
// payer's account can't take on every ending, so refusing the transaction
// would change only which ending does it.
func matchEnding(field string, ix solana.Instruction, build func(Ending, ClaimFields) solana.Instruction, e Ending, claim ClaimFields) *refusal {
	const rentPayerAt = 5
	if len(ix.Accounts) <= rentPayerAt {
		return refuse(field+".accounts", "%s names %d accounts", field, len(ix.Accounts))
	}
	e.RentPayer = ix.Accounts[rentPayerAt].PublicKey
	fallbacks := []RefundFallback{NoFallback}
	if !e.Treasury.IsZero() {
		fallbacks = append(fallbacks, FallbackReadonly)
	}
	for _, fb := range fallbacks {
		e.Fallback = fb
		if want := build(e, claim); sameKeys(ix.Accounts, want.Accounts) {
			return sameInstruction(ix, want, field)
		}
	}
	return refuse(field+".accounts", "%s's accounts are not the payer's ticket %x at node %d/%d", field, e.TicketID, e.OperatorID, e.NodeID)
}

func hasDiscriminator(data []byte, name string) bool {
	disc := discriminator("global", name)
	return len(data) >= 8 && bytes.Equal(data[:8], disc[:])
}

// sameInstruction compares the program, the account keys in order and the
// data. Privileges are the message's, checked once in the header.
func sameInstruction(got, want solana.Instruction, field string) *refusal {
	if got.ProgramID != want.ProgramID || !sameKeys(got.Accounts, want.Accounts) {
		return refuse(field+".accounts", "%s's accounts are not the payer's", field)
	}
	if !bytes.Equal(got.Data, want.Data) {
		return refuse(field+".data", "%s's data %x, want %x", field, got.Data, want.Data)
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
