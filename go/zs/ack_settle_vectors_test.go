/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

// Generates / verifies proto/testdata/ack_settle_vectors.json: scripted runs of
// the payer's ack (ackSettle), which the TS SDK mirrors as ackSettle in
// sdk/src/ack.ts. Each scenario scripts the steps onto chain (building the
// group's spec, submitting the node's group, reading the operator's claim,
// the standalone ack) and records which were tried and what the ack reports.
// The claims block pins judgeClaim, which reads that claim off a ticket box
// for the ack, the protest's fallback and the reconciler alike, and the
// solana_claims block judgeSolanaClaim, its twin for a Solana ticket account.
//
//	cd proto/go && go test ./zs -run TestAckSettleVectors -update

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/TxnLab/zerosignal/go/escrow"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
)

const ackSettleVectorsPath = "../../testdata/ack_settle_vectors.json"

// The scripted results: the payer pays nothing on the group, which pools its
// fee on the node's half, and pays its own standalone ack.
const (
	ackGroupTxID      = "GROUPTX"
	ackStandaloneTxID = "STANDALONETX"
	ackStandaloneFee  = 5_000
	// A freeze, and the payer's half on an open box, pay for the outer call
	// alone.
	ackFreezeTxID = "FREEZETX"
	ackFreezeFee  = 1_000
	ackHalfTxID   = "HALFTX"
	ackHalfFee    = 1_000
)

type ackSettleWant struct {
	// Calls names each step tried, in order: spec, group, claim, then
	// standalone, freeze or half.
	Calls         []string `json:"calls"`
	TxID          string   `json:"txid"`
	FeeMicroalgos uint64   `json:"fee_microalgos"`
	GroupRejected bool     `json:"group_rejected"`
	// Claim is the ack's ClaimVerdict: "" when it read none.
	Claim ClaimVerdict `json:"claim"`
	// PayerSettle and Frozen are AckResult's.
	PayerSettle bool `json:"payer_settle"`
	Frozen      bool `json:"frozen"`
	// Result is ok, or which submit's error the ack returned: group,
	// standalone, freeze or half.
	Result string `json:"result"`
}

type ackSettleScenario struct {
	Name string `json:"name"`
	// Atomic: the node sent a settle group that decoded.
	Atomic bool `json:"atomic"`
	// Spec is ok or error.
	Spec string `json:"spec"`
	// Group is ok, rejected (the payer's checks refused it), rejected_wrapped
	// (the same, inside another error), no_route (no relay could carry the
	// ack, so nothing was sent) or error (anything else).
	Group string `json:"group"`
	// Claim is the ClaimVerdict the box read returns, or error when it fails.
	Claim string `json:"claim"`
	// Standalone, Freeze and Half are ok, error, or landed: sent, and failed
	// having paid its fee, as a Solana transaction can.
	Standalone string `json:"standalone"`
	Freeze     string `json:"freeze"`
	Half       string `json:"half"`
	// ResolvesFrozen is whether the deployed escrow has resolveFrozen.
	ResolvesFrozen bool          `json:"resolves_frozen"`
	Want           ackSettleWant `json:"want"`
}

func ackSettleScenarios() []ackSettleScenario {
	none, over, open := string(ClaimNone), string(ClaimOverclaims), string(ClaimOpen)
	scenarios := []ackSettleScenario{
		{Name: "no group: the payer acks standalone", Spec: "ok", Group: "ok", Claim: none, Standalone: "ok"},
		{Name: "no group: a failed standalone ack is returned", Spec: "ok", Group: "ok", Claim: none, Standalone: "error"},
		{Name: "a group that passes the checks settles atomically", Atomic: true, Spec: "ok", Group: "ok", Claim: none, Standalone: "ok"},
		{Name: "a rejected group falls back to standalone and reports the node", Atomic: true, Spec: "ok", Group: "rejected", Claim: none, Standalone: "ok"},
		{Name: "a rejection inside another error is still a rejection", Atomic: true, Spec: "ok", Group: "rejected_wrapped", Claim: none, Standalone: "ok"},
		{Name: "a rejected group still reports the node when standalone fails", Atomic: true, Spec: "ok", Group: "rejected", Claim: none, Standalone: "error"},
		{Name: "a group submit that fails otherwise is returned, never re-sent standalone", Atomic: true, Spec: "ok", Group: "error", Claim: none, Standalone: "ok"},
		{Name: "a spec that cannot be built falls back to standalone, blaming no node", Atomic: true, Spec: "error", Group: "ok", Claim: none, Standalone: "ok"},
		{Name: "a spec failure then a failed standalone ack is returned", Atomic: true, Spec: "error", Group: "ok", Claim: none, Standalone: "error"},

		{Name: "no group: a claim matching the receipt is acked, finalizing it", Spec: "ok", Group: "ok", Claim: string(ClaimAgrees), Standalone: "ok"},
		{Name: "no group: a claim above the receipt is acked, freezing it", Spec: "ok", Group: "ok", Claim: over, Standalone: "ok"},
		{Name: "no group: a failed freeze is returned with the claim", Spec: "ok", Group: "ok", Claim: over, Standalone: "ok", Freeze: "error"},
		{Name: "no group: a claim contradicting the receipt without taking more is not acked", Spec: "ok", Group: "ok", Claim: string(ClaimContradicts), Standalone: "ok"},
		{Name: "no group: an unreadable claim is acked anyway", Spec: "ok", Group: "ok", Claim: "error", Standalone: "ok"},
		{Name: "a rejected group then a claim above the receipt freezes and reports the node", Atomic: true, Spec: "ok", Group: "rejected", Claim: over, Standalone: "ok"},
		{Name: "a rejected group then a contradicting claim sends nothing but still reports the node", Atomic: true, Spec: "ok", Group: "rejected", Claim: string(ClaimContradicts), Standalone: "ok"},
		{Name: "a spec failure then a contradicting claim sends nothing", Atomic: true, Spec: "error", Group: "ok", Claim: string(ClaimContradicts), Standalone: "ok"},
		{Name: "a group that settles reads no claim", Atomic: true, Spec: "ok", Group: "ok", Claim: string(ClaimContradicts), Standalone: "ok"},

		// A group that fails to submit, which may still land, is re-sent as
		// nothing, except over a claim above the receipt: the node's half
		// already stands, so its group can only revert.
		{Name: "a failed group submit over a claim above the receipt freezes it", Atomic: true, Spec: "ok", Group: "error", Claim: over, Standalone: "ok"},
		{Name: "a failed group submit then a failed freeze returns the freeze's error", Atomic: true, Spec: "ok", Group: "error", Claim: over, Standalone: "ok", Freeze: "error"},
		{Name: "a failed group submit over a matching claim sends nothing", Atomic: true, Spec: "ok", Group: "error", Claim: string(ClaimAgrees), Standalone: "ok"},
		{Name: "a failed group submit over a contradicting claim sends nothing", Atomic: true, Spec: "ok", Group: "error", Claim: string(ClaimContradicts), Standalone: "ok"},
		{Name: "a failed group submit over an unreadable claim sends nothing", Atomic: true, Spec: "ok", Group: "error", Claim: "error", Standalone: "ok"},
		{Name: "a failed group submit over the payer's own half sends nothing", Atomic: true, Spec: "ok", Group: "error", Claim: none, Standalone: "ok"},

		// Over an open box the payer's half goes first, so a node half at
		// another figure then freezes the ticket instead of lapsing.
		{Name: "a failed group submit over an open box posts the payer's half", Atomic: true, Spec: "ok", Group: "error", Claim: open, Standalone: "ok"},
		{Name: "a failed group submit then a failed half returns the half's error", Atomic: true, Spec: "ok", Group: "error", Claim: open, Standalone: "ok", Half: "error"},
		{Name: "no group: an open box is acked standalone", Spec: "ok", Group: "ok", Claim: open, Standalone: "ok"},
		{Name: "a rejected group then an open box acks standalone", Atomic: true, Spec: "ok", Group: "rejected", Claim: open, Standalone: "ok"},

		// No relay could carry the ack, so the node never saw it: on Solana the
		// payer acks standalone, blaming no node, as if no slot had come.
		{Name: "an ack no relay can carry goes standalone, blaming no node", Atomic: true, Spec: "ok", Group: "no_route", Claim: open, Standalone: "ok"},
		{Name: "an ack no relay can carry, over a claim above the receipt, freezes it", Atomic: true, Spec: "ok", Group: "no_route", Claim: over, Standalone: "ok"},
		{Name: "an ack no relay can carry, over a contradicting claim, sends nothing", Atomic: true, Spec: "ok", Group: "no_route", Claim: string(ClaimContradicts), Standalone: "ok"},

		// A payer settle that landed and failed reports what it paid.
		{Name: "a standalone ack that landed and failed reports its id and fee", Spec: "ok", Group: "ok", Claim: open, Standalone: "landed"},
		{Name: "a freeze that landed and failed reports its id and fee, unfrozen", Spec: "ok", Group: "ok", Claim: over, Standalone: "ok", Freeze: "landed"},
		{Name: "a half that landed and failed reports its id and fee", Atomic: true, Spec: "ok", Group: "error", Claim: open, Standalone: "ok", Half: "landed"},
	}
	// An escrow without resolveFrozen keeps a frozen ticket's escrow for good,
	// so the ack sends no freeze, and no payer half after a failed group
	// submit. The standalone ack on an open box is not gated.
	noResolve := []ackSettleScenario{
		{Name: "no resolveFrozen: no group, a claim above the receipt is not acked", Spec: "ok", Group: "ok", Claim: over, Standalone: "ok"},
		{Name: "no resolveFrozen: a rejected group then a claim above the receipt sends nothing", Atomic: true, Spec: "ok", Group: "rejected", Claim: over, Standalone: "ok"},
		{Name: "no resolveFrozen: a failed group submit over a claim above the receipt sends nothing", Atomic: true, Spec: "ok", Group: "error", Claim: over, Standalone: "ok"},
		{Name: "no resolveFrozen: a failed group submit over an open box sends nothing", Atomic: true, Spec: "ok", Group: "error", Claim: open, Standalone: "ok"},
		{Name: "no resolveFrozen: no group, an open box is still acked standalone", Spec: "ok", Group: "ok", Claim: open, Standalone: "ok"},
		{Name: "no resolveFrozen: no group, a matching claim is still acked", Spec: "ok", Group: "ok", Claim: string(ClaimAgrees), Standalone: "ok"},
	}
	for i := range scenarios {
		scenarios[i].ResolvesFrozen = true
	}
	scenarios = append(scenarios, noResolve...)
	for i := range scenarios {
		if scenarios[i].Freeze == "" {
			scenarios[i].Freeze = "ok"
		}
		if scenarios[i].Half == "" {
			scenarios[i].Half = "ok"
		}
	}
	return scenarios
}

func runAckSettleScenario(sc ackSettleScenario) ackSettleWant {
	w := ackSettleWant{Calls: []string{}}
	// A step scripted "landed" sent its transaction, which failed having paid
	// its fee.
	step := func(script string, sent ackSubmission, fail error) (ackSubmission, error) {
		switch script {
		case "error":
			return ackSubmission{}, fail
		case "landed":
			return sent, fail
		}
		return sent, nil
	}
	res, err := ackSettle(sc.Atomic, ackSettleDeps[struct{}]{
		spec: func() (struct{}, error) {
			w.Calls = append(w.Calls, "spec")
			if sc.Spec == "error" {
				return struct{}{}, errors.New("spec")
			}
			return struct{}{}, nil
		},
		submitGroup: func(struct{}) (ackSubmission, error) {
			w.Calls = append(w.Calls, "group")
			rejection := &escrow.SettleGroupRejectedError{Field: "payer.rekeyTo", Detail: "scripted"}
			switch sc.Group {
			case "rejected":
				return ackSubmission{}, rejection
			case "rejected_wrapped":
				return ackSubmission{}, fmt.Errorf("submit: %w", rejection)
			case "no_route":
				return ackSubmission{}, fmt.Errorf("deliver: %w", errNoSettleAckRoute)
			case "error":
				return ackSubmission{}, errGroupSubmit
			}
			return ackSubmission{TxID: ackGroupTxID}, nil
		},
		claim: func() (ClaimVerdict, error) {
			w.Calls = append(w.Calls, "claim")
			if sc.Claim == "error" {
				return ClaimUnreadable, errors.New("box read")
			}
			return ClaimVerdict(sc.Claim), nil
		},
		standalone: func() (ackSubmission, error) {
			w.Calls = append(w.Calls, "standalone")
			return step(sc.Standalone, ackSubmission{TxID: ackStandaloneTxID, Fee: ackStandaloneFee}, errStandaloneSubmit)
		},
		freeze: func() (ackSubmission, error) {
			w.Calls = append(w.Calls, "freeze")
			return step(sc.Freeze, ackSubmission{TxID: ackFreezeTxID, Fee: ackFreezeFee}, errFreezeSubmit)
		},
		half: func() (ackSubmission, error) {
			w.Calls = append(w.Calls, "half")
			return step(sc.Half, ackSubmission{TxID: ackHalfTxID, Fee: ackHalfFee}, errHalfSubmit)
		},
		freezes: sc.ResolvesFrozen,
		log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	w.TxID, w.FeeMicroalgos, w.GroupRejected, w.Claim = res.TxID, res.FeeMicroalgos, res.GroupRejected, res.Claim
	w.PayerSettle, w.Frozen = res.PayerSettle, res.Frozen
	switch {
	case err == nil:
		w.Result = "ok"
	case errors.Is(err, errGroupSubmit):
		w.Result = "group"
	case errors.Is(err, errStandaloneSubmit):
		w.Result = "standalone"
	case errors.Is(err, errFreezeSubmit):
		w.Result = "freeze"
	case errors.Is(err, errHalfSubmit):
		w.Result = "half"
	default:
		w.Result = "other"
	}
	return w
}

var (
	errGroupSubmit      = errors.New("group submit")
	errStandaloneSubmit = errors.New("standalone submit")
	errFreezeSubmit     = errors.New("freeze submit")
	errHalfSubmit       = errors.New("half submit")
)

// claimVectorCase is one ticket box (null when gone) and the payer's settle
// args, with the verdict judgeClaim gives. It reuses the reconcile vectors'
// shapes, so both suites decode one box format.
type claimVectorCase struct {
	Name    string                `json:"name"`
	Settle  reconcileVectorSettle `json:"settle"`
	Box     *reconcileVectorBox   `json:"box"`
	Verdict ClaimVerdict          `json:"verdict"`
}

func claimVectorInputs() []claimVectorCase {
	edit := func(status, pendingBy uint64, f func(*reconcileVectorBox)) *reconcileVectorBox {
		b := rvBox(status, pendingBy)
		if f != nil {
			f(&b)
		}
		return &b
	}
	otherDigest := func(b *reconcileVectorBox) {
		d := rvDigest()
		d[0] ^= 0xff
		b.PendingDigest = base64.StdEncoding.EncodeToString(d[:])
	}
	op := func(f func(*reconcileVectorBox)) *reconcileVectorBox {
		return edit(escrow.StatusPendingSettle, escrow.PendingByOperator, f)
	}
	cases := []claimVectorCase{
		{Name: "no box", Box: nil},
		{Name: "open box", Box: edit(escrow.StatusOpen, 0, nil)},
		{Name: "payer-side claim matching the receipt", Box: edit(escrow.StatusPendingSettle, escrow.PendingByPayer, nil)},
		{Name: "payer-side claim above the receipt", Box: edit(escrow.StatusPendingSettle, escrow.PendingByPayer, func(b *reconcileVectorBox) { b.PendingAmount += 1000 })},
		{Name: "pending claim on no side", Box: edit(escrow.StatusPendingSettle, 0, func(b *reconcileVectorBox) { b.PendingAmount += 1000 })},
		{Name: "frozen box over an operator claim above the receipt", Box: edit(escrow.StatusFrozen, escrow.PendingByOperator, func(b *reconcileVectorBox) { b.PendingAmount += 1000 })},
		{Name: "unrecognized status over an operator claim above the receipt", Box: edit(escrow.StatusSettled, escrow.PendingByOperator, func(b *reconcileVectorBox) { b.PendingAmount += 1000 })},
		{Name: "operator claim equal to the receipt", Box: op(nil)},
		{Name: "operator claim one below the receipt", Box: op(func(b *reconcileVectorBox) { b.PendingAmount-- })},
		{Name: "operator claim below the receipt with another digest", Box: op(func(b *reconcileVectorBox) { b.PendingAmount -= 1000; otherDigest(b) })},
		{Name: "operator claim of zero", Box: op(func(b *reconcileVectorBox) { b.PendingAmount = 0; otherDigest(b) })},
		{Name: "operator claim one above the receipt", Box: op(func(b *reconcileVectorBox) { b.PendingAmount++ })},
		{Name: "operator claim above the receipt with another digest", Box: op(func(b *reconcileVectorBox) { b.PendingAmount += 1000; otherDigest(b) })},
		{Name: "operator claim above the receipt, every other value matching", Box: op(func(b *reconcileVectorBox) { b.PendingAmount *= 2 })},
		{Name: "operator claim at the receipt's amount with another digest", Box: op(otherDigest)},
		{Name: "operator claim at the receipt's amount with another ttft", Box: op(func(b *reconcileVectorBox) { b.PendingTtftMs++ })},
		{Name: "operator claim at the receipt's amount with another output count", Box: op(func(b *reconcileVectorBox) { b.PendingOutputCount++ })},
		{Name: "operator claim at the receipt's amount with another aux usage type", Box: op(func(b *reconcileVectorBox) { b.PendingAuxOutputUsageType = 0 })},
	}
	for i := range cases {
		cases[i].Settle = rvSettle()
	}
	// A zero receipt, which an error turn settles at: any operator claim of
	// more is an over-claim.
	zero := rvSettle()
	zero.AmountCharged = 0
	cases = append(cases,
		claimVectorCase{Name: "zero receipt, operator claim of zero", Settle: zero, Box: op(func(b *reconcileVectorBox) { b.PendingAmount = 0 })},
		claimVectorCase{Name: "zero receipt, operator claim of one", Settle: zero, Box: op(func(b *reconcileVectorBox) { b.PendingAmount = 1 })},
	)
	return cases
}

func runClaimVector(t *testing.T, c claimVectorCase) ClaimVerdict {
	t.Helper()
	// Through the reconcile vector's decoder, so the box mapping is the one
	// that file already pins.
	rc := reconcileVectorCase{Status: TicketSettlePending, Settle: &c.Settle, Box: c.Box}
	rec, box := reconcileVectorInputsOf(t, rc)
	return judgeClaim(*rec.Settle, box)
}

// solanaClaimTicket is the part of a Solana ticket account judgeSolanaClaim
// reads.
type solanaClaimTicket struct {
	Status  uint8              `json:"status"`
	Pending solanaPendingClaim `json:"pending"`
}

// solanaPendingClaim is zsescrow.ClaimFields with the digest in hex.
type solanaPendingClaim struct {
	Amount          uint64 `json:"amount"`
	ReceiptDigest   string `json:"receipt_digest"`
	TTFTMs          uint64 `json:"ttft_ms"`
	DecodeMs        uint64 `json:"decode_ms"`
	InputUnits      uint64 `json:"input_units"`
	OutputUnits     uint64 `json:"output_units"`
	OutputUsageType uint8  `json:"output_usage_type"`
	AuxUsageType    uint8  `json:"aux_usage_type"`
	AuxCount        uint64 `json:"aux_count"`
}

func pendingClaimOf(f zsescrow.ClaimFields) solanaPendingClaim {
	return solanaPendingClaim{f.Amount, hex.EncodeToString(f.ReceiptDigest[:]), f.TTFTMs, f.DecodeMs, f.InputUnits, f.OutputUnits,
		f.OutputUsageType, f.AuxUsageType, f.AuxCount}
}

func (p solanaPendingClaim) fields(t *testing.T) zsescrow.ClaimFields {
	d, err := hex.DecodeString(p.ReceiptDigest)
	if err != nil || len(d) != 32 {
		t.Fatalf("receipt digest %q", p.ReceiptDigest)
	}
	return zsescrow.ClaimFields{Amount: p.Amount, ReceiptDigest: [32]byte(d), TTFTMs: p.TTFTMs, DecodeMs: p.DecodeMs, InputUnits: p.InputUnits,
		OutputUnits: p.OutputUnits, OutputUsageType: p.OutputUsageType, AuxUsageType: p.AuxUsageType, AuxCount: p.AuxCount}
}

// solanaClaimVectorCase is claimVectorCase for a Solana ticket (null when
// closed), with the verdict judgeSolanaClaim gives.
type solanaClaimVectorCase struct {
	Name    string                `json:"name"`
	Settle  reconcileVectorSettle `json:"settle"`
	Ticket  *solanaClaimTicket    `json:"ticket"`
	Verdict ClaimVerdict          `json:"verdict"`
}

func solanaClaimVectorInputs(t *testing.T) []solanaClaimVectorCase {
	// A ticket whose first half is s's fields changed by f.
	ticketOf := func(status zsescrow.TicketStatus, s reconcileVectorSettle, f func(*zsescrow.ClaimFields)) *solanaClaimTicket {
		fields := solanaClaimFields(*rvArgs(t, &s))
		if f != nil {
			f(&fields)
		}
		return &solanaClaimTicket{Status: uint8(status), Pending: pendingClaimOf(fields)}
	}
	s := rvSettle()
	at := func(status zsescrow.TicketStatus, f func(*zsescrow.ClaimFields)) *solanaClaimTicket {
		return ticketOf(status, s, f)
	}
	op := func(pending uint64, f func(*zsescrow.ClaimFields)) *solanaClaimTicket {
		return ticketOf(zsescrow.TicketPendingByOperator, s, func(c *zsescrow.ClaimFields) {
			c.Amount = pending
			if f != nil {
				f(c)
			}
		})
	}
	otherDigest := func(c *zsescrow.ClaimFields) { c.ReceiptDigest[0] ^= 0xff }
	cases := []solanaClaimVectorCase{
		{Name: "no ticket", Ticket: nil},
		{Name: "open ticket", Ticket: &solanaClaimTicket{Status: uint8(zsescrow.TicketOpen), Pending: pendingClaimOf(zsescrow.ClaimFields{})}},
		{Name: "payer-side claim matching the receipt", Ticket: at(zsescrow.TicketPendingByPayer, nil)},
		{Name: "payer-side claim above the receipt", Ticket: at(zsescrow.TicketPendingByPayer, func(c *zsescrow.ClaimFields) { c.Amount += 1000 })},
		{Name: "frozen ticket over an operator claim above the receipt", Ticket: at(zsescrow.TicketFrozen, func(c *zsescrow.ClaimFields) { c.Amount += 1000 })},
		{Name: "unrecognized status over an operator claim above the receipt", Ticket: at(4, func(c *zsescrow.ClaimFields) { c.Amount += 1000 })},
		{Name: "operator claim equal to the receipt", Ticket: op(s.AmountCharged, nil)},
		{Name: "operator claim one below the receipt", Ticket: op(s.AmountCharged-1, nil)},
		{Name: "operator claim below the receipt with another digest", Ticket: op(s.AmountCharged-1000, otherDigest)},
		{Name: "operator claim of zero", Ticket: op(0, otherDigest)},
		{Name: "operator claim one above the receipt", Ticket: op(s.AmountCharged+1, nil)},
		{Name: "operator claim above the receipt with another digest", Ticket: op(s.AmountCharged+1000, otherDigest)},
		{Name: "operator claim at the receipt's amount with another digest", Ticket: op(s.AmountCharged, otherDigest)},
		{Name: "operator claim at the receipt's amount with another last digest byte", Ticket: op(s.AmountCharged, func(c *zsescrow.ClaimFields) { c.ReceiptDigest[31] ^= 0x01 })},
		{Name: "operator claim at the receipt's amount with another ttft", Ticket: op(s.AmountCharged, func(c *zsescrow.ClaimFields) { c.TTFTMs++ })},
		{Name: "operator claim at the receipt's amount with another output count", Ticket: op(s.AmountCharged, func(c *zsescrow.ClaimFields) { c.OutputUnits++ })},
		{Name: "operator claim at the receipt's amount with another aux usage type", Ticket: op(s.AmountCharged, func(c *zsescrow.ClaimFields) { c.AuxUsageType = 0 })},
		{Name: "operator claim at the receipt's amount with another decode time", Ticket: op(s.AmountCharged, func(c *zsescrow.ClaimFields) { c.DecodeMs++ })},
		{Name: "operator claim at the receipt's amount with another input count", Ticket: op(s.AmountCharged, func(c *zsescrow.ClaimFields) { c.InputUnits++ })},
		{Name: "operator claim at the receipt's amount with another output usage type", Ticket: op(s.AmountCharged, func(c *zsescrow.ClaimFields) { c.OutputUsageType ^= 1 })},
		{Name: "operator claim at the receipt's amount with another aux count", Ticket: op(s.AmountCharged, func(c *zsescrow.ClaimFields) { c.AuxCount++ })},
	}
	for i := range cases {
		cases[i].Settle = s
	}
	zero := rvSettle()
	zero.AmountCharged = 0
	cases = append(cases,
		solanaClaimVectorCase{Name: "zero receipt, operator claim of zero", Settle: zero, Ticket: ticketOf(zsescrow.TicketPendingByOperator, zero, nil)},
		solanaClaimVectorCase{Name: "zero receipt, operator claim of one", Settle: zero, Ticket: ticketOf(zsescrow.TicketPendingByOperator, zero, func(c *zsescrow.ClaimFields) { c.Amount = 1 })},
	)
	return cases
}

func runSolanaClaimVector(t *testing.T, c solanaClaimVectorCase) ClaimVerdict {
	t.Helper()
	var tk *zsescrow.Ticket
	if c.Ticket != nil {
		tk = &zsescrow.Ticket{Status: zsescrow.TicketStatus(c.Ticket.Status), Pending: c.Ticket.Pending.fields(t)}
	}
	return judgeSolanaClaim(*rvArgs(t, &c.Settle), tk)
}

func TestAckSettleVectors(t *testing.T) {
	scenarios := ackSettleScenarios()
	for i := range scenarios {
		scenarios[i].Want = runAckSettleScenario(scenarios[i])
	}
	claims := claimVectorInputs()
	for i := range claims {
		claims[i].Verdict = runClaimVector(t, claims[i])
	}
	solanaClaims := solanaClaimVectorInputs(t)
	for i := range solanaClaims {
		solanaClaims[i].Verdict = runSolanaClaimVector(t, solanaClaims[i])
	}
	f := struct {
		Comment      string                  `json:"comment"`
		Scenarios    []ackSettleScenario     `json:"scenarios"`
		Claims       []claimVectorCase       `json:"claims"`
		SolanaClaims []solanaClaimVectorCase `json:"solana_claims"`
	}{
		Comment:      "Generated by proto/go/zs TestAckSettleVectors. Compare want and verdict exactly. solana_claims: judgeSolanaClaim on a Solana ticket account, whose pending claim's receipt_digest is hex.",
		Scenarios:    scenarios,
		Claims:       claims,
		SolanaClaims: solanaClaims,
	}
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')

	if *updateVectors {
		if err := os.WriteFile(ackSettleVectorsPath, out, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(ackSettleVectorsPath)
	if err != nil {
		t.Fatalf("read vectors (regenerate with -update): %v", err)
	}
	if !bytes.Equal(want, out) {
		t.Fatalf("ack settle differs from %s; if the change is intended, regenerate with -update and review the diff", ackSettleVectorsPath)
	}
}
