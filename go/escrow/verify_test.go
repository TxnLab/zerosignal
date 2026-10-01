/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package escrow

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// buildValidOpenGroup builds a 2-member open() group that matches
// spec (usdcPayment + app call). The ticket-box MBR is drawn from the
// payer's prepaid pool at open(), so there is no feePayment leg. gtxn[0]
// (usdcPayment) is payer-signed with fee=0; gtxn[1] (open AppCall) is
// operator-signed with fee=2000 (fee-pools the entire group). Used as
// the baseline; tests then mutate one field at a time to verify each
// check fires.
func buildValidOpenGroup(t *testing.T) ([]types.SignedTxn, OpenGroupSpec, types.Address) {
	t.Helper()

	_, payerPub, _ := genKey(t)
	var payerAddr types.Address
	copy(payerAddr[:], payerPub)

	_, opSigningPub, _ := genKey(t)
	var operatorSigningAddr types.Address
	copy(operatorSigningAddr[:], opSigningPub)

	_, appPub, _ := genKey(t)
	var appAddr types.Address
	copy(appAddr[:], appPub)

	ticketID := make([]byte, 16)
	if _, err := rand.Read(ticketID); err != nil {
		t.Fatal(err)
	}

	spec := OpenGroupSpec{
		AppID:           42,
		AppAddress:      appAddr,
		TicketIDRaw:     ticketID,
		OperatorID:      7,
		NodeID:          11,
		MaxPrice:        100_000,
		TicketMbr:       86_500,
		UsdcAssetID:     31566704,
		NodeSigningAddr: operatorSigningAddr,
		PayerAddr:       payerAddr,
		// Window args: expiresAt matches the ticket; grace pinned 0
		// (contract default applies) as reference payer-side callers do.
		ExpiresAt:              1_900_000_000,
		SettlementGraceSeconds: 0,
	}

	// gtxn[0] usdcPayment: payer-signed, fee=0.
	axfer := types.Transaction{
		Type: types.AssetTransferTx,
		Header: types.Header{
			Sender: payerAddr,
			Fee:    0,
		},
		AssetTransferTxnFields: types.AssetTransferTxnFields{
			XferAsset:     types.AssetIndex(spec.UsdcAssetID),
			AssetAmount:   spec.MaxPrice,
			AssetReceiver: spec.AppAddress,
		},
	}

	openSelector, err := MethodSelector("open")
	if err != nil {
		t.Fatal(err)
	}
	ticketIDArg := abiByteSlice(spec.TicketIDRaw)
	operatorIDArg := abiUint64(spec.OperatorID)
	nodeIDArg := abiUint64(spec.NodeID)
	payerAddrArg := payerAddr[:] // ABI `address` is raw 32 bytes
	maxPriceArg := abiUint64(spec.MaxPrice)
	expiresAtArg := abiUint64(spec.ExpiresAt)
	graceArg := abiUint64(spec.SettlementGraceSeconds)
	// ApplicationArgs positions (transaction-typed args don't appear here —
	// they're separate group members):
	//   0: selector
	//   1: ticketId (byte[])
	//   2: operatorId (uint64)
	//   3: nodeId (uint64)
	//   4: payerAddr (address, 32 bytes)
	//   5: maxPrice (uint64)
	//   6: expiresAt (uint64)         — VerifyOpenGroup-only (payer-side) check
	//   7: settlementGraceSeconds (uint64) — VerifyOpenGroup-only (payer-side) check
	app := types.Transaction{
		Type: types.ApplicationCallTx,
		Header: types.Header{
			Sender: operatorSigningAddr,
			Fee:    2000,
		},
		ApplicationFields: types.ApplicationFields{
			ApplicationCallTxnFields: types.ApplicationCallTxnFields{
				ApplicationID: types.AppIndex(spec.AppID),
				OnCompletion:  types.NoOpOC,
				ApplicationArgs: [][]byte{
					openSelector,
					ticketIDArg,
					operatorIDArg,
					nodeIDArg,
					payerAddrArg,
					maxPriceArg,
					expiresAtArg,
					graceArg,
				},
			},
		},
	}

	gid, err := crypto.ComputeGroupID([]types.Transaction{axfer, app})
	if err != nil {
		t.Fatal(err)
	}
	axfer.Group = gid
	app.Group = gid

	return []types.SignedTxn{{Txn: axfer}, {Txn: app}}, spec, payerAddr
}

func TestVerifyOpenGroup_Happy(t *testing.T) {
	group, spec, _ := buildValidOpenGroup(t)
	if err := VerifyOpenGroup(group, spec); err != nil {
		t.Fatalf("VerifyOpenGroup: %v", err)
	}
}

// A shared, non-zero gid that commits to a different gtxn[1] than the one
// presented: the node shows an honest NoOp open() but the gid (which the
// payer's signature over gtxn[0] covers) hashes a ClearState variant.
func TestVerifyOpenGroup_GroupIDCommitsToOtherSibling(t *testing.T) {
	group, spec, _ := buildValidOpenGroup(t)
	hidden := []types.SignedTxn{group[0], group[1]}
	hidden[1].Txn.OnCompletion = types.ClearStateOC
	gid := regrouped(t, hidden)[0].Txn.Group
	group[0].Txn.Group = gid
	group[1].Txn.Group = gid
	if err := VerifyOpenGroup(group, spec); err == nil || !strings.Contains(err.Error(), "does not commit to its members") {
		t.Fatalf("got %v, want group-id commitment error", err)
	}
}

// The window args (expiresAt / settlementGraceSeconds) are payer-side-only
// checks: the node authored them, so a divergence from the ticket shifts the
// settlement/refund windows away from what the payer agreed to (a non-zero
// grace silently pushes out the refundInactive deadline).
func TestVerifyOpenGroup_ExpiresAtMismatch(t *testing.T) {
	group, spec, _ := buildValidOpenGroup(t)
	spec.ExpiresAt++
	err := VerifyOpenGroup(group, spec)
	if err == nil || !strings.Contains(err.Error(), "expiresAt") {
		t.Fatalf("err = %v, want expiresAt mismatch", err)
	}
}

func TestVerifyOpenGroup_SettlementGraceMismatch(t *testing.T) {
	group, spec, _ := buildValidOpenGroup(t)
	// Group carries grace 0 (the reference-node value); a spec pinning 0
	// must refuse a group that smuggled a non-zero window — simulate by
	// expecting 0 while the group says 3600.
	group[1].Txn.ApplicationArgs[7] = abiUint64(3600)
	err := VerifyOpenGroup(regrouped(t, group), spec)
	if err == nil || !strings.Contains(err.Error(), "settlementGraceSeconds") {
		t.Fatalf("err = %v, want settlementGraceSeconds mismatch", err)
	}
}

func TestVerifyOpenGroup_WrongSize(t *testing.T) {
	group, spec, _ := buildValidOpenGroup(t)
	if err := VerifyOpenGroup(group[:1], spec); err == nil || !strings.Contains(err.Error(), "size") {
		t.Fatalf("got %v, want size error", err)
	}
}

func TestVerifyOpenGroup_MissingGroupID(t *testing.T) {
	group, spec, _ := buildValidOpenGroup(t)
	group[0].Txn.Group = types.Digest{}
	if err := VerifyOpenGroup(group, spec); err == nil || !strings.Contains(err.Error(), "group id") {
		t.Fatalf("got %v, want group-id error", err)
	}
}

func TestVerifyOpenGroup_WrongUsdcReceiver(t *testing.T) {
	group, spec, _ := buildValidOpenGroup(t)
	var other types.Address
	other[0] = 0x02
	group[0].Txn.AssetReceiver = other
	if err := VerifyOpenGroup(regrouped(t, group), spec); err == nil || !strings.Contains(err.Error(), "asset_receiver") {
		t.Fatalf("got %v, want asset_receiver error", err)
	}
}

func TestVerifyOpenGroup_WrongUsdcAsset(t *testing.T) {
	group, spec, _ := buildValidOpenGroup(t)
	group[0].Txn.XferAsset = types.AssetIndex(spec.UsdcAssetID + 1)
	if err := VerifyOpenGroup(regrouped(t, group), spec); err == nil || !strings.Contains(err.Error(), "xfer_asset") {
		t.Fatalf("got %v, want xfer_asset error", err)
	}
}

func TestVerifyOpenGroup_WrongUsdcAmount(t *testing.T) {
	group, spec, _ := buildValidOpenGroup(t)
	group[0].Txn.AssetAmount = spec.MaxPrice + 1
	if err := VerifyOpenGroup(regrouped(t, group), spec); err == nil || !strings.Contains(err.Error(), "asset_amount") {
		t.Fatalf("got %v, want asset_amount error", err)
	}
}

func TestVerifyOpenGroup_WrongAppID(t *testing.T) {
	group, spec, _ := buildValidOpenGroup(t)
	group[1].Txn.ApplicationID = types.AppIndex(spec.AppID + 1)
	if err := VerifyOpenGroup(regrouped(t, group), spec); err == nil || !strings.Contains(err.Error(), "app_id") {
		t.Fatalf("got %v, want app_id error", err)
	}
}

func TestVerifyOpenGroup_WrongSelector(t *testing.T) {
	group, spec, _ := buildValidOpenGroup(t)
	group[1].Txn.ApplicationArgs[0] = []byte{0, 0, 0, 0}
	if err := VerifyOpenGroup(regrouped(t, group), spec); err == nil || !strings.Contains(err.Error(), "selector") {
		t.Fatalf("got %v, want selector error", err)
	}
}

func TestVerifyOpenGroup_WrongTicketID(t *testing.T) {
	group, spec, _ := buildValidOpenGroup(t)
	// Change one byte of the ticket id argument — keep the length prefix intact.
	group[1].Txn.ApplicationArgs[1][2] ^= 0xFF
	if err := VerifyOpenGroup(regrouped(t, group), spec); err == nil || !strings.Contains(err.Error(), "ticketId") {
		t.Fatalf("got %v, want ticketId error", err)
	}
}

func TestVerifyOpenGroup_WrongOperatorID(t *testing.T) {
	group, spec, _ := buildValidOpenGroup(t)
	group[1].Txn.ApplicationArgs[2] = abiUint64(spec.OperatorID + 1)
	if err := VerifyOpenGroup(regrouped(t, group), spec); err == nil || !strings.Contains(err.Error(), "operatorId") {
		t.Fatalf("got %v, want operatorId error", err)
	}
}

func TestVerifyOpenGroup_WrongNodeID(t *testing.T) {
	group, spec, _ := buildValidOpenGroup(t)
	group[1].Txn.ApplicationArgs[3] = abiUint64(spec.NodeID + 1)
	if err := VerifyOpenGroup(regrouped(t, group), spec); err == nil || !strings.Contains(err.Error(), "nodeId") {
		t.Fatalf("got %v, want nodeId error", err)
	}
}

func TestVerifyOpenGroup_WrongPayerAddrArg(t *testing.T) {
	group, spec, _ := buildValidOpenGroup(t)
	// Flip a byte of the payerAddr ABI arg (position 4 — address is
	// raw 32 bytes, no length prefix).
	group[1].Txn.ApplicationArgs[4][0] ^= 0xFF
	if err := VerifyOpenGroup(regrouped(t, group), spec); err == nil || !strings.Contains(err.Error(), "payerAddr") {
		t.Fatalf("got %v, want payerAddr error", err)
	}
}

func TestVerifyOpenGroup_WrongMaxPrice(t *testing.T) {
	group, spec, _ := buildValidOpenGroup(t)
	group[1].Txn.ApplicationArgs[5] = abiUint64(spec.MaxPrice + 1)
	if err := VerifyOpenGroup(regrouped(t, group), spec); err == nil || !strings.Contains(err.Error(), "maxPrice") {
		t.Fatalf("got %v, want maxPrice error", err)
	}
}

func TestVerifyOpenGroup_WrongAppCallSender(t *testing.T) {
	group, spec, _ := buildValidOpenGroup(t)
	// Swap gtxn[1].sender (the open AppCall) to something that isn't
	// node_signing — the consensus-verified authentication check fires on this.
	var other types.Address
	other[0] = 0x09
	group[1].Txn.Sender = other
	if err := VerifyOpenGroup(regrouped(t, group), spec); err == nil || !strings.Contains(err.Error(), "node_signing") {
		t.Fatalf("got %v, want node_signing error", err)
	}
}

func TestVerifyOpenGroup_WrongFundingSender(t *testing.T) {
	group, spec, _ := buildValidOpenGroup(t)
	// Funding-txn sender mismatch — the contract pins gtxn[0] (usdcPayment)
	// sender to payerAddr.
	var other types.Address
	other[0] = 0x10
	group[0].Txn.Sender = other
	if err := VerifyOpenGroup(regrouped(t, group), spec); err == nil || !strings.Contains(err.Error(), "payer") {
		t.Fatalf("got %v, want payer-sender error", err)
	}
}

// Shape guards on the payer-signed usdcPayment: each case sets exactly one
// field the honest composer leaves zero. Every one of them would turn the
// payer's signature into more than the max_price transfer it agreed to. That
// the real composer leaves them zero (fee included, despite a non-zero
// suggested min fee) is pinned end to end by TestComposeOpenGroup_SplitSigners.
func TestVerifyOpenGroup_PayerLegShapeGuards(t *testing.T) {
	var attacker types.Address
	attacker[0] = 0x66
	cases := []struct {
		name    string
		mutate  func(*types.Transaction)
		wantErr string
	}{
		{"rekey_to", func(tx *types.Transaction) { tx.RekeyTo = attacker }, "open[0] rekey_to"},
		{"asset_close_to", func(tx *types.Transaction) { tx.AssetCloseTo = attacker }, "open[0] asset_close_to"},
		{"asset_sender", func(tx *types.Transaction) { tx.AssetSender = attacker }, "open[0] asset_sender"},
		{"close_remainder_to", func(tx *types.Transaction) { tx.CloseRemainderTo = attacker }, "open[0] close_remainder_to"},
		{"fee", func(tx *types.Transaction) { tx.Fee = 1000 }, "open[0] fee"},
		{"note", func(tx *types.Transaction) { tx.Note = []byte("x") }, "open[0] note"},
		{"lease", func(tx *types.Transaction) { tx.Lease[31] = 1 }, "open[0] lease"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			group, spec, _ := buildValidOpenGroup(t)
			tc.mutate(&group[0].Txn)
			err := VerifyOpenGroup(regrouped(t, group), spec)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

// ClearState skips open()'s approval program, so the group would commit the
// payer's USDC into the app with no ticket box to refund against. The other
// non-NoOp actions are refused too: open() is a NoOp-only method, so none of
// them is an honest shape.
func TestVerifyOpenGroup_AppCallNotNoOp(t *testing.T) {
	for _, oc := range []types.OnCompletion{
		types.OptInOC, types.CloseOutOC, types.ClearStateOC, types.UpdateApplicationOC, types.DeleteApplicationOC,
	} {
		t.Run(fmt.Sprint(oc), func(t *testing.T) {
			group, spec, _ := buildValidOpenGroup(t)
			group[1].Txn.OnCompletion = oc
			if err := VerifyOpenGroup(regrouped(t, group), spec); err == nil || !strings.Contains(err.Error(), "open[1] on_complete") {
				t.Fatalf("got %v, want on_complete error", err)
			}
		})
	}
}

// ---------------------------------------------------------------------
// VerifySettleGroup tests: the payer-ack pre-sign guard. buildValidSettleGroup
// hand-builds the 2-tx atomic settle pair (operator first-half + payer ack)
// matching spec; each case mutates one field and asserts the matching typed
// rejection fires — with special attention to the shape-fraud checks
// (rekeyTo → account takeover, onComplete != NoOp → ClearState approval
// bypass), which the open path guards too.

func buildValidSettleGroup(t *testing.T) ([]types.SignedTxn, SettleGroupSpec) {
	t.Helper()

	_, payerPub, _ := genKey(t)
	var payerAddr types.Address
	copy(payerAddr[:], payerPub)

	_, opSigningPub, _ := genKey(t)
	var operatorSigningAddr types.Address
	copy(operatorSigningAddr[:], opSigningPub)

	ticketID := make([]byte, 16)
	if _, err := rand.Read(ticketID); err != nil {
		t.Fatal(err)
	}
	var digest [32]byte
	if _, err := rand.Read(digest[:]); err != nil {
		t.Fatal(err)
	}

	spec := SettleGroupSpec{
		AppID:               1234,
		TicketIDRaw:         ticketID,
		AmountCharged:       50_000,
		ReceiptDigest:       digest,
		TtftMs:              1200,
		DecodeMs:            300,
		InputCount:          250,
		OutputCount:         750,
		OutputUsageType:     1, // ticket.UsageTypeTokens
		AuxOutputUsageType:  0,
		AuxOutputCount:      0,
		PayerAddr:           payerAddr,
		OperatorSigningAddr: operatorSigningAddr,
	}

	settleSelector, err := MethodSelector("settle")
	if err != nil {
		t.Fatal(err)
	}
	// Shared ABI args for both members; only the trailing asOperator byte and
	// the sender/fee differ. Layout mirrors settle() (see verifySettleMember).
	baseArgs := func(asOperator byte) [][]byte {
		return [][]byte{
			settleSelector,
			abiByteSlice(spec.TicketIDRaw),
			abiUint64(spec.AmountCharged),
			abiByteSlice(spec.ReceiptDigest[:]),
			abiUint64(spec.TtftMs),
			abiUint64(spec.DecodeMs),
			abiUint64(spec.InputCount),
			abiUint64(spec.OutputCount),
			abiUint64(spec.OutputUsageType),
			abiUint64(spec.AuxOutputUsageType),
			abiUint64(spec.AuxOutputCount),
			{asOperator},
		}
	}

	// gtxn[0]: operator first-half, asOperator=true, pools the group fee.
	opTxn := types.Transaction{
		Type: types.ApplicationCallTx,
		Header: types.Header{
			Sender: operatorSigningAddr,
			Fee:    6000,
		},
		ApplicationFields: types.ApplicationFields{
			ApplicationCallTxnFields: types.ApplicationCallTxnFields{
				ApplicationID:   types.AppIndex(spec.AppID),
				OnCompletion:    types.NoOpOC,
				ApplicationArgs: baseArgs(settleAsOperatorTrue),
			},
		},
	}
	// gtxn[1]: payer ack, asOperator=false, fee=0 (pooled from gtxn[0]).
	payerTxn := types.Transaction{
		Type: types.ApplicationCallTx,
		Header: types.Header{
			Sender: payerAddr,
			Fee:    0,
		},
		ApplicationFields: types.ApplicationFields{
			ApplicationCallTxnFields: types.ApplicationCallTxnFields{
				ApplicationID:   types.AppIndex(spec.AppID),
				OnCompletion:    types.NoOpOC,
				ApplicationArgs: baseArgs(settleAsOperatorFalse),
			},
		},
	}

	gid, err := crypto.ComputeGroupID([]types.Transaction{opTxn, payerTxn})
	if err != nil {
		t.Fatal(err)
	}
	opTxn.Group = gid
	payerTxn.Group = gid

	return []types.SignedTxn{{Txn: opTxn}, {Txn: payerTxn}}, spec
}

// expectSettleRejected asserts err is a *SettleGroupRejectedError with the
// given Field slug.
func expectSettleRejected(t *testing.T, err error, wantField string) {
	t.Helper()
	if err == nil {
		t.Fatalf("VerifySettleGroup: got nil, want rejection on %q", wantField)
	}
	var rejected *SettleGroupRejectedError
	if !errors.As(err, &rejected) {
		t.Fatalf("VerifySettleGroup: err = %v (%T), want *SettleGroupRejectedError", err, err)
	}
	if rejected.Field != wantField {
		t.Fatalf("rejected.Field = %q, want %q (detail: %s)", rejected.Field, wantField, rejected.Detail)
	}
}

func TestVerifySettleGroup_Happy(t *testing.T) {
	group, spec := buildValidSettleGroup(t)
	if err := VerifySettleGroup(group, spec); err != nil {
		t.Fatalf("VerifySettleGroup: %v", err)
	}
}

// The payer is shown an honest ack template, but the shared gid commits to a
// variant of the operator half the payer never checked (inflated amount).
func TestVerifySettleGroup_GroupIDCommitsToOtherSibling(t *testing.T) {
	group, spec := buildValidSettleGroup(t)
	hidden := []types.SignedTxn{group[0], group[1]}
	hiddenArgs := append([][]byte(nil), hidden[0].Txn.ApplicationArgs...)
	hiddenArgs[2] = abiUint64(spec.AmountCharged + 10_000)
	hidden[0].Txn.ApplicationArgs = hiddenArgs
	gid := regrouped(t, hidden)[0].Txn.Group
	group[0].Txn.Group = gid
	group[1].Txn.Group = gid
	err := VerifySettleGroup(group, spec)
	expectSettleRejected(t, err, "group.id")
	if !strings.Contains(err.Error(), "does not commit to its members") {
		t.Fatalf("err = %v, want the commitment rejection, not the mismatch one", err)
	}
}

// Shape-fraud on the payer half: a rekeyTo hands the payer's account to the
// operator the instant the payer signs → the check must fire on gtxn[1].
func TestVerifySettleGroup_RekeyToPayer(t *testing.T) {
	group, spec := buildValidSettleGroup(t)
	var attacker types.Address
	attacker[0] = 0x09
	group[1].Txn.RekeyTo = attacker
	expectSettleRejected(t, VerifySettleGroup(regrouped(t, group), spec), "payer.rekeyTo")
}

func TestVerifySettleGroup_RekeyToOperator(t *testing.T) {
	group, spec := buildValidSettleGroup(t)
	var attacker types.Address
	attacker[0] = 0x09
	group[0].Txn.RekeyTo = attacker
	expectSettleRejected(t, VerifySettleGroup(regrouped(t, group), spec), "operator.rekeyTo")
}

// ClearState runs the clear-state program instead of `approval`, bypassing
// every contract assert — a signed ClearState on the payer half would wipe
// the payer's local MBR-pool accounting.
func TestVerifySettleGroup_ClearStatePayer(t *testing.T) {
	group, spec := buildValidSettleGroup(t)
	group[1].Txn.OnCompletion = types.ClearStateOC
	expectSettleRejected(t, VerifySettleGroup(regrouped(t, group), spec), "payer.onComplete")
}

func TestVerifySettleGroup_CloseOutOperator(t *testing.T) {
	group, spec := buildValidSettleGroup(t)
	group[0].Txn.OnCompletion = types.CloseOutOC
	expectSettleRejected(t, VerifySettleGroup(regrouped(t, group), spec), "operator.onComplete")
}

func TestVerifySettleGroup_NonZeroPayerFee(t *testing.T) {
	group, spec := buildValidSettleGroup(t)
	group[1].Txn.Fee = 1000
	expectSettleRejected(t, VerifySettleGroup(regrouped(t, group), spec), "payer.fee")
}

func TestVerifySettleGroup_WrongOperatorSender(t *testing.T) {
	group, spec := buildValidSettleGroup(t)
	var other types.Address
	other[0] = 0x11
	group[0].Txn.Sender = other
	expectSettleRejected(t, VerifySettleGroup(regrouped(t, group), spec), "operator.sender")
}

func TestVerifySettleGroup_WrongPayerSender(t *testing.T) {
	group, spec := buildValidSettleGroup(t)
	var other types.Address
	other[0] = 0x12
	group[1].Txn.Sender = other
	expectSettleRejected(t, VerifySettleGroup(regrouped(t, group), spec), "payer.sender")
}

func TestVerifySettleGroup_WrongAppID(t *testing.T) {
	group, spec := buildValidSettleGroup(t)
	group[0].Txn.ApplicationID = types.AppIndex(spec.AppID + 1)
	expectSettleRejected(t, VerifySettleGroup(regrouped(t, group), spec), "operator.appId")
}

func TestVerifySettleGroup_WrongSelector(t *testing.T) {
	group, spec := buildValidSettleGroup(t)
	group[0].Txn.ApplicationArgs[0] = []byte{0, 0, 0, 0}
	expectSettleRejected(t, VerifySettleGroup(regrouped(t, group), spec), "operator.selector")
}

// A node signs a receipt for X but bakes Y (a higher amount) into the group.
// The amount arg no longer matches the receipt-derived spec → conviction.
func TestVerifySettleGroup_AmountInflation(t *testing.T) {
	group, spec := buildValidSettleGroup(t)
	group[0].Txn.ApplicationArgs[2] = abiUint64(spec.AmountCharged + 10_000)
	expectSettleRejected(t, VerifySettleGroup(regrouped(t, group), spec), "operator.amountCharged")
}

func TestVerifySettleGroup_DigestMismatch(t *testing.T) {
	group, spec := buildValidSettleGroup(t)
	var other [32]byte
	other[0] = 0xEE
	group[0].Txn.ApplicationArgs[3] = abiByteSlice(other[:])
	expectSettleRejected(t, VerifySettleGroup(regrouped(t, group), spec), "operator.receiptDigest")
}

func TestVerifySettleGroup_TicketIDMismatch(t *testing.T) {
	group, spec := buildValidSettleGroup(t)
	group[0].Txn.ApplicationArgs[1][2] ^= 0xFF
	expectSettleRejected(t, VerifySettleGroup(regrouped(t, group), spec), "operator.ticketId")
}

func TestVerifySettleGroup_AsOperatorFlipped(t *testing.T) {
	group, spec := buildValidSettleGroup(t)
	// Operator half claiming asOperator=false.
	group[0].Txn.ApplicationArgs[11] = []byte{settleAsOperatorFalse}
	expectSettleRejected(t, VerifySettleGroup(regrouped(t, group), spec), "operator.asOperator")
}

func TestVerifySettleGroup_GroupIDMismatch(t *testing.T) {
	group, spec := buildValidSettleGroup(t)
	group[1].Txn.Group = types.Digest{}
	expectSettleRejected(t, VerifySettleGroup(group, spec), "group.id")
}

func TestVerifySettleGroup_WrongSize(t *testing.T) {
	group, spec := buildValidSettleGroup(t)
	expectSettleRejected(t, VerifySettleGroup(group[:1], spec), "group.size")
}

// --- helpers ---

// regrouped recomputes and restamps the group id after a test has mutated a
// member, so the verifier's group-id recompute passes and the rejection comes
// from the one field the test changed. Without it every single-field mutation
// case would be refused by the group-id check first, and would keep passing
// even if the check it names were deleted.
func regrouped(t *testing.T, group []types.SignedTxn) []types.SignedTxn {
	t.Helper()
	txns := make([]types.Transaction, len(group))
	for i := range group {
		txns[i] = group[i].Txn
		txns[i].Group = types.Digest{}
	}
	gid, err := crypto.ComputeGroupID(txns)
	if err != nil {
		t.Fatal(err)
	}
	for i := range group {
		group[i].Txn.Group = gid
	}
	return group
}

func genKey(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var a types.Address
	copy(a[:], pub)
	return priv, pub, a.String()
}

func abiByteSlice(b []byte) []byte {
	out := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(out[:2], uint16(len(b)))
	copy(out[2:], b)
	return out
}

func abiUint64(n uint64) []byte {
	var out [8]byte
	binary.BigEndian.PutUint64(out[:], n)
	return out[:]
}
