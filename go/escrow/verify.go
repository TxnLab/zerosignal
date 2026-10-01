/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package escrow

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// groupCommitsToMembers reports whether gid is the group id of exactly these
// members. Sharing a non-zero gid only proves the members agree with each
// other; algod admits a group only when its gid hashes the txids actually
// submitted, so without this a node could show the payer an honest sibling
// while the gid — which the payer's signature covers — commits to a
// different one the node holds (a ClearState open(), say). A payer signature
// that escapes, e.g. via a failed submit the algod provider saw, would then
// be usable with the sibling the payer never checked.
func groupCommitsToMembers(gid types.Digest, group []types.SignedTxn) (bool, error) {
	txns := make([]types.Transaction, len(group))
	for i, stx := range group {
		txns[i] = stx.Txn
		txns[i].Group = types.Digest{}
	}
	want, err := crypto.ComputeGroupID(txns)
	if err != nil {
		return false, err
	}
	return want == gid, nil
}

// OpenAppCallSpec captures the fields a verifier needs to check JUST
// the escrow.open() application call — independent of the payment
// sibling. Used by the node's mempool-admission path: algod's mempool
// will not admit an open() app-call unless the contract's TEAL (which
// checks the gtxn[0] USDC AssetTransfer's shape; see VerifyOpenAppCall)
// approves the entire group, so the node can rely on the contract for
// those payment-side invariants and only verify that the app call is for
// *our* app, has the open() selector, and carries the expected ticket
// id / operator id / node id / payer / max price.
type OpenAppCallSpec struct {
	// AppID is the deployed ZeroSignalEscrow application id.
	AppID uint64
	// TicketIDRaw is the 16-byte raw ticket id (NOT base64). The
	// contract's ABI takes raw bytes; the envelope/wire form is the
	// base64 of these same 16 bytes.
	TicketIDRaw []byte
	// OperatorID is the expected operator id; the contract resolves the
	// owner (payout) address from the operator box using this id.
	OperatorID uint64
	// NodeID is the expected node id (within OperatorID). The contract
	// resolves the node's signing key from the node box using this id, so
	// the node only needs to confirm the open() call names *its* (op, node).
	NodeID uint64
	// PayerAddr is the expected ticket.payer — the contract pins this
	// to the gtxn[0] usdcPayment sender, and binds rec.payer to it.
	PayerAddr types.Address
	// MaxPrice is the expected ticket.max_price (microUSDC).
	MaxPrice uint64
	// NodeSigningAddr is the serving node's signing address. In the
	// consensus-verified design, the open() AppCall's (gtxn[1] in the
	// 2-tx group) sender == this address is what authenticates the node's
	// commitment to the args; the contract requires it via
	// assert(Txn.sender === nodeRec.signing).
	NodeSigningAddr types.Address
}

// OpenGroupSpec captures what a verifier needs to check the full
// 2-tx open group (usdcPayment + escrow.open). The ticket-box MBR is no
// longer a per-turn ALGO leg — it is drawn from the payer's prepaid pool
// at open(). Used by composers as a defense-in-depth sanity check on the
// group they just built, before submit.
type OpenGroupSpec struct {
	// AppID is the deployed ZeroSignalEscrow application id.
	AppID uint64
	// AppAddress is the application account — the receiver of the USDC
	// usdcPayment.
	AppAddress types.Address
	// TicketIDRaw is the 16-byte raw ticket id (NOT base64). The
	// contract's ABI takes raw bytes; the envelope/wire form is the
	// base64 of these same 16 bytes.
	TicketIDRaw []byte
	// OperatorID is the expected operator id.
	OperatorID uint64
	// NodeID is the expected node id (within OperatorID).
	NodeID uint64
	// MaxPrice is the expected ticket.max_price (microUSDC). Both the
	// app-call's maxPrice arg and the usdcPayment's assetAmount must
	// equal this value.
	MaxPrice uint64
	// TicketMbr is the box MBR each ticket reserves, read from the
	// deployed contract via mbrForTicket(). No longer verified on the open
	// group (there is no feePayment leg) — retained because callers use it
	// to size depositMbr / withdrawMbr pool headroom.
	TicketMbr uint64
	// UsdcAssetID is the asset the usdcPayment must transfer. Read
	// from the contract's `usdcAssetId` global state at startup.
	UsdcAssetID uint64
	// NodeSigningAddr is the expected gtxn[1] (open AppCall) sender. The
	// serving node's Algorand-consensus signature on gtxn[1] is what
	// authenticates the args under this design; the verifier confirms the
	// sender matches the expected node-signing address.
	NodeSigningAddr types.Address
	// PayerAddr is the expected gtxn[0] (usdcPayment) sender — the address
	// the contract binds the ticket's payer field to.
	PayerAddr types.Address
	// ExpiresAt is the expected expiresAt ABI arg (unix seconds) — the
	// signed ticket's expires_at. Checked here (NOT in VerifyOpenAppCall):
	// the node's admission path skips it because the node authored the arg,
	// but the payer did not — a divergence from the ticket would shift the
	// settlement/refund windows away from what the payer agreed to.
	ExpiresAt uint64
	// SettlementGraceSeconds is the expected settlementGraceSeconds ABI arg.
	// The reference node always passes 0 (the contract's `grace` default
	// applies), and payer-side callers pin 0 here: a node-authored non-zero
	// grace would silently extend the payer's refundInactive deadline
	// D = expires_at + grace beyond what the payer's refund logic computes.
	SettlementGraceSeconds uint64
}

// VerifyOpenAppCall checks that stx is a ZeroSignalEscrow.open() application
// call matching spec — independent of the payment sibling. Returns nil
// on match, a structured error otherwise. The checks performed, in
// order:
//
//  1. Type is an Application Call.
//  2. ApplicationID == spec.AppID.
//  3. Sender == spec.NodeSigningAddr — the consensus-verified
//     authentication that authorises the args.
//  4. First application arg is the open() method selector.
//  5. ABI-encoded ticketId / operatorId / nodeId / payerAddr / maxPrice
//     args (positions 1..5 after the selector) match spec.
//
// The payment sibling is intentionally NOT checked here. The group is
// [usdcPayment, open()], and open()'s TEAL checks gtxn[0]'s receiver, asset,
// amount (== maxPrice), fee (== 0) and the absence of rekey / close-to /
// asset-sender; algod's mempool admission runs that TEAL before accepting the
// app call, so an open() in the pool implies the contract has already
// approved those. The payer still runs VerifyOpenGroup before signing: the
// TEAL only runs if gtxn[1] really is open(), and it leaves note and lease
// unchecked.
func VerifyOpenAppCall(stx types.SignedTxn, spec OpenAppCallSpec) error {
	app := stx.Txn
	if app.Type != types.ApplicationCallTx {
		return fmt.Errorf("escrow: open app call type = %q, want %q", app.Type, types.ApplicationCallTx)
	}
	if uint64(app.ApplicationID) != spec.AppID {
		return fmt.Errorf("escrow: open app call app_id = %d, want %d", app.ApplicationID, spec.AppID)
	}
	if app.Sender != spec.NodeSigningAddr {
		return fmt.Errorf("escrow: open app call sender = %s, want node_signing %s", app.Sender, spec.NodeSigningAddr)
	}
	if len(app.ApplicationArgs) < 1 {
		return errors.New("escrow: open app call missing application args")
	}
	openSelector, err := MethodSelector("open")
	if err != nil {
		return fmt.Errorf("escrow: load open selector: %w", err)
	}
	if !bytes.Equal(app.ApplicationArgs[0], openSelector) {
		return fmt.Errorf("escrow: open app call selector = %x, want %x", app.ApplicationArgs[0], openSelector)
	}

	// Positions of the non-txn ABI args in ApplicationArgs (the first
	// slot is the selector, then the 7 non-reference args from the
	// open() signature — see ZeroSignalEscrow.algo.ts):
	//   0: selector
	//   1: ticketId (byte[])
	//   2: operatorId (uint64)
	//   3: nodeId (uint64)
	//   4: payerAddr (address)
	//   5: maxPrice (uint64)
	//   6: expiresAt (uint64)
	//   7: settlementGraceSeconds (uint64)
	const (
		argTicketID   = 1
		argOperatorID = 2
		argNodeID     = 3
		argPayerAddr  = 4
		argMaxPrice   = 5
	)
	if len(app.ApplicationArgs) <= argMaxPrice {
		return fmt.Errorf("escrow: open app call has %d args, want ≥ %d", len(app.ApplicationArgs), argMaxPrice+1)
	}
	if err := checkABIByteSlice(app.ApplicationArgs[argTicketID], spec.TicketIDRaw, "ticketId"); err != nil {
		return err
	}
	if err := checkABIUint64(app.ApplicationArgs[argOperatorID], spec.OperatorID, "operatorId"); err != nil {
		return err
	}
	if err := checkABIUint64(app.ApplicationArgs[argNodeID], spec.NodeID, "nodeId"); err != nil {
		return err
	}
	if err := checkABIAddress(app.ApplicationArgs[argPayerAddr], spec.PayerAddr, "payerAddr"); err != nil {
		return err
	}
	if err := checkABIUint64(app.ApplicationArgs[argMaxPrice], spec.MaxPrice, "maxPrice"); err != nil {
		return err
	}
	return nil
}

// VerifyOpenGroup checks that group is a well-formed ZeroSignalEscrow.open
// call matching spec. Returns nil on match, a structured error
// otherwise. The checks performed, in order:
//
//  1. Group size == 2.
//  2. Both txns share a non-zero group id, and it is the group id
//     recomputed over these two members.
//  3. group[0] is an AssetTransfer with no rekey_to, asset_close_to,
//     asset_sender, close_remainder_to, note or lease, and fee == 0; sender ==
//     spec.PayerAddr; assetReceiver == spec.AppAddress; xferAsset ==
//     spec.UsdcAssetID; amount == spec.MaxPrice.
//  4. group[1] passes VerifyOpenAppCall against the matching subset
//     of spec — including sender == spec.NodeSigningAddr — and is NoOp.
//  5. group[1]'s expiresAt / settlementGraceSeconds ABI args match
//     spec.ExpiresAt / spec.SettlementGraceSeconds — payer-side-only
//     checks the node's own admission path deliberately skips (it
//     authored those args); see the field docs on OpenGroupSpec.
//
// There is no longer an ALGO feePayment leg — the ticket-box MBR is
// drawn from the payer's prepaid pool at open() (openTickets++), so the
// group is [usdcPayment, open()]. Used by composers as a sanity check on
// the group they just built. The node can also use VerifyOpenAppCall
// directly against the pending app-call (the contract's TEAL covers the
// fund-moving fields of the payment side, though not note or lease).
func VerifyOpenGroup(group []types.SignedTxn, spec OpenGroupSpec) error {
	if len(group) != 2 {
		return fmt.Errorf("escrow: open group size = %d, want 2", len(group))
	}

	gid := group[0].Txn.Group
	if gid == (types.Digest{}) {
		return errors.New("escrow: open group missing group id")
	}
	if group[1].Txn.Group != gid {
		return errors.New("escrow: open group: group id mismatch across members")
	}
	if ok, err := groupCommitsToMembers(gid, group); err != nil {
		return fmt.Errorf("escrow: open group: recompute group id: %w", err)
	} else if !ok {
		return errors.New("escrow: open group id does not commit to its members")
	}

	// Member 0: usdcPayment (AssetTransfer), payer-signed, fee=0.
	axfer := group[0].Txn
	if axfer.Type != types.AssetTransferTx {
		return fmt.Errorf("escrow: open[0] type = %q, want %q", axfer.Type, types.AssetTransferTx)
	}
	// Shape guards on the one txn the payer signs. Each one turns the payer's
	// signature into something other than "move max_price USDC into escrow".
	// open()'s TEAL also rejects rekey, asset close-to, asset sender and fee,
	// but only when gtxn[1] really is open() on an app built with those
	// asserts, so these guards are the defense and the TEAL the backstop: a
	// rekey hands the payer's account to whoever the node names; an asset close-to
	// sweeps the payer's entire remaining USDC holding to that address; an
	// asset sender turns the transfer into a clawback; a non-zero fee drains
	// payer ALGO the node's gtxn[1] was supposed to pool. close_remainder_to
	// is a payment-only field algod refuses on an axfer anyway, but it would
	// close out the payer's whole ALGO balance if that ever changed, so it is
	// pinned too. Note and lease move no funds, but both are node-chosen bytes
	// published on chain under the payer's signature (a note can carry up to
	// 1KB the payer never saw), so the signed txn is pinned to the transfer and
	// nothing else. The honest composer (ComposeOpenGroup) sets none of these.
	if !axfer.RekeyTo.IsZero() {
		return fmt.Errorf("escrow: open[0] rekey_to = %s, want none (account-takeover attempt)", axfer.RekeyTo)
	}
	if !axfer.AssetCloseTo.IsZero() {
		return fmt.Errorf("escrow: open[0] asset_close_to = %s, want none (balance-sweep attempt)", axfer.AssetCloseTo)
	}
	if !axfer.AssetSender.IsZero() {
		return fmt.Errorf("escrow: open[0] asset_sender = %s, want none (clawback form)", axfer.AssetSender)
	}
	if !axfer.CloseRemainderTo.IsZero() {
		return fmt.Errorf("escrow: open[0] close_remainder_to = %s, want none", axfer.CloseRemainderTo)
	}
	if axfer.Fee != 0 {
		return fmt.Errorf("escrow: open[0] fee = %d, want 0", axfer.Fee)
	}
	if len(axfer.Note) != 0 {
		return fmt.Errorf("escrow: open[0] note = %d bytes, want none", len(axfer.Note))
	}
	if axfer.Lease != ([32]byte{}) {
		return fmt.Errorf("escrow: open[0] lease = %x, want none", axfer.Lease)
	}
	if axfer.Sender != spec.PayerAddr {
		return fmt.Errorf("escrow: open[0] sender = %s, want payer %s", axfer.Sender, spec.PayerAddr)
	}
	if axfer.AssetReceiver != spec.AppAddress {
		return fmt.Errorf("escrow: open[0] asset_receiver = %s, want app %s", axfer.AssetReceiver, spec.AppAddress)
	}
	if uint64(axfer.XferAsset) != spec.UsdcAssetID {
		return fmt.Errorf("escrow: open[0] xfer_asset = %d, want usdc = %d", axfer.XferAsset, spec.UsdcAssetID)
	}
	if axfer.AssetAmount != spec.MaxPrice {
		return fmt.Errorf("escrow: open[0] asset_amount = %d, want max_price = %d", axfer.AssetAmount, spec.MaxPrice)
	}

	// Member 1: Application call. Delegate to VerifyOpenAppCall so the
	// app-call rule lives in one place.
	if err := VerifyOpenAppCall(group[1], OpenAppCallSpec{
		AppID:           spec.AppID,
		TicketIDRaw:     spec.TicketIDRaw,
		OperatorID:      spec.OperatorID,
		NodeID:          spec.NodeID,
		PayerAddr:       spec.PayerAddr,
		MaxPrice:        spec.MaxPrice,
		NodeSigningAddr: spec.NodeSigningAddr,
	}); err != nil {
		return err
	}
	// ClearState runs the clear program instead of approval, so open() never
	// executes: the group still commits and the payer's USDC lands in the app
	// account with no ticket box behind it, hence nothing to refund. Any
	// account can opt in (depositMbr allows OptIn), so the node's signing key
	// can set this up. Payer-side only: on the node's own admission path the
	// node authored the call.
	if oc := group[1].Txn.OnCompletion; oc != types.NoOpOC {
		return fmt.Errorf("escrow: open[1] on_complete = %d, want NoOp (%d)", oc, types.NoOpOC)
	}

	// Window args (positions 6/7 after the selector — see the arg layout in
	// VerifyOpenAppCall). Checked only on the full-group (payer-side) path:
	// the node's admission verifier skips them because the node authored and
	// consensus-signed the very txn it is checking, but for the payer these
	// are counterparty-authored — expiresAt must match the signed ticket and
	// settlementGraceSeconds is pinned (0 from reference callers) so the
	// refundInactive deadline D = expires_at + grace is what the payer's
	// refund logic computes.
	const (
		argExpiresAt       = 6
		argSettlementGrace = 7
	)
	args := group[1].Txn.ApplicationArgs
	if len(args) <= argSettlementGrace {
		return fmt.Errorf("escrow: open app call has %d args, want ≥ %d", len(args), argSettlementGrace+1)
	}
	if err := checkABIUint64(args[argExpiresAt], spec.ExpiresAt, "expiresAt"); err != nil {
		return err
	}
	return checkABIUint64(args[argSettlementGrace], spec.SettlementGraceSeconds, "settlementGraceSeconds")
}

// checkABIByteSlice verifies that raw equals ABI-encoded want where
// want is a variable-length byte slice. ABI byte[] encoding is
// uint16-big-endian length prefix + bytes.
func checkABIByteSlice(raw, want []byte, field string) error {
	if len(raw) < 2 {
		return fmt.Errorf("escrow: open[1] %s: %d-byte arg, want length-prefixed", field, len(raw))
	}
	gotLen := binary.BigEndian.Uint16(raw[:2])
	if int(gotLen) != len(raw)-2 {
		return fmt.Errorf("escrow: open[1] %s: length prefix %d, payload %d", field, gotLen, len(raw)-2)
	}
	if int(gotLen) != len(want) {
		return fmt.Errorf("escrow: open[1] %s: len prefix %d, want %d", field, gotLen, len(want))
	}
	if !bytes.Equal(raw[2:], want) {
		return fmt.Errorf("escrow: open[1] %s: value mismatch (got %x want %x)", field, raw[2:], want)
	}
	return nil
}

// checkABIUint64 verifies an 8-byte big-endian uint64 arg equals want.
func checkABIUint64(raw []byte, want uint64, field string) error {
	if len(raw) != 8 {
		return fmt.Errorf("escrow: open[1] %s: %d-byte uint64, want 8", field, len(raw))
	}
	got := binary.BigEndian.Uint64(raw)
	if got != want {
		return fmt.Errorf("escrow: open[1] %s: %d, want %d", field, got, want)
	}
	return nil
}

// checkABIAddress verifies a 32-byte address arg equals want. ABI
// `address` encoding is the raw 32-byte public key with no length
// prefix.
func checkABIAddress(raw []byte, want types.Address, field string) error {
	if len(raw) != 32 {
		return fmt.Errorf("escrow: open[1] %s: %d-byte address, want 32", field, len(raw))
	}
	var got types.Address
	copy(got[:], raw)
	if got != want {
		return fmt.Errorf("escrow: open[1] %s: %s, want %s", field, got, want)
	}
	return nil
}

// ---------------------------------------------------------------------
// Settle-group verification (payer-ack pre-sign guard)
//
// The atomic settle group is authored entirely by the node: it signs
// gtxn[0] (operator first-half) and hands the still-unsigned gtxn[1]
// (payer ack) template. The payer/proxy then signs gtxn[1] with the
// payer key and submits. Because the payer's own signature is what
// authorises gtxn[1], the signer MUST validate the node-composed group
// before applying it — otherwise the node can bake fraud into the half
// the payer blindly signs. Two attack classes matter and are checked
// below alongside the nine co-signed billing values:
//
//   - RekeyTo on either member (especially the payer's gtxn[1]) sets the
//     payer account's AuthAddr to the operator → full account takeover.
//     settle()'s TEAL also rejects a rekey, but only when gtxn[1] really is
//     a settle() call on an app built with that assert; a node can carry
//     the rekey on any other txn type, so this check stays the defense.
//   - OnCompletion != NoOp. ClearState runs the clear-state program
//     instead of `approval`, bypassing every contract assert to wipe the
//     payer's local MBR-pool accounting, and nothing on chain can refuse
//     it. CloseOut does run `approval`, which rejects it on settle() and
//     on closeDeposit while a ticket is open, but it is still no settle.
//
// A legitimate settle never rekeys, always uses NoOp, and pools its fee
// on gtxn[0] (payer half fee = 0). So any rejection here is the node
// contradicting itself (it signed a receipt describing an honest settle,
// then handed a malformed group), never honest desync — callers treat a
// SettleGroupRejectedError as proven operator misbehaviour: refuse the
// atomic path, fall back to the standalone receipt-sourced ack, and
// locally downrank the node. Mirrors the client's verifySettleGroup
// (client/src/algorand/escrow.ts).

// SettleGroupRejectedError is returned (as a typed error) by
// VerifySettleGroup / SubmitPresignedSettleGroup when the node-composed
// settle group fails a structural, shape, or value check before the payer
// signs its ack half. Field is a stable machine slug (e.g. "payer.rekeyTo")
// callers can branch on; Detail is the human-readable message. Because the
// node authored both halves and its own receipt, every rejection is
// operator self-contradiction — safe to hard-refuse and downrank.
type SettleGroupRejectedError struct {
	Field  string
	Detail string
}

func (e *SettleGroupRejectedError) Error() string {
	return fmt.Sprintf("escrow: settle group rejected [%s]: %s", e.Field, e.Detail)
}

// SettleGroupSpec captures what VerifySettleGroup needs to check the 2-tx
// atomic settle group. Every value is sourced by the caller from the
// operator's signature-verified receipt (and the chain-resolved operator
// snapshot / config) — never from the group itself. ReceiptDigest is
// ticket.ReceiptSigDigest(receipt); the nine billing values are the
// receipt's authoritative counts/timings, which the contract co-signs
// across both halves (a second-half mismatch freezes the ticket).
type SettleGroupSpec struct {
	// AppID is the deployed ZeroSignalEscrow application id — from config,
	// never read off the group.
	AppID uint64
	// TicketIDRaw is the 16-byte raw ticket id (NOT base64).
	TicketIDRaw []byte
	// The nine co-signed billing values, in ABI-arg order after the
	// selector + ticketId.
	AmountCharged      uint64
	ReceiptDigest      [32]byte
	TtftMs             uint64
	DecodeMs           uint64
	InputCount         uint64
	OutputCount        uint64
	OutputUsageType    uint64
	AuxOutputUsageType uint64
	AuxOutputCount     uint64
	// PayerAddr / OperatorSigningAddr are the expected senders of gtxn[1] /
	// gtxn[0] respectively.
	PayerAddr           types.Address
	OperatorSigningAddr types.Address
}

// ABI bool encodes to a single byte: 0x80 true, 0x00 false. The settle()
// asOperator arg is true on the operator half, false on the payer ack.
const (
	settleAsOperatorTrue  = 0x80
	settleAsOperatorFalse = 0x00
	// settleArgCount is selector + 11 ABI args (the last is asOperator).
	settleArgCount = 12
)

// VerifySettleGroup checks that group is a well-formed
// ZeroSignalEscrow.settle atomic pair matching spec. Returns nil on
// match, a *SettleGroupRejectedError otherwise. Checks, in order:
//
//  1. Group size == 2, both members share a non-zero group id, and it is
//     the group id recomputed over these two members.
//  2. gtxn[0] (operator first-half): appl, our app, no rekey, NoOp,
//     sender == OperatorSigningAddr, selector == settle, all nine values +
//     ticket id match spec, asOperator == true.
//  3. gtxn[1] (payer ack): same, plus fee == 0, sender == PayerAddr,
//     asOperator == false.
//
// gtxn[0]'s fee is deliberately NOT pinned — the operator funds and sizes
// it to the disbursement inners its settle fires; a too-low fee just fails
// admission (the operator eats that) and can't harm the payer.
func VerifySettleGroup(group []types.SignedTxn, spec SettleGroupSpec) error {
	if len(group) != 2 {
		return &SettleGroupRejectedError{Field: "group.size", Detail: fmt.Sprintf("settle group size = %d, want 2", len(group))}
	}
	gid := group[0].Txn.Group
	if gid == (types.Digest{}) {
		return &SettleGroupRejectedError{Field: "group.id", Detail: "settle group missing group id"}
	}
	if group[1].Txn.Group != gid {
		return &SettleGroupRejectedError{Field: "group.id", Detail: "settle group: group id mismatch across members"}
	}
	if ok, err := groupCommitsToMembers(gid, group); err != nil {
		return &SettleGroupRejectedError{Field: "group.id", Detail: fmt.Sprintf("settle group: recompute group id: %v", err)}
	} else if !ok {
		return &SettleGroupRejectedError{Field: "group.id", Detail: "settle group id does not commit to its members"}
	}
	if err := verifySettleMember(group[0].Txn, spec, "operator", spec.OperatorSigningAddr, settleAsOperatorTrue, false); err != nil {
		return err
	}
	if err := verifySettleMember(group[1].Txn, spec, "payer", spec.PayerAddr, settleAsOperatorFalse, true); err != nil {
		return err
	}
	return nil
}

// verifySettleMember checks one member of the settle group. sender is the
// expected txn sender, asOperator the expected value of the asOperator ABI
// arg (0x80/0x00), and feeMustBeZero pins fee == 0 (payer half only — the
// operator pools the group fee on gtxn[0]).
func verifySettleMember(txn types.Transaction, spec SettleGroupSpec, role string, sender types.Address, asOperator byte, feeMustBeZero bool) *SettleGroupRejectedError {
	tag := "settle[" + role + "]"
	reject := func(field, msg string) *SettleGroupRejectedError {
		return &SettleGroupRejectedError{Field: role + "." + field, Detail: tag + " " + msg}
	}
	if txn.Type != types.ApplicationCallTx {
		return reject("type", fmt.Sprintf("type = %q, want %q", txn.Type, types.ApplicationCallTx))
	}
	if uint64(txn.ApplicationID) != spec.AppID {
		return reject("appId", fmt.Sprintf("app_id = %d, want %d", txn.ApplicationID, spec.AppID))
	}
	// Shape guards — reject before any signature is applied. A rekeyTo
	// hands the payer's account to the operator; a non-NoOp onComplete
	// (ClearState) bypasses the approval program's asserts.
	if !txn.RekeyTo.IsZero() {
		return reject("rekeyTo", fmt.Sprintf("rekeyTo = %s, want none (account-takeover attempt)", txn.RekeyTo))
	}
	if txn.OnCompletion != types.NoOpOC {
		return reject("onComplete", fmt.Sprintf("onComplete = %d, want NoOp (%d)", txn.OnCompletion, types.NoOpOC))
	}
	if txn.Sender != sender {
		return reject("sender", fmt.Sprintf("sender = %s, want %s", txn.Sender, sender))
	}
	if feeMustBeZero && txn.Fee != 0 {
		return reject("fee", fmt.Sprintf("fee = %d, want 0", txn.Fee))
	}
	args := txn.ApplicationArgs
	if len(args) < settleArgCount {
		return reject("args", fmt.Sprintf("has %d args, want >= %d", len(args), settleArgCount))
	}
	settleSelector, err := MethodSelector("settle")
	if err != nil {
		return reject("selector", fmt.Sprintf("load settle selector: %v", err))
	}
	if !bytes.Equal(args[0], settleSelector) {
		return reject("selector", fmt.Sprintf("selector = %x, want %x", args[0], settleSelector))
	}
	// ABI-arg layout after the selector mirrors settle():
	//   [1] ticketId (byte[])   [2] amountCharged   [3] receiptDigest (byte[])
	//   [4] ttftMs  [5] decodeMs [6] inputCount      [7] outputCount
	//   [8] outputUsageType [9] auxOutputUsageType [10] auxOutputCount
	//   [11] asOperator (bool, 1 byte)
	if m := settleByteSliceArg(args[1], spec.TicketIDRaw); m != "" {
		return reject("ticketId", "ticketId "+m)
	}
	if m := settleUint64Arg(args[2], spec.AmountCharged); m != "" {
		return reject("amountCharged", "amountCharged "+m)
	}
	if m := settleByteSliceArg(args[3], spec.ReceiptDigest[:]); m != "" {
		return reject("receiptDigest", "receiptDigest "+m)
	}
	if m := settleUint64Arg(args[4], spec.TtftMs); m != "" {
		return reject("ttftMs", "ttftMs "+m)
	}
	if m := settleUint64Arg(args[5], spec.DecodeMs); m != "" {
		return reject("decodeMs", "decodeMs "+m)
	}
	if m := settleUint64Arg(args[6], spec.InputCount); m != "" {
		return reject("inputCount", "inputCount "+m)
	}
	if m := settleUint64Arg(args[7], spec.OutputCount); m != "" {
		return reject("outputCount", "outputCount "+m)
	}
	if m := settleUint64Arg(args[8], spec.OutputUsageType); m != "" {
		return reject("outputUsageType", "outputUsageType "+m)
	}
	if m := settleUint64Arg(args[9], spec.AuxOutputUsageType); m != "" {
		return reject("auxOutputUsageType", "auxOutputUsageType "+m)
	}
	if m := settleUint64Arg(args[10], spec.AuxOutputCount); m != "" {
		return reject("auxOutputCount", "auxOutputCount "+m)
	}
	if asOp := args[11]; len(asOp) != 1 || asOp[0] != asOperator {
		return reject("asOperator", fmt.Sprintf("asOperator = %x, want 0x%02x", asOp, asOperator))
	}
	return nil
}

// settleUint64Arg returns "" if raw is an 8-byte big-endian uint64 equal
// to want, else a human-readable mismatch fragment. Decodes by shape (not
// abi.Type.Decode) — the settle args are all fixed-width.
func settleUint64Arg(raw []byte, want uint64) string {
	if len(raw) != 8 {
		return fmt.Sprintf("= %d-byte uint64, want 8", len(raw))
	}
	if got := binary.BigEndian.Uint64(raw); got != want {
		return fmt.Sprintf("= %d, want %d", got, want)
	}
	return ""
}

// settleByteSliceArg returns "" if raw is an ABI byte[] (uint16-BE length
// prefix + bytes) equal to want, else a mismatch fragment.
func settleByteSliceArg(raw, want []byte) string {
	if len(raw) < 2 {
		return fmt.Sprintf("= %d-byte arg, want length-prefixed", len(raw))
	}
	gotLen := int(binary.BigEndian.Uint16(raw[:2]))
	if gotLen != len(raw)-2 {
		return fmt.Sprintf("length prefix %d, payload %d", gotLen, len(raw)-2)
	}
	if gotLen != len(want) || !bytes.Equal(raw[2:], want) {
		return fmt.Sprintf("value mismatch (got %x want %x)", raw[2:], want)
	}
	return ""
}
