/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"errors"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/TxnLab/zerosignal/go/escrow"
)

// EscrowChain is the escrow app as the Wallet reaches it, the Go counterpart
// of the TS SDK's EscrowChain (sdk/src/wallet.ts). The Wallet touches the
// chain only through it, so a test fakes the whole surface and nothing else
// in the wallet reads *escrow.Client. NewEscrowChain binds it to one. Each
// call that acts as the payer signs with the signer it is handed.
//
// The two differ in shape where the escrow client already did the work: the
// implementation here stamps the deployment's half of the open spec and
// verifies and signs the node's groups in typed calls, where the TS wallet
// builds the spec and sends raw bytes; and the settle lookup is the chain's
// here, the handle's in TS.
type EscrowChain interface {
	// TicketMBR is the per-ticket box MBR (µALGO) the pool backs per slot.
	// 0 means RefreshConfig hasn't loaded it yet.
	TicketMBR() uint64
	// FreeQuotaMbrDueFor is the free-quota box MBR this payer's pool STILL has
	// to cover: the full term while they have no quota box, 0 once open() has
	// created one (it's charged exactly once and never refunded). Exactness
	// matters for a payer who opens a free ticket — a flat term would leave them
	// carrying an idle slice of ALGO forever after the charge could no longer
	// recur. It buys nothing for a paid-only payer, who never gets a box and so
	// keeps the term due indefinitely (see Wallet.quotaMbrDue). Fails open (full
	// term) on a read error.
	FreeQuotaMbrDueFor(ctx context.Context, payerAddr string) uint64
	// ReadPayerDeposit returns the payer's pool state (AlgoBalance on
	// deposit + live OpenTickets count).
	ReadPayerDeposit(ctx context.Context, payerAddr string) (escrow.PayerDeposit, error)
	// IsPayerOptedIn distinguishes "no pool yet" (OptIn on first deposit)
	// from "opted in with a drained balance" (NoOp top-up).
	IsPayerOptedIn(ctx context.Context, payerAddr string) (bool, error)
	// SpendableMicroAlgos is the payer's withdrawable ALGO (Amount −
	// MinBalance): the affordability ceiling for the deposit Payment + fees.
	SpendableMicroAlgos(ctx context.Context, payerAddr string) (uint64, error)
	// MinTxnFee is the network's per-txn minimum fee (µALGO), used to size
	// the deposit group's pooled fee for the affordability check.
	MinTxnFee(ctx context.Context) (uint64, error)
	// ComposeDepositMbr funds (or tops up) the pool; optIn carries the
	// OnComplete=OptIn on the first deposit.
	ComposeDepositMbr(ctx context.Context, amount uint64, optIn bool, signer transaction.TransactionSigner, signerAddr string) (escrow.CallResult, error)
	// ComposeWithdrawMbr reclaims unreserved pool balance; the contract caps
	// it at what no ticket reserves.
	ComposeWithdrawMbr(ctx context.Context, amount uint64, signer transaction.TransactionSigner, signerAddr string) (escrow.CallResult, error)
	// ComposeCloseDeposit closes the pool and opts out; it reverts while any
	// ticket is live.
	ComposeCloseDeposit(ctx context.Context, signer transaction.TransactionSigner, signerAddr string) (escrow.CallResult, error)

	// Config is the deployment's settings as RefreshConfig loaded them.
	Config() EscrowChainConfig
	// ProtocolFeeBps reads the contract's protocolFeeBps global.
	ProtocolFeeBps(ctx context.Context) (uint64, error)

	// SubmitPresignedOpenGroup verifies the node-delivered 2-tx open group
	// against spec (every field pinned to the signature-verified ticket —
	// the group is counterparty-composed, so this runs BEFORE the payer
	// signs gtxn[0] = usdcPayment; gtxn[1] = open() AppCall is
	// operator-signed), then completes + broadcasts it. The implementation
	// stamps the deployment's slice of spec (app, USDC asset, ticket MBR).
	SubmitPresignedOpenGroup(ctx context.Context, group []types.SignedTxn, payerSigner transaction.TransactionSigner, spec escrow.OpenGroupSpec) (escrow.OpenResult, error)
	// CompletePresignedOpenGroup runs the same verification and signature but
	// broadcasts nothing, for a node that submits the group itself.
	CompletePresignedOpenGroup(group []types.SignedTxn, payerSigner transaction.TransactionSigner, spec escrow.OpenGroupSpec) (escrow.OpenResult, error)

	// SubmitPresignedSettleGroup verifies the node's settle group against
	// spec, signs the payer's ack and broadcasts the group.
	SubmitPresignedSettleGroup(ctx context.Context, group []types.SignedTxn, payerSigner transaction.TransactionSigner, spec escrow.SettleGroupSpec) (escrow.CallResult, error)
	// CompletePresignedSettleGroup verifies and signs the same way but
	// broadcasts nothing, returning the completed group encoded for the node.
	CompletePresignedSettleGroup(group []types.SignedTxn, payerSigner transaction.TransactionSigner, spec escrow.SettleGroupSpec) (escrow.CallResult, string, error)
	// SubmitSettleGroup broadcasts a settle group already completed. A revert
	// commits nothing, so the same group can be sent again.
	SubmitSettleGroup(ctx context.Context, group []types.SignedTxn) error
	// SettleOutcome is where a submitted settle transaction stands.
	SettleOutcome(ctx context.Context, txid string) (SettleOutcome, error)

	ComposeSettleStandalone(ctx context.Context, args escrow.SettleArgs, signer transaction.TransactionSigner, signerAddr string) (escrow.CallResult, error)
	ComposeProtest(ctx context.Context, args escrow.ProtestArgs, payerSigner transaction.TransactionSigner, payerAddr string) (escrow.CallResult, error)
	ComposeRefundInactive(ctx context.Context, args escrow.RefundInactiveArgs, callerSigner transaction.TransactionSigner, callerAddr string) (escrow.CallResult, error)
	ComposeSettleLapsed(ctx context.Context, args escrow.SettleLapsedArgs, signer transaction.TransactionSigner, signerAddr string) (escrow.CallResult, error)
	// ReadTicketBox is the ticket's box, or nil once it is gone: finalized
	// and deleted.
	ReadTicketBox(ctx context.Context, ticketIDRaw []byte) (*escrow.TicketRecord, error)
}

// EscrowChainConfig is the slice of the deployment the wallet reads.
type EscrowChainConfig struct {
	AppID uint64
	// SettlementGraceDefault is the contract's grace global: the settlement
	// window of a ticket opened with settlementGraceSeconds 0, as the payer
	// opens every one.
	SettlementGraceDefault uint64
}

// NewEscrowChain is the production EscrowChain over c. Its reads of c's
// RefreshConfig-loaded fields happen per call, so a refresh is seen at once.
// A nil c is a nil chain, which the wallet's guards treat as no chain rather
// than dereferencing.
func NewEscrowChain(c *escrow.Client) EscrowChain {
	if c == nil {
		return nil
	}
	return escrowClientChain{c}
}

// escrowClientChain embeds the client for the calls whose signatures already
// match, and bridges the rest: the fields read as methods, and the two reads
// the client doesn't surface (spendable balance, min fee) through its algod.
type escrowClientChain struct{ *escrow.Client }

func (a escrowClientChain) TicketMBR() uint64 { return a.TicketMbr }

func (a escrowClientChain) Config() EscrowChainConfig {
	return EscrowChainConfig{AppID: a.AppID, SettlementGraceDefault: a.SettlementGraceDefault}
}

func (a escrowClientChain) ProtocolFeeBps(ctx context.Context) (uint64, error) {
	return a.ProtocolFeeBpsNow(ctx)
}

func (a escrowClientChain) SpendableMicroAlgos(ctx context.Context, payerAddr string) (uint64, error) {
	acct, err := a.Algod.SDKClient().AccountInformation(payerAddr).Do(ctx)
	if err != nil {
		return 0, fmt.Errorf("escrow: account info for spendable balance: %w", err)
	}
	if acct.Amount < acct.MinBalance {
		return 0, nil
	}
	return acct.Amount - acct.MinBalance, nil
}

func (a escrowClientChain) MinTxnFee(ctx context.Context) (uint64, error) {
	sp, err := a.Algod.SuggestedParams(ctx)
	if err != nil {
		return 0, fmt.Errorf("escrow: suggested params for min fee: %w", err)
	}
	return sp.MinFee, nil
}

func (a escrowClientChain) SubmitPresignedOpenGroup(ctx context.Context, group []types.SignedTxn, payerSigner transaction.TransactionSigner, spec escrow.OpenGroupSpec) (escrow.OpenResult, error) {
	// Stamp the chain-config slice of the spec here rather than in
	// Wallet.Open: the escrow client is its single source of truth
	// (RefreshConfig-loaded), and it keeps the wallet free of
	// *escrow.Client field access so the fake stays a pure recorder.
	return a.Client.SubmitPresignedOpenGroup(ctx, group, payerSigner, a.stampChain(spec))
}

func (a escrowClientChain) CompletePresignedOpenGroup(group []types.SignedTxn, payerSigner transaction.TransactionSigner, spec escrow.OpenGroupSpec) (escrow.OpenResult, error) {
	return a.Client.CompletePresignedOpenGroup(group, payerSigner, a.stampChain(spec))
}

func (a escrowClientChain) stampChain(spec escrow.OpenGroupSpec) escrow.OpenGroupSpec {
	spec.AppID = a.AppID
	spec.AppAddress = a.AppAddr
	spec.UsdcAssetID = a.UsdcAssetID
	spec.TicketMbr = a.TicketMbr
	return spec
}

func (a escrowClientChain) SubmitSettleGroup(ctx context.Context, group []types.SignedTxn) error {
	return escrow.SubmitSettleGroup(ctx, a.Algod, group)
}

func (a escrowClientChain) SettleOutcome(ctx context.Context, txid string) (SettleOutcome, error) {
	if a.Algod == nil {
		return SettlePending, errors.New("zs: escrow client has no algod")
	}
	info, err := a.Algod.PendingTransactionInformation(ctx, txid)
	if err != nil {
		return SettlePending, err
	}
	return settleOutcomeOf(info), nil
}
