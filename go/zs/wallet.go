/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sync"
	"sync/atomic"

	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/TxnLab/zerosignal/go/algo"
	"github.com/TxnLab/zerosignal/go/escrow"
	"github.com/TxnLab/zerosignal/go/ticket"
)

// Wallet drives the escrow payment path from the proxy side.
// One Wallet instance per process; shared across all hayai requests.
// Per-request state lives on OpenHandle, which Wallet.Open returns
// and the dispatcher threads through its factories so the
// post-response verification path can call AckSettle or Protest with
// the right bound arguments.
type Wallet struct {
	escrow    *escrow.Client
	keystore  algo.MultipleWalletSigner
	payerAddr string

	// pool is the narrow escrow-dependency surface the prepaid-MBR-pool
	// path (EnsureDeposit + the Open deposit-revert retry) drives. It's a
	// seam over *escrow.Client (poolEscrowAdapter) so unit tests can inject a
	// fake without a live algod/keystore. AckSettle / Protest / RefundInactive
	// stay on the concrete w.escrow — they're not part of the pool surface.
	pool poolEscrow

	// depositSlots is the prepaid-MBR-pool working set (concurrent ticket
	// boxes the auto-deposit backs), from zs.concurrent_slots; 0 falls
	// back to DefaultDepositSlots.
	depositSlots uint64

	// depositMu serializes the lazy prepaid-MBR-pool setup (ensureDepositForServe)
	// so concurrent first requests don't race two opt-in deposits. depositReady is
	// set once the pool is confirmed to cover the working set, after which Open
	// skips the per-request chain read.
	depositMu    sync.Mutex
	depositReady bool

	// quotaBoxKnown latches once the payer's free-quota box is confirmed to
	// exist. Only `true` is cacheable — the contract never deletes a quota box,
	// so existence is monotonic — which keeps steady-state funding passes free
	// of the extra box read. Absence must stay live: the box appears the moment
	// the payer's first free ticket opens.
	quotaBoxKnown atomic.Bool
}

// quotaMbrDue is the free-quota box MBR this payer's pool still has to cover,
// with the box-exists answer latched. See poolEscrow.FreeQuotaMbrDueFor.
//
// Note the asymmetry the latch can't fix: a payer who only ever uses PAID
// models never gets a quota box, so the term stays due forever and every
// sizing pass re-reads the box. That is bounded — ensureDepositForServe latches
// depositReady once the pool covers slots + the term, so the read happens on
// funding passes, not per request — and the parked ALGO stays withdrawable. The
// exactness below therefore buys nothing for a paid-only payer; it pays off for
// the (common) payer who does open a free ticket, after which the term drops
// out permanently.
func (w *Wallet) quotaMbrDue(ctx context.Context) uint64 {
	if w.quotaBoxKnown.Load() {
		return 0
	}
	due := w.pool.FreeQuotaMbrDueFor(ctx, w.payerAddr)
	if due == 0 {
		w.quotaBoxKnown.Store(true)
	}
	return due
}

// poolEscrow is the narrow escrow surface the prepaid-MBR-pool path depends
// on. Kept tight (only what EnsureDeposit + the Open retry need) so the test
// fake stays small; the production binding is poolEscrowAdapter over
// *escrow.Client.
type poolEscrow interface {
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
	// SubmitPresignedOpenGroup verifies the node-delivered 2-tx open group
	// against spec (every field pinned to the signature-verified ticket —
	// the group is counterparty-composed, so this runs BEFORE the payer
	// signs gtxn[0] = usdcPayment; gtxn[1] = open() AppCall is
	// operator-signed), then completes + broadcasts it.
	SubmitPresignedOpenGroup(ctx context.Context, group []types.SignedTxn, payerSigner transaction.TransactionSigner, spec escrow.OpenGroupSpec) (escrow.OpenResult, error)
}

// poolEscrowAdapter is the production poolEscrow, wrapping *escrow.Client.
// It bridges the field-vs-method gap (TicketMbr is a struct field) and the
// two reads the escrow.Client doesn't surface directly (spendable balance,
// min-fee) via its embedded algod SDK client.
type poolEscrowAdapter struct{ c *escrow.Client }

func (a poolEscrowAdapter) TicketMBR() uint64 { return a.c.TicketMbr }
func (a poolEscrowAdapter) FreeQuotaMbrDueFor(ctx context.Context, payerAddr string) uint64 {
	return a.c.FreeQuotaMbrDueFor(ctx, payerAddr)
}

func (a poolEscrowAdapter) ReadPayerDeposit(ctx context.Context, payerAddr string) (escrow.PayerDeposit, error) {
	return a.c.ReadPayerDeposit(ctx, payerAddr)
}

func (a poolEscrowAdapter) IsPayerOptedIn(ctx context.Context, payerAddr string) (bool, error) {
	return a.c.IsPayerOptedIn(ctx, payerAddr)
}

func (a poolEscrowAdapter) SpendableMicroAlgos(ctx context.Context, payerAddr string) (uint64, error) {
	acct, err := a.c.Algod.SDKClient().AccountInformation(payerAddr).Do(ctx)
	if err != nil {
		return 0, fmt.Errorf("escrow: account info for spendable balance: %w", err)
	}
	if acct.Amount < acct.MinBalance {
		return 0, nil
	}
	return acct.Amount - acct.MinBalance, nil
}

func (a poolEscrowAdapter) MinTxnFee(ctx context.Context) (uint64, error) {
	sp, err := a.c.Algod.SuggestedParams(ctx)
	if err != nil {
		return 0, fmt.Errorf("escrow: suggested params for min fee: %w", err)
	}
	return sp.MinFee, nil
}

func (a poolEscrowAdapter) ComposeDepositMbr(ctx context.Context, amount uint64, optIn bool, signer transaction.TransactionSigner, signerAddr string) (escrow.CallResult, error) {
	return a.c.ComposeDepositMbr(ctx, amount, optIn, signer, signerAddr)
}

func (a poolEscrowAdapter) SubmitPresignedOpenGroup(ctx context.Context, group []types.SignedTxn, payerSigner transaction.TransactionSigner, spec escrow.OpenGroupSpec) (escrow.OpenResult, error) {
	// Stamp the chain-config slice of the spec here rather than in
	// Wallet.Open: the escrow client is its single source of truth
	// (RefreshConfig-loaded), and it keeps the pool seam's callers free of
	// *escrow.Client field access so the fake stays a pure recorder.
	spec.AppID = a.c.AppID
	spec.AppAddress = a.c.AppAddr
	spec.UsdcAssetID = a.c.UsdcAssetID
	spec.TicketMbr = a.c.TicketMbr
	return a.c.SubmitPresignedOpenGroup(ctx, group, payerSigner, spec)
}

// WalletConfig groups the dependencies main.go assembles. Keeping
// this a struct lets the constructor evolve (e.g. add a retry policy
// or a metrics sink) without breaking call sites.
type WalletConfig struct {
	Escrow    *escrow.Client
	Keystore  algo.MultipleWalletSigner
	PayerAddr string
	// DepositSlots is the prepaid-MBR-pool working set (zs.concurrent_slots);
	// 0 falls back to DefaultDepositSlots.
	DepositSlots uint64
}

// NewWallet validates its dependencies and checks that payerAddr is
// one the keystore can actually sign for. Fails fast rather than
// letting the first Open call discover the missing key mid-request.
func NewWallet(cfg WalletConfig) (*Wallet, error) {
	if cfg.Escrow == nil {
		return nil, errors.New("wallet: escrow client is nil")
	}
	if cfg.Keystore == nil {
		return nil, errors.New("wallet: keystore is nil")
	}
	if cfg.PayerAddr == "" {
		return nil, errors.New("wallet: payer address is empty")
	}
	if !cfg.Keystore.HasAccount(cfg.PayerAddr) {
		return nil, fmt.Errorf("wallet: keystore has no private key for payer address %s", cfg.PayerAddr)
	}
	return &Wallet{
		escrow:       cfg.Escrow,
		pool:         poolEscrowAdapter{c: cfg.Escrow},
		keystore:     cfg.Keystore,
		payerAddr:    cfg.PayerAddr,
		depositSlots: cfg.DepositSlots,
	}, nil
}

// PayerAddr returns the Algorand address the wallet signs with. Used
// by startup logging + tests.
func (w *Wallet) PayerAddr() string { return w.payerAddr }

// ProtocolFeeBps returns the proxy payer's effective protocol-fee rate (feeBps
// gross, basis points) read directly from the contract's `protocolFeeBps`
// global — no readonly simulate. The HAY fee discount is RETIRED, so there is
// no per-account discount term and this single rate is the whole story (one
// cached value serves every request; the payer is the sole tenant). The
// on-chain open-time snapshot remains the settlement authority. See
// escrow.Client.ProtocolFeeBpsNow.
func (w *Wallet) ProtocolFeeBps(ctx context.Context) (feeBps uint64, err error) {
	if w == nil || w.escrow == nil {
		return 0, errors.New("wallet: escrow client unavailable")
	}
	return w.escrow.ProtocolFeeBpsNow(ctx)
}

// OpenHandle is the per-request state Wallet.Open returns. The
// dispatcher stores it on a handler-scoped struct so the
// non-stream responder and stream frame factory have the context
// they need to drive Protest (step 8) on body_hash mismatch.
type OpenHandle struct {
	// AppCallTxID is the per-tx id of the escrow.open application
	// call — position 1 of the submitted payment+app-call group, in
	// its wire form (base32, 52 chars). This is what gets threaded
	// into the envelope's algorand_tx_id so the node can look it up
	// directly via algod's PendingTransactionInformation(txid).
	AppCallTxID string
	// GroupID is the submitted atomic group's id in its wire form
	// (base32, 52 chars). Retained for audit/dispute logging; NOT
	// threaded into the envelope — algod has no "find pending txn by
	// group id" primitive, so we use the app-call txid for lookups
	// and keep the group id for correlation.
	GroupID string
	// TicketID is the envelope's ticket_id (base64 of the same 16
	// bytes ComposeOpen used for the on-chain arg). Kept so the
	// Protest path doesn't have to round-trip through the ticket.
	TicketID string
	// Operator is a snapshot of the registry entry we dispatched to.
	// Needed later for Protest (needs the operator's signing address)
	// and for dispute retention.
	Operator Operator
	// MaxPrice is the ceiling the contract enforces on settle(). The
	// proxy's AckSettle path asserts the receipt's amount_charged
	// doesn't exceed it before driving the co-signed settlement.
	MaxPrice uint64
	// OpenFeesMicroalgos is only the slice of the open group's network
	// fees that the payer's own signed transaction paid (gtxn[0]
	// usdcPayment). In the consensus-verified design it is 0 — the
	// operator's gtxn[1] (open AppCall) over-fees and pools the entire
	// group — so this is 0 in practice. The ticket-box MBR is no longer
	// a per-turn ALGO leg; it is drawn from the payer's prepaid pool.
	// Surfaced via
	// setHayaiUsageHeaders / zs.usage so the caller (the TUI) sees
	// only what the payer actually paid in ALGO fees, not the
	// operator's pool. The total committed group fee remains
	// recoverable from algod / the indexer for audit.
	OpenFeesMicroalgos uint64
	// SignedGroup is the raw msgpack bytes of the submitted group —
	// retained for dispute evidence per SPEC.md §3b.
	SignedGroup [][]byte

	wallet *Wallet
}

// Open composes, signs, submits the atomic group (Payment +
// escrow.open). Returns the OpenHandle that flows through the
// response path. Errors here surface on the proxy as a 502
// proxy_error; the client sees a clean error without any payment
// being attempted.
//
// SettlementGraceSeconds is passed as 0 in step 6, letting the
// contract's global default apply. When the proxy wants a tighter
// window it'll thread a per-ticket value through here; that's a
// step-8 knob.
func (w *Wallet) Open(ctx context.Context, tk *ticket.Ticket, op Operator, presignedOpenGroup []types.SignedTxn) (*OpenHandle, error) {
	if tk == nil {
		return nil, errors.New("wallet: open: ticket is nil")
	}
	if op.ID == 0 {
		return nil, errors.New("wallet: open: operator id is unset")
	}
	if op.OwnerAddr == "" || op.SigningAddr == "" {
		return nil, errors.New("wallet: open: operator addresses incomplete")
	}
	if len(presignedOpenGroup) == 0 {
		return nil, errors.New("wallet: open: presignedOpenGroup is empty (operator did not return a pre-signed open group on reserve)")
	}

	ticketIDRaw, err := decodeTicketID(tk.TicketID)
	if err != nil {
		return nil, fmt.Errorf("wallet: decode ticket id: %w", err)
	}

	// Spec for the pre-sign verification of the node-composed group. Every
	// field comes from the signature-verified ticket or the chain-resolved
	// operator snapshot — never from the group itself. The chain-config
	// slice (app id/address, USDC asset, ticket MBR) is stamped by
	// poolEscrowAdapter from the escrow client, its single source of truth.
	// SettlementGraceSeconds is pinned to 0 (the contract's `grace` default
	// applies), which is what makes the refund watchdog's deadline
	// D = expires_at + default grace sound; a node that authored a different
	// window is refused before the payer signs anything.
	nodeSigningAddr, err := types.DecodeAddress(op.SigningAddr)
	if err != nil {
		return nil, fmt.Errorf("wallet: decode node signing addr: %w", err)
	}
	payerAddr, err := types.DecodeAddress(w.payerAddr)
	if err != nil {
		return nil, fmt.Errorf("wallet: decode payer addr: %w", err)
	}
	openSpec := escrow.OpenGroupSpec{
		TicketIDRaw:            ticketIDRaw,
		OperatorID:             tk.OperatorID,
		NodeID:                 tk.NodeID,
		MaxPrice:               tk.MaxPrice,
		NodeSigningAddr:        nodeSigningAddr,
		PayerAddr:              payerAddr,
		ExpiresAt:              uint64(tk.ExpiresAt),
		SettlementGraceSeconds: 0,
	}

	// Establish the payer's prepaid ticket-MBR pool before drawing a slot —
	// open() reverts 'payer has no MBR deposit' / 'insufficient MBR deposit'
	// otherwise (the box MBR is no longer a per-turn ALGO leg). Lazy +
	// idempotent: a no-op once the pool covers the working set. A funding
	// failure here is an underfunded-open error (402), same as the USDC leg.
	if err := w.ensureDepositForServe(ctx); err != nil {
		return nil, fmt.Errorf("wallet: ensure MBR deposit: %w", err)
	}

	signer := algo.SignWithAccountForATC(w.keystore, w.payerAddr)
	result, err := w.pool.SubmitPresignedOpenGroup(ctx, presignedOpenGroup, signer, openSpec)
	if err != nil {
		// An open() that reverts on a prepaid-pool guard ('payer has no MBR
		// deposit' / 'insufficient MBR deposit') is identifiable — the escrow
		// client resolves algod's 'assert failed pc=…' through the ARC-56
		// source map into an *escrow.ApprovalError — but self-healing beats
		// classifying here, because the guard may already be satisfiable.
		// So: re-check the pool regardless of which revert it was. Drop the
		// ready cache
		// and re-ensure. If that actually tops up a drained/absent pool
		// (deposited > 0) — e.g. the cache said ready but a withdraw/close
		// emptied it, or a fresh deploy gave a new app id — the failing guard is
		// now satisfied, so retry the SAME group once (the revert committed
		// nothing; the group's hash + sigs stay valid). If the pool already
		// covers the working set, EnsureDeposit no-ops (deposited == 0) — the
		// failure was exhaustion (self-heals as in-flight tickets settle) or
		// unrelated — so we don't retry and the original error surfaces.
		w.depositMu.Lock()
		w.depositReady = false
		w.depositMu.Unlock()
		_, deposited, derr := w.EnsureDeposit(ctx, w.depositSlots)
		switch {
		case derr == nil:
			w.depositMu.Lock()
			w.depositReady = true
			w.depositMu.Unlock()
		case errors.Is(derr, ErrDepositBelowTarget):
			// Partial success: the free-quota box is now funded — which is
			// precisely the guard a payer's FIRST free open trips ('insufficient
			// MBR deposit for free-quota box') — but the pool is still short of
			// the working set. Retry below, since the failing guard may now be
			// satisfied, but leave depositReady false so the next request
			// re-attempts the remaining slots.
		default:
			deposited = 0 // nothing landed; the guard is unchanged, so don't retry
		}
		if deposited > 0 {
			result, err = w.pool.SubmitPresignedOpenGroup(ctx, presignedOpenGroup, signer, openSpec)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("wallet: submit presigned open group: %w", err)
	}
	if len(result.TxIDs) != 2 {
		return nil, fmt.Errorf("wallet: escrow submit returned %d txids, want 2", len(result.TxIDs))
	}

	return &OpenHandle{
		AppCallTxID:        result.TxIDs[1],
		GroupID:            result.GroupID,
		TicketID:           tk.TicketID,
		Operator:           op,
		MaxPrice:           tk.MaxPrice,
		OpenFeesMicroalgos: result.PayerFeeMicroalgos,
		SignedGroup:        result.SignedGroup,
		wallet:             w,
	}, nil
}

// AckSettle is the payer's matching co-sign on an operator-initiated
// settle call. The contract enforces that:
//  1. the payer's amountCharged / receiptDigest / receiptSig match
//     what the operator submitted first (or the slot freezes);
//  2. both calls happen inside the settle window.
//
// Called from the dispatcher's receipt-verification hook once the
// three checks (sig, amount ≤ max_price, body_hash) pass. Returns
// the submitted txid + the slice of the call's network fee paid by
// the payer's own signed transaction(s) — 0 on the atomic path
// (operator's gtxn[0] pools the entire settle group), ~5,000 µALGO
// on the standalone fallback (payer signs the single AppCall). The
// dispatcher reports this number to the client as "ALGO fees paid";
// surfacing operator-paid pool fees here would mislead the user.
// Errors surface without blocking the client's response — the ack
// is an after-the-fact settlement step, not a pre-condition for
// returning bytes to the OpenAI caller.
//
// Nil-wallet guard: test fakes can construct OpenHandle values
// directly; those don't carry a real wallet and shouldn't submit
// any transaction. Fail loudly rather than panic on dereference.
// groupRejected (the third return) is true iff the operator handed a settle
// group the verifier refused as fraudulent (*escrow.SettleGroupRejectedError).
// It stays true through the standalone fallback so the caller can locally
// downrank the node even though the payment still settled. It is NOT set for a
// spec-build failure (our decode, not the node's fault) or a plain algod error.
func (h *OpenHandle) AckSettle(ctx context.Context, receipt *ticket.UsageReceipt, presignedSettleGroup []types.SignedTxn) (txid string, feeMicroalgos uint64, groupRejected bool, err error) {
	if h.wallet == nil {
		return "", 0, false, errors.New("wallet: ack-settle on detached OpenHandle (test-only or misconstructed)")
	}
	signer := algo.SignWithAccountForATC(h.wallet.keystore, h.wallet.payerAddr)

	// Atomic settle path: the operator's pre-signed gtxn[0] arrived
	// in the response's X-Zs-Settle-Group header. We VERIFY the
	// node-composed group against the receipt-derived spec, sign the
	// payer-ack member, and submit the 2-tx group; payer's outer fee
	// is 0 (operator's gtxn[0] over-fee covers the entire group).
	if len(presignedSettleGroup) > 0 {
		spec, specErr := h.settleGroupSpec(receipt)
		if specErr != nil {
			// Spec build failed (address / ticket-id decode) — shouldn't happen
			// for a signature-verified ticket. Log and fall through to the
			// standalone receipt-sourced ack rather than block settlement. NOT a
			// node fault, so groupRejected stays false.
			slog.Warn("ack-settle: settle-group spec build failed; falling back to standalone",
				"operator_id", h.Operator.ID, "node_id", h.Operator.NodeID, "err", specErr)
		} else {
			res, subErr := h.wallet.escrow.SubmitPresignedSettleGroup(ctx, presignedSettleGroup, signer, spec)
			if subErr == nil {
				return res.TxID, res.PayerFeeMicroalgos, false, nil
			}
			var rejected *escrow.SettleGroupRejectedError
			if errors.As(subErr, &rejected) {
				// The node handed a malformed / fraudulent group: a rekeyTo
				// (account takeover), a non-NoOp onComplete (ClearState wipes the
				// payer's local pool accounting), a non-zero payer fee, or a value
				// that doesn't match the node's own signed receipt. The node
				// authored both halves and the receipt, so this is proven operator
				// misbehaviour. Refuse the atomic path and fall through to the
				// standalone receipt-sourced ack — which posts a payer-side pending
				// claim (pendingBy=PAYER → refundInactive-eligible), preserving the
				// clean-refund guarantee — while surfacing groupRejected so the
				// dispatcher hard-excludes this (operatorId,nodeId) from selection.
				slog.Warn("ack-settle: operator settle group REJECTED; refusing atomic path, falling back to standalone ack",
					"operator_id", h.Operator.ID, "node_id", h.Operator.NodeID,
					"field", rejected.Field, "detail", rejected.Detail)
				groupRejected = true
				// fall through to the standalone ack below
			} else {
				// A non-rejection submit error (algod outage, pool eval, etc.).
				// Preserve prior behaviour: surface it rather than silently
				// re-settling standalone at the payer's expense.
				return "", 0, false, fmt.Errorf("wallet: ack-settle (atomic): %w", subErr)
			}
		}
	}

	// Standalone fallback: pre-update operator that doesn't emit the
	// settle-group header, or atomic path failed somewhere upstream. Here the
	// PAYER funds the call — 1 outer + finalize's op-up + the disbursement
	// inners this settle actually fires (sized from AmountCharged/MaxPrice).
	ticketIDRaw, decErr := decodeTicketID(h.TicketID)
	if decErr != nil {
		return "", 0, groupRejected, fmt.Errorf("wallet: ack-settle decode ticket id: %w", decErr)
	}
	receiptDigest := ticket.ReceiptSigDigest(receipt)
	res, settleErr := h.wallet.escrow.ComposeSettleStandalone(ctx, escrow.SettleArgs{
		TicketIDRaw:   ticketIDRaw,
		AmountCharged: receipt.AmountCharged,
		MaxPrice:      h.MaxPrice,
		ReceiptDigest: receiptDigest,
		// All co-signed metric args come straight from the operator's signed
		// receipt so this payer-side ack matches the operator's first-half
		// verbatim (mismatch on any one freezes the ticket).
		TtftMs:             receipt.TtftMs,
		DecodeMs:           receipt.DecodeMs,
		InputCount:         receipt.ActualInputCount,
		OutputCount:        receipt.ActualOutputCount,
		OutputUsageType:    uint64(receipt.OutputUsageType),
		AuxOutputUsageType: uint64(receipt.AuxOutputUsageType),
		AuxOutputCount:     receipt.AuxOutputCount,
		AsOperator:         false,
		PayerAddr:          h.wallet.payerAddr,
		OperatorOwnerAddr:  h.Operator.OwnerAddr,
		OperatorID:         h.Operator.ID,
		NodeID:             h.Operator.NodeID,
	}, signer, h.wallet.payerAddr)
	if settleErr != nil {
		return "", 0, groupRejected, fmt.Errorf("wallet: ack-settle: %w", settleErr)
	}
	return res.TxID, res.FeeMicroalgos, groupRejected, nil
}

// settleGroupSpec builds the escrow.SettleGroupSpec the atomic-settle
// verifier compares the node-composed group against. Every value is
// sourced from the operator's signature-verified receipt (and the
// handle's chain-resolved operator snapshot / escrow config) — never from
// the group itself, which is exactly what the verifier is guarding. The
// nine billing values match what the standalone-ack path passes as
// SettleArgs, so a well-formed node group verifies and an
// inflated/tampered one is refused.
func (h *OpenHandle) settleGroupSpec(receipt *ticket.UsageReceipt) (escrow.SettleGroupSpec, error) {
	ticketIDRaw, err := decodeTicketID(h.TicketID)
	if err != nil {
		return escrow.SettleGroupSpec{}, fmt.Errorf("decode ticket id: %w", err)
	}
	payerAddr, err := types.DecodeAddress(h.wallet.payerAddr)
	if err != nil {
		return escrow.SettleGroupSpec{}, fmt.Errorf("decode payer addr: %w", err)
	}
	opSigningAddr, err := types.DecodeAddress(h.Operator.SigningAddr)
	if err != nil {
		return escrow.SettleGroupSpec{}, fmt.Errorf("decode operator signing addr: %w", err)
	}
	return escrow.SettleGroupSpec{
		AppID:               h.wallet.escrow.AppID,
		TicketIDRaw:         ticketIDRaw,
		AmountCharged:       receipt.AmountCharged,
		ReceiptDigest:       ticket.ReceiptSigDigest(receipt),
		TtftMs:              receipt.TtftMs,
		DecodeMs:            receipt.DecodeMs,
		InputCount:          receipt.ActualInputCount,
		OutputCount:         receipt.ActualOutputCount,
		OutputUsageType:     uint64(receipt.OutputUsageType),
		AuxOutputUsageType:  uint64(receipt.AuxOutputUsageType),
		AuxOutputCount:      receipt.AuxOutputCount,
		PayerAddr:           payerAddr,
		OperatorSigningAddr: opSigningAddr,
	}, nil
}

// Protest is the payer's freeze when receipt.body_hash doesn't match
// the proxy's reconstructed plaintext. The dispute excerpt is a
// caller-supplied byte slice of evidence the off-chain arbiter can
// inspect (ciphertext chunk + ephemeral priv key per SPEC.md §3b).
// The contract caps the excerpt length; the caller must pre-truncate.
// reason rides as an indexable transaction arg (see escrow.ProtestReason*)
// so off-chain consumers can categorize the freeze without re-running
// receipt-vs-plaintext comparisons; the contract rejects 0.
func (h *OpenHandle) Protest(ctx context.Context, receipt *ticket.UsageReceipt, excerpt []byte, reason escrow.ProtestReasonCode) (string, error) {
	if h.wallet == nil {
		return "", errors.New("wallet: protest on detached OpenHandle (test-only or misconstructed)")
	}
	ticketIDRaw, err := decodeTicketID(h.TicketID)
	if err != nil {
		return "", fmt.Errorf("wallet: protest decode ticket id: %w", err)
	}
	receiptSig, err := decodeReceiptSig(receipt.Sig)
	if err != nil {
		return "", fmt.Errorf("wallet: protest decode receipt sig: %w", err)
	}
	receiptDigest := ticket.ReceiptSigDigest(receipt)

	signer := algo.SignWithAccountForATC(h.wallet.keystore, h.wallet.payerAddr)
	res, err := h.wallet.escrow.ComposeProtest(ctx, escrow.ProtestArgs{
		TicketIDRaw:    ticketIDRaw,
		AmountCharged:  receipt.AmountCharged,
		ReceiptDigest:  receiptDigest,
		ReceiptSig:     receiptSig,
		DisputeExcerpt: excerpt,
		ReasonCode:     reason,
		OperatorID:     h.Operator.ID,
		NodeID:         h.Operator.NodeID,
	}, signer, h.wallet.payerAddr)
	if err != nil {
		return "", fmt.Errorf("wallet: protest: %w", err)
	}
	return res.TxID, nil
}

// RefundInactive is the payer's escape hatch when no operator claim
// ever posted and the refund window has opened. Exposed on the
// handle so timeout logic can drive it without re-deriving the
// ticket id.
func (h *OpenHandle) RefundInactive(ctx context.Context) (string, error) {
	if h.wallet == nil {
		return "", errors.New("wallet: refund-inactive on detached OpenHandle (test-only or misconstructed)")
	}
	ticketIDRaw, err := decodeTicketID(h.TicketID)
	if err != nil {
		return "", fmt.Errorf("wallet: refund-inactive decode ticket id: %w", err)
	}
	signer := algo.SignWithAccountForATC(h.wallet.keystore, h.wallet.payerAddr)
	res, err := h.wallet.escrow.ComposeRefundInactive(ctx, escrow.RefundInactiveArgs{
		TicketIDRaw: ticketIDRaw,
		OperatorID:  h.Operator.ID,
		NodeID:      h.Operator.NodeID,
		PayerAddr:   h.wallet.payerAddr,
	}, signer, h.wallet.payerAddr)
	if err != nil {
		return "", fmt.Errorf("wallet: refund-inactive: %w", err)
	}
	return res.TxID, nil
}

// SettleLapsed force-finalizes an operator-side pending claim once the
// settlement deadline has passed, disbursing the operator's claimed amount and
// returning the remainder of max_price to the payer. It is the payer's only
// lever on a ticket in PENDING_SETTLE/pending_by=OPERATOR: refundInactive is
// barred there (the contract routes the state here instead), so without this
// the escrowed USDC is recoverable only by the node's own settlement driver.
//
// Normally that driver does it and the payer never calls this — it's the
// backstop for a node that died after its claim confirmed, lost its ledger, or
// burned its lapse-retry budget. The call is permissionless (the contract puts
// no sender assert on settleLapsed), so the payer can post it; the payer pays
// only the network fee, and the disbursement is the contract's own math off the
// box either way.
//
// h.Operator is a snapshot of the proxy's cached registry entry, so its
// OwnerAddr can disagree with the one the box snapshotted at open() if the
// operator has rotated it since (updateOperator). That only matters for the
// ForeignAccounts reference the payout needs, and ComposeSettleLapsed re-reads
// the box and prefers its owner for exactly that reason — what's passed here is
// its fallback for an unreadable box. Same for the amounts: the contract reads
// them off the box, never from a caller's copy.
//
// Racing the node's driver is safe: whichever call lands second reverts on the
// deleted box, and a reverted app call commits nothing.
func (h *OpenHandle) SettleLapsed(ctx context.Context) (string, error) {
	if h.wallet == nil {
		return "", errors.New("wallet: settle-lapsed on detached OpenHandle (test-only or misconstructed)")
	}
	ticketIDRaw, err := decodeTicketID(h.TicketID)
	if err != nil {
		return "", fmt.Errorf("wallet: settle-lapsed decode ticket id: %w", err)
	}
	signer := algo.SignWithAccountForATC(h.wallet.keystore, h.wallet.payerAddr)
	res, err := h.wallet.escrow.ComposeSettleLapsed(ctx, escrow.SettleLapsedArgs{
		TicketIDRaw:       ticketIDRaw,
		OperatorID:        h.Operator.ID,
		NodeID:            h.Operator.NodeID,
		OperatorOwnerAddr: h.Operator.OwnerAddr,
		PayerAddr:         h.wallet.payerAddr,
	}, signer, h.wallet.payerAddr)
	if err != nil {
		return "", fmt.Errorf("wallet: settle-lapsed: %w", err)
	}
	return res.TxID, nil
}

// DefaultDepositSlots is the fallback working-set size EnsureDeposit funds
// when the caller passes 0 (and the configured zs.concurrent_slots is
// unset) — concurrent ticket boxes one payer can hold open at once
// (parallel tool calls, the settle grace window). At mbrForTicket() ≈ 0.115
// ALGO/slot, 10 slots ≈ 1.15 ALGO of recoverable deposit. Sized for
// concurrency, not lifetime count. Operators tune it via zs.concurrent_slots.
const DefaultDepositSlots = 10

// depositOptInMBR is the account-MBR delta the payer's own balance must cover
// when depositMbr opts them into the escrow app on the first deposit. The
// contract's local schema is 6 uints (algoBalance + openTickets + 4 reserved
// slots) and no byte-slices, so the cost is the Algorand opt-in base
// (100_000) + 6 × per-uint (28_500) = 271_000 µALGO. Used only to pad the
// pre-submit affordability check so a first-deposit attempt fails with a clear
// shortfall message rather than opaquely at algod admission. The MBR locks in
// the payer's own account (recoverable on closeDeposit), it is not sent to the
// app.
const depositOptInMBR = 100_000 + 6*28_500

// ErrDepositUnaffordable is the sentinel EnsureDeposit returns when the payer's
// spendable ALGO can't cover the shortfall + the deposit group fee (+ the
// opt-in MBR on a first deposit). Distinct from a deposit that fails at algod:
// this is caught BEFORE submit so callers (the CLI, the dispatch 402 path) can
// name the µALGO needed instead of surfacing an opaque "overspend". Its message
// already contains the actionable detail; callers can errors.Is to branch.
var ErrDepositUnaffordable = errors.New("wallet: insufficient ALGO to fund the prepaid MBR pool")

// ErrDepositBelowTarget is the sentinel EnsureDeposit returns when it DID
// deposit — the returned txid and `deposited` are real and the funds are in the
// pool — but the pool is still short of the requested working set. Today the
// only such partial success is the free-quota-box-only fallback: the wallet
// couldn't afford another whole ticket slot, so it funded just the sub-slot
// quota term.
//
// It exists so a partial success can't be mistaken for a complete one.
// ensureDepositForServe latches depositReady on a nil error and then skips the
// top-up for the process lifetime; latching on a partial deposit would freeze
// the pool below target until an open actually reverted, even after the wallet
// was refilled. Deliberately does NOT wrap ErrDepositUnaffordable — callers
// that branch on that sentinel are asking "did the deposit fail?", and here it
// didn't.
var ErrDepositBelowTarget = errors.New("wallet: prepaid MBR pool funded below the configured working set")

// ensureDepositForServe lazily establishes the payer's prepaid ticket-MBR
// pool the first time the serving path needs it, so open() has box-MBR
// headroom. Serialized (depositMu) so concurrent first requests don't
// double-opt-in; cached (depositReady) once the pool covers the working set
// so steady-state opens add no chain round-trip. A funding failure (unfunded
// payer) is returned and classified as an underfunded-open error by the
// dispatch (402 wallet_unfunded), same as the USDC/ALGO legs.
func (w *Wallet) ensureDepositForServe(ctx context.Context) error {
	w.depositMu.Lock()
	defer w.depositMu.Unlock()
	if w.depositReady {
		return nil
	}
	// w.depositSlots is the configured working set (zs.concurrent_slots);
	// EnsureDeposit treats 0 as DefaultDepositSlots.
	_, _, err := w.EnsureDeposit(ctx, w.depositSlots)
	if err == nil {
		w.depositReady = true
		return nil
	}
	// A top-up we can't afford is only fatal when the pool has ZERO free
	// headroom. open() draws just ONE box-MBR slot, so with even a single free
	// slot the pending open commits on-chain — refusing the request because we
	// couldn't restore the *full* working set would be a false "underfunded"
	// (the exact bug: a pool with free slots for this request, blocked because
	// ALGO ran short of the greedy top-up target). Proceed on any free slot,
	// but DON'T cache depositReady: the pool is below target, so the next
	// request retries the top-up as ALGO is added / in-flight tickets settle.
	// If we misjudge headroom under a concurrent-open race, open() reverts on
	// its own pool guard → the honest 429 mbr_pool_exhausted, never a 402. Any
	// other failure (chain read error, unrelated) stays fatal.
	//
	// ErrDepositBelowTarget takes the same branch, and that is the whole reason
	// it isn't a nil error: a partial (free-quota-box-only) deposit leaves the
	// pool under target exactly like an unaffordable one, so it must reach the
	// serving path the same way — usable now, re-attempted next request — rather
	// than latching depositReady and freezing the pool where it stands.
	if errors.Is(err, ErrDepositUnaffordable) || errors.Is(err, ErrDepositBelowTarget) {
		if free, ferr := w.freeDepositSlots(ctx); ferr == nil && free >= 1 {
			return nil
		}
	}
	return err
}

// freeDepositSlots reports how many additional ticket boxes the prepaid pool
// can currently back: (AlgoBalance − OpenTickets × ticketMbr) / ticketMbr. An
// open needs only ONE free slot to commit, so ensureDepositForServe uses this
// to tell a genuinely-unaffordable open (zero headroom → fatal) apart from a
// pool that just can't reach its full working-set target but can still serve
// the request.
func (w *Wallet) freeDepositSlots(ctx context.Context) (uint64, error) {
	ticketMbr := w.pool.TicketMBR()
	if ticketMbr == 0 {
		return 0, errors.New("wallet: free-deposit-slots: ticket MBR not loaded (call RefreshConfig first)")
	}
	dep, err := w.pool.ReadPayerDeposit(ctx, w.payerAddr)
	if err != nil {
		return 0, fmt.Errorf("wallet: free-deposit-slots read: %w", err)
	}
	return FreePoolHeadroom(ticketMbr, dep) / ticketMbr, nil
}

// ReadDeposit returns the payer's current prepaid-pool state (algoBalance
// on deposit + live openTickets count). algoBalance == 0 means no pool
// (or a fully-drained one); use the on-chain opt-in check inside
// EnsureDeposit to tell those apart.
func (w *Wallet) ReadDeposit(ctx context.Context) (escrow.PayerDeposit, error) {
	return w.pool.ReadPayerDeposit(ctx, w.payerAddr)
}

// DepositShortfall reports how much µALGO `slots` of free working-set
// headroom needs beyond the pool's current FREE balance (AlgoBalance −
// OpenTickets × ticketMbr), without submitting anything. 0 means the pool
// already covers it. notOptedIn is true when the payer has no pool yet (a
// first deposit will opt in, which also costs the local-schema MBR out of the
// payer's own account). Used by `zs fund` / `status` to show the requirement
// up front. slots == 0 falls back to DefaultDepositSlots.
func (w *Wallet) DepositShortfall(ctx context.Context, slots uint64) (shortfall uint64, notOptedIn bool, err error) {
	if slots == 0 {
		slots = DefaultDepositSlots
	}
	ticketMbr := w.pool.TicketMBR()
	if ticketMbr == 0 {
		return 0, false, errors.New("wallet: deposit-shortfall: ticket MBR not loaded (call RefreshConfig first)")
	}
	dep, err := w.pool.ReadPayerDeposit(ctx, w.payerAddr)
	if err != nil {
		return 0, false, fmt.Errorf("wallet: deposit-shortfall read: %w", err)
	}
	optedIn, err := w.pool.IsPayerOptedIn(ctx, w.payerAddr)
	if err != nil {
		return 0, false, fmt.Errorf("wallet: deposit-shortfall opt-in check: %w", err)
	}
	return DepositShortfall(slots, ticketMbr, w.quotaMbrDue(ctx), dep), !optedIn, nil
}

// DepositShortfall is the pure sizing core: the µALGO needed so the pool TOTALS
// `slots` ticket boxes' worth of MBR, plus the one-time free-quota box term.
// Exported so the CLI (status) can report the same figure without a wallet.
//
// Sized against GROSS AlgoBalance, deliberately: `slots` is the size of the
// pool, not the number of boxes free right now. OpenTickets is transient — a
// live ticket has borrowed a slot and gives it back at settle — so subtracting
// it here would read normal serving load as a funding gap. That is not a
// one-time overshoot but a ratchet, because the caller does not always latch:
// ensureDepositForServe deliberately leaves depositReady false whenever the
// pool is under target, so every subsequent request re-sizes — and each pass
// under load sees N tickets in flight, targets slots+N, funds the difference,
// and the ALGO it just parked is still not "free" the next time N tickets are
// in flight. The pool would climb with concurrency, never with need.
//
// This also matches the client (`ensureMbrDepositOnce` sizes `currentSlots =
// algoBalance / ticketMbr` off gross balance). The proxy is the payer's own
// localhost twin of the client, so the two must not disagree about how much
// ALGO the same wallet needs.
//
// The trade this accepts: a ticket that never settles — FROZEN is terminal, so
// its slot is gone for good — permanently costs one slot of the working set,
// and nothing re-grows it. That is the honest reading. The pool is genuinely
// smaller, `zs-proxy tickets` names the frozen ticket, and the fix is to raise
// zs.concurrent_slots or resolve the ticket — not to have every proxy silently
// inflate its deposit on every busy moment to keep a rare terminal case
// invisible. `freeDepositSlots` (admission: "can I open one right now?") still
// answers on free-of-reserved; that is a different question from sizing.
func DepositShortfall(slots, ticketMbr, freeQuotaMbr uint64, dep escrow.PayerDeposit) uint64 {
	// freeQuotaMbr is the term this payer STILL owes — callers pass
	// FreeQuotaMbrDueFor, which is 0 once they already have a quota box (the
	// charge is one-time and can never recur), and 0 against an app with no
	// free-ticket quota. Passing a flat term instead would still be safe — the
	// excess is withdrawable — but would leave a payer who HAS a box carrying an
	// idle copy of a charge that can never recur. (A paid-only payer never gets
	// a box, so for them the two are the same; see Wallet.quotaMbrDue.)
	target := poolTarget(slots, ticketMbr, freeQuotaMbr)
	if dep.AlgoBalance >= target {
		return 0
	}
	return target - dep.AlgoBalance
}

// poolTarget is `slots*ticketMbr + freeQuotaMbr`, SATURATING at MaxUint64
// instead of wrapping.
//
// The wrap is not theoretical and it inverts the caller's intent. A slot count
// large enough to overflow produces a tiny target, so a request to GROW the
// pool reads as an excess: the shrink path then reclaims the pool's free
// headroom, and every later sizing pass sees the same tiny target already
// satisfied — so the auto-top-up never fires again and the payer silently
// stops being able to open tickets. Saturating turns that into an
// unaffordable shortfall, which fails loudly at the pre-submit check.
//
// The count reaches here from config and env as well as the CLI, so the guard
// belongs in the shared arithmetic rather than only at the command that
// parses an argument.
func poolTarget(slots, ticketMbr, freeQuotaMbr uint64) uint64 {
	if ticketMbr != 0 && slots > (math.MaxUint64-freeQuotaMbr)/ticketMbr {
		return math.MaxUint64
	}
	return slots*ticketMbr + freeQuotaMbr
}

// DepositExcess is DepositShortfall's exact inverse: the µALGO the pool holds
// ABOVE what `slots` ticket boxes need (plus the free-quota term still owed).
// It answers "how much can shrinking the working set release?" — 0 when the
// pool is at or below target.
//
// Same gross-AlgoBalance basis as DepositShortfall, and for the same reason:
// `slots` sizes the pool, not the boxes free at this instant. That makes this
// the SIZING answer only — it is deliberately NOT the withdrawable amount. The
// contract caps a withdraw at the unreserved balance
// (algoBalance − openTickets × mbrForTicket()) and reverts on an over-ask, so a
// caller must take the smaller of the two. Folding that bound in here would
// quietly conflate "the pool is oversized by X" with "you can take X out right
// now", and those differ by exactly the tickets in flight — which is precisely
// what the caller needs to be able to tell the user about.
func DepositExcess(slots, ticketMbr, freeQuotaMbr uint64, dep escrow.PayerDeposit) uint64 {
	target := poolTarget(slots, ticketMbr, freeQuotaMbr)
	if dep.AlgoBalance <= target {
		return 0
	}
	return dep.AlgoBalance - target
}

// quotaOnlyShortfall is the µALGO needed to cover the free-quota box term ALONE,
// on top of whatever whole ticket slots the pool already backs — i.e. ignoring
// any slot shortfall. It's the degraded target EnsureDeposit falls back to when
// the full working set is unaffordable: the box term is sub-slot, so it is
// reachable for a wallet that can't add another slot, and without it the payer's
// first free open reverts forever.
//
// Returns 0 when the pool's sub-slot remainder already covers the term (or the
// app has no quota).
func quotaOnlyShortfall(ticketMbr, freeQuotaMbr uint64, dep escrow.PayerDeposit) uint64 {
	if freeQuotaMbr == 0 || ticketMbr == 0 {
		return 0
	}
	// Gross balance, same basis as DepositShortfall. Invariant to OpenTickets
	// either way (live tickets reserve whole slots, and subtracting whole
	// multiples of ticketMbr can't change a remainder), but stated on the same
	// basis as the sizing it degrades from so the two can't drift.
	remainder := dep.AlgoBalance % ticketMbr
	if remainder >= freeQuotaMbr {
		return 0
	}
	return freeQuotaMbr - remainder
}

// FreePoolHeadroom is the payer's UNCOMMITTED pool balance: the deposit less
// what live ticket boxes currently reserve, floored at 0 so a reserved figure
// exceeding the balance (shouldn't happen on chain) can't underflow.
//
// This is the ADMISSION basis — "can this payer open a ticket right now?" — and
// it is deliberately not the sizing basis. DepositShortfall sizes the pool
// against gross balance so transient load can't be mistaken for a funding gap;
// see its doc. Keep the two apart: conflating them is what made the pool grow
// with concurrency.
//
// Exported for the same reason DepositShortfall is: it is also the contract's
// cap on a withdraw, so `zs slots <n>` needs it to bound a shrink without
// building a wallet.
func FreePoolHeadroom(ticketMbr uint64, dep escrow.PayerDeposit) uint64 {
	reserved := dep.OpenTickets * ticketMbr
	if dep.AlgoBalance <= reserved {
		return 0
	}
	return dep.AlgoBalance - reserved
}

// EnsureDeposit makes sure the payer's prepaid pool is SIZED for `slots`
// concurrent ticket boxes (slots × mbrForTicket(), plus any free-quota box term
// still owed), opting in on first use and topping up the shortfall otherwise.
// Idempotent: a no-op (txid "", deposited 0) when the pool already holds that
// much. Utilization is not part of the target — tickets in flight have borrowed
// slots and return them at settle (see DepositShortfall).
//
// Before submitting, it checks the payer's spendable ALGO covers the shortfall
// + the deposit group fee (+ the opt-in MBR on a first deposit) and returns
// ErrDepositUnaffordable — naming the µALGO needed — if not, so the failure is
// actionable instead of an opaque "overspend" at algod admission. Returns the
// deposit txid and the µALGO deposited. Callers gate this on account.Funded()
// the same way they gate the USDC opt-in.
func (w *Wallet) EnsureDeposit(ctx context.Context, slots uint64) (txid string, deposited uint64, err error) {
	if slots == 0 {
		slots = DefaultDepositSlots
	}
	ticketMbr := w.pool.TicketMBR()
	if ticketMbr == 0 {
		return "", 0, errors.New("wallet: ensure-deposit: ticket MBR not loaded (call RefreshConfig first)")
	}

	dep, err := w.pool.ReadPayerDeposit(ctx, w.payerAddr)
	if err != nil {
		return "", 0, fmt.Errorf("wallet: ensure-deposit read: %w", err)
	}
	quotaDue := w.quotaMbrDue(ctx)
	shortfall := DepositShortfall(slots, ticketMbr, quotaDue, dep)
	if shortfall == 0 {
		return "", 0, nil // pool already covers the working set
	}
	optedIn, err := w.pool.IsPayerOptedIn(ctx, w.payerAddr)
	if err != nil {
		return "", 0, fmt.Errorf("wallet: ensure-deposit opt-in check: %w", err)
	}

	// Affordability pre-check: the deposit Payment moves `shortfall` µALGO into
	// the pool and the 2-tx group costs 2 × minTxnFee (pooled on the AppCall).
	// A first deposit also raises the payer's OWN account min-balance by the
	// local-schema opt-in MBR. Confirm spendable ALGO covers all three before
	// signing so we surface the exact µALGO needed rather than an opaque algod
	// "overspend".
	minFee, err := w.pool.MinTxnFee(ctx)
	if err != nil {
		return "", 0, fmt.Errorf("wallet: ensure-deposit min fee: %w", err)
	}
	need := shortfall + 2*minFee
	if !optedIn {
		need += depositOptInMBR
	}
	spendable, err := w.pool.SpendableMicroAlgos(ctx, w.payerAddr)
	if err != nil {
		return "", 0, fmt.Errorf("wallet: ensure-deposit balance check: %w", err)
	}
	if spendable < need {
		// Can't reach the full working set. Before giving up, try funding just
		// the free-quota box term if that's what the pool is missing: it is
		// SUB-SLOT (~0.0225 vs ~0.115 ALGO), so a wallet too thin for another
		// whole slot can still very plausibly afford it. Without this, a pool
		// sitting at N whole slots (notably one that predates the quota) fails
		// here, the caller's ≥1-free-slot fallback lets the request through, and
		// then every FIRST free open reverts with `insufficient MBR deposit for
		// free-quota box` — permanently, with nothing ever attempting the tiny
		// top-up that would fix it.
		//
		// Gated on the pool ALREADY backing at least one ticket slot. The box
		// term alone backs no ticket, so funding it for a pool that backs none
		// would leave the payer unable to open anything — free or paid — while
		// this returns nil, which latches depositReady in ensureDepositForServe
		// and makes `zs-proxy fund` report success. Such a pool needs the
		// actionable ErrDepositUnaffordable below instead.
		//
		// Gross balance, matching DepositShortfall: the question is whether the
		// pool is PROVISIONED for a ticket, not whether one is free this
		// instant. A fully-utilized pool (every slot on loan to a live ticket)
		// is correctly provisioned and gets its slots back at settle — refusing
		// to fund its quota box would strand it on the error path for the
		// duration of ordinary load.
		backedSlots := dep.AlgoBalance / ticketMbr
		if quotaOnly := quotaOnlyShortfall(ticketMbr, quotaDue, dep); backedSlots >= 1 && quotaOnly > 0 && quotaOnly < shortfall {
			quotaNeed := quotaOnly + 2*minFee
			if !optedIn {
				quotaNeed += depositOptInMBR
			}
			if spendable >= quotaNeed {
				signer := algo.SignWithAccountForATC(w.keystore, w.payerAddr)
				res, cerr := w.pool.ComposeDepositMbr(ctx, quotaOnly, !optedIn, signer, w.payerAddr)
				if cerr != nil {
					return "", 0, fmt.Errorf("wallet: ensure-deposit (free-quota only): %w", cerr)
				}
				// Deposited, but NOT to target — the slot shortfall is still
				// outstanding. Report that as ErrDepositBelowTarget alongside the
				// real txid/amount so callers can use the deposit (retry a
				// reverted open) without treating the pool as provisioned. A bare
				// nil here would latch depositReady and strand the pool below
				// target for the process lifetime.
				return res.TxID, quotaOnly, fmt.Errorf(
					"%w: deposited %d µALGO for the free-quota box, still %d µALGO short of %d slot(s) — add ALGO and re-run `zs-proxy fund`",
					ErrDepositBelowTarget, quotaOnly, shortfall-quotaOnly, slots)
			}
		}
		return "", 0, fmt.Errorf("%w: need %d µALGO (%d shortfall + %d fee%s), have %d µALGO spendable — fund the wallet with more ALGO",
			ErrDepositUnaffordable, need, shortfall, 2*minFee, optInNote(!optedIn), spendable)
	}

	signer := algo.SignWithAccountForATC(w.keystore, w.payerAddr)
	res, err := w.pool.ComposeDepositMbr(ctx, shortfall, !optedIn, signer, w.payerAddr)
	if err != nil {
		return "", 0, fmt.Errorf("wallet: ensure-deposit: %w", err)
	}
	return res.TxID, shortfall, nil
}

// optInNote annotates the affordability error when a first deposit also pays
// the local-schema opt-in MBR, so the breakdown adds up.
func optInNote(firstDeposit bool) string {
	if firstDeposit {
		return fmt.Sprintf(" + %d opt-in MBR", depositOptInMBR)
	}
	return ""
}

// WithdrawDeposit reclaims `amount` µALGO of unreserved pool headroom to
// the payer. The contract caps it at the available (non-reserved) balance
// and reverts otherwise.
func (w *Wallet) WithdrawDeposit(ctx context.Context, amount uint64) (string, error) {
	signer := algo.SignWithAccountForATC(w.keystore, w.payerAddr)
	res, err := w.escrow.ComposeWithdrawMbr(ctx, amount, signer, w.payerAddr)
	if err != nil {
		return "", fmt.Errorf("wallet: withdraw-deposit: %w", err)
	}
	return res.TxID, nil
}

// CloseDeposit closes the payer's pool and opts them out, refunding the
// remaining balance + the local-schema MBR. Reverts on chain while any
// ticket (incl. frozen) is still live (openTickets != 0).
func (w *Wallet) CloseDeposit(ctx context.Context) (string, error) {
	signer := algo.SignWithAccountForATC(w.keystore, w.payerAddr)
	res, err := w.escrow.ComposeCloseDeposit(ctx, signer, w.payerAddr)
	if err != nil {
		return "", fmt.Errorf("wallet: close-deposit: %w", err)
	}
	return res.TxID, nil
}

// decodeReceiptSig converts the receipt's base64 Sig field to the 64
// raw bytes the escrow contract passes to ed25519verify_bare.
func decodeReceiptSig(b64 string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode base64: %w", err)
	}
	if len(raw) != 64 {
		return nil, fmt.Errorf("receipt sig length %d, want 64", len(raw))
	}
	return raw, nil
}

// decodeTicketID converts the envelope's base64 ticket_id (24 chars
// with padding) back to the 16 raw bytes the contract's ABI expects.
func decodeTicketID(b64 string) ([]byte, error) {
	const rawLen = 16
	if b64 == "" {
		return nil, errors.New("ticket id is empty")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode ticket id base64: %w", err)
	}
	if len(raw) != rawLen {
		return nil, fmt.Errorf("ticket id decodes to %d bytes, want %d", len(raw), rawLen)
	}
	return raw, nil
}
