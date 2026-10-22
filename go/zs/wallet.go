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
	"math/bits"
	"sync"
	"sync/atomic"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/TxnLab/zerosignal/go/algo"
	"github.com/TxnLab/zerosignal/go/escrow"
	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/wire"
)

// Wallet drives the escrow payment path from the proxy side.
// One Wallet instance per process; shared across all requests.
// Per-request state lives on OpenHandle, which Wallet.Open returns
// and the dispatcher threads through its factories so the
// post-response verification path can call AckSettle or Protest with
// the right bound arguments.
type Wallet struct {
	// chain is every escrow call the wallet makes, so a test fakes it without
	// a live algod.
	chain     EscrowChain
	keystore  algo.MultipleWalletSigner
	payerAddr string
	log       *slog.Logger // nil: slog.Default()

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
// with the box-exists answer latched. See EscrowChain.FreeQuotaMbrDueFor.
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
	due := w.chain.FreeQuotaMbrDueFor(ctx, w.payerAddr)
	if due == 0 {
		w.quotaBoxKnown.Store(true)
	}
	return due
}

// WalletConfig groups the dependencies buildWallet assembles. Keeping
// this a struct lets the constructor evolve (e.g. add a retry policy
// or a metrics sink) without breaking call sites.
type WalletConfig struct {
	Escrow    *escrow.Client
	Keystore  algo.MultipleWalletSigner
	PayerAddr string
	// DepositSlots is the prepaid-MBR-pool working set (zs.concurrent_slots);
	// 0 falls back to DefaultDepositSlots.
	DepositSlots uint64
	// Logger receives the wallet's warnings; nil uses slog.Default().
	Logger *slog.Logger
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
		chain:        NewEscrowChain(cfg.Escrow),
		keystore:     cfg.Keystore,
		payerAddr:    cfg.PayerAddr,
		depositSlots: cfg.DepositSlots,
		log:          cfg.Logger,
	}, nil
}

func (w *Wallet) logger() *slog.Logger {
	if w.log == nil {
		return slog.Default()
	}
	return w.log
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
	if w == nil || w.chain == nil {
		return 0, errors.New("wallet: escrow client unavailable")
	}
	return w.chain.ProtocolFeeBps(ctx)
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
	// directly via algod's PendingTransactionInformation(txid). On Solana
	// it is payment_ref, the open transaction's id.
	AppCallTxID string
	// journaled is the ticket's journal row, set once it is written, so the
	// receipt update rewrites the same row.
	journaled TicketRecord
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
	// PaymentCommitted and ReceiptVerified so the caller (the TUI) sees
	// only what the payer actually paid in ALGO fees, not the
	// operator's pool. The total committed group fee remains
	// recoverable from algod / the indexer for audit.
	OpenFeesMicroalgos uint64
	// SignedGroup is the raw msgpack bytes of the submitted group —
	// retained for dispute evidence per SPEC.md §3b.
	SignedGroup [][]byte
	// OpenGroup is the completed group in escrow.EncodeOpenGroup's form, set
	// only by OpenForNode: nothing has been broadcast, and the sealed request
	// carries it for the node to submit. On Solana it is payment_open, the
	// signed offer, and SignedGroup holds its bytes.
	OpenGroup string

	// deliverAck hands the completed settle group to the node instead of
	// broadcasting it (wire.TakesSettleAck); nil keeps the broadcast. Set by
	// dispatch, which owns the transport.
	deliverAck func(ctx context.Context, ack wire.SettleAck) error

	wallet *Wallet
	// solana is the wallet that signed a Solana open, whose handle has no
	// settle path yet; nil on Algorand.
	solana *SolanaWallet
}

// detached is the error of a settle path called on a handle without an
// Algorand wallet.
func (h *OpenHandle) detached(what string) error {
	if h.solana != nil {
		return fmt.Errorf("wallet: %s on Solana is not supported yet", what)
	}
	return fmt.Errorf("wallet: %s on detached OpenHandle (test-only or misconstructed)", what)
}

// errNoSettleAckRoute is a deliverAck failure that sent nothing: no relay can
// carry the ack yet (every relay predates wire.SettleAckMinVersion). The ack
// then goes out as it did before 9.12, which costs exactly the old privacy.
var errNoSettleAckRoute = errors.New("zs: no relay serves the settle ack")

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
func (w *Wallet) Open(ctx context.Context, tk *ticket.Ticket, op Operator, presignedOpen string) (*OpenHandle, error) {
	return w.open(ctx, tk, op, presignedOpen, true)
}

// OpenForNode is Open for a node that submits the group itself
// (wire.SubmitsOpen): it verifies and signs the group but broadcasts nothing,
// so the payer's IP never reaches an algod alongside its address. The handle's
// OpenGroup carries the completed group for the sealed request.
//
// The open may still land after this returns, whenever the node submits it, so
// the caller arms the refund watchdog and journals the ticket exactly as after
// Open. The contract refuses an open past the ticket's expires_at, which bounds
// how long a node can hold it.
func (w *Wallet) OpenForNode(ctx context.Context, tk *ticket.Ticket, op Operator, presignedOpen string) (*OpenHandle, error) {
	return w.open(ctx, tk, op, presignedOpen, false)
}

func (w *Wallet) open(ctx context.Context, tk *ticket.Ticket, op Operator, presignedOpen string, submit bool) (*OpenHandle, error) {
	if tk == nil {
		return nil, errors.New("wallet: open: ticket is nil")
	}
	if op.ID == 0 {
		return nil, errors.New("wallet: open: operator id is unset")
	}
	if op.OwnerAddr == "" || op.SigningAddr == "" {
		return nil, errors.New("wallet: open: operator addresses incomplete")
	}
	if presignedOpen == "" {
		return nil, errors.New("wallet: open: presignedOpenGroup is empty (operator did not return a pre-signed open group on reserve)")
	}
	presignedOpenGroup, err := escrow.DecodeOpenGroup(presignedOpen)
	if err != nil {
		return nil, fmt.Errorf("wallet: open: decode presigned open group: %w", err)
	}

	ticketIDRaw, err := decodeTicketID(tk.TicketID)
	if err != nil {
		return nil, fmt.Errorf("wallet: decode ticket id: %w", err)
	}
	// VerifyReceipt refuses every receipt for a ticket id in any other
	// spelling, so opening one would only lock the escrow for a turn that can't
	// settle. TS's decoder already refuses it here. Checked at open only: the
	// journal and the watchdog decode with decodeTicketID, and an escrow an
	// older build opened under such an id must stay refundable.
	if canonical := base64.StdEncoding.EncodeToString(ticketIDRaw); canonical != tk.TicketID {
		return nil, fmt.Errorf("wallet: decode ticket id: %q is not the canonical spelling %q", tk.TicketID, canonical)
	}

	// Spec for the pre-sign verification of the node-composed group. Every
	// field comes from the signature-verified ticket or the chain-resolved
	// operator snapshot — never from the group itself. The chain-config
	// slice (app id/address, USDC asset, ticket MBR) is stamped by
	// the EscrowChain from the escrow client, its single source of truth.
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
	if !submit {
		// No retry here: nothing reached the chain, so a pool revert can only
		// surface at the node, which refuses with payment_verification_failed and
		// the dispatcher answers with RecheckDeposit.
		result, err := w.chain.CompletePresignedOpenGroup(presignedOpenGroup, signer, openSpec)
		if err != nil {
			return nil, fmt.Errorf("wallet: complete presigned open group: %w", err)
		}
		if len(result.TxIDs) != 2 {
			return nil, fmt.Errorf("wallet: escrow complete returned %d txids, want 2", len(result.TxIDs))
		}
		h := w.handleFor(tk, op, result)
		h.OpenGroup = result.Encoded
		return h, nil
	}
	result, err := w.chain.SubmitPresignedOpenGroup(ctx, presignedOpenGroup, signer, openSpec)
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
			// Partial success: some slots, or the free-quota box the payer's
			// FIRST free open trips on ('insufficient MBR deposit for free-quota
			// box'), are now funded, but the pool is still short of the working
			// set. Retry below, since the failing guard may now be satisfied,
			// but leave depositReady false so the next request re-attempts the
			// rest.
		default:
			deposited = 0 // nothing landed; the guard is unchanged, so don't retry
		}
		if deposited > 0 {
			result, err = w.chain.SubmitPresignedOpenGroup(ctx, presignedOpenGroup, signer, openSpec)
		}
		// The re-ensure's failure is the one the caller can act on (it names
		// the ALGO the pool needs), so it rides along with the revert; with
		// none, the pool already covers the working set and the revert is
		// exhaustion that waiting clears.
		if err != nil && derr != nil {
			err = fmt.Errorf("%w; topping up the ticket pool: %w", err, derr)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("wallet: submit presigned open group: %w", err)
	}
	if len(result.TxIDs) != 2 {
		return nil, fmt.Errorf("wallet: escrow submit returned %d txids, want 2", len(result.TxIDs))
	}
	return w.handleFor(tk, op, result), nil
}

func (w *Wallet) handleFor(tk *ticket.Ticket, op Operator, result escrow.OpenResult) *OpenHandle {
	return &OpenHandle{
		AppCallTxID:        result.TxIDs[1],
		GroupID:            result.GroupID,
		TicketID:           tk.TicketID,
		Operator:           op,
		MaxPrice:           tk.MaxPrice,
		OpenFeesMicroalgos: result.PayerFeeMicroalgos,
		SignedGroup:        result.SignedGroup,
		wallet:             w,
	}
}

// AckSettle is the payer's matching co-sign on an operator-initiated
// settle call. settleGroup is the node's group in its wire form, or "" for
// none; the caller checks that it decodes first (checkSettleGroupHeader), as
// one that doesn't fails the ack outright rather than going standalone. The
// contract enforces that:
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
// Before a standalone ack, and after the node's group fails to submit, it reads
// the ticket box for an operator claim, which no check has compared with the
// receipt on either path (AckResult.Claim).
func (h *OpenHandle) AckSettle(ctx context.Context, receipt *ticket.UsageReceipt, settleGroup string) (AckResult, error) {
	if h.wallet == nil {
		return AckResult{}, h.detached("ack-settle")
	}
	signer := algo.SignWithAccountForATC(h.wallet.keystore, h.wallet.payerAddr)
	// Whatever runs after the node's group failed runs on followCtx: the box
	// read, and the freeze or the payer's half it may call for. An ack
	// delivery the node held open until ctx's deadline would otherwise leave
	// them nothing.
	followCtx, cancelFollow := ctx, context.CancelFunc(func() {})
	defer func() { cancelFollow() }()
	return ackSettle(settleGroup != "", ackSettleDeps{
		spec: func() (escrow.SettleGroupSpec, error) { return h.settleGroupSpec(receipt) },
		submitGroup: func(spec escrow.SettleGroupSpec) (res escrow.CallResult, err error) {
			defer func() {
				if err != nil {
					followCtx, cancelFollow = followUpCtx(ctx)
				}
			}()
			// The caller checked that it decodes (checkSettleGroupHeader), so a
			// failure here is a group no node sent and surfaces as the error.
			presignedSettleGroup, err := escrow.DecodeSettleGroup(settleGroup)
			if err != nil {
				return escrow.CallResult{}, err
			}
			if h.deliverAck == nil {
				return h.wallet.chain.SubmitPresignedSettleGroup(ctx, presignedSettleGroup, signer, spec)
			}
			res, encoded, err := h.wallet.chain.CompletePresignedSettleGroup(presignedSettleGroup, signer, spec)
			if err != nil {
				return escrow.CallResult{}, err
			}
			err = h.deliverAck(ctx, wire.SettleAck{TicketID: h.TicketID, SettleGroup: encoded})
			if errors.Is(err, errNoSettleAckRoute) {
				// Broadcast the group already completed above rather than
				// verifying and signing it a second time (as the TS twin does).
				completed, derr := escrow.DecodeSettleGroup(encoded)
				if derr != nil {
					return escrow.CallResult{}, derr
				}
				if err := h.wallet.chain.SubmitSettleGroup(ctx, completed); err != nil {
					return escrow.CallResult{}, err
				}
				return res, nil
			}
			if err != nil {
				return escrow.CallResult{}, err
			}
			return res, nil
		},
		claim:      func() (ClaimVerdict, error) { return h.readClaim(followCtx, settleArgsOf(receipt)) },
		standalone: func() (escrow.CallResult, error) { return h.settleStandalone(followCtx, settleArgsOf(receipt)) },
		freeze:     func() (escrow.CallResult, error) { return h.settleOuterOnly(followCtx, settleArgsOf(receipt)) },
		half:       func() (escrow.CallResult, error) { return h.settleOuterOnly(followCtx, settleArgsOf(receipt)) },
		freezes:    h.wallet.resolvesFrozen(),
		log:        h.wallet.logger().With("operator_id", h.Operator.ID, "node_id", h.Operator.NodeID),
	})
}

// followUpCtx is a budget of settleSubmitTimeout of its own for the calls an
// ack makes after the node's group failed. Only ctx's cancellation carries
// over, not its deadline, which the failed attempt may have spent.
func followUpCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	fresh, cancel := context.WithTimeout(context.WithoutCancel(ctx), settleSubmitTimeout)
	cancelled := func() {
		if errors.Is(ctx.Err(), context.Canceled) {
			cancel()
		}
	}
	// AfterFunc runs on its own goroutine even for a ctx already done, so a
	// cancellation that came first is applied here, before any call.
	cancelled()
	stop := context.AfterFunc(ctx, cancelled)
	return fresh, func() { stop(); cancel() }
}

// resolvesFrozen is whether the deployed escrow can end a frozen ticket, so
// that a settle which freezes one does not lock its escrow for good.
func (w *Wallet) resolvesFrozen() bool {
	return w.chain != nil && w.chain.Config().ResolvesFrozen
}

// AckResult is what one AckSettle did.
type AckResult struct {
	TxID string
	// FeeMicroalgos is the network fee the payer's own transactions paid: 0
	// on the node's group, which pools the fee on its half, and the standalone
	// settle's fee otherwise.
	FeeMicroalgos uint64
	// GroupRejected is set when the node handed a settle group the payer's
	// checks refused (*escrow.SettleGroupRejectedError). It survives the
	// standalone fallback, so the caller can bar the node though the payment
	// settled. A spec-build failure (the payer's own decode) or a plain algod
	// error does not set it.
	GroupRejected bool
	// Claim is how the operator's claim on the box stood when the payer read
	// it: before a standalone ack, or after the node's group failed to
	// submit. ClaimUnread when the node's group carried the ack. On
	// ClaimContradicts nothing was sent. On ClaimOverclaims the payer's settle
	// was sent to freeze the ticket, unless the deployed escrow has no
	// resolveFrozen, when nothing was sent.
	Claim ClaimVerdict
	// PayerSettle is set when the payer's own settle was sent, or failed to
	// send, in place of the node's group: standalone, to freeze an
	// over-claim, or as its half on an open box after the group failed.
	PayerSettle bool
	// Frozen is set when the payer's settle went out to freeze an over-claim.
	Frozen bool
}

// ackSettleDeps is the open handle's ways of putting the ack on chain and of
// reading the claim it answers, injected so ackSettle is the decision alone:
// the code testdata/ack_settle_vectors.json pins and the TS SDK mirrors as
// ackSettle in sdk/src/ack.ts.
type ackSettleDeps struct {
	spec        func() (escrow.SettleGroupSpec, error)
	submitGroup func(escrow.SettleGroupSpec) (escrow.CallResult, error)
	claim       func() (ClaimVerdict, error)
	standalone  func() (escrow.CallResult, error)
	// freeze is standalone paid for the freeze an over-claim turns it into.
	freeze func() (escrow.CallResult, error)
	// half is the payer's half on an open box, paid the same way: a first
	// half finalizes nothing.
	half func() (escrow.CallResult, error)
	// freezes is whether the deployed escrow has resolveFrozen. Without it
	// neither freeze nor half is sent: a frozen ticket's escrow would be
	// locked for good, and a half on an open box freezes the ticket when the
	// node's half differs.
	freezes bool
	log     *slog.Logger
}

// readClaim is d.claim, ClaimUnread without one and ClaimUnreadable when the
// read fails.
func (d ackSettleDeps) readClaim() ClaimVerdict {
	if d.claim == nil {
		return ClaimUnread
	}
	v, err := d.claim()
	if err != nil {
		d.log.Debug("ack-settle: operator claim unreadable", "err", err)
		return ClaimUnreadable
	}
	return v
}

// ackSettle is AckSettle's decision between the node's pre-signed group and
// the payer's standalone ack. atomic is whether the node sent a group that
// decoded.
func ackSettle(atomic bool, d ackSettleDeps) (AckResult, error) {
	var groupRejected bool
	// Atomic settle path: the operator's pre-signed gtxn[0] arrived
	// in the response's X-Zs-Settle-Group header. We VERIFY the
	// node-composed group against the receipt-derived spec, sign the
	// payer-ack member, and submit the 2-tx group; payer's outer fee
	// is 0 (operator's gtxn[0] over-fee covers the entire group).
	if atomic {
		spec, specErr := d.spec()
		if specErr != nil {
			// Spec build failed (address / ticket-id decode). Unreachable for a
			// handle Open returned, since Open decoded the same three values
			// before opening the ticket. Log and fall through to the
			// standalone receipt-sourced ack rather than block settlement. NOT a
			// node fault, so groupRejected stays false.
			d.log.Warn("ack-settle: settle-group spec build failed; falling back to standalone", "err", specErr)
		} else {
			res, subErr := d.submitGroup(spec)
			if subErr == nil {
				return AckResult{TxID: res.TxID, FeeMicroalgos: res.PayerFeeMicroalgos}, nil
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
				d.log.Warn("ack-settle: operator settle group REJECTED; refusing atomic path, falling back to standalone ack",
					"field", rejected.Field, "detail", rejected.Detail)
				groupRejected = true
				// fall through to the standalone ack below
			} else {
				// A non-rejection submit error: an algod outage, a pool eval
				// failure, or an ack delivery the node answered with an error.
				// The node may still land the group, so no settle that could
				// finalize goes out in its place at the payer's expense. Two
				// box states call for the payer's settle at one fee:
				//   - An over-claim. The node's half already stands at another
				//     figure, so its group can only revert as a same-side
				//     re-claim, and the claim lapses at the deadline unless the
				//     payer freezes it inside the window.
				//   - An open box. The payer's half at the receipt goes first,
				//     so an operator half the node posts later at another figure
				//     freezes the ticket rather than lapsing at that figure. A
				//     node group landing after it reverts whole, and the node's
				//     driver then posts its own half, which at the receipt
				//     finalizes the ticket.
				// Both can freeze the ticket, so neither is sent to an escrow
				// that cannot resolve a frozen one.
				claim := d.readClaim()
				switch {
				case !d.freezes:
				case claim == ClaimOverclaims:
					d.log.Warn("ack-settle: settle group failed to submit over an operator claim above the receipt; freezing the ticket", "err", subErr)
					return sendAck(d.freeze, false, claim, true)
				case claim == ClaimOpen:
					d.log.Warn("ack-settle: settle group failed to submit over an open ticket; posting the payer's half at the receipt", "err", subErr)
					return sendAck(d.half, false, claim, false)
				}
				return AckResult{Claim: claim}, fmt.Errorf("wallet: ack-settle (atomic): %w", subErr)
			}
		}
	}

	// The standalone ack is checked against nothing else: the node's group
	// is verified before the payer signs it, but a node that posts its own
	// first half and then sends no group, or one the checks refuse, has the
	// payer settle into a claim nobody compared with the receipt. So read it.
	claim := d.readClaim()
	switch claim {
	case ClaimContradicts:
		// The settle would freeze a ticket whose claim takes no more than the
		// receipt. Nothing is sent, so the refund watchdog keeps the ticket.
		return AckResult{GroupRejected: groupRejected, Claim: claim}, nil
	case ClaimOverclaims:
		if !d.freezes {
			// The settle would freeze the ticket, and an escrow without
			// resolveFrozen keeps a frozen ticket's max_price locked for good:
			// the claim's lapse costs the payer less. Nothing is sent.
			return AckResult{GroupRejected: groupRejected, Claim: claim}, nil
		}
		return sendAck(d.freeze, groupRejected, claim, true)
	}

	// Standalone fallback: pre-update operator that doesn't emit the
	// settle-group header, or atomic path failed somewhere upstream. Here the
	// PAYER funds the call — 1 outer + finalize's op-up + the disbursement
	// inners this settle actually fires (sized from AmountCharged/MaxPrice).
	return sendAck(d.standalone, groupRejected, claim, false)
}

// sendAck submits the payer's own settle through send and reports it. frozen
// is whether the settle freezes the ticket once it lands.
func sendAck(send func() (escrow.CallResult, error), groupRejected bool, claim ClaimVerdict, frozen bool) (AckResult, error) {
	res, err := send()
	if err != nil {
		return AckResult{GroupRejected: groupRejected, Claim: claim, PayerSettle: true}, fmt.Errorf("wallet: ack-settle: %w", err)
	}
	return AckResult{
		TxID: res.TxID, FeeMicroalgos: res.PayerFeeMicroalgos, GroupRejected: groupRejected, Claim: claim,
		PayerSettle: true, Frozen: frozen,
	}, nil
}

// readClaim is how the operator's claim on the ticket's box stands against a.
func (h *OpenHandle) readClaim(ctx context.Context, a SettleArgs) (ClaimVerdict, error) {
	raw, err := decodeTicketID(h.TicketID)
	if err != nil {
		return ClaimUnreadable, fmt.Errorf("decode ticket id: %w", err)
	}
	box, err := h.wallet.chain.ReadTicketBox(ctx, raw)
	if err != nil {
		return ClaimUnreadable, err
	}
	return judgeClaim(a, box), nil
}

// freezeOverclaim sends the payer's settle at the receipt's values when the
// operator's claim on the box takes more than the receipt charges, which
// freezes the ticket, and sends nothing otherwise. It is the protest's
// fallback. A contract that binds a protest to the operator's pending claim
// refuses one whose receipt digest differs from it, and that is exactly the
// receipt a node over-claiming against its own receipt has handed out. On an
// escrow without resolveFrozen the claim is still read and reported, but
// nothing is sent.
func (h *OpenHandle) freezeOverclaim(ctx context.Context, receipt *ticket.UsageReceipt) (txid string, feeMicroalgos uint64, claim ClaimVerdict, err error) {
	if h.wallet == nil {
		return "", 0, ClaimUnreadable, h.detached("freeze")
	}
	a := settleArgsOf(receipt)
	claim, err = h.readClaim(ctx, a)
	if err != nil || claim != ClaimOverclaims {
		return "", 0, claim, err
	}
	if !h.wallet.resolvesFrozen() {
		return "", 0, claim, errNoResolveFrozen
	}
	res, err := h.settleOuterOnly(ctx, a)
	if err != nil {
		return "", 0, claim, fmt.Errorf("wallet: freeze: %w", err)
	}
	return res.TxID, res.PayerFeeMicroalgos, claim, nil
}

// settleArgsOf is what the payer co-signs on settle() for a verified receipt.
// Every value comes straight from the operator's signed receipt, so the
// payer's half matches the operator's verbatim; a mismatch on any one freezes
// the ticket.
func settleArgsOf(receipt *ticket.UsageReceipt) SettleArgs {
	return SettleArgs{
		AmountCharged:      receipt.AmountCharged,
		ReceiptDigest:      ticket.ReceiptSigDigest(receipt),
		TtftMs:             receipt.TtftMs,
		DecodeMs:           receipt.DecodeMs,
		InputTokens:        receipt.ActualInputCount,
		OutputTokens:       receipt.ActualOutputCount,
		OutputUsageType:    receipt.OutputUsageType,
		AuxOutputUsageType: receipt.AuxOutputUsageType,
		AuxOutputCount:     receipt.AuxOutputCount,
	}
}

// settleStandalone submits the payer's settle() on its own, signed and paid
// by the payer. The live ack falls back to it, and the reconciler re-fires it
// from a journaled receipt.
func (h *OpenHandle) settleStandalone(ctx context.Context, a SettleArgs) (escrow.CallResult, error) {
	return h.settleAlone(ctx, a, false)
}

// settleOuterOnly is settleStandalone where the payer read the box and expects
// the call not to finalize: a freeze of an operator claim that takes more
// than a, or the payer's first half on an open box. It pays for the outer
// call alone.
func (h *OpenHandle) settleOuterOnly(ctx context.Context, a SettleArgs) (escrow.CallResult, error) {
	return h.settleAlone(ctx, a, true)
}

// errNoResolveFrozen is why a freeze was not sent: the deployed escrow has no
// resolveFrozen, so a frozen ticket's escrow would be locked for good.
var errNoResolveFrozen = errors.New("wallet: freeze not sent: the deployed escrow has no resolveFrozen")

func (h *OpenHandle) settleAlone(ctx context.Context, a SettleArgs, outerFeeOnly bool) (escrow.CallResult, error) {
	ticketIDRaw, err := decodeTicketID(h.TicketID)
	if err != nil {
		return escrow.CallResult{}, fmt.Errorf("decode ticket id: %w", err)
	}
	signer := algo.SignWithAccountForATC(h.wallet.keystore, h.wallet.payerAddr)
	args := h.payerSettleArgs(ticketIDRaw, a)
	args.OuterFeeOnly = outerFeeOnly
	return h.wallet.chain.ComposeSettleStandalone(ctx, args, signer, h.wallet.payerAddr)
}

// payerSettleArgs is the payer's half of settle() for a. The contract freezes
// the ticket when any value differs from the operator's half.
func (h *OpenHandle) payerSettleArgs(ticketIDRaw []byte, a SettleArgs) escrow.SettleArgs {
	return escrow.SettleArgs{
		TicketIDRaw:        ticketIDRaw,
		AmountCharged:      a.AmountCharged,
		MaxPrice:           h.MaxPrice,
		ReceiptDigest:      a.ReceiptDigest,
		TtftMs:             a.TtftMs,
		DecodeMs:           a.DecodeMs,
		InputCount:         a.InputTokens,
		OutputCount:        a.OutputTokens,
		OutputUsageType:    uint64(a.OutputUsageType),
		AuxOutputUsageType: uint64(a.AuxOutputUsageType),
		AuxOutputCount:     a.AuxOutputCount,
		AsOperator:         false,
		PayerAddr:          h.wallet.payerAddr,
		OperatorOwnerAddr:  h.Operator.OwnerAddr,
		OperatorID:         h.Operator.ID,
		NodeID:             h.Operator.NodeID,
	}
}

// walletChain is the reconciler's ticketChain: each call acts as the payer on
// a ticket known only from its journal row and, where it has one, its box.
type walletChain struct{ w *Wallet }

func (c walletChain) readBox(ctx context.Context, ticketID string) (*escrow.TicketRecord, error) {
	raw, err := decodeTicketID(ticketID)
	if err != nil {
		return nil, err
	}
	return c.w.chain.ReadTicketBox(ctx, raw)
}

// handle is an OpenHandle for rec. The box's operator owner is the one the
// contract pays, so it is preferred over none.
func (c walletChain) handle(rec TicketRecord, box *escrow.TicketRecord) *OpenHandle {
	op := Operator{ID: rec.Target.Op, NodeID: rec.Target.Node}
	if box != nil {
		op.OwnerAddr = box.OperatorOwnerAddr
	}
	return &OpenHandle{TicketID: rec.TicketID, Operator: op, MaxPrice: rec.MaxPrice, wallet: c.w}
}

func (c walletChain) refund(ctx context.Context, rec TicketRecord) (string, error) {
	return c.handle(rec, nil).RefundInactive(ctx)
}

func (c walletChain) lapse(ctx context.Context, rec TicketRecord, box *escrow.TicketRecord) (string, error) {
	return c.handle(rec, box).SettleLapsed(ctx)
}

func (c walletChain) resettle(ctx context.Context, rec TicketRecord, box *escrow.TicketRecord) (string, error) {
	if rec.Settle == nil {
		return "", errors.New("wallet: re-settle without a recorded receipt")
	}
	res, err := c.handle(rec, box).settleStandalone(ctx, *rec.Settle)
	if err != nil {
		return "", fmt.Errorf("wallet: re-settle: %w", err)
	}
	return res.TxID, nil
}

func (c walletChain) freezes() bool { return c.w.resolvesFrozen() }

func (c walletChain) freeze(ctx context.Context, rec TicketRecord, box *escrow.TicketRecord, a SettleArgs) (string, error) {
	res, err := c.handle(rec, box).settleOuterOnly(ctx, a)
	if err != nil {
		return "", fmt.Errorf("wallet: freeze: %w", err)
	}
	return res.TxID, nil
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
	// The key routing saw, not the node box's current one the contract now
	// accepts: a node that rotates mid-turn gets its group refused here, and
	// the ticket finishes on its driver path, which is the safe direction.
	opSigningAddr, err := types.DecodeAddress(h.Operator.SigningAddr)
	if err != nil {
		return escrow.SettleGroupSpec{}, fmt.Errorf("decode operator signing addr: %w", err)
	}
	return escrow.SettleGroupSpec{
		AppID:               h.wallet.chain.Config().AppID,
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
func (h *OpenHandle) Protest(ctx context.Context, receipt *ticket.UsageReceipt, excerpt []byte, reason escrow.ProtestReasonCode) (string, uint64, error) {
	if h.wallet == nil {
		return "", 0, h.detached("protest")
	}
	ticketIDRaw, err := decodeTicketID(h.TicketID)
	if err != nil {
		return "", 0, fmt.Errorf("wallet: protest decode ticket id: %w", err)
	}
	receiptSig, err := decodeReceiptSig(receipt.Sig)
	if err != nil {
		return "", 0, fmt.Errorf("wallet: protest decode receipt sig: %w", err)
	}
	receiptDigest := ticket.ReceiptSigDigest(receipt)

	signer := algo.SignWithAccountForATC(h.wallet.keystore, h.wallet.payerAddr)
	res, err := h.wallet.chain.ComposeProtest(ctx, escrow.ProtestArgs{
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
		return "", 0, fmt.Errorf("wallet: protest: %w", err)
	}
	return res.TxID, res.PayerFeeMicroalgos, nil
}

// RefundInactive is the payer's escape hatch when no operator claim
// ever posted and the refund window has opened. Exposed on the
// handle so timeout logic can drive it without re-deriving the
// ticket id.
func (h *OpenHandle) RefundInactive(ctx context.Context) (string, error) {
	if h.wallet == nil {
		return "", h.detached("refund-inactive")
	}
	ticketIDRaw, err := decodeTicketID(h.TicketID)
	if err != nil {
		return "", fmt.Errorf("wallet: refund-inactive decode ticket id: %w", err)
	}
	signer := algo.SignWithAccountForATC(h.wallet.keystore, h.wallet.payerAddr)
	res, err := h.wallet.chain.ComposeRefundInactive(ctx, escrow.RefundInactiveArgs{
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
		return "", h.detached("settle-lapsed")
	}
	ticketIDRaw, err := decodeTicketID(h.TicketID)
	if err != nil {
		return "", fmt.Errorf("wallet: settle-lapsed decode ticket id: %w", err)
	}
	signer := algo.SignWithAccountForATC(h.wallet.keystore, h.wallet.payerAddr)
	res, err := h.wallet.chain.ComposeSettleLapsed(ctx, escrow.SettleLapsedArgs{
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
// spendable ALGO can't complete another slot + the deposit group fee (+ the
// opt-in MBR on a first deposit), and nothing smaller is worth depositing.
// Distinct from a deposit that fails at algod:
// this is caught BEFORE submit so callers (the CLI, the dispatch 402 path) can
// name the µALGO needed instead of surfacing an opaque "overspend". Its message
// already contains the actionable detail; callers can errors.Is to branch.
var ErrDepositUnaffordable = errors.New("wallet: insufficient ALGO to fund the prepaid MBR pool")

// ErrDepositBelowTarget is the sentinel EnsureDeposit returns when it DID
// deposit — the returned txid and `deposited` are real and the funds are in the
// pool — but the pool is still short of the requested working set: the wallet
// afforded only some of the slots, or only the sub-slot quota term
// (planDeposit).
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
	// its own pool guard: the honest 429 mbr_pool_exhausted when the payer
	// submits the open, or the node's 402 payment_verification_failed (with a
	// deposit recheck) when the node does. Any other failure (chain read
	// error, unrelated) stays fatal.
	//
	// ErrDepositBelowTarget takes the same branch, and that is the whole reason
	// it isn't a nil error: a partial deposit (some slots, or the quota term
	// alone) leaves the pool under target exactly like an unaffordable one, so
	// it must reach the serving path the same way — usable now, re-attempted
	// next request — rather than latching depositReady and freezing the pool
	// where it stands.
	if errors.Is(err, ErrDepositUnaffordable) || errors.Is(err, ErrDepositBelowTarget) {
		if free, ferr := w.freeDepositSlots(ctx); ferr == nil && free >= 1 {
			return nil
		}
	}
	return err
}

// PrepareDeposit makes sure the payer holds the prepaid pool's opt-in before a
// reserve, the one thing a node checks there. It deposits only for a payer who
// isn't opted in. Topping up an opted-in pool short of its working set is left
// to Open: such a pool never latches depositReady, so doing it here too would
// repeat the whole funding pass on every request. Once the pool is ready it
// reads nothing.
func (w *Wallet) PrepareDeposit(ctx context.Context) error {
	w.depositMu.Lock()
	ready := w.depositReady
	w.depositMu.Unlock()
	if ready {
		return nil
	}
	optedIn, err := w.chain.IsPayerOptedIn(ctx, w.payerAddr)
	if err != nil {
		return fmt.Errorf("wallet: prepaid pool opt-in check: %w", err)
	}
	if optedIn {
		return nil
	}
	return w.ensureDepositForServe(ctx)
}

// RecheckDeposit clears depositReady, so the next PrepareDeposit reads the
// payer's escrow-app opt-in again and deposits if it's gone. Open's revert
// path does the same, but a node that refuses the reserve for a missing
// opt-in ends the request before any open.
func (w *Wallet) RecheckDeposit() {
	w.depositMu.Lock()
	w.depositReady = false
	w.depositMu.Unlock()
}

// freeDepositSlots reports how many additional ticket boxes the prepaid pool
// can currently back: (AlgoBalance − OpenTickets × ticketMbr) / ticketMbr. An
// open needs only ONE free slot to commit, so ensureDepositForServe uses this
// to tell a genuinely-unaffordable open (zero headroom → fatal) apart from a
// pool that just can't reach its full working-set target but can still serve
// the request.
func (w *Wallet) freeDepositSlots(ctx context.Context) (uint64, error) {
	ticketMbr := w.chain.TicketMBR()
	if ticketMbr == 0 {
		return 0, errors.New("wallet: free-deposit-slots: ticket MBR not loaded (call RefreshConfig first)")
	}
	dep, err := w.chain.ReadPayerDeposit(ctx, w.payerAddr)
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
	return w.chain.ReadPayerDeposit(ctx, w.payerAddr)
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
	ticketMbr := w.chain.TicketMBR()
	if ticketMbr == 0 {
		return 0, false, errors.New("wallet: deposit-shortfall: ticket MBR not loaded (call RefreshConfig first)")
	}
	dep, err := w.chain.ReadPayerDeposit(ctx, w.payerAddr)
	if err != nil {
		return 0, false, fmt.Errorf("wallet: deposit-shortfall read: %w", err)
	}
	optedIn, err := w.chain.IsPayerOptedIn(ctx, w.payerAddr)
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
// The TS SDK's planMbrDeposit, which the client funds through, sizes off gross
// balance too (vectored with planDeposit). The proxy is the payer's own
// localhost twin of the client, so the two must not disagree about how much
// ALGO the same wallet needs.
//
// The trade this accepts: a FROZEN ticket holds its slot until the admin's
// resolveFrozen deletes the box, so it costs one slot of the working set for
// as long as it stays frozen, and nothing re-grows it. That is the honest
// reading. The pool is genuinely smaller until the arbiter acts, the host can
// name the frozen ticket, and the fix is to raise the concurrent-slot count or
// get the ticket resolved — not to have every payer silently inflate its
// deposit on every busy moment to hide a rare, arbiter-bound case. `freeDepositSlots` (admission: "can I open one right now?") still
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
// any slot shortfall. It's the degraded target planDeposit falls back to when
// no whole slot is affordable: the box term is sub-slot, so it is
// reachable for a wallet that can't add another slot, and without it the payer's
// first free open reverts forever.
//
// Returns 0 when the pool's sub-slot remainder already covers the term (or the
// app has no quota).
func quotaOnlyShortfall(ticketMbr, freeQuotaMbr uint64, dep escrow.PayerDeposit) uint64 {
	// Gross balance, same basis as DepositShortfall. Invariant to OpenTickets
	// either way (live tickets reserve whole slots, and subtracting whole
	// multiples of ticketMbr can't change a remainder), but stated on the same
	// basis as the sizing it degrades from so the two can't drift.
	return quotaRemainderShortfall(ticketMbr, freeQuotaMbr, dep.AlgoBalance)
}

// quotaRemainderShortfall is the quota term a pool of gross balance doesn't
// already cover with what it holds past its whole slots.
func quotaRemainderShortfall(unit, quotaDue, gross uint64) uint64 {
	if quotaDue == 0 || unit == 0 {
		return 0
	}
	remainder := gross % unit
	if remainder >= quotaDue {
		return 0
	}
	return quotaDue - remainder
}

// depositPlan is what one funding pass does to the pool. Amount > 0 deposits
// that much, and BelowTarget says the pool is still short of the working set
// after it. Amount == 0 below target means the wallet can't afford the next
// useful deposit: Unaffordable when the pool backs no slot (it can't serve),
// BelowTarget when it backs one (it serves on what it has). EnsureDeposit
// returns ErrDepositUnaffordable for both; Unaffordable records which, for the
// vectors.
type depositPlan struct {
	Amount       uint64
	BelowTarget  bool
	Unaffordable bool
	// Need is what the next useful deposit costs the wallet: the free-quota
	// term a pool backing a slot still lacks, else what the pool's part slot
	// lacks of a whole one; plus the
	// 2-txn group fee and, on a first deposit, the opt-in MBR. Set when nothing
	// is deposited for want of ALGO.
	Need uint64
}

// planDeposit sizes a funding pass, the rule the chat app had before it moved
// to the SDK: the working set is an ideal, not a requirement, so a wallet that can't reach
// it funds as many whole slots as it can afford. A sponsored trial account is
// seeded with exactly enough for two; an all-or-nothing rule would leave it
// with none.
//
//   - Whole slots first, up to `slots`, counted out of the pool and spendable
//     ALGO together (less the group fee and, on a first deposit, the opt-in
//     MBR), so a part slot already in the pool counts toward the next one.
//   - The free-quota term rides on top only if the wallet still covers it.
//     Slots serve requests and the box alone serves none, so the term is the
//     one dropped at the boundary; the next pass funds it on its own, below.
//   - No whole slot affordable: fund just the sub-slot quota term if that is
//     what the pool lacks and the pool already backs a slot. A box with no slot
//     is useless, and such a pool needs the actionable "add ALGO" error.
//
// Sized on gross AlgoBalance throughout; see DepositShortfall. Pinned by
// testdata/deposit_plan_vectors.json, which the TS SDK's planMbrDeposit
// replays.
func planDeposit(slots, ticketMbr, quotaDue uint64, dep escrow.PayerDeposit, optedIn bool, spendable, minFee uint64) depositPlan {
	overhead := 2 * minFee
	if !optedIn {
		overhead += depositOptInMBR
	}
	return planPoolDeposit(slots, ticketMbr, quotaDue, dep.AlgoBalance, overhead, spendable)
}

// planPoolDeposit is planDeposit's rule over either rail's pool: unit is what
// one ticket holds (box MBR, or rent), gross what the pool backs counting
// live tickets, and overhead what a deposit costs the wallet past its amount.
// planRentDeposit sizes the Solana pool through it.
func planPoolDeposit(slots, unit, quotaDue, gross, overhead, spendable uint64) depositPlan {
	target := poolTarget(slots, unit, quotaDue)
	if gross >= target {
		return depositPlan{}
	}
	var net uint64 // spendable past the overhead; 0 when the overhead isn't covered
	if spendable > overhead {
		net = spendable - overhead
	}
	// The next slot costs only what the pool's part slot lacks.
	need := unit - gross%unit + overhead

	current := gross / unit
	reach, carry := bits.Add64(gross, net, 0)
	if carry != 0 {
		reach = math.MaxUint64
	}
	targetSlots := min(reach/unit, slots)
	if targetSlots <= current {
		quota := quotaRemainderShortfall(unit, quotaDue, gross)
		if current >= 1 && quota > 0 {
			if net >= quota {
				return depositPlan{Amount: quota, BelowTarget: gross+quota < target}
			}
			// The box term is what this pool lacks first, and it is far
			// cheaper than a slot; asking for a slot would overstate it.
			return depositPlan{BelowTarget: true, Need: quota + overhead}
		}
		if current >= 1 {
			return depositPlan{BelowTarget: true, Need: need}
		}
		return depositPlan{Unaffordable: true, Need: need}
	}
	amount := targetSlots*unit - gross
	if net >= amount+quotaDue {
		amount += quotaDue
	}
	return depositPlan{Amount: amount, BelowTarget: gross+amount < target}
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
// A wallet that can't reach the working set funds as many whole slots as it
// affords (planDeposit), returning ErrDepositBelowTarget with the real txid and
// amount. One that can't afford even a slot gets ErrDepositUnaffordable, naming
// the µALGO needed, before anything is signed. Returns the deposit txid and the
// µALGO deposited. Callers gate this on account.Funded() the same way they gate
// the USDC opt-in.
func (w *Wallet) EnsureDeposit(ctx context.Context, slots uint64) (txid string, deposited uint64, err error) {
	if slots == 0 {
		slots = DefaultDepositSlots
	}
	ticketMbr := w.chain.TicketMBR()
	if ticketMbr == 0 {
		return "", 0, errors.New("wallet: ensure-deposit: ticket MBR not loaded (call RefreshConfig first)")
	}

	dep, err := w.chain.ReadPayerDeposit(ctx, w.payerAddr)
	if err != nil {
		return "", 0, fmt.Errorf("wallet: ensure-deposit read: %w", err)
	}
	quotaDue := w.quotaMbrDue(ctx)
	shortfall := DepositShortfall(slots, ticketMbr, quotaDue, dep)
	if shortfall == 0 {
		return "", 0, nil // pool already covers the working set
	}
	optedIn, err := w.chain.IsPayerOptedIn(ctx, w.payerAddr)
	if err != nil {
		return "", 0, fmt.Errorf("wallet: ensure-deposit opt-in check: %w", err)
	}

	minFee, err := w.chain.MinTxnFee(ctx)
	if err != nil {
		return "", 0, fmt.Errorf("wallet: ensure-deposit min fee: %w", err)
	}
	spendable, err := w.chain.SpendableMicroAlgos(ctx, w.payerAddr)
	if err != nil {
		return "", 0, fmt.Errorf("wallet: ensure-deposit balance check: %w", err)
	}

	// Sized before signing, so a wallet that can't afford a slot gets the µALGO
	// it needs rather than an opaque algod "overspend".
	plan := planDeposit(slots, ticketMbr, quotaDue, dep, optedIn, spendable, minFee)
	if plan.Amount == 0 {
		// Nothing deposited for want of ALGO. A pool that backs a slot can still
		// serve (ensureDepositForServe checks for a free one); one that backs
		// none can't.
		backed := dep.AlgoBalance / ticketMbr
		what, part := "one more slot", ticketMbr-dep.AlgoBalance%ticketMbr
		if q := quotaOnlyShortfall(ticketMbr, quotaDue, dep); backed >= 1 && q > 0 {
			what, part = "the free-quota box", q
		}
		return "", 0, fmt.Errorf("%w: the pool backs %d of %d slot(s); %s needs %d µALGO (%d + %d fee%s), have %d µALGO spendable — fund the wallet with more ALGO",
			ErrDepositUnaffordable, backed, slots, what, plan.Need, part, 2*minFee, optInNote(!optedIn), spendable)
	}
	signer := algo.SignWithAccountForATC(w.keystore, w.payerAddr)
	res, err := w.chain.ComposeDepositMbr(ctx, plan.Amount, !optedIn, signer, w.payerAddr)
	if err != nil {
		return "", 0, fmt.Errorf("wallet: ensure-deposit: %w", err)
	}
	if plan.BelowTarget {
		// Deposited, but not to target. Report that as ErrDepositBelowTarget
		// alongside the real txid and amount, so callers can use the deposit
		// (retry a reverted open) without treating the pool as provisioned: a
		// bare nil would latch depositReady and strand the pool below target
		// for the process lifetime.
		return res.TxID, plan.Amount, fmt.Errorf(
			"%w: deposited %d µALGO, still %d µALGO short of %d slot(s) — add ALGO and deposit again",
			ErrDepositBelowTarget, plan.Amount, shortfall-min(plan.Amount, shortfall), slots)
	}
	return res.TxID, plan.Amount, nil
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
	res, err := w.chain.ComposeWithdrawMbr(ctx, amount, signer, w.payerAddr)
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
	res, err := w.chain.ComposeCloseDeposit(ctx, signer, w.payerAddr)
	if err != nil {
		return "", fmt.Errorf("wallet: close-deposit: %w", err)
	}
	// The payer is opted out now, and a node may refuse its next reserve
	// for that, so the next request must not skip the deposit.
	w.depositMu.Lock()
	w.depositReady = false
	w.depositMu.Unlock()
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
