/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package escrow

import (
	"context"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"

	protoalgod "github.com/TxnLab/zerosignal/go/algod"
)

// Client drives calls against a deployed ZeroSignalEscrow application.
// Holds the AppID + derived escrow address, an algod client, and
// lazily-cached config read once from the contract (TicketMBRAndFees,
// UsdcAssetID, HayAssetID, Treasury).
type Client struct {
	AppID   uint64
	AppAddr types.Address
	Algod   protoalgod.Client

	// TicketMbr is the ALGO amount the payer locks alongside the USDC
	// maxPrice in the open() group's first member (the Payment txn).
	// It is exactly the box MBR — no settlement-inner-txn pre-fund
	// anymore; disbursement fees pool from the settle caller's outer
	// fee in the new design (see SPEC.md "Operator authentication").
	// Loaded once from the contract's readonly mbrForTicket method via
	// RefreshConfig and cached.
	TicketMbr uint64

	// FreeQuotaMbr is the one-time microALGO a payer's prepaid pool must cover,
	// on top of their ticket slots, before their FIRST free (maxPrice == 0)
	// ticket: open() creates that payer's free-quota box and permanently debits
	// this from their pool credit. Loaded via RefreshConfig; 0 against an app
	// that predates the quota (nothing to fund).
	//
	// Unlike TicketMbr this is never returned: the box is never deleted, which
	// is what makes the quota un-resettable. Deposit sizing should go through
	// FreeQuotaMbrDueFor rather than reading this raw value — it drops the term
	// once the payer HAS a box, so the pool doesn't carry an idle copy of a
	// charge that can never recur. Note the term is SUB-SLOT (well under one
	// ticket MBR), so slot-granular sizing can't express it: a funding path that
	// only deposits whole slots will never acquire the box for a pool sitting at
	// exactly N slots.
	FreeQuotaMbr uint64

	// UsdcAssetID is the USDC ASA the contract is configured to escrow.
	// Loaded from the contract's `usdcAssetId` global state via
	// RefreshConfig / RefreshAssetIDs. Required as the xferAsset for
	// the open group's AssetTransfer member, and as a ForeignAssets
	// reference on settle / settleLapsed / refundInactive (the contract
	// fires inner USDC transfers from those paths).
	UsdcAssetID uint64

	// HayAssetID is the HAY ASA the contract reads payer balance from
	// for the protocol-fee tier discount in finalizeSettlement. Loaded
	// from the contract's `hayAssetId` global state via RefreshConfig
	// / RefreshAssetIDs. Zero is a valid value — it disables the HAY
	// tier read at the contract level — so the foreign-assets array
	// only includes it when non-zero.
	HayAssetID uint64

	// HayOracleAppID and StakingAppID are the HAY price-oracle and HAY
	// staking applications the contract reads when snapshotting the
	// payer's discount at open() (getHayDiscount → getHayHoldingUsd6 →
	// getHayPrice oracle-global read + getStakedHayBalance inner-call).
	// Both default 0 (unset): 0 oracle → the contract uses the built-in
	// test price; 0 staking → no staking inner-call. They matter only to
	// the open() compose path, which must put the configured apps on the
	// AppCall's ForeignApps (and the HAY asset on ForeignAssets) so the
	// snapshot read resolves — and, when StakingAppID != 0, bump the open()
	// AppCall's (gtxn[1]) fee to cover the one staking inner-txn. Loaded via RefreshConfig.
	HayOracleAppID uint64
	StakingAppID   uint64

	// Treasury is the protocol-owned account that receives the USDC
	// protocol-fee inner transfer fired by finalizeSettlement when
	// netFee > 0 (any settled ticket with a non-zero amountCharged and
	// a non-zero protocol fee that isn't fully cancelled by a HAY tier
	// discount). Loaded from the contract's `trea` (Account) global
	// state via RefreshConfig / RefreshTreasury and cached as the
	// 58-char encoded address.
	//
	// REQUIRED as a ForeignAccounts reference on every settle /
	// settleLapsed app-call. Reading the address from global state
	// inside the contract does not, on its own, make it available to
	// inner txns — the AVM authorizes inner-txn receivers only when
	// they appear in the calling txn's `accounts` reference array.
	// Without it, the outer call rejects at admission the moment the
	// contract tries to fire the fee inner transfer.
	//
	// The slot is set at createApplication and rotatable by admin via
	// setTreasury — same change-frequency profile as hayAssetId — so a
	// one-shot read at startup is enough. Long-running processes that
	// span a treasury rotation must Refresh again, otherwise the cached
	// address goes stale and the inner transfer fails AVM authorization.
	Treasury string

	// ProtocolFeeBps is the contract's `pfee` global — the protocol fee in
	// basis points (e.g. 1000 = 10%), capped at 2000 admin-side. Under the
	// additive fee model the node reads this at reserve time to gross up the
	// escrowed maxPrice (base + worst-case fee) so on-chain settlement has
	// headroom to pay operator=base, treasury=netFee, and refund the remainder
	// (including the HAY discount) to the payer. Loaded via RefreshConfig /
	// RefreshProtocolFeeBps. Zero is valid (fee disabled). Admin-rotatable via
	// setProtocolFeeBps, so long-running processes should refresh periodically.
	ProtocolFeeBps uint64

	// SettlementGraceDefault is the contract's `grace` global — the default
	// settlement_grace_seconds applied to tickets opened with
	// settlementGraceSeconds = 0 (the reference node passes 0). A payer-side
	// process that wants to time refundInactive against an unsettled ticket
	// adds this to the ticket's expires_at to find the on-chain refund
	// deadline D = expires_at + grace. Loaded via RefreshConfig. Zero means
	// the global is absent/zero on-chain (a misconfigured deploy) — callers
	// should treat their computed deadline as a lower bound and tolerate a
	// "refund before deadline" revert.
	SettlementGraceDefault uint64
}

// NewClient constructs a Client for the given app id against the
// given algod client. The escrow address is derived from the app id
// via crypto.GetApplicationAddress — this is the account the Payment
// member of the open() group must target.
//
// TicketMBRAndFees and UsdcAssetID are left zero; the wallet must call
// RefreshConfig at least once before composing groups. Separating
// construction from the algod round-trip keeps this constructor usable
// in tests that don't wire a real algod.
func NewClient(appID uint64, algod protoalgod.Client) (*Client, error) {
	if appID == 0 {
		return nil, fmt.Errorf("escrow: app id must be > 0")
	}
	if algod == nil {
		return nil, fmt.Errorf("escrow: algod client is nil")
	}
	return &Client{
		AppID:   appID,
		AppAddr: crypto.GetApplicationAddress(appID),
		Algod:   algod,
	}, nil
}

// RefreshConfig populates every lazily-loaded field the wallet needs:
// TicketMbr (read via the contract's readonly mbrForTicket method),
// UsdcAssetID and HayAssetID, Treasury, and ProtocolFeeBps (all read from
// the contract's global state in a single GetApplicationByID). Must be
// called once before ComposeOpen and before any settle / settleLapsed
// compose call.
//
// senderAddr is used as the simulate-call sender for the MBR readonly;
// pass any valid on-chain Algorand address.
//
// Contract re-deploys change every cached value; admin rotations
// (setTreasury, hay-asset migration, setProtocolFeeBps) change a subset.
// Callers that hot-swap the app id, or run long enough to span a rotation,
// must Refresh again. In practice all values are stable for the life of a
// deployment and one call at startup is enough.
func (c *Client) RefreshConfig(ctx context.Context, senderAddr string) error {
	mbr, err := c.readMbrForTicket(ctx, senderAddr)
	if err != nil {
		return err
	}
	g, err := c.readGlobals(ctx)
	if err != nil {
		return err
	}
	c.UsdcAssetID = g.usdc
	c.HayAssetID = g.hay
	c.Treasury = g.treasury
	c.ProtocolFeeBps = g.protocolFeeBps
	c.HayOracleAppID = g.hayOracleAppId
	c.StakingAppID = g.stakingAppId
	c.SettlementGraceDefault = g.settlementGraceDefault
	c.TicketMbr = mbr
	// Free-quota box MBR. An app predating the free-ticket quota has no such
	// method, which is not a config error — there is simply no quota box to
	// fund, so 0 is the correct sizing term.
	//
	// Anything ELSE is a hard error, deliberately. This runs once at startup, and
	// callers latch the result for the process lifetime, so quietly mapping a
	// transient algod blip to 0 would drop the quota term from deposit sizing
	// *permanently* — the payer's first free open then reverts with
	// `insufficient MBR deposit for free-quota box` and nothing ever retries.
	// The sibling readMbrForTicket above treats the identical condition as fatal;
	// match it rather than inventing a quieter failure mode for the term that is
	// harder to notice missing.
	q, qerr := c.readFreeQuotaMbr(ctx, senderAddr)
	switch {
	case qerr == nil:
		c.FreeQuotaMbr = q
	case errors.Is(qerr, ErrFreeQuotaUnsupported):
		c.FreeQuotaMbr = 0
	default:
		return qerr
	}
	return nil
}

// escrowGlobals is the cached-config slice of the contract's global state.
type escrowGlobals struct {
	usdc                   uint64
	hay                    uint64
	treasury               string
	protocolFeeBps         uint64
	hayOracleAppId         uint64
	stakingAppId           uint64
	settlementGraceDefault uint64
}

// readGlobals fetches the application once and extracts every global-state
// value RefreshConfig caches, so the common startup path makes a single
// algod round-trip instead of one per field. usdc and treasury are required
// (a contract missing either is misconfigured); hay and protocolFeeBps are
// optional (zero/absent is valid — hay disables the tier read, a zero fee is
// a valid configuration). The standalone Refresh{AssetIDs,Treasury,
// ProtocolFeeBps} readers remain for callers that need just one field.
func (c *Client) readGlobals(ctx context.Context) (escrowGlobals, error) {
	app, err := c.Algod.SDKClient().GetApplicationByID(c.AppID).Do(ctx)
	if err != nil {
		return escrowGlobals{}, fmt.Errorf("escrow: get application %d: %w", c.AppID, err)
	}
	const (
		usdcKeyB64   = "dXNkYw=="             // base64("usdc")
		hayKeyB64    = "aGF5QXNzZXRJZA=="     // base64("hayAssetId")
		treaKeyB64   = "dHJlYQ=="             // base64("trea")
		pfeeKeyB64   = "cGZlZQ=="             // base64("pfee")
		oracleKeyB64 = "aGF5T3JhY2xlQXBwSWQ=" // base64("hayOracleAppId")
		stakeKeyB64  = "c3Rha2luZ0FwcElk"     // base64("stakingAppId")
		graceKeyB64  = "Z3JhY2U="             // base64("grace")
	)
	var g escrowGlobals
	var foundUsdc, foundTreasury bool
	for _, kv := range app.Params.GlobalState {
		switch kv.Key {
		case usdcKeyB64:
			if kv.Value.Type != 2 {
				return escrowGlobals{}, fmt.Errorf("escrow: usdcAssetId global has type %d, want 2 (uint)", kv.Value.Type)
			}
			g.usdc = kv.Value.Uint
			foundUsdc = true
		case hayKeyB64:
			if kv.Value.Type != 2 {
				return escrowGlobals{}, fmt.Errorf("escrow: hayAssetId global has type %d, want 2 (uint)", kv.Value.Type)
			}
			g.hay = kv.Value.Uint
		case pfeeKeyB64:
			if kv.Value.Type != 2 {
				return escrowGlobals{}, fmt.Errorf("escrow: protocolFeeBps global has type %d, want 2 (uint)", kv.Value.Type)
			}
			g.protocolFeeBps = kv.Value.Uint
		case oracleKeyB64:
			if kv.Value.Type != 2 {
				return escrowGlobals{}, fmt.Errorf("escrow: hayOracleAppId global has type %d, want 2 (uint)", kv.Value.Type)
			}
			g.hayOracleAppId = kv.Value.Uint
		case stakeKeyB64:
			if kv.Value.Type != 2 {
				return escrowGlobals{}, fmt.Errorf("escrow: stakingAppId global has type %d, want 2 (uint)", kv.Value.Type)
			}
			g.stakingAppId = kv.Value.Uint
		case graceKeyB64:
			if kv.Value.Type != 2 {
				return escrowGlobals{}, fmt.Errorf("escrow: settlementGraceDefault global has type %d, want 2 (uint)", kv.Value.Type)
			}
			g.settlementGraceDefault = kv.Value.Uint
		case treaKeyB64:
			if kv.Value.Type != 1 {
				return escrowGlobals{}, fmt.Errorf("escrow: treasury global has type %d, want 1 (bytes)", kv.Value.Type)
			}
			raw, decErr := base64.StdEncoding.DecodeString(kv.Value.Bytes)
			if decErr != nil {
				return escrowGlobals{}, fmt.Errorf("escrow: decode treasury bytes: %w", decErr)
			}
			if len(raw) != 32 {
				return escrowGlobals{}, fmt.Errorf("escrow: treasury raw bytes len = %d, want 32", len(raw))
			}
			var addr types.Address
			copy(addr[:], raw)
			g.treasury = addr.String()
			foundTreasury = true
		}
	}
	if !foundUsdc {
		return escrowGlobals{}, fmt.Errorf("escrow: usdcAssetId global not found on app %d", c.AppID)
	}
	if g.usdc == 0 {
		return escrowGlobals{}, fmt.Errorf("escrow: usdcAssetId global is 0 (contract misconfigured?)")
	}
	if !foundTreasury {
		return escrowGlobals{}, fmt.Errorf("escrow: treasury global not found on app %d", c.AppID)
	}
	return g, nil
}

// RefreshAssetIDs loads UsdcAssetID and HayAssetID from the contract's
// global state without simulating the MBR readonly. The node uses this
// at startup — it doesn't compose open() groups (so doesn't need
// TicketMbr) but does need the asset ids in the ForeignAssets array
// for ComposeSettle / ComposeSettleLapsed.
func (c *Client) RefreshAssetIDs(ctx context.Context) error {
	usdc, hay, err := c.readAssetIDs(ctx)
	if err != nil {
		return err
	}
	c.UsdcAssetID = usdc
	c.HayAssetID = hay
	return nil
}

func (c *Client) readMbrForTicket(ctx context.Context, senderAddr string) (uint64, error) {
	sender, err := types.DecodeAddress(senderAddr)
	if err != nil {
		return 0, fmt.Errorf("escrow: decode sender addr: %w", err)
	}
	sp, err := c.Algod.SuggestedParams(ctx)
	if err != nil {
		return 0, fmt.Errorf("escrow: suggested params: %w", err)
	}
	method, err := MethodByName("mbrForTicket")
	if err != nil {
		return 0, err
	}

	atc := transaction.AtomicTransactionComposer{}
	if err := atc.AddMethodCall(transaction.AddMethodCallParams{
		AppID:           c.AppID,
		Method:          method,
		Sender:          sender,
		SuggestedParams: sp,
		OnComplete:      types.NoOpOC,
		Signer:          transaction.EmptyTransactionSigner{},
	}); err != nil {
		return 0, fmt.Errorf("escrow: atc add mbrForTicket: %w", err)
	}

	result, err := atc.Simulate(ctx, c.Algod.SDKClient(), models.SimulateRequest{AllowEmptySignatures: true})
	if err != nil {
		return 0, fmt.Errorf("escrow: simulate mbrForTicket: %w", err)
	}
	// Eval-level failures (account not in ledger, opcode reject, missing
	// box reference, etc.) surface in TxnGroups[0].FailureMessage rather
	// than as a transport error.
	if len(result.SimulateResponse.TxnGroups) > 0 {
		if msg := result.SimulateResponse.TxnGroups[0].FailureMessage; msg != "" {
			return 0, fmt.Errorf("escrow: simulate mbrForTicket failed (app=%d sender=%s): %s",
				c.AppID, senderAddr, msg)
		}
	}
	if len(result.MethodResults) != 1 {
		return 0, fmt.Errorf("escrow: simulate mbrForTicket returned %d results, want 1", len(result.MethodResults))
	}
	mr := result.MethodResults[0]
	if mr.DecodeError != nil {
		return 0, fmt.Errorf("escrow: decode mbrForTicket return: %w", mr.DecodeError)
	}
	mbr, ok := mr.ReturnValue.(uint64)
	if !ok {
		return 0, fmt.Errorf("escrow: mbrForTicket returned %T, want uint64", mr.ReturnValue)
	}
	if mbr == 0 {
		return 0, fmt.Errorf("escrow: mbrForTicket returned 0 (contract misconfigured?)")
	}
	return mbr, nil
}

// IsPayerOptedIn reports whether payerAddr has opted into the escrow app
// (i.e. has a prepaid-pool local-state record). Distinguishes "no pool
// yet" from "opted in with a drained balance", which ReadPayerDeposit /
// payerDeposit cannot (both report a zero tuple). Used to choose the
// depositMbr OnComplete (OptIn on first deposit, NoOp on top-up).
func (c *Client) IsPayerOptedIn(ctx context.Context, payerAddr string) (bool, error) {
	acct, err := c.Algod.SDKClient().AccountInformation(payerAddr).Do(ctx)
	if err != nil {
		return false, fmt.Errorf("escrow: account info for opt-in check: %w", err)
	}
	for _, ls := range acct.AppsLocalState {
		if ls.Id == c.AppID {
			return true, nil
		}
	}
	return false, nil
}

// PayerDeposit is a payer's prepaid ticket-MBR pool state, read from the
// contract's readonly payerDeposit(payer). Reserved = OpenTickets ×
// mbrForTicket(); Available = AlgoBalance − Reserved is withdrawable.
type PayerDeposit struct {
	AlgoBalance uint64 // µALGO on deposit backing this payer's ticket boxes
	OpenTickets uint64 // live ticket boxes (OPEN + PENDING_SETTLE + FROZEN)
}

// ReadPayerDeposit simulates the contract's readonly payerDeposit(payer)
// and returns the payer's pool state. Returns {0, 0} for a payer with no
// deposit (not opted in) — the contract probes app_opted_in and returns a
// zero tuple in that case, so callers can treat AlgoBalance == 0 as "no
// pool yet". The payer rides ForeignAccounts so the contract's local-state
// read resolves under simulate; the payer is also the (empty-signature)
// simulate sender, so it must be a funded on-chain account (true for the
// proxy's own payer wallet).
func (c *Client) ReadPayerDeposit(ctx context.Context, payerAddr string) (PayerDeposit, error) {
	addr, err := types.DecodeAddress(payerAddr)
	if err != nil {
		return PayerDeposit{}, fmt.Errorf("escrow: decode payer addr: %w", err)
	}
	sp, err := c.Algod.SuggestedParams(ctx)
	if err != nil {
		return PayerDeposit{}, fmt.Errorf("escrow: suggested params: %w", err)
	}
	method, err := MethodByName("payerDeposit")
	if err != nil {
		return PayerDeposit{}, err
	}

	atc := transaction.AtomicTransactionComposer{}
	if err := atc.AddMethodCall(transaction.AddMethodCallParams{
		AppID:           c.AppID,
		Method:          method,
		Sender:          addr,
		SuggestedParams: sp,
		OnComplete:      types.NoOpOC,
		Signer:          transaction.EmptyTransactionSigner{},
		MethodArgs:      []any{addr},
		ForeignAccounts: []string{payerAddr},
	}); err != nil {
		return PayerDeposit{}, fmt.Errorf("escrow: atc add payerDeposit: %w", err)
	}

	result, err := atc.Simulate(ctx, c.Algod.SDKClient(), models.SimulateRequest{AllowEmptySignatures: true})
	if err != nil {
		return PayerDeposit{}, fmt.Errorf("escrow: simulate payerDeposit: %w", err)
	}
	if len(result.SimulateResponse.TxnGroups) > 0 {
		if msg := result.SimulateResponse.TxnGroups[0].FailureMessage; msg != "" {
			return PayerDeposit{}, fmt.Errorf("escrow: simulate payerDeposit failed (app=%d payer=%s): %s", c.AppID, payerAddr, msg)
		}
	}
	if len(result.MethodResults) != 1 {
		return PayerDeposit{}, fmt.Errorf("escrow: simulate payerDeposit returned %d results, want 1", len(result.MethodResults))
	}
	mr := result.MethodResults[0]
	if mr.DecodeError != nil {
		return PayerDeposit{}, fmt.Errorf("escrow: decode payerDeposit return: %w", mr.DecodeError)
	}
	tuple, ok := mr.ReturnValue.([]interface{})
	if !ok || len(tuple) != 2 {
		return PayerDeposit{}, fmt.Errorf("escrow: payerDeposit returned %T, want (uint64,uint64) tuple", mr.ReturnValue)
	}
	bal, ok1 := tuple[0].(uint64)
	open, ok2 := tuple[1].(uint64)
	if !ok1 || !ok2 {
		return PayerDeposit{}, fmt.Errorf("escrow: payerDeposit tuple elements %T,%T, want uint64,uint64", tuple[0], tuple[1])
	}
	return PayerDeposit{AlgoBalance: bal, OpenTickets: open}, nil
}

// FreeAllowance is a payer's remaining budget of FREE tickets (open() with
// maxPrice == 0), read from the contract's readonly freeTicketAllowance(payer).
// The contract rations free tickets per payer per 24-hour window, the window
// anchored at that payer's first free open — so this is a point-in-time answer
// that changes as the payer opens free tickets and resets when the window
// lapses.
type FreeAllowance struct {
	// Remaining free tickets the payer may open right now. Window expiry is
	// already applied by the contract, so this needs no clock arithmetic on
	// the caller's side: a lapsed window reports the full CapPerDay.
	Remaining uint64
	// WindowEndsAt is the unix second the payer's current window lapses. ALWAYS
	// a real future timestamp: with no window running the contract reports the
	// end of the one that would start now, never 0 — a 0 sentinel reads as the
	// epoch to any caller doing time arithmetic and collapses into a bogus
	// "retry immediately". Callers surface it as a Retry-After / "resets at" hint.
	WindowEndsAt uint64
	// CapPerDay is the contract's per-window cap. A compile-time constant on
	// chain, returned here so callers don't hard-code a second copy of it.
	CapPerDay uint64
}

// ErrFreeQuotaUnsupported reports that the deployed app has no
// freeTicketAllowance method — i.e. it predates the free-ticket quota. Callers
// should treat the quota as absent (skip the gate) rather than fail closed:
// a contract that can't enforce a cap also can't reject an open() for it, so
// refusing free reserves would take every free model offline against an app
// that is behaving correctly. Detect it ONCE at startup by calling
// ReadFreeQuotaMbr and classifying the error, rather than per-request.
var ErrFreeQuotaUnsupported = errors.New("escrow: deployed app has no freeTicketAllowance method")

// ReadFreeQuotaMbr simulates the contract's readonly mbrForFreeQuota() and
// returns the one-time microALGO a payer's prepaid pool must cover, on top of
// their ticket slots, before their FIRST free (maxPrice == 0) ticket. The
// contract charges it once when it creates that payer's quota box and never
// refunds it, so deposit sizing must include it or the first free request fails
// on the pool guard.
//
// Returns ErrFreeQuotaUnsupported ONLY when the deployed app rejected the call
// in its ABI router (a logic eval failure — i.e. it predates the quota). Any
// other simulate failure propagates as a plain error: callers latch this value,
// so a transient fault must not be mistaken for a permanent absence.
func (c *Client) ReadFreeQuotaMbr(ctx context.Context, senderAddr string) (uint64, error) {
	return c.readFreeQuotaMbr(ctx, senderAddr)
}

func (c *Client) readFreeQuotaMbr(ctx context.Context, senderAddr string) (uint64, error) {
	sender, err := types.DecodeAddress(senderAddr)
	if err != nil {
		return 0, fmt.Errorf("escrow: decode sender addr: %w", err)
	}
	sp, err := c.Algod.SuggestedParams(ctx)
	if err != nil {
		return 0, fmt.Errorf("escrow: suggested params: %w", err)
	}
	method, err := MethodByName("mbrForFreeQuota")
	if err != nil {
		return 0, err
	}

	atc := transaction.AtomicTransactionComposer{}
	if err := atc.AddMethodCall(transaction.AddMethodCallParams{
		AppID:           c.AppID,
		Method:          method,
		Sender:          sender,
		SuggestedParams: sp,
		OnComplete:      types.NoOpOC,
		Signer:          transaction.EmptyTransactionSigner{},
	}); err != nil {
		return 0, fmt.Errorf("escrow: atc add mbrForFreeQuota: %w", err)
	}

	result, err := atc.Simulate(ctx, c.Algod.SDKClient(), models.SimulateRequest{AllowEmptySignatures: true})
	if err != nil {
		return 0, fmt.Errorf("escrow: simulate mbrForFreeQuota: %w", err)
	}
	if len(result.SimulateResponse.TxnGroups) > 0 {
		if msg := result.SimulateResponse.TxnGroups[0].FailureMessage; msg != "" {
			// An app without the method falls through its ABI router to a
			// reject — a LOGIC EVAL failure, surfaced here rather than as a
			// transport error. ONLY that shape means "unsupported".
			//
			// Everything else at this layer — an unfunded or nonexistent
			// sender, a fee or resource problem, a ledger fault — is a real
			// error and must propagate. Callers latch this answer for the
			// process lifetime (RefreshConfig), so folding a transient fault
			// into "unsupported" would drop the quota term from deposit sizing
			// PERMANENTLY, and every payer's first free open would then revert
			// with `insufficient MBR deposit for free-quota box` with nothing
			// left to retry it. mbrForFreeQuota reads no state and returns a
			// constant expression, so a deployed app that DOES have the method
			// has no way to fail eval here — the narrowing costs nothing.
			if strings.Contains(msg, "logic eval error") {
				return 0, fmt.Errorf("%w (app=%d): %s", ErrFreeQuotaUnsupported, c.AppID, msg)
			}
			return 0, fmt.Errorf("escrow: simulate mbrForFreeQuota failed (app=%d sender=%s): %s",
				c.AppID, senderAddr, msg)
		}
	}
	if len(result.MethodResults) != 1 {
		return 0, fmt.Errorf("escrow: simulate mbrForFreeQuota returned %d results, want 1", len(result.MethodResults))
	}
	mr := result.MethodResults[0]
	if mr.DecodeError != nil {
		return 0, fmt.Errorf("escrow: decode mbrForFreeQuota return: %w", mr.DecodeError)
	}
	mbr, ok := mr.ReturnValue.(uint64)
	if !ok {
		return 0, fmt.Errorf("escrow: mbrForFreeQuota returned %T, want uint64", mr.ReturnValue)
	}
	return mbr, nil
}

// HasFreeQuotaBox reports whether payerAddr already has a free-ticket quota
// box — i.e. whether mbrForFreeQuota() has ALREADY been spent out of their
// prepaid pool. It is the exactness signal for deposit sizing: the term belongs
// in the target only while the box is absent, and adding it unconditionally
// leaves every payer carrying a permanent slice of idle (if withdrawable) ALGO.
//
// A direct box read rather than a contract readonly: it needs no simulate, no
// ABI surface, and answers precisely the question sizing asks. `false` is the
// only answer that can change — the contract never deletes a quota box, so a
// `true` result is safe to cache for the life of the process (and callers
// should, since sizing runs on every funding pass).
//
// A missing box is (false, nil), not an error; a transport failure propagates.
func (c *Client) HasFreeQuotaBox(ctx context.Context, payerAddr string) (bool, error) {
	key, err := FreeQuotaBoxKeyFromAddr(payerAddr)
	if err != nil {
		return false, err
	}
	if _, err := c.Algod.SDKClient().GetApplicationBoxByName(c.AppID, key).Do(ctx); err != nil {
		if isNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("escrow: check free-quota box: %w", err)
	}
	return true, nil
}

// FreeQuotaMbrDueFor returns the free-quota box MBR a payer's pool still has to
// cover: FreeQuotaMbr while they have no box, 0 once they do. This is the term
// deposit sizing should add — see DepositShortfall callers.
//
// Fails OPEN (returns the full term) on a read error rather than propagating:
// over-funding by ~0.0225 ALGO of withdrawable ALGO is strictly better than an
// under-funded pool whose first free open reverts, and deposit sizing is
// advisory anyway — the contract asserts the real requirement.
func (c *Client) FreeQuotaMbrDueFor(ctx context.Context, payerAddr string) uint64 {
	if c.FreeQuotaMbr == 0 {
		return 0
	}
	has, err := c.HasFreeQuotaBox(ctx, payerAddr)
	if err != nil || !has {
		return c.FreeQuotaMbr
	}
	return 0
}

// ReadFreeAllowance simulates the contract's readonly freeTicketAllowance(payer)
// and returns how many free (maxPrice == 0) tickets payerAddr may still open.
// Returns a full allowance for a payer that has never opened one — including a
// payer with no deposit at all, since the quota lives in an app-owned box and
// needs no opt-in.
//
// Unlike ReadPayerDeposit, the simulate sender is senderAddr, NOT the payer:
// the caller here is a node answering for someone else's address, which may not
// be funded (an unfunded sender fails the simulate at the fee check). The payer
// rides ForeignAccounts and its quota box rides BoxReferences. senderAddr must
// be a funded on-chain account — the node's own signing address.
func (c *Client) ReadFreeAllowance(ctx context.Context, senderAddr, payerAddr string) (FreeAllowance, error) {
	sender, err := types.DecodeAddress(senderAddr)
	if err != nil {
		return FreeAllowance{}, fmt.Errorf("escrow: decode sender addr: %w", err)
	}
	payer, err := types.DecodeAddress(payerAddr)
	if err != nil {
		return FreeAllowance{}, fmt.Errorf("escrow: decode payer addr: %w", err)
	}
	sp, err := c.Algod.SuggestedParams(ctx)
	if err != nil {
		return FreeAllowance{}, fmt.Errorf("escrow: suggested params: %w", err)
	}
	method, err := MethodByName("freeTicketAllowance")
	if err != nil {
		return FreeAllowance{}, err
	}

	atc := transaction.AtomicTransactionComposer{}
	if err := atc.AddMethodCall(transaction.AddMethodCallParams{
		AppID:           c.AppID,
		Method:          method,
		Sender:          sender,
		SuggestedParams: sp,
		OnComplete:      types.NoOpOC,
		Signer:          transaction.EmptyTransactionSigner{},
		MethodArgs:      []any{payer},
		ForeignAccounts: []string{payerAddr},
		// The readonly reads freeQuotas[payer]; without the box reference the
		// simulate fails the same way a real call would.
		BoxReferences: []types.AppBoxReference{
			{AppID: 0, Name: FreeQuotaBoxKey(payer)},
		},
	}); err != nil {
		return FreeAllowance{}, fmt.Errorf("escrow: atc add freeTicketAllowance: %w", err)
	}

	result, err := atc.Simulate(ctx, c.Algod.SDKClient(), models.SimulateRequest{AllowEmptySignatures: true})
	if err != nil {
		return FreeAllowance{}, fmt.Errorf("escrow: simulate freeTicketAllowance: %w", err)
	}
	if len(result.SimulateResponse.TxnGroups) > 0 {
		if msg := result.SimulateResponse.TxnGroups[0].FailureMessage; msg != "" {
			return FreeAllowance{}, fmt.Errorf(
				"escrow: simulate freeTicketAllowance failed (app=%d payer=%s): %s", c.AppID, payerAddr, msg)
		}
	}
	if len(result.MethodResults) != 1 {
		return FreeAllowance{}, fmt.Errorf(
			"escrow: simulate freeTicketAllowance returned %d results, want 1", len(result.MethodResults))
	}
	mr := result.MethodResults[0]
	if mr.DecodeError != nil {
		return FreeAllowance{}, fmt.Errorf("escrow: decode freeTicketAllowance return: %w", mr.DecodeError)
	}
	tuple, ok := mr.ReturnValue.([]interface{})
	if !ok || len(tuple) != 3 {
		return FreeAllowance{}, fmt.Errorf(
			"escrow: freeTicketAllowance returned %T, want (uint64,uint64,uint64) tuple", mr.ReturnValue)
	}
	remaining, ok1 := tuple[0].(uint64)
	windowEndsAt, ok2 := tuple[1].(uint64)
	capPerDay, ok3 := tuple[2].(uint64)
	if !ok1 || !ok2 || !ok3 {
		return FreeAllowance{}, fmt.Errorf(
			"escrow: freeTicketAllowance tuple elements %T,%T,%T, want uint64,uint64,uint64",
			tuple[0], tuple[1], tuple[2])
	}
	return FreeAllowance{Remaining: remaining, WindowEndsAt: windowEndsAt, CapPerDay: capPerDay}, nil
}

// readAssetIDs reads the contract's `usdcAssetId` and `hayAssetId`
// global-state slots via a single algod GetApplicationByID call. The
// USDC slot is set at createApplication and immutable afterward (no
// setter exists); the HAY slot is set at createApplication and only
// rewritten by an admin migration. A one-shot read at startup is
// enough in either case.
//
// USDC is required (zero / absent → error). HAY is allowed to be zero
// — the contract treats hayAssetId == 0 as "tier discount disabled"
// — so a missing or zero slot returns hay=0 without error.
func (c *Client) readAssetIDs(ctx context.Context) (usdc, hay uint64, err error) {
	app, err := c.Algod.SDKClient().GetApplicationByID(c.AppID).Do(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("escrow: get application %d: %w", c.AppID, err)
	}
	const (
		usdcKeyB64 = "dXNkYw=="         // base64("usdc")
		hayKeyB64  = "aGF5QXNzZXRJZA==" // base64("hayAssetId")
	)
	var foundUsdc bool
	for _, kv := range app.Params.GlobalState {
		switch kv.Key {
		case usdcKeyB64:
			// TealValue.Type == 2 → uint; .Bytes is empty for uint values.
			if kv.Value.Type != 2 {
				return 0, 0, fmt.Errorf("escrow: usdcAssetId global has type %d, want 2 (uint)", kv.Value.Type)
			}
			usdc = kv.Value.Uint
			foundUsdc = true
		case hayKeyB64:
			if kv.Value.Type != 2 {
				return 0, 0, fmt.Errorf("escrow: hayAssetId global has type %d, want 2 (uint)", kv.Value.Type)
			}
			hay = kv.Value.Uint
		}
	}
	if !foundUsdc {
		return 0, 0, fmt.Errorf("escrow: usdcAssetId global not found on app %d", c.AppID)
	}
	if usdc == 0 {
		return 0, 0, fmt.Errorf("escrow: usdcAssetId global is 0 (contract misconfigured?)")
	}
	return usdc, hay, nil
}

// RefreshTreasury loads the contract's `trea` (Account) global into
// c.Treasury. Set at createApplication and only rewritten by admin via
// setTreasury — same change-frequency profile as the asset ids — so a
// one-shot read at startup is enough. Long-running processes that span
// a treasury rotation must call this again, otherwise ComposeSettle*
// will reference a stale address that no longer matches the contract's
// view and the inner fee transfer will fail AVM authorization.
func (c *Client) RefreshTreasury(ctx context.Context) error {
	treasury, err := c.readTreasury(ctx)
	if err != nil {
		return err
	}
	c.Treasury = treasury
	return nil
}

// readTreasury reads the contract's `trea` global-state slot via a
// single algod GetApplicationByID call and returns the 58-char encoded
// address. Mirrors readAssetIDs in shape but decodes a TealValue
// Type==1 (bytes) — the slot stores raw 32-byte address bytes — rather
// than Type==2 (uint). The TealValue.Bytes field is a base64-encoded
// string in the algod REST response, so we DecodeString it before
// copying into a types.Address.
func (c *Client) readTreasury(ctx context.Context) (string, error) {
	app, err := c.Algod.SDKClient().GetApplicationByID(c.AppID).Do(ctx)
	if err != nil {
		return "", fmt.Errorf("escrow: get application %d: %w", c.AppID, err)
	}
	const treasuryKeyB64 = "dHJlYQ==" // base64("trea")
	for _, kv := range app.Params.GlobalState {
		if kv.Key != treasuryKeyB64 {
			continue
		}
		if kv.Value.Type != 1 {
			return "", fmt.Errorf("escrow: treasury global has type %d, want 1 (bytes)", kv.Value.Type)
		}
		raw, err := base64.StdEncoding.DecodeString(kv.Value.Bytes)
		if err != nil {
			return "", fmt.Errorf("escrow: decode treasury bytes: %w", err)
		}
		if len(raw) != 32 {
			return "", fmt.Errorf("escrow: treasury raw bytes len = %d, want 32", len(raw))
		}
		var addr types.Address
		copy(addr[:], raw)
		return addr.String(), nil
	}
	return "", fmt.Errorf("escrow: treasury global not found on app %d", c.AppID)
}

// RefreshProtocolFeeBps loads the contract's `pfee` (uint64) global into
// c.ProtocolFeeBps. Set at createApplication and admin-rotatable via
// setProtocolFeeBps. The node reads it at reserve time to gross up maxPrice
// under the additive fee model; long-running nodes should refresh it
// periodically so a fee rotation is eventually picked up.
func (c *Client) RefreshProtocolFeeBps(ctx context.Context) error {
	bps, err := c.readProtocolFeeBps(ctx)
	if err != nil {
		return err
	}
	c.ProtocolFeeBps = bps
	return nil
}

// ProtocolFeeBpsNow reads the contract's live `pfee` global (uint64) via a
// single algod call and returns it WITHOUT mutating the cached c.ProtocolFeeBps.
// An off-chain cost meter (proxy) uses it to show a payer their effective fee
// rate for the payer-facing breakdown; reading without touching the field keeps
// a background refresh goroutine from racing a compose path that reads the
// cache. The HAY fee discount is retired, so this single rate is the whole
// story — there is no per-account discount term. A zero rate is valid (fee
// disabled); an error is returned rather than a silent zero so the caller can
// distinguish "fee is 0" from "couldn't read".
func (c *Client) ProtocolFeeBpsNow(ctx context.Context) (uint64, error) {
	return c.readProtocolFeeBps(ctx)
}

// readProtocolFeeBps reads the contract's `pfee` global-state slot (uint64)
// via a single algod GetApplicationByID call. Mirrors readAssetIDs in shape.
// A missing slot returns 0 without error — a zero protocol fee is valid.
func (c *Client) readProtocolFeeBps(ctx context.Context) (uint64, error) {
	app, err := c.Algod.SDKClient().GetApplicationByID(c.AppID).Do(ctx)
	if err != nil {
		return 0, fmt.Errorf("escrow: get application %d: %w", c.AppID, err)
	}
	const pfeeKeyB64 = "cGZlZQ==" // base64("pfee")
	for _, kv := range app.Params.GlobalState {
		if kv.Key != pfeeKeyB64 {
			continue
		}
		if kv.Value.Type != 2 {
			return 0, fmt.Errorf("escrow: protocolFeeBps global has type %d, want 2 (uint)", kv.Value.Type)
		}
		return kv.Value.Uint, nil
	}
	return 0, nil
}

// OpenArgs mirrors the ZeroSignalEscrow.open() ABI method args, minus the
// leading `pay`/`axfer` references (ATC derives those from
// TransactionWithSigner). `OperatorID` is the sequential id allocated
// by createOperator; the contract resolves the operator's owner +
// signing addresses from the operator box and snapshots both into the
// ticket. `TicketIDRaw` is the 16-byte unwrapped id (NOT the
// envelope's base64 form). `PayerAddr` is the 58-char Algorand
// address that signs the open() group's usdcPayment (the sole funding
// leg now — box MBR is drawn from this payer's prepaid pool, not a
// per-turn feePayment); the contract pins it as the usdcPayment sender
// and binds the ticket's payer to it.
type OpenArgs struct {
	TicketIDRaw []byte // 16 bytes
	OperatorID  uint64
	// NodeID is the serving node (within OperatorID). The contract resolves
	// the node's signing key from the node box and snapshots (OperatorID,
	// NodeID) onto the ticket. The operator-side signer passed to ComposeOpen
	// / ComposeOpenGroup must be THIS node's signing key.
	NodeID    uint64
	PayerAddr string
	MaxPrice  uint64
	// ExpiresAt is a unix timestamp (seconds) — matches the ticket wire
	// format and the contract's Global.latestTimestamp comparison.
	ExpiresAt uint64
	// SettlementGraceSeconds is the post-expiry payer-silence window before
	// settleLapsed / refundInactive becomes callable. 0 → contract uses global default.
	SettlementGraceSeconds uint64
}

// OpenResult is what a successful ComposeOpen returns. The caller
// threads TxIDs[1] (the escrow.open app-call txid) into the
// envelope's algorand_tx_id — algod has no "find pending txn by
// group id" primitive, so the real transaction id is the lookup
// key. GroupID is retained for audit/dispute logging. SignedGroup
// is the per-member signed bytes kept for dispute retention per
// SPEC.md §3b.
type OpenResult struct {
	// GroupID is base32(types.Digest) — 52 chars, matches Algorand
	// conventions. Retained for audit/dispute logging; NOT the
	// lookup key for the node's mempool check (see TxIDs below).
	GroupID string
	// GroupDigest is the raw 32-byte group digest algod assigned. Kept
	// for future use (e.g. quoting in error messages) without forcing
	// callers to round-trip through base32.
	GroupDigest types.Digest
	// SignedGroup is the full set of signed-txn bytes in group order.
	// Retain alongside the ticket for the dispute window so slashing
	// evidence stays intact even after the group confirms.
	SignedGroup [][]byte
	// TxIDs mirrors ATC's submit return — element i is the txid for
	// group member i. Handy for operator-side mempool lookups.
	TxIDs []string
	// TotalFeeMicroalgos is the sum of FlatFee values set on every
	// member of the submitted group. In the consensus-verified design
	// this is the operator's fee — the operator's gtxn[1] over-fees and
	// pools to cover the payer's gtxn[0] usdcPayment (Fee = 0). Useful
	// for log/audit lines that report the group's total committed
	// network cost.
	TotalFeeMicroalgos uint64

	// PayerFeeMicroalgos is the subset of TotalFeeMicroalgos paid by
	// transactions the payer signs (gtxn[0] usdcPayment). In the current
	// fee model that is 0 — the operator's gtxn[1] pools the entire
	// group via Algorand fee pooling — so this is 0 in practice.
	// Surfaced separately so the
	// proxy can report only payer-paid fees to its callers (the TUI)
	// without leaking operator-paid fees as if the payer paid them.
	PayerFeeMicroalgos uint64
}

// The HAY fee discount is retired. open() snapshots discountBps as 0 and makes
// no staking/oracle inner-call, so the open AppCall carries no HAY/oracle/
// staking foreign refs and no discount inner-txn fee. The former
// discountOpenRefs / payerDiscountAccounts / openDiscountStakingInnerTxns
// helpers (which sized those refs) are gone; ComposeOpen / ComposeOpenGroup now
// put only the three escrow boxes on the AppCall and only the payer on
// ForeignAccounts (for its prepaid-pool local state).

// ComposeOpen builds the 2-tx open group (usdcPayment + escrow.open),
// signs it via ATC, submits to algod, and returns the group id. Verifies
// its own output against VerifyOpenGroup before broadcast as a fail-safe.
// The ticket-box MBR is no longer a per-turn ALGO leg — it is drawn from
// the payer's prepaid pool at open() (openTickets++), so there is no
// feePayment member.
//
// In the consensus-verified design (see SPEC.md "Operator authentication"):
//
//   - gtxn[0] usdcPayment: sender = payerAddr, fee = 0, amount = MaxPrice
//   - gtxn[1] open() AppCall: sender = operatorAddr, fee = 2 × minTxnFee
//     (fee-pools to cover both outer fees; +1 when the HAY discount
//     snapshot fires the staking inner-call)
//
// Algorand consensus verifies operatorSigner's Ed25519 sig on gtxn[1]
// at pool admission, which binds the operator to the ABI args
// (operatorId, maxPrice, expiresAt, payerAddr, …). The contract's
// in-method ed25519verify_bare is gone; gtxn[1].sender == operatorSigning
// is the authentication.
//
// Both signers are required because the call assembles + submits in one
// shot. In production this is split between the node (pre-signs gtxn[1]
// at reserve time) and the proxy (signs gtxn[0] and submits at open
// time); this single-call helper exists for tests, single-process
// integrators, and any caller that holds both keys.
//
// The payer must already be opted into c.UsdcAssetID — algod rejects
// asset-transfer txns from non-opted-in accounts at admission time.
func (c *Client) ComposeOpen(
	ctx context.Context,
	args OpenArgs,
	operatorSigner transaction.TransactionSigner,
	operatorAddr string,
	payerSigner transaction.TransactionSigner,
) (OpenResult, error) {
	// c.TicketMbr is a RefreshConfig-loaded sentinel (the contract's
	// mbrForTicket() value, used to size depositMbr / withdrawMbr pool
	// headroom) — it is NOT an input to the open group anymore (the
	// feePayment leg that consumed it is gone). Kept as a "config loaded?"
	// guard so callers get a clear error before composing, same as USDC.
	if c.TicketMbr == 0 {
		return OpenResult{}, fmt.Errorf("escrow: ticket MBR not loaded; call RefreshConfig first")
	}
	if c.UsdcAssetID == 0 {
		return OpenResult{}, fmt.Errorf("escrow: USDC asset id not loaded; call RefreshConfig first")
	}
	if len(args.TicketIDRaw) != 16 {
		return OpenResult{}, fmt.Errorf("escrow: ticket id must be 16 bytes (got %d)", len(args.TicketIDRaw))
	}
	if args.OperatorID == 0 {
		return OpenResult{}, fmt.Errorf("escrow: operator id must be > 0")
	}
	if args.NodeID == 0 {
		return OpenResult{}, fmt.Errorf("escrow: node id must be > 0")
	}
	if args.PayerAddr == "" {
		return OpenResult{}, fmt.Errorf("escrow: payer addr is required")
	}
	payerSenderAddr, err := types.DecodeAddress(args.PayerAddr)
	if err != nil {
		return OpenResult{}, fmt.Errorf("escrow: decode payer addr: %w", err)
	}
	operatorSenderAddr, err := types.DecodeAddress(operatorAddr)
	if err != nil {
		return OpenResult{}, fmt.Errorf("escrow: decode operator addr: %w", err)
	}

	sp, err := c.Algod.SuggestedParams(ctx)
	if err != nil {
		return OpenResult{}, fmt.Errorf("escrow: suggested params: %w", err)
	}

	// MBR funding moved to the per-payer prepaid pool (depositMbr → local
	// state); there is no per-turn feePayment leg anymore. open() draws box-MBR
	// headroom from the payer's deposit (openTickets++). The group is now
	// [usdcPayment, open()].

	// usdcPayment: USDC asset transfer locking maxPrice into escrow.
	// Fee = 0; pooled from the open() AppCall's over-fee (gtxn[1]).
	usdcTxn, err := transaction.MakeAssetTransferTxn(
		args.PayerAddr,
		c.AppAddr.String(),
		args.MaxPrice,
		nil, // note
		sp,
		"", // closeRemainderTo
		c.UsdcAssetID,
	)
	if err != nil {
		return OpenResult{}, fmt.Errorf("escrow: build usdcPayment txn: %w", err)
	}
	usdcTxn.Fee = 0
	usdcTxn.Sender = payerSenderAddr

	method, err := MethodByName("open")
	if err != nil {
		return OpenResult{}, err
	}

	// gtxn[1] (open() AppCall, sender = operator) over-fees to cover both
	// outer txns via Algorand fee pooling. There are no discount inner txns:
	// the HAY fee discount is retired, so open() makes no staking/oracle
	// inner-call and the AppCall carries no HAY/oracle/staking refs.
	//
	// The payer must be on ForeignAccounts: open() reads + writes the payer's
	// prepaid-pool local state (app_opted_in + openTickets++), and app_local
	// ops require the account on the reference array.
	openAccounts := []string{args.PayerAddr}
	sp.FlatFee = true
	sp.Fee = types.MicroAlgos(sp.MinFee * 2)

	atc := transaction.AtomicTransactionComposer{}
	if err := atc.AddMethodCall(transaction.AddMethodCallParams{
		AppID:           c.AppID,
		Method:          method,
		Sender:          operatorSenderAddr,
		SuggestedParams: sp,
		OnComplete:      types.NoOpOC,
		Signer:          operatorSigner,
		MethodArgs: []any{
			transaction.TransactionWithSigner{Txn: usdcTxn, Signer: payerSigner},
			args.TicketIDRaw,
			args.OperatorID,
			args.NodeID,
			payerSenderAddr,
			args.MaxPrice,
			args.ExpiresAt,
			args.SettlementGraceSeconds,
		},
		// open() reads operators[operatorID] + nodes[operatorID,nodeID] and writes
		// tickets[ticketId]; on a FREE (MaxPrice == 0) ticket it also reads and may
		// create freeQuotas[payer]. OpenBoxReferences includes the quota box only
		// for a free open — see its doc for why a paid open omits it.
		BoxReferences: OpenBoxReferences(args.OperatorID, args.NodeID, args.TicketIDRaw, payerSenderAddr, args.MaxPrice),
		// Only the payer on ForeignAccounts (for its prepaid-pool local state).
		// No HAY/oracle/staking refs — the fee discount is retired.
		ForeignAccounts: openAccounts,
	}); err != nil {
		return OpenResult{}, fmt.Errorf("escrow: atc add open: %w", err)
	}

	built, err := atc.BuildGroup()
	if err != nil {
		return OpenResult{}, fmt.Errorf("escrow: atc build group: %w", err)
	}
	if len(built) != 2 {
		return OpenResult{}, fmt.Errorf("escrow: atc built %d txns, want 2", len(built))
	}
	// Group id is written onto each member by BuildGroup. Take it from
	// position 0 — no need to re-call crypto.ComputeGroupID.
	groupDigest := built[0].Txn.Group
	// Total network fee for the group: sum of per-member fees as set
	// by ATC. Captured here (post-BuildGroup, pre-Submit) so the value
	// reflects exactly what the operator is committing to pay even if
	// the submit step later fails. payerFee is the slice the payer's
	// own signed member (gtxn[0] = usdcPayment) committed; in the current
	// fee model that's 0 because the operator's gtxn[1] pools the
	// entire group.
	var totalFee, payerFee uint64
	for i, w := range built {
		fee := uint64(w.Txn.Fee)
		totalFee += fee
		if i == 0 {
			payerFee += fee
		}
	}

	signedRaw, err := atc.GatherSignatures()
	if err != nil {
		return OpenResult{}, fmt.Errorf("escrow: gather signatures: %w", err)
	}

	// Belt-and-braces self-check: the group we're about to send must
	// pass the same VerifyOpenGroup rule the node will apply at admit
	// time. This can only fail if ATC drifts from our expectations —
	// in which case failing here is strictly better than sending a
	// group the node will refuse.
	decoded, err := decodeSignedGroup(signedRaw)
	if err != nil {
		return OpenResult{}, fmt.Errorf("escrow: decode signed group for self-check: %w", err)
	}
	if err := VerifyOpenGroup(decoded, OpenGroupSpec{
		AppID:                  c.AppID,
		AppAddress:             c.AppAddr,
		TicketIDRaw:            args.TicketIDRaw,
		OperatorID:             args.OperatorID,
		NodeID:                 args.NodeID,
		MaxPrice:               args.MaxPrice,
		TicketMbr:              c.TicketMbr,
		UsdcAssetID:            c.UsdcAssetID,
		NodeSigningAddr:        operatorSenderAddr,
		PayerAddr:              payerSenderAddr,
		ExpiresAt:              args.ExpiresAt,
		SettlementGraceSeconds: args.SettlementGraceSeconds,
	}); err != nil {
		return OpenResult{}, fmt.Errorf("escrow: self-verify open group: %w", err)
	}

	txids, err := atc.Submit(c.Algod.SDKClient(), ctx)
	if err != nil {
		return OpenResult{}, enrichSubmitError("open", err)
	}

	return OpenResult{
		GroupID:            base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(groupDigest[:]),
		GroupDigest:        groupDigest,
		SignedGroup:        signedRaw,
		TxIDs:              txids,
		TotalFeeMicroalgos: totalFee,
		PayerFeeMicroalgos: payerFee,
	}, nil
}

// ComposeOpenGroup builds the 2-tx open group with gtxn[1] (open()
// AppCall) signed by the operator and gtxn[0] (the payer-signed
// usdcPayment) left unsigned. The proxy completes signing the
// usdcPayment and submits via SubmitPresignedOpenGroup. There is no
// feePayment leg — the ticket-box MBR is drawn from the payer's prepaid
// pool at open() (openTickets++).
//
// This is the node-side composer used by the reserve handler to
// emit the operator's pre-signed gtxn[1] in PreSignedOpenTxn. The
// returned slice is wire-encoded by EncodeOpenGroup.
//
// Fee model: gtxn[1].fee = 2 × minTxnFee, covering both outer txns via
// Algorand fee pooling. open() fires no inner txn — the HAY fee discount is
// retired, so there is no staking inner-call to fund. gtxn[0].fee = 0. The
// operator pays the entire group's fees out of their signing account.
func (c *Client) ComposeOpenGroup(
	ctx context.Context,
	args OpenArgs,
	operatorSigner transaction.TransactionSigner,
	operatorAddr string,
) ([]types.SignedTxn, error) {
	if c.TicketMbr == 0 {
		return nil, fmt.Errorf("escrow: ticket MBR not loaded; call RefreshConfig first")
	}
	if c.UsdcAssetID == 0 {
		return nil, fmt.Errorf("escrow: USDC asset id not loaded; call RefreshConfig first")
	}
	if len(args.TicketIDRaw) != 16 {
		return nil, fmt.Errorf("escrow: ticket id must be 16 bytes (got %d)", len(args.TicketIDRaw))
	}
	if args.OperatorID == 0 {
		return nil, fmt.Errorf("escrow: operator id must be > 0")
	}
	if args.NodeID == 0 {
		return nil, fmt.Errorf("escrow: node id must be > 0")
	}
	if args.PayerAddr == "" {
		return nil, fmt.Errorf("escrow: payer addr is required")
	}
	payerSenderAddr, err := types.DecodeAddress(args.PayerAddr)
	if err != nil {
		return nil, fmt.Errorf("escrow: decode payer addr: %w", err)
	}
	operatorSenderAddr, err := types.DecodeAddress(operatorAddr)
	if err != nil {
		return nil, fmt.Errorf("escrow: decode operator addr: %w", err)
	}

	sp, err := c.Algod.SuggestedParams(ctx)
	if err != nil {
		return nil, fmt.Errorf("escrow: suggested params: %w", err)
	}

	// No feePayment leg — box MBR is drawn from the payer's prepaid pool at
	// open() (openTickets++). The group is [usdcPayment, open()].
	usdcTxn, err := transaction.MakeAssetTransferTxn(args.PayerAddr, c.AppAddr.String(), args.MaxPrice, nil, sp, "", c.UsdcAssetID)
	if err != nil {
		return nil, fmt.Errorf("escrow: build usdcPayment txn: %w", err)
	}
	usdcTxn.Fee = 0
	usdcTxn.Sender = payerSenderAddr

	method, err := MethodByName("open")
	if err != nil {
		return nil, err
	}

	// The operator's gtxn[1] pools the whole group's outer fees. No discount
	// inner txns: the HAY fee discount is retired, so open() makes no
	// staking/oracle inner-call and carries no HAY/oracle/staking refs.
	//
	// Payer on ForeignAccounts, baked onto the operator-signed gtxn[1] at
	// reserve: open() reads + writes the payer's prepaid-pool local state
	// (app_opted_in + openTickets++), which needs the account on the ref array.
	openAccounts := []string{args.PayerAddr}
	sp.FlatFee = true
	sp.Fee = types.MicroAlgos(sp.MinFee * 2)

	// Use ATC for the build phase; operator signs gtxn[1] (the open()
	// AppCall) via the supplied operatorSigner, EmptyTransactionSigner
	// placeholder produces SignedTxn-encoded-with-empty-sig bytes for the
	// gtxn[0] usdcPayment. The proxy fills the empty sig in
	// SubmitPresignedOpenGroup.
	atc := transaction.AtomicTransactionComposer{}
	if err := atc.AddMethodCall(transaction.AddMethodCallParams{
		AppID:           c.AppID,
		Method:          method,
		Sender:          operatorSenderAddr,
		SuggestedParams: sp,
		OnComplete:      types.NoOpOC,
		Signer:          operatorSigner,
		MethodArgs: []any{
			transaction.TransactionWithSigner{Txn: usdcTxn, Signer: transaction.EmptyTransactionSigner{}},
			args.TicketIDRaw,
			args.OperatorID,
			args.NodeID,
			payerSenderAddr,
			args.MaxPrice,
			args.ExpiresAt,
			args.SettlementGraceSeconds,
		},
		// operators[operatorID] + nodes[operatorID,nodeID] + tickets[ticketId] are
		// read/written by open(); the free-quota box rides along only on a free
		// open. See OpenBoxReferences.
		BoxReferences: OpenBoxReferences(args.OperatorID, args.NodeID, args.TicketIDRaw, payerSenderAddr, args.MaxPrice),
		// Only the payer on ForeignAccounts (for its prepaid-pool local state),
		// baked onto the operator-signed gtxn[1] at reserve. No HAY/oracle/
		// staking refs — the fee discount is retired.
		ForeignAccounts: openAccounts,
	}); err != nil {
		return nil, fmt.Errorf("escrow: atc add open: %w", err)
	}

	signedRaw, err := atc.GatherSignatures()
	if err != nil {
		return nil, fmt.Errorf("escrow: gather signatures: %w", err)
	}
	if len(signedRaw) != 2 {
		return nil, fmt.Errorf("escrow: gather produced %d txns, want 2", len(signedRaw))
	}

	out := make([]types.SignedTxn, 2)
	for i, raw := range signedRaw {
		if err := msgpack.Decode(raw, &out[i]); err != nil {
			return nil, fmt.Errorf("escrow: decode signed txn %d: %w", i, err)
		}
	}
	return out, nil
}

// EncodeOpenGroup serializes a 2-tx open group (as returned by
// ComposeOpenGroup) into base64(msgpack([]SignedTxn)) suitable for
// the wire (PreSignedOpenTxn field on ReserveResponse).
func EncodeOpenGroup(group []types.SignedTxn) (string, error) {
	if len(group) != 2 {
		return "", fmt.Errorf("escrow: encode open group expects 2 txns, got %d", len(group))
	}
	raw := msgpack.Encode(group)
	return base64.StdEncoding.EncodeToString(raw), nil
}

// DecodeOpenGroup is the inverse of EncodeOpenGroup. Used by the
// proxy on the reserve response to recover the operator's
// pre-signed group ahead of SubmitPresignedOpenGroup.
func DecodeOpenGroup(b64 string) ([]types.SignedTxn, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("escrow: decode base64: %w", err)
	}
	var group []types.SignedTxn
	if err := msgpack.Decode(raw, &group); err != nil {
		return nil, fmt.Errorf("escrow: decode msgpack: %w", err)
	}
	if len(group) != 2 {
		return nil, fmt.Errorf("escrow: decoded %d txns, want 2", len(group))
	}
	return group, nil
}

// SubmitPresignedOpenGroup is the proxy-side completer/submitter.
// Takes the 2-tx group from the reserve response (gtxn[0] = usdcPayment
// has empty Sig, gtxn[1] = open() AppCall is operator-signed), verifies
// it against spec, signs gtxn[0] with the payer's signer, and
// broadcasts to algod.
//
// The VerifyOpenGroup run against spec happens BEFORE the payer signs
// anything. This is the payer's only defense on this path: the entire
// group — including the usdcPayment the payer is about to sign — was
// composed by the counterparty node, so without this check a hostile
// reserve response could hand the payer an arbitrary asset transfer
// (any amount, any receiver) grouped with an arbitrary app call, and
// the payer would blind-sign and broadcast it. The spec pins every
// field to the signature-verified ticket (ids, max_price, payer,
// expiry) plus the caller's own chain config (app id/address, USDC
// asset) and settlementGraceSeconds (0 from reference callers).
func (c *Client) SubmitPresignedOpenGroup(
	ctx context.Context,
	group []types.SignedTxn,
	payerSigner transaction.TransactionSigner,
	spec OpenGroupSpec,
) (OpenResult, error) {
	if len(group) != 2 {
		return OpenResult{}, fmt.Errorf("escrow: open group must have 2 txns (got %d)", len(group))
	}
	if err := VerifyOpenGroup(group, spec); err != nil {
		return OpenResult{}, fmt.Errorf("escrow: verify presigned open group: %w", err)
	}

	txns := []types.Transaction{group[0].Txn, group[1].Txn}
	payerSignedBytes, err := payerSigner.SignTransactions(txns, []int{0})
	if err != nil {
		return OpenResult{}, fmt.Errorf("escrow: sign funding txn: %w", err)
	}

	appCallEncoded := msgpack.Encode(group[1])

	// Re-assemble the exact bytes we're about to broadcast (payer-signed
	// gtxn[0] + operator-signed gtxn[1]) so the group-id sanity check and
	// the fee accounting below run on the final wire form.
	finalGroup := make([]types.SignedTxn, 2)
	if err := msgpack.Decode(payerSignedBytes[0], &finalGroup[0]); err != nil {
		return OpenResult{}, fmt.Errorf("escrow: decode payer-signed gtxn[0]: %w", err)
	}
	finalGroup[1] = group[1]

	groupDigest := finalGroup[0].Txn.Group
	if groupDigest == (types.Digest{}) {
		return OpenResult{}, fmt.Errorf("escrow: open group missing group id")
	}

	combined := make([]byte, 0, len(payerSignedBytes[0])+len(appCallEncoded))
	combined = append(combined, payerSignedBytes[0]...)
	combined = append(combined, appCallEncoded...)

	txid, err := c.Algod.SendRawTransactionGroup(ctx, combined)
	if err != nil {
		// Same treatment the single-txn calls get: algod hands back only
		// "assert failed pc=NNN", so without the ARC-56 source-map lookup the
		// proxy has no way to tell an MBR-pool revert (retryable, points at
		// zs.concurrent_slots) from any other open() failure.
		return OpenResult{}, enrichSubmitError("open", err)
	}

	// totalFee is the whole group's committed fee (operator's gtxn[1]
	// over-fees, payer's gtxn[0] is 0). payerFee is just the payer's
	// slice — used by the proxy to surface only what the payer paid to
	// its own callers.
	var totalFee, payerFee uint64
	for i, stx := range finalGroup {
		fee := uint64(stx.Txn.Fee)
		totalFee += fee
		if i == 0 {
			payerFee += fee
		}
	}
	signedRaw := [][]byte{payerSignedBytes[0], appCallEncoded}

	// Submit returns one txid, but each member of an Algorand group
	// has its own txid. Recompute the per-member txids from the
	// canonical txn bytes so callers (the proxy) can thread
	// txids[1] (the AppCall) into the envelope's algorand_tx_id —
	// matching what ComposeOpen returns.
	txids := make([]string, 2)
	for i := range finalGroup {
		txids[i] = crypto.GetTxID(finalGroup[i].Txn)
	}
	_ = txid // SendRawTransactionGroup returns the first txn's txid; we use the canonical per-member ids instead

	return OpenResult{
		GroupID:            base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(groupDigest[:]),
		GroupDigest:        groupDigest,
		SignedGroup:        signedRaw,
		TxIDs:              txids,
		TotalFeeMicroalgos: totalFee,
		PayerFeeMicroalgos: payerFee,
	}, nil
}

// ComposeSettleGroup builds the atomic 2-tx settle group with gtxn[0]
// (operator first-half) signed by the operator and gtxn[1] (payer ack
// template) left unsigned. The proxy completes signing gtxn[1] and
// submits via SubmitPresignedSettleGroup.
//
// Used by the node's receipt sealer at request-end. The encoded result
// rides the sealed response envelope so the proxy can complete + submit
// without holding the operator's signing key.
//
// Fee model: gtxn[0] carries the whole group's fee via Algorand fee
// pooling and gtxn[1].fee = 0, so the operator pays for everything. The
// fee is sized to the work that will actually run rather than a flat
// worst case — see the comment at the FlatFee assignment below.
//
// Both txns reference payer + operator-owner + treasury in
// ForeignAccounts — those are the three receivers of the disbursement
// inner-txns finalizeSettlement fires (USDC refund, operator payout,
// treasury fee). Treasury is read once via RefreshConfig and cached on
// the Client; callers do not pass it.
//
// args.AsOperator is set to true on gtxn[0] internally; the payer's
// gtxn[1] template carries asOperator=false. Callers don't need to
// set AsOperator on the args.
func (c *Client) ComposeSettleGroup(
	ctx context.Context,
	args SettleArgs,
	operatorSigner transaction.TransactionSigner,
	operatorAddr string,
) ([]types.SignedTxn, error) {
	if c.Treasury == "" {
		return nil, fmt.Errorf("escrow: treasury addr not loaded; call RefreshConfig first")
	}
	if len(args.TicketIDRaw) != 16 {
		return nil, fmt.Errorf("escrow: settle ticket id must be 16 bytes (got %d)", len(args.TicketIDRaw))
	}
	payerSenderAddr, err := types.DecodeAddress(args.PayerAddr)
	if err != nil {
		return nil, fmt.Errorf("escrow: decode payer addr: %w", err)
	}
	if _, err := types.DecodeAddress(args.OperatorOwnerAddr); err != nil {
		return nil, fmt.Errorf("escrow: decode operator owner addr: %w", err)
	}
	operatorSenderAddr, err := types.DecodeAddress(operatorAddr)
	if err != nil {
		return nil, fmt.Errorf("escrow: decode operator addr: %w", err)
	}

	method, err := MethodByName("settle")
	if err != nil {
		return nil, err
	}

	// Operator's gtxn[0]: asOperator=true, and the pooled fee for the group:
	//
	//	2 settle outers
	//	+ the disbursement inners finalizeSettlement will actually submit
	//	+ args.GapOpUps ensureBudget op-up inners
	//
	// The inner count is derived from amountCharged/maxPrice rather than assumed
	// (SettleInnerCount) — a free model disburses nothing and a zero-charge
	// settle only refunds, so a flat worst-case fee made the operator pay for
	// inners that never fired. (The per-turn ALGO MBR refund inner is gone — the
	// pool slot is released by openTickets-- instead.)
	//
	// finalizeSettlement sizes its ensureBudget target to the revenue-ring
	// catch-up loop a multi-day-idle settle runs. On this grouped path the entry
	// opcode budget already clears the base target, so a steady-state settle
	// op-ups zero times and GapOpUps is 0; the caller raises it only when it
	// knows the node has been idle across day boundaries. Under-funding here
	// costs nothing — the group fails admission unconfirmed and the operator's
	// settlement watchdog re-settles via the single-app-call path, which reads
	// the real box days. See proto/SPEC.md "Atomic settle group".
	spOp, err := c.Algod.SuggestedParams(ctx)
	if err != nil {
		return nil, fmt.Errorf("escrow: suggested params: %w", err)
	}
	spOp.FlatFee = true
	spOp.Fee = types.MicroAlgos(spOp.MinFee * (2 + SettleInnerCount(args.AmountCharged, args.MaxPrice) + args.GapOpUps))

	// Payer's gtxn[1]: fee=0 (pooled from gtxn[0]). Same suggested
	// params so the validity window matches.
	spPayer := spOp
	spPayer.Fee = 0

	atc := transaction.AtomicTransactionComposer{}
	if err := atc.AddMethodCall(transaction.AddMethodCallParams{
		AppID:           c.AppID,
		Method:          method,
		Sender:          operatorSenderAddr,
		SuggestedParams: spOp,
		OnComplete:      types.NoOpOC,
		Signer:          operatorSigner,
		MethodArgs: []any{
			args.TicketIDRaw,
			args.AmountCharged,
			args.ReceiptDigest[:],
			args.TtftMs,
			args.DecodeMs,
			args.InputCount,
			args.OutputCount,
			args.OutputUsageType,
			args.AuxOutputUsageType,
			args.AuxOutputCount,
			true, // asOperator
		},
		BoxReferences: []types.AppBoxReference{
			{AppID: 0, Name: TicketBoxKey(args.TicketIDRaw)},
			// Required: contract writes per-operator metrics on finalization.
			{AppID: 0, Name: OperatorBoxKey(args.OperatorID)},
			{AppID: 0, Name: NodeBoxKey(args.OperatorID, args.NodeID)},
		},
		ForeignAccounts: []string{args.PayerAddr, args.OperatorOwnerAddr, c.Treasury},
		ForeignAssets:   filterNonZero(c.UsdcAssetID),
	}); err != nil {
		return nil, fmt.Errorf("escrow: atc add settle (operator): %w", err)
	}
	if err := atc.AddMethodCall(transaction.AddMethodCallParams{
		AppID:           c.AppID,
		Method:          method,
		Sender:          payerSenderAddr,
		SuggestedParams: spPayer,
		OnComplete:      types.NoOpOC,
		Signer:          transaction.EmptyTransactionSigner{},
		MethodArgs: []any{
			args.TicketIDRaw,
			args.AmountCharged,
			args.ReceiptDigest[:],
			args.TtftMs,
			args.DecodeMs,
			args.InputCount,
			args.OutputCount,
			args.OutputUsageType,
			args.AuxOutputUsageType,
			args.AuxOutputCount,
			false, // asOperator (payer side)
		},
		BoxReferences: []types.AppBoxReference{
			{AppID: 0, Name: TicketBoxKey(args.TicketIDRaw)},
			{AppID: 0, Name: OperatorBoxKey(args.OperatorID)},
			{AppID: 0, Name: NodeBoxKey(args.OperatorID, args.NodeID)},
		},
		ForeignAccounts: []string{args.PayerAddr, args.OperatorOwnerAddr, c.Treasury},
		ForeignAssets:   filterNonZero(c.UsdcAssetID),
	}); err != nil {
		return nil, fmt.Errorf("escrow: atc add settle (payer): %w", err)
	}

	signedRaw, err := atc.GatherSignatures()
	if err != nil {
		return nil, fmt.Errorf("escrow: gather signatures: %w", err)
	}
	if len(signedRaw) != 2 {
		return nil, fmt.Errorf("escrow: gather produced %d txns, want 2", len(signedRaw))
	}
	out := make([]types.SignedTxn, 2)
	for i, raw := range signedRaw {
		if err := msgpack.Decode(raw, &out[i]); err != nil {
			return nil, fmt.Errorf("escrow: decode signed txn %d: %w", i, err)
		}
	}
	return out, nil
}

// EncodeSettleGroup serializes a 2-tx settle group (as returned by
// ComposeSettleGroup) into base64(msgpack([]SignedTxn)) for the sealed
// response envelope.
func EncodeSettleGroup(group []types.SignedTxn) (string, error) {
	if len(group) != 2 {
		return "", fmt.Errorf("escrow: encode settle group expects 2 txns, got %d", len(group))
	}
	raw := msgpack.Encode(group)
	return base64.StdEncoding.EncodeToString(raw), nil
}

// DecodeSettleGroup is the inverse of EncodeSettleGroup. Used by the
// proxy on the response envelope to recover the operator's pre-signed
// group ahead of SubmitPresignedSettleGroup.
func DecodeSettleGroup(b64 string) ([]types.SignedTxn, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("escrow: decode base64: %w", err)
	}
	var group []types.SignedTxn
	if err := msgpack.Decode(raw, &group); err != nil {
		return nil, fmt.Errorf("escrow: decode msgpack: %w", err)
	}
	if len(group) != 2 {
		return nil, fmt.Errorf("escrow: decoded %d txns, want 2", len(group))
	}
	return group, nil
}

// SubmitPresignedSettleGroup is the proxy-side completer/submitter
// for the atomic settle path. It VERIFIES the node-composed group
// against spec (see VerifySettleGroup) BEFORE applying the payer
// signature — a node authored both halves, so a rekeyTo / non-NoOp
// onComplete / fee / value mismatch is proven operator misbehaviour and
// must never be signed. On a bad group it returns a
// *SettleGroupRejectedError (the caller refuses, downranks, and falls
// back to the standalone ack). On success it signs gtxn[1] (payer ack)
// and broadcasts; payer's outer fee = 0 — the operator's gtxn[0]
// over-fee covers everything. Mirrors the client's
// submitPresignedSettleGroup, which calls verifySettleGroup internally.
func (c *Client) SubmitPresignedSettleGroup(
	ctx context.Context,
	group []types.SignedTxn,
	payerSigner transaction.TransactionSigner,
	spec SettleGroupSpec,
) (CallResult, error) {
	// Fail closed before any signature touches the wire. VerifySettleGroup
	// also enforces the group-size==2 invariant the rest of this function
	// relies on.
	if err := VerifySettleGroup(group, spec); err != nil {
		return CallResult{}, err
	}

	txns := []types.Transaction{group[0].Txn, group[1].Txn}
	payerSignedBytes, err := payerSigner.SignTransactions(txns, []int{1})
	if err != nil {
		return CallResult{}, fmt.Errorf("escrow: sign payer ack: %w", err)
	}

	opCallEncoded := msgpack.Encode(group[0])

	combined := make([]byte, 0, len(opCallEncoded)+len(payerSignedBytes[0]))
	combined = append(combined, opCallEncoded...)
	combined = append(combined, payerSignedBytes[0]...)

	if _, err := c.Algod.SendRawTransactionGroup(ctx, combined); err != nil {
		// Enriched like every other submit path: a settle group can revert on
		// ticket-not-found / after-refund-deadline / not-settleable, the three
		// reverts the settlement driver already fails fast on — and algod
		// carries only the PC, so without the source-map lookup none of them
		// is recognizable here either.
		return CallResult{}, enrichSubmitError("settle", err)
	}

	// totalFee is the whole group's committed fee — operator's gtxn[0]
	// over-fees and gtxn[1] (payer ack) is 0. payerFee is the payer
	// ack's own fee, surfaced separately so the proxy only reports
	// payer-paid fees to its callers.
	totalFee := uint64(group[0].Txn.Fee) + uint64(group[1].Txn.Fee)
	payerFee := uint64(group[1].Txn.Fee)
	// Use gtxn[1] (payer ack) txid for CallResult.TxID — that's the
	// half the proxy submitted; operator's gtxn[0] txid is a sibling
	// recoverable from the same group.
	txID := crypto.GetTxID(group[1].Txn)

	// Reconstitute the payer's signed gtxn[1] for SignedTxn return
	// (matches the existing CallResult shape).
	signedAck := payerSignedBytes[0]

	return CallResult{
		TxID:               txID,
		SignedTxn:          signedAck,
		FeeMicroalgos:      totalFee,
		PayerFeeMicroalgos: payerFee,
	}, nil
}

// SettleArgs / ProtestArgs / RefundInactiveArgs mirror the contract
// ABI. proxy/internal/hayai/wallet.go's OpenHandle API binds against
// these via real signatures.

// SettleArgs matches the contract's settle(bytes, uint64, bytes, bool).
// Either side (operator-signing or payer) can call settle; the contract
// enforces the co-sign rule and reverts on a second call from the same
// side with mismatched (amountCharged, receiptDigest). In the
// consensus-verified design, settle has no receipt sig — the caller's
// Algorand-consensus signature on the txn body authenticates the args.
//
// AsOperator declares the caller's role explicitly. The contract
// verifies Txn.sender matches the claimed role: when AsOperator is
// true, Txn.sender must equal the ticket's operatorSigning; when false,
// it must equal the ticket's payer. Without this explicit dispatch, an
// operator using their own signing account as a payer would silently
// trip the same-side check on the atomic settle group.
//
// PayerAddr and OperatorOwnerAddr are two of the three receivers of
// the inner payments the contract fires on the finalizing call (payer
// gets the unspent USDC remainder + MBR, operator_owner gets
// AmountCharged net of any shortfall). The third receiver — the
// protocol treasury — is loaded from the contract once at startup and
// cached on the Client (c.Treasury). All three must be referenced in
// the app call's ForeignAccounts for the AVM to authorize the
// transfers; the ComposeSettle* helpers wire all three automatically.
type SettleArgs struct {
	TicketIDRaw   []byte
	AmountCharged uint64
	ReceiptDigest [32]byte
	// TtftMs / DecodeMs are the operator-measured timing halves (from the
	// receipt's TtftMs / DecodeMs fields), committed inside the receipt
	// digest (see ticket.UsageReceipt.CanonicalBytes). The contract requires
	// each to match across both halves of the co-signed settle (operator
	// first-half + payer ack); a mismatch freezes the ticket. On finalization
	// the contract folds TtftMs into the per-operator latency metric
	// (latencyTotalMs / latencyEwmaMs) and DecodeMs + OutputTokens into the
	// throughput EWMA (tokensPerSecEwma). A non-stream / no-first-token settle
	// passes TtftMs = total service time, DecodeMs = 0.
	TtftMs   uint64
	DecodeMs uint64
	// InputCount / OutputCount are the operator-claimed actual counts (from the
	// receipt's ActualInputCount / ActualOutputCount). OutputCount is in units of
	// OutputUsageType. The receipt digest already commits to both via
	// ticket.UsageReceipt.CanonicalBytes; the contract credits the operator's
	// totalInputTokens / outputUnits[OutputUsageType] and the protocol-wide
	// aggregates on finalization. Same co-signing trust model as the timing
	// halves — a mismatch on the second-half ack freezes the ticket.
	InputCount  uint64
	OutputCount uint64
	// OutputUsageType / AuxOutputUsageType / AuxOutputCount carry the modality
	// routing the contract co-signs and applies on finalization (from the
	// receipt's matching fields): OutputUsageType (1=Tokens, 2=Images, …)
	// selects the outputUnits slot for OutputCount and gates the speed EWMAs
	// (folded only when ==Tokens); when AuxOutputUsageType != None (Images on a
	// text+image tool turn) AuxOutputCount additionally credits
	// outputUnits[AuxOutputUsageType]. Co-signed via match-or-freeze.
	OutputUsageType    uint64
	AuxOutputUsageType uint64
	AuxOutputCount     uint64
	AsOperator         bool
	PayerAddr          string // 58-char Algorand address
	OperatorOwnerAddr  string // 58-char Algorand address
	// OperatorID is the per-operator monotonic id assigned at
	// createOperator time. Must equal the ticket's snapshotted
	// operatorId. Required so the compose helpers can reference the
	// operator box on settle — the contract writes the rolled-up
	// reliability metrics there on finalization.
	OperatorID uint64
	// NodeID is the ticket's snapshotted node id. Required so the compose
	// helpers can reference the serving node's box — finalizeSettlement
	// writes the per-node metrics there alongside the operator rollup.
	NodeID uint64
	// MaxPrice is the ticket's escrowed USDC ceiling. Not an ABI arg — the
	// contract reads it off the ticket box — but the compose helpers need it
	// to size the settle fee: together with AmountCharged it determines which
	// disbursement inner-txns finalizeSettlement will submit. See
	// SettleInnerCount. Leaving it 0 on a paid ticket under-funds the group.
	MaxPrice uint64
	// GapOpUps is the number of ensureBudget op-up inner-txns to fund on the
	// ATOMIC GROUP path (ComposeSettleGroup) beyond the outers and the
	// disbursements. Zero at steady state: the grouped call's entry opcode
	// budget already clears the contract's base target, so it op-ups only when
	// the revenue-ring catch-up loop runs after a multi-day-idle settle. A
	// caller that knows a lower bound on the boxes' bucketsLastDay derives it
	// as GapOpUpsForIters(2 * BoundedRingGapIters(lastDay, today)); a caller
	// that doesn't know should pass 1 for headroom. Ignored by the
	// single-app-call composers, which read the real box days themselves.
	GapOpUps uint64
}

// ProtestReasonCode is the payer-asserted reason carried as a
// transaction arg on protest(). Not part of the receipt digest, not
// stored on the ticket box; surfaced for off-chain arbiters and
// analytics. The contract rejects 0 and accepts any other value, so
// off-chain consumers can extend this numbering without a contract
// upgrade. Keep wire-compatible with the table in proto/SPEC.md
// "Protest reason codes".
type ProtestReasonCode uint64

const (
	ProtestReasonUnspecified    ProtestReasonCode = 0 // sentinel — contract rejects
	ProtestReasonBodyHash       ProtestReasonCode = 1 // receipt.body_hash != reconstructed plaintext hash
	ProtestReasonReceiptSig     ProtestReasonCode = 2 // reserved
	ProtestReasonAmount         ProtestReasonCode = 3 // reserved
	ProtestReasonSealing        ProtestReasonCode = 4 // reserved — operator returned unsealed/malformed envelope
	ProtestReasonReceiptMissing ProtestReasonCode = 5 // reserved — operator returned 2xx without a receipt
)

// ProtestArgs matches protest(bytes, uint64, bytes, bytes, bytes, uint64).
// DisputeExcerpt is opaque bytes the arbiter inspects off-chain; the
// contract only caps its length (see maxDisputeExcerptBytes). ReasonCode
// must be non-zero; see ProtestReasonCode.
type ProtestArgs struct {
	TicketIDRaw    []byte
	AmountCharged  uint64
	ReceiptDigest  [32]byte
	ReceiptSig     []byte
	DisputeExcerpt []byte
	ReasonCode     ProtestReasonCode
	// OperatorID is the ticket's snapshotted operator id. Required so
	// the compose helper can include the operator box reference — the
	// contract writes the ticketsProtested metric there on freeze.
	OperatorID uint64
	// NodeID is the ticket's snapshotted node id, for the node box
	// reference (the freeze counter is bumped on the node too).
	NodeID uint64
}

// SettleLapsedArgs matches settleLapsed(bytes). Wrapped in a struct so
// later additions (e.g. operator-claimed settlement metadata) are
// non-breaking changes for callers.
type SettleLapsedArgs struct {
	TicketIDRaw []byte
	OperatorID  uint64 // ticket's snapshotted operator id; required for the operator box reference (rollup metric write)
	NodeID      uint64 // ticket's snapshotted node id; required for the node box reference (per-node metric write)
	// OperatorOwnerAddr is a 58-char Algorand address: the receiver of the
	// operator USDC payout, needed as a ForeignAccounts reference.
	//
	// Only a FALLBACK for when the ticket box can't be read — ComposeSettleLapsed
	// prefers the box's own operatorOwner, which is what the contract actually
	// pays. Pass the box's value when you have it; a cached registry entry is
	// wrong for any ticket opened before an updateOperator owner rotation.
	OperatorOwnerAddr string
	PayerAddr         string // 58-char Algorand address; receiver of the ALGO MBR + any USDC refund
}

// RefundInactiveArgs matches refundInactive(bytes). Wrapped in a struct
// for the same forward-compatibility reason as SettleLapsedArgs.
type RefundInactiveArgs struct {
	TicketIDRaw []byte
	OperatorID  uint64 // ticket's snapshotted operator id; required for the operator box reference (rollup metric write)
	NodeID      uint64 // ticket's snapshotted node id; required for the node box reference (per-node metric write)
	PayerAddr   string // 58-char Algorand address; receiver of the inner refund payment
}

// UpdateNodeURLArgs matches updateNodeUrl(uint64, uint64, byte[]). Wrapped
// in a struct so later additions are non-breaking changes for callers.
// BaseURL is raw UTF-8 bytes ≤ BaseURLMax; the contract pads with zeros to
// that fixed-width field. Both the operator owner and the node's signing
// account are authorized on chain (see ZeroSignalEscrow.updateNodeUrl), so a node
// driving this with its hot signing key needs no extra setup.
type UpdateNodeURLArgs struct {
	OperatorID uint64
	NodeID     uint64
	BaseURL    string
}

// CallResult is the common return for the single-txn contract
// methods (settle / protest / refund_inactive). TxID is what the
// caller polls via algod.PendingTransactionInformation when they need
// confirmation; SignedTxn is the raw msgpack bytes retained for
// dispute evidence.
type CallResult struct {
	TxID      string
	SignedTxn []byte
	// FeeMicroalgos is the total committed fee for this call. For
	// single-txn methods (settle / protest / refund_inactive) it's the
	// FlatFee assigned to the one AppCall txn, pooled to cover any
	// inner txns the contract fires. For the atomic settle group
	// returned by SubmitPresignedSettleGroup it's the sum of the
	// operator's gtxn[0] (over-fee, covers everything) and the payer
	// ack's gtxn[1] (0). Surfaced so callers can log the group's full
	// network cost without re-decoding SignedTxn.
	FeeMicroalgos uint64
	// PayerFeeMicroalgos is the subset of FeeMicroalgos paid by the
	// payer's own signed transactions:
	//   - SubmitPresignedSettleGroup: gtxn[1].Fee (payer ack, 0 in the
	//     consensus-verified design — operator's gtxn[0] pools).
	//   - submitSingle (proxy-as-caller paths: standalone settle,
	//     protest, refundInactive): equals FeeMicroalgos because the
	//     caller signs the only txn.
	// Consumers (the proxy) use this when reporting "what the payer
	// paid" to their own callers (the TUI), so operator-paid fees
	// don't leak into payer-facing summaries.
	PayerFeeMicroalgos uint64
}

// ComposeSettleStandalone submits a single-txn settle(ticket_id,
// amount_charged, receipt_digest) call. Used by the operator's
// settlement-driver watchdog when the payer's atomic group never
// landed, and by either side as a fallback path. The pooled fee covers
// 1 outer + the disbursement inners this call fires if it finalizes
// (status was PENDING_SETTLE on the other side) + finalize's op-ups; on
// a first-half call (status = OPEN) nothing is disbursed and the
// over-fee is wasted budget, not a correctness issue.
//
// The signer's address decides which side of the protocol is
// speaking — the contract reads Txn.sender and compares against
// operator_signing / payer on the ticket.
//
// ForeignAccounts wires payer + operator-owner + treasury — the three
// receivers of the disbursement inner-txns finalizeSettlement fires.
// Treasury is read once via RefreshConfig and cached on the Client.
func (c *Client) ComposeSettleStandalone(ctx context.Context, args SettleArgs, signer transaction.TransactionSigner, signerAddr string) (CallResult, error) {
	if c.Treasury == "" {
		return CallResult{}, fmt.Errorf("escrow: treasury addr not loaded; call RefreshConfig first")
	}
	if len(args.TicketIDRaw) != 16 {
		return CallResult{}, fmt.Errorf("escrow: settle ticket id must be 16 bytes (got %d)", len(args.TicketIDRaw))
	}
	if _, err := types.DecodeAddress(args.PayerAddr); err != nil {
		return CallResult{}, fmt.Errorf("escrow: settle payer addr: %w", err)
	}
	if _, err := types.DecodeAddress(args.OperatorOwnerAddr); err != nil {
		return CallResult{}, fmt.Errorf("escrow: settle operator owner addr: %w", err)
	}
	return c.submitSingle(ctx, "settle", signer, signerAddr,
		[]any{
			args.TicketIDRaw,
			args.AmountCharged,
			args.ReceiptDigest[:],
			args.TtftMs,
			args.DecodeMs,
			args.InputCount,
			args.OutputCount,
			args.OutputUsageType,
			args.AuxOutputUsageType,
			args.AuxOutputCount,
			args.AsOperator,
		},
		[]types.AppBoxReference{
			{AppID: 0, Name: TicketBoxKey(args.TicketIDRaw)},
			// Required: contract writes per-operator metrics on finalization.
			{AppID: 0, Name: OperatorBoxKey(args.OperatorID)},
			{AppID: 0, Name: NodeBoxKey(args.OperatorID, args.NodeID)},
		},
		[]string{args.PayerAddr, args.OperatorOwnerAddr, c.Treasury},
		// USDC is referenced by the inner asset transfers in
		// finalizeSettlement (payer refund, operator payout, treasury fee).
		// HAY is NOT referenced at settle — the fee/discount is the open-time
		// snapshot on the ticket (feeBps/discountBps), so finalizeSettlement
		// never reads HAY. Keeping HAY off the foreign-asset list also matters
		// for the reference budget: settle now references three boxes (ticket
		// + operator + node), and a stray HAY ref would push a single-app-call
		// settleLapsed past the 8-reference cap on a HAY-enabled contract.
		filterNonZero(c.UsdcAssetID),
		// The disbursement inner-txns this call fires if it finalizes, sized to
		// AmountCharged/MaxPrice rather than assumed (a free model disburses
		// nothing; a zero-charge settle only refunds) — a first-half on a
		// STATUS_OPEN ticket records pending and fires none, in which case the
		// surplus is harmless. The per-turn ALGO MBR refund inner is gone — the
		// pool slot is released by openTickets--. Pooled from the outer fee.
		// finalize's gap-aware ensureBudget always op-ups once on this
		// single-app-call path (its entry budget is only ~30 opcodes above the
		// steady body); gapSettleOpUps adds inner-txns for a multi-day
		// revenue-ring gap so a long-idle node's settle finalizes instead of
		// reverting for want of fee (see proto/SPEC.md "Atomic settle group").
		// No on-chain ed25519verify_bare in settle().
		SettleInnerCount(args.AmountCharged, args.MaxPrice)+1+c.gapSettleOpUps(ctx, args.OperatorID, args.NodeID),
	)
}

// ComposeProtest submits a protest(ticket_id, amount_charged,
// receipt_digest, receipt_sig, dispute_excerpt, reason_code) call.
// Callable only by the payer, only while the ticket status is OPEN or
// PENDING_SETTLE. The contract caps dispute_excerpt's length via
// maxDisputeExcerptBytes; the proxy pre-truncates its evidence bundle
// to fit. ReasonCode must be non-zero — the contract enforces this so
// every protest carries a deliberate, indexable reason for off-chain
// arbiters and analytics.
func (c *Client) ComposeProtest(ctx context.Context, args ProtestArgs, payerSigner transaction.TransactionSigner, payerAddr string) (CallResult, error) {
	if len(args.TicketIDRaw) != 16 {
		return CallResult{}, fmt.Errorf("escrow: protest ticket id must be 16 bytes (got %d)", len(args.TicketIDRaw))
	}
	if len(args.ReceiptSig) != 64 {
		return CallResult{}, fmt.Errorf("escrow: protest receipt sig must be 64 bytes (got %d)", len(args.ReceiptSig))
	}
	if args.ReasonCode == ProtestReasonUnspecified {
		return CallResult{}, fmt.Errorf("escrow: protest reason code must be non-zero")
	}
	return c.submitSingle(ctx, "protest", payerSigner, payerAddr,
		[]any{
			args.TicketIDRaw,
			args.AmountCharged,
			args.ReceiptDigest[:],
			args.ReceiptSig,
			args.DisputeExcerpt,
			uint64(args.ReasonCode),
		},
		[]types.AppBoxReference{
			{AppID: 0, Name: TicketBoxKey(args.TicketIDRaw)},
			// Required: contract bumps ticketsProtested on the operator box.
			{AppID: 0, Name: OperatorBoxKey(args.OperatorID)},
			{AppID: 0, Name: NodeBoxKey(args.OperatorID, args.NodeID)},
		},
		nil,
		// protest only freezes the ticket — no inner asset transfers
		// fire and no asset balances are read, so no ForeignAssets ref.
		nil,
		3 /* for ed25519verify_bare call */)
}

// TicketBoxExists reports whether the ticket's on-chain box is still
// present. A (false, nil) return means the box was deleted — the
// ticket was finalized (both sides settled, or refundInactive ran).
// Callers use this after their own settle txn confirms to decide
// whether they were the first or second co-signer: if the box is
// gone the ticket finalized on their call; if it still exists they
// were first and settlement is still pending.
func (c *Client) TicketBoxExists(ctx context.Context, ticketIDRaw []byte) (bool, error) {
	_, err := c.Algod.SDKClient().GetApplicationBoxByName(c.AppID, TicketBoxKey(ticketIDRaw)).Do(ctx)
	if err != nil {
		if isNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("escrow: check ticket box: %w", err)
	}
	return true, nil
}

// ComposeSettleLapsed submits a settleLapsed(ticket_id) call.
// Callable by anyone after expiresAt + settlementGraceSeconds when
// the operator's claim is still STATUS_PENDING_SETTLE with
// pendingBy==OPERATOR and the refund deadline has passed.
//
// ForeignAccounts wires operator-owner + payer + treasury — the three
// receivers of the same finalizeSettlement disbursement inner-txns as
// settle. Treasury is read once via RefreshConfig and cached on the
// Client.
func (c *Client) ComposeSettleLapsed(ctx context.Context, args SettleLapsedArgs, signer transaction.TransactionSigner, signerAddr string) (CallResult, error) {
	if c.Treasury == "" {
		return CallResult{}, fmt.Errorf("escrow: treasury addr not loaded; call RefreshConfig first")
	}
	if len(args.TicketIDRaw) != 16 {
		return CallResult{}, fmt.Errorf("escrow: settleLapsed ticket id must be 16 bytes (got %d)", len(args.TicketIDRaw))
	}
	if _, err := types.DecodeAddress(args.OperatorOwnerAddr); err != nil {
		return CallResult{}, fmt.Errorf("escrow: settleLapsed operator owner addr: %w", err)
	}
	if _, err := types.DecodeAddress(args.PayerAddr); err != nil {
		return CallResult{}, fmt.Errorf("escrow: settleLapsed payer addr: %w", err)
	}

	// Size the fee to the disbursement inners finalizeSettlement will submit,
	// and take the payout recipient, from the box. settleLapsed takes only the
	// ticket id — the contract reads both off the box — so read them from the
	// same place rather than trusting a caller's copy: the box is authoritative,
	// and this path is a rare, off-hot-path fallback that already does box reads
	// for the op-up gap. On a read failure assume the worst case; an extra fee
	// slot costs ~0.001 ALGO once, while an under-pooled fee reverts every retry
	// and strands the operator's USDC.
	//
	// The owner matters for the same reason but bites harder: finalizeSettlement
	// pays `t.operatorOwner` — the address snapshotted on the BOX at open() — by
	// inner asset transfer, so that exact account must be in ForeignAccounts or
	// the transfer reverts for want of an available receiver. A caller's copy can
	// legitimately disagree, because OperatorRecord.owner is mutable
	// (updateOperator rotates it) while the box's snapshot never changes: anyone
	// holding a cached registry entry — the proxy caches and even persists one —
	// would reference the operator's *current* owner while the box still names
	// the one in force at open(). Funds can't be misdirected (the contract picks
	// the receiver, not the caller), but the call reverts, which on the payer's
	// watchdog burns its whole attempt budget and strands the ticket.
	owner := args.OperatorOwnerAddr
	inners := settleLapsedMaxInners
	if rec, err := c.ReadTicketBox(ctx, args.TicketIDRaw); err == nil && rec != nil {
		inners = SettleInnerCount(rec.PendingAmount, rec.MaxPrice)
		owner = rec.OperatorOwnerAddr
	}

	return c.submitSingle(ctx, "settleLapsed", signer, signerAddr,
		[]any{args.TicketIDRaw},
		[]types.AppBoxReference{
			{AppID: 0, Name: TicketBoxKey(args.TicketIDRaw)},
			// Required: finalizeSettlement writes per-operator metrics.
			{AppID: 0, Name: OperatorBoxKey(args.OperatorID)},
			{AppID: 0, Name: NodeBoxKey(args.OperatorID, args.NodeID)},
		},
		[]string{owner, args.PayerAddr, c.Treasury},
		// Same finalizeSettlement disbursements as settle(), so the
		// same USDC + HAY references are required.
		filterNonZero(c.UsdcAssetID),
		// The disbursement inner-txns finalizeSettlement fires (payer USDC refund,
		// operator USDC payout, treasury USDC fee), sized above from the box, + 1
		// base finalize op-up inner. The per-turn ALGO MBR refund inner is gone —
		// the pool slot is released by openTickets--. settleLapsed is a single app
		// call, so finalize's gap-aware ensureBudget always op-ups once here; the
		// base op-up funds a no-gap settle. gapSettleOpUps adds inner-txns for a
		// multi-day revenue-ring gap (the catch-up loop a long-idle node's first
		// lapse runs) so it finalizes instead of reverting for want of fee. See
		// proto/SPEC.md "Atomic settle group" and finalizeSettlement's
		// ensureBudget.
		inners+1+c.gapSettleOpUps(ctx, args.OperatorID, args.NodeID),
	)
}

// ComposeRefundInactive submits a refundInactive(ticket_id) call.
// Callable by anyone after expires_at + settlement_grace_seconds
// when no operator claim is pending (status Open or (PendingSettle
// && pending_by == Payer)). Typically driven by the proxy's
// "request timed out" backstop, but a third-party keeper can also
// kick it off to close stale tickets.
//
// payerAddr is the ticket's payer — the receiver of the inner
// refund payment, and thus a required ForeignAccounts reference.
func (c *Client) ComposeRefundInactive(ctx context.Context, args RefundInactiveArgs, callerSigner transaction.TransactionSigner, callerAddr string) (CallResult, error) {
	if len(args.TicketIDRaw) != 16 {
		return CallResult{}, fmt.Errorf("escrow: refundInactive ticket id must be 16 bytes (got %d)", len(args.TicketIDRaw))
	}
	if _, err := types.DecodeAddress(args.PayerAddr); err != nil {
		return CallResult{}, fmt.Errorf("escrow: refundInactive payer addr: %w", err)
	}
	return c.submitSingle(ctx, "refundInactive", callerSigner, callerAddr,
		[]any{args.TicketIDRaw},
		[]types.AppBoxReference{
			{AppID: 0, Name: TicketBoxKey(args.TicketIDRaw)},
			// Required: contract bumps ticketsRefundedInactive on the operator box.
			{AppID: 0, Name: OperatorBoxKey(args.OperatorID)},
			{AppID: 0, Name: NodeBoxKey(args.OperatorID, args.NodeID)},
		},
		[]string{args.PayerAddr},
		// USDC is referenced by the inner USDC refund the contract
		// fires when t.maxPrice > 0. HAY is not read on this path.
		filterNonZero(c.UsdcAssetID),
		// Up to 1 inner txn (USDC refund only) — the ALGO MBR refund inner is
		// gone; the pool slot is released by openTickets--. Pooled from the
		// outer fee since there's no pre-fund anymore.
		1)
}

// ComposeDepositMbr funds (or tops up) the caller's prepaid ticket-MBR
// pool. The first call MUST pass optIn=true — it carries OnComplete=OptIn,
// allocating the payer's local state; later top-ups pass optIn=false
// (NoOp). The 2-tx group is [payment(caller→app, amount, fee=0),
// depositMbr AppCall(caller, fee=2×minTxnFee)] — the caller signs both and
// the AppCall over-fees to pool the group. `amount` is the µALGO credited
// to algoBalance (size as a multiple of mbrForTicket() to back a working
// set of concurrent tickets); the local-schema MBR is locked in the
// caller's own account by the opt-in itself, NOT sent here.
func (c *Client) ComposeDepositMbr(ctx context.Context, amount uint64, optIn bool, signer transaction.TransactionSigner, signerAddr string) (CallResult, error) {
	if amount == 0 {
		return CallResult{}, fmt.Errorf("escrow: depositMbr amount must be > 0")
	}
	sender, err := types.DecodeAddress(signerAddr)
	if err != nil {
		return CallResult{}, fmt.Errorf("escrow: decode depositMbr signer addr: %w", err)
	}
	sp, err := c.Algod.SuggestedParams(ctx)
	if err != nil {
		return CallResult{}, fmt.Errorf("escrow: suggested params: %w", err)
	}

	payTxn, err := transaction.MakePaymentTxn(signerAddr, c.AppAddr.String(), amount, nil, "", sp)
	if err != nil {
		return CallResult{}, fmt.Errorf("escrow: build deposit payment txn: %w", err)
	}
	payTxn.Fee = 0
	payTxn.Sender = sender

	method, err := MethodByName("depositMbr")
	if err != nil {
		return CallResult{}, err
	}
	oc := types.NoOpOC
	if optIn {
		oc = types.OptInOC
	}
	sp.FlatFee = true
	sp.Fee = types.MicroAlgos(sp.MinFee * 2) // payment + AppCall, pooled on the AppCall

	atc := transaction.AtomicTransactionComposer{}
	if err := atc.AddMethodCall(transaction.AddMethodCallParams{
		AppID:           c.AppID,
		Method:          method,
		Sender:          sender,
		SuggestedParams: sp,
		OnComplete:      oc,
		Signer:          signer,
		MethodArgs: []any{
			transaction.TransactionWithSigner{Txn: payTxn, Signer: signer},
		},
	}); err != nil {
		return CallResult{}, fmt.Errorf("escrow: atc add depositMbr: %w", err)
	}

	built, err := atc.BuildGroup()
	if err != nil {
		return CallResult{}, fmt.Errorf("escrow: atc build group for depositMbr: %w", err)
	}
	if len(built) != 2 {
		return CallResult{}, fmt.Errorf("escrow: depositMbr built %d txns, want 2", len(built))
	}
	var feeMicroalgos uint64
	for _, w := range built {
		feeMicroalgos += uint64(w.Txn.Fee)
	}

	signedRaw, err := atc.GatherSignatures()
	if err != nil {
		return CallResult{}, fmt.Errorf("escrow: gather signatures for depositMbr: %w", err)
	}
	txids, err := atc.Submit(c.Algod.SDKClient(), ctx)
	if err != nil {
		return CallResult{}, enrichSubmitError("depositMbr", err)
	}
	if len(txids) != 2 {
		return CallResult{}, fmt.Errorf("escrow: depositMbr submit returned %d txids, want 2", len(txids))
	}
	// txids[0] = payment, txids[1] = AppCall. Report the AppCall.
	return CallResult{
		TxID:               txids[1],
		SignedTxn:          signedRaw[1],
		FeeMicroalgos:      feeMicroalgos,
		PayerFeeMicroalgos: feeMicroalgos,
	}, nil
}

// ComposeWithdrawMbr reclaims `amount` µALGO of unreserved headroom from
// the caller's prepaid pool. The contract asserts amount <= available
// (= algoBalance − openTickets × mbrForTicket()) and inner-pays it back to
// the caller. 1 outer + 1 inner refund = 2 × minTxnFee.
func (c *Client) ComposeWithdrawMbr(ctx context.Context, amount uint64, signer transaction.TransactionSigner, signerAddr string) (CallResult, error) {
	if amount == 0 {
		return CallResult{}, fmt.Errorf("escrow: withdrawMbr amount must be > 0")
	}
	return c.submitSingle(ctx, "withdrawMbr", signer, signerAddr,
		[]any{amount},
		nil, // no box refs (local state only)
		nil, // no foreign accounts (inner refund receiver = Txn.sender)
		nil, // no foreign assets
		1,   // 1 inner: the ALGO refund payment
	)
}

// ComposeCloseDeposit closes the caller's prepaid pool and opts them out
// (CloseOut). Reverts on chain while any ticket (incl. frozen) is still
// live (openTickets != 0). Inner-refunds the remaining algoBalance; the
// CloseOut returns the local-schema MBR natively. 1 outer + 1 inner = 2 ×
// minTxnFee (the inner is skipped on a zero balance — harmless over-fee).
func (c *Client) ComposeCloseDeposit(ctx context.Context, signer transaction.TransactionSigner, signerAddr string) (CallResult, error) {
	return c.submitSingleOC(ctx, "closeDeposit", signer, signerAddr,
		[]any{},
		nil, // no box refs
		nil, // no foreign accounts (inner refund receiver = Txn.sender)
		nil, // no foreign assets
		1,   // up to 1 inner: the balance refund
		types.CloseOutOC,
	)
}

// ComposeUpdateNodeURL submits an updateNodeUrl(operator_id, node_id,
// base_url) call. Callable by the operator's owner OR the node's signing
// account (see ZeroSignalEscrow.updateNodeUrl assert), so the node's hot signing
// key — already in the keystore for ticket signing — can drive this without
// exposing the cold owner key. Used by the ip_sync URL reconcile loop to keep
// the node's NodeRecord.baseUrl in step with its canonical NFD-derived
// endpoint.
//
// No inner txns and no foreign accounts/assets — the contract just rewrites
// the node box in place; metrics carry forward verbatim. Both the operator
// box (owner/status check) and the node box are referenced.
func (c *Client) ComposeUpdateNodeURL(ctx context.Context, args UpdateNodeURLArgs, signer transaction.TransactionSigner, signerAddr string) (CallResult, error) {
	if args.OperatorID == 0 {
		return CallResult{}, fmt.Errorf("escrow: updateNodeUrl operator id must be > 0")
	}
	if args.NodeID == 0 {
		return CallResult{}, fmt.Errorf("escrow: updateNodeUrl node id must be > 0")
	}
	b := []byte(args.BaseURL)
	if len(b) == 0 {
		return CallResult{}, fmt.Errorf("escrow: updateNodeUrl base url is empty")
	}
	if len(b) > BaseURLMax {
		return CallResult{}, fmt.Errorf("escrow: updateNodeUrl base url is %d bytes (max %d)", len(b), BaseURLMax)
	}
	return c.submitSingle(ctx, "updateNodeUrl", signer, signerAddr,
		[]any{args.OperatorID, args.NodeID, b},
		[]types.AppBoxReference{
			{AppID: 0, Name: OperatorBoxKey(args.OperatorID)},
			{AppID: 0, Name: NodeBoxKey(args.OperatorID, args.NodeID)},
		},
		nil, // no foreign accounts (no inner payments)
		nil, // no foreign assets (no inner asset transfers)
		0,   // no inner txns to cover; outer fee = 1 × minFee
	)
}

// submitSingle is the shared ATC path for the single-txn NoOp contract
// methods (settle / settleLapsed / refundInactive / updateNodeUrl /
// withdrawMbr). See submitSingleOC for the OnComplete-parameterized form
// used by the CloseOut close-deposit path.
func (c *Client) submitSingle(ctx context.Context, methodName string, signer transaction.TransactionSigner, signerAddr string, methodArgs []any, boxRefs []types.AppBoxReference, foreignAccounts []string, foreignAssets []uint64, numInnersToCover uint64) (CallResult, error) {
	return c.submitSingleOC(ctx, methodName, signer, signerAddr, methodArgs, boxRefs, foreignAccounts, foreignAssets, numInnersToCover, types.NoOpOC)
}

// submitSingleOC is submitSingle with an explicit OnComplete. Builds a
// 1-txn "group" through ATC — AppCall only, no associated Payment —
// signs it via `signer`, submits to algod via `atc.Submit`, and returns
// the single txid + raw bytes. The raw bytes go on dispute ledgers so
// evidence is durable.
func (c *Client) submitSingleOC(ctx context.Context, methodName string, signer transaction.TransactionSigner, signerAddr string, methodArgs []any, boxRefs []types.AppBoxReference, foreignAccounts []string, foreignAssets []uint64, numInnersToCover uint64, onComplete types.OnCompletion) (CallResult, error) {
	senderAddr, err := types.DecodeAddress(signerAddr)
	if err != nil {
		return CallResult{}, fmt.Errorf("escrow: decode signer addr: %w", err)
	}
	sp, err := c.Algod.SuggestedParams(ctx)
	if err != nil {
		return CallResult{}, fmt.Errorf("escrow: suggested params: %w", err)
	}
	method, err := MethodByName(methodName)
	if err != nil {
		return CallResult{}, err
	}

	sp.FlatFee = true
	sp.Fee = types.MicroAlgos(sp.MinFee * (1 /* ourselves */ + numInnersToCover))

	atc := transaction.AtomicTransactionComposer{}
	if err := atc.AddMethodCall(transaction.AddMethodCallParams{
		AppID:           c.AppID,
		Method:          method,
		Sender:          senderAddr,
		SuggestedParams: sp,
		OnComplete:      onComplete,
		Signer:          signer,
		MethodArgs:      methodArgs,
		ForeignAccounts: foreignAccounts,
		ForeignAssets:   foreignAssets,
		BoxReferences:   boxRefs,
	}); err != nil {
		return CallResult{}, fmt.Errorf("escrow: atc add %s: %w", methodName, err)
	}

	// Fee captured pre-submit so the caller can report exactly what
	// the request commits to even if Submit later fails.
	built, err := atc.BuildGroup()
	if err != nil {
		return CallResult{}, fmt.Errorf("escrow: atc build group for %s: %w", methodName, err)
	}
	if len(built) != 1 {
		return CallResult{}, fmt.Errorf("escrow: %s built %d txns, want 1", methodName, len(built))
	}
	feeMicroalgos := uint64(built[0].Txn.Fee)

	signedRaw, err := atc.GatherSignatures()
	if err != nil {
		return CallResult{}, fmt.Errorf("escrow: gather signatures for %s: %w", methodName, err)
	}
	if len(signedRaw) != 1 {
		return CallResult{}, fmt.Errorf("escrow: %s produced %d txns, want 1", methodName, len(signedRaw))
	}
	txids, err := atc.Submit(c.Algod.SDKClient(), ctx)
	if err != nil {
		// enrichSubmitError parses pc=NNN out of algod's eval-error
		// string and wraps with the matching ARC-56 message + (when
		// known) a typed sentinel like ErrTicketNotFound, so callers
		// can errors.Is rather than substring-matching the algod
		// surface. Falls back to the plain wrap when there's no PC
		// (non-TEAL failure) or no sentinel mapped.
		return CallResult{}, enrichSubmitError(methodName, err)
	}
	if len(txids) != 1 {
		return CallResult{}, fmt.Errorf("escrow: %s submit returned %d txids, want 1", methodName, len(txids))
	}
	// PayerFeeMicroalgos == FeeMicroalgos here: this is a single-txn
	// call, the caller signed it, and the proxy only routes to this
	// path on the payer side (standalone settle ack, protest,
	// refundInactive). Node-side / watchdog callers using these helpers
	// as the operator simply ignore the field — it represents "the
	// fee on transactions the caller signed" and is correct for that
	// caller; the "payer" framing belongs to the proxy consumer.
	return CallResult{
		TxID:               txids[0],
		SignedTxn:          signedRaw[0],
		FeeMicroalgos:      feeMicroalgos,
		PayerFeeMicroalgos: feeMicroalgos,
	}, nil
}

// filterNonZero drops zero entries from an asset-id list. The escrow
// contract treats hayAssetId == 0 as "tier discount disabled", and
// the AVM rejects a ForeignAssets reference of asset id 0, so the
// final ForeignAssets slice must omit zeros entirely. Returns nil
// rather than an empty slice when nothing survives — keeps the
// AddMethodCallParams field at its zero value, matching the prior
// no-foreign-assets shape exactly.
func filterNonZero(ids ...uint64) []uint64 {
	out := make([]uint64, 0, len(ids))
	for _, id := range ids {
		if id != 0 {
			out = append(out, id)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// decodeSignedGroup converts the per-member signed msgpack bytes ATC
// hands back into the []SignedTxn form VerifyOpenGroup expects.
func decodeSignedGroup(signedRaw [][]byte) ([]types.SignedTxn, error) {
	out := make([]types.SignedTxn, len(signedRaw))
	for i, raw := range signedRaw {
		var stx types.SignedTxn
		if err := msgpack.Decode(raw, &stx); err != nil {
			return nil, fmt.Errorf("decode signed txn %d: %w", i, err)
		}
		out[i] = stx
	}
	return out, nil
}

// The off-chain ticket.Sig is no longer consumed by the contract on
// open() — gtxn[1]'s Algorand-consensus signature authenticates the
// args. The Sig field stays on the wire for off-chain audit and is
// still consumed by protest(); see SPEC.md "Operator authentication"
// for the full rationale.
