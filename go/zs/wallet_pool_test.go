/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/TxnLab/zerosignal/go/algod"
	"github.com/TxnLab/zerosignal/go/escrow"
	"github.com/TxnLab/zerosignal/go/ticket"
)

// fakePool is a scriptable poolEscrow for unit-testing the prepaid-MBR-pool
// path (EnsureDeposit + the Open deposit-revert retry) without a live
// algod/keystore. Each field overrides the corresponding seam method; counters
// record calls so tests can assert how many deposits/submits fired.
type fakePool struct {
	ticketMbr    uint64
	freeQuotaMbr uint64
	// quotaBoxExists mirrors the real client: once the payer has a quota box the
	// term is already spent and drops out of the sizing target.
	quotaBoxExists bool
	quotaDueCalls  int

	dep         escrow.PayerDeposit
	depErr      error
	optedIn     bool
	optedInErr  error
	spendable   uint64
	spendErr    error
	minFee      uint64
	minFeeErr   error
	depositErr  error
	depositTxID string

	// submitResults is consumed one entry per SubmitPresignedOpenGroup call;
	// an entry's err (if non-nil) is returned, else its res. When exhausted,
	// the last entry repeats.
	submitResults []submitOutcome

	depositCalls int
	submitCalls  int
	depositedAmt uint64               // last shortfall passed to ComposeDepositMbr
	lastOptIn    bool                 // last optIn passed to ComposeDepositMbr
	lastSpec     escrow.OpenGroupSpec // last spec passed to SubmitPresignedOpenGroup
}

type submitOutcome struct {
	res escrow.OpenResult
	err error
}

func (f *fakePool) TicketMBR() uint64 { return f.ticketMbr }

func (f *fakePool) FreeQuotaMbrDueFor(context.Context, string) uint64 {
	f.quotaDueCalls++
	if f.quotaBoxExists {
		return 0
	}
	return f.freeQuotaMbr
}

func (f *fakePool) ReadPayerDeposit(context.Context, string) (escrow.PayerDeposit, error) {
	return f.dep, f.depErr
}

func (f *fakePool) IsPayerOptedIn(context.Context, string) (bool, error) {
	return f.optedIn, f.optedInErr
}

func (f *fakePool) SpendableMicroAlgos(context.Context, string) (uint64, error) {
	return f.spendable, f.spendErr
}

func (f *fakePool) MinTxnFee(context.Context) (uint64, error) {
	return f.minFee, f.minFeeErr
}

func (f *fakePool) ComposeDepositMbr(_ context.Context, amount uint64, optIn bool, _ transaction.TransactionSigner, _ string) (escrow.CallResult, error) {
	f.depositCalls++
	f.depositedAmt = amount
	f.lastOptIn = optIn
	if f.depositErr != nil {
		return escrow.CallResult{}, f.depositErr
	}
	// Simulate the credit landing so a subsequent ReadPayerDeposit sees the
	// pool covered (the Open retry reads the deposit again via EnsureDeposit).
	f.dep.AlgoBalance += amount
	f.optedIn = true
	return escrow.CallResult{TxID: f.depositTxID}, nil
}

func (f *fakePool) SubmitPresignedOpenGroup(_ context.Context, _ []types.SignedTxn, _ transaction.TransactionSigner, spec escrow.OpenGroupSpec) (escrow.OpenResult, error) {
	f.submitCalls++
	f.lastSpec = spec
	if len(f.submitResults) == 0 {
		return escrow.OpenResult{}, errors.New("fakePool: no submit outcome scripted")
	}
	idx := f.submitCalls - 1
	if idx >= len(f.submitResults) {
		idx = len(f.submitResults) - 1
	}
	o := f.submitResults[idx]
	return o.res, o.err
}

// fakeKeystore satisfies algo.MultipleWalletSigner. The pool tests fake the
// escrow seam, so no transaction is ever actually signed; HasAccount only has
// to report true for NewWallet's guard (these tests build Wallet directly, so
// even that is unused, but keep it correct).
type fakeKeystore struct{}

func (fakeKeystore) HasAccount(string) bool { return true }
func (fakeKeystore) SignWithAccount(context.Context, types.Transaction, string) (string, []byte, error) {
	return "", nil, errors.New("fakeKeystore: signing not expected in pool tests")
}

// testPayerAddr / testSignerAddr are valid (decodable) Algorand addresses —
// Wallet.Open decodes both into the OpenGroupSpec before submitting.
var (
	testPayerAddr  = func() string { var a types.Address; a[0] = 0xAA; return a.String() }()
	testSignerAddr = func() string { var a types.Address; a[0] = 0xBB; return a.String() }()
)

func newPoolWallet(p *fakePool) *Wallet {
	return &Wallet{
		pool:      p,
		keystore:  fakeKeystore{},
		payerAddr: testPayerAddr,
	}
}

const testTicketMbr = 115_000

// A payer with no pool opts in and funds it before any reserve; once the pool
// covers the working set, a later call reads nothing.
func TestPrepareDeposit_OptsInANewPayerOnce(t *testing.T) {
	ctx := context.Background()
	pool := &fakePool{ticketMbr: testTicketMbr, minFee: 1_000, spendable: 100_000_000}
	w := newPoolWallet(pool)
	if err := w.PrepareDeposit(ctx); err != nil {
		t.Fatalf("PrepareDeposit: %v", err)
	}
	if pool.depositCalls != 1 || !pool.lastOptIn {
		t.Fatalf("deposits = %d, optIn = %v; want one opt-in deposit", pool.depositCalls, pool.lastOptIn)
	}
	pool.depErr = errors.New("read after the pool was ready")
	pool.optedInErr = errors.New("opt-in read after the pool was ready")
	if err := w.PrepareDeposit(ctx); err != nil {
		t.Fatalf("second PrepareDeposit: %v", err)
	}
	if pool.depositCalls != 1 {
		t.Errorf("deposits = %d after the pool was ready, want 1", pool.depositCalls)
	}
}

// Closing the pool opts the payer out, so the next request makes the first
// deposit again rather than reaching a node that refuses it unopted.
func TestPrepareDeposit_DepositsAgainAfterClose(t *testing.T) {
	ctx := context.Background()
	client, err := escrow.NewClient(1234, algodAnsweringSubmit(t, func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"txId":"CLOSED"}`)
	}))
	if err != nil {
		t.Fatalf("escrow.NewClient: %v", err)
	}
	pool := &fakePool{ticketMbr: testTicketMbr, minFee: 1_000, spendable: 100_000_000}
	w := newPoolWallet(pool)
	w.escrow = client
	w.keystore = encodingSigner{}
	if err := w.PrepareDeposit(ctx); err != nil {
		t.Fatalf("PrepareDeposit: %v", err)
	}
	if _, err := w.CloseDeposit(ctx); err != nil {
		t.Fatalf("CloseDeposit: %v", err)
	}
	pool.optedIn = false
	pool.dep = escrow.PayerDeposit{}
	if err := w.PrepareDeposit(ctx); err != nil {
		t.Fatalf("PrepareDeposit after close: %v", err)
	}
	if pool.depositCalls != 2 || !pool.lastOptIn {
		t.Errorf("deposits = %d, optIn = %v; want a second opt-in deposit", pool.depositCalls, pool.lastOptIn)
	}
}

// An opted-in pool short of its working set is left to Open: a node checks
// only the opt-in at reserve, and such a pool never latches, so a top-up here
// would repeat the whole funding pass on every request.
func TestPrepareDeposit_LeavesAnOptedInPoolToOpen(t *testing.T) {
	pool := &fakePool{
		ticketMbr: testTicketMbr,
		minFee:    1_000,
		optedIn:   true,
		dep:       escrow.PayerDeposit{AlgoBalance: testTicketMbr},
		depErr:    errors.New("the pool was read"),
	}
	w := newPoolWallet(pool)
	for range 2 {
		if err := w.PrepareDeposit(context.Background()); err != nil {
			t.Fatalf("PrepareDeposit: %v", err)
		}
	}
	if pool.depositCalls != 0 {
		t.Errorf("deposits = %d, want 0", pool.depositCalls)
	}
}

// An opt-in that can't be read is not a funds answer, so dispatch goes on to
// the reserve.
func TestPrepareDeposit_UnreadableOptIn(t *testing.T) {
	pool := &fakePool{ticketMbr: testTicketMbr, optedInErr: errors.New("algod down")}
	err := newPoolWallet(pool).PrepareDeposit(context.Background())
	if err == nil || errors.Is(err, ErrDepositUnaffordable) || errors.Is(err, ErrDepositBelowTarget) {
		t.Fatalf("err = %v, want a read error that isn't a funds answer", err)
	}
	if pool.depositCalls != 0 {
		t.Errorf("deposits = %d, want 0", pool.depositCalls)
	}
}

// With no ALGO for a first deposit and no pool to serve from, the payer is
// told before any reserve.
func TestPrepareDeposit_UnaffordableWithNoPool(t *testing.T) {
	pool := &fakePool{ticketMbr: testTicketMbr, minFee: 1_000, spendable: 1_000}
	err := newPoolWallet(pool).PrepareDeposit(context.Background())
	if !errors.Is(err, ErrDepositUnaffordable) {
		t.Fatalf("err = %v, want ErrDepositUnaffordable", err)
	}
	if pool.depositCalls != 0 {
		t.Errorf("deposits = %d, want 0", pool.depositCalls)
	}
}

// The refusal names what the pool's part slot lacks, the same figure as the
// plan's need, not a whole slot.
func TestEnsureDeposit_UnaffordableNamesThePartSlotShortfall(t *testing.T) {
	part := uint64(testTicketMbr / 3)
	pool := &fakePool{
		ticketMbr: testTicketMbr,
		minFee:    1_000,
		optedIn:   true,
		dep:       escrow.PayerDeposit{AlgoBalance: part},
		spendable: 2_000,
	}
	_, _, err := newPoolWallet(pool).EnsureDeposit(context.Background(), 1)
	if !errors.Is(err, ErrDepositUnaffordable) {
		t.Fatalf("err = %v, want ErrDepositUnaffordable", err)
	}
	if want := fmt.Sprintf("(%d + 2000 fee", testTicketMbr-part); !strings.Contains(err.Error(), want) {
		t.Errorf("err = %v, want it to contain %q", err, want)
	}
}

func TestEnsureDeposit(t *testing.T) {
	ctx := context.Background()
	const minFee = 1_000

	tests := []struct {
		name  string
		pool  *fakePool
		slots uint64

		wantTxID      string
		wantDeposited uint64
		wantDeposits  int
		wantOptIn     bool // expected optIn arg to ComposeDepositMbr (when a deposit fires)
		wantErrIs     error
		wantErrSubstr string
	}{
		{
			name: "already funded no-op",
			pool: &fakePool{
				ticketMbr: testTicketMbr,
				dep:       escrow.PayerDeposit{AlgoBalance: 10 * testTicketMbr},
				optedIn:   true,
				minFee:    minFee,
				spendable: 100_000_000,
			},
			slots:         10,
			wantDeposited: 0,
			wantDeposits:  0,
		},
		{
			name: "first deposit opts in",
			pool: &fakePool{
				ticketMbr:   testTicketMbr,
				dep:         escrow.PayerDeposit{}, // no pool yet
				optedIn:     false,
				minFee:      minFee,
				spendable:   100_000_000,
				depositTxID: "DEPOSITTX",
			},
			slots:         10,
			wantTxID:      "DEPOSITTX",
			wantDeposited: 10 * testTicketMbr,
			wantDeposits:  1,
			wantOptIn:     true,
		},
		{
			name: "shortfall top-up does not opt in",
			pool: &fakePool{
				ticketMbr:   testTicketMbr,
				dep:         escrow.PayerDeposit{AlgoBalance: 4 * testTicketMbr},
				optedIn:     true,
				minFee:      minFee,
				spendable:   100_000_000,
				depositTxID: "TOPUPTX",
			},
			slots:         10,
			wantTxID:      "TOPUPTX",
			wantDeposited: 6 * testTicketMbr, // 10 - 4 already deposited
			wantDeposits:  1,
			wantOptIn:     false,
		},
		{
			// Live tickets are BORROWED slots, not missing ones — they come back
			// at settle. Sizing must therefore ignore OpenTickets: a pool holding
			// its full working set is fully funded no matter how much of it is in
			// flight. Reading utilization as a funding gap would ratchet the pool
			// upward with concurrency (ensureDepositForServe deliberately does not
			// latch while under target, so every request would re-size against
			// however many tickets happened to be open), and would put the proxy
			// out of step with the client, which sizes off gross balance too.
			name: "live tickets do not inflate the target (sized on gross balance)",
			pool: &fakePool{
				ticketMbr:   testTicketMbr,
				dep:         escrow.PayerDeposit{AlgoBalance: 10 * testTicketMbr, OpenTickets: 2},
				optedIn:     true,
				minFee:      minFee,
				spendable:   100_000_000,
				depositTxID: "SHOULDNOTFIRE",
			},
			slots:         10,
			wantTxID:      "",
			wantDeposited: 0,
			wantDeposits:  0,
		},
		{
			name: "ticket MBR not loaded errors",
			pool: &fakePool{
				ticketMbr: 0,
				minFee:    minFee,
				spendable: 100_000_000,
			},
			slots:         10,
			wantErrSubstr: "ticket MBR not loaded",
		},
		{
			name: "unaffordable slot returns sentinel",
			pool: &fakePool{
				ticketMbr: testTicketMbr,
				dep:       escrow.PayerDeposit{},
				optedIn:   false,
				minFee:    minFee,
				spendable: 380_000, // short of one 115_000 slot + 2_000 fee + 271_000 opt-in MBR
			},
			slots:        10,
			wantErrIs:    ErrDepositUnaffordable,
			wantDeposits: 0,
		},
		{
			// A pool with no slot needs a slot before the box term is any use,
			// so that is the cost the message names, even with the term owed.
			name: "unaffordable empty pool owing the quota asks for a slot",
			pool: &fakePool{
				ticketMbr:    testTicketMbr,
				freeQuotaMbr: 22_500,
				dep:          escrow.PayerDeposit{},
				optedIn:      false,
				minFee:       minFee,
				spendable:    380_000,
			},
			slots:         10,
			wantErrSubstr: "one more slot needs 388000 µALGO",
		},
		{
			// A pool at exactly the working set in whole slots still owes the box
			// term until the first free open; the early "covered" return must count it.
			name: "full slots still fund the owed quota term",
			pool: &fakePool{
				ticketMbr:    testTicketMbr,
				freeQuotaMbr: 22_500,
				dep:          escrow.PayerDeposit{AlgoBalance: 10 * testTicketMbr},
				optedIn:      true,
				minFee:       minFee,
				spendable:    100_000_000,
				depositTxID:  "QUOTATX",
			},
			slots:         10,
			wantTxID:      "QUOTATX",
			wantDeposited: 22_500,
			wantDeposits:  1,
		},
		{
			// The working set is an ideal, not a requirement: a wallet that can't
			// reach it funds the whole slots it can, and says it fell short.
			name: "thin wallet funds the slots it affords",
			pool: &fakePool{
				ticketMbr:   testTicketMbr,
				dep:         escrow.PayerDeposit{},
				optedIn:     false,
				minFee:      minFee,
				spendable:   2*testTicketMbr + 2*minFee + depositOptInMBR + 1_000,
				depositTxID: "PARTIALTX",
			},
			slots:         10,
			wantTxID:      "PARTIALTX",
			wantDeposited: 2 * testTicketMbr,
			wantDeposits:  1,
			wantOptIn:     true,
			wantErrIs:     ErrDepositBelowTarget,
		},
		{
			name: "zero slots falls back to default",
			pool: &fakePool{
				ticketMbr:   testTicketMbr,
				dep:         escrow.PayerDeposit{},
				optedIn:     false,
				minFee:      minFee,
				spendable:   100_000_000,
				depositTxID: "DEFAULTTX",
			},
			slots:         0,
			wantTxID:      "DEFAULTTX",
			wantDeposited: DefaultDepositSlots * testTicketMbr,
			wantDeposits:  1,
			wantOptIn:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := newPoolWallet(tc.pool)
			txid, deposited, err := w.EnsureDeposit(ctx, tc.slots)

			if tc.wantErrIs != nil {
				if !errors.Is(err, tc.wantErrIs) {
					t.Fatalf("err = %v, want errors.Is %v", err, tc.wantErrIs)
				}
				if tc.wantDeposits == 0 {
					if tc.pool.depositCalls != 0 {
						t.Errorf("deposit calls = %d, want 0 (no submit on unaffordable)", tc.pool.depositCalls)
					}
					return
				}
				// A partial deposit: the error rides with a real one, checked below.
			} else if tc.wantErrSubstr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErrSubstr) {
					t.Fatalf("err = %v, want substring %q", err, tc.wantErrSubstr)
				}
				return
			} else if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if txid != tc.wantTxID {
				t.Errorf("txid = %q, want %q", txid, tc.wantTxID)
			}
			if deposited != tc.wantDeposited {
				t.Errorf("deposited = %d, want %d", deposited, tc.wantDeposited)
			}
			if tc.wantDeposits > 0 && tc.pool.depositedAmt != tc.wantDeposited {
				t.Errorf("ComposeDepositMbr amount = %d, want %d (what was sent must be what is reported)", tc.pool.depositedAmt, tc.wantDeposited)
			}
			if tc.pool.depositCalls != tc.wantDeposits {
				t.Errorf("deposit calls = %d, want %d", tc.pool.depositCalls, tc.wantDeposits)
			}
			if tc.wantDeposits > 0 && tc.pool.lastOptIn != tc.wantOptIn {
				t.Errorf("ComposeDepositMbr optIn = %v, want %v", tc.pool.lastOptIn, tc.wantOptIn)
			}
		})
	}
}

func TestDepositShortfall_SizesOnGrossBalance(t *testing.T) {
	// 10 slots wanted, 10 deposited, 3 of them on loan to live tickets → the
	// pool is the right SIZE, so nothing is short. Sizing free-of-reserved here
	// would report a 3-slot gap purely because the proxy was busy, and — since
	// ensureDepositForServe leaves depositReady false while under target — would
	// re-report it on every request, growing the deposit with concurrency rather
	// than with need. Matches the client's gross-balance sizing.
	dep := escrow.PayerDeposit{AlgoBalance: 10 * testTicketMbr, OpenTickets: 3}
	if got := DepositShortfall(10, testTicketMbr, 0, dep); got != 0 {
		t.Errorf("shortfall = %d, want 0 (live tickets are borrowed slots, not a funding gap)", got)
	}
	// A genuinely undersized pool is still reported, open tickets or not.
	under := escrow.PayerDeposit{AlgoBalance: 7 * testTicketMbr, OpenTickets: 3}
	if got := DepositShortfall(10, testTicketMbr, 0, under); got != 3*testTicketMbr {
		t.Errorf("shortfall = %d, want %d", got, 3*testTicketMbr)
	}
	// Fully free → no shortfall.
	if got := DepositShortfall(10, testTicketMbr, 0, escrow.PayerDeposit{AlgoBalance: 10 * testTicketMbr}); got != 0 {
		t.Errorf("shortfall = %d, want 0", got)
	}
	// Reserved exceeds balance (shouldn't happen on chain, but don't underflow).
	if got := DepositShortfall(1, testTicketMbr, 0, escrow.PayerDeposit{AlgoBalance: 0, OpenTickets: 5}); got != testTicketMbr {
		t.Errorf("shortfall = %d, want %d (no underflow)", got, testTicketMbr)
	}
}

// The free-quota box MBR is an additional term in the target, so a pool
// sized only for ticket slots reports it as a shortfall. Without it a payer's
// FIRST free (max_price 0) request fails on the contract's pool guard even
// though `zs fund` said the pool was fully backed.
func TestDepositShortfall_IncludesFreeQuotaBoxMbr(t *testing.T) {
	const quotaMbr = 22_500
	// Exactly 10 slots deposited, nothing reserved: without the quota term this
	// is fully backed; with it, the box MBR is the whole shortfall.
	dep := escrow.PayerDeposit{AlgoBalance: 10 * testTicketMbr}
	if got := DepositShortfall(10, testTicketMbr, quotaMbr, dep); got != quotaMbr {
		t.Errorf("shortfall = %d, want %d (the one-time free-quota box MBR)", got, quotaMbr)
	}
	// Covered once it's deposited.
	dep.AlgoBalance += quotaMbr
	if got := DepositShortfall(10, testTicketMbr, quotaMbr, dep); got != 0 {
		t.Errorf("shortfall = %d, want 0 once the quota MBR is deposited", got)
	}
	// An app with no free-ticket quota contributes nothing (the 0 above), so
	// sizing is byte-identical to the pre-feature behavior.
	if got := DepositShortfall(10, testTicketMbr, 0, escrow.PayerDeposit{AlgoBalance: 10 * testTicketMbr}); got != 0 {
		t.Errorf("shortfall = %d, want 0 against an app without the quota", got)
	}
}

// TestDepositExcess_IsShortfallInverse pins DepositExcess against
// DepositShortfall across the same target: at most one of them is non-zero, and
// together they say how far the pool is from `slots` in either direction. A
// bug that made both fire (or neither) would let `zs slots <n>` deposit and
// withdraw on the same pool.
func TestDepositExcess_IsShortfallInverse(t *testing.T) {
	const quotaMbr = 22_500
	tests := []struct {
		name          string
		slots         uint64
		balance       uint64
		freeQuotaMbr  uint64
		wantExcess    uint64
		wantShortfall uint64
	}{
		{
			name: "under target", slots: 10, balance: 4 * testTicketMbr,
			wantShortfall: 6 * testTicketMbr,
		},
		{
			name: "exactly at target", slots: 10, balance: 10 * testTicketMbr,
		},
		{
			name: "over target", slots: 10, balance: 14 * testTicketMbr,
			wantExcess: 4 * testTicketMbr,
		},
		{
			// The quota box term is part of the target, so a pool holding
			// exactly slots×mbr is SHORT by it — and shrinking must leave it
			// behind rather than reclaiming it into an inevitable re-deposit.
			name: "quota term counts toward the target", slots: 10,
			balance: 10 * testTicketMbr, freeQuotaMbr: quotaMbr,
			wantShortfall: quotaMbr,
		},
		{
			name: "excess is measured above the quota term too", slots: 10,
			balance: 12*testTicketMbr + quotaMbr, freeQuotaMbr: quotaMbr,
			wantExcess: 2 * testTicketMbr,
		},
		{
			// Sizing is gross: in-flight tickets are a transient loan, not a
			// reason to think the pool is the wrong size.
			name: "open tickets do not change either figure", slots: 10,
			balance: 14 * testTicketMbr, wantExcess: 4 * testTicketMbr,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dep := escrow.PayerDeposit{AlgoBalance: tc.balance, OpenTickets: 7}
			gotExcess := DepositExcess(tc.slots, testTicketMbr, tc.freeQuotaMbr, dep)
			gotShort := DepositShortfall(tc.slots, testTicketMbr, tc.freeQuotaMbr, dep)
			if gotExcess != tc.wantExcess {
				t.Errorf("excess = %d, want %d", gotExcess, tc.wantExcess)
			}
			if gotShort != tc.wantShortfall {
				t.Errorf("shortfall = %d, want %d", gotShort, tc.wantShortfall)
			}
			if gotExcess > 0 && gotShort > 0 {
				t.Errorf("both fired: excess %d and shortfall %d", gotExcess, gotShort)
			}
		})
	}
}

// TestPoolSizing_SaturatesInsteadOfWrapping is the guard against a slot count
// large enough to overflow `slots*ticketMbr`. Wrapping produces a TINY target,
// which inverts the whole command: a request to GROW the pool reports an excess,
// the shrink path reclaims the free headroom, and every later sizing pass sees
// that tiny target already satisfied — so the auto-top-up never fires again and
// the payer silently stops being able to open tickets.
//
// The count arrives from config and env too, not just a CLI argument, which is
// why this lives in the shared arithmetic.
func TestPoolSizing_SaturatesInsteadOfWrapping(t *testing.T) {
	// Chosen to land inside the wrap band: slots*ticketMbr exceeds MaxUint64.
	const huge = math.MaxUint64/testTicketMbr + 1
	dep := escrow.PayerDeposit{AlgoBalance: 25 * testTicketMbr, OpenTickets: 5}

	if got := DepositExcess(huge, testTicketMbr, 0, dep); got != 0 {
		t.Errorf("excess = %d, want 0 — a raise must never report reclaimable ALGO", got)
	}
	if got := DepositShortfall(huge, testTicketMbr, 0, dep); got == 0 {
		t.Error("shortfall = 0 for an enormous target; it must fail loudly, not read as satisfied")
	}
	// The free-quota term is chain-fed, so it must not wrap the addition either.
	if got := DepositExcess(math.MaxUint64/testTicketMbr, testTicketMbr, math.MaxUint64-10, dep); got != 0 {
		t.Errorf("excess = %d, want 0 when the quota term overflows the sum", got)
	}
	// MaxUint64 slots was always safe (it lands on a colossal shortfall); pin
	// it so a future "optimisation" can't make it the unsafe one.
	if got := DepositExcess(math.MaxUint64, testTicketMbr, 0, dep); got != 0 {
		t.Errorf("excess = %d, want 0 at MaxUint64 slots", got)
	}
	// And ordinary sizing is unaffected by the guard.
	if got := DepositExcess(10, testTicketMbr, 0, escrow.PayerDeposit{AlgoBalance: 14 * testTicketMbr}); got != 4*testTicketMbr {
		t.Errorf("excess = %d, want %d — the guard must not disturb normal sizing", got, 4*testTicketMbr)
	}
}

// TestPoolTarget covers the saturating multiply/add directly, including the
// ticketMbr == 0 case where the overflow check itself would divide by zero.
func TestPoolTarget(t *testing.T) {
	tests := []struct {
		name                           string
		slots, ticketMbr, freeQuotaMbr uint64
		want                           uint64
	}{
		{name: "ordinary", slots: 10, ticketMbr: 100, want: 1000},
		{name: "with the quota term", slots: 10, ticketMbr: 100, freeQuotaMbr: 25, want: 1025},
		{name: "zero ticket mbr cannot divide by zero", slots: math.MaxUint64, ticketMbr: 0, freeQuotaMbr: 7, want: 7},
		{name: "multiply overflows", slots: math.MaxUint64, ticketMbr: 2, want: math.MaxUint64},
		{name: "addition overflows", slots: 1, ticketMbr: 2, freeQuotaMbr: math.MaxUint64 - 1, want: math.MaxUint64},
		{name: "exactly at the boundary", slots: math.MaxUint64 / 2, ticketMbr: 2, want: math.MaxUint64 - 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := poolTarget(tc.slots, tc.ticketMbr, tc.freeQuotaMbr); got != tc.want {
				t.Errorf("poolTarget(%d, %d, %d) = %d, want %d",
					tc.slots, tc.ticketMbr, tc.freeQuotaMbr, got, tc.want)
			}
		})
	}
}

// TestDepositExcess_IsNotTheWithdrawableAmount keeps the two apart. Excess is a
// SIZING answer on gross balance; the contract admits a withdraw only against
// the unreserved balance. Folding the bound into DepositExcess would make an
// oversized-but-busy pool look freely reclaimable and revert on chain.
func TestDepositExcess_IsNotTheWithdrawableAmount(t *testing.T) {
	dep := escrow.PayerDeposit{AlgoBalance: 25 * testTicketMbr, OpenTickets: 20}
	excess := DepositExcess(10, testTicketMbr, 0, dep)
	headroom := FreePoolHeadroom(testTicketMbr, dep)
	if excess != 15*testTicketMbr {
		t.Errorf("excess = %d, want %d (gross basis)", excess, 15*testTicketMbr)
	}
	if headroom != 5*testTicketMbr {
		t.Errorf("headroom = %d, want %d", headroom, 5*testTicketMbr)
	}
	if excess <= headroom {
		t.Fatal("this case exists to prove excess can exceed what is withdrawable")
	}
}

// validTicket returns a Ticket with a decodable 16-byte ticket id, the minimum
// Wallet.Open's pre-submit validation needs.
func validTicket() *ticket.Ticket {
	return &ticket.Ticket{
		TicketID:  base64.StdEncoding.EncodeToString(make([]byte, 16)),
		MaxPrice:  1_000_000,
		ExpiresAt: 1_700_000_123,
	}
}

func validOperator() Operator {
	return Operator{ID: 1, NodeID: 1, OwnerAddr: "OWNER", SigningAddr: testSignerAddr}
}

func TestOpen_DepositRevert_RetryFiresWhenTopUpDeposits(t *testing.T) {
	ctx := context.Background()
	// depositReady seeded true so ensureDepositForServe is a no-op and the FIRST
	// submit runs against a (scripted) revert. The retry path then resets ready,
	// re-ensures, and because the pool reads as drained it deposits (>0) and
	// retries the same group once.
	pool := &fakePool{
		ticketMbr:   testTicketMbr,
		dep:         escrow.PayerDeposit{}, // drained → re-ensure deposits
		optedIn:     true,
		minFee:      1_000,
		spendable:   100_000_000,
		depositTxID: "RETRYDEPOSIT",
		submitResults: []submitOutcome{
			{err: errors.New("escrow: submit open pc=123: insufficient MBR deposit")},
			{res: escrow.OpenResult{TxIDs: []string{"USDC", "APPCALL"}, GroupID: "GID"}},
		},
	}
	w := newPoolWallet(pool)
	w.depositReady = true // skip the upfront ensure so the revert path is what tops up

	h, err := w.Open(ctx, validTicket(), validOperator(), []types.SignedTxn{{}, {}})
	if err != nil {
		t.Fatalf("Open: unexpected err: %v", err)
	}
	if h.AppCallTxID != "APPCALL" {
		t.Errorf("AppCallTxID = %q, want APPCALL", h.AppCallTxID)
	}
	if pool.submitCalls != 2 {
		t.Errorf("submit calls = %d, want 2 (revert + retry after top-up)", pool.submitCalls)
	}
	if pool.depositCalls != 1 {
		t.Errorf("deposit calls = %d, want 1 (the revert re-ensure top-up)", pool.depositCalls)
	}
}

func TestOpen_DepositRevert_NoTopUpSurfacesOriginal(t *testing.T) {
	ctx := context.Background()
	// Pool already covers the working set, so the revert re-ensure no-ops
	// (deposited == 0) and the original submit error surfaces — exhaustion that
	// can only self-heal as in-flight tickets settle, not a fundable shortfall.
	pool := &fakePool{
		ticketMbr: testTicketMbr,
		dep:       escrow.PayerDeposit{AlgoBalance: 100 * testTicketMbr},
		optedIn:   true,
		minFee:    1_000,
		spendable: 100_000_000,
		submitResults: []submitOutcome{
			{err: errors.New("escrow: submit open pc=123: insufficient MBR deposit")},
		},
	}
	w := newPoolWallet(pool)
	w.depositReady = true

	_, err := w.Open(ctx, validTicket(), validOperator(), []types.SignedTxn{{}, {}})
	if err == nil {
		t.Fatal("Open: expected error to surface, got nil")
	}
	if !strings.Contains(err.Error(), "insufficient MBR deposit") {
		t.Errorf("err = %v, want the original revert surfaced", err)
	}
	if pool.submitCalls != 1 {
		t.Errorf("submit calls = %d, want 1 (no retry when re-ensure no-ops)", pool.submitCalls)
	}
	if pool.depositCalls != 0 {
		t.Errorf("deposit calls = %d, want 0 (pool already covered)", pool.depositCalls)
	}
}

// A pool revert the top-up could not clear because the payer can't afford it
// surfaces both: the revert, still typed, and the top-up's failure, which
// names what the pool needs and decides the caller's answer.
func TestOpen_DepositRevert_TopUpFailureRidesAlong(t *testing.T) {
	ctx := context.Background()
	pool := &fakePool{
		ticketMbr: testTicketMbr,
		dep:       escrow.PayerDeposit{}, // drained → the re-ensure wants to deposit
		optedIn:   true,
		minFee:    1_000,
		spendable: 0, // and can't
		submitResults: []submitOutcome{
			{err: &escrow.ApprovalError{Method: "open", Message: escrow.AssertPayerHasNoMbrDeposit, Err: errors.New("assert failed")}},
		},
	}
	w := newPoolWallet(pool)
	w.depositReady = true

	_, err := w.Open(ctx, validTicket(), validOperator(), []types.SignedTxn{{}, {}})
	if !errors.Is(err, ErrDepositUnaffordable) {
		t.Errorf("err = %v, want the top-up's ErrDepositUnaffordable", err)
	}
	if revert, ok := errors.AsType[*escrow.ApprovalError](err); !ok || revert.Message != escrow.AssertPayerHasNoMbrDeposit {
		t.Errorf("err = %v, want the open revert still typed", err)
	}
	if pool.submitCalls != 1 {
		t.Errorf("submit calls = %d, want 1: nothing was deposited to retry on", pool.submitCalls)
	}
}

// algodRejectingSubmit serves suggested-params and answers the submit with
// algod's real logic-eval-error shape for the given PC. algod knows nothing
// about the contract's assert strings — a PC is the whole signal on the wire.
func algodRejectingSubmit(t *testing.T, pc uint64) algod.Client {
	t.Helper()
	return algodAnsweringSubmit(t, func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(w, `{"message":"TransactionPool.Remember: logic eval error: assert failed pc=%d. Details: pc=%d"}`, pc, pc)
	})
}

func algodAnsweringSubmit(t *testing.T, submit func(http.ResponseWriter)) algod.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v2/transactions/params"):
			w.Header().Set("Content-Type", "application/json")
			gh := base64.StdEncoding.EncodeToString(make([]byte, 32))
			_, _ = io.WriteString(w, `{"consensus-version":"v30","fee":1000,"genesis-id":"dev-v1","genesis-hash":"`+gh+`","last-round":100,"min-fee":1000}`)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v2/transactions"):
			_, _ = io.Copy(io.Discard, r.Body)
			submit(w)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	c, err := algod.NewClient(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("algod.NewClient: %v", err)
	}
	return c
}

// TestPoolEscrowAdapter_RevertStaysTyped covers the one link in the
// open→429 chain that no other test touches: poolEscrowAdapter is the sole
// production edge between escrow.Client and Wallet.Open, and every other test
// on this path substitutes fakePool for it.
//
// The line it guards did not change in this work — its load-bearingness did.
// The dispatch classifier used to read err.Error(), which any wrap verb
// preserves, so the adapter could not break it; it now reads errors.AsType,
// which a %v erases. A type-erasing wrap here silently converts every
// MBR-pool revert from an actionable 429 naming zs.concurrent_slots into an
// opaque 502.
func TestPoolEscrowAdapter_RevertStaysTyped(t *testing.T) {
	spec, err := escrow.GetSpec()
	if err != nil {
		t.Fatal(err)
	}
	var pc uint64
	for probe := uint64(0); probe < 200_000 && pc == 0; probe++ {
		if msg, ok := spec.ApprovalErrorMessage(probe); ok && msg == escrow.AssertInsufficientMbrDeposit {
			pc = probe
		}
	}
	if pc == 0 {
		t.Fatalf("no PC in the embedded ARC-56 maps to %q", escrow.AssertInsufficientMbrDeposit)
	}

	payer := crypto.GenerateAccount()
	operator := crypto.GenerateAccount()

	client, err := escrow.NewClient(1234, algodRejectingSubmit(t, pc))
	if err != nil {
		t.Fatalf("escrow.NewClient: %v", err)
	}
	client.TicketMbr = testTicketMbr
	client.UsdcAssetID = 31566704

	ticketIDRaw := make([]byte, 16)
	copy(ticketIDRaw, "ticket-id-16byte")

	group, err := client.ComposeOpenGroup(context.Background(), escrow.OpenArgs{
		TicketIDRaw:            ticketIDRaw,
		OperatorID:             7,
		NodeID:                 11,
		PayerAddr:              payer.Address.String(),
		MaxPrice:               1_000_000,
		ExpiresAt:              2_000_000_000,
		SettlementGraceSeconds: 60,
	}, transaction.BasicAccountTransactionSigner{Account: operator}, operator.Address.String())
	if err != nil {
		t.Fatalf("ComposeOpenGroup: %v", err)
	}

	// The chain-config fields are stamped by the adapter, so the spec here
	// carries only the per-request half.
	_, err = poolEscrowAdapter{c: client}.SubmitPresignedOpenGroup(
		context.Background(), group,
		transaction.BasicAccountTransactionSigner{Account: payer},
		escrow.OpenGroupSpec{
			TicketIDRaw:            ticketIDRaw,
			OperatorID:             7,
			NodeID:                 11,
			MaxPrice:               1_000_000,
			NodeSigningAddr:        operator.Address,
			PayerAddr:              payer.Address,
			ExpiresAt:              2_000_000_000,
			SettlementGraceSeconds: 60,
		},
	)
	if err == nil {
		t.Fatal("adapter returned nil error for a rejected submit")
	}
	revert, ok := errors.AsType[*escrow.ApprovalError](err)
	if !ok {
		t.Fatalf("err = %v, want the contract revert to survive the adapter untyped", err)
	}
	if revert.Message != escrow.AssertInsufficientMbrDeposit {
		t.Errorf("Message = %q, want %q", revert.Message, escrow.AssertInsufficientMbrDeposit)
	}
	// Method matters as much as Message and is the harder of the two to keep
	// honest: the dispatch classifier gates on it, but the value is stamped in
	// proto, a SEPARATE repo with a separate suite. A proto-side rename is red
	// there and silent here — the 429 quietly degrades to an opaque 502 with
	// every proxy test green. This assertion is the only thing binding the two.
	if revert.Method != "open" {
		t.Errorf("Method = %q, want %q — the dispatch classifier gates on it", revert.Method, "open")
	}
}

// TestOpen_RevertStaysTyped pins the wrap verb on Open's submit-error return.
// The dispatch layer classifies an MBR-pool revert with
// errors.AsType[*escrow.ApprovalError] to answer 429 mbr_pool_exhausted with
// the zs.concurrent_slots instruction; %v instead of %w flattens the chain,
// the assertion fails, and the payer gets an opaque 502 "payment group could
// not be submitted" for a condition the proxy knows exactly how to explain.
// The classifier's own test builds its wrap by hand, so this is the only place
// the production wrap is checked.
func TestOpen_RevertStaysTyped(t *testing.T) {
	ctx := context.Background()
	pool := &fakePool{
		ticketMbr: testTicketMbr,
		dep:       escrow.PayerDeposit{AlgoBalance: 100 * testTicketMbr},
		optedIn:   true,
		minFee:    1_000,
		spendable: 100_000_000,
		submitResults: []submitOutcome{
			{err: &escrow.ApprovalError{
				Method:  "open",
				PC:      3255,
				Message: escrow.AssertInsufficientMbrDeposit,
				Err:     errors.New("logic eval error: assert failed pc=3255"),
			}},
		},
	}
	w := newPoolWallet(pool)
	w.depositReady = true

	_, err := w.Open(ctx, validTicket(), validOperator(), []types.SignedTxn{{}, {}})
	if err == nil {
		t.Fatal("Open: expected the revert to surface, got nil")
	}
	revert, ok := errors.AsType[*escrow.ApprovalError](err)
	if !ok {
		t.Fatalf("err = %v, want the contract revert to stay unwrappable through Open's wrap", err)
	}
	if revert.Message != escrow.AssertInsufficientMbrDeposit {
		t.Errorf("Message = %q, want %q", revert.Message, escrow.AssertInsufficientMbrDeposit)
	}
}

// TestOpen_UnaffordableTopUp_ProceedsOnFreeSlot asserts an open is NOT refused
// when the greedy working-set top-up is unaffordable but the pool still has a
// free box-MBR slot to back this one request. This is the bug fix: a wallet
// short on ALGO for the full top-up — yet holding open-ticket headroom — must
// still serve, not surface a false 402.
func TestOpen_UnaffordableTopUp_ProceedsOnFreeSlot(t *testing.T) {
	ctx := context.Background()
	// Pool: 6 slots deposited (under the 10-slot working set), 5 in use → 1
	// free. EnsureDeposit wants a 4-slot top-up the wallet can't afford
	// (spendable far below), but there is 1 free slot, so the open commits
	// anyway. The pool has to be genuinely UNDER-SIZED for this path — sizing is
	// on gross balance, so 5 in-flight tickets alone would not make it short.
	pool := &fakePool{
		ticketMbr: testTicketMbr,
		dep:       escrow.PayerDeposit{AlgoBalance: 6 * testTicketMbr, OpenTickets: 5},
		optedIn:   true,
		minFee:    1_000,
		spendable: 100_000, // far below the 4*testTicketMbr top-up
		submitResults: []submitOutcome{
			{res: escrow.OpenResult{TxIDs: []string{"USDC", "APPCALL"}, GroupID: "GID"}},
		},
	}
	w := newPoolWallet(pool) // depositReady false → ensureDepositForServe runs

	h, err := w.Open(ctx, validTicket(), validOperator(), []types.SignedTxn{{}, {}})
	if err != nil {
		t.Fatalf("Open: unexpected err (should proceed on free slot): %v", err)
	}
	if h.AppCallTxID != "APPCALL" {
		t.Errorf("AppCallTxID = %q, want APPCALL", h.AppCallTxID)
	}
	if pool.submitCalls != 1 {
		t.Errorf("submit calls = %d, want 1 (open proceeds despite unaffordable top-up)", pool.submitCalls)
	}
	if pool.depositCalls != 0 {
		t.Errorf("deposit calls = %d, want 0 (top-up unaffordable, not attempted)", pool.depositCalls)
	}
	// Pool is below its working-set target, so readiness must NOT be cached —
	// the next request re-attempts the top-up as ALGO/settlements free up.
	if w.depositReady {
		t.Error("depositReady = true, want false (pool below target; retry next request)")
	}
}

// TestOpen_UnaffordableTopUp_ZeroFreeSlots_Fatal asserts that when the top-up
// is unaffordable AND the pool has zero free headroom (every slot reserved by a
// live ticket), the open fails with the ErrDepositUnaffordable sentinel intact —
// so the dispatch layer can surface the actionable "add ALGO" 402 rather than a
// misleading pool-exhausted retry or generic 502.
func TestOpen_UnaffordableTopUp_ZeroFreeSlots_Fatal(t *testing.T) {
	ctx := context.Background()
	pool := &fakePool{
		ticketMbr: testTicketMbr,
		dep:       escrow.PayerDeposit{AlgoBalance: 5 * testTicketMbr, OpenTickets: 5}, // 0 free
		optedIn:   true,
		minFee:    1_000,
		spendable: 100_000, // can't fund the top-up
	}
	w := newPoolWallet(pool)

	_, err := w.Open(ctx, validTicket(), validOperator(), []types.SignedTxn{{}, {}})
	if err == nil {
		t.Fatal("Open: expected ErrDepositUnaffordable, got nil")
	}
	if !errors.Is(err, ErrDepositUnaffordable) {
		t.Errorf("err = %v, want errors.Is ErrDepositUnaffordable (drives the mbr_pool_underfunded 402)", err)
	}
	if pool.submitCalls != 0 {
		t.Errorf("submit calls = %d, want 0 (never opened; zero headroom + unaffordable)", pool.submitCalls)
	}
}

func TestOpen_Success_TwoTxIDs(t *testing.T) {
	ctx := context.Background()
	pool := &fakePool{
		ticketMbr: testTicketMbr,
		dep:       escrow.PayerDeposit{AlgoBalance: 100 * testTicketMbr},
		optedIn:   true,
		minFee:    1_000,
		spendable: 100_000_000,
		submitResults: []submitOutcome{
			{res: escrow.OpenResult{TxIDs: []string{"USDC", "APPCALL"}, GroupID: "GID"}},
		},
	}
	w := newPoolWallet(pool)

	h, err := w.Open(ctx, validTicket(), validOperator(), []types.SignedTxn{{}, {}})
	if err != nil {
		t.Fatalf("Open: unexpected err: %v", err)
	}
	if h.AppCallTxID != "APPCALL" || h.GroupID != "GID" {
		t.Errorf("handle = %+v, want AppCallTxID=APPCALL GroupID=GID", h)
	}
	if pool.submitCalls != 1 {
		t.Errorf("submit calls = %d, want 1", pool.submitCalls)
	}

	// The spec threaded to the submit seam must pin the ticket + operator
	// snapshot — this is what the pre-sign VerifyOpenGroup in the production
	// adapter checks the node-composed group against.
	tk, op := validTicket(), validOperator()
	spec := pool.lastSpec
	if spec.MaxPrice != tk.MaxPrice {
		t.Errorf("spec.MaxPrice = %d, want %d", spec.MaxPrice, tk.MaxPrice)
	}
	if spec.ExpiresAt != uint64(tk.ExpiresAt) {
		t.Errorf("spec.ExpiresAt = %d, want %d", spec.ExpiresAt, tk.ExpiresAt)
	}
	if spec.SettlementGraceSeconds != 0 {
		t.Errorf("spec.SettlementGraceSeconds = %d, want pinned 0", spec.SettlementGraceSeconds)
	}
	if got := spec.NodeSigningAddr.String(); got != op.SigningAddr {
		t.Errorf("spec.NodeSigningAddr = %s, want %s", got, op.SigningAddr)
	}
	if got := spec.PayerAddr.String(); got != testPayerAddr {
		t.Errorf("spec.PayerAddr = %s, want %s", got, testPayerAddr)
	}
	if wantID := make([]byte, 16); !bytes.Equal(spec.TicketIDRaw, wantID) {
		t.Errorf("spec.TicketIDRaw = %x, want %x", spec.TicketIDRaw, wantID)
	}
}

func TestOpen_WrongTxIDCount(t *testing.T) {
	ctx := context.Background()
	pool := &fakePool{
		ticketMbr: testTicketMbr,
		dep:       escrow.PayerDeposit{AlgoBalance: 100 * testTicketMbr},
		optedIn:   true,
		minFee:    1_000,
		spendable: 100_000_000,
		submitResults: []submitOutcome{
			{res: escrow.OpenResult{TxIDs: []string{"ONLYONE"}}}, // wrong count
		},
	}
	w := newPoolWallet(pool)

	_, err := w.Open(ctx, validTicket(), validOperator(), []types.SignedTxn{{}, {}})
	if err == nil || !strings.Contains(err.Error(), "want 2") {
		t.Fatalf("err = %v, want a 'want 2' txid-count error", err)
	}
}

// The free-quota box term is sub-slot, so a wallet too thin to reach the full
// working set can still afford it — and MUST, or the payer's first free
// (max_price 0) open reverts forever with `insufficient MBR deposit for
// free-quota box` while the ≥1-free-slot fallback keeps letting requests
// through. EnsureDeposit degrades to a quota-only deposit instead of failing.
func TestEnsureDeposit_FallsBackToQuotaOnlyWhenFullTargetUnaffordable(t *testing.T) {
	const quotaMbr = 22_500
	p := &fakePool{
		ticketMbr:    testTicketMbr,
		freeQuotaMbr: quotaMbr,
		// Exactly 3 whole slots, no sub-slot remainder: the pool that predates
		// the quota.
		dep:     escrow.PayerDeposit{AlgoBalance: 3 * testTicketMbr},
		optedIn: true,
		minFee:  1_000,
		// Nowhere near the 7 more slots the full target wants, but comfortably
		// over the box term + fees.
		spendable:   50_000,
		depositTxID: "QUOTAONLYTX",
	}
	w := newPoolWallet(p)
	txid, deposited, err := w.EnsureDeposit(context.Background(), 10)
	// Partial success, and it must SAY so: the deposit is real, but the pool is
	// still short of the working set. A nil error here would latch depositReady
	// in ensureDepositForServe and freeze the pool where it stands for the
	// process lifetime — see TestEnsureDeposit_QuotaOnlyDoesNotLatchDepositReady.
	if !errors.Is(err, ErrDepositBelowTarget) {
		t.Fatalf("EnsureDeposit err = %v, want ErrDepositBelowTarget", err)
	}
	if errors.Is(err, ErrDepositUnaffordable) {
		t.Fatal("ErrDepositBelowTarget must not wrap ErrDepositUnaffordable — the deposit succeeded")
	}
	if txid != "QUOTAONLYTX" || deposited != quotaMbr {
		t.Fatalf("txid=%q deposited=%d, want QUOTAONLYTX / %d (quota term only)", txid, deposited, quotaMbr)
	}
	if p.depositedAmt != quotaMbr {
		t.Fatalf("ComposeDepositMbr amount = %d, want %d", p.depositedAmt, quotaMbr)
	}
}

// The partial deposit must NOT mark the pool ready. ensureDepositForServe
// latches depositReady on a nil error and then skips the top-up for the rest of
// the process, so treating "funded the sub-slot quota box" as success would
// strand the pool below its configured working set even after the wallet was
// refilled — recoverable only via an open that actually reverts.
func TestEnsureDeposit_QuotaOnlyDoesNotLatchDepositReady(t *testing.T) {
	const quotaMbr = 22_500
	p := &fakePool{
		ticketMbr:    testTicketMbr,
		freeQuotaMbr: quotaMbr,
		dep:          escrow.PayerDeposit{AlgoBalance: 3 * testTicketMbr},
		optedIn:      true,
		minFee:       1_000,
		spendable:    50_000,
		depositTxID:  "QUOTAONLYTX",
	}
	w := newPoolWallet(p)
	// 3 whole slots backed, none in flight → a free slot exists, so the serving
	// path proceeds rather than 402-ing.
	if err := w.ensureDepositForServe(context.Background()); err != nil {
		t.Fatalf("ensureDepositForServe: %v", err)
	}
	w.depositMu.Lock()
	ready := w.depositReady
	w.depositMu.Unlock()
	if ready {
		t.Fatal("depositReady latched after a below-target deposit; the pool would never be topped up again")
	}
}

// The degraded path must not fire when the wallet can't even afford the box
// term — that's a genuine ErrDepositUnaffordable, unchanged.
func TestEnsureDeposit_QuotaOnlyStillUnaffordable(t *testing.T) {
	p := &fakePool{
		ticketMbr:    testTicketMbr,
		freeQuotaMbr: 22_500,
		dep:          escrow.PayerDeposit{AlgoBalance: 3 * testTicketMbr},
		optedIn:      true,
		minFee:       1_000,
		spendable:    5_000, // < 22_500 + 2_000 fee
	}
	w := newPoolWallet(p)
	_, _, err := w.EnsureDeposit(context.Background(), 10)
	if !errors.Is(err, ErrDepositUnaffordable) {
		t.Fatalf("err = %v, want ErrDepositUnaffordable", err)
	}
	if p.depositCalls != 0 {
		t.Fatalf("deposit calls = %d, want 0", p.depositCalls)
	}
	// The pool lacks the box term before another slot, so that is what the
	// message asks for: 22_500 + 2_000 fee, not a whole slot.
	if !strings.Contains(err.Error(), "the free-quota box needs 24500 µALGO") {
		t.Fatalf("err = %v, want it to name the box term's need", err)
	}
}

// Once the pool's sub-slot remainder covers the term there is nothing to fund,
// so the degraded path stays quiet rather than re-depositing it every pass.
func TestQuotaOnlyShortfall_ZeroOnceCovered(t *testing.T) {
	const quotaMbr = 22_500
	covered := escrow.PayerDeposit{AlgoBalance: 3*testTicketMbr + quotaMbr}
	if got := quotaOnlyShortfall(testTicketMbr, quotaMbr, covered); got != 0 {
		t.Fatalf("shortfall = %d, want 0 once the remainder covers the term", got)
	}
	partial := escrow.PayerDeposit{AlgoBalance: 3*testTicketMbr + 10_000}
	if got := quotaOnlyShortfall(testTicketMbr, quotaMbr, partial); got != quotaMbr-10_000 {
		t.Fatalf("shortfall = %d, want %d (only the missing part)", got, quotaMbr-10_000)
	}
	// An app with no free-ticket quota contributes nothing.
	if got := quotaOnlyShortfall(testTicketMbr, 0, escrow.PayerDeposit{}); got != 0 {
		t.Fatalf("shortfall = %d, want 0 against an app without the quota", got)
	}
}

// Exactness: once the payer has a quota box the term is already spent, so it
// must drop out of the sizing target entirely. Without this the pool would keep
// re-funding a box MBR that can never be charged again, leaving every payer
// carrying a permanent slice of idle ALGO.
func TestEnsureDeposit_QuotaTermDropsOutOnceBoxExists(t *testing.T) {
	p := &fakePool{
		ticketMbr:      testTicketMbr,
		freeQuotaMbr:   22_500,
		quotaBoxExists: true,
		// Exactly the working set, no quota headroom — and none needed.
		dep:       escrow.PayerDeposit{AlgoBalance: 10 * testTicketMbr},
		optedIn:   true,
		minFee:    1_000,
		spendable: 100_000_000,
	}
	w := newPoolWallet(p)
	txid, deposited, err := w.EnsureDeposit(context.Background(), 10)
	if err != nil {
		t.Fatalf("EnsureDeposit: %v", err)
	}
	if txid != "" || deposited != 0 || p.depositCalls != 0 {
		t.Fatalf("txid=%q deposited=%d calls=%d, want a clean no-op — the box MBR is already spent",
			txid, deposited, p.depositCalls)
	}
}

// The box-exists answer is latched: existence is monotonic on chain (nothing
// deletes a quota box), so steady-state funding passes must not keep paying for
// the extra read.
func TestWallet_QuotaBoxExistenceIsLatched(t *testing.T) {
	p := &fakePool{ticketMbr: testTicketMbr, freeQuotaMbr: 22_500, quotaBoxExists: true}
	w := newPoolWallet(p)
	for i := 0; i < 5; i++ {
		if due := w.quotaMbrDue(context.Background()); due != 0 {
			t.Fatalf("pass %d: due = %d, want 0", i, due)
		}
	}
	if p.quotaDueCalls != 1 {
		t.Fatalf("quota-due reads = %d, want 1 (latched after the first)", p.quotaDueCalls)
	}
}

// Absence must NOT latch — the box appears the moment the payer's first free
// ticket opens, and a stale "absent" would keep the term in the target forever.
func TestWallet_QuotaBoxAbsenceIsNotLatched(t *testing.T) {
	p := &fakePool{ticketMbr: testTicketMbr, freeQuotaMbr: 22_500, quotaBoxExists: false}
	w := newPoolWallet(p)
	if due := w.quotaMbrDue(context.Background()); due != 22_500 {
		t.Fatalf("due = %d, want the full term while the box is absent", due)
	}
	p.quotaBoxExists = true // the payer's first free open just landed
	if due := w.quotaMbrDue(context.Background()); due != 0 {
		t.Fatalf("due = %d, want 0 once the box exists", due)
	}
	if p.quotaDueCalls != 2 {
		t.Fatalf("quota-due reads = %d, want 2 (absence re-read)", p.quotaDueCalls)
	}
}

// A pool with ZERO ticket slots must never take the quota-only path. The box
// term alone backs no ticket, so depositing it would leave the pool unable to
// open ANY ticket (free or paid) while reporting success — and because the
// error is nil, ensureDepositForServe latches depositReady, `zs-proxy fund`
// prints "wallet ready", and the actionable ErrDepositUnaffordable is never
// surfaced. Mirrors the client's `currentSlots >= 1n` guard.
func TestEnsureDeposit_QuotaOnlyRefusedWithNoTicketSlot(t *testing.T) {
	p := &fakePool{
		ticketMbr:    testTicketMbr,
		freeQuotaMbr: 22_500,
		dep:          escrow.PayerDeposit{}, // empty pool, no slots
		optedIn:      false,
		minFee:       1_000,
		// Covers 22_500 + 2_000 fee + the 271_000 opt-in MBR, but not a single
		// 115_000 ticket slot on top of the fee and opt-in.
		spendable:   380_000,
		depositTxID: "SHOULDNOTFIRE",
	}
	w := newPoolWallet(p)
	_, deposited, err := w.EnsureDeposit(context.Background(), 10)
	if !errors.Is(err, ErrDepositUnaffordable) {
		t.Fatalf("err = %v (deposited %d), want ErrDepositUnaffordable — a quota box with no ticket slot is useless",
			err, deposited)
	}
	if p.depositCalls != 0 {
		t.Fatalf("deposit calls = %d, want 0", p.depositCalls)
	}
}

// The box term is SUB-SLOT, so it always comes out of the pool's fractional
// part — and live tickets reserve only whole slots. quotaOnlyShortfall is
// therefore invariant to OpenTickets, and these cases pin that: the answer
// depends on the remainder alone, never on how much of the pool is spoken for.
// (The free-of-reserved basis in the implementation is there to match
// DepositShortfall on inspection; it is not what makes these pass. The place
// OpenTickets genuinely changes the outcome is the backedSlots guard — see
// TestEnsureDeposit_QuotaOnlyRefusedWhenEverySlotIsReserved.)
func TestQuotaOnlyShortfall_InvariantToOpenTickets(t *testing.T) {
	const quotaMbr = 22_500
	for _, openTickets := range []uint64{0, 3} {
		// Whole slots, no fractional part → the whole term is owed.
		whole := escrow.PayerDeposit{AlgoBalance: 3 * testTicketMbr, OpenTickets: openTickets}
		if got := quotaOnlyShortfall(testTicketMbr, quotaMbr, whole); got != quotaMbr {
			t.Errorf("openTickets=%d: shortfall = %d, want %d (no remainder backs the box)",
				openTickets, got, quotaMbr)
		}
		// Remainder already covers the term.
		covered := escrow.PayerDeposit{AlgoBalance: 3*testTicketMbr + quotaMbr, OpenTickets: openTickets}
		if got := quotaOnlyShortfall(testTicketMbr, quotaMbr, covered); got != 0 {
			t.Errorf("openTickets=%d: shortfall = %d, want 0 (remainder covers the term)",
				openTickets, got)
		}
		// Partial remainder → only the missing part.
		partial := escrow.PayerDeposit{AlgoBalance: 3*testTicketMbr + 10_000, OpenTickets: openTickets}
		if got := quotaOnlyShortfall(testTicketMbr, quotaMbr, partial); got != quotaMbr-10_000 {
			t.Errorf("openTickets=%d: shortfall = %d, want %d", openTickets, got, quotaMbr-10_000)
		}
	}
}

// The degraded quota-only path asks whether the pool is PROVISIONED for a
// ticket, not whether one is free this instant. A fully-utilized pool — every
// slot on loan to a live ticket — is correctly provisioned and gets its slots
// back at settle, so it must still be allowed to fund its quota box. Gating on
// free-of-reserved here would strand it on the error path for the duration of
// ordinary load, and the `zs-proxy fund` a user then ran would fail for a pool
// with nothing wrong with it.
func TestEnsureDeposit_QuotaOnlyAllowedWhilePoolIsFullyUtilized(t *testing.T) {
	const quotaMbr = 22_500
	p := &fakePool{
		ticketMbr:    testTicketMbr,
		freeQuotaMbr: quotaMbr,
		// 3 slots deposited, all 3 in flight. Provisioned, just busy.
		dep:         escrow.PayerDeposit{AlgoBalance: 3 * testTicketMbr, OpenTickets: 3},
		optedIn:     true,
		minFee:      1_000,
		spendable:   50_000, // covers the box term + fees, nowhere near a slot
		depositTxID: "QUOTAONLYTX",
	}
	w := newPoolWallet(p)
	txid, deposited, err := w.EnsureDeposit(context.Background(), 10)
	if !errors.Is(err, ErrDepositBelowTarget) {
		t.Fatalf("EnsureDeposit err = %v, want ErrDepositBelowTarget", err)
	}
	if txid != "QUOTAONLYTX" || deposited != quotaMbr {
		t.Fatalf("txid=%q deposited=%d, want QUOTAONLYTX / %d", txid, deposited, quotaMbr)
	}
}

// The ratchet this basis exists to prevent: EnsureDeposit runs repeatedly while
// the proxy serves (ensureDepositForServe deliberately leaves depositReady
// false whenever the pool is under target, so every request re-sizes), and each
// pass sees whatever tickets happen to be in flight. Free-of-reserved sizing
// reads that transient load as a funding gap, funds it, and then reads the NEXT
// burst as a gap too — so the deposit climbs with concurrency and never comes
// back down, even though the pool was correctly sized all along.
func TestEnsureDeposit_DoesNotRatchetWithInFlightTickets(t *testing.T) {
	const slots = 10
	p := &fakePool{
		ticketMbr:   testTicketMbr,
		dep:         escrow.PayerDeposit{AlgoBalance: slots * testTicketMbr},
		optedIn:     true,
		minFee:      1_000,
		spendable:   100_000_000, // affordability is never the binding constraint
		depositTxID: "RATCHETTX",
	}
	w := newPoolWallet(p)

	// Serving load: tickets open and settle across passes. Credit anything the
	// wallet deposits back to the pool, exactly as the chain would.
	for pass, openTickets := range []uint64{3, 7, 5, 9, 0} {
		p.dep.OpenTickets = openTickets
		_, deposited, err := w.EnsureDeposit(context.Background(), slots)
		if err != nil {
			t.Fatalf("pass %d: EnsureDeposit: %v", pass, err)
		}
		p.dep.AlgoBalance += deposited
	}

	if p.depositCalls != 0 {
		t.Fatalf("deposit calls = %d, want 0 — a correctly sized pool must not be topped up for being busy", p.depositCalls)
	}
	if p.dep.AlgoBalance != slots*testTicketMbr {
		t.Fatalf("pool balance = %d, want %d (unchanged); it grew with concurrency",
			p.dep.AlgoBalance, uint64(slots)*testTicketMbr)
	}
}
