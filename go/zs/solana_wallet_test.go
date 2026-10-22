/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/rpc"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/wire"
)

// walletCluster is rentChain with the deployment's Config, counting the reads
// of the pool.
type walletCluster struct {
	*rentChain
	config    *rpc.Account
	poolReads int
}

func (c *walletCluster) GetAccountInfo(ctx context.Context, k solana.PublicKey, cm rpc.Commitment) (*rpc.Account, error) {
	if k == c.d.Config() {
		if cm != rpc.Confirmed {
			panic("config read at " + string(cm))
		}
		return c.config, nil
	}
	c.poolReads++
	return c.rentChain.GetAccountInfo(ctx, k, cm)
}

// countingSolanaSigner counts the transactions it signs.
type countingSolanaSigner struct {
	testSolanaSigner
	asked atomic.Int32
}

func (s *countingSolanaSigner) SignTransactionMessage(ctx context.Context, address string, msg []byte) ([]byte, error) {
	s.asked.Add(1)
	return s.testSolanaSigner.SignTransactionMessage(ctx, address, msg)
}

func readSolanaFixture(t *testing.T, name string, v any) {
	t.Helper()
	b, err := os.ReadFile("../../testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

// solanaOpenFixture is the program's own open offer from the shared sign
// vectors, with the ticket, operator and cluster it was made for.
type solanaOpenFixture struct {
	cluster *walletCluster
	signer  *countingSolanaSigner
	wallet  *SolanaWallet
	ticket  *ticket.Ticket
	op      Operator
	offer   string
	// wire is the offer as the program's payer signed it.
	wire []byte
}

// newSolanaOpenFixture builds the fixture with a payer holding balance
// lamports and a rent pool funding poolSlots tickets, or none when negative.
// The working set is 3.
func newSolanaOpenFixture(t *testing.T, balance uint64, poolSlots int) *solanaOpenFixture {
	t.Helper()
	var sv struct {
		Mint   string `json:"usdc_mint"`
		Offers []struct {
			Name  string `json:"name"`
			Offer string `json:"offer_base64"`
			Wire  string `json:"wire_base64"`
			Spec  struct {
				NodeSigning string `json:"node_signing"`
				Payer       string `json:"payer"`
				PayerUSDC   string `json:"payer_usdc"`
			} `json:"spec"`
		} `json:"offers"`
	}
	readSolanaFixture(t, "solana_sign_vectors.json", &sv)
	var tv struct {
		Context struct {
			Keys map[string]struct {
				Seed byte `json:"seed"`
			} `json:"keys"`
		} `json:"context"`
	}
	readSolanaFixture(t, "solana_tx_vectors.json", &tv)
	var av struct {
		Accounts []struct {
			Name string `json:"name"`
			Data string `json:"data_base64"`
		} `json:"accounts"`
	}
	readSolanaFixture(t, "solana_account_vectors.json", &av)

	o := sv.Offers[0]
	if o.Name != "open" {
		t.Fatalf("first offer is %q, want the program's plain open", o.Name)
	}
	s := &countingSolanaSigner{testSolanaSigner: testSolanaSigner{ed25519.NewKeyFromSeed(bytes.Repeat([]byte{tv.Context.Keys["payer"].Seed}, 32))}}
	if s.Address() != o.Spec.Payer {
		t.Fatalf("payer key %s, offer's payer %s", s.Address(), o.Spec.Payer)
	}
	rc := newRentChain(t, s.testSolanaSigner, balance)
	rc.d.Mint = solana.MustPublicKey(sv.Mint)
	if poolSlots >= 0 {
		rc.withPool(testPoolRent+uint64(poolSlots)*testTicketRent, 0)
	}
	var config []byte
	for _, a := range av.Accounts {
		if a.Name == "config_initialized" {
			config, _ = base64.StdEncoding.DecodeString(a.Data)
		}
	}
	c := &walletCluster{rentChain: rc, config: &rpc.Account{Owner: rc.d.Program, Data: config}}
	w, err := NewSolanaWallet(t.Context(), SolanaWalletConfig{RPC: c, Deployment: rc.d, Signer: s, DepositSlots: 3,
		Confirm: rpc.ConfirmOptions{Poll: time.Millisecond, HeightCheck: time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	if w.payerUSDC.String() != o.Spec.PayerUSDC {
		t.Fatalf("payer USDC %s, offer's %s", w.payerUSDC, o.Spec.PayerUSDC)
	}
	w.now = func() time.Time { return time.Unix(1_790_000_000, 0) }
	wireBytes, err := base64.StdEncoding.DecodeString(o.Wire)
	if err != nil {
		t.Fatal(err)
	}
	return &solanaOpenFixture{
		cluster: c,
		signer:  s,
		wallet:  w,
		ticket: &ticket.Ticket{
			TicketID:   base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16)),
			OperatorID: 1,
			NodeID:     1,
			MaxPrice:   250_000,
			ExpiresAt:  1_790_000_300,
		},
		op:    Operator{ID: 1, NodeID: 1, OwnerAddr: "owner", SigningAddr: o.Spec.NodeSigning, ProtoVersion: wire.RailNeutralNamesMinVersion},
		offer: o.Offer,
		wire:  wireBytes,
	}
}

func (f *solanaOpenFixture) open(t *testing.T) (*OpenHandle, error) {
	t.Helper()
	return f.wallet.OpenForNode(t.Context(), f.ticket, f.op, f.offer)
}

// The wallet signs the node's offer exactly as the program's payer did, sends
// nothing, and hands over what the node reads.
func TestSolanaWallet_SignsTheNodesOffer(t *testing.T) {
	f := newSolanaOpenFixture(t, 1_000_000_000, 3)
	h, err := f.open(t)
	if err != nil {
		t.Fatal(err)
	}
	if len(h.SignedGroup) != 1 || !bytes.Equal(h.SignedGroup[0], f.wire) {
		t.Fatal("signed offer is not the program's payer-signed transaction")
	}
	if h.OpenGroup != base64.StdEncoding.EncodeToString(f.wire) {
		t.Fatalf("payment_open %q", h.OpenGroup)
	}
	tx, err := zsescrow.DecodeOpenPayment(h.OpenGroup, h.AppCallTxID)
	if err != nil {
		t.Fatalf("the node's reading: %v", err)
	}
	if h.AppCallTxID != tx.Signatures[0].String() {
		t.Fatalf("payment_ref %s", h.AppCallTxID)
	}
	if h.TicketID != f.ticket.TicketID || h.MaxPrice != f.ticket.MaxPrice || h.Operator.ID != 1 || h.OpenFeesMicroalgos != 0 {
		t.Fatalf("handle %+v", h)
	}
	if len(f.cluster.sent) != 0 {
		t.Fatalf("%d transactions sent", len(f.cluster.sent))
	}
}

// With no pool, the wallet funds one before it signs, and a pool the payer
// can't fund refuses the open with nothing signed, leaving the ticket free to
// open once the payer funds the wallet.
func TestSolanaWallet_FundsTheRentPoolBeforeSigning(t *testing.T) {
	f := newSolanaOpenFixture(t, 0, -1)
	if _, err := f.open(t); !errors.Is(err, ErrDepositUnaffordable) {
		t.Fatalf("err = %v, want the rent pool unaffordable", err)
	}
	if n := f.signer.asked.Load(); n != 0 {
		t.Fatalf("signed %d transactions with no pool", n)
	}
	f.cluster.balance = 1_000_000_000
	if _, err := f.open(t); err != nil {
		t.Fatal(err)
	}
	if len(f.cluster.sent) != 1 || f.cluster.pool == nil {
		t.Fatalf("%d sent, pool %v: want one deposit creating the pool", len(f.cluster.sent), f.cluster.pool)
	}
	if n := f.signer.asked.Load(); n != 2 {
		t.Fatalf("signed %d transactions, want the deposit and the offer", n)
	}
}

// A pool short of the working set still serves while it can fund this one
// ticket, and isn't latched ready, so the next open tries the top-up again; a
// pool that can fund none refuses the open.
func TestSolanaWallet_ServesOnAShortPool(t *testing.T) {
	f := newSolanaOpenFixture(t, 0, 1)
	if _, err := f.open(t); err != nil {
		t.Fatalf("one free slot: %v", err)
	}
	if n := f.signer.asked.Load(); n != 1 || len(f.cluster.sent) != 0 {
		t.Fatalf("signed %d, sent %d: want the offer alone", n, len(f.cluster.sent))
	}
	reads := f.cluster.balReads
	if err := f.wallet.ensureDepositForServe(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f.cluster.balReads != reads+1 {
		t.Fatal("a short pool was latched ready")
	}

	f = newSolanaOpenFixture(t, 0, 0)
	if _, err := f.open(t); !errors.Is(err, ErrDepositUnaffordable) {
		t.Fatalf("no free slot: err = %v, want the rent pool unaffordable", err)
	}
	if n := f.signer.asked.Load(); n != 0 {
		t.Fatalf("signed %d with no free slot", n)
	}
}

// A first deposit that lands short of the working set serves the open it
// funded, and the next open tries the top-up again.
func TestSolanaWallet_ServesOnADepositBelowTarget(t *testing.T) {
	// The pool's own rent, one ticket's and the fee, and no more.
	f := newSolanaOpenFixture(t, solanaSignerReserveLamports+testPoolRent+testTicketRent+solanaSignatureFee, -1)
	if _, err := f.open(t); err != nil {
		t.Fatal(err)
	}
	if len(f.cluster.sent) != 1 {
		t.Fatalf("%d sent, want one deposit", len(f.cluster.sent))
	}
	reads := f.cluster.balReads
	if err := f.wallet.ensureDepositForServe(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f.cluster.balReads != reads+1 {
		t.Fatal("a pool below target was latched ready")
	}
}

// A pool covering the working set is latched: later opens read nothing until
// a node's refusal clears the latch.
func TestSolanaWallet_LatchesACoveredPoolUntilRecheck(t *testing.T) {
	f := newSolanaOpenFixture(t, 1_000_000_000, 3)
	if _, err := f.open(t); err != nil {
		t.Fatal(err)
	}
	if f.cluster.poolReads != 1 {
		t.Fatalf("%d pool reads, want 1", f.cluster.poolReads)
	}
	if err := f.wallet.ensureDepositForServe(t.Context()); err != nil || f.cluster.poolReads != 1 {
		t.Fatalf("latched pool: err %v, %d reads", err, f.cluster.poolReads)
	}
	f.wallet.RecheckDeposit()
	if err := f.wallet.ensureDepositForServe(t.Context()); err != nil || f.cluster.poolReads != 2 {
		t.Fatalf("after recheck: err %v, %d reads", err, f.cluster.poolReads)
	}
}

// The ack binds the node's open_seq, which holds only while the payer signs
// one open per ticket: a second offer for the same ticket is refused before
// the signer is asked, unless the first was never signed.
func TestSolanaWallet_SignsOneOpenPerTicket(t *testing.T) {
	f := newSolanaOpenFixture(t, 1_000_000_000, 3)
	refused := *f.ticket
	refused.MaxPrice++
	var rej *zsescrow.OfferRejectedError
	if _, err := f.wallet.OpenForNode(t.Context(), &refused, f.op, f.offer); !errors.As(err, &rej) {
		t.Fatalf("err = %v, want the offer refused", err)
	}
	if _, err := f.open(t); err != nil {
		t.Fatalf("after a refused offer: %v", err)
	}
	if _, err := f.open(t); err == nil || !strings.Contains(err.Error(), "already signed, or is signing, an open") {
		t.Fatalf("second open: err = %v", err)
	}
	if n := f.signer.asked.Load(); n != 1 {
		t.Fatalf("signed %d offers, want one", n)
	}
}

// The wallet forgets a ticket once its open can no longer land, and not
// before.
func TestSolanaWallet_ForgetsATicketPastItsOpenWindow(t *testing.T) {
	f := newSolanaOpenFixture(t, 1_000_000_000, 3)
	if _, err := f.open(t); err != nil {
		t.Fatal(err)
	}
	edge := time.Unix(f.ticket.ExpiresAt, 0).Add(signedOpenRetention)
	f.wallet.now = func() time.Time { return edge }
	if _, err := f.open(t); err == nil {
		t.Fatal("re-signed at the end of the window")
	}
	f.wallet.now = func() time.Time { return edge.Add(time.Second) }
	if _, err := f.open(t); err != nil {
		t.Fatalf("past the window: %v", err)
	}
}

// The node submits the open from payment_open, so a node that reads only the
// Algorand names gets nothing signed, nor a node that doesn't submit opens.
func TestSolanaWallet_NeedsANodeThatReadsRailNeutralNames(t *testing.T) {
	f := newSolanaOpenFixture(t, 1_000_000_000, -1)
	old := f.op
	old.ProtoVersion = "9.12"
	if _, err := f.wallet.OpenForNode(t.Context(), f.ticket, old, f.offer); err == nil || !strings.Contains(err.Error(), "needs 9.13") {
		t.Fatalf("OpenForNode on 9.12: err = %v", err)
	}
	if _, err := f.wallet.Open(t.Context(), f.ticket, f.op, f.offer); err == nil {
		t.Fatal("Open signed for a node that doesn't submit")
	}
	if n := f.signer.asked.Load(); n != 0 || len(f.cluster.sent) != 0 {
		t.Fatalf("signed %d, sent %d", n, len(f.cluster.sent))
	}
}

// VerifyReceipt refuses a receipt for a ticket id in another spelling, so the
// wallet opens none.
func TestSolanaWallet_RefusesANonCanonicalTicketID(t *testing.T) {
	f := newSolanaOpenFixture(t, 1_000_000_000, 3)
	f.ticket.TicketID = "AQEBAQEBAQEBAQEBAQEBAR=="
	if _, err := f.open(t); err == nil || !strings.Contains(err.Error(), "canonical spelling") {
		t.Fatalf("err = %v", err)
	}
}

// The wallet checks offers against the Config's mint and decimals, so a
// Config missing or naming another mint fails construction.
func TestNewSolanaWallet_ChecksTheConfig(t *testing.T) {
	f := newSolanaOpenFixture(t, 0, -1)
	if f.wallet.decimals != 6 {
		t.Fatalf("decimals %d", f.wallet.decimals)
	}
	good := f.cluster.config
	foreign := *good
	foreign.Owner = solana.PublicKey{1}
	for _, tc := range []struct {
		name    string
		config  *rpc.Account
		mint    solana.PublicKey
		wantErr string
	}{
		{"no account", nil, f.cluster.d.Mint, "has no Config"},
		{"another owner", &foreign, f.cluster.d.Mint, "has no Config"},
		{"another mint", good, solana.PublicKey{2}, "not the deployment's"},
	} {
		f.cluster.config = tc.config
		d := f.cluster.d
		d.Mint = tc.mint
		_, err := NewSolanaWallet(t.Context(), SolanaWalletConfig{RPC: f.cluster, Deployment: d, Signer: f.signer})
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.wantErr)
		}
	}
}

// Dispatch finds the Solana wallet's open and its deposit recheck through
// these interfaces; one it stopped satisfying would take the payer-submits
// path or skip the recheck without a compile error elsewhere.
var (
	_ WalletOpener     = (*SolanaWallet)(nil)
	_ NodeOpener       = (*SolanaWallet)(nil)
	_ DepositRechecker = (*SolanaWallet)(nil)
)

// A Solana handle settles nothing yet, and says so.
func TestSolanaHandle_HasNoSettlePath(t *testing.T) {
	f := newSolanaOpenFixture(t, 1_000_000_000, 3)
	h, err := f.open(t)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.AckSettle(t.Context(), &ticket.UsageReceipt{}, ""); err == nil || !strings.Contains(err.Error(), "on Solana is not supported yet") {
		t.Fatalf("AckSettle: err = %v", err)
	}
	const want = "on Solana is not supported yet"
	r := &ticket.UsageReceipt{}
	if _, err := h.RefundInactive(t.Context()); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("RefundInactive: err = %v", err)
	}
	if _, _, err := h.Protest(t.Context(), r, nil, 1); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("Protest: err = %v", err)
	}
	if _, err := h.SettleLapsed(t.Context()); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("SettleLapsed: err = %v", err)
	}
	if _, _, claim, err := h.freezeOverclaim(t.Context(), r); claim != ClaimUnreadable || err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("freezeOverclaim: %v, err = %v", claim, err)
	}
}

// A ticket already signed for is refused before the pool is read, so a
// second offer for it costs no top-up even once the latch is cleared.
func TestSolanaWallet_RefusesASignedTicketBeforeThePool(t *testing.T) {
	f := newSolanaOpenFixture(t, 1_000_000_000, 3)
	if _, err := f.open(t); err != nil {
		t.Fatal(err)
	}
	f.wallet.RecheckDeposit()
	reads := f.cluster.poolReads
	if _, err := f.open(t); err == nil {
		t.Fatal("signed a second open")
	}
	if f.cluster.poolReads != reads {
		t.Fatalf("read the pool %d more times for a refused ticket", f.cluster.poolReads-reads)
	}
}

// The offer's transfer must carry the Config's decimals, not an assumed 6:
// against a Config of 9 decimals, the program's 6-decimal offer is refused.
func TestSolanaWallet_ChecksTheOfferAtTheConfigsDecimals(t *testing.T) {
	f := newSolanaOpenFixture(t, 1_000_000_000, 3)
	data := bytes.Clone(f.cluster.config.Data)
	data[12] = 9
	if c, err := zsescrow.DecodeConfig(data); err != nil || c.USDCDecimals != 9 {
		t.Fatalf("decimals byte: %v, %v", c, err)
	}
	f.cluster.config = &rpc.Account{Owner: f.cluster.d.Program, Data: data}
	w, err := NewSolanaWallet(t.Context(), SolanaWalletConfig{RPC: f.cluster, Deployment: f.cluster.d, Signer: f.signer, DepositSlots: 3})
	if err != nil {
		t.Fatal(err)
	}
	var rej *zsescrow.OfferRejectedError
	if _, err := w.OpenForNode(t.Context(), f.ticket, f.op, f.offer); !errors.As(err, &rej) {
		t.Fatalf("err = %v, want the offer refused", err)
	}
	if n := f.signer.asked.Load(); n != 0 {
		t.Fatalf("signed %d", n)
	}
}
