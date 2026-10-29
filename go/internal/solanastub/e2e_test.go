/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package solanastub_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/internal/solanastub"
	"github.com/TxnLab/zerosignal/go/keystore"
	"github.com/TxnLab/zerosignal/go/settle"
	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/rpc"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/zs"
)

// The scenarios run against a cluster holding zs_escrow: a local validator,
// as contracts-solana's `make localnet` starts one, or devnet.
// ZS_SOLANA_E2E_RPC names its endpoint. The run is funded by
// ZS_SOLANA_E2E_MINT_AUTHORITY, the keypair file of a local validator's test
// USDC mint's authority, which is also the Config's admin, or by
// ZS_SOLANA_E2E_FUNDER, a wallet's holding SOL and test USDC (see
// solanastub.Funding); without the endpoint and one of them they skip.
// ZS_SOLANA_E2E_CLUSTER is the payers' network preset, localnet unless it
// says devnet, and ZS_SOLANA_E2E_STUB_IDENTITY an identity file to serve as
// rather than register a node.
const (
	envRPC       = "ZS_SOLANA_E2E_RPC"
	envAuthority = "ZS_SOLANA_E2E_MINT_AUTHORITY"
	envFunder    = "ZS_SOLANA_E2E_FUNDER"
	envCluster   = "ZS_SOLANA_E2E_CLUSTER"
	envIdentity  = "ZS_SOLANA_E2E_STUB_IDENTITY"
)

// harness is the chain and the one stub node every scenario shares.
type harness struct {
	*solanastub.Stub
	cluster string
	// confirm bounds a wait on a transaction the node or payer sends.
	confirm time.Duration
}

var (
	setupOnce sync.Once
	shared    *harness
	setupErr  error
)

func setup(t *testing.T) *harness {
	t.Helper()
	endpoint, authority, funder := os.Getenv(envRPC), os.Getenv(envAuthority), os.Getenv(envFunder)
	if endpoint == "" || (authority == "" && funder == "") {
		t.Skipf("set %s and one of %s and %s to run against a cluster", envRPC, envAuthority, envFunder)
	}
	setupOnce.Do(func() { shared, setupErr = newHarness(endpoint, authority, funder) })
	if setupErr != nil {
		t.Fatal(setupErr)
	}
	return shared
}

func newHarness(endpoint, authorityFile, funderFile string) (*harness, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	h := &harness{cluster: zs.SolanaClusterLocalnet, confirm: 30 * time.Second}
	switch c := os.Getenv(envCluster); c {
	case "", zs.SolanaClusterLocalnet:
	case zs.SolanaClusterDevnet:
		h.cluster, h.confirm = zs.SolanaClusterDevnet, time.Minute
	default:
		return nil, fmt.Errorf("%s=%q: want localnet or devnet", envCluster, c)
	}
	o := solanastub.Options{Endpoint: endpoint, Listen: "127.0.0.1:0"}
	var err error
	if authorityFile != "" {
		if o.Funding.Authority, err = keystore.ReadSolanaKeypairFile(authorityFile); err != nil {
			return nil, err
		}
	}
	if funderFile != "" {
		if o.Funding.Funder, err = keystore.ReadSolanaKeypairFile(funderFile); err != nil {
			return nil, err
		}
	}
	if path := os.Getenv(envIdentity); path != "" {
		id, err := solanastub.ReadIdentity(path)
		if err != nil {
			return nil, err
		}
		o.Identity = &id
	}
	if h.Stub, err = solanastub.Start(ctx, o); err != nil {
		return nil, err
	}
	return h, nil
}

func newKey() ed25519.PrivateKey {
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}

// sweep hands back what key holds once the test ends, when a funder paid for
// it: SOL and test USDC on a shared cluster are topped up by hand, so a
// nightly run must not bleed them into throwaway keys. A scenario can end
// with its ticket still settling, and the settle's refund then lands between
// the balance read and the return, whose close fails on the balance it
// didn't send: so each step is tried again after a pause. The pool's close
// fails for good while a ticket stays frozen, which leaves its lamports
// behind. Any failure is logged, never a test's. Registered before the
// payer's Client, so it runs after the Client closes.
func (h *harness) sweep(t *testing.T, key ed25519.PrivateKey) {
	t.Helper()
	if h.Funding.Funder == nil {
		return
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 4*h.confirm)
		defer cancel()
		pool := &zs.SolanaRentPool{RPC: h.Chain.RPC, Deployment: h.Chain.Deployment, Signer: payerSigner{key}}
		closePool := func() error {
			st, err := pool.Status(ctx)
			if err != nil || !st.Exists {
				return err
			}
			_, _, err = pool.Close(ctx)
			return err
		}
		// The pool first: once the SOL is returned, nothing is left to pay
		// its close's fee.
		if err := retrySweep(ctx, closePool); err != nil {
			t.Logf("sweep: the rent pool: %v", err)
		}
		if err := retrySweep(ctx, func() error { return h.Chain.ReturnFunds(ctx, h.Funding, key) }); err != nil {
			t.Logf("sweep: %v", err)
		}
	})
}

// retrySweep runs step up to three times, five seconds apart, long enough
// for a settle in flight to land.
func retrySweep(ctx context.Context, step func() error) error {
	var err error
	for range 3 {
		if err = step(); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(5 * time.Second):
		}
	}
	return err
}

type payerSigner struct{ key ed25519.PrivateKey }

func (s payerSigner) Address() string { return solanastub.PublicKey(s.key).String() }
func (s payerSigner) SignBytes(_ context.Context, _ string, msg []byte) ([]byte, error) {
	return ed25519.Sign(s.key, msg), nil
}
func (s payerSigner) SignTransactionMessage(_ context.Context, _ string, msg []byte) ([]byte, error) {
	return ed25519.Sign(s.key, msg), nil
}

// payer is one funded payer and its own Client, so a node one scenario bars
// stays routable for the rest.
type payer struct {
	key    solana.PublicKey
	signer payerSigner
	client *zs.Client
}

const payerUSDC = solanastub.PayerUSDC

func (l *harness) newPayer(t *testing.T, b solanastub.Behavior) *payer {
	t.Helper()
	return l.newPayerWith(t, b, nil)
}

// newPayerWith is newPayer with edit applied to the Client's Config, which it
// gets with the payer's own key.
func (l *harness) newPayerWith(t *testing.T, b solanastub.Behavior, edit func(*zs.Config, solana.PublicKey)) *payer {
	t.Helper()
	return l.newPayerFunded(t, b, payerUSDC, edit)
}

// newPayerFunded is newPayerWith giving the payer usdc base units of test
// USDC rather than payerUSDC.
func (l *harness) newPayerFunded(t *testing.T, b solanastub.Behavior, usdc uint64, edit func(*zs.Config, solana.PublicKey)) *payer {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	key := newKey()
	pub := solanastub.PublicKey(key)
	l.sweep(t, key)
	if err := l.FundPayer(ctx, pub, usdc); err != nil {
		t.Fatal(err)
	}
	l.Node.SetBehavior(pub, b)
	cfg := zs.Config{
		SolanaSigner: payerSigner{key},
		Network: zs.Network{Rail: ticket.RailSolana, Solana: zs.SolanaNetwork{
			Cluster: l.cluster, RPCEndpoint: l.Chain.Endpoint, Program: l.Chain.Deployment.Program,
		}},
		// One node can't be its own relay.
		Privacy:           zs.PrivacyDirect,
		AllowPrivateHosts: true,
		DisableTEE:        true,
		Discovery:         zs.Discovery{OperatorIDs: []uint64{l.OperatorID}},
	}
	if edit != nil {
		edit(&cfg, pub)
	}
	client, err := zs.New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return &payer{key: pub, signer: payerSigner{key}, client: client}
}

// priced is every priced ticket the stub issued p, opened or not.
func (l *harness) priced(p *payer) []solanastub.Issued {
	var out []solanastub.Issued
	for _, is := range l.Node.Issued(p.key) {
		if is.MaxPrice > 0 {
			out = append(out, is)
		}
	}
	return out
}

// maxPrice is the max price of the ticket the stub issued p as id.
func (l *harness) maxPrice(t *testing.T, p *payer, id [16]byte) uint64 {
	t.Helper()
	for _, is := range l.Node.Issued(p.key) {
		if is.ID == id {
			return is.MaxPrice
		}
	}
	t.Fatalf("the stub issued payer no ticket %x", id)
	return 0
}

func chatBody(model string, stream bool) []byte {
	b, _ := json.Marshal(map[string]any{
		"model":      model,
		"messages":   []any{map[string]string{"role": "user", "content": "say hello"}},
		"max_tokens": 64,
		"stream":     stream,
	})
	return b
}

// ask runs one chat turn on the stub's priced model and waits for its
// settle submit.
func (p *payer) ask(t *testing.T, stream bool) (string, zs.Settlement, error, error) {
	t.Helper()
	return p.askModel(t, solanastub.Model, stream)
}

func (p *payer) askModel(t *testing.T, model string, stream bool) (string, zs.Settlement, error, error) {
	t.Helper()
	return p.askWithin(t, model, stream, 2*time.Minute)
}

// askWithin is askModel with the turn's budget, for a node a scenario has
// answer slowly.
func (p *payer) askWithin(t *testing.T, model string, stream bool, within time.Duration) (string, zs.Settlement, error, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), within)
	defer cancel()
	s := p.client.Stream(ctx, zs.Request{Endpoint: zs.EndpointChatCompletions, Body: chatBody(model, stream)})
	text, err := s.Text()
	set, werr := s.Wait(ctx)
	return text, set, err, werr
}

// askVerified is ask, also returning the turn's verified receipt, nil when
// it had none.
func (p *payer) askVerified(t *testing.T, stream bool) (string, *zs.ReceiptVerified, zs.Settlement, error, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	s := p.client.Stream(ctx, zs.Request{Endpoint: zs.EndpointChatCompletions, Body: chatBody(solanastub.Model, stream)})
	var b strings.Builder
	var verified *zs.ReceiptVerified
	var err error
	for ev, eerr := range s.Events() {
		if eerr != nil {
			err = eerr
			break
		}
		switch ev := ev.(type) {
		case zs.TextDelta:
			b.WriteString(ev.Delta)
		case zs.ReceiptVerified:
			verified = &ev
		}
	}
	set, werr := s.Wait(ctx)
	return b.String(), verified, set, err, werr
}

// onlyTicket is the one ticket p opened at the stub.
func (l *harness) onlyTicket(t *testing.T, p *payer) [16]byte {
	t.Helper()
	ids := l.Node.Opened(p.key)
	if len(ids) != 1 {
		t.Fatalf("payer opened %d tickets at the stub, want 1", len(ids))
	}
	return ids[0]
}

// waitTicket polls the ticket until done says it has reached the state a
// scenario waits for, or within fails the test.
func (l *harness) waitTicket(t *testing.T, id [16]byte, within time.Duration, what string, done func(*zsescrow.Ticket) bool) *zsescrow.Ticket {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(within)
	for {
		tk, err := l.Chain.Ticket(ctx, l.OperatorID, l.NodeID, id)
		if err != nil {
			t.Fatal(err)
		}
		if done(tk) {
			return tk
		}
		if time.Now().After(deadline) {
			t.Fatalf("ticket %x: not %s within %s (now %+v)", id, what, within, tk)
		}
		time.Sleep(time.Second)
	}
}

func closed(tk *zsescrow.Ticket) bool { return tk == nil }

// wantCode fails unless err is the SDK's error carrying the node's code, so a
// turn that failed some other way, timing out before the node answered, say,
// doesn't pass for the refusal a scenario drives.
func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	var zerr *zs.Error
	if !errors.As(err, &zerr) || zerr.Code != code {
		t.Errorf("turn error %v, want the node's %s", err, code)
	}
}

func (l *harness) usdc(t *testing.T, owner solana.PublicKey) uint64 {
	t.Helper()
	v, err := l.Chain.USDC(context.Background(), owner)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func (l *harness) checkStub(t *testing.T, p *payer) {
	t.Helper()
	for _, err := range l.Node.Errors(p.key) {
		t.Errorf("stub node: %v", err)
	}
}

// The payer opens, the node serves and settles on the payer's ack, and the
// payer pays exactly the receipt's amount.
func TestSolanaE2E_Settles(t *testing.T) {
	l := setup(t)
	for _, stream := range []bool{false, true} {
		name := map[bool]string{false: "buffered", true: "streamed"}[stream]
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			p := l.newPayer(t, solanastub.Behavior{})
			text, v, set, err, werr := p.askVerified(t, stream)
			if err != nil || werr != nil {
				t.Fatalf("turn: %v; settle: %v", err, werr)
			}
			if text != solanastub.Reply {
				t.Errorf("text = %q, want %q", text, solanastub.Reply)
			}
			// The fees are priced at the node's SOL rate, not the ALGO one it
			// also sends.
			if v == nil || v.NativeUSD != solanastub.SOLUSD || v.FeeUnit.Currency != "SOL" {
				t.Errorf("verified receipt %+v, want its fees priced at SOL/USD %v", v, solanastub.SOLUSD)
			}
			if set.Kind != zs.SettleAtomic || set.Frozen {
				t.Errorf("settlement = %+v, want the node's settle on the payer's ack", set)
			}
			id := l.onlyTicket(t, p)
			l.waitTicket(t, id, l.confirm, "settled", closed)
			receipts := l.Node.Receipts(p.key)
			if len(receipts) != 1 {
				t.Fatalf("%d receipts, want 1", len(receipts))
			}
			if got, want := payerUSDC-l.usdc(t, p.key), l.WithFee(receipts[0].AmountCharged); got != want {
				t.Errorf("payer paid %d, want the receipt's %d and its fee", got, want)
			}
			l.checkStub(t, p)
		})
	}
}

// A free turn opens nothing: the payer signs and pays nothing, the node's
// receipt charges zero, and nothing settles.
func TestSolanaE2E_FreeTurnOpensNothing(t *testing.T) {
	l := setup(t)
	for _, stream := range []bool{false, true} {
		name := map[bool]string{false: "buffered", true: "streamed"}[stream]
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			p := l.newPayer(t, solanastub.Behavior{})
			text, set, err, werr := p.askModel(t, solanastub.FreeModel, stream)
			if err != nil || werr != nil {
				t.Fatalf("turn: %v; settle: %v", err, werr)
			}
			if text != solanastub.Reply {
				t.Errorf("text = %q, want %q", text, solanastub.Reply)
			}
			if set.Kind != zs.SettleNone {
				t.Errorf("settlement = %+v, want none", set)
			}
			if ids := l.Node.Opened(p.key); len(ids) != 0 {
				t.Errorf("payer opened %d tickets", len(ids))
			}
			receipts := l.Node.Receipts(p.key)
			if len(receipts) != 1 || receipts[0].AmountCharged != 0 {
				t.Errorf("receipts %+v, want one at zero", receipts)
			}
			if got := l.usdc(t, p.key); got != payerUSDC {
				t.Errorf("payer holds %d, want %d", got, payerUSDC)
			}
			l.checkStub(t, p)
		})
	}
}

// withStubIssuer has the payer fetch credits from the stub's issuer, naming
// itself in the header the stub counts by, as a host's gate header would.
func (l *harness) withStubIssuer(cfg *zs.Config, pub solana.PublicKey) {
	key := base64.StdEncoding.EncodeToString(l.Node.Issuer().Key())
	cfg.FreeCredits = zs.FreeCredits{Issuers: map[string]zs.CreditIssuer{key: &zs.HTTPCreditIssuer{
		URL: l.URL,
		Header: func(_ context.Context, h http.Header) error {
			h.Set(solanastub.IssuerPayerHeader, pub.String())
			return nil
		},
	}}}
}

// A free turn at a node that trusts the issuer carries a credit the node
// verifies; the next turn spends the batch's next credit without asking the
// issuer again. With the issuer down the turn still goes, with no credit.
func TestSolanaE2E_FreeTurnCarriesACredit(t *testing.T) {
	l := setup(t)
	t.Run("from the batch", func(t *testing.T) {
		t.Parallel()
		p := l.newPayerWith(t, solanastub.Behavior{}, l.withStubIssuer)
		for turn := 1; turn <= 2; turn++ {
			text, _, err, werr := p.askModel(t, solanastub.FreeModel, turn == 2)
			if err != nil || werr != nil {
				t.Fatalf("turn %d: %v; settle: %v", turn, err, werr)
			}
			if text != solanastub.Reply {
				t.Errorf("turn %d: text = %q", turn, text)
			}
			if got := l.Node.Credits(p.key); got != turn {
				t.Errorf("after turn %d the node verified %d credits", turn, got)
			}
		}
		// The day key and one batch.
		if got := l.Node.Issuer().Calls(p.key); got != 2 {
			t.Errorf("%d issuer calls for two turns, want 2", got)
		}
		l.checkStub(t, p)
	})
	t.Run("issuer down", func(t *testing.T) {
		t.Parallel()
		p := l.newPayerWith(t, solanastub.Behavior{IssuerDown: true}, l.withStubIssuer)
		text, _, err, werr := p.askModel(t, solanastub.FreeModel, false)
		if err != nil || werr != nil {
			t.Fatalf("turn: %v; settle: %v", err, werr)
		}
		if text != solanastub.Reply {
			t.Errorf("text = %q", text)
		}
		if got := l.Node.Credits(p.key); got != 0 {
			t.Errorf("the node verified %d credits from a down issuer", got)
		}
		if got := l.Node.Issuer().Calls(p.key); got != 1 {
			t.Errorf("%d issuer calls, want the one that failed", got)
		}
		l.checkStub(t, p)
	})
	t.Run("a paid turn", func(t *testing.T) {
		t.Parallel()
		p := l.newPayerWith(t, solanastub.Behavior{}, l.withStubIssuer)
		if _, _, err, werr := p.ask(t, false); err != nil || werr != nil {
			t.Fatalf("turn: %v; settle: %v", err, werr)
		}
		if got := l.Node.Issuer().Calls(p.key); got != 0 {
			t.Errorf("%d issuer calls for a paid turn", got)
		}
		l.checkStub(t, p)
	})
}

// A ticket the node opened and never served is refunded in full by the
// payer's watchdog once its deadline passes.
func TestSolanaE2E_RefundsAnUnservedTicket(t *testing.T) {
	l := setup(t)
	t.Parallel()
	p := l.newPayer(t, solanastub.Behavior{NoReceipt: true, TicketLifetime: 10 * time.Second})
	if _, _, err, _ := p.ask(t, false); err == nil {
		t.Fatal("turn succeeded, want the node's failure")
	}
	id := l.onlyTicket(t, p)
	grace := time.Duration(l.Chain.Config.DefaultGrace) * time.Second
	// Room for the watchdog's margin past the deadline and one retry of a
	// refund the validator's clock refused as early.
	l.waitTicket(t, id, 10*time.Second+grace+2*time.Minute, "refunded", closed)
	if got := l.usdc(t, p.key); got != payerUSDC {
		t.Errorf("payer holds %d after the refund, want %d", got, payerUSDC)
	}
	l.checkStub(t, p)
}

// wallet is a SolanaWallet for signer apart from any Client, as a host's
// wallet commands build one.
func (l *harness) wallet(t *testing.T, signer payerSigner) *zs.SolanaWallet {
	t.Helper()
	w, err := zs.NewSolanaWallet(t.Context(), zs.SolanaWalletConfig{RPC: l.Chain.RPC, Deployment: l.Chain.Deployment, Signer: signer})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// What a host's wallet commands call, against the program: the fee rate and
// the USDC account create for a payer with SOL alone, then the ticket listing
// and recovery, and the rent pool's withdraw and close, around a ticket the
// watchdog refunds.
func TestSolanaE2E_HostWalletCalls(t *testing.T) {
	l := setup(t)
	t.Parallel()
	ctx := t.Context()

	fresh := payerSigner{newKey()}
	freshKey := solanastub.PublicKey(fresh.key)
	l.sweep(t, fresh.key)
	if err := l.Chain.FundSOL(ctx, l.Funding, freshKey, 10_000_000); err != nil {
		t.Fatal(err)
	}
	w := l.wallet(t, fresh)
	if fee, err := w.ProtocolFeeBps(ctx); err != nil || fee != uint64(l.Chain.Config.FeeBps) {
		t.Fatalf("ProtocolFeeBps = %d, %v; the Config's is %d", fee, err, l.Chain.Config.FeeBps)
	}
	if sig, err := w.EnsureUSDCAccount(ctx); err != nil || sig == "" {
		t.Fatalf("EnsureUSDCAccount with no account = %q, %v", sig, err)
	}
	if sig, err := w.EnsureUSDCAccount(ctx); err != nil || sig != "" {
		t.Fatalf("EnsureUSDCAccount with the account there = %q, %v", sig, err)
	}
	if acct, err := l.Chain.RPC.GetAccountInfo(ctx, l.Chain.Deployment.TokenAccount(freshKey), rpc.Confirmed); err != nil || acct.Owner != solana.TokenProgramID {
		t.Fatalf("the payer's token account: %+v, %v", acct, err)
	}

	p := l.newPayer(t, solanastub.Behavior{NoReceipt: true, TicketLifetime: 10 * time.Second})
	if _, _, err, _ := p.ask(t, false); err == nil {
		t.Fatal("turn succeeded, want the node's failure")
	}
	id := l.onlyTicket(t, p)
	listed, err := zs.FetchSolanaPayerTickets(ctx, l.Chain.RPC, l.Chain.Deployment, p.key)
	if err != nil || len(listed.Unreadable) != 0 || len(listed.Tickets) != 1 {
		t.Fatalf("FetchSolanaPayerTickets = %+v, %v", listed, err)
	}
	if pt := listed.Tickets[0]; pt.Ticket.TicketID != id || pt.OperatorID != l.OperatorID || pt.NodeID != l.NodeID {
		t.Fatalf("listed %x at %d/%d, want %x at %d/%d", pt.Ticket.TicketID, pt.OperatorID, pt.NodeID, id, l.OperatorID, l.NodeID)
	}
	// Inside its settle window the program allows no ending, so nothing goes.
	pw := l.wallet(t, p.signer)
	if verdict, sig, err := pw.RecoverTicket(ctx, l.OperatorID, l.NodeID, id); err != nil || verdict != settle.VerdictWait || sig != "" {
		t.Fatalf("RecoverTicket in the window = %s, %q, %v", verdict, sig, err)
	}
	grace := time.Duration(l.Chain.Config.DefaultGrace) * time.Second
	l.waitTicket(t, id, 10*time.Second+grace+2*time.Minute, "refunded", closed)
	if _, _, err := pw.RecoverTicket(ctx, l.OperatorID, l.NodeID, id); !errors.Is(err, zs.ErrSolanaTicketGone) {
		t.Fatalf("RecoverTicket after the refund: %v", err)
	}
	if listed, err := zs.FetchSolanaPayerTickets(ctx, l.Chain.RPC, l.Chain.Deployment, p.key); err != nil || len(listed.Tickets) != 0 {
		t.Fatalf("after the refund: %+v, %v", listed, err)
	}

	pool := &zs.SolanaRentPool{RPC: l.Chain.RPC, Deployment: l.Chain.Deployment, Signer: p.signer}
	st, err := pool.Status(ctx)
	if err != nil || !st.Exists || st.OpenTickets != 0 || st.FreeSlots() == 0 {
		t.Fatalf("pool after the refund: %+v, %v", st, err)
	}
	if _, err := pool.Withdraw(ctx, st.TicketRent); err != nil {
		t.Fatal(err)
	}
	after, err := pool.Status(ctx)
	if err != nil || after.Available() != st.Available()-st.TicketRent {
		t.Fatalf("after the withdraw: available %d, want %d (%v)", after.Available(), st.Available()-st.TicketRent, err)
	}
	if _, returned, err := pool.Close(ctx); err != nil || returned != after.Lamports {
		t.Fatalf("Close = %d, %v; the pool held %d", returned, err, after.Lamports)
	}
	if st, err := pool.Status(ctx); err != nil || st.Exists {
		t.Fatalf("after the close: %+v, %v", st, err)
	}
	l.checkStub(t, p)
}

// A receipt that doesn't hash the reply is protested at once, which freezes
// the ticket.
func TestSolanaE2E_ProtestsABadReceipt(t *testing.T) {
	l := setup(t)
	t.Parallel()
	p := l.newPayer(t, solanastub.Behavior{BadBodyHash: true})
	_, set, _, werr := p.ask(t, false)
	if werr != nil {
		t.Fatalf("settle: %v", werr)
	}
	if set.Kind != zs.SettleProtest || !set.Frozen {
		t.Errorf("settlement = %+v, want a protest that freezes", set)
	}
	tk := l.waitTicket(t, l.onlyTicket(t, p), l.confirm, "frozen by the protest", func(tk *zsescrow.Ticket) bool {
		return tk != nil && tk.Status == zsescrow.TicketFrozen
	})
	if tk.FreezeOrigin != zsescrow.FreezeOriginProtest {
		t.Errorf("freeze origin = %d, want the protest's", tk.FreezeOrigin)
	}
	l.checkStub(t, p)
}

// A node claim above the receipt, with the node refusing the ack, gets the
// payer's own half at the receipt's figures, which freezes the ticket.
func TestSolanaE2E_FreezesAnOverClaim(t *testing.T) {
	l := setup(t)
	t.Parallel()
	// Small enough that the claim and its fee stay under max_price.
	p := l.newPayer(t, solanastub.Behavior{OverClaim: 10})
	_, set, err, werr := p.ask(t, false)
	if err != nil || werr != nil {
		t.Fatalf("turn: %v; settle: %v", err, werr)
	}
	if !set.Frozen {
		t.Errorf("settlement = %+v, want the payer's freezing half", set)
	}
	id := l.onlyTicket(t, p)
	tk := l.waitTicket(t, id, l.confirm, "frozen by the mismatch", func(tk *zsescrow.Ticket) bool {
		return tk != nil && tk.Status == zsescrow.TicketFrozen
	})
	if tk.FreezeOrigin != zsescrow.FreezeOriginSettleMismatch {
		t.Errorf("freeze origin = %d, want the settle mismatch's", tk.FreezeOrigin)
	}
	// The over-claim bars the node, so the next turn finds nowhere to go.
	if _, _, err, _ := p.ask(t, false); err == nil {
		t.Error("a second turn succeeded, want the over-claiming node barred")
	}
	if n := len(l.Node.Opened(p.key)); n != 1 {
		t.Errorf("payer opened %d tickets at the barred node, want 1", n)
	}
	l.checkStub(t, p)

	// Only the admin releases a frozen ticket. A run funded without it,
	// devnet's, stops at the freeze; that is the scenario's end there, not a
	// skip.
	if l.Funding.Admin() == nil {
		t.Log("resolving the freeze needs the Config's admin, which this run doesn't hold")
		return
	}
	// Half the pre-fee ceiling to the node, its fee on top, the rest back to
	// the payer, as the program's resolve_split divides it.
	const share = 5_000
	if err := l.Resolve(t.Context(), id, p.key, share); err != nil {
		t.Fatal(err)
	}
	l.waitTicket(t, id, l.confirm, "resolved", closed)
	maxPrice, feeBps := l.maxPrice(t, p, id), uint64(l.Chain.Config.FeeBps)
	award := maxPrice * 10_000 / (10_000 + feeBps) * share / 10_000
	if got, want := payerUSDC-l.usdc(t, p.key), l.WithFee(award); got != want {
		t.Errorf("payer paid %d after the resolve, want the award %d and its fee", got, want)
	}
}

// A node that sends the payer's open only after its blockhash expired can
// never land it: the turn fails, no ticket account exists, and the payer is
// charged nothing.
func TestSolanaE2E_ExpiredBlockhashChargesNothing(t *testing.T) {
	l := setup(t)
	t.Parallel()
	p := l.newPayer(t, solanastub.Behavior{HoldOpen: true})
	// The node holds the turn for a blockhash's whole life, 150 blocks, a
	// minute or more on a busy cluster, before it answers.
	_, _, err, _ := p.askWithin(t, solanastub.Model, false, 5*time.Minute)
	wantCode(t, err, "payment_verification_failed")
	if ids := l.Node.Opened(p.key); len(ids) != 0 {
		t.Errorf("payer opened %d tickets", len(ids))
	}
	issued := l.priced(p)
	if len(issued) == 0 {
		t.Fatal("the stub issued no priced ticket, so no open was held")
	}
	for _, is := range issued {
		if tk, err := l.Chain.Ticket(t.Context(), l.OperatorID, l.NodeID, is.ID); err != nil || tk != nil {
			t.Errorf("ticket %x: %+v, %v; want no account", is.ID, tk, err)
		}
	}
	if got := l.usdc(t, p.key); got != payerUSDC {
		t.Errorf("payer holds %d, want %d", got, payerUSDC)
	}
	l.checkStub(t, p)
}

// Two turns at once whose max prices together exceed the payer's balance:
// one open lands and is served, the cluster refuses the other's transfer, and
// the payer pays once.
func TestSolanaE2E_ConcurrentTurnsSpendOnce(t *testing.T) {
	l := setup(t)
	t.Parallel()
	// A turn's max price and charge, from a payer with plenty; the second
	// payer's turns are the same request, so the same figures.
	warm := l.newPayer(t, solanastub.Behavior{})
	if _, _, err, werr := warm.ask(t, false); err != nil || werr != nil {
		t.Fatalf("warm-up turn: %v; settle: %v", err, werr)
	}
	maxPrice := l.maxPrice(t, warm, l.onlyTicket(t, warm))
	receipts := l.Node.Receipts(warm.key)
	if len(receipts) != 1 {
		t.Fatalf("%d warm-up receipts, want 1", len(receipts))
	}
	// One max price held, and short of a second even after the first
	// settles and refunds.
	funded := maxPrice + l.WithFee(receipts[0].AmountCharged) - 1
	p := l.newPayerFunded(t, solanastub.Behavior{}, funded, nil)

	type result struct {
		text     string
		err, set error
	}
	results := make([]result, 2)
	var wg sync.WaitGroup
	for i := range results {
		wg.Go(func() {
			text, _, err, werr := p.ask(t, false)
			results[i] = result{text, err, werr}
		})
	}
	wg.Wait()
	served := 0
	for _, r := range results {
		if r.err == nil && r.set == nil && r.text == solanastub.Reply {
			served++
		} else {
			wantCode(t, r.err, "payment_verification_failed")
		}
	}
	if served != 1 {
		t.Fatalf("%d turns served, want 1: %+v", served, results)
	}
	id := l.onlyTicket(t, p)
	l.waitTicket(t, id, l.confirm, "settled", closed)
	receipts = l.Node.Receipts(p.key)
	if len(receipts) != 1 {
		t.Fatalf("%d receipts, want 1", len(receipts))
	}
	if got, want := funded-l.usdc(t, p.key), l.WithFee(receipts[0].AmountCharged); got != want {
		t.Errorf("payer paid %d, want one receipt's %d and its fee", got, want)
	}
	for _, is := range l.priced(p) {
		if tk, err := l.Chain.Ticket(t.Context(), l.OperatorID, l.NodeID, is.ID); err != nil || tk != nil {
			t.Errorf("ticket %x left open: %+v, %v", is.ID, tk, err)
		}
	}
	l.checkStub(t, p)
}

// A refund the payer can't take, its USDC account closed, goes to the
// treasury: the ticket still closes, and the payer's account stays closed.
func TestSolanaE2E_ClosedAccountForfeitsTheRefund(t *testing.T) {
	l := setup(t)
	t.Parallel()
	ctx := t.Context()
	p := l.newPayer(t, solanastub.Behavior{NoReceipt: true, TicketLifetime: 10 * time.Second})
	if _, _, err, _ := p.ask(t, false); err == nil {
		t.Fatal("turn succeeded, want the node's failure")
	}
	id := l.onlyTicket(t, p)
	maxPrice := l.maxPrice(t, p, id)
	treasury := l.Chain.Config.Treasury
	before := l.usdc(t, treasury)

	// The payer empties its USDC account and closes it, keeping its SOL for
	// the refund's fee.
	d, source := l.Chain.Deployment, l.Funding.Source()
	left := l.usdc(t, p.key)
	if _, err := l.Chain.Send(ctx, []solana.Instruction{
		solana.CreateAssociatedTokenAccountIdempotent(p.key, source, d.Mint),
		solana.TransferChecked(d.TokenAccount(p.key), d.Mint, d.TokenAccount(source), p.key, left, l.Chain.Config.USDCDecimals),
		solanastub.CloseTokenAccount(d.TokenAccount(p.key), p.key, p.key),
	}, p.signer.key); err != nil {
		t.Fatal(err)
	}

	grace := time.Duration(l.Chain.Config.DefaultGrace) * time.Second
	l.waitTicket(t, id, 10*time.Second+grace+2*time.Minute, "refunded", closed)
	// At least the forfeit: on a shared cluster another run's forfeits land
	// on the treasury too. A fee withdrawal there could also lower it, which
	// fails this rather than wrap.
	if after := l.usdc(t, treasury); after < before+maxPrice {
		t.Errorf("the treasury went from %d to %d, want at least the forfeited %d more", before, after, maxPrice)
	}
	if _, err := l.Chain.RPC.GetAccountInfo(ctx, d.TokenAccount(p.key), rpc.Confirmed); !errors.Is(err, rpc.ErrNotFound) {
		t.Errorf("the payer's USDC account after the refund: %v, want none", err)
	}
	l.checkStub(t, p)
}

// A claim the payer holds no receipt against is left to lapse: the payer
// neither refunds nor freezes it, and it lapses to the node at the deadline.
func TestSolanaE2E_LeavesAnUncontestedClaimToLapse(t *testing.T) {
	l := setup(t)
	t.Parallel()
	p := l.newPayer(t, solanastub.Behavior{ClaimNoReceipt: true, TicketLifetime: 10 * time.Second})
	if _, _, err, _ := p.ask(t, false); err == nil {
		t.Fatal("turn succeeded, want the node's failure")
	}
	id := l.onlyTicket(t, p)
	tk := l.waitTicket(t, id, l.confirm, "claimed", func(tk *zsescrow.Ticket) bool {
		return tk != nil && tk.Status == zsescrow.TicketPendingByOperator
	})
	// Past the watchdog's first look (the deadline plus its 15 s margin) and
	// a confirm: a payer that refunded or froze the claim would have by now.
	// Its own lapse waits ten minutes, so the claim is still the node's.
	time.Sleep(time.Until(time.Unix(tk.Deadline(), 0).Add(30 * time.Second)))
	tk = l.waitTicket(t, id, 0, "still claimed past the payer's first look", func(tk *zsescrow.Ticket) bool {
		return tk != nil && tk.Status == zsescrow.TicketPendingByOperator
	})
	// The validator's clock can trail the wall clock under load, which the
	// program reads as before the deadline.
	for start := time.Now(); ; time.Sleep(2 * time.Second) {
		err := l.Node.SettleLapsed(context.Background(), id, p.key)
		if err == nil {
			break
		}
		if time.Since(start) > 30*time.Second {
			t.Fatal(err)
		}
	}
	l.waitTicket(t, id, l.confirm, "lapsed", closed)
	if got, want := payerUSDC-l.usdc(t, p.key), l.WithFee(tk.Pending.Amount); got != want {
		t.Errorf("payer paid %d, want the claim's %d and its fee", got, want)
	}
	l.checkStub(t, p)
}
