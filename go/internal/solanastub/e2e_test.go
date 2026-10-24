/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package solanastub_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/internal/solanastub"
	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/zs"
)

// The scenarios run against a local validator holding zs_escrow, as
// contracts-solana's `make localnet` starts one. ZS_SOLANA_E2E_RPC names its
// endpoint and ZS_SOLANA_E2E_MINT_AUTHORITY the keypair file of its test USDC
// mint's authority, which is also the Config's admin; without both they skip.
const (
	envRPC       = "ZS_SOLANA_E2E_RPC"
	envAuthority = "ZS_SOLANA_E2E_MINT_AUTHORITY"
)

// localnet is the chain and the one stub node every scenario shares.
type localnet struct {
	chain     *solanastub.Chain
	authority ed25519.PrivateKey
	node      *solanastub.Node
	operator  uint64
	nodeID    uint64
}

var (
	setupOnce sync.Once
	shared    *localnet
	setupErr  error
)

func setup(t *testing.T) *localnet {
	t.Helper()
	endpoint, keyFile := os.Getenv(envRPC), os.Getenv(envAuthority)
	if endpoint == "" || keyFile == "" {
		t.Skipf("set %s and %s to run against a local validator", envRPC, envAuthority)
	}
	setupOnce.Do(func() { shared, setupErr = newLocalnet(endpoint, keyFile) })
	if setupErr != nil {
		t.Fatal(setupErr)
	}
	return shared
}

func newLocalnet(endpoint, keyFile string) (*localnet, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	authority, err := solanastub.ReadKeypair(keyFile)
	if err != nil {
		return nil, err
	}
	chain, err := solanastub.Dial(ctx, endpoint, zsescrow.ProgramID)
	if err != nil {
		return nil, err
	}
	// The shortest grace the program allows, so the endings that wait out a
	// deadline wait about a minute.
	if chain.Config.DefaultGrace != chain.Config.MinGrace {
		grace := chain.Config.MinGrace
		ix, err := chain.Deployment.SetConfig(solanastub.PublicKey(authority), zsescrow.SetConfigArgs{DefaultGrace: &grace})
		if err != nil {
			return nil, err
		}
		if _, err := chain.Send(ctx, []solana.Instruction{ix}, authority); err != nil {
			return nil, err
		}
		if err := chain.Refresh(ctx); err != nil {
			return nil, err
		}
	}

	owner, signing := newKey(), newKey()
	if err := chain.Airdrop(ctx, solanastub.PublicKey(owner), 2_000_000_000); err != nil {
		return nil, err
	}
	if err := chain.Airdrop(ctx, solanastub.PublicKey(signing), 2_000_000_000); err != nil {
		return nil, err
	}
	if err := chain.MintUSDC(ctx, authority, solanastub.PublicKey(owner), chain.Config.OperatorStake+chain.Config.NodeStake); err != nil {
		return nil, err
	}
	srv := httptest.NewUnstartedServer(nil)
	opID, nodeID, err := chain.RegisterNode(ctx, owner, solanastub.PublicKey(signing), "http://"+srv.Listener.Addr().String())
	if err != nil {
		return nil, err
	}
	node, err := solanastub.NewNode(chain, signing, opID, nodeID)
	if err != nil {
		return nil, err
	}
	srv.Config.Handler = node.Handler()
	srv.Start()
	return &localnet{chain: chain, authority: authority, node: node, operator: opID, nodeID: nodeID}, nil
}

func newKey() ed25519.PrivateKey {
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
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
	client *zs.Client
}

const payerUSDC = 10_000_000

func (l *localnet) newPayer(t *testing.T, b solanastub.Behavior) *payer {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	key := newKey()
	pub := solanastub.PublicKey(key)
	if err := l.chain.Airdrop(ctx, pub, 1_000_000_000); err != nil {
		t.Fatal(err)
	}
	if err := l.chain.MintUSDC(ctx, l.authority, pub, payerUSDC); err != nil {
		t.Fatal(err)
	}
	l.node.SetBehavior(pub, b)
	client, err := zs.New(ctx, zs.Config{
		SolanaSigner: payerSigner{key},
		Network: zs.Network{Rail: ticket.RailSolana, Solana: zs.SolanaNetwork{
			Cluster: zs.SolanaClusterLocalnet, RPCEndpoint: l.chain.Endpoint, Program: l.chain.Deployment.Program,
		}},
		// One node can't be its own relay.
		Privacy:           zs.PrivacyDirect,
		AllowPrivateHosts: true,
		DisableTEE:        true,
		Discovery:         zs.Discovery{OperatorIDs: []uint64{l.operator}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return &payer{key: pub, client: client}
}

func chatBody(stream bool) []byte {
	b, _ := json.Marshal(map[string]any{
		"model":      solanastub.Model,
		"messages":   []any{map[string]string{"role": "user", "content": "say hello"}},
		"max_tokens": 64,
		"stream":     stream,
	})
	return b
}

// ask runs one chat turn and waits for its settle submit.
func (p *payer) ask(t *testing.T, stream bool) (string, zs.Settlement, error, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	s := p.client.Stream(ctx, zs.Request{Endpoint: zs.EndpointChatCompletions, Body: chatBody(stream)})
	text, err := s.Text()
	set, werr := s.Wait(ctx)
	return text, set, err, werr
}

// onlyTicket is the one ticket p opened at the stub.
func (l *localnet) onlyTicket(t *testing.T, p *payer) [16]byte {
	t.Helper()
	ids := l.node.Opened(p.key)
	if len(ids) != 1 {
		t.Fatalf("payer opened %d tickets at the stub, want 1", len(ids))
	}
	return ids[0]
}

// waitTicket polls the ticket until done says it has reached the state a
// scenario waits for, or within fails the test.
func (l *localnet) waitTicket(t *testing.T, id [16]byte, within time.Duration, what string, done func(*zsescrow.Ticket) bool) *zsescrow.Ticket {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(within)
	for {
		tk, err := l.chain.Ticket(ctx, l.operator, l.nodeID, id)
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

func (l *localnet) usdc(t *testing.T, owner solana.PublicKey) uint64 {
	t.Helper()
	v, err := l.chain.USDC(context.Background(), owner)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// withFee is what a payer pays for a charge: the program adds the protocol
// fee on top, rounded down.
func (l *localnet) withFee(amount uint64) uint64 {
	return amount + amount*uint64(l.chain.Config.FeeBps)/10_000
}

func (l *localnet) checkStub(t *testing.T, p *payer) {
	t.Helper()
	for _, err := range l.node.Errors(p.key) {
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
			text, set, err, werr := p.ask(t, stream)
			if err != nil || werr != nil {
				t.Fatalf("turn: %v; settle: %v", err, werr)
			}
			if text != solanastub.Reply {
				t.Errorf("text = %q, want %q", text, solanastub.Reply)
			}
			if set.Kind != zs.SettleAtomic || set.Frozen {
				t.Errorf("settlement = %+v, want the node's settle on the payer's ack", set)
			}
			id := l.onlyTicket(t, p)
			l.waitTicket(t, id, 30*time.Second, "settled", closed)
			receipts := l.node.Receipts(p.key)
			if len(receipts) != 1 {
				t.Fatalf("%d receipts, want 1", len(receipts))
			}
			if got, want := payerUSDC-l.usdc(t, p.key), l.withFee(receipts[0].AmountCharged); got != want {
				t.Errorf("payer paid %d, want the receipt's %d and its fee", got, want)
			}
			l.checkStub(t, p)
		})
	}
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
	grace := time.Duration(l.chain.Config.DefaultGrace) * time.Second
	// Room for the watchdog's margin past the deadline and one retry of a
	// refund the validator's clock refused as early.
	l.waitTicket(t, id, 10*time.Second+grace+2*time.Minute, "refunded", closed)
	if got := l.usdc(t, p.key); got != payerUSDC {
		t.Errorf("payer holds %d after the refund, want %d", got, payerUSDC)
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
	tk := l.waitTicket(t, l.onlyTicket(t, p), 30*time.Second, "frozen by the protest", func(tk *zsescrow.Ticket) bool {
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
	tk := l.waitTicket(t, l.onlyTicket(t, p), 30*time.Second, "frozen by the mismatch", func(tk *zsescrow.Ticket) bool {
		return tk != nil && tk.Status == zsescrow.TicketFrozen
	})
	if tk.FreezeOrigin != zsescrow.FreezeOriginSettleMismatch {
		t.Errorf("freeze origin = %d, want the settle mismatch's", tk.FreezeOrigin)
	}
	// The over-claim bars the node, so the next turn finds nowhere to go.
	if _, _, err, _ := p.ask(t, false); err == nil {
		t.Error("a second turn succeeded, want the over-claiming node barred")
	}
	if n := len(l.node.Opened(p.key)); n != 1 {
		t.Errorf("payer opened %d tickets at the barred node, want 1", n)
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
	tk := l.waitTicket(t, id, 30*time.Second, "claimed", func(tk *zsescrow.Ticket) bool {
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
		err := l.node.SettleLapsed(context.Background(), id, p.key)
		if err == nil {
			break
		}
		if time.Since(start) > 30*time.Second {
			t.Fatal(err)
		}
	}
	l.waitTicket(t, id, 30*time.Second, "lapsed", closed)
	if got, want := payerUSDC-l.usdc(t, p.key), l.withFee(tk.Pending.Amount); got != want {
		t.Errorf("payer paid %d, want the claim's %d and its fee", got, want)
	}
	l.checkStub(t, p)
}
