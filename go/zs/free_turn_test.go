/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/wire"
)

// noOpenWallet refuses every open, counting the asks: a free Solana turn must
// make none.
type noOpenWallet struct{ opens atomic.Int32 }

func (w *noOpenWallet) Open(context.Context, *ticket.Ticket, Operator, string) (*OpenHandle, error) {
	w.opens.Add(1)
	return nil, errors.New("a free turn asked the wallet to open")
}

func (w *noOpenWallet) OpenForNode(context.Context, *ticket.Ticket, Operator, string) (*OpenHandle, error) {
	w.opens.Add(1)
	return nil, errors.New("a free turn asked the wallet to open")
}

func (*noOpenWallet) PayerAddr() string { return "PAYER" }

// freeNode is a node serving one free ticket: it opens the sealed request,
// records the payment fields and whether the admission tag binds an empty
// tx id, and answers with a sealed reply and a receipt charging charge.
type freeNode struct {
	mu                    sync.Mutex
	paymentRef, openGroup string
	tagBindsNoTx          bool
	requests              int
}

func newFreeTurn(t *testing.T, charge uint64) (*Client, Operator, *ReservedTicket, *freeNode) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var addr types.Address
	copy(addr[:], pub)
	nodeID, payerID := mustX25519(t), mustX25519(t)
	var k [wire.ResponseKeySize]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	commit := ticket.CommitResponseKey(k)
	tkt := &ticket.Ticket{TicketID: "ZnJlZS10dXJuLXRpY2tldA==", OperatorID: 7, NodeID: 3, InputCount: 8, MaxOutputCount: 64,
		CommitK: base64.StdEncoding.EncodeToString(commit[:])}
	rt := &ReservedTicket{Ticket: tkt, ResponseKey: k, AgeIdentity: payerID, SealRecipient: nodeID.Recipient()}

	n := &freeNode{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		dec, err := wire.DecryptRequest(raw, nodeID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		n.mu.Lock()
		n.requests++
		n.paymentRef, n.openGroup = dec.AlgorandTxID, dec.OpenGroup
		n.tagBindsNoTx = hmac.Equal(dec.AdmissionTag, wire.ComputeAdmissionTag(k, dec.TicketID, "", dec.Body))
		n.mu.Unlock()
		body := []byte(`{"id":"c","object":"chat.completion","model":"gpt-test","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"hi"}}],"usage":{"prompt_tokens":8,"completion_tokens":5}}`)
		sealer, err := wire.NewResponseSealerWithKey(dec.ReplyToRecipient, "", dec.TicketID, k)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		sum := wire.BodyHashOfBody(body)
		rcpt := &ticket.UsageReceipt{TicketID: dec.TicketID, ActualInputCount: 8, ActualOutputCount: 5, AmountCharged: charge, BodyHash: hex.EncodeToString(sum[:])}
		if err := rcpt.Sign(r.Context(), rawKeyBytesSigner{addr: addr.String(), priv: priv}, addr.String()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		rh, err := rcpt.EncodeReceiptHeader()
		if err == nil {
			rh, err = sealer.SealHeader(wire.SealedHeaderReceipt, []byte(rh))
		}
		sealed, err2 := sealer.SealBody(body)
		if err != nil || err2 != nil {
			http.Error(w, "seal", http.StatusInternalServerError)
			return
		}
		w.Header().Set(wire.ResponseKeyHeader, sealer.WrappedKeyHeader())
		w.Header().Set(wire.ReceiptHeader, rh)
		w.Header().Set("Content-Type", wire.EncryptedContentType)
		_, _ = w.Write(sealed)
	}))
	t.Cleanup(srv.Close)
	op := Operator{ID: 7, NodeID: 3, SigningAddr: addr.String(), TicketSigningKey: pub, BaseURL: srv.URL, ProtoVersion: wire.ProtoVersion, Reachable: true}

	c := settleClient()
	c.httpClient = http.DefaultClient
	c.deployment = Deployment{Rail: ticket.RailSolana}
	return c, op, rt, n
}

// A free Solana turn opens nothing: the wallet is never asked, the envelope
// names no open and its tag binds an empty tx id, hosts still hear the turn
// committed, and the zero receipt leaves nothing to submit, journal or watch.
// The spend reservation, which holds no exposure, is released at once.
func TestRunSealed_FreeSolanaTurnOpensNothing(t *testing.T) {
	c, op, rt, node := newFreeTurn(t, 0)
	wallet, guard := &noOpenWallet{}, &outcomeGuard{}
	c.wallet, c.spend = wallet, guard
	slot := newSettleSlot()
	em := &recEmitter{}
	c.runSealed(withSettleSlot(context.Background(), slot), em, endpointChatCompletions, "gpt-test",
		[]byte(`{"model":"gpt-test","messages":[{"role":"user","content":"hi"}]}`), op, rt, false, nil)

	if em.failed != nil {
		t.Fatalf("turn failed: %v", em.failed)
	}
	if em.replied == nil || em.replied.Status != http.StatusOK {
		t.Fatalf("reply = %+v, want the node's 200", em.replied)
	}
	if n := wallet.opens.Load(); n != 0 {
		t.Errorf("the wallet was asked to open %d times", n)
	}
	node.mu.Lock()
	ref, group, tagOK, reqs := node.paymentRef, node.openGroup, node.tagBindsNoTx, node.requests
	node.mu.Unlock()
	if reqs != 1 || ref != "" || group != "" || !tagOK {
		t.Errorf("node saw %d requests, payment_ref %q, payment_open %q, tag over no tx %v; want one, none, none, true", reqs, ref, group, tagOK)
	}
	if want := []string{rt.Ticket.TicketID + ` "" 0`}; !slices.Equal(em.commits, want) {
		t.Errorf("committed %v, want %v", em.commits, want)
	}
	if got := guard.seen(); len(got) == 0 || got[0] != "release "+rt.Ticket.TicketID {
		t.Errorf("spend guard heard %v, want the reservation released first", got)
	}
	if c.refunds.watching(rt.Ticket.TicketID) {
		t.Error("the refund watchdog is watching a ticket that opened nothing")
	}
	if slot.expected {
		t.Error("the settle slot expects a settlement for a free turn")
	}
}

// A free ticket's receipt that charges anything fails its check, as any
// receipt over max_price does, and the reply reports it; with nothing opened
// there is no protest to send.
func TestRunSealed_FreeSolanaTurnFlagsACharge(t *testing.T) {
	c, op, rt, _ := newFreeTurn(t, 1)
	c.wallet, c.spend = &noOpenWallet{}, &outcomeGuard{}
	slot := newSettleSlot()
	em := &recEmitter{}
	c.runSealed(withSettleSlot(context.Background(), slot), em, endpointChatCompletions, "gpt-test",
		[]byte(`{"model":"gpt-test","messages":[{"role":"user","content":"hi"}]}`), op, rt, false, nil)

	if em.failed != nil {
		t.Fatalf("turn failed: %v", em.failed)
	}
	if len(em.usages) != 1 || em.usages[0].check.violation != "amount" {
		t.Fatalf("usage %+v, want one report of the amount violation", em.usages)
	}
	if slot.expected {
		t.Error("the settle slot expects a protest for a ticket that opened nothing")
	}
}

// noOpenRecheckWallet is a noOpenWallet that counts deposit rechecks.
type noOpenRecheckWallet struct {
	noOpenWallet
	rechecks atomic.Int32
}

func (w *noOpenRecheckWallet) RecheckDeposit() { w.rechecks.Add(1) }

// A free turn's payment refusal is about no open, so it rechecks no deposit.
func TestRunSealed_FreeSolanaTurnRefusalRechecksNoDeposit(t *testing.T) {
	c, op, rt, _ := newFreeTurn(t, 0)
	refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusPaymentRequired)
		_, _ = w.Write([]byte(`{"error":{"code":"payment_verification_failed","message":"payment verification failed"}}`))
	}))
	t.Cleanup(refusing.Close)
	op.BaseURL = refusing.URL
	wallet := &noOpenRecheckWallet{}
	c.wallet, c.spend = wallet, &outcomeGuard{}
	em := &recEmitter{}
	c.runSealed(context.Background(), em, endpointChatCompletions, "gpt-test",
		[]byte(`{"model":"gpt-test","messages":[{"role":"user","content":"hi"}]}`), op, rt, false, nil)

	if e, ok := errors.AsType[*Error](em.failed); !ok || e.Code != "payment_verification_failed" {
		t.Fatalf("failed %v; want the node's payment refusal", em.failed)
	}
	if n := wallet.rechecks.Load(); n != 0 {
		t.Errorf("%d deposit rechecks for a turn that opened nothing", n)
	}
}

// byOpReserveClient answers each operator's reserves from its own script,
// replaying the script's last entry once it runs out.
type byOpReserveClient struct {
	mu      sync.Mutex
	scripts map[uint64][]error
	calls   map[uint64]int
}

func (c *byOpReserveClient) Reserve(_ context.Context, op Operator, _ ticket.ReserveRequest, _ *RelayHop) (*ReservedTicket, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, n := c.scripts[op.ID], c.calls[op.ID]
	c.calls[op.ID]++
	return nil, s[min(n, len(s)-1)]
}

func (c *byOpReserveClient) callsTo(id uint64) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls[id]
}

// When every node's free tier is spent the turn ends with that, not with
// operators_busy, whose advice is to retry in seconds. A node merely at
// capacity still makes it operators_busy, since a slot may free, and a node
// that was only unreachable is swept again, since it may have budget.
func TestDispatch_EveryFreeBudgetSpent(t *testing.T) {
	spent := &BusyError{Code: "free_budget_exhausted", RetryAfter: time.Hour}
	for _, tc := range []struct {
		name     string
		second   []error // node 2's answers; node 1's free tier is spent
		wantCode string
		// wantSecond is how often node 2 is asked; 0 skips the check.
		wantSecond int
	}{
		{"every node spent", []error{spent}, "free_budget_exhausted", 1},
		{"one spent, one busy", []error{&BusyError{Code: "no_capacity"}}, "operators_busy", 0},
		{"one spent, one unreachable, then spent", []error{gatewayErr(http.StatusBadGateway), spent}, "free_budget_exhausted", 0},
		{"one spent, one unreachable throughout", []error{gatewayErr(http.StatusBadGateway)}, "operators_busy", 0},
		// Only the last sweep decides: an earlier sweep left node 2
		// unreachable, and the re-sweep found it spent.
		{"one spent, one unreachable for a sweep, then spent", []error{gatewayErr(http.StatusBadGateway), gatewayErr(http.StatusBadGateway), gatewayErr(http.StatusBadGateway), spent}, "free_budget_exhausted", 0},
		// A later candidate's other refusal doesn't clear the spent one.
		{"one spent, one refusing otherwise", []error{&ReserveHTTPError{Status: http.StatusBadRequest, Code: "invalid_reserve"}}, "free_budget_exhausted", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := admitClient(t, []Operator{pricedOp(1, 1, 2), pricedOp(2, 1, 2)}, nil)
			rc := &byOpReserveClient{scripts: map[uint64][]error{1: {spent}, 2: tc.second}, calls: map[uint64]int{}}
			c.reserveClient = rc
			c.sweepDelayFn = func(int) time.Duration { return time.Millisecond }
			c.retryBudget = 2 * time.Second
			_, err := runRequest(t, c, Request{Endpoint: EndpointChatCompletions, Body: admitBody})
			var e *Error
			if !errors.As(err, &e) || e.Code != tc.wantCode {
				t.Fatalf("err = %v, want %s", err, tc.wantCode)
			}
			if tc.wantSecond > 0 && rc.callsTo(2) != tc.wantSecond {
				t.Errorf("node 2 asked %d times, want %d: a spent pool earns no re-sweep", rc.callsTo(2), tc.wantSecond)
			}
			if tc.wantCode != "free_budget_exhausted" {
				return
			}
			if e.Kind != KindFunds || e.Retryable {
				t.Errorf("kind %s, retryable %v; want funds, not retryable", e.Kind, e.Retryable)
			}
			if want := untilUTCMidnight(time.Now()); e.RetryAfter <= 0 || e.RetryAfter > want+time.Minute || e.RetryAfter < want-time.Minute {
				t.Errorf("retry after %s, want about %s, the next 00:00 UTC", e.RetryAfter, want)
			}
		})
	}
}

// A free turn's commit names no open and leaves the turn unpaid, so a later
// failure carries no Ticket and a host may resend it; a paid one is paid.
func TestStreamEmitter_FreeCommitIsUnpaid(t *testing.T) {
	for _, tc := range []struct {
		open string
		paid bool
	}{{"", false}, {"OPENTX", true}} {
		e := &streamEmitter{yield: func(Event, error) bool { return true }}
		e.reserved(&ReservedTicket{Ticket: &ticket.Ticket{TicketID: "T"}}, Operator{})
		e.committed("T", tc.open, 0)
		e.fail(newError("upstream_unreachable", "gone"))
		if e.err.Paid != tc.paid || (e.err.Ticket != nil) != tc.paid {
			t.Errorf("open %q: paid %v, ticket %v; want paid %v", tc.open, e.err.Paid, e.err.Ticket, tc.paid)
		}
	}
}

func TestUntilUTCMidnight(t *testing.T) {
	// 23:59:30 at UTC-5 is 04:59:30 UTC the next day: the local day is not
	// the one that resets.
	if got := untilUTCMidnight(time.Date(2026, 10, 26, 23, 59, 30, 0, time.FixedZone("EST", -5*3600))); got != 19*time.Hour+30*time.Second {
		t.Errorf("23:59:30 at UTC-5: %s, want 19h0m30s", got)
	}
	if got := untilUTCMidnight(time.Date(2026, 10, 26, 23, 59, 30, 0, time.UTC)); got != 30*time.Second {
		t.Errorf("30s before midnight UTC: %s", got)
	}
	if got := untilUTCMidnight(time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)); got != 24*time.Hour {
		t.Errorf("at midnight UTC: %s, want a full day", got)
	}
}
