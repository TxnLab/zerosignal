/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"filippo.io/age"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/wire"
)

// settleAckNode is a node's settle-ack endpoint: it opens what arrives with
// its identity and answers status.
func settleAckNode(t *testing.T, id *age.X25519Identity, status int) (*httptest.Server, *[]wire.SettleAck) {
	t.Helper()
	var got []wire.SettleAck
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != wire.SettleAckPath || r.Header.Get("Content-Type") != wire.SealedSettleAckContentType {
			http.Error(w, "wrong route", http.StatusNotFound)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		ack, err := wire.OpenSettleAck(raw, id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		got = append(got, ack)
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

func newAckClient(t *testing.T, ops []Operator) *Client {
	t.Helper()
	registry, err := NewStaticRegistryProvider(ops)
	if err != nil {
		t.Fatal(err)
	}
	return &Client{httpClient: http.DefaultClient, registryProvider: registry}
}

func TestSettleAckPoster(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	ack := wire.SettleAck{TicketID: "TKT", SettleGroup: "GROUP"}

	t.Run("an older node gets no poster, so the payer broadcasts", func(t *testing.T) {
		s := newAckClient(t, nil)
		if s.settleAckPoster(Operator{ProtoVersion: "9.11"}, id.Recipient(), false) != nil {
			t.Error("poster built for a node that does not serve settle-ack")
		}
	})

	t.Run("a direct request posts the sealed ack to the node", func(t *testing.T) {
		node, got := settleAckNode(t, id, http.StatusAccepted)
		s := newAckClient(t, nil)
		post := s.settleAckPoster(Operator{ProtoVersion: wire.SettleAckMinVersion, BaseURL: node.URL}, id.Recipient(), false)
		if err := post(context.Background(), ack); err != nil {
			t.Fatal(err)
		}
		if len(*got) != 1 || (*got)[0] != ack {
			t.Errorf("node received %+v, want one %+v", *got, ack)
		}
	})

	t.Run("the group goes under the name the node reads", func(t *testing.T) {
		for _, tc := range []struct {
			version string
			neutral bool
		}{
			{wire.SettleAckMinVersion, false},
			{wire.RailNeutralNamesMinVersion, true},
		} {
			node, got := settleAckNode(t, id, http.StatusAccepted)
			s := newAckClient(t, nil)
			post := s.settleAckPoster(Operator{ProtoVersion: tc.version, BaseURL: node.URL}, id.Recipient(), false)
			if err := post(context.Background(), ack); err != nil {
				t.Fatal(err)
			}
			if len(*got) != 1 || (*got)[0].NeutralNames != tc.neutral || (*got)[0].SettleGroup != ack.SettleGroup {
				t.Errorf("%s node received %+v, want neutral names %v", tc.version, *got, tc.neutral)
			}
		}
	})

	t.Run("a refusal is final, not a reason to broadcast", func(t *testing.T) {
		node, _ := settleAckNode(t, id, http.StatusConflict)
		s := newAckClient(t, nil)
		post := s.settleAckPoster(Operator{ProtoVersion: wire.SettleAckMinVersion, BaseURL: node.URL}, id.Recipient(), false)
		err := post(context.Background(), ack)
		if err == nil || errors.Is(err, errNoSettleAckRoute) {
			t.Errorf("err = %v, want a final error", err)
		}
	})

	// The target sits on a public address and the relays have their own
	// owners, so relay eligibility (owner and subnet diversity) passes and the
	// relay's version is the only thing deciding.
	target := Operator{ID: 1, NodeID: 1, OwnerAddr: "TARGETOWNER", ProtoVersion: wire.SettleAckMinVersion,
		BaseURL: "https://198.51.100.9", Reachable: true}

	t.Run("a relayed request with no capable relay sends nothing", func(t *testing.T) {
		relay, got := settleAckRelay(t, id)
		old := Operator{ID: 2, NodeID: 1, OwnerAddr: "RELAYOWNER", ProtoVersion: "9.11", BaseURL: relay.URL, Reachable: true}
		s := newAckClient(t, []Operator{target, old})
		post := s.settleAckPoster(target, id.Recipient(), true)
		if err := post(context.Background(), ack); !errors.Is(err, errNoSettleAckRoute) {
			t.Errorf("err = %v, want errNoSettleAckRoute", err)
		}
		if len(*got) != 0 {
			t.Errorf("ack sent through a relay that cannot forward it (%d times)", len(*got))
		}
	})

	t.Run("a relayed request goes through a capable relay", func(t *testing.T) {
		relay, got := settleAckRelay(t, id)
		capable := Operator{ID: 2, NodeID: 1, OwnerAddr: "RELAYOWNER", ProtoVersion: wire.SettleAckMinVersion, BaseURL: relay.URL, Reachable: true}
		s := newAckClient(t, []Operator{target, capable})
		post := s.settleAckPoster(target, id.Recipient(), true)
		if err := post(context.Background(), ack); err != nil {
			t.Fatal(err)
		}
		if len(*got) != 1 || (*got)[0] != ack {
			t.Errorf("relay forwarded %+v, want one %+v", *got, ack)
		}
	})

	t.Run("only 202 is delivery", func(t *testing.T) {
		node, _ := settleAckNode(t, id, http.StatusOK)
		s := newAckClient(t, nil)
		post := s.settleAckPoster(Operator{ProtoVersion: wire.SettleAckMinVersion, BaseURL: node.URL}, id.Recipient(), false)
		if err := post(context.Background(), ack); err == nil {
			t.Error("a 200 was taken as an accepted ack")
		}
	})

	t.Run("a transport failure is final", func(t *testing.T) {
		dead := httptest.NewServer(http.NotFoundHandler())
		dead.Close()
		s := newAckClient(t, nil)
		post := s.settleAckPoster(Operator{ProtoVersion: wire.SettleAckMinVersion, BaseURL: dead.URL}, id.Recipient(), false)
		err := post(context.Background(), ack)
		if err == nil || errors.Is(err, errNoSettleAckRoute) {
			t.Errorf("err = %v, want a final error", err)
		}
	})
}

// handleWallet hands runSealed one fixed handle, so the test can read what
// runSealed wired onto it.
type handleWallet struct{ h *OpenHandle }

func (w handleWallet) Open(context.Context, *ticket.Ticket, Operator, []types.SignedTxn) (*OpenHandle, error) {
	return w.h, nil
}
func (handleWallet) PayerAddr() string { return "PAYER" }

// recheckWallet counts deposit rechecks.
type recheckWallet struct {
	handleWallet
	rechecks int
}

func (w *recheckWallet) RecheckDeposit() { w.rechecks++ }

// Only the node's own plaintext payment refusal means a handed-off open may
// have hit the prepaid pool. The same code at another status, or on a sealed
// reply, is not that refusal, and the pass-through must not wait on a recheck.
func TestRecheckDepositOnRefusedOpen(t *testing.T) {
	refusal := []byte(`{"error":{"code":"payment_verification_failed","message":"payment verification failed"}}`)
	for _, tc := range []struct {
		name   string
		status int
		sealed bool
		body   []byte
		want   int
	}{
		{"plaintext 402 payment refusal", http.StatusPaymentRequired, false, refusal, 1},
		{"same code at 400", http.StatusBadRequest, false, refusal, 0},
		{"sealed 402", http.StatusPaymentRequired, true, refusal, 0},
		{"other 402 code", http.StatusPaymentRequired, false, []byte(`{"error":{"code":"ticket_invalid"}}`), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := &recheckWallet{}
			c := &Client{wallet: w}
			resp := &http.Response{StatusCode: tc.status, Header: http.Header{}}
			if tc.sealed {
				resp.Header.Set(wire.ResponseKeyHeader, "KEY")
			}
			passed := false
			next := func(emitter, *http.Response, []byte) error { passed = true; return nil }
			if err := c.recheckDepositOnRefusedOpen(next)(&recEmitter{}, resp, tc.body); err != nil {
				t.Fatal(err)
			}
			if !passed {
				t.Error("the refusal was not passed on")
			}
			if w.rechecks != tc.want {
				t.Errorf("rechecks = %d, want %d", w.rechecks, tc.want)
			}
		})
	}
}

// A request that rode a relay must ack through one too: a direct ack would
// show the target the payer's IP next to a group naming the payer.
func TestRunSealed_RelayedRequestAcksThroughARelay(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	node, direct := settleAckNode(t, id, http.StatusAccepted)
	relay, relayed := settleAckRelay(t, id)
	target := Operator{ID: 1, NodeID: 1, OwnerAddr: "TARGETOWNER", ProtoVersion: wire.SettleAckMinVersion, BaseURL: node.URL, Reachable: true}
	capable := Operator{ID: 2, NodeID: 1, OwnerAddr: "RELAYOWNER", ProtoVersion: wire.SettleAckMinVersion, BaseURL: relay.URL, Reachable: true}

	c := newAckClient(t, []Operator{target, capable})
	c.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	c.refunds = NewRefundWatchdog(c.log)
	handle := &OpenHandle{}
	c.wallet = handleWallet{h: handle}
	rt := &ReservedTicket{Ticket: &ticket.Ticket{TicketID: "T"}, SealRecipient: id.Recipient()}
	hop := &RelayHop{BaseURL: relay.URL, TargetID: 1, TargetNodeID: 1}

	c.runSealed(context.Background(), &recEmitter{}, endpointChatCompletions, "m", []byte(`{}`), target, rt, false, hop)

	if handle.deliverAck == nil {
		t.Fatal("no ack route wired for a 9.12 node")
	}
	*direct, *relayed = nil, nil // drop whatever the inference leg itself sent
	if err := handle.deliverAck(context.Background(), wire.SettleAck{TicketID: "T", SettleGroup: "G"}); err != nil {
		t.Fatal(err)
	}
	if len(*direct) != 0 || len(*relayed) != 1 {
		t.Errorf("ack went direct %d times and through the relay %d times, want 0 and 1", len(*direct), len(*relayed))
	}
}

// settleAckRelay is a relay that accepts only a well-formed relayed settle ack
// for target (1,1), opens it as the target would, and answers 202.
func settleAckRelay(t *testing.T, id *age.X25519Identity) (*httptest.Server, *[]wire.SettleAck) {
	t.Helper()
	var got []wire.SettleAck
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != wire.RelayPath ||
			r.Header.Get(wire.RelayPathHeader) != wire.SettleAckPath ||
			r.Header.Get(wire.RelayMethodHeader) != http.MethodPost ||
			r.Header.Get(wire.RelayTargetHeader) != "1" ||
			r.Header.Get(wire.RelayTargetNodeHeader) != "1" ||
			r.Header.Get("Content-Type") != wire.SealedSettleAckContentType {
			http.Error(w, "bad relay request", http.StatusBadRequest)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		ack, err := wire.OpenSettleAck(raw, id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		got = append(got, ack)
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}
