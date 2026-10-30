/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/wire"
	"github.com/TxnLab/zerosignal/go/zs"
	"github.com/TxnLab/zerosignal/go/zs/handler/transform"
)

// These pin each zs.Config field and request header through a served request.
// Every one is a privacy or a security gate, and the Client's own tests cannot
// see the handler drop or rename a header.

// refusingReserveClient refuses every reserve, with err or else a plain 400,
// and records the target and hop of each. The refusal ends the request before
// payment, so no wallet is needed.
type refusingReserveClient struct {
	err  error
	mu   sync.Mutex
	ops  []zs.Operator
	hops []*zs.RelayHop
}

func (c *refusingReserveClient) Reserve(_ context.Context, op zs.Operator, _ ticket.ReserveRequest, hop *zs.RelayHop) (*zs.ReservedTicket, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ops = append(c.ops, op)
	c.hops = append(c.hops, hop)
	if c.err != nil {
		return nil, c.err
	}
	return nil, &zs.ReserveHTTPError{Status: http.StatusBadRequest, Code: "invalid_request"}
}

// gatesOp is a reachable, version-compatible operator. Distinct owners matter:
// a relay must not share its target's owner.
func gatesOp(id uint64, owner string) zs.Operator {
	return zs.Operator{
		ID:           id,
		NodeID:       1,
		OwnerAddr:    owner,
		BaseURL:      "http://op.example",
		ProtoVersion: wire.ProtoVersion,
		Reachable:    true,
		Models:       []string{"gpt-test"},
	}
}

// gatesServer builds a Server over ops whose reserves are all refused.
func gatesServer(t *testing.T, cfg *policy, rc zs.ReserveClient, ops ...zs.Operator) *Server {
	t.Helper()
	registry, err := zs.NewStaticRegistryProvider(ops)
	if err != nil {
		t.Fatalf("NewStaticRegistryProvider: %v", err)
	}
	return newServer(cfg, silentLogger(), transform.Passthrough{}, transform.Passthrough{}, deps{
		RegistryProvider: registry,
		ReserveClient:    rc,
		Tokenizer:        testTokenizer(),
		Wallet:           &fakeWallet{},
	})
}

// dispatchRelayHops sends one chat request against a target and a relay of
// distinct owners and returns the hop each reserve rode.
func dispatchRelayHops(t *testing.T, cfg *policy, relayHeader, bodyRelay string) []*zs.RelayHop {
	t.Helper()
	rc := &refusingReserveClient{}
	s := gatesServer(t, cfg, rc, gatesOp(1, "OWNER_A"), gatesOp(2, "OWNER_B"))

	provider := ""
	if bodyRelay != "" {
		provider = `,"provider":{"relay":"` + bodyRelay + `"}`
	}
	req := clientReq(http.MethodPost, "/v1/chat/completions",
		`{"model":"gpt-test","messages":[{"role":"user","content":"hi"}]`+provider+`}`)
	if relayHeader != "" {
		req.Header.Set("X-Zs-Relay", relayHeader)
	}
	s.mux.ServeHTTP(httptest.NewRecorder(), req)

	if len(rc.hops) == 0 {
		t.Fatal("no reserve was attempted; the test reached no routing decision")
	}
	return rc.hops
}

func TestDispatch_RelayPosture(t *testing.T) {
	for _, tc := range []struct {
		name      string
		cfg       *policy
		header    string
		bodyRelay string
		wantRelay bool
	}{
		// A caller who never set Privacy, on a public network and on a local
		// chain, where the one node has no relay.
		{"zero Privacy relays", &policy{Network: "testnet", Affinity: zs.AffinityNone}, "", "", true},
		{"zero Privacy on localnet sends direct", &policy{Network: "localnet", Affinity: zs.AffinityNone}, "", "", false},
		{"direct sends direct", &policy{Privacy: zs.PrivacyDirect, Affinity: zs.AffinityNone}, "", "", false},
		// A caller's relay=off must not override a payer who didn't allow it.
		{"off refused without override", &policy{Privacy: zs.PrivacyRelayRequired, Affinity: zs.AffinityNone}, "off", "", true},
		// The control for the row above: the header does reach the decision.
		{"off honored with override", &policy{Privacy: zs.PrivacyRelayRequired, AllowPrivacyOverride: true, Affinity: zs.AffinityNone}, "off", "", false},
		// The body's provider.relay outranks the header, in both directions.
		{"body required beats header off", &policy{Privacy: zs.PrivacyRelayRequired, AllowPrivacyOverride: true, Affinity: zs.AffinityNone}, "off", "required", true},
		{"body off beats header required", &policy{Privacy: zs.PrivacyRelayRequired, AllowPrivacyOverride: true, Affinity: zs.AffinityNone}, "required", "off", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.cfg.AllowPrivateOperators = true
			for i, hop := range dispatchRelayHops(t, tc.cfg, tc.header, tc.bodyRelay) {
				if (hop != nil) != tc.wantRelay {
					t.Errorf("reserve %d: relayed = %v, want %v", i, hop != nil, tc.wantRelay)
				}
			}
		})
	}
}

// A TEE requirement reaches routing from either source — the payer's per-model
// list or the caller's header — and only for what it names. Every candidate
// here is unattested, so a requirement that arrives ends in no_tee_capacity
// before any reserve; one that is dropped reaches the reserve.
func TestDispatch_TEERequirement(t *testing.T) {
	for _, tc := range []struct {
		name    string
		models  []string
		header  string
		wantTEE bool
	}{
		{"listed model", []string{"gpt-test"}, "", true},
		{"unlisted model", []string{"other"}, "", false},
		{"header", nil, "nvidia-cc", true},
		{"neither", nil, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rc := &refusingReserveClient{}
			cfg := &policy{Privacy: zs.PrivacyDirect, TEERequiredModels: tc.models}
			s := gatesServer(t, cfg, rc, gatesOp(1, "OWNER_A"))
			req := clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test","max_completion_tokens":100}`)
			if tc.header != "" {
				req.Header.Set("X-Zs-Require-TEE", tc.header)
			}
			w := httptest.NewRecorder()
			s.mux.ServeHTTP(w, req)

			gotTEE := strings.Contains(w.Body.String(), `"no_tee_capacity"`)
			if gotTEE != tc.wantTEE {
				t.Errorf("no_tee_capacity = %v, want %v (status %d body %s)", gotTEE, tc.wantTEE, w.Code, w.Body.String())
			}
			if tc.wantTEE && (w.Code != http.StatusServiceUnavailable || len(rc.hops) != 0) {
				t.Errorf("status %d after %d reserves, want 503 before any", w.Code, len(rc.hops))
			}
		})
	}
}

// Strict affinity keeps a continuation on its pinned operator; a turn with no
// pin has nothing to keep, so a candidate with no eligible relay is skipped
// like any other rather than ending the turn.
func TestDispatch_StrictUnpinnedSkipsRelaylessCandidate(t *testing.T) {
	at := func(op zs.Operator, url string) zs.Operator { op.BaseURL = url; return op }
	// Op 1 has no relay: op 2 shares its /16, op 3 its owner. Ops 2 and 3
	// relay for each other.
	relayless := at(gatesOp(1, "OWNER_A"), "http://203.0.113.1")
	rc := &refusingReserveClient{}
	s := gatesServer(t, &policy{Privacy: zs.PrivacyRelayRequired, Affinity: zs.AffinityStrict, AllowPrivateOperators: true}, rc,
		relayless,
		at(gatesOp(2, "OWNER_B"), "http://203.0.113.2"),
		at(gatesOp(3, "OWNER_A"), "http://198.51.100.1"))
	s.mux.ServeHTTP(httptest.NewRecorder(), clientReq(http.MethodPost, "/v1/chat/completions",
		`{"model":"gpt-test","messages":[{"role":"user","content":"hi"}]}`))

	var ids []uint64
	for _, op := range rc.ops {
		ids = append(ids, op.ID)
	}
	if len(ids) != 2 || ids[0] == 1 || ids[1] == 1 {
		t.Errorf("reserved %v, want ops 2 and 3 after op 1 was skipped", ids)
	}
}

// The same holds for a candidate that cannot price an image tool the turn
// budgets for. The turn budgets both tools, so op 1, pricing one of them,
// still ranks first; it is skipped for the other.
func TestDispatch_StrictUnpinnedSkipsUnpricedToolCandidate(t *testing.T) {
	priced := func(op zs.Operator, gen, edit uint64) zs.Operator {
		op.ModelCapacities = map[string]zs.ModelCapacity{"gpt-test": {
			ImageToolRateMicroUSDC: gen, ImageEditToolRateMicroUSDC: edit, OutputUSDPer1M: 10,
		}}
		return op
	}
	for _, tc := range []struct {
		name      string
		gen, edit uint64
	}{
		{"generation unpriced", 0, 80_000},
		{"edit unpriced", 80_000, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rc := &refusingReserveClient{}
			s := gatesServer(t, &policy{Privacy: zs.PrivacyDirect, Affinity: zs.AffinityStrict}, rc,
				priced(gatesOp(1, "OWNER_A"), tc.gen, tc.edit), priced(gatesOp(2, "OWNER_B"), 80_000, 80_000))
			s.mux.ServeHTTP(httptest.NewRecorder(), clientReq(http.MethodPost, "/v1/responses",
				`{"model":"gpt-test","input":[{"role":"user","content":"hi"}],"max_output_tokens":50,`+
					`"tool_budgets":{"zs_image_generation":{"max_n":1},"zs_image_edit":{"max_n":1}}}`))

			if len(rc.ops) != 1 || rc.ops[0].ID != 2 {
				var ids []uint64
				for _, op := range rc.ops {
					ids = append(ids, op.ID)
				}
				t.Errorf("reserved %v, want op 2 after op 1 was skipped", ids)
			}
		})
	}
}

// Each routing store in Config.Stores reaches routing. The fraud ban is the one
// that matters most — a dropped NodeExcluder silently routes to a node proven
// to have tried to take the payer's money — but a dropped store of any kind
// leaves routing blind to evidence the proxy is still collecting.
func TestNew_PassesRoutingStores(t *testing.T) {
	ref := func(op zs.Operator) zs.NodeRef { return zs.RefOf(op) }
	op1, op2, op3 := gatesOp(1, "OWNER_A"), gatesOp(2, "OWNER_B"), gatesOp(3, "OWNER_C")

	// reserved dispatches one chat request in direct mode and returns the
	// operators reserved against, in order. Every reserve is refused with a
	// code, so every candidate is asked once.
	reserved := func(t *testing.T, opts func(*deps)) []uint64 {
		t.Helper()
		registry, err := zs.NewStaticRegistryProvider([]zs.Operator{op1, op2})
		if err != nil {
			t.Fatalf("NewStaticRegistryProvider: %v", err)
		}
		rc := &refusingReserveClient{}
		o := deps{RegistryProvider: registry, ReserveClient: rc, Tokenizer: testTokenizer(), Wallet: &fakeWallet{}}
		opts(&o)
		s := newServer(&policy{Privacy: zs.PrivacyDirect, Affinity: zs.AffinityNone, AllowPrivateOperators: true},
			silentLogger(), transform.Passthrough{}, transform.Passthrough{}, o)
		s.mux.ServeHTTP(httptest.NewRecorder(), clientReq(http.MethodPost, "/v1/chat/completions",
			`{"model":"gpt-test","messages":[{"role":"user","content":"hi"}]}`))
		var ids []uint64
		for _, op := range rc.ops {
			ids = append(ids, op.ID)
		}
		return ids
	}

	// The control: with no store, op 1 is asked first. Each case below moves it.
	if got := reserved(t, func(*deps) {}); len(got) != 2 || got[0] != 1 {
		t.Fatalf("control: reserved %v, want op 1 then op 2", got)
	}

	t.Run("NodeExcluder", func(t *testing.T) {
		src := &zs.ChainOperatorSource{}
		src.ExcludeNode(ref(op1))
		if got := reserved(t, func(o *deps) { o.NodeExcluder = src }); len(got) != 1 || got[0] != 2 {
			t.Errorf("reserved %v, want only op 2", got)
		}
	})
	t.Run("TargetBackoff", func(t *testing.T) {
		src := &zs.ChainOperatorSource{}
		src.RecordTargetOutcome(ref(op1), false)
		if got := reserved(t, func(o *deps) { o.TargetBackoff = src }); len(got) != 2 || got[0] != 2 {
			t.Errorf("reserved %v, want op 2 first", got)
		}
	})
	t.Run("RelayLatency", func(t *testing.T) {
		src := &zs.ChainOperatorSource{}
		for range zs.LatencyMinSamples {
			src.RecordDirectRTT(ref(op1), 10*time.Second)
			src.RecordDirectRTT(ref(op2), 10*time.Millisecond)
		}
		if got := reserved(t, func(o *deps) { o.RelayLatency = src }); len(got) != 2 || got[0] != 2 {
			t.Errorf("reserved %v, want op 2 first", got)
		}
	})
	t.Run("RelayReputation", func(t *testing.T) {
		// A downranked relay is a fallback, never a drop, so it is chosen only
		// when no other relay can carry the target. With three owners every
		// target has another, so op 2 must never relay.
		src := &zs.ChainOperatorSource{}
		for !src.RelayDownranked(ref(op2)) {
			src.RecordRelayOutcome(ref(op2), false)
		}
		registry, err := zs.NewStaticRegistryProvider([]zs.Operator{op1, op2, op3})
		if err != nil {
			t.Fatalf("NewStaticRegistryProvider: %v", err)
		}
		rc := &refusingReserveClient{}
		s := newServer(&policy{Privacy: zs.PrivacyRelayRequired, Affinity: zs.AffinityNone, AllowPrivateOperators: true},
			silentLogger(), transform.Passthrough{}, transform.Passthrough{}, deps{
				RegistryProvider: registry, ReserveClient: rc, Tokenizer: testTokenizer(), Wallet: &fakeWallet{},
				RelayReputation: src,
			})
		// Relay choice is random; 8 requests × 3 targets leave a dropped store
		// a 2^-24 chance of passing.
		for range 8 {
			s.mux.ServeHTTP(httptest.NewRecorder(), clientReq(http.MethodPost, "/v1/chat/completions",
				`{"model":"gpt-test","messages":[{"role":"user","content":"hi"}]}`))
		}
		if len(rc.hops) == 0 {
			t.Fatal("no reserve was attempted")
		}
		for i, hop := range rc.hops {
			if hop == nil || hop.RelayRef() == ref(op2) {
				t.Fatalf("reserve %d rode %+v; the downranked relay was used", i, hop)
			}
		}
	})
}

// The SSRF dial guard is on unless the payer opts out: a malicious operator's
// loopback BaseURL must not let it probe the payer's own machine. The fake
// node's reserve runs on its own client, so what the guard decides is whether
// the paid request reaches the node.
func TestNew_BlocksPrivateTargetsUnlessAllowed(t *testing.T) {
	for _, allow := range []bool{false, true} {
		node := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{"ok":true}`)})
		cfg := testConfig()
		opts := setup(t, cfg, node)
		cfg.AllowPrivateOperators = allow
		s := newServer(&cfg.policy, silentLogger(), transform.Passthrough{}, transform.Passthrough{}, opts)

		w := httptest.NewRecorder()
		s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))

		reached := node.lastSealedAlgorandTxID != ""
		if reached != allow {
			t.Errorf("AllowPrivateOperators=%v: loopback node reached = %v (status %d)", allow, reached, w.Code)
		}
		if allow && w.Code != http.StatusOK {
			t.Errorf("control: AllowPrivateOperators did not serve: status %d body %s", w.Code, w.Body.String())
		}
	}
}
