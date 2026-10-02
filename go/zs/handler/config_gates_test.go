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
	hayai "github.com/TxnLab/zerosignal/go/zs"
	"github.com/TxnLab/zerosignal/go/zs/handler/transform"
)

// These pin each Config field and request header at the point the handler
// hands it to the Client. Every one is a privacy or a security gate, and the
// Client's own tests cannot see the handler drop or rename one.

// refusingReserveClient refuses every reserve, with err or else a plain 400,
// and records the target and hop of each. The refusal ends the request before
// payment, so no wallet is needed.
type refusingReserveClient struct {
	err  error
	mu   sync.Mutex
	ops  []hayai.Operator
	hops []*hayai.RelayHop
}

func (c *refusingReserveClient) Reserve(_ context.Context, op hayai.Operator, _ ticket.ReserveRequest, hop *hayai.RelayHop) (*hayai.ReservedTicket, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ops = append(c.ops, op)
	c.hops = append(c.hops, hop)
	if c.err != nil {
		return nil, c.err
	}
	return nil, &hayai.ReserveHTTPError{Status: http.StatusBadRequest, Code: "invalid_request"}
}

// gatesOp is a reachable, version-compatible operator. Distinct owners matter:
// a relay must not share its target's owner.
func gatesOp(id uint64, owner string) hayai.Operator {
	return hayai.Operator{
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
func gatesServer(t *testing.T, cfg *Config, rc hayai.ReserveClient, ops ...hayai.Operator) *Server {
	t.Helper()
	registry, err := hayai.NewStaticRegistryProvider(ops)
	if err != nil {
		t.Fatalf("NewStaticRegistryProvider: %v", err)
	}
	return New(cfg, silentLogger(), transform.Passthrough{}, transform.Passthrough{}, Options{
		RegistryProvider: registry,
		ReserveClient:    rc,
		Tokenizer:        testTokenizer(),
		Wallet:           &fakeWallet{},
	})
}

// dispatchRelayHops sends one chat request against a target and a relay of
// distinct owners and returns the hop each reserve rode.
func dispatchRelayHops(t *testing.T, cfg *Config, relayHeader, bodyRelay string) []*hayai.RelayHop {
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
		cfg       *Config
		header    string
		bodyRelay string
		wantRelay bool
	}{
		// A caller who never set Privacy.
		{"zero Privacy relays", &Config{Affinity: hayai.AffinityNone}, "", "", true},
		// A typo is not an opt-out.
		{"unknown Privacy relays", &Config{Privacy: "relay-required", Affinity: hayai.AffinityNone}, "", "", true},
		{"direct sends direct", &Config{Privacy: hayai.PrivacyDirect, Affinity: hayai.AffinityNone}, "", "", false},
		// A caller's relay=off must not override a payer who didn't allow it.
		{"off refused without override", &Config{Privacy: hayai.PrivacyRelayRequired, Affinity: hayai.AffinityNone}, "off", "", true},
		// The control for the row above: the header does reach the decision.
		{"off honored with override", &Config{Privacy: hayai.PrivacyRelayRequired, AllowPrivacyOverride: true, Affinity: hayai.AffinityNone}, "off", "", false},
		// The body's provider.relay outranks the header, in both directions.
		{"body required beats header off", &Config{Privacy: hayai.PrivacyRelayRequired, AllowPrivacyOverride: true, Affinity: hayai.AffinityNone}, "off", "required", true},
		{"body off beats header required", &Config{Privacy: hayai.PrivacyRelayRequired, AllowPrivacyOverride: true, Affinity: hayai.AffinityNone}, "required", "off", false},
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
			cfg := &Config{Privacy: hayai.PrivacyDirect, TEERequiredModels: tc.models}
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

// Each routing store in Options reaches the Client. The fraud ban is the one
// that matters most — a dropped NodeExcluder silently routes to a node proven
// to have tried to take the payer's money — but a dropped store of any kind
// leaves routing blind to evidence the proxy is still collecting.
func TestNew_PassesRoutingStores(t *testing.T) {
	ref := func(op hayai.Operator) hayai.NodeRef { return hayai.RefOf(op) }
	op1, op2, op3 := gatesOp(1, "OWNER_A"), gatesOp(2, "OWNER_B"), gatesOp(3, "OWNER_C")

	// reserved dispatches one chat request in direct mode and returns the
	// operators reserved against, in order. Every reserve is refused with a
	// code, so every candidate is asked once.
	reserved := func(t *testing.T, opts func(*Options)) []uint64 {
		t.Helper()
		registry, err := hayai.NewStaticRegistryProvider([]hayai.Operator{op1, op2})
		if err != nil {
			t.Fatalf("NewStaticRegistryProvider: %v", err)
		}
		rc := &refusingReserveClient{}
		o := Options{RegistryProvider: registry, ReserveClient: rc, Tokenizer: testTokenizer(), Wallet: &fakeWallet{}}
		opts(&o)
		s := New(&Config{Privacy: hayai.PrivacyDirect, Affinity: hayai.AffinityNone, AllowPrivateOperators: true},
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
	if got := reserved(t, func(*Options) {}); len(got) != 2 || got[0] != 1 {
		t.Fatalf("control: reserved %v, want op 1 then op 2", got)
	}

	t.Run("NodeExcluder", func(t *testing.T) {
		src := &hayai.ChainOperatorSource{}
		src.ExcludeNode(ref(op1))
		if got := reserved(t, func(o *Options) { o.NodeExcluder = src }); len(got) != 1 || got[0] != 2 {
			t.Errorf("reserved %v, want only op 2", got)
		}
	})
	t.Run("TargetBackoff", func(t *testing.T) {
		src := &hayai.ChainOperatorSource{}
		src.RecordTargetOutcome(ref(op1), false)
		if got := reserved(t, func(o *Options) { o.TargetBackoff = src }); len(got) != 2 || got[0] != 2 {
			t.Errorf("reserved %v, want op 2 first", got)
		}
	})
	t.Run("RelayLatency", func(t *testing.T) {
		src := &hayai.ChainOperatorSource{}
		for range hayai.LatencyMinSamples {
			src.RecordDirectRTT(ref(op1), 10*time.Second)
			src.RecordDirectRTT(ref(op2), 10*time.Millisecond)
		}
		if got := reserved(t, func(o *Options) { o.RelayLatency = src }); len(got) != 2 || got[0] != 2 {
			t.Errorf("reserved %v, want op 2 first", got)
		}
	})
	t.Run("RelayReputation", func(t *testing.T) {
		// A downranked relay is a fallback, never a drop, so it is chosen only
		// when no other relay can carry the target. With three owners every
		// target has another, so op 2 must never relay.
		src := &hayai.ChainOperatorSource{}
		for !src.RelayDownranked(ref(op2)) {
			src.RecordRelayOutcome(ref(op2), false)
		}
		registry, err := hayai.NewStaticRegistryProvider([]hayai.Operator{op1, op2, op3})
		if err != nil {
			t.Fatalf("NewStaticRegistryProvider: %v", err)
		}
		rc := &refusingReserveClient{}
		s := New(&Config{Privacy: hayai.PrivacyRelayRequired, Affinity: hayai.AffinityNone, AllowPrivateOperators: true},
			silentLogger(), transform.Passthrough{}, transform.Passthrough{}, Options{
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
		opts := setupHayai(t, cfg, node)
		cfg.AllowPrivateOperators = allow
		s := New(&cfg.Config, silentLogger(), transform.Passthrough{}, transform.Passthrough{}, opts)

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
