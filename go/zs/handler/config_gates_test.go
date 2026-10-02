/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	hayai "github.com/TxnLab/zerosignal/go/zs"
	"github.com/TxnLab/zerosignal/go/zs/handler/transform"
)

// These pin each Config field at the point dispatch reads it. A helper test
// alone (relayByDefault, teeRequired) leaves the call site free to stop using
// the helper, and every field here is either a privacy or a security gate.

// dispatchRelayHops drives one chat request through dispatchHayai against a
// target and a relay of distinct owners, with a reserve client that refuses
// every call, and returns the hop each reserve rode. The refusal ends the
// request before payment, so no wallet is needed.
func dispatchRelayHops(t *testing.T, cfg *Config, relayHeader, bodyRelay string) []*hayai.RelayHop {
	t.Helper()
	refuse := &hayai.ReserveHTTPError{Status: http.StatusBadRequest, Code: "invalid_request"}
	rc := &scriptedReserveClient{script: []error{refuse}}
	s := retryServer(t, true, rc, []hayai.Operator{retryOp(1, "OWNER_A"), retryOp(2, "OWNER_B")})
	s.cfg = cfg
	s.tokenizer = testTokenizer()
	s.wallet = &fakeWallet{}

	provider := ""
	if bodyRelay != "" {
		provider = `,"provider":{"relay":"` + bodyRelay + `"}`
	}
	body := []byte(`{"model":"gpt-test","messages":[{"role":"user","content":"hi"}]` + provider + `}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(string(body)))
	if relayHeader != "" {
		req.Header.Set("X-Zs-Relay", relayHeader)
	}
	s.dispatchHayai(httptest.NewRecorder(), req, endpointChatCompletions, body, formatChat)

	if rc.calls() == 0 {
		t.Fatal("no reserve was attempted; the test reached no routing decision")
	}
	hops := make([]*hayai.RelayHop, rc.calls())
	for i := range hops {
		hops[i] = rc.hopAt(i)
	}
	return hops
}

func TestDispatch_RelayPosture(t *testing.T) {
	for _, tc := range []struct {
		name      string
		cfg       *Config
		header    string
		bodyRelay string
		wantRelay bool
	}{
		// An SDK caller who never set Privacy.
		{"zero Privacy relays", &Config{Affinity: hayai.AffinityNone}, "", "", true},
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
			for i, hop := range dispatchRelayHops(t, tc.cfg, tc.header, tc.bodyRelay) {
				if (hop != nil) != tc.wantRelay {
					t.Errorf("reserve %d: relayed = %v, want %v", i, hop != nil, tc.wantRelay)
				}
			}
		})
	}
}

func TestConfig_TEERequiredOnlyForListedModels(t *testing.T) {
	c := &Config{TEERequiredModels: []string{"listed"}}
	if !c.teeRequired("listed") {
		t.Error("a listed model is not TEE-required")
	}
	if c.teeRequired("other") {
		t.Error("an unlisted model is TEE-required; one entry must not gate every model")
	}
	if (&Config{}).teeRequired("listed") {
		t.Error("an empty list requires TEE")
	}
}

// The Config doc promises a zero Affinity behaves as prefer: the tool-call pin
// leads. AffinityNone is the control that shows the pin is what moved it.
func TestPickCandidates_ZeroAffinityPinsLikePrefer(t *testing.T) {
	const model = "gpt-4o-mini"
	// The pin takes the higher id so a tie-break can't put it first by itself.
	pinned, peer := signerOp(9, model, nil), signerOp(8, model, nil)
	body := []byte(`{"model":"gpt-4o-mini","messages":[{"role":"tool","tool_call_id":"call_1","content":"x"}]}`)

	first := func(policy hayai.AffinityPolicy) uint64 {
		srv := minimalTEEServer(t, []hayai.Operator{peer, pinned})
		srv.cfg.Affinity = policy
		srv.toolAffinity = hayai.NewIDAffinity(16, time.Minute, time.Now)
		srv.toolAffinity.Record(pinned.ID, pinned.NodeID, []string{"call_1"})
		got := pickChat(t, srv, model, body)
		if len(got.Operators) != 2 {
			t.Fatalf("policy %q: got %v, want both operators", policy, opIDSet(got.Operators))
		}
		return got.Operators[0].ID
	}
	if got := first(hayai.AffinityNone); got == pinned.ID {
		t.Fatal("control: the pinned node leads with affinity off, so this test can't tell")
	}
	if got := first(""); got != pinned.ID {
		t.Errorf("zero Affinity: %d leads, want the pinned %d", got, pinned.ID)
	}
}

// Under prefer, an underfunded pin with no funded peer is a model-wide outage.
// Naming the pin and "affinity_policy: strict" would send the payer to a knob
// they already have set the way the message recommends.
func TestPickCandidates_ToolAffinityPrefer_UnderfundedPinNotReportedAsStrict(t *testing.T) {
	const model = "gpt-4o-mini"
	pinned := signerOp(7, model, micro(0))
	srv := minimalTEEServer(t, []hayai.Operator{pinned})
	srv.cfg.Affinity = hayai.AffinityPrefer
	srv.toolAffinity = hayai.NewIDAffinity(16, time.Minute, time.Now)
	srv.toolAffinity.Record(pinned.ID, pinned.NodeID, []string{"call_1"})

	body := []byte(`{"model":"gpt-4o-mini","messages":[{"role":"tool","tool_call_id":"call_1","content":"x"}]}`)
	pick := pickChat(t, srv, model, body)
	if !pick.SignerUnderfundedBlocked {
		t.Fatalf("got %+v, want SignerUnderfundedBlocked", pick)
	}
	if r := pick.SignerUnderfundedReason; r != "" {
		t.Errorf("reason = %q, want empty so the model-wide message is used", r)
	}
}

// The SSRF dial guard is on unless the caller opts out: a malicious operator's
// loopback BaseURL must not let it probe the payer's own machine.
func TestNew_BlocksPrivateTargetsUnlessAllowed(t *testing.T) {
	var hits atomic.Int32
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
	}))
	defer local.Close()

	guarded := New(&Config{}, silentLogger(), transform.Passthrough{}, transform.Passthrough{}, Options{})
	if resp, err := guarded.httpClient.Get(local.URL); err == nil {
		resp.Body.Close()
		t.Error("default Config dialed a loopback target")
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("loopback server saw %d requests through the guard", n)
	}

	open := New(&Config{AllowPrivateOperators: true}, silentLogger(), transform.Passthrough{}, transform.Passthrough{}, Options{})
	resp, err := open.httpClient.Get(local.URL)
	if err != nil {
		t.Fatalf("AllowPrivateOperators: %v", err)
	}
	resp.Body.Close()
	if hits.Load() != 1 {
		t.Error("control: AllowPrivateOperators did not reach the loopback server")
	}
}
