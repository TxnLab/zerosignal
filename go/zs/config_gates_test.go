/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"testing"
	"time"
)

// New takes the network-facing parts as given, nil included, and builds the
// in-process ones it was not handed.
func TestNew_BuildsInProcessParts(t *testing.T) {
	c, err := New(context.Background(), Config{})
	if err != nil {
		t.Fatal(err)
	}
	if c.registryProvider != nil || c.reserveClient != nil || c.wallet != nil {
		t.Error("New invented a registry, reserve client or wallet it was not given")
	}
	if c.toolAffinity == nil || c.responseAffinity == nil {
		t.Error("New left an affinity cache nil")
	}
	if c.tokenizer == nil {
		t.Error("New left the tokenizer nil")
	}

	tool := NewIDAffinity(4, time.Minute, time.Now)
	c, err = New(context.Background(), Config{Stores: Stores{ToolAffinity: tool}})
	if err != nil {
		t.Fatal(err)
	}
	if c.toolAffinity != tool {
		t.Error("New replaced the supplied tool affinity")
	}
}

// With RequireMaxOutput and no Tokenizer, the tokenizer New builds must refuse
// a request that names no output budget, not size it at MaxOutputCeiling.
func TestNew_RequireMaxOutputWithoutTokenizer(t *testing.T) {
	registry, err := NewStaticRegistryProvider([]Operator{retryOp(1, "OWNER_A")})
	if err != nil {
		t.Fatal(err)
	}
	rc := &scriptedReserveClient{script: []error{&ReserveHTTPError{Status: 400, Code: "invalid_request"}}}
	c, err := New(context.Background(), Config{
		Privacy:          PrivacyDirect,
		RequireMaxOutput: true,
		Registry:         registry,
		ReserveClient:    rc,
		Wallet:           fakeFeeWallet{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ze := turnErr(t, c, `{"model":"gpt-test","messages":[{"role":"user","content":"hi"}]}`)
	if ze.Code != "max_output_required" {
		t.Errorf("code %q, want max_output_required", ze.Code)
	}
	if rc.calls() != 0 {
		t.Errorf("%d reserves made for an unsized request", rc.calls())
	}
}

// A caller who never sets Privacy must not send direct: a direct send shows
// the target the payer's IP. Only PrivacyDirect opts out; anything else,
// including a typo, relays.
func TestConfig_RelaysUnlessDirect(t *testing.T) {
	for _, tc := range []struct {
		privacy Privacy
		want    bool
	}{
		{"", true},
		{PrivacyRelayRequired, true},
		{"relay-required", true},
		{PrivacyDirect, false},
	} {
		c := &Config{Privacy: tc.privacy}
		if got := c.relayByDefault(); got != tc.want {
			t.Errorf("Privacy %q: relayByDefault = %v, want %v", tc.privacy, got, tc.want)
		}
	}
}

func TestConfig_TEERequiredOnlyForListedModels(t *testing.T) {
	c := &Config{RequireTEEModels: []string{"listed"}}
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

	first := func(policy AffinityPolicy) uint64 {
		srv := minimalTEEServer(t, []Operator{peer, pinned})
		srv.cfg.Affinity.Policy = policy
		srv.toolAffinity = NewIDAffinity(16, time.Minute, time.Now)
		srv.toolAffinity.Record(pinned.ID, pinned.NodeID, []string{"call_1"})
		got := pickChat(t, srv, model, body)
		if len(got.Operators) != 2 {
			t.Fatalf("policy %q: got %v, want both operators", policy, opIDSet(got.Operators))
		}
		return got.Operators[0].ID
	}
	if got := first(AffinityNone); got == pinned.ID {
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
	srv := minimalTEEServer(t, []Operator{pinned})
	srv.cfg.Affinity.Policy = AffinityPrefer
	srv.toolAffinity = NewIDAffinity(16, time.Minute, time.Now)
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
