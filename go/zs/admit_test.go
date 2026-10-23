/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"mime/multipart"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/ticket"
)

// admitGuard records each Admit estimate and refuses any above limit.
type admitGuard struct {
	mu        sync.Mutex
	limit     uint64
	estimates []uint64
}

func (g *admitGuard) Admit(est uint64) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.estimates = append(g.estimates, est)
	if est > g.limit {
		return errors.New("over the cap")
	}
	return nil
}
func (*admitGuard) Reserve(string, uint64) error { return nil }
func (*admitGuard) Settle(string, uint64)        {}
func (*admitGuard) Release(string)               {}

func (g *admitGuard) seen() []uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]uint64(nil), g.estimates...)
}

// pricedOp is retryOp advertising in/out USD per 1M tokens for gpt-test.
func pricedOp(id uint64, in, out float64) Operator {
	op := retryOp(id, "OWNER")
	op.ModelCapacities = map[string]ModelCapacity{"gpt-test": {InputUSDPer1M: in, OutputUSDPer1M: out}}
	return op
}

var admitBody = []byte(`{"model":"gpt-test","messages":[{"role":"user","content":"hello there"}],"max_tokens":100}`)

var admitSizing = SizingRequest{Model: "gpt-test", MaxOutputTokens: 100}

// At $1 and $2 per 1M tokens a token costs 1 and 2 microUSDC, so the ceiling
// is input + 2×output before the fee.
func TestAdmitEstimate_PricesFromAdvertisedRates(t *testing.T) {
	op := pricedOp(1, 1, 2)
	input, _ := reserveInputCount(op, "gpt-test", admitBody, 100)
	for _, tc := range []struct {
		feeBps uint64
		want   uint64
	}{
		{0, input + 200},
		// 10%, rounded up.
		{1000, input + 200 + (input+200+9)/10},
	} {
		got, ok := newPriceTestServer(tc.feeBps, true).admitEstimate([]Operator{op}, "gpt-test", admitBody, admitSizing)
		if !ok || got != tc.want {
			t.Errorf("fee %d bps: estimate %d (ok %v), want %d", tc.feeBps, got, ok, tc.want)
		}
	}
}

// The estimate is the cheapest candidate's, in any order: Admit must not refuse
// a request a cheaper node could serve.
func TestAdmitEstimate_TakesTheCheapestCandidate(t *testing.T) {
	s := newPriceTestServer(0, true)
	cheap, dear := pricedOp(1, 1, 2), pricedOp(2, 10, 20)
	want, _ := s.admitEstimate([]Operator{cheap}, "gpt-test", admitBody, admitSizing)
	alone, _ := s.admitEstimate([]Operator{dear}, "gpt-test", admitBody, admitSizing)
	if want >= alone {
		t.Fatalf("control: cheap %d not below dear %d", want, alone)
	}
	for _, ops := range [][]Operator{{cheap, dear}, {dear, cheap}} {
		if got, ok := s.admitEstimate(ops, "gpt-test", admitBody, admitSizing); !ok || got != want {
			t.Errorf("order %d,%d: estimate %d, want the cheapest %d", ops[0].ID, ops[1].ID, got, want)
		}
	}
}

// Above the threshold the node signs the long-context rates, so the estimate
// uses them too; a tier without its rates leaves that candidate unpriced.
func TestAdmitEstimate_LongContextTier(t *testing.T) {
	s := newPriceTestServer(0, true)
	op := pricedOp(1, 1, 2)
	input, _ := reserveInputCount(op, "gpt-test", admitBody, 100)
	mc := op.ModelCapacities["gpt-test"]
	mc.LongContextThresholdTokens = input
	mc.LongContextInputUSDPer1M, mc.LongContextOutputUSDPer1M = f64ptr(3), f64ptr(4)
	op.ModelCapacities["gpt-test"] = mc
	if got, ok := s.admitEstimate([]Operator{op}, "gpt-test", admitBody, admitSizing); !ok || got != 3*input+400 {
		t.Errorf("long-context estimate %d (ok %v), want %d", got, ok, 3*input+400)
	}
	// One token short of the threshold is still the base tier.
	below := mc
	below.LongContextThresholdTokens = input + 1
	op.ModelCapacities["gpt-test"] = below
	if got, ok := s.admitEstimate([]Operator{op}, "gpt-test", admitBody, admitSizing); !ok || got != 1*input+200 {
		t.Errorf("sub-threshold estimate %d (ok %v), want %d", got, ok, 1*input+200)
	}
	op.ModelCapacities["gpt-test"] = mc
	// Details carry the two tier rates separately, so either can be missing.
	for name, set := range map[string]func(*ModelCapacity){
		"input":  func(m *ModelCapacity) { m.LongContextInputUSDPer1M = nil },
		"output": func(m *ModelCapacity) { m.LongContextOutputUSDPer1M = nil },
	} {
		m := mc
		set(&m)
		op.ModelCapacities["gpt-test"] = m
		if got, ok := s.admitEstimate([]Operator{op}, "gpt-test", admitBody, admitSizing); ok {
			t.Errorf("a tier with no %s rate priced at %d", name, got)
		}
	}
}

// The estimate prices the input and output the reserve loop would send this
// operator: input capped by its window less the output, and the output derived
// from its own cap when the request names none.
func TestAdmitEstimate_PricesTheOperatorsOwnSizing(t *testing.T) {
	s := newPriceTestServer(0, true)
	op := pricedOp(1, 1, 2)
	mc := op.ModelCapacities["gpt-test"]
	mc.ContextWindow = 10_000
	op.ModelCapacities["gpt-test"] = mc
	// A continuation reserves the whole window less the output.
	cont := []byte(`{"model":"gpt-test","input":"hi","previous_response_id":"resp_1","max_output_tokens":100}`)
	if got, ok := s.admitEstimate([]Operator{op}, "gpt-test", cont, admitSizing); !ok || got != (10_000-100)+100*2 {
		t.Errorf("continuation estimate %d (ok %v), want %d", got, ok, (10_000-100)+100*2)
	}

	mc.MaxOutputTokens = 50
	op.ModelCapacities["gpt-test"] = mc
	derive := SizingRequest{Model: "gpt-test", MaxOutputTokens: 100, DeriveMaxOutput: true, MaxOutputCeiling: 4096}
	maxOut := EffectiveMaxOutput(op, derive)
	if maxOut == derive.MaxOutputTokens {
		t.Fatalf("control: derived output %d equals the flat value", maxOut)
	}
	input, _ := reserveInputCount(op, "gpt-test", admitBody, maxOut)
	if got, ok := s.admitEstimate([]Operator{op}, "gpt-test", admitBody, derive); !ok || got != input+2*maxOut {
		t.Errorf("derived estimate %d (ok %v), want %d", got, ok, input+2*maxOut)
	}
}

// With nothing to price from, Admit is skipped rather than told the request
// is free.
func TestAdmitEstimate_UnpricedIsNotOK(t *testing.T) {
	priced := pricedOp(1, 1, 2)
	for name, tc := range map[string]struct {
		s   *Client
		ops []Operator
	}{
		"fee not read":   {newPriceTestServer(0, false), []Operator{priced}},
		"no capacity":    {newPriceTestServer(0, true), []Operator{retryOp(1, "OWNER")}},
		"no input rate":  {newPriceTestServer(0, true), []Operator{pricedOp(1, 0, 2)}},
		"no output rate": {newPriceTestServer(0, true), []Operator{pricedOp(1, 1, 0)}},
		"no candidates":  {newPriceTestServer(0, true), nil},
		"negative rate":  {newPriceTestServer(0, true), []Operator{pricedOp(1, -1, 2)}},
	} {
		if got, ok := tc.s.admitEstimate(tc.ops, "gpt-test", admitBody, admitSizing); ok {
			t.Errorf("%s: estimate %d reported as priced", name, got)
		}
	}
	// An unpriced candidate may be the cheapest, so it cancels the estimate
	// rather than dropping out of the minimum, in either position.
	for _, ops := range [][]Operator{{retryOp(2, "OWNER"), priced}, {priced, retryOp(2, "OWNER")}} {
		if got, ok := newPriceTestServer(0, true).admitEstimate(ops, "gpt-test", admitBody, admitSizing); ok {
			t.Errorf("order %d,%d: estimate %d from a pool with an unpriced candidate", ops[0].ID, ops[1].ID, got)
		}
	}
}

// admitClient is a Client over ops with guard, a warm 0 fee, and a reserve
// client that fails every reserve.
func admitClient(t *testing.T, ops []Operator, guard SpendGuard) (*Client, *scriptedReserveClient) {
	t.Helper()
	registry, err := NewStaticRegistryProvider(ops)
	if err != nil {
		t.Fatal(err)
	}
	rc := &scriptedReserveClient{script: []error{&ReserveHTTPError{Status: 400, Code: "invalid_request"}}}
	cfg := suppliedParts(t)
	cfg.Privacy, cfg.Registry, cfg.ReserveClient, cfg.SpendGuard = PrivacyDirect, registry, rc, guard
	c, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	// New only starts the fee read; a turn that beats it would skip Admit.
	c.feeRate.mu.Lock()
	c.feeRate.feeBps, c.feeRate.ok, c.feeRate.fetchedAt = 0, true, time.Now()
	c.feeRate.mu.Unlock()
	return c, rc
}

// The turn hands Admit every candidate, not just the first or the last: with a
// cap between the two estimates, a dear node listed or routed first must not
// refuse a request the cheap one can serve.
func TestDispatch_AdmitPricesEveryCandidate(t *testing.T) {
	routedDearFirst := []byte(`{"model":"gpt-test","messages":[{"role":"user","content":"hello there"}],"max_tokens":100,"provider":{"order":["2:1"]}}`)
	for _, tc := range []struct {
		name string
		body []byte
		// firstRouted is the node the sweep tries first, which the case
		// exists to vary.
		firstRouted uint64
	}{
		{"routing puts the cheap node first", admitBody, 1},
		{"routing puts the dear node first", routedDearFirst, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newPriceTestServer(0, true)
			cheap, dear := pricedOp(1, 1, 2), pricedOp(2, 10, 20)
			low, _ := s.admitEstimate([]Operator{cheap}, "gpt-test", tc.body, admitSizing)
			high, _ := s.admitEstimate([]Operator{dear}, "gpt-test", tc.body, admitSizing)
			guard := &admitGuard{limit: (low + high) / 2}
			c, rc := admitClient(t, []Operator{dear, cheap}, guard)
			turnErr(t, c, string(tc.body))
			if rc.calls() == 0 {
				t.Fatal("no reserve made: Admit refused a request the cheap candidate fits")
			}
			// Priced at the cheap node's $1/$2 on the input count reserved
			// with it: dispatch sizes the body it sends, not the caller's.
			var req ticket.ReserveRequest
			for i, op := range rc.ops {
				if op.ID == cheap.ID {
					req = rc.reqs[i]
				}
			}
			if req.Model == "" {
				t.Fatal("no reserve went to the cheap node")
			}
			if want, got := req.InputCount+2*req.MaxOutputCount, guard.seen(); len(got) != 1 || got[0] != want {
				t.Errorf("Admit saw %v, want the cheap candidate's %d (dear is about %d)", got, want, high)
			}
			if rc.ops[0].ID != tc.firstRouted {
				t.Errorf("control: node %d routed first, want %d", rc.ops[0].ID, tc.firstRouted)
			}
		})
	}
}

// A refusal at Admit ends the turn as a spend cap before any node is asked
// for a reservation.
func TestDispatch_AdmitRefusalReservesNothing(t *testing.T) {
	guard := &admitGuard{limit: 0}
	c, rc := admitClient(t, []Operator{pricedOp(1, 1, 2)}, guard)
	ze := turnErr(t, c, string(admitBody))
	if ze.Code != "spend_cap_exceeded" || ze.Kind != KindSpendCap {
		t.Errorf("code %q kind %q, want spend_cap_exceeded / spend_cap", ze.Code, ze.Kind)
	}
	if want := (Remedies{}).withDefaults(ticket.RailAlgorand).RaiseSpendCap; !strings.Contains(ze.Message, want) {
		t.Errorf("message %q, want it to end with the remedy %q", ze.Message, want)
	}
	if rc.calls() != 0 {
		t.Errorf("%d reserves made after Admit refused", rc.calls())
	}
	if got := guard.seen(); len(got) != 1 || got[0] == 0 {
		t.Errorf("Admit saw %v, want one non-zero estimate", got)
	}
}

// An admitted request goes on to reserve; an unpriced one never asks Admit.
func TestDispatch_AdmitThenReserve(t *testing.T) {
	guard := &admitGuard{limit: ^uint64(0)}
	c, rc := admitClient(t, []Operator{pricedOp(1, 1, 2)}, guard)
	_ = turnErr(t, c, string(admitBody))
	if len(guard.seen()) != 1 || rc.calls() == 0 {
		t.Errorf("Admit calls %d, reserves %d: want one Admit, then a reserve", len(guard.seen()), rc.calls())
	}

	guard = &admitGuard{limit: 0}
	c, rc = admitClient(t, []Operator{retryOp(1, "OWNER")}, guard)
	_ = turnErr(t, c, string(admitBody))
	if len(guard.seen()) != 0 || rc.calls() == 0 {
		t.Errorf("unpriced: Admit calls %d, reserves %d: want no Admit, then a reserve", len(guard.seen()), rc.calls())
	}
}

// capGuard admits every estimate and refuses every reservation as a cap trip.
type capGuard struct{ admitGuard }

func (*capGuard) Reserve(string, uint64) error { return errors.New("daily spend cap exceeded") }

// ticketPerOperator signs each operator a ticket whose input rate is far above
// any advertised rate.
type ticketPerOperator struct{}

func (ticketPerOperator) Reserve(_ context.Context, op Operator, req ticket.ReserveRequest, _ *RelayHop) (*ReservedTicket, error) {
	return &ReservedTicket{Ticket: &ticket.Ticket{
		TicketID: fmt.Sprint(op.ID), Model: req.Model, InputCount: req.InputCount, MaxOutputCount: req.MaxOutputCount,
		InputRate: 1_000_000_000, OutputRate: 1_000_000_000, MaxPrice: 1_000_000_000,
	}}, nil
}

// One candidate over the cap and one whose ticket fails price verification is
// a spend cap: the cap is the payer's to change, while "every operator was
// mis-priced" would be false.
func TestDispatch_SpendCapOutranksPriceRejection(t *testing.T) {
	// The unpriced operator's ticket passes verification (no advertised rate
	// to check against) and reaches the guard; the priced one is rejected.
	ops := []Operator{retryOp(1, "OWNER_A"), pricedOp(2, 1, 2)}
	guard := &capGuard{admitGuard{limit: ^uint64(0)}}
	c, _ := admitClient(t, ops, guard)
	c.reserveClient = ticketPerOperator{}
	if ze := turnErr(t, c, string(admitBody)); ze.Code != "spend_cap_exceeded" {
		t.Errorf("code %q, want spend_cap_exceeded", ze.Code)
	}
}

// noEphemeralFor reserves like ticketPerOperator, except for operator id,
// which has no valid ephemeral recipient.
type noEphemeralFor struct{ id uint64 }

func (n noEphemeralFor) Reserve(ctx context.Context, op Operator, req ticket.ReserveRequest, hop *RelayHop) (*ReservedTicket, error) {
	if op.ID == n.id {
		return nil, ErrNoEphemeral
	}
	return ticketPerOperator{}.Reserve(ctx, op, req, hop)
}

// A spend cap also outranks a candidate skipped for a missing ephemeral key:
// the cap is the payer's own limit, and the key gap says nothing about
// whether that node's ticket would have fit.
func TestDispatch_SpendCapOutranksNoEphemeral(t *testing.T) {
	ops := []Operator{retryOp(1, "OWNER_A"), retryOp(2, "OWNER_B")}
	c, _ := admitClient(t, ops, &capGuard{admitGuard{limit: ^uint64(0)}})
	c.reserveClient = noEphemeralFor{id: 2}
	if ze := turnErr(t, c, string(admitBody)); ze.Code != "spend_cap_exceeded" {
		t.Errorf("code %q, want spend_cap_exceeded", ze.Code)
	}
}

// Image routes are priced per image, so token rates must not feed Admit even
// when the model advertises them.
func TestDispatch_ImageRoutesSkipAdmit(t *testing.T) {
	op := pricedOp(1, 1, 2)
	mc := op.ModelCapacities["gpt-test"]
	mc.ImageRateMicroUSDC, mc.ImageEditRateMicroUSDC = 40_000, 40_000
	op.ModelCapacities["gpt-test"] = mc
	var edit bytes.Buffer
	mw := multipart.NewWriter(&edit)
	_ = mw.WriteField("model", "gpt-test")
	_ = mw.WriteField("prompt", "a cat")
	img, _ := mw.CreateFormFile("image", "cat.png")
	_, _ = img.Write([]byte("\x89PNG\r\n\x1a\n"))
	_ = mw.Close()
	for _, req := range []Request{
		{Endpoint: EndpointImages, Body: []byte(`{"model":"gpt-test","prompt":"a cat","n":1,"size":"1024x1024"}`)},
		{Endpoint: EndpointImageEdits, Body: edit.Bytes(), ContentType: mw.FormDataContentType()},
	} {
		guard := &admitGuard{limit: 0}
		c, rc := admitClient(t, []Operator{op}, guard)
		_, _ = runRequest(t, c, req)
		if len(guard.seen()) != 0 || rc.calls() == 0 {
			t.Errorf("%s: Admit calls %d, reserves %d: want no Admit, then a reserve", req.Endpoint, len(guard.seen()), rc.calls())
		}
	}
}
