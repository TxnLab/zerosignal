/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

// Generates / verifies proto/testdata/dispatch_verdict_vectors.json: what one
// candidate's failed reserve means for the dispatch loop (classifyReserveFailure)
// and whether a pass over the candidates earns another (nextResweep), which the
// TS SDK mirrors in sdk/src/routing/verdict.ts. Each failure case describes the
// error and its route as data, so both sides build their own typed error from
// it.
//
//	cd proto/go && go test ./zs -run TestDispatchVerdictVectors -update

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"
)

const dispatchVerdictVectorsPath = "../../testdata/dispatch_verdict_vectors.json"

type verdictVectorFile struct {
	Comment  string               `json:"comment"`
	Failures []verdictFailureCase `json:"failures"`
	Resweeps []verdictResweepCase `json:"resweeps"`
}

// verdictError describes a reserve failure. Kind is one of busy, size,
// payer_refusal, no_ephemeral, bad_reserve_envelope, http (a ReserveHTTPError;
// status 0 is a transport failure) and other (an error of no known type).
type verdictError struct {
	Kind           string `json:"kind"`
	Status         int    `json:"status,omitempty"`
	Code           string `json:"code,omitempty"`
	RetryAfterMs   int64  `json:"retry_after_ms,omitempty"`
	RelayHopMarked bool   `json:"relay_hop_marked,omitempty"`
}

type verdictRoute struct {
	Relayed        bool `json:"relayed"`
	RelayMarksHops bool `json:"relay_marks_hops"`
	CallerAborted  bool `json:"caller_aborted"`
}

type verdictWant struct {
	Outcome          string `json:"outcome"`
	Stop             bool   `json:"stop"`
	Strike           bool   `json:"strike"`
	Refused          bool   `json:"refused"`
	HardRefused      bool   `json:"hard_refused"`
	Busy             bool   `json:"busy"`
	BusyResweepable  bool   `json:"busy_resweepable"`
	Transient        bool   `json:"transient"`
	SizeRejected     bool   `json:"size_rejected"`
	EphemeralMissing bool   `json:"ephemeral_missing"`
	FreeBudgetSpent  bool   `json:"free_budget_spent"`
	HintMs           int64  `json:"hint_ms"`
	Attribution      string `json:"attribution"`
}

type verdictFailureCase struct {
	Name       string       `json:"name"`
	Error      verdictError `json:"error"`
	Route      verdictRoute `json:"route"`
	UsePrivacy bool         `json:"use_privacy"`
	Want       verdictWant  `json:"want"`
}

type verdictResweepInput struct {
	Transient         bool `json:"transient"`
	Refused           bool `json:"refused"`
	Busy              bool `json:"busy"`
	HardRefused       bool `json:"hard_refused"`
	SizeRejected      bool `json:"size_rejected"`
	AnyBusy           bool `json:"any_busy"`
	RelayUnavailable  bool `json:"relay_unavailable"`
	ToolFactorMissing bool `json:"tool_factor_missing"`
	EphemeralMissing  bool `json:"ephemeral_missing"`
	PriceRejected     bool `json:"price_rejected"`
	BusyBudgetLeft    bool `json:"busy_budget_left"`
}

type verdictResweepCase struct {
	Name  string              `json:"name"`
	Input verdictResweepInput `json:"input"`
	// Want is none, weather or busy.
	Want string `json:"want"`
}

func verdictErr(e verdictError) error {
	retryAfter := time.Duration(e.RetryAfterMs) * time.Millisecond
	switch e.Kind {
	case "busy":
		return &BusyError{Code: e.Code, RetryAfter: retryAfter}
	case "size":
		return &SizeError{Code: e.Code, Message: "too big"}
	case "payer_refusal":
		return &PayerRefusalError{Code: e.Code, Message: "spent", RetryAfter: retryAfter}
	case "no_ephemeral":
		return errNoEphemeral
	case "bad_reserve_envelope":
		return errBadReserveEnvelope
	case "http":
		re := &ReserveHTTPError{Status: e.Status, Code: e.Code, RetryAfter: retryAfter, RelayHopMarked: e.RelayHopMarked}
		if e.Status == 0 {
			re.Err = errors.New("connection refused")
		}
		return re
	default:
		return errors.New("something else")
	}
}

func runVerdictFailure(c verdictFailureCase) verdictFailureCase {
	f := classifyReserveFailure(verdictErr(c.Error), reserveRoute(c.Route), c.UsePrivacy)
	c.Want = verdictWant{
		Outcome:          f.Outcome,
		Stop:             f.Stop,
		Strike:           f.Strike,
		Refused:          f.Refused,
		HardRefused:      f.HardRefused,
		Busy:             f.Busy,
		BusyResweepable:  f.BusyResweepable,
		Transient:        f.Transient,
		SizeRejected:     f.SizeRejected,
		EphemeralMissing: f.EphemeralMissing,
		FreeBudgetSpent:  f.FreeBudgetSpent,
		HintMs:           f.Hint.Milliseconds(),
		Attribution:      string(f.Attribution),
	}
	return c
}

var resweepNames = map[resweepReason]string{resweepNone: "none", resweepWeather: "weather", resweepBusy: "busy"}

func verdictFailureInputs() []verdictFailureCase {
	direct := verdictRoute{}
	relay91 := verdictRoute{Relayed: true, RelayMarksHops: true}
	relayOld := verdictRoute{Relayed: true}
	http := func(status int, code string) verdictError {
		return verdictError{Kind: "http", Status: status, Code: code}
	}
	return []verdictFailureCase{
		{Name: "a resweepable 429", Error: verdictError{Kind: "busy", Code: "no_capacity", RetryAfterMs: 2000}, Route: direct},
		{Name: "a 429 re-asking would penalize", Error: verdictError{Kind: "busy", Code: "payer_slot_cap", RetryAfterMs: 2000}, Route: direct},
		{Name: "a 429 with no code", Error: verdictError{Kind: "busy"}, Route: direct},
		{Name: "a 429's long Retry-After is capped", Error: verdictError{Kind: "busy", Code: "no_capacity", RetryAfterMs: 3_600_000}, Route: direct},
		{Name: "a 429 never strikes, even relayed", Error: verdictError{Kind: "busy", Code: "no_capacity"}, Route: relay91, UsePrivacy: true},
		// Not busy, and its day-long Retry-After is no hint: the payer
		// computes the reset itself.
		{Name: "a spent free budget is its own refusal", Error: verdictError{Kind: "busy", Code: "free_budget_exhausted", RetryAfterMs: 3_600_000}, Route: direct},
		{Name: "a sizing refusal", Error: verdictError{Kind: "size", Code: "context_length_exceeded"}, Route: direct},
		{Name: "a payer-scoped refusal stops", Error: verdictError{Kind: "payer_refusal", Code: "free_quota_exhausted", RetryAfterMs: 3_600_000}, Route: direct},
		{Name: "no ephemeral to seal to", Error: verdictError{Kind: "no_ephemeral"}, Route: direct},
		{Name: "a bad_reserve_envelope the heal didn't fix", Error: verdictError{Kind: "bad_reserve_envelope"}, Route: direct},
		{Name: "an error of no known type", Error: verdictError{Kind: "other"}, Route: direct},
		{Name: "direct: a code-less 503 strikes", Error: http(503, ""), Route: direct},
		{Name: "direct: a transport failure strikes", Error: http(0, ""), Route: direct},
		{Name: "direct: a gateway's Retry-After is the hint", Error: verdictError{Kind: "http", Status: 503, RetryAfterMs: 20_000}, Route: direct},
		// The transient wait's own schedule bounds this hint, so it isn't capped
		// the way a busy node's is.
		{Name: "a transient Retry-After past the busy cap stays raw", Error: verdictError{Kind: "http", Status: 503, RetryAfterMs: 600_000}, Route: direct},
		// Privacy without a relay is not a case the Go loop produces (it skips the
		// candidate), but the strike rule reads usePrivacy, not the route.
		{Name: "privacy on, unrelayed: a code-less 503 strikes nobody", Error: http(503, ""), Route: direct, UsePrivacy: true},
		{Name: "relayed: an unmarked code-less 502 is the relay's", Error: http(502, ""), Route: relay91, UsePrivacy: true},
		{Name: "relayed: a marked code-less 502 is the target's", Error: verdictError{Kind: "http", Status: 502, RelayHopMarked: true}, Route: relay91, UsePrivacy: true},
		{Name: "relayed: a pre-9.1 relay's code-less 502 is nobody's", Error: http(502, ""), Route: relayOld, UsePrivacy: true},
		{Name: "relayed: a transport failure is the relay's", Error: http(0, ""), Route: relay91, UsePrivacy: true},
		{Name: "relayed: our own timeout blames nobody", Error: http(0, ""), Route: verdictRoute{Relayed: true, RelayMarksHops: true, CallerAborted: true}, UsePrivacy: true},
		{Name: "relayed: relay_upstream_unreachable is the target's", Error: http(502, "relay_upstream_unreachable"), Route: relay91, UsePrivacy: true},
		{Name: "a coded provider_unavailable is a refusal, no strike", Error: http(503, "provider_unavailable"), Route: direct},
		{Name: "a refusal's Retry-After is no hint", Error: verdictError{Kind: "http", Status: 503, Code: "provider_unavailable", RetryAfterMs: 20_000}, Route: direct},
		{Name: "invalid_payer_sig is a refusal, no strike", Error: http(401, "invalid_payer_sig"), Route: direct},
		{Name: "invalid_reserve is a refusal, no strike", Error: http(400, "invalid_reserve"), Route: direct},
		// The loop drops the credit and asks again once before it gets here.
		{Name: "a refused free credit is a refusal, no strike", Error: http(400, "free_credit_invalid"), Route: direct},
		{Name: "a spent free credit asked again is a refusal, no strike", Error: http(409, "free_credit_spent"), Route: direct},
		{Name: "commit_k_mismatch is a refusal, no strike", Error: http(502, "commit_k_mismatch"), Route: relay91, UsePrivacy: true},
	}
}

func verdictResweepInputs() []verdictResweepCase {
	return []verdictResweepCase{
		{Name: "nothing failed", Input: verdictResweepInput{}},
		{Name: "pure weather", Input: verdictResweepInput{Transient: true}},
		{Name: "weather and a refusal", Input: verdictResweepInput{Transient: true, Refused: true}},
		// Every producer sets Refused with HardRefused; this pins the term on its own.
		{Name: "weather and a hard refusal alone", Input: verdictResweepInput{Transient: true, HardRefused: true}},
		{Name: "weather and a size rejection", Input: verdictResweepInput{Transient: true, SizeRejected: true}},
		{Name: "weather and any 429", Input: verdictResweepInput{Transient: true, AnyBusy: true}},
		{Name: "weather and a relay gap", Input: verdictResweepInput{Transient: true, RelayUnavailable: true}},
		{Name: "weather and a missing tool factor", Input: verdictResweepInput{Transient: true, ToolFactorMissing: true}},
		{Name: "weather and a missing ephemeral", Input: verdictResweepInput{Transient: true, EphemeralMissing: true}},
		{Name: "weather and a price violation", Input: verdictResweepInput{Transient: true, PriceRejected: true}},
		{Name: "pure capacity", Input: verdictResweepInput{Busy: true, Refused: true, AnyBusy: true, BusyBudgetLeft: true}},
		{Name: "capacity with no budget left", Input: verdictResweepInput{Busy: true, Refused: true, AnyBusy: true}},
		{Name: "capacity and a hard refusal", Input: verdictResweepInput{Busy: true, Refused: true, AnyBusy: true, HardRefused: true, BusyBudgetLeft: true}},
		{Name: "capacity and a size rejection", Input: verdictResweepInput{Busy: true, Refused: true, AnyBusy: true, SizeRejected: true, BusyBudgetLeft: true}},
		{Name: "capacity and a relay gap", Input: verdictResweepInput{Busy: true, Refused: true, AnyBusy: true, RelayUnavailable: true, BusyBudgetLeft: true}},
		{Name: "capacity outranks a missing ephemeral", Input: verdictResweepInput{Busy: true, Refused: true, AnyBusy: true, EphemeralMissing: true, BusyBudgetLeft: true}},
		{Name: "capacity outranks a missing tool factor and a price violation", Input: verdictResweepInput{Busy: true, Refused: true, AnyBusy: true, ToolFactorMissing: true, PriceRejected: true, BusyBudgetLeft: true}},
		{Name: "a non-resweepable 429 alone", Input: verdictResweepInput{Refused: true, AnyBusy: true, BusyBudgetLeft: true}},
		{Name: "weather and capacity together re-sweep for capacity", Input: verdictResweepInput{Transient: true, Busy: true, Refused: true, AnyBusy: true, BusyBudgetLeft: true}},
	}
}

// The vectors give each error exactly one type, so they can't see the order the
// classifier tests in. Go's can matter: errors.As matches anywhere in a chain,
// and a chain can carry two of the types. The TS port matches one class per
// error, so this stays Go-only.
func TestClassifyReserveFailureOrder(t *testing.T) {
	busy := &BusyError{Code: "no_capacity"}
	transient503 := &ReserveHTTPError{Status: 503}
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"a wrapped 429 is still busy", fmt.Errorf("reserve: %w", busy), outcomeBusy},
		{"busy outranks a transient failure", errors.Join(transient503, busy), outcomeBusy},
		{"busy outranks a sizing refusal", errors.Join(&SizeError{Code: "context_length_exceeded"}, busy), outcomeBusy},
		{"size outranks a payer refusal", errors.Join(&PayerRefusalError{Code: "free_quota_exhausted"}, &SizeError{}), outcomeSize},
		{"a payer refusal outranks a missing ephemeral", errors.Join(errNoEphemeral, &PayerRefusalError{}), outcomePayerRefusal},
		{"a missing ephemeral outranks a transient failure", errors.Join(transient503, errNoEphemeral), outcomeNoEphemeral},
	}
	for _, c := range cases {
		if got := classifyReserveFailure(c.err, reserveRoute{}, false).Outcome; got != c.want {
			t.Errorf("%s: outcome %q, want %q", c.name, got, c.want)
		}
	}
}

func TestDispatchVerdictVectors(t *testing.T) {
	f := verdictVectorFile{
		Comment: "Generated by proto/go/zs TestDispatchVerdictVectors. Compare every field exactly.",
	}
	for _, c := range verdictFailureInputs() {
		f.Failures = append(f.Failures, runVerdictFailure(c))
	}
	for _, c := range verdictResweepInputs() {
		in := c.Input
		c.Want = resweepNames[nextResweep(sweepOutcome{
			Transient: in.Transient, Refused: in.Refused, Busy: in.Busy, HardRefused: in.HardRefused,
			SizeRejected: in.SizeRejected, AnyBusy: in.AnyBusy, RelayUnavailable: in.RelayUnavailable,
			ToolFactorMissing: in.ToolFactorMissing, EphemeralMissing: in.EphemeralMissing,
			PriceRejected: in.PriceRejected, BusyBudgetLeft: in.BusyBudgetLeft,
		})]
		f.Resweeps = append(f.Resweeps, c)
	}
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')

	if *updateVectors {
		if err := os.WriteFile(dispatchVerdictVectorsPath, out, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(dispatchVerdictVectorsPath)
	if err != nil {
		t.Fatalf("read vectors (regenerate with -update): %v", err)
	}
	if !bytes.Equal(want, out) {
		t.Fatalf("dispatch verdict differs from %s; if the change is intended, regenerate with -update and review the diff", dispatchVerdictVectorsPath)
	}
}
