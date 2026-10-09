/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

// Generates / verifies proto/testdata/reserve_retry_vectors.json: scripted runs
// of the reserve leg's transient retry (retryReserve), which the TS SDK mirrors
// as reserveWithTransientRetry in sdk/src/reserve-retry.ts. Each scenario fixes
// the dependencies both sides inject: a fake clock that a wait advances, a
// rotation that takes the first relay in the pool not yet excluded, and a
// script of reserve outcomes (the last repeats). The vectors record every call,
// every relay charged, every event and the final result.
//
//	cd proto/go && go test ./zs -run TestReserveRetryVectors -update

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/selection"
)

const reserveRetryVectorsPath = "../../testdata/reserve_retry_vectors.json"

// retryOutcome is one scripted reserve result. Kind is ok, http (a
// ReserveHTTPError; status 0 is a transport failure, aborted our own
// deadline), bad_reserve_envelope, no_ephemeral or other.
type retryOutcome struct {
	Kind         string `json:"kind"`
	Status       int    `json:"status,omitempty"`
	Code         string `json:"code,omitempty"`
	Marked       bool   `json:"marked,omitempty"`
	Aborted      bool   `json:"aborted,omitempty"`
	RetryAfterMs int64  `json:"retry_after_ms,omitempty"`
}

type retryRelay struct {
	ID           uint64 `json:"id"`
	Node         uint64 `json:"node"`
	ProtoVersion string `json:"proto_version"`
}

// Relays are named "operator/node" throughout the want, so a rotation keyed
// on the operator alone shows.
type retryCall struct {
	Relay    *string `json:"relay"`
	Reprobed bool    `json:"reprobed"`
}

type retryEvent struct {
	Type        string  `json:"type"`
	Relay       *string `json:"relay,omitempty"`
	Attempt     int     `json:"attempt,omitempty"`
	Status      int     `json:"status,omitempty"`
	Code        string  `json:"code,omitempty"`
	Attribution string  `json:"attribution,omitempty"`
	WaitMs      int64   `json:"wait_ms,omitempty"`
	Reason      string  `json:"reason,omitempty"`
}

type retryWant struct {
	Calls         []retryCall  `json:"calls"`
	RelayFailures []string     `json:"relay_failures"`
	Events        []retryEvent `json:"events"`
	// Result is "ok", or the final error as "<kind>[ <status>[ <code>]]".
	Result   string  `json:"result"`
	FinalHop *string `json:"final_hop"`
	// FinalReprobed: the attempt returned carries the re-probed candidate,
	// which is the one the paid forward must seal to.
	FinalReprobed bool  `json:"final_reprobed"`
	ElapsedMs     int64 `json:"elapsed_ms"`
}

type retryScenario struct {
	Name       string `json:"name"`
	UsePrivacy bool   `json:"use_privacy"`
	// Relays is the pool in rotation order; the first carries the first
	// attempt when relayed.
	Relays    []retryRelay   `json:"relays"`
	BudgetMs  int64          `json:"budget_ms"`
	AttemptMs int64          `json:"attempt_ms"`
	Script    []retryOutcome `json:"script"`
	// Reprobe: whether a stale-ephemeral re-probe finds a fresh key.
	Reprobe bool `json:"reprobe"`
	// AbortSleep: the caller is gone by the first wait.
	AbortSleep bool      `json:"abort_sleep"`
	Want       retryWant `json:"want"`
}

const (
	marking    = "9.1"
	preMarking = "9.0"
)

func retryOK() retryOutcome { return retryOutcome{Kind: "ok"} }
func retryStatus(s int) retryOutcome {
	return retryOutcome{Kind: "http", Status: s}
}
func retryCoded(s int, code string) retryOutcome {
	return retryOutcome{Kind: "http", Status: s, Code: code}
}
func retryRelays(version string, ids ...uint64) []retryRelay {
	out := make([]retryRelay, len(ids))
	for i, id := range ids {
		out[i] = retryRelay{ID: id, Node: 1, ProtoVersion: version}
	}
	return out
}

func retryScenarios() []retryScenario {
	const budget = 60_000
	return []retryScenario{
		{Name: "a marking relay's unmarked 502 is its own, charged at once", UsePrivacy: true,
			Relays: retryRelays(marking, 2, 3), BudgetMs: budget, Script: []retryOutcome{retryStatus(502), retryOK()}},
		{Name: "a pre-marking relay's 502 is settled by the rotation differential", UsePrivacy: true,
			Relays: retryRelays(preMarking, 2, 3), BudgetMs: budget, Script: []retryOutcome{retryStatus(502), retryOK()}},
		{Name: "the differential charges only the most recent held relay", UsePrivacy: true,
			Relays: retryRelays(preMarking, 2, 3, 4), BudgetMs: budget, Script: []retryOutcome{retryStatus(502), retryStatus(503), retryOK()}},
		{Name: "every relay failing charges nobody", UsePrivacy: true,
			Relays: retryRelays(preMarking, 2, 3, 4), BudgetMs: budget, Script: []retryOutcome{retryStatus(502)}},
		{Name: "a transport failure is the relay's at any version", UsePrivacy: true,
			Relays: retryRelays(preMarking, 2, 3), BudgetMs: budget, Script: []retryOutcome{retryStatus(0), retryOK()}},
		{Name: "our own deadline on a transport failure is held, then settled", UsePrivacy: true,
			Relays: retryRelays(marking, 2, 3), BudgetMs: budget,
			Script: []retryOutcome{{Kind: "http", Status: 0, Aborted: true}, retryOK()}},
		{Name: "a marked 502 is the target's and charges no relay", UsePrivacy: true,
			Relays: retryRelays(marking, 2, 3), BudgetMs: budget,
			Script: []retryOutcome{{Kind: "http", Status: 502, Marked: true}, retryOK()}},
		{Name: "an unmarked gateway timeout is held, then settled", UsePrivacy: true,
			Relays: retryRelays(marking, 2, 3), BudgetMs: budget, Script: []retryOutcome{retryStatus(504), retryOK()}},
		{Name: "relay_busy is the relay's", UsePrivacy: true,
			Relays: retryRelays(preMarking, 2, 3), BudgetMs: budget, Script: []retryOutcome{retryCoded(503, "relay_busy"), retryOK()}},
		{Name: "relay_upstream_unreachable charges no relay here", UsePrivacy: true,
			Relays: retryRelays(marking, 2, 3), BudgetMs: budget,
			Script: []retryOutcome{retryCoded(502, "relay_upstream_unreachable"), retryOK()}},
		{Name: "direct mode retries in place and charges nothing", UsePrivacy: false,
			BudgetMs: budget, Script: []retryOutcome{retryStatus(502), retryOK()}},
		{Name: "a coded refusal is not retried", UsePrivacy: true,
			Relays: retryRelays(marking, 2, 3), BudgetMs: budget, Script: []retryOutcome{retryCoded(400, "invalid_request")}},
		{Name: "an error of no known type is not retried", UsePrivacy: true,
			Relays: retryRelays(marking, 2, 3), BudgetMs: budget, Script: []retryOutcome{{Kind: "other"}}},
		{Name: "a 429 is not this loop's to retry", UsePrivacy: true,
			Relays: retryRelays(marking, 2, 3), BudgetMs: budget, Script: []retryOutcome{retryCoded(429, "no_capacity")}},
		{Name: "attempts stop at the inner budget", UsePrivacy: false,
			BudgetMs: budget, Script: []retryOutcome{retryStatus(503)}},
		{Name: "a wait that would pass the deadline stops the retries", UsePrivacy: false,
			BudgetMs: 400, Script: []retryOutcome{retryStatus(503), retryOK()}},
		{Name: "time spent in attempts counts against the deadline", UsePrivacy: false,
			BudgetMs: budget, AttemptMs: 29_000, Script: []retryOutcome{retryStatus(503), retryStatus(503), retryOK()}},
		{Name: "a longer Retry-After wins over the schedule", UsePrivacy: false,
			BudgetMs: budget, Script: []retryOutcome{{Kind: "http", Status: 503, RetryAfterMs: 2_000}, retryOK()}},
		{Name: "a Retry-After past the deadline stops the retries", UsePrivacy: false,
			BudgetMs: budget, Script: []retryOutcome{{Kind: "http", Status: 503, RetryAfterMs: 90_000}, retryOK()}},
		{Name: "a caller gone during the wait ends it", UsePrivacy: true, AbortSleep: true,
			Relays: retryRelays(marking, 2, 3), BudgetMs: budget, Script: []retryOutcome{retryStatus(502), retryOK()}},
		{Name: "no relay left to rotate to stops rather than going direct", UsePrivacy: true,
			Relays: retryRelays(preMarking, 2), BudgetMs: budget, Script: []retryOutcome{retryStatus(502), retryOK()}},
		{Name: "a Retry-After holds for its own wait only", UsePrivacy: false,
			BudgetMs: budget, Script: []retryOutcome{{Kind: "http", Status: 503, RetryAfterMs: 2_000}, retryStatus(503), retryOK()}},
		{Name: "two nodes of one relay operator are separate relays", UsePrivacy: true,
			Relays:   []retryRelay{{ID: 2, Node: 1, ProtoVersion: marking}, {ID: 2, Node: 2, ProtoVersion: marking}},
			BudgetMs: budget, Script: []retryOutcome{retryStatus(502), retryOK()}},
		{Name: "a stale envelope re-probes and resends once", UsePrivacy: true, Reprobe: true,
			Relays: retryRelays(marking, 2, 3), BudgetMs: budget, AttemptMs: 100,
			Script: []retryOutcome{{Kind: "bad_reserve_envelope"}, retryOK()}},
		{Name: "the re-probe runs once per candidate, across attempts", UsePrivacy: true, Reprobe: true,
			Relays: retryRelays(marking, 2, 3), BudgetMs: budget,
			Script: []retryOutcome{{Kind: "no_ephemeral"}, retryStatus(502), {Kind: "no_ephemeral"}, retryOK()}},
		{Name: "a missing ephemeral re-probes and resends once", UsePrivacy: false, Reprobe: true,
			BudgetMs: budget, Script: []retryOutcome{{Kind: "no_ephemeral"}, retryOK()}},
		{Name: "a re-probe that finds nothing surfaces the refusal", UsePrivacy: true, Reprobe: false,
			Relays: retryRelays(marking, 2, 3), BudgetMs: budget,
			Script: []retryOutcome{{Kind: "bad_reserve_envelope"}, retryOK()}},
		{Name: "the re-probe runs once per candidate", UsePrivacy: true, Reprobe: true,
			Relays: retryRelays(marking, 2, 3), BudgetMs: budget,
			Script: []retryOutcome{{Kind: "no_ephemeral"}, {Kind: "no_ephemeral"}, retryOK()}},
		{Name: "a re-probed candidate keeps rotating on weather", UsePrivacy: true, Reprobe: true,
			Relays: retryRelays(marking, 2, 3), BudgetMs: budget,
			Script: []retryOutcome{{Kind: "bad_reserve_envelope"}, retryStatus(502), retryOK()}},
	}
}

func (o retryOutcome) err() error {
	switch o.Kind {
	case "ok":
		return nil
	case "http":
		re := &ReserveHTTPError{
			Status: o.Status, Code: o.Code, RelayHopMarked: o.Marked,
			RetryAfter: time.Duration(o.RetryAfterMs) * time.Millisecond,
		}
		if o.Aborted {
			re.Err = context.DeadlineExceeded
		}
		return re
	case "bad_reserve_envelope":
		return errBadReserveEnvelope
	case "no_ephemeral":
		return errNoEphemeral
	default:
		return errors.New("other")
	}
}

func describeRetryResult(err error) string {
	switch {
	case err == nil:
		return "ok"
	case IsBadReserveEnvelope(err):
		return "bad_reserve_envelope"
	case IsNoEphemeral(err):
		return "no_ephemeral"
	}
	if re, ok := AsReserveHTTP(err); ok {
		if re.Code != "" {
			return fmt.Sprintf("http %d %s", re.Status, re.Code)
		}
		return fmt.Sprintf("http %d", re.Status)
	}
	return "other"
}

func runRetryScenario(sc retryScenario) retryWant {
	const reprobedURL = "http://reprobed.example"
	target := Operator{ID: 1, NodeID: 1, BaseURL: "http://op.example"}
	hopFor := func(r retryRelay) *RelayHop {
		return &RelayHop{TargetID: 1, TargetNodeID: 1, RelayID: r.ID, RelayNodeID: r.Node, RelayProtoVersion: r.ProtoVersion}
	}
	var hop *RelayHop
	if sc.UsePrivacy && len(sc.Relays) > 0 {
		hop = hopFor(sc.Relays[0])
	}
	refID := func(r *NodeRef) *string {
		if r == nil {
			return nil
		}
		s := fmt.Sprintf("%d/%d", r.Op, r.Node)
		return &s
	}
	idOf := func(h *RelayHop) *string {
		if h == nil {
			return nil
		}
		ref := h.RelayRef()
		return refID(&ref)
	}

	now := time.Unix(1_700_000_000, 0)
	w := retryWant{Calls: []retryCall{}, RelayFailures: []string{}, Events: []retryEvent{}}
	calls := 0
	got := retryReserve(context.Background(), target, hop, sc.UsePrivacy, now.Add(time.Duration(sc.BudgetMs)*time.Millisecond), retryReserveDeps{
		attempt: func(op Operator, hop *RelayHop) (*ReservedTicket, error) {
			w.Calls = append(w.Calls, retryCall{Relay: idOf(hop), Reprobed: op.BaseURL == reprobedURL})
			o := sc.Script[min(calls, len(sc.Script)-1)]
			calls++
			now = now.Add(time.Duration(sc.AttemptMs) * time.Millisecond)
			if err := o.err(); err != nil {
				return nil, err
			}
			return &ReservedTicket{}, nil
		},
		nextHop: func(_ Operator, excluded map[NodeRef]bool) (*RelayHop, error) {
			for _, r := range sc.Relays {
				if h := hopFor(r); !excluded[h.RelayRef()] {
					return h, nil
				}
			}
			return nil, selection.ErrNoRelay
		},
		reprobe: func(op Operator) (Operator, bool) {
			if !sc.Reprobe {
				return op, false
			}
			op.BaseURL = reprobedURL
			return op, true
		},
		recordRelayFailure: func(h *RelayHop) { w.RelayFailures = append(w.RelayFailures, *idOf(h)) },
		note: func(e Event) {
			switch e := e.(type) {
			case ReserveStarted:
				w.Events = append(w.Events, retryEvent{Type: "reserve.started", Relay: refID(e.Relay), Attempt: e.Attempt})
			case ReserveRetrying:
				w.Events = append(w.Events, retryEvent{
					Type: "reserve.retrying", Status: e.Status, Code: e.Code,
					Attribution: string(e.Attribution), WaitMs: e.Wait.Milliseconds(), Attempt: e.Attempt,
				})
			case RelayHopChanged:
				w.Events = append(w.Events, retryEvent{Type: "relay.hop", Relay: refID(e.Relay), Reason: string(e.Reason)})
			default:
				panic(fmt.Sprintf("unexpected event %T", e))
			}
		},
		now: func() time.Time { return now },
		sleep: func(_ context.Context, d time.Duration) bool {
			if sc.AbortSleep {
				return false
			}
			now = now.Add(d)
			return true
		},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	w.Result = describeRetryResult(got.Err)
	if got.Err == nil && got.Ticket == nil {
		w.Result = "no ticket"
	}
	w.FinalHop = idOf(got.Hop)
	w.FinalReprobed = got.Op.BaseURL == reprobedURL
	w.ElapsedMs = got.Elapsed.Milliseconds()
	return w
}

func TestReserveRetryVectors(t *testing.T) {
	scenarios := retryScenarios()
	for i := range scenarios {
		scenarios[i].Want = runRetryScenario(scenarios[i])
	}
	f := struct {
		Comment   string          `json:"comment"`
		Scenarios []retryScenario `json:"scenarios"`
	}{
		Comment:   "Generated by proto/go/zs TestReserveRetryVectors. Compare want exactly.",
		Scenarios: scenarios,
	}
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')

	if *updateVectors {
		if err := os.WriteFile(reserveRetryVectorsPath, out, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(reserveRetryVectorsPath)
	if err != nil {
		t.Fatalf("read vectors (regenerate with -update): %v", err)
	}
	if !bytes.Equal(want, out) {
		t.Fatalf("reserve retry differs from %s; if the change is intended, regenerate with -update and review the diff", reserveRetryVectorsPath)
	}
}
