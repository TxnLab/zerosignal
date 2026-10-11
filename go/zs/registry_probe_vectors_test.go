/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

// Generates / verifies proto/testdata/registry_probe_vectors.json: what one
// details probe's outcome writes onto the node it probed (applyProbeOutcome),
// and the reachability it leaves for the next cycle's relay pool. The TS SDK
// replays it against sdk/src/registry/probe.ts.
//
//	cd proto/go && go test ./zs -run TestRegistryProbeVectors -update

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/TxnLab/zerosignal/go/selection"
)

const registryProbeVectorsPath = "../../testdata/registry_probe_vectors.json"

// probeVectorState is the part of an Operator a probe outcome can touch. Times
// are Unix milliseconds, 0 for Go's zero time.
type probeVectorState struct {
	Reachable       bool     `json:"reachable"`
	Probed          bool     `json:"probed"`
	LastRefreshAtMs int64    `json:"last_refresh_at_ms"`
	ReachableAsOfMs int64    `json:"reachable_as_of_ms"`
	Models          []string `json:"models"`
	Ephemeral       bool     `json:"ephemeral"`
	TEE             bool     `json:"tee"`
}

type probeVectorWant struct {
	probeVectorState
	// RecordReachable is the reachability remembered for the node, or null
	// when the outcome leaves the remembered one alone.
	RecordReachable *bool `json:"record_reachable"`
}

type probeOutcomeCase struct {
	Name    string           `json:"name"`
	Outcome probeOutcome     `json:"outcome"`
	Prior   probeVectorState `json:"prior"`
	Want    probeVectorWant  `json:"want"`
}

const probeVectorNowMs int64 = 1_800_000_000_000

var probeVectorRecipient = func() age.Recipient {
	r, err := age.ParseX25519Recipient("age1rc8wp62cfvmldwhm49mdp5lg3gu6qkrs2whhactp0w9nqjk6wp7sl74d8s")
	if err != nil {
		panic(err)
	}
	return r
}()

func probeVectorTime(ms int64) time.Time {
	if ms == 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms)
}

func probeVectorMillis(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func probeVectorOperator(s probeVectorState) Operator {
	op := Operator{
		ID:            42,
		NodeID:        7,
		Reachable:     s.Reachable,
		Probed:        s.Probed,
		LastRefreshAt: probeVectorTime(s.LastRefreshAtMs),
		ReachableAsOf: probeVectorTime(s.ReachableAsOfMs),
		Models:        s.Models,
	}
	if s.Ephemeral {
		op.EphemeralRecipient = probeVectorRecipient
		op.EphemeralRecipientPubkey = "age1rc8wp62cfvmldwhm49mdp5lg3gu6qkrs2whhactp0w9nqjk6wp7sl74d8s"
		op.EphemeralExpiry = probeVectorNowMs/1000 + 600
		op.EphemeralIssuedAt = probeVectorNowMs/1000 - 600
	}
	if s.TEE {
		op.TEE = &TEEStatus{Mode: "dstack", VerifierID: "dstack-tdx", Verified: true}
	}
	return op
}

func probeVectorStateOf(op Operator) probeVectorState {
	models := op.Models
	if models == nil {
		models = []string{}
	}
	return probeVectorState{
		Reachable:       op.Reachable,
		Probed:          op.Probed,
		LastRefreshAtMs: probeVectorMillis(op.LastRefreshAt),
		ReachableAsOfMs: probeVectorMillis(op.ReachableAsOf),
		Models:          models,
		// Any one field left behind would carry a seal target, or the expiry
		// that gates one, across the outcome.
		Ephemeral: op.EphemeralRecipient != nil || op.EphemeralRecipientPubkey != "" ||
			op.EphemeralExpiry != 0 || op.EphemeralIssuedAt != 0,
		TEE: op.TEE != nil,
	}
}

func probeOutcomeCases() []probeOutcomeCase {
	priors := []struct {
		name  string
		state probeVectorState
	}{
		{"a node never probed", probeVectorState{Models: []string{}}},
		{"a node up last cycle", probeVectorState{
			Reachable: true, Probed: true,
			LastRefreshAtMs: probeVectorNowMs - 60_000, ReachableAsOfMs: probeVectorNowMs - 60_000,
			Models: []string{"m"}, Ephemeral: true, TEE: true,
		}},
		{"a node down last cycle", probeVectorState{
			Probed:          true,
			LastRefreshAtMs: probeVectorNowMs - 60_000, ReachableAsOfMs: probeVectorNowMs - 600_000,
			Models: []string{"m"}, Ephemeral: true,
		}},
		// The registry's shape for a node it did not probe: a fresh chain row
		// with last-known capabilities carried onto it.
		{"a carried node", probeVectorState{
			LastRefreshAtMs: probeVectorNowMs - 120_000, ReachableAsOfMs: probeVectorNowMs - 120_000,
			Models: []string{"m", "n"}, TEE: true,
		}},
	}
	outcomes := []probeOutcome{probeNoRelay, probeCancelled, probeHopFailed, probeTargetFailed, probeSucceeded}
	var out []probeOutcomeCase
	for _, o := range outcomes {
		for _, p := range priors {
			out = append(out, probeOutcomeCase{Name: fmt.Sprintf("%s from %s", o, p.name), Outcome: o, Prior: p.state})
		}
	}
	return out
}

func TestRegistryProbeVectors(t *testing.T) {
	cases := probeOutcomeCases()
	for i := range cases {
		op := probeVectorOperator(cases[i].Prior)
		reachable, record := applyProbeOutcome(&op, cases[i].Outcome, time.UnixMilli(probeVectorNowMs))
		cases[i].Want.probeVectorState = probeVectorStateOf(op)
		if record {
			cases[i].Want.RecordReachable = &reachable
		}
	}
	f := struct {
		Comment string             `json:"comment"`
		NowMs   int64              `json:"now_ms"`
		Cases   []probeOutcomeCase `json:"cases"`
	}{
		Comment: "Generated by proto/go/zs TestRegistryProbeVectors. Each case applies one details probe's outcome (no_relay | cancelled | hop_failed | target_failed | succeeded) at now_ms to a node in the prior state. Times are Unix ms, 0 for never. ephemeral is whether any ephemeral field is set, tee whether a TEE verdict is. want.record_reachable is the reachability remembered for the node, null when the remembered one is left alone. On success the ephemeral recipient and the TEE verdict are voided here; the probe's own advertisement sets them again afterwards.",
		NowMs:   probeVectorNowMs,
		Cases:   cases,
	}
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')

	if *updateVectors {
		if err := os.WriteFile(registryProbeVectorsPath, out, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(registryProbeVectorsPath)
	if err != nil {
		t.Fatalf("read vectors (regenerate with -update): %v", err)
	}
	if !bytes.Equal(want, out) {
		t.Fatalf("probe outcomes differ from %s; if the change is intended, regenerate with -update and review the diff", registryProbeVectorsPath)
	}
}

// classifyProbe's order is not in the vectors: the TS SDK sorts its own error
// classes, and the two error vocabularies share no values to compare.
func TestClassifyProbe_Order(t *testing.T) {
	hop := &RelayHopError{RelayID: 1, RelayNodeID: 1}
	cases := []struct {
		name   string
		err    error
		ctxErr error
		want   probeOutcome
	}{
		{"no error", nil, nil, probeSucceeded},
		{"no error from a probe cancelled after it landed", nil, context.Canceled, probeSucceeded},
		{"no relay wins over a cancelled context", selection.ErrNoRelay, context.Canceled, probeNoRelay},
		{"a cancelled context wins over a hop error", hop, context.DeadlineExceeded, probeCancelled},
		{"a cancelled context wins over a target error", errors.New("details endpoint returned 500"), context.Canceled, probeCancelled},
		{"a wrapped hop error", fmt.Errorf("probe: %w", hop), nil, probeHopFailed},
		{"a relay's claim the target is down", &RelayUpstreamUnreachableError{RelayID: 1}, nil, probeTargetFailed},
		{"a body the target got wrong", &DetailsBodyError{Err: errors.New("bad")}, nil, probeTargetFailed},
	}
	for _, c := range cases {
		if got := classifyProbe(c.err, c.ctxErr); got != c.want {
			t.Errorf("%s: classifyProbe = %s, want %s", c.name, got, c.want)
		}
	}
}
