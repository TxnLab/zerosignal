/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

// Generates / verifies proto/testdata/ack_settle_vectors.json: scripted runs of
// the payer's ack (ackSettle), which the TS SDK mirrors as ackSettle in
// sdk/src/ack.ts. Each scenario scripts the three ways onto chain (building
// the group's spec, submitting the node's group, the standalone ack) and
// records which were tried and what the ack reports.
//
//	cd proto/go && go test ./zs -run TestAckSettleVectors -update

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/TxnLab/zerosignal/go/escrow"
)

const ackSettleVectorsPath = "../../testdata/ack_settle_vectors.json"

// The scripted results: the payer pays nothing on the group, which pools its
// fee on the node's half, and pays its own standalone ack.
const (
	ackGroupTxID      = "GROUPTX"
	ackStandaloneTxID = "STANDALONETX"
	ackStandaloneFee  = 5_000
)

type ackSettleWant struct {
	// Calls names each step tried, in order: spec, group, standalone.
	Calls         []string `json:"calls"`
	TxID          string   `json:"txid"`
	FeeMicroalgos uint64   `json:"fee_microalgos"`
	GroupRejected bool     `json:"group_rejected"`
	// Result is ok, or which submit's error the ack returned: group or
	// standalone.
	Result string `json:"result"`
}

type ackSettleScenario struct {
	Name string `json:"name"`
	// Atomic: the node sent a settle group that decoded.
	Atomic bool `json:"atomic"`
	// Spec is ok or error.
	Spec string `json:"spec"`
	// Group is ok, rejected (the payer's checks refused it), rejected_wrapped
	// (the same, inside another error) or error (anything else).
	Group string `json:"group"`
	// Standalone is ok or error.
	Standalone string        `json:"standalone"`
	Want       ackSettleWant `json:"want"`
}

func ackSettleScenarios() []ackSettleScenario {
	return []ackSettleScenario{
		{Name: "no group: the payer acks standalone", Spec: "ok", Group: "ok", Standalone: "ok"},
		{Name: "no group: a failed standalone ack is returned", Spec: "ok", Group: "ok", Standalone: "error"},
		{Name: "a group that passes the checks settles atomically", Atomic: true, Spec: "ok", Group: "ok", Standalone: "ok"},
		{Name: "a rejected group falls back to standalone and reports the node", Atomic: true, Spec: "ok", Group: "rejected", Standalone: "ok"},
		{Name: "a rejection inside another error is still a rejection", Atomic: true, Spec: "ok", Group: "rejected_wrapped", Standalone: "ok"},
		{Name: "a rejected group still reports the node when standalone fails", Atomic: true, Spec: "ok", Group: "rejected", Standalone: "error"},
		{Name: "a group submit that fails otherwise is returned, never re-sent standalone", Atomic: true, Spec: "ok", Group: "error", Standalone: "ok"},
		{Name: "a spec that cannot be built falls back to standalone, blaming no node", Atomic: true, Spec: "error", Group: "ok", Standalone: "ok"},
		{Name: "a spec failure then a failed standalone ack is returned", Atomic: true, Spec: "error", Group: "ok", Standalone: "error"},
	}
}

func runAckSettleScenario(sc ackSettleScenario) ackSettleWant {
	w := ackSettleWant{Calls: []string{}}
	txid, fee, rejected, err := ackSettle(sc.Atomic, ackSettleDeps{
		spec: func() (escrow.SettleGroupSpec, error) {
			w.Calls = append(w.Calls, "spec")
			if sc.Spec == "error" {
				return escrow.SettleGroupSpec{}, errors.New("spec")
			}
			return escrow.SettleGroupSpec{}, nil
		},
		submitGroup: func(escrow.SettleGroupSpec) (escrow.CallResult, error) {
			w.Calls = append(w.Calls, "group")
			rejection := &escrow.SettleGroupRejectedError{Field: "payer.rekeyTo", Detail: "scripted"}
			switch sc.Group {
			case "rejected":
				return escrow.CallResult{}, rejection
			case "rejected_wrapped":
				return escrow.CallResult{}, fmt.Errorf("submit: %w", rejection)
			case "error":
				return escrow.CallResult{}, errGroupSubmit
			}
			return escrow.CallResult{TxID: ackGroupTxID}, nil
		},
		standalone: func() (escrow.CallResult, error) {
			w.Calls = append(w.Calls, "standalone")
			if sc.Standalone == "error" {
				return escrow.CallResult{}, errStandaloneSubmit
			}
			return escrow.CallResult{TxID: ackStandaloneTxID, PayerFeeMicroalgos: ackStandaloneFee}, nil
		},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	w.TxID, w.FeeMicroalgos, w.GroupRejected = txid, fee, rejected
	switch {
	case err == nil:
		w.Result = "ok"
	case errors.Is(err, errGroupSubmit):
		w.Result = "group"
	case errors.Is(err, errStandaloneSubmit):
		w.Result = "standalone"
	default:
		w.Result = "other"
	}
	return w
}

var (
	errGroupSubmit      = errors.New("group submit")
	errStandaloneSubmit = errors.New("standalone submit")
)

func TestAckSettleVectors(t *testing.T) {
	scenarios := ackSettleScenarios()
	for i := range scenarios {
		scenarios[i].Want = runAckSettleScenario(scenarios[i])
	}
	f := struct {
		Comment   string              `json:"comment"`
		Scenarios []ackSettleScenario `json:"scenarios"`
	}{
		Comment:   "Generated by proto/go/zs TestAckSettleVectors. Compare want exactly.",
		Scenarios: scenarios,
	}
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')

	if *updateVectors {
		if err := os.WriteFile(ackSettleVectorsPath, out, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(ackSettleVectorsPath)
	if err != nil {
		t.Fatalf("read vectors (regenerate with -update): %v", err)
	}
	if !bytes.Equal(want, out) {
		t.Fatalf("ack settle differs from %s; if the change is intended, regenerate with -update and review the diff", ackSettleVectorsPath)
	}
}
