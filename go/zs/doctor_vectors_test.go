/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

// Generates / verifies proto/testdata/doctor_vectors.json: the doctor's
// verdicts over a set of readings (DoctorChecks). The TS SDK mirrors it as
// doctorChecks in sdk/src/doctor.ts.
//
//	cd proto/go && go test ./zs -run TestDoctorVectors -update

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/TxnLab/zerosignal/go/selection"
	"github.com/TxnLab/zerosignal/go/wire"
)

const doctorVectorsPath = "../../testdata/doctor_vectors.json"

type doctorCase struct {
	Name     string         `json:"name"`
	Readings DoctorReadings `json:"readings"`
	Checks   []DoctorCheck  `json:"checks"`
}

func TestDoctorVectors(t *testing.T) {
	var addr types.Address
	for i := range addr {
		addr[i] = byte(i + 1)
	}
	const mbr = 115_000
	usable := DoctorNode{Reachable: true, ProtoVersion: wire.ProtoVersion, SignerSpendable: new(selection.MinSignerSpendableMicroAlgos)}
	base := func() DoctorReadings {
		return DoctorReadings{
			Network: "testnet", Address: addr.String(), Slots: 10, RelayRequired: true,
			LastRound: 51_234_567, MinFee: 1_000,
			EscrowAppID: 765860477, TicketMbr: mbr, UsdcAssetID: 10458941,
			Amount: 5_000_000, MinBalance: 471_000, UsdcOptedIn: true, UsdcBalance: 2_500_000, PoolOptedIn: true,
			AlgoBalance: 10 * mbr, OpenTickets: 2,
			Nodes: []DoctorNode{usable, usable, {Reachable: false, ProtoVersion: wire.ProtoVersion}},
		}
	}
	type variant struct {
		name string
		edit func(*DoctorReadings)
	}
	variants := []variant{
		{"healthy", func(*DoctorReadings) {}},
		{"algod unreachable", func(r *DoctorReadings) { r.AlgodErr = "dial tcp: connection refused" }},
		{"algod unreachable on a private chain", func(r *DoctorReadings) {
			r.Network = ""
			r.AlgodErr = "dial tcp: connection refused"
		}},
		{"escrow unreadable", func(r *DoctorReadings) {
			r.EscrowErr = "escrow: get application 765860477: not found"
			r.TicketMbr, r.UsdcAssetID = 0, 0
		}},
		{"escrow without a ticket MBR", func(r *DoctorReadings) { r.TicketMbr = 0 }},
		{"account unreadable", func(r *DoctorReadings) {
			r.AccountErr = "HTTP 500"
			r.Amount, r.MinBalance, r.UsdcOptedIn, r.UsdcBalance, r.PoolOptedIn = 0, 0, false, 0, false
			r.AlgoBalance, r.OpenTickets = 0, 0
		}},
		{"fresh account", func(r *DoctorReadings) {
			r.Amount, r.MinBalance, r.UsdcOptedIn, r.UsdcBalance, r.PoolOptedIn = 0, 100_000, false, 0, false
			r.AlgoBalance, r.OpenTickets = 0, 0
		}},
		{"no USDC opt-in", func(r *DoctorReadings) { r.UsdcOptedIn, r.UsdcBalance = false, 0 }},
		{"no USDC", func(r *DoctorReadings) { r.UsdcBalance = 0 }},
		{"sub-unit balances", func(r *DoctorReadings) {
			r.Amount, r.UsdcBalance = 471_001, 1
		}},
		{"pool unreadable", func(r *DoctorReadings) {
			r.PoolErr = "escrow: simulate payerDeposit: timeout"
			r.AlgoBalance, r.OpenTickets = 0, 0
		}},
		{"pool not opted in, first deposit affordable", func(r *DoctorReadings) {
			r.PoolOptedIn, r.AlgoBalance, r.OpenTickets = false, 0, 0
			r.MinBalance = 200_000
		}},
		{"pool not opted in, first deposit unaffordable", func(r *DoctorReadings) {
			r.PoolOptedIn, r.AlgoBalance, r.OpenTickets = false, 0, 0
			r.Amount, r.MinBalance = 300_000, 200_000
		}},
		{"opted-in empty pool, unaffordable", func(r *DoctorReadings) {
			r.AlgoBalance, r.OpenTickets = 0, 0
			r.Amount = r.MinBalance + 50_000
		}},
		{"pool short, no ALGO for another slot", func(r *DoctorReadings) {
			r.AlgoBalance, r.OpenTickets = 2*mbr, 2
			r.Amount = r.MinBalance + 50_000
		}},
		{"pool short, top-up affordable", func(r *DoctorReadings) { r.AlgoBalance, r.OpenTickets = 3*mbr, 0 }},
		{"pool full, quota term due", func(r *DoctorReadings) { r.QuotaDue = 22_500 }},
		{"pool full, short only of the quota box", func(r *DoctorReadings) {
			r.QuotaDue = 22_500
			r.Amount = r.MinBalance + 5_000
		}},
		{"every ticket the pool backs in use", func(r *DoctorReadings) { r.OpenTickets = 10 }},
		{"more tickets in use than the pool backs", func(r *DoctorReadings) { r.OpenTickets = 12 }},
		{"every backed ticket in use, top-up affordable", func(r *DoctorReadings) {
			r.AlgoBalance, r.OpenTickets = 3*mbr, 3
		}},
		{"operators unreadable", func(r *DoctorReadings) {
			r.OperatorsErr = "escrow: list boxes: HTTP 503"
			r.Nodes = nil
		}},
		{"no nodes", func(r *DoctorReadings) { r.Nodes = nil }},
		{"no usable node", func(r *DoctorReadings) {
			r.Nodes = []DoctorNode{
				{Reachable: false, ProtoVersion: wire.ProtoVersion},
				{Reachable: true, ProtoVersion: "1.0"},
				{Reachable: true, ProtoVersion: ""},
				{Reachable: true, ProtoVersion: "not-a-version"},
				{Reachable: true, ProtoVersion: wire.ProtoVersion, Staging: true},
				{Reachable: true, ProtoVersion: wire.ProtoVersion, SignerSpendable: new(selection.MinSignerSpendableMicroAlgos - 1)},
			}
		}},
		{"only staging", func(r *DoctorReadings) {
			r.Nodes = []DoctorNode{{Reachable: true, ProtoVersion: wire.ProtoVersion, Staging: true}}
		}},
		{"only staging, staging allowed", func(r *DoctorReadings) {
			r.AllowStaging = true
			r.Nodes = []DoctorNode{{Reachable: true, ProtoVersion: wire.ProtoVersion, Staging: true}}
		}},
		{"one operator under relay privacy", func(r *DoctorReadings) {
			r.Nodes = []DoctorNode{
				{Owner: "OWNER-A", Reachable: false, ProtoVersion: wire.ProtoVersion},
				{Owner: "OWNER-A", Reachable: false, ProtoVersion: wire.ProtoVersion},
			}
		}},
		{"one operator, direct", func(r *DoctorReadings) {
			r.RelayRequired = false
			r.Nodes = []DoctorNode{
				{Owner: "OWNER-A", Reachable: false, ProtoVersion: wire.ProtoVersion},
				{Owner: "OWNER-A", Reachable: true, ProtoVersion: wire.ProtoVersion},
			}
		}},
		{"every node usable", func(r *DoctorReadings) {
			r.Nodes = []DoctorNode{usable, {Reachable: true, ProtoVersion: wire.ProtoVersion}}
		}},
		{"a later reason doesn't count an earlier one twice", func(r *DoctorReadings) {
			r.Nodes = []DoctorNode{
				usable,
				{Reachable: false, ProtoVersion: "1.0", Staging: true, SignerSpendable: new(uint64(0))},
				{Reachable: true, ProtoVersion: "1.0", Staging: true, SignerSpendable: new(uint64(0))},
				{Reachable: true, ProtoVersion: wire.ProtoVersion, Staging: true, SignerSpendable: new(uint64(0))},
			}
		}},
	}

	cases := make([]doctorCase, len(variants))
	for i, v := range variants {
		r := base()
		v.edit(&r)
		// A node with no owner given gets one of its own, so relay privacy
		// has a relay of another owner for it; a case about owners names them.
		for j := range r.Nodes {
			if r.Nodes[j].Owner == "" {
				r.Nodes[j].Owner = fmt.Sprintf("OWNER-%d", j)
			}
		}
		cases[i] = doctorCase{Name: v.name, Readings: r, Checks: DoctorChecks(r)}
	}
	f := struct {
		Comment      string       `json:"comment"`
		ProtoVersion string       `json:"protoVersion"`
		Cases        []doctorCase `json:"cases"`
	}{
		Comment:      "Generated by proto/go/zs TestDoctorVectors. The doctor's checks (DoctorChecks) over the readings Diagnose gathers: each check's id, status and message, in order. Quantities are decimal strings. protoVersion is the build's own, against which nodes are judged compatible.",
		ProtoVersion: wire.ProtoVersion,
		Cases:        cases,
	}
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')

	if *updateVectors {
		if err := os.WriteFile(doctorVectorsPath, out, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(doctorVectorsPath)
	if err != nil {
		t.Fatalf("read vectors (regenerate with -update): %v", err)
	}
	if !bytes.Equal(want, out) {
		t.Fatal("doctor_vectors.json is stale; regenerate with -update")
	}
}
