/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"

	"github.com/TxnLab/zerosignal/go/algod"
	"github.com/TxnLab/zerosignal/go/escrow"
)

func TestDiagnose_RefusesAnAddressItCantRead(t *testing.T) {
	_, err := Diagnose(context.Background(), Config{Network: Testnet()}, "not-an-address")
	if e, ok := err.(*Error); !ok || e.Code != "invalid_config" {
		t.Fatalf("err = %v, want invalid_config", err)
	}
}

// The doctor reads Algorand only, and says so rather than blaming a signer
// the caller never passed. A SolanaSigner left on an Algorand Config is one
// of the signers it ignores.
func TestDiagnose_RefusesSolanaAndIgnoresItsSigner(t *testing.T) {
	_, err := Diagnose(context.Background(), Config{Network: SolanaDevnet()}, testPayerAddr)
	if e, ok := err.(*Error); !ok || e.Code != "invalid_config" || !strings.Contains(e.Message, "Algorand rail only") {
		t.Fatalf("err = %v, want the Algorand-only refusal", err)
	}
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	cfg := Config{SolanaSigner: newTestSolanaSigner(), Network: Network{Algod: algod.Config{Endpoint: srv.URL}, EscrowAppID: 1}}
	if _, err := Diagnose(context.Background(), cfg, testPayerAddr); err != nil {
		t.Fatalf("Diagnose with a stray SolanaSigner: %v", err)
	}
}

// With algod down every check that needs it is skipped rather than failed,
// so the report names the one cause.
func TestDiagnose_UnreachableAlgod(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	cfg := Config{Network: Network{Algod: algod.Config{Endpoint: srv.URL}, EscrowAppID: 1}}
	rep, err := Diagnose(context.Background(), cfg, testPayerAddr)
	if err != nil {
		t.Fatalf("Diagnose: %v", err)
	}
	if !rep.Failed || rep.Address != testPayerAddr {
		t.Fatalf("report = %+v, want a failed report for %s", rep, testPayerAddr)
	}
	ids := make([]string, len(rep.Checks))
	for i, c := range rep.Checks {
		ids[i] = c.ID
		want := DoctorSkip
		if i == 0 {
			want = DoctorFail
		}
		if c.Status != want {
			t.Errorf("%s = %s (%s), want %s", c.ID, c.Status, c.Message, want)
		}
	}
	if got := strings.Join(ids, ","); got != "algod,escrow,algo,usdc_opt_in,usdc_balance,prepaid_pool,operators" {
		t.Errorf("checks = %s", got)
	}
}

// An endpoint override that keeps the preset's app id is a warning New logs,
// which the report carries.
func TestDiagnose_CarriesConfigWarnings(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	cfg := Config{Network: Network{Algod: algod.Config{Network: "testnet", Endpoint: srv.URL}}}
	rep, err := Diagnose(context.Background(), cfg, testPayerAddr)
	if err != nil {
		t.Fatalf("Diagnose: %v", err)
	}
	if len(rep.Warnings) != 1 || !strings.Contains(rep.Warnings[0], "escrow app id") {
		t.Errorf("warnings = %q, want the endpoint-override warning", rep.Warnings)
	}
}

type fakeDoctorChain struct {
	statusErr, escrowErr, accountErr, poolErr, nodesErr error
	acct                                                models.Account
	dep                                                 escrow.PayerDeposit
	ops                                                 []Operator
	calls                                               []string
}

func (f *fakeDoctorChain) status(context.Context) (uint64, uint64, error) {
	f.calls = append(f.calls, "status")
	return 42, 1_000, f.statusErr
}

func (f *fakeDoctorChain) escrowConfig(context.Context) (uint64, uint64, uint64, error) {
	f.calls = append(f.calls, "escrow")
	return 115_000, 777, 22_500, f.escrowErr
}

func (f *fakeDoctorChain) account(context.Context) (models.Account, error) {
	f.calls = append(f.calls, "account")
	return f.acct, f.accountErr
}

func (f *fakeDoctorChain) payerDeposit(context.Context) (escrow.PayerDeposit, error) {
	f.calls = append(f.calls, "deposit")
	return f.dep, f.poolErr
}

func (f *fakeDoctorChain) nodes(context.Context) ([]Operator, error) { return f.ops, f.nodesErr }

func optedInAccount(appID uint64) models.Account {
	return models.Account{
		Amount:         5_000_000,
		MinBalance:     400_000,
		Assets:         []models.AssetHolding{{AssetId: 1, Amount: 9}, {AssetId: 777, Amount: 2_500_000}},
		AppsLocalState: []models.ApplicationLocalState{{Id: appID + 1}, {Id: appID}},
	}
}

func TestGatherDoctorReadings_MapsEachRead(t *testing.T) {
	const appID = 99
	spend := uint64(6_000_000)
	f := &fakeDoctorChain{
		acct: optedInAccount(appID),
		dep:  escrow.PayerDeposit{AlgoBalance: 345_000, OpenTickets: 1},
		ops: []Operator{
			{OwnerAddr: "A", Reachable: true, ProtoVersion: "9.11", Staging: true, SignerSpendableMicroAlgos: &spend},
			{OwnerAddr: "B"},
		},
	}
	r := gatherDoctorReadings(context.Background(), f, DoctorReadings{EscrowAppID: appID})
	want := DoctorReadings{
		EscrowAppID: appID, LastRound: 42, MinFee: 1_000,
		TicketMbr: 115_000, UsdcAssetID: 777, QuotaDue: 22_500,
		Amount: 5_000_000, MinBalance: 400_000, UsdcOptedIn: true, UsdcBalance: 2_500_000, PoolOptedIn: true,
		AlgoBalance: 345_000, OpenTickets: 1,
		Nodes: []DoctorNode{
			{Owner: "A", Reachable: true, ProtoVersion: "9.11", Staging: true, SignerSpendable: &spend},
			{Owner: "B"},
		},
	}
	if !reflect.DeepEqual(r, want) {
		t.Errorf("readings =\n  %+v\nwant\n  %+v", r, want)
	}
}

func TestGatherDoctorReadings_ReadsWhatItCan(t *testing.T) {
	const appID = 99
	tests := []struct {
		name      string
		chain     *fakeDoctorChain
		wantCalls string
		check     func(*testing.T, DoctorReadings)
	}{
		{
			name:      "algod down reads nothing else",
			chain:     &fakeDoctorChain{statusErr: errors.New("refused")},
			wantCalls: "status",
			check: func(t *testing.T, r DoctorReadings) {
				if r.AlgodErr != "refused" || r.Nodes != nil {
					t.Errorf("readings = %+v", r)
				}
			},
		},
		{
			name:      "a payer not opted in has no pool to read",
			chain:     &fakeDoctorChain{acct: models.Account{Amount: 1}},
			wantCalls: "status,escrow,account",
		},
		{
			name:      "no pool read without the escrow, and no USDC to match",
			chain:     &fakeDoctorChain{escrowErr: errors.New("no app"), acct: optedInAccount(appID)},
			wantCalls: "status,escrow,account",
			check: func(t *testing.T, r DoctorReadings) {
				if r.EscrowErr != "no app" || r.TicketMbr != 0 || r.UsdcAssetID != 0 || r.UsdcOptedIn || !r.PoolOptedIn {
					t.Errorf("readings = %+v", r)
				}
			},
		},
		{
			name:      "a failed pool read keeps no balance",
			chain:     &fakeDoctorChain{acct: optedInAccount(appID), dep: escrow.PayerDeposit{AlgoBalance: 5}, poolErr: errors.New("simulate")},
			wantCalls: "status,escrow,account,deposit",
			check: func(t *testing.T, r DoctorReadings) {
				if r.PoolErr != "simulate" || r.AlgoBalance != 0 {
					t.Errorf("readings = %+v", r)
				}
			},
		},
		{
			name:      "an empty fleet is not a failed read",
			chain:     &fakeDoctorChain{nodesErr: fmt.Errorf("%w for escrow app %d", errNoOperators, appID)},
			wantCalls: "status,escrow,account",
			check: func(t *testing.T, r DoctorReadings) {
				if r.OperatorsErr != "" || len(r.Nodes) != 0 {
					t.Errorf("readings = %+v", r)
				}
			},
		},
		{
			name:      "a failed fleet read is",
			chain:     &fakeDoctorChain{nodesErr: errors.New("boxes: 503")},
			wantCalls: "status,escrow,account",
			check: func(t *testing.T, r DoctorReadings) {
				if r.OperatorsErr != "boxes: 503" {
					t.Errorf("readings = %+v", r)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := gatherDoctorReadings(context.Background(), tc.chain, DoctorReadings{EscrowAppID: appID})
			if got := strings.Join(tc.chain.calls, ","); got != tc.wantCalls {
				t.Errorf("calls = %s, want %s", got, tc.wantCalls)
			}
			if tc.check != nil {
				tc.check(t, r)
			}
		})
	}
}

// The doctor tells an empty fleet from a failed read by this sentinel, so the
// real chain read must carry it.
func TestReadChainNodes_EmptyFleetIsErrNoOperators(t *testing.T) {
	s := &ChainOperatorSource{EscrowAppID: chainVectorApp, Algod: boxListAlgod(t, map[string][]byte{})}
	if _, err := s.readChainNodes(context.Background()); !errors.Is(err, errNoOperators) {
		t.Fatalf("err = %v, want errNoOperators", err)
	}
}

// doctorBase maps the Config onto what decides which nodes a request could
// reach.
func TestDoctorBase(t *testing.T) {
	for _, tc := range []struct {
		cfg           Config
		relayRequired bool
		allowStaging  bool
		slots         uint64
	}{
		{Config{}, true, false, DefaultDepositSlots},
		{Config{Privacy: PrivacyRelayRequired, ConcurrentSlots: 3}, true, false, 3},
		{Config{Privacy: PrivacyDirect, AllowStaging: true}, false, true, DefaultDepositSlots},
	} {
		r := doctorBase(tc.cfg.withDefaults(), algod.Config{ResolvedNetwork: "testnet"}, 7, testPayerAddr)
		want := DoctorReadings{
			Network: "testnet", Address: testPayerAddr, Slots: tc.slots, EscrowAppID: 7,
			RelayRequired: tc.relayRequired, AllowStaging: tc.allowStaging,
		}
		if !reflect.DeepEqual(r, want) {
			t.Errorf("doctorBase(%+v) =\n  %+v\nwant\n  %+v", tc.cfg.Privacy, r, want)
		}
	}
}

func TestMicros(t *testing.T) {
	for v, want := range map[uint64]string{0: "0", 1: "0.000001", 115_000: "0.115", 1_000_000: "1", 12_345_678: "12.345678"} {
		if got := micros(v); got != want {
			t.Errorf("micros(%d) = %q, want %q", v, got, want)
		}
	}
}
