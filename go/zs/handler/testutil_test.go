/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/TxnLab/zerosignal/go/algod"
	"github.com/TxnLab/zerosignal/go/inject"
	"github.com/TxnLab/zerosignal/go/zs"
	"github.com/TxnLab/zerosignal/go/zs/handler/transform"
	"github.com/TxnLab/zerosignal/go/zs/tokenize"
)

func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// capturingLogger returns a logger that appends each record's text
// form to *buf. Used by receipt tests to assert which violation
// classification the dispatcher logged without having to reach into
// internal state.
func capturingLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, nil))
}

// policy is the part of zs.Config, plus the handler Config, that handler tests
// vary.
type policy struct {
	Network               string
	FundingURL            string
	Privacy               zs.Privacy
	AllowPrivacyOverride  bool
	Affinity              zs.AffinityPolicy
	AllowStaging          bool
	AllowPrivateOperators bool
	TEERequiredModels     []string
}

// deps are the Client parts a handler test supplies. A nil network part gets
// a stub, so the Client never builds one against a chain.
type deps struct {
	RegistryProvider zs.RegistryProvider
	ReserveClient    zs.ReserveClient
	Wallet           zs.WalletOpener
	ToolAffinity     *zs.IDAffinity
	ResponseAffinity *zs.IDAffinity
	Tokenizer        *tokenize.Registry
	RelayReputation  zs.RelayReputation
	RelayLatency     zs.RelayLatency
	TargetBackoff    zs.TargetBackoff
	NodeExcluder     zs.NodeExcluder
	SpendGuard       spendGuard
	Journal          zs.TicketJournal
	TrackCryptoTimes bool
	DebugLogBodies   bool
	RetryBudget      time.Duration
	SweepDelay       func(sweep int) time.Duration
	Remedies         zs.Remedies
}

// spendGuard is a zs.SpendGuard without Admit, which no handler test needs.
type spendGuard interface {
	Reserve(ticketID string, maxPriceMicroUSDC uint64) error
	Settle(ticketID string, spentMicroUSDC uint64)
	Release(ticketID string)
}

type admitAll struct{ spendGuard }

func (admitAll) Admit(uint64) error { return nil }

// testPayer is the Signer every test Client is built with. Nothing signs with
// it: the Wallet and ReserveClient are fakes.
type testPayer struct{}

func (testPayer) Address() string                                           { return "PAYER" }
func (testPayer) HasAccount(a string) bool                                  { return a == "PAYER" }
func (testPayer) SignBytes(context.Context, string, []byte) ([]byte, error) { return nil, nil }
func (testPayer) SignWithAccount(context.Context, types.Transaction, string) (string, []byte, error) {
	return "", nil, nil
}

// newServer builds the Client p and d describe, and the Server over it.
func newServer(p *policy, log *slog.Logger, reqTx transform.RequestTransformer, respTx transform.ResponseTransformer, d deps) *Server {
	network := p.Network
	if network == "" {
		network = "localnet"
	}
	if d.RegistryProvider == nil {
		d.RegistryProvider = errRegistry{}
	}
	if d.ReserveClient == nil {
		d.ReserveClient = &refusingReserveClient{}
	}
	if d.Wallet == nil {
		d.Wallet = &fakeWallet{}
	}
	var spend zs.SpendGuard
	if d.SpendGuard != nil {
		spend = admitAll{d.SpendGuard}
	}
	c, err := zs.New(context.Background(), zs.Config{
		Signer:               testPayer{},
		Network:              zs.Network{Algod: algod.Config{Network: network}, EscrowAppID: 1},
		Privacy:              p.Privacy,
		AllowPrivacyOverride: p.AllowPrivacyOverride,
		RequireTEEModels:     p.TEERequiredModels,
		Affinity:             zs.Affinity{Policy: p.Affinity},
		AllowStaging:         p.AllowStaging,
		AllowPrivateHosts:    p.AllowPrivateOperators,
		RetryBudget:          d.RetryBudget,
		SweepDelay:           d.SweepDelay,
		Stores: zs.Stores{
			RelayReputation:  d.RelayReputation,
			RelayLatency:     d.RelayLatency,
			TargetBackoff:    d.TargetBackoff,
			NodeExclusions:   d.NodeExcluder,
			ToolAffinity:     d.ToolAffinity,
			ResponseAffinity: d.ResponseAffinity,
			Journal:          d.Journal,
		},
		SpendGuard:     spend,
		Remedies:       d.Remedies,
		Registry:       d.RegistryProvider,
		ReserveClient:  d.ReserveClient,
		Wallet:         d.Wallet,
		Tokenizer:      d.Tokenizer,
		DebugLogBodies: d.DebugLogBodies,
		Logger:         log,
	})
	if err != nil {
		panic("newServer: " + err.Error())
	}
	return New(c, &Config{FundingURL: p.FundingURL}, log, reqTx, respTx, Options{TrackCryptoTimes: d.TrackCryptoTimes})
}

// testCfg is the test policy plus the operator list setup built the
// static registry from, which tests edit and rebuild a registry from.
type testCfg struct {
	policy
	ResolvedOperators []zs.Operator
}

// testConfig returns a minimal policy for handler-level tests. Direct, because
// most fake-node tests stand up one node and relaying needs a second; tests of
// the relay path set Privacy themselves. AllowPrivateOperators: tests forward to
// httptest fake nodes on 127.0.0.1, which the default-on SSRF dial guard would
// refuse.
func testConfig() *testCfg {
	return &testCfg{policy: policy{Privacy: zs.PrivacyDirect, AllowPrivateOperators: true}}
}

// privacyMode maps the relay-on bool the routing tests are written in.
func privacyMode(relay bool) zs.Privacy {
	if relay {
		return zs.PrivacyRelayRequired
	}
	return zs.PrivacyDirect
}

// testServer constructs a Server with silent logging and passthrough
// transforms wired to cfg. The SSRF dial guard is opted out (tests forward to
// 127.0.0.1 fake nodes) regardless of how the caller built cfg.
func testServer(cfg *testCfg, opts deps) *Server {
	cfg.AllowPrivateOperators = true
	return newServer(&cfg.policy, silentLogger(), transform.Passthrough{}, transform.Passthrough{}, opts)
}

// testServerWithTransforms is like testServer but lets the caller inject
// custom req/resp transforms.
func testServerWithTransforms(cfg *testCfg, reqTx transform.RequestTransformer, respTx transform.ResponseTransformer, opts deps) *Server {
	cfg.AllowPrivateOperators = true
	return newServer(&cfg.policy, silentLogger(), reqTx, respTx, opts)
}

// noSweepDelay is a deps.SweepDelay that never waits, so a test can run
// several retry or busy sweeps without sleeping through the real schedule.
func noSweepDelay(int) time.Duration { return 0 }

func mustNewIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id
}

// errRegistry always fails. Used to pin the error path where the
// registry can't be queried at all.
type errRegistry struct{ err error }

func (e errRegistry) Operators(_ context.Context, _ string) ([]zs.Operator, error) {
	return nil, e.err
}

func (e errRegistry) Resolve(_ context.Context, _, _ uint64) (zs.Operator, error) {
	return zs.Operator{}, e.err
}

func (e errRegistry) AllModels(_ context.Context) []string                  { return nil }
func (e errRegistry) AllBuiltinTools(_ context.Context) []zs.BuiltinToolDef { return nil }
func (e errRegistry) AllModelDetails(_ context.Context) []inject.OperatorDetailsModel {
	return nil
}
func (e errRegistry) AllNodeVersions(_ context.Context) []string { return nil }
func (e errRegistry) AllOperators(_ context.Context) []zs.Operator {
	return nil
}
func (e errRegistry) ReprobeEphemeral(_ context.Context, op zs.Operator) (zs.Operator, bool) {
	return op, false
}
func (e errRegistry) RecordModelDemand(_ string) {}

var (
	_ zs.RegistryProvider = errRegistry{}
)
