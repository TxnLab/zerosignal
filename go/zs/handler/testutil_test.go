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

	"github.com/TxnLab/zerosignal/go/inject"
	hayai "github.com/TxnLab/zerosignal/go/zs"
	"github.com/TxnLab/zerosignal/go/zs/handler/transform"
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

// testCfg is the handler Config plus the operator list setupHayai built the
// static registry from, which tests edit and rebuild a registry from.
type testCfg struct {
	Config
	ResolvedOperators []hayai.Operator
}

// testConfig returns a minimal Config for handler-level tests. Direct, because
// most fake-node tests stand up one node and relaying needs a second; tests of
// the relay path set Privacy themselves. AllowPrivateOperators: tests forward to
// httptest fake nodes on 127.0.0.1, which the default-on SSRF dial guard would
// refuse.
func testConfig() *testCfg {
	return &testCfg{Config: Config{Privacy: hayai.PrivacyDirect, AllowPrivateOperators: true}}
}

// privacyMode maps the relay-on bool the routing tests are written in.
func privacyMode(relay bool) hayai.Privacy {
	if relay {
		return hayai.PrivacyRelayRequired
	}
	return hayai.PrivacyDirect
}

// testServer constructs a Server with silent logging and passthrough
// transforms wired to cfg. The SSRF dial guard is opted out (tests forward to
// 127.0.0.1 fake nodes) regardless of how the caller built cfg.
func testServer(cfg *testCfg, opts Options) *Server {
	cfg.AllowPrivateOperators = true
	return New(&cfg.Config, silentLogger(), transform.Passthrough{}, transform.Passthrough{}, opts)
}

// testServerWithTransforms is like testServer but lets the caller inject
// custom req/resp transforms.
func testServerWithTransforms(cfg *testCfg, reqTx transform.RequestTransformer, respTx transform.ResponseTransformer, opts Options) *Server {
	cfg.AllowPrivateOperators = true
	return New(&cfg.Config, silentLogger(), reqTx, respTx, opts)
}

// noSweepDelay is an Options.SweepDelay that never waits, so a test can run
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

func (e errRegistry) Operators(_ context.Context, _ string) ([]hayai.Operator, error) {
	return nil, e.err
}

func (e errRegistry) Resolve(_ context.Context, _, _ uint64) (hayai.Operator, error) {
	return hayai.Operator{}, e.err
}

func (e errRegistry) AllModels(_ context.Context) []string                     { return nil }
func (e errRegistry) AllBuiltinTools(_ context.Context) []hayai.BuiltinToolDef { return nil }
func (e errRegistry) AllModelDetails(_ context.Context) []inject.OperatorDetailsModel {
	return nil
}
func (e errRegistry) AllNodeVersions(_ context.Context) []string { return nil }
func (e errRegistry) AllOperators(_ context.Context) []hayai.Operator {
	return nil
}
func (e errRegistry) ReprobeEphemeral(_ context.Context, op hayai.Operator) (hayai.Operator, bool) {
	return op, false
}
func (e errRegistry) RecordModelDemand(_ string) {}

var (
	_ hayai.RegistryProvider = errRegistry{}
)
