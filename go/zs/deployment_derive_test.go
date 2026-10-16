/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/TxnLab/zerosignal/go/algod"
	"github.com/TxnLab/zerosignal/go/ticket"
)

// genesisAlgod answers SuggestedParams; any other call panics on the nil
// embedded interface, which these tests must not reach.
type genesisAlgod struct {
	algod.Client
	hash  []byte
	err   error
	calls int
}

func (g *genesisAlgod) SuggestedParams(context.Context) (types.SuggestedParams, error) {
	g.calls++
	return types.SuggestedParams{GenesisHash: g.hash}, g.err
}

func genesis7() []byte {
	h := make([]byte, 32)
	for i := range h {
		h[i] = 7
	}
	return h
}

func TestReadDeploymentID_HashesGenesisAndAppID(t *testing.T) {
	want, err := ticket.AlgorandDeploymentID(genesis7(), 42)
	if err != nil {
		t.Fatal(err)
	}
	got, err := readDeploymentID(context.Background(), &genesisAlgod{hash: genesis7()}, 42)
	if err != nil {
		t.Fatalf("readDeploymentID: %v", err)
	}
	if got != want {
		t.Fatalf("deployment = %s, want %s", got, want)
	}
	if _, err := readDeploymentID(context.Background(), &genesisAlgod{err: errors.New("down")}, 42); err == nil {
		t.Fatal("an algod failure must fail the read")
	}
}

// A host that builds its own source supplies no deployment; the chain read
// derives it, or every node's ephemeral would be checked on the legacy
// signature alone.
func TestFetchChain_DerivesDeploymentWhenUnset(t *testing.T) {
	g := &genesisAlgod{err: errors.New("down")}
	s := &ChainOperatorSource{
		Algod:       g,
		EscrowAppID: 42,
		readChain:   func(context.Context) ([]Operator, error) { return nil, nil },
	}
	if _, err := s.FetchChain(context.Background()); err != nil {
		t.Fatalf("FetchChain: %v", err)
	}
	if !s.deployment().IsZero() {
		t.Fatal("a failed genesis read must leave the deployment unknown")
	}

	// Retried on the next read, then kept.
	g.err, g.hash = nil, genesis7()
	for range 2 {
		if _, err := s.FetchChain(context.Background()); err != nil {
			t.Fatalf("FetchChain: %v", err)
		}
	}
	want, _ := ticket.AlgorandDeploymentID(genesis7(), 42)
	if got := s.deployment(); got != want {
		t.Fatalf("derived deployment = %s, want %s", got, want)
	}
	if g.calls != 2 {
		t.Fatalf("genesis reads = %d, want 2: one failed, one kept", g.calls)
	}
}

// With the SDK's own wallet algod is known to be up, so a failed genesis read
// fails New; with a host's wallet it warns and starts unbound.
func TestDeploymentOrFail(t *testing.T) {
	d, _ := ticket.AlgorandDeploymentID(genesis7(), 42)
	down := errors.New("down")
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))

	if got, err := deploymentOrFail(d, nil, true, log); err != nil || got != d {
		t.Fatalf("success: got %s, %v", got, err)
	}
	if _, err := deploymentOrFail(ticket.DeploymentID{}, down, true, log); !errors.Is(err, down) {
		t.Fatalf("built wallet: err = %v, want the read's error", err)
	}
	if logs.Len() != 0 {
		t.Fatalf("a failing New must not also warn: %s", logs.String())
	}
	got, err := deploymentOrFail(ticket.DeploymentID{}, down, false, log)
	if err != nil || !got.IsZero() {
		t.Fatalf("host wallet: got %s, %v; want zero and no error", got, err)
	}
	if !strings.Contains(logs.String(), "level=WARN") {
		t.Fatalf("host wallet: want a WARN, got %q", logs.String())
	}
}

// New hands the genesis-derived id to the reserve client it builds, so
// reserves to a 9.13 node are bound.
func TestNew_ReserveClientGetsTheDeployment(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/transactions/params" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"consensus-version": "v1",
			"fee":               0,
			"genesis-hash":      base64.StdEncoding.EncodeToString(genesis7()),
			"genesis-id":        "testnet-v1.0",
			"last-round":        1,
			"min-fee":           1000,
		})
	}))
	defer srv.Close()

	cfg := suppliedParts(t)
	cfg.Registry, cfg.ReserveClient = nil, nil
	cfg.Logger = discardLogger()
	cfg.Network.Algod = algod.Config{Endpoint: srv.URL}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	rc, ok := c.reserveClient.(*HTTPReserveClient)
	if !ok {
		t.Fatalf("reserve client %T, want the built *HTTPReserveClient", c.reserveClient)
	}
	want, _ := ticket.AlgorandDeploymentID(genesis7(), cfg.Network.EscrowAppID)
	if rc.Deployment != want {
		t.Fatalf("reserve client deployment = %s, want %s", rc.Deployment, want)
	}
}

// A supplied id wins and costs no read.
func TestFetchChain_SuppliedDeploymentSkipsRead(t *testing.T) {
	g := &genesisAlgod{hash: genesis7()}
	supplied, _ := ticket.AlgorandDeploymentID(genesis7(), 99)
	s := &ChainOperatorSource{
		Algod:       g,
		EscrowAppID: 42,
		Deployment:  supplied,
		readChain:   func(context.Context) ([]Operator, error) { return nil, nil },
	}
	if _, err := s.FetchChain(context.Background()); err != nil {
		t.Fatalf("FetchChain: %v", err)
	}
	if g.calls != 0 || s.deployment() != supplied {
		t.Fatalf("calls = %d, deployment = %s; want 0 and the supplied id", g.calls, s.deployment())
	}
}
