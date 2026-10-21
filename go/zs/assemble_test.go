/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/algod"
	"github.com/TxnLab/zerosignal/go/keystore"
	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/zs/tee"
)

// A keystore is a Signer once an address is chosen, and a Solana one a
// SolanaSigner.
var (
	_ Signer       = keystore.AccountSigner{}
	_ SolanaSigner = keystore.SolanaAccountSigner{}
)

// The SDK reads no proxy variables unless UseEnvProxy: http.DefaultTransport
// does, and both clients start from a clone of it.
func TestEnvProxyOnlyWithUseEnvProxy(t *testing.T) {
	for _, use := range []bool{false, true} {
		c := Config{UseEnvProxy: use}
		node := c.nodeHTTPClient(0, 0).Transport.(*http.Transport).Proxy != nil
		chain := c.algodTransport().Transport.Proxy != nil
		if node != use || chain != use {
			t.Errorf("UseEnvProxy %v: node client proxy %v, algod proxy %v", use, node, chain)
		}
	}
}

// running reports whether the refresh loop was started and not stopped.
func (p *DynamicRegistryProvider) running() bool {
	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()
	return p.started && !p.stopped
}

// The escrow config read must succeed before the payer holds any ALGO, so it
// is simulated from the network's fee sink; localnet has none and falls back
// to the payer.
func TestSimulateSender(t *testing.T) {
	for _, tc := range []struct {
		network string
		want    string
	}{
		{"testnet", algod.FeeSink("testnet")},
		{"mainnet", algod.FeeSink("mainnet")},
		{"localnet", "PAYER"},
		{"", "PAYER"},
	} {
		ac := algod.Config{Network: tc.network, Endpoint: "http://algod.invalid"}
		if err := ac.Resolve(); err != nil {
			t.Fatal(err)
		}
		if got := simulateSender(ac, "PAYER"); got != tc.want || got == "" {
			t.Errorf("network %q: sender %q, want %q", tc.network, got, tc.want)
		}
	}
}

// Every field here is a silent no-op when dropped: discovery still runs, and
// only the knob stops working.
func TestNewChainSource_MapsConfig(t *testing.T) {
	verifier := &tee.BundleVerifier{}
	cfg := Config{
		Signer:      fakeSigner{addr: "PAYER"},
		Privacy:     PrivacyRelayRequired,
		TEEVerifier: verifier,
		Discovery: Discovery{
			OperatorIDs:        []uint64{3, 5},
			DetailsTimeout:     7 * time.Second,
			DetailsConcurrency: 11,
			LatencyStateMax:    13,
		},
	}.withDefaults()
	dep := ticket.DeploymentID{9}
	src := newChainSource(cfg, 99, nil, dep)
	if src.EscrowAppID != 99 || src.ProxyPayerAddr != "PAYER" || !slices.Equal(src.OperatorIDs, []uint64{3, 5}) {
		t.Errorf("app %d payer %q ids %v", src.EscrowAppID, src.ProxyPayerAddr, src.OperatorIDs)
	}
	if src.Deployment != dep {
		t.Error("deployment dropped: the ephemeral check would fall back to the legacy signature")
	}
	if src.DetailsTimeout != 7*time.Second || src.DetailsConcurrency != 11 || src.LatencyStateMax != 13 {
		t.Errorf("timeout %v concurrency %d latency max %d", src.DetailsTimeout, src.DetailsConcurrency, src.LatencyStateMax)
	}
	if src.TEEVerifier != tee.Verifier(verifier) {
		t.Error("TEEVerifier dropped")
	}
	if !src.Privacy {
		t.Error("relay_required does not relay the discovery probes")
	}
	if src.Details == nil || src.Attestation == nil {
		t.Error("probe clients not built")
	}
	cfg.Privacy = PrivacyDirect
	if newChainSource(cfg, 99, nil, ticket.DeploymentID{}).Privacy {
		t.Error("direct relays the discovery probes")
	}
}

// Every value distinct, so a field dropped or threaded into the wrong slot
// fails.
func TestRegistryConfig_ThreadsEveryField(t *testing.T) {
	got := registryConfig(Config{
		AllowStaging: true,
		Discovery: Discovery{
			RefreshInterval: 11 * time.Second,
			RefreshTimeout:  12 * time.Second,
			MaxCacheAge:     13 * time.Second,
			MaxCarryAge:     14 * time.Second,
			ProbeBudget:     15,
			TargetTopK:      16,
			CatalogPath:     "/tmp/catalog.json",
		},
	})
	want := DynamicRegistryConfig{
		RefreshInterval: 11 * time.Second,
		RefreshTimeout:  12 * time.Second,
		MaxCacheAge:     13 * time.Second,
		MaxCarryAge:     14 * time.Second,
		ProbeBudget:     15,
		TargetTopK:      16,
		CatalogPath:     "/tmp/catalog.json",
		AllowStaging:    true,
	}
	if got != want {
		t.Fatalf("registryConfig =\n  %+v\nwant\n  %+v", got, want)
	}
	v := reflect.ValueOf(want)
	for i := range v.NumField() {
		if v.Field(i).IsZero() {
			t.Errorf("DynamicRegistryConfig.%s is not covered by this test", v.Type().Field(i).Name)
		}
	}
}

// The reserve and the discovery probes dial node-registered addresses, so a
// node that registers a loopback or LAN address must not reach the payer's
// own machine through them unless the payer allows it.
func TestBuiltClients_BlockPrivateTargetsUnlessAllowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	for _, allow := range []bool{false, true} {
		cfg := Config{Signer: fakeSigner{addr: "PAYER"}, AllowPrivateHosts: allow}.withDefaults()
		src := newChainSource(cfg, 1, nil, ticket.DeploymentID{})
		for name, hc := range map[string]*http.Client{
			"reserve":     newReserveClient(cfg, ticket.DeploymentID{}).HTTPClient,
			"details":     src.Details.HTTP,
			"attestation": src.Attestation.HTTP,
		} {
			resp, err := hc.Get(srv.URL)
			if err == nil {
				resp.Body.Close()
			}
			if reached := err == nil; reached != allow {
				t.Errorf("%s client, AllowPrivateHosts=%v: reached loopback = %v (%v)", name, allow, reached, err)
			}
		}
	}
}

// The reserve is signed as the payer, and each attempt is bounded.
func TestNewReserveClient_MapsConfig(t *testing.T) {
	signer := fakeSigner{addr: "PAYER"}
	dep := ticket.DeploymentID{9}
	rc := newReserveClient(Config{Signer: signer, ReserveTimeout: 3 * time.Second}, dep)
	if rc.Signer != signer {
		t.Error("reserve is not signed by the payer")
	}
	if rc.Deployment != dep {
		t.Error("deployment dropped: reserves would never ask for bound tickets")
	}
	if rc.HTTPClient == nil || rc.HTTPClient.Timeout != 3*time.Second {
		t.Errorf("reserve client %+v, want a 3s timeout", rc.HTTPClient)
	}
}

// probed is op as a discovery cycle that reached it returns it.
func probed(op Operator) Operator {
	op.Probed, op.Reachable = true, true
	return op
}

// bootConfig is a defaulted Config for bootRegistry.
func bootConfig(catalog string, allowStaging bool) Config {
	return Config{
		Discovery:    Discovery{CatalogPath: catalog, RefreshInterval: time.Hour},
		AllowStaging: allowStaging,
		Logger:       discardLogger(),
	}.withDefaults()
}

// The first discovery seeds the registry, and is saved for the next start.
func TestBootRegistry_SeedsFromTheFirstFetchAndSavesIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.json")
	src := &fakeSource{ops: []Operator{probed(retryOp(1, "OWNER_A"))}}
	reg, err := bootRegistry(context.Background(), bootConfig(path, false), src)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Stop()
	if got := reg.AllModels(context.Background()); !slices.Equal(got, []string{"gpt-test"}) {
		t.Errorf("models %v, want the fetched gpt-test", got)
	}
	saved, err := LoadCatalog(path)
	if err != nil || len(saved) != 1 || saved[0].ID != 1 {
		t.Errorf("saved catalog %v (err %v), want operator 1", saved, err)
	}
}

// A failed first fetch does not fail New: the saved catalog routes until the
// refresh loop recovers, but only within the carry window. A node past it
// keeps its identity, so it stays a relay, and serves nothing.
func TestBootRegistry_FailedFetchSeedsTheSavedCatalog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.json")
	op := retryOp(2, "OWNER_B")
	op.ReachableAsOf = time.Now()
	aged := retryOp(3, "OWNER_C")
	aged.BaseURL, aged.Models, aged.NodeVersion = "http://aged.example", []string{"old"}, "zs-node 1.0"
	aged.ReachableAsOf = time.Now().Add(-2 * DefaultMaxCarryAge)
	if err := SaveCatalog(path, []Operator{op, aged}); err != nil {
		t.Fatal(err)
	}
	src := &fakeSource{err: errors.New("algod down")}
	reg, err := bootRegistry(context.Background(), bootConfig(path, false), src)
	if err != nil {
		t.Fatalf("a failed fetch failed boot: %v", err)
	}
	defer reg.Stop()
	ops := reg.AllOperators(context.Background())
	if len(ops) != 2 || ops[0].ID != 2 || ops[1].ID != 3 {
		t.Fatalf("operators %v, want the saved operators 2 and 3", ops)
	}
	if got, _ := reg.Operators(context.Background(), "gpt-test"); len(got) != 1 || got[0].ID != 2 {
		t.Errorf("operators for gpt-test %v, want operator 2, inside the window", got)
	}
	if got, _ := reg.Operators(context.Background(), "old"); len(got) != 0 {
		t.Errorf("operators for old %v, want none: operator 3 aged out", got)
	}
	if a := ops[1]; a.BaseURL != "http://aged.example" || a.Models != nil || a.NodeVersion != "" || !a.ReachableAsOf.IsZero() {
		t.Errorf("aged operator %+v, want its identity alone", a)
	}
}

// A node the first probe did not reach keeps its saved capabilities, so a
// restart routes to it at once instead of after several refresh cycles; but
// only while they are younger than MaxCarryAge.
func TestBootRegistry_MergesTheSavedCatalogIntoTheFirstFetch(t *testing.T) {
	for _, tc := range []struct {
		name     string
		maxCarry time.Duration
		carried  bool
	}{
		{"default carry age", 0, true},
		{"configured carry age", time.Minute, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "catalog.json")
			saved := retryOp(2, "OWNER_B")
			saved.Models = []string{"saved-model"}
			saved.ReachableAsOf = time.Now().Add(-10 * time.Minute)
			if err := SaveCatalog(path, []Operator{saved}); err != nil {
				t.Fatal(err)
			}
			unprobed := retryOp(2, "OWNER_B")
			unprobed.Reachable, unprobed.Models = false, nil
			src := &fakeSource{ops: []Operator{probed(retryOp(1, "OWNER_A")), unprobed}}
			cfg := bootConfig(path, false)
			if tc.maxCarry != 0 {
				cfg.Discovery.MaxCarryAge = tc.maxCarry
			}
			reg, err := bootRegistry(context.Background(), cfg, src)
			if err != nil {
				t.Fatal(err)
			}
			defer reg.Stop()
			got := reg.AllModels(context.Background())
			if !slices.Contains(got, "gpt-test") || slices.Contains(got, "saved-model") != tc.carried {
				t.Errorf("models %v, want the fetched gpt-test, saved-model carried = %v", got, tc.carried)
			}
			// Dispatch reads Operators, which has no age gate of its own: the
			// carry age is enforced only by the merge.
			ops, err := reg.Operators(context.Background(), "saved-model")
			if err != nil {
				t.Fatal(err)
			}
			if (len(ops) > 0) != tc.carried {
				t.Errorf("Operators(saved-model) = %d ops, want carried = %v", len(ops), tc.carried)
			}
		})
	}
}

// The registry's staging gate is the Client's: the discovery aggregates and
// the per-request gate must agree on which nodes exist.
func TestBootRegistry_AllowStaging(t *testing.T) {
	for _, allow := range []bool{false, true} {
		src := &fakeSource{ops: []Operator{probed(stagingNodeOp(1, "staged-model", true))}}
		reg, err := bootRegistry(context.Background(), bootConfig("", allow), src)
		if err != nil {
			t.Fatal(err)
		}
		got := slices.Contains(reg.AllModels(context.Background()), "staged-model")
		reg.Stop()
		if got != allow {
			t.Errorf("AllowStaging=%v: staging model listed = %v", allow, got)
		}
	}
}

// A Client that builds its registry starts its refresh loop and backs every
// routing signal the caller left nil with the chain source; Close stops the
// loop. The chain is unreachable, which New survives once ctx ends the first
// fetch.
func TestNew_BuildsTheRegistryAndCloseStopsIt(t *testing.T) {
	cfg := suppliedParts(t)
	cfg.Registry = nil
	cfg.Logger = discardLogger()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("New with an unreachable chain: %v", err)
	}
	reg, ok := c.Registry().(*DynamicRegistryProvider)
	if !ok {
		t.Fatalf("registry %T, want the built *DynamicRegistryProvider", c.Registry())
	}
	st := c.Config().Stores
	src, ok := st.RelayReputation.(*ChainOperatorSource)
	if !ok || st.RelayLatency != RelayLatency(src) || st.TargetBackoff != TargetBackoff(src) || st.NodeExclusions != NodeExcluder(src) {
		t.Errorf("stores %+v, want each backed by the chain source", st)
	}
	if c.relayRep == nil || c.nodeExcluder == nil {
		t.Error("routing does not read the stores New filled")
	}
	if !reg.running() {
		t.Error("New did not start the refresh loop")
	}
	// ctx bounds construction only: the loop outlives it and runs until Close.
	cancel()
	reg.lifecycleMu.Lock()
	done := reg.done
	reg.lifecycleMu.Unlock()
	select {
	case <-done:
		t.Error("the refresh loop ended with New's context")
	case <-time.After(100 * time.Millisecond):
	}
	c.Close()
	if reg.running() {
		t.Error("Close did not stop the refresh loop")
	}
	c.Close()
}
