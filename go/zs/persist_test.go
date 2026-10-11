/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"bytes"
	"crypto/ed25519"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/wire"

	"filippo.io/age"
)

func TestSaveLoadCatalog_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.json")
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("gen identity: %v", err)
	}
	reachAt := time.Now().Add(-3 * time.Minute).Truncate(time.Second)
	key := ed25519.PublicKey(bytes.Repeat([]byte{7}, ed25519.PublicKeySize))

	op := Operator{
		ID: 3, NodeID: 2, NFDAppID: 99,
		OwnerAddr: "OWNER", SigningAddr: "SIGN",
		TicketSigningKey: key,
		BaseURL:          "http://node:9090", Staging: true,
		Models:             []string{"m1", "m2"},
		ModelCapacities:    map[string]ModelCapacity{"m1": {ContextWindow: 8000, InputUSDPer1M: 1.5}},
		BuiltinTools:       []BuiltinToolDef{{Type: "zs_web_search"}},
		MaxToolIters:       5,
		NodeVersion:        "abc",
		ProtoVersion:       "3.0",
		ReachableAsOf:      reachAt,
		Metrics:            OperatorMetrics{LatencyEwmaMs: 42, TokensPerSecEwma: 100, TicketsSettled: 7},
		MinChargeMicroUSDC: 1620,
		// Fields that MUST NOT survive persistence:
		Reachable:                true,
		Probed:                   true,
		EphemeralRecipient:       id.Recipient(),
		EphemeralRecipientPubkey: id.Recipient().String(),
		EphemeralExpiry:          time.Now().Add(time.Hour).Unix(),
		LastRefreshAt:            time.Now(),
		TEE:                      &TEEStatus{Verified: true},
	}

	if err := SaveCatalog(path, []Operator{op}); err != nil {
		t.Fatalf("SaveCatalog: %v", err)
	}
	got, err := LoadCatalog(path)
	if err != nil {
		t.Fatalf("LoadCatalog: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("loaded %d operators, want 1", len(got))
	}
	g := got[0]

	// Identity + capabilities preserved.
	if g.ID != 3 || g.NodeID != 2 || g.NFDAppID != 99 || g.OwnerAddr != "OWNER" ||
		g.SigningAddr != "SIGN" || g.BaseURL != "http://node:9090" || !g.Staging {
		t.Fatalf("identity not preserved: %+v", g)
	}
	if !reflect.DeepEqual(g.Models, []string{"m1", "m2"}) {
		t.Fatalf("Models = %v", g.Models)
	}
	if !reflect.DeepEqual(g.ModelCapacities, op.ModelCapacities) {
		t.Fatalf("ModelCapacities = %+v", g.ModelCapacities)
	}
	if len(g.BuiltinTools) != 1 || g.BuiltinTools[0].Type != "zs_web_search" {
		t.Fatalf("BuiltinTools = %v", g.BuiltinTools)
	}
	if g.MaxToolIters != 5 || g.NodeVersion != "abc" || g.ProtoVersion != "3.0" {
		t.Fatalf("meta not preserved: %+v", g)
	}
	if !g.ReachableAsOf.Equal(reachAt) {
		t.Fatalf("ReachableAsOf = %v, want %v", g.ReachableAsOf, reachAt)
	}
	if g.Metrics.LatencyEwmaMs != 42 || g.Metrics.TokensPerSecEwma != 100 || g.Metrics.TicketsSettled != 7 {
		t.Fatalf("Metrics = %+v", g.Metrics)
	}
	if !bytes.Equal(g.TicketSigningKey, key) {
		t.Fatalf("TicketSigningKey not preserved")
	}
	if g.MinChargeMicroUSDC != 1620 {
		t.Fatalf("MinChargeMicroUSDC = %d", g.MinChargeMicroUSDC)
	}

	// Forward-secret / re-verified / this-cycle fields must NOT survive.
	if g.EphemeralRecipient != nil {
		t.Fatal("ephemeral recipient must not be persisted (forward secrecy)")
	}
	if g.EphemeralRecipientPubkey != "" || g.EphemeralExpiry != 0 {
		t.Fatal("ephemeral pubkey/expiry must not be persisted")
	}
	if g.Reachable || g.Probed {
		t.Fatal("Reachable/Probed are this-cycle transients; must not be persisted")
	}
	if g.TEE != nil {
		t.Fatal("TEE verdict must not be persisted (re-verified on next probe)")
	}
	if !g.LastRefreshAt.IsZero() {
		t.Fatal("LastRefreshAt must not be persisted")
	}
}

// TestPersist_SkipsUnchangedWrite: persist MkdirAll-creates the catalog dir and
// writes once, then skips the disk write when the next snapshot marshals
// identically, and writes again once it changes.
func TestPersist_SkipsUnchangedWrite(t *testing.T) {
	// A nested dir the provider must create itself, exercising the MkdirAll path.
	path := filepath.Join(t.TempDir(), "state", "catalog.json")
	p := &DynamicRegistryProvider{catalogPath: path, log: slog.Default()}
	ops := []Operator{{ID: 1, NodeID: 1, Models: []string{"m"}}}

	p.persist(ops)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("first persist should write the file (dir created): %v", err)
	}

	// Same snapshot again: delete the file, persist, and confirm it is NOT
	// recreated — the dedup skipped the write entirely.
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	p.persist(ops)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("identical snapshot must skip the write; file was recreated (stat err=%v)", err)
	}

	// A changed snapshot writes again.
	p.persist([]Operator{{ID: 2, NodeID: 2}})
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("changed snapshot should write: %v", err)
	}
}

// The signer balance moves on every settle. Were it persisted, every refresh
// would rewrite the catalog (defeating the skip above) to store a number no
// load path reads.
func TestCatalog_DoesNotPersistSignerBalance(t *testing.T) {
	base := Operator{ID: 1, NodeID: 1, SigningAddr: "S", Models: []string{"m"}}
	a, b := uint64(1), uint64(9_000_000)
	withA, withB := base, base
	withA.SignerSpendableMicroAlgos = &a
	withB.SignerSpendableMicroAlgos = &b

	plain, err := marshalCatalog([]Operator{base})
	if err != nil {
		t.Fatalf("marshalCatalog: %v", err)
	}
	for _, op := range []Operator{withA, withB} {
		got, err := marshalCatalog([]Operator{op})
		if err != nil {
			t.Fatalf("marshalCatalog: %v", err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("catalog bytes change with the signer balance:\n%s\nvs\n%s", got, plain)
		}
	}
}

func TestLoadCatalog_MissingFileIsNotError(t *testing.T) {
	got, err := LoadCatalog(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err != nil || got != nil {
		t.Fatalf("missing catalog: got (%v, %v), want (nil, nil)", got, err)
	}
}

func TestLoadCatalog_VersionMismatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.json")
	if err := os.WriteFile(path, []byte(`{"version":999,"operators":[]}`), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := LoadCatalog(path); err == nil {
		t.Fatal("want an error on catalog format version mismatch")
	}
}

func TestMergeCatalog(t *testing.T) {
	base := []Operator{
		{ID: 1, ReachableAsOf: time.Now().Add(-1 * time.Minute), Models: []string{"m1"}, MaxToolIters: 4}, // recent
		{ID: 2, ReachableAsOf: time.Now().Add(-3 * time.Hour), Models: []string{"m2"}},                    // aged out
		{ID: 3, ReachableAsOf: time.Now().Add(-1 * time.Minute), Models: []string{"m3"}},                  // recent
	}
	fresh := []Operator{
		{ID: 1}, // not probed → inherit from base
		{ID: 2}, // not probed, base aged out → stays empty
		{ID: 3, Reachable: true, Models: []string{"m3-new"}}, // probed-good → fresh wins
		{ID: 4}, // not in base → stays empty
	}

	byID := map[uint64]Operator{}
	for _, o := range MergeCatalog(base, fresh, DefaultMaxCarryAge) {
		byID[o.ID] = o
	}

	if !reflect.DeepEqual(byID[1].Models, []string{"m1"}) || byID[1].MaxToolIters != 4 {
		t.Fatalf("node 1 should inherit last-known caps from base: %+v", byID[1])
	}
	if byID[2].Models != nil {
		t.Fatalf("node 2 base aged out past the window; must not be carried: %v", byID[2].Models)
	}
	if !reflect.DeepEqual(byID[3].Models, []string{"m3-new"}) {
		t.Fatalf("node 3 probed-good this fetch; fresh must win: %v", byID[3].Models)
	}
	if byID[4].Models != nil {
		t.Fatalf("node 4 not in base; stays empty: %v", byID[4].Models)
	}
}

// TestPersistedProtoVersionFloorsMinor pins the fail-toward-v1 rule for a
// version read off disk.
//
// The seed snapshot is served immediately, before any probe, so a persisted
// version really does drive reserve sizing. Trusting its MINOR would let a
// proxy restart size the input bound with v2 against an operator that has since
// rolled back to 9.1 — the node measures the same body with v1 and rejects it
// after escrow.open, with no failover and no recovery until the next refresh.
func TestPersistedProtoVersionFloorsMinor(t *testing.T) {
	for _, tc := range []struct{ persisted, want string }{
		{"9.2", "9.0"}, // the case that matters: a minor-gated capability is not assumed
		{"9.1", "9.0"},
		{"9.0", "9.0"},
		{"10.7", "10.0"},
		{"", ""},               // never probed; leave it alone
		{"garbage", "garbage"}, // unparseable stays as-is, and fails closed downstream
	} {
		if got := minorFloor(tc.persisted); got != tc.want {
			t.Errorf("minorFloor(%q) = %q, want %q", tc.persisted, got, tc.want)
		}
	}

	// End to end through the restore path, and the MAJOR must survive so
	// compatibility filtering (major equality) still admits the peer.
	op := persistedOperator{ID: 7, NodeID: 1, ProtoVersion: "9.2"}.toOperator()
	if op.ProtoVersion != "9.0" {
		t.Errorf("restored ProtoVersion = %q, want 9.0", op.ProtoVersion)
	}
	if !wire.ProtoVersionCompatible(op.ProtoVersion) {
		t.Error("flooring the minor must not make a restored peer incompatible")
	}
	if wire.UsesTightInputBound(op.ProtoVersion) {
		t.Error("a restored version must NOT enable the tight input bound before a live probe")
	}
}
