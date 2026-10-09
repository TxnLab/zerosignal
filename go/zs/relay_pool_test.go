/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/wire"
)

func relayPoolOp(id uint64, mutate func(*Operator)) Operator {
	op := Operator{
		ID: id, OwnerAddr: "A", BaseURL: "http://op.example",
		Reachable: true, Probed: true, ReachableAsOf: time.Now(),
		Models:       []string{"m"},
		ProtoVersion: wire.ProtoVersion,
	}
	mutate(&op)
	return op
}

func relayPoolOf(t *testing.T, allowStaging bool, ops ...Operator) int {
	t.Helper()
	reg, err := NewStaticRegistryProviderWithConfig(ops, StaticRegistryConfig{AllowStaging: allowStaging})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	s := &Client{cfg: Config{AllowStaging: allowStaging}, registryProvider: reg}
	return len(s.relayPool(context.Background()))
}

// TestRelayPoolKeepsStagingNodes is the consumer-side half of the hard
// constraint (the provider-side half is
// TestDynamicRegistry_AllOperatorsKeepsStagingForRelayUse). proto/SPEC.md: the
// staging flag "gates TARGET selection only. Staging nodes remain usable as
// relays, since a relay forwards bytes and runs no inference." Pinning it at both
// layers means neither a provider refactor nor a "filter everywhere in the
// caller" refactor can shrink the relay pool quietly.
func TestRelayPoolKeepsStagingNodes(t *testing.T) {
	staging := func(op *Operator) { op.Staging = true }
	if n := relayPoolOf(t, false, relayPoolOp(1, staging), relayPoolOp(2, staging)); n != 2 {
		t.Fatalf("relayPool = %d nodes, want 2 — staging nodes are still valid relay hops", n)
	}
}

// Target-only: the relay pool still includes a broke node, since a relay pays
// no fee for the request it forwards.
func TestRelayPoolKeepsUnderfundedNodes(t *testing.T) {
	broke := func(op *Operator) { op.SignerSpendableMicroAlgos = micro(0) }
	if n := relayPoolOf(t, false, relayPoolOp(1, broke), relayPoolOp(2, broke)); n != 2 {
		t.Fatalf("relayPool = %d nodes, want 2 — underfunded nodes are still valid relay hops", n)
	}
}
