/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
)

// TestRelayAttr_OmittedOnDirectRoute pins the behavior dispatch-path logs rely
// on: a nil hop (privacy off / direct route) must produce no relay_* keys at
// all, while a real hop emits the relay's (operator_id, node_id) pair. The
// omission depends on slog's handlers dropping the zero Attr that relayAttr
// returns for nil; the flat pair depends on slog inlining the empty-key group
// relayAttr returns otherwise. Both are asserted against rendered output.
func TestRelayAttr_OmittedOnDirectRoute(t *testing.T) {
	logKeys := func(hop *RelayHop) map[string]any {
		var buf bytes.Buffer
		log := slog.New(slog.NewJSONHandler(&buf, nil))
		log.LogAttrs(context.Background(), slog.LevelInfo, "test",
			opAttr(Operator{ID: 7, NodeID: 3}),
			relayAttr(hop))
		var m map[string]any
		if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
			t.Fatalf("unmarshal log line: %v", err)
		}
		return m
	}

	// Direct route: no relay keys.
	if m := logKeys(nil); m["relay_operator_id"] != nil || m["relay_node_id"] != nil {
		t.Errorf("direct route logged relay keys op=%v node=%v, want both absent",
			m["relay_operator_id"], m["relay_node_id"])
	}

	// Relayed: relay's (operator, node) pair present alongside the target's pair.
	m := logKeys(&RelayHop{TargetID: 7, RelayID: 42, RelayNodeID: 9})
	if got, ok := m["relay_operator_id"]; !ok || got != float64(42) {
		t.Errorf("relay_operator_id = %v (present=%v), want 42", got, ok)
	}
	if got, ok := m["relay_node_id"]; !ok || got != float64(9) {
		t.Errorf("relay_node_id = %v (present=%v), want 9", got, ok)
	}
	if m["operator_id"] != float64(7) || m["node_id"] != float64(3) {
		t.Errorf("target pair = op %v / node %v, want 7 / 3 (target still logged)",
			m["operator_id"], m["node_id"])
	}
}
