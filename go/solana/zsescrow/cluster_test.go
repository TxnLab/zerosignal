/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zsescrow_test

import (
	"testing"

	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
)

// A node's config and the payer SDK must accept the same spellings, and the
// node calls ClusterPreset directly, without ResolveNetwork's lowering.
func TestClusterPreset_MatchesAnyCase(t *testing.T) {
	want, ok := zsescrow.ClusterPreset(zsescrow.ClusterDevnet)
	if !ok {
		t.Fatal("devnet is not a preset")
	}
	for _, name := range []string{"Devnet", "DEVNET"} {
		if got, ok := zsescrow.ClusterPreset(name); !ok || got != want {
			t.Errorf("ClusterPreset(%q) = %+v, %v; want devnet's", name, got, ok)
		}
	}
	if _, ok := zsescrow.ClusterPreset("mainnet"); ok {
		t.Error("mainnet is a preset; there is no mainnet deployment")
	}
}
