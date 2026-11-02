/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"reflect"
	"strings"
	"testing"

	"github.com/TxnLab/zerosignal/go/ticket"
)

// Every listed name is a preset on its rail, and the list is every name
// NetworkNamed takes, so a host's help text can't offer one it refuses.
func TestNetworkNamed(t *testing.T) {
	want := map[string]Network{
		"mainnet":         Mainnet(),
		"testnet":         Testnet(),
		"localnet":        Localnet(),
		"solana-devnet":   SolanaDevnet(),
		"solana-localnet": SolanaLocalnet(),
	}
	names := strings.Split(NetworkNames, "|")
	if len(names) != len(want) {
		t.Fatalf("NetworkNames lists %d names, want %d", len(names), len(want))
	}
	for _, name := range names {
		n, ok := NetworkNamed(name)
		if !ok || !reflect.DeepEqual(n, want[name]) {
			t.Errorf("NetworkNamed(%q) = %+v, %v; want %+v", name, n, ok, want[name])
		}
		if solana := strings.HasPrefix(name, "solana-"); solana != (n.Rail == ticket.RailSolana) {
			t.Errorf("%q is on rail %v", name, n.Rail)
		}
	}
	for _, name := range []string{"", "Mainnet", "devnet", "solana-mainnet", "betanet"} {
		if _, ok := NetworkNamed(name); ok {
			t.Errorf("NetworkNamed(%q) took it", name)
		}
	}
}
