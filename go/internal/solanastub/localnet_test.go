/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package solanastub

import (
	"encoding/base64"
	"slices"
	"testing"

	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
	"github.com/TxnLab/zerosignal/go/ticket"
)

// The stub's issuer signs with the committed localnet key, whose public half
// is the one the localnet preset names.
func TestIssuer_IsTheLocalnetPresets(t *testing.T) {
	is, err := newIssuer(ticket.DeploymentID{1})
	if err != nil {
		t.Fatal(err)
	}
	c, _ := zsescrow.ClusterPreset(zsescrow.ClusterLocalnet)
	key := base64.StdEncoding.EncodeToString(is.Key())
	if !slices.ContainsFunc(c.FreeCreditIssuers, func(i zsescrow.FreeCreditIssuer) bool { return i.Key == key }) {
		t.Errorf("the stub issuer %s is not among the localnet preset's %v", key, c.FreeCreditIssuers)
	}
}

// The localnet's keypair is also devnet's admin, so StartLocalnet must refuse
// before it writes the Config anywhere but this machine.
func TestCheckLoopback(t *testing.T) {
	for endpoint, ok := range map[string]bool{
		"http://127.0.0.1:8899":         true,
		"http://localhost:8899":         true,
		"http://[::1]:8899":             true,
		"http://127.0.0.2:8899":         true,
		"https://api.devnet.solana.com": false,
		"http://10.0.0.5:8899":          false,
		"http://localhost.example.com":  false,
		"http://0.0.0.0:8899":           false,
		"":                              false,
	} {
		if err := checkLoopback(endpoint); (err == nil) != ok {
			t.Errorf("checkLoopback(%q) = %v, want ok %v", endpoint, err, ok)
		}
	}
}
