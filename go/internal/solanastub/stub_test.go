/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package solanastub

import (
	"encoding/base64"
	"slices"
	"testing"

	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/rpc"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
	"github.com/TxnLab/zerosignal/go/ticket"
)

// The stub serves the deployment its payers' presets read on each cluster;
// the literals catch a preset that moved without the stub's runs.
func TestProgramOn(t *testing.T) {
	for _, c := range []struct {
		genesis, want string
	}{
		{rpc.DevnetGenesis, "EnkEN4zvxpPVoSr87qpokZDvV2PLmtmapuJBZDx9vf47"},
		{rpc.MainnetGenesis, "2sXCgAPUVAFvmDhXG1pLGA6mjnWpqR521MZTfMnyc9h1"},
		{"11111111111111111111111111111111", "2sXCgAPUVAFvmDhXG1pLGA6mjnWpqR521MZTfMnyc9h1"},
	} {
		h, err := solana.ParseHash(c.genesis)
		if err != nil {
			t.Fatal(err)
		}
		if got := ProgramOn(h).String(); got != c.want {
			t.Errorf("ProgramOn(%s) = %s, want %s", c.genesis, got, c.want)
		}
	}
}

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

// A localnet's keypair can be devnet's admin, so a run holding it must refuse
// before it writes the Config anywhere but this machine.
func TestCheckLoopback(t *testing.T) {
	for endpoint, ok := range map[string]bool{
		"http://127.0.0.1:8899":         true,
		"http://localhost:8899":         true,
		"http://[::1]:8899":             true,
		"http://[::1]":                  true,
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

// The /stub/ routes fund whoever asks, so the stub listens on loopback alone,
// and a bare port, which listens everywhere, is refused.
func TestCheckLoopbackHost(t *testing.T) {
	for listen, ok := range map[string]bool{
		"127.0.0.1:0":    true,
		"localhost:9000": true,
		"[::1]:9000":     true,
		":0":             false,
		"0.0.0.0:9000":   false,
		"[::]:9000":      false,
		"10.0.0.5:9000":  false,
	} {
		if err := checkLoopbackHost(listen); (err == nil) != ok {
			t.Errorf("checkLoopbackHost(%q) = %v, want ok %v", listen, err, ok)
		}
	}
}
