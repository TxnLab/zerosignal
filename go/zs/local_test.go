/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TxnLab/zerosignal/go/algod"
	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/rpc"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
)

// A localnet preset whose loopback endpoint answers with devnet's genesis is
// a tunnel to devnet: New and Diagnose refuse the defaults they would have
// loosened, and a payer that set both settings itself is not checked.
func TestLocalDefaults_RefusePublicGenesis(t *testing.T) {
	devnet, err := solana.ParseHash(rpc.DevnetGenesis)
	if err != nil {
		t.Fatal(err)
	}
	addr, acct, _ := solanaConfigAccount(t, zsescrow.ProgramID)
	for _, tc := range []struct {
		name    string
		genesis solana.Hash
		cfg     func(*Config)
		refused bool
	}{
		{"devnet genesis, defaults", devnet, func(*Config) {}, true},
		{"devnet genesis, only privacy set", devnet, func(c *Config) { c.Privacy = PrivacyRelayRequired }, true},
		{"devnet genesis, only private hosts set", devnet, func(c *Config) { c.AllowPrivateHosts = new(false) }, true},
		{"devnet genesis, both set", devnet, func(c *Config) { c.Privacy, c.AllowPrivateHosts = PrivacyDirect, new(true) }, false},
		{"a local genesis, defaults", solana.Hash{9}, func(*Config) {}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(&fakeSolanaRPC{genesis: tc.genesis, accounts: map[string]solanaRegistryAccount{addr: acct}})
			t.Cleanup(srv.Close)
			network := SolanaLocalnet()
			network.Solana.RPCEndpoint = srv.URL
			cfg := Config{SolanaSigner: newTestSolanaSigner(), Network: network, DisableTEE: true}
			tc.cfg(&cfg)

			c, err := New(t.Context(), cfg)
			if c != nil {
				c.Close()
			}
			if got := isPublicGenesisRefusal(err); got != tc.refused {
				t.Errorf("New: err = %v, refused %v, want %v", err, got, tc.refused)
			}
			_, err = Diagnose(t.Context(), cfg, newTestSolanaSigner().Address())
			if got := isPublicGenesisRefusal(err); got != tc.refused {
				t.Errorf("Diagnose: err = %v, refused %v, want %v", err, got, tc.refused)
			}
		})
	}
}

// The Algorand rail reads its genesis from algod's params: a localnet preset
// whose loopback algod answers as testnet is refused by New and Diagnose.
func TestLocalDefaults_RefuseAlgorandPublicGenesis(t *testing.T) {
	testnet, err := base64.StdEncoding.DecodeString("SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/transactions/params" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"consensus-version": "v1",
			"genesis-hash":      base64.StdEncoding.EncodeToString(testnet),
			"genesis-id":        "testnet-v1.0",
			"last-round":        1,
			"min-fee":           1000,
		})
	}))
	t.Cleanup(srv.Close)

	cfg := suppliedParts(t)
	cfg.Registry, cfg.ReserveClient = nil, nil
	cfg.Logger = discardLogger()
	cfg.Network.Algod = algod.Config{Network: "localnet", Endpoint: srv.URL}
	c, err := New(t.Context(), cfg)
	if c != nil {
		c.Close()
	}
	if !isPublicGenesisRefusal(err, "testnet") {
		t.Errorf("New: err = %v, want the testnet refusal", err)
	}
	cfg.Wallet = nil
	if _, err := Diagnose(t.Context(), cfg, testPayerAddr); !isPublicGenesisRefusal(err, "testnet") {
		t.Errorf("Diagnose: err = %v, want the testnet refusal", err)
	}
}

func isPublicGenesisRefusal(err error, chain ...string) bool {
	name := "devnet"
	if len(chain) > 0 {
		name = chain[0]
	}
	zerr, ok := err.(*Error)
	return ok && zerr.Code == "invalid_config" && strings.Contains(err.Error(), "serves "+name)
}
