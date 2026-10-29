/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package rpc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TxnLab/zerosignal/go/solana"
)

// A faucet is asked on devnet's genesis or a local validator's, never on
// mainnet's or testnet's, even behind a loopback URL, which can be a tunnel.
func TestFaucetCluster(t *testing.T) {
	other := "8TYJXvS3ae24xkjeH1XzZB5KWnzFJVNav6pd9a7uUS2v"
	for _, c := range []struct {
		genesis, url string
		want         bool
	}{
		{DevnetGenesis, "https://api.devnet.solana.com", true},
		{DevnetGenesis, "https://rpc.example", true},
		{other, "http://127.0.0.1:8899", true},
		{other, "http://localhost:8899", true},
		{MainnetGenesis, "https://api.mainnet-beta.solana.com", false},
		{MainnetGenesis, "http://127.0.0.1:8899", false},
		{TestnetGenesis, "http://localhost:8899", false},
		{other, "https://rpc.example", false},
	} {
		g, err := solana.ParseHash(c.genesis)
		if err != nil {
			t.Fatal(err)
		}
		if got := FaucetCluster(g, c.url); got != c.want {
			t.Errorf("FaucetCluster(%s, %s) = %v, want %v", c.genesis, c.url, got, c.want)
		}
	}
}

func TestRequestAirdrop(t *testing.T) {
	to := solana.PublicKey{3}
	sig := solana.Signature{4}
	for name, c := range map[string]struct {
		status int
		body   string
		want   string
	}{
		"landed":         {200, `{"jsonrpc":"2.0","id":1,"result":"` + sig.String() + `"}`, ""},
		"json-rpc error": {200, `{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"airdrop request limit reached"}}`, "-32600 airdrop request limit reached"},
		"429 as json":    {429, `{"jsonrpc":"2.0","id":1,"error":{"code":429,"message":"Too many requests"}}`, "429 Too many requests"},
		"429 as html":    {429, `<html>slow down</html>`, "HTTP 429 Too Many Requests"},
		"no signature":   {200, `{"jsonrpc":"2.0","id":1}`, "no signature"},
	} {
		t.Run(name, func(t *testing.T) {
			var got map[string]any
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewDecoder(r.Body).Decode(&got)
				w.WriteHeader(c.status)
				_, _ = w.Write([]byte(c.body))
			}))
			defer srv.Close()
			s, err := RequestAirdrop(context.Background(), srv.URL, to, 7)
			if c.want == "" {
				if err != nil || s != sig {
					t.Fatalf("= %s, %v", s, err)
				}
				if got["method"] != "requestAirdrop" || fmt.Sprint(got["params"]) != fmt.Sprintf("[%s 7]", to) {
					t.Errorf("sent %v", got)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want %q", err, c.want)
			}
		})
	}
	// A transport failure doesn't quote the endpoint, whose query can hold
	// a provider's key.
	srv := httptest.NewServer(http.NotFoundHandler())
	endpoint := srv.URL + "/?api-key=secret"
	srv.Close()
	if _, err := RequestAirdrop(context.Background(), endpoint, to, 7); err == nil || strings.Contains(err.Error(), "secret") {
		t.Errorf("err = %v", err)
	}
}
