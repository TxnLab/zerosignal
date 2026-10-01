/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package algod

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestEscrowAppID(t *testing.T) {
	cases := []struct {
		network string
		want    uint64
	}{
		{"testnet", 765860477},
		{"mainnet", 3628061142},
		{"MainNet", 3628061142},  // case-insensitive, mirrors Resolve
		{" testnet ", 765860477}, // trimmed
		{"localnet", 0},          // deploy-specific, never embedded
		{"", 0},                  // manual endpoint / unset
		{"betanet", 0},           // unknown network ships no preset
	}
	for _, c := range cases {
		if got := EscrowAppID(c.network); got != c.want {
			t.Errorf("EscrowAppID(%q) = %d, want %d", c.network, got, c.want)
		}
	}
}

func TestConfigResolve(t *testing.T) {
	localToken := strings.Repeat("a", 64)
	cases := []struct {
		name         string
		in           Config
		wantNetwork  Network
		wantEndpoint string
		wantToken    string
		wantErr      bool
	}{
		{
			name: "empty is allowed and resolves to nothing",
			in:   Config{},
		},
		{
			name:         "localnet preset",
			in:           Config{Network: "localnet"},
			wantNetwork:  NetworkLocalnet,
			wantEndpoint: "http://localhost:4001",
			wantToken:    localToken,
		},
		{
			name:         "testnet preset",
			in:           Config{Network: "testnet"},
			wantNetwork:  NetworkTestnet,
			wantEndpoint: "https://testnet-api.4160.nodely.dev",
		},
		{
			name:         "mainnet preset",
			in:           Config{Network: "mainnet"},
			wantNetwork:  NetworkMainnet,
			wantEndpoint: "https://mainnet-api.4160.nodely.dev",
		},
		{
			name:         "endpoint overrides network default and trims trailing slash",
			in:           Config{Network: "testnet", Endpoint: "https://custom:4001/"},
			wantNetwork:  NetworkTestnet,
			wantEndpoint: "https://custom:4001",
		},
		{
			name:         "token overrides without touching endpoint",
			in:           Config{Network: "testnet", Token: "secret"},
			wantNetwork:  NetworkTestnet,
			wantEndpoint: "https://testnet-api.4160.nodely.dev",
			wantToken:    "secret",
		},
		{
			name:         "endpoint alone (no network) is allowed",
			in:           Config{Endpoint: "http://localhost:4001"},
			wantEndpoint: "http://localhost:4001",
		},
		{
			name:    "unknown network errors with valid set",
			in:      Config{Network: "bogus"},
			wantErr: true,
		},
		{
			name:         "network is case-insensitive",
			in:           Config{Network: "TestNet"},
			wantNetwork:  NetworkTestnet,
			wantEndpoint: "https://testnet-api.4160.nodely.dev",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.in
			err := cfg.Resolve()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if !strings.Contains(err.Error(), "localnet|testnet|mainnet") {
					t.Errorf("error should list valid networks; got %q", err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if cfg.ResolvedNetwork != tc.wantNetwork {
				t.Errorf("ResolvedNetwork = %q, want %q", cfg.ResolvedNetwork, tc.wantNetwork)
			}
			if cfg.ResolvedEndpoint != tc.wantEndpoint {
				t.Errorf("ResolvedEndpoint = %q, want %q", cfg.ResolvedEndpoint, tc.wantEndpoint)
			}
			if cfg.ResolvedToken != tc.wantToken {
				t.Errorf("ResolvedToken = %q, want %q", cfg.ResolvedToken, tc.wantToken)
			}
		})
	}
}

// TestConfigResolveResetsStaleValues guards against a prior Resolve()
// leaking its Resolved* values when inputs are cleared and Resolve() is
// called again (e.g. config reload).
func TestConfigResolveResetsStaleValues(t *testing.T) {
	cfg := Config{Network: "testnet", Token: "t"}
	if err := cfg.Resolve(); err != nil {
		t.Fatalf("first Resolve: %v", err)
	}
	cfg.Network = ""
	cfg.Token = ""
	cfg.Endpoint = ""
	if err := cfg.Resolve(); err != nil {
		t.Fatalf("second Resolve: %v", err)
	}
	if cfg.ResolvedNetwork != "" || cfg.ResolvedEndpoint != "" || cfg.ResolvedToken != "" {
		t.Errorf("expected all Resolved* cleared after second Resolve; got network=%q endpoint=%q token_set=%v",
			cfg.ResolvedNetwork, cfg.ResolvedEndpoint, cfg.ResolvedToken != "")
	}
}

func TestConfigEndpointOverrides(t *testing.T) {
	cases := []struct {
		name string
		in   Config
		want bool
	}{
		{"neither set", Config{}, false},
		{"only network", Config{Network: "testnet"}, false},
		{"only endpoint", Config{Endpoint: "http://x"}, false},
		{"both set", Config{Network: "testnet", Endpoint: "http://x"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.in.EndpointOverrides(); got != tc.want {
				t.Errorf("EndpointOverrides = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestConfigLogValueRedactsToken verifies the slog handler never emits
// the literal token — if someone ever swaps LogValue for a default
// reflect-based rendering, this test fires.
func TestConfigLogValueRedactsToken(t *testing.T) {
	cfg := Config{Network: "testnet", Token: "sensitive-api-token"}
	if err := cfg.Resolve(); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// Override resolved token to a distinct sentinel to also catch
	// accidental exposure of the post-override value.
	cfg.ResolvedToken = "resolved-sensitive-token"

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	logger.Info("startup", slog.Any("algod", cfg))

	out := buf.String()
	if strings.Contains(out, "sensitive-api-token") || strings.Contains(out, "resolved-sensitive-token") {
		t.Fatalf("log output leaked token: %q", out)
	}
	if !strings.Contains(out, "token_set=true") {
		t.Errorf("log output should note that a token is set; got %q", out)
	}
	if !strings.Contains(out, "resolved_token_set=true") {
		t.Errorf("log output should note that resolved token is set; got %q", out)
	}
}
