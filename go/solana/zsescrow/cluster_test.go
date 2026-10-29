/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zsescrow_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"reflect"
	"testing"

	"github.com/TxnLab/zerosignal/go/freecredit"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
)

// Every preset issuer key must parse: a node trusting the preset would
// otherwise refuse its own default config at startup.
func TestClusterPreset_FreeCreditIssuersParse(t *testing.T) {
	for _, name := range zsescrow.Clusters() {
		c, _ := zsescrow.ClusterPreset(name)
		for _, iss := range c.FreeCreditIssuers {
			if _, err := freecredit.ParseIssuerKey(iss.Key); err != nil {
				t.Errorf("%s: %v", name, err)
			}
		}
	}
	c, _ := zsescrow.ClusterPreset(zsescrow.ClusterLocalnet)
	if len(c.FreeCreditIssuers) == 0 {
		t.Fatal("localnet has no issuer; the end-to-end tests make credits with one")
	}
	// The stub certifies with the committed private half; a key regenerated on
	// one side only would leave every localnet credit unverifiable.
	raw, err := os.ReadFile("../../internal/solanastub/freecredit_localnet_issuer.pem")
	if err != nil {
		t.Fatal(err)
	}
	sk, err := freecredit.ParseIssuerPEM(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := base64.StdEncoding.EncodeToString(sk.Public().(ed25519.PublicKey)); got != c.FreeCreditIssuers[0].Key {
		t.Error("the localnet preset's issuer is not the stub's committed key")
	}
}

// The table is shared; a caller appending to its copy must not change what
// the next caller reads.
func TestClusterPreset_IssuersAreACopy(t *testing.T) {
	c, _ := zsescrow.ClusterPreset(zsescrow.ClusterLocalnet)
	c.FreeCreditIssuers[0].Key = "changed"
	if again, _ := zsescrow.ClusterPreset(zsescrow.ClusterLocalnet); again.FreeCreditIssuers[0].Key == "changed" {
		t.Error("ClusterPreset hands out the table's own slice")
	}
}

// The localnet issuer's private key is committed, so a node off a loopback
// RPC must not trust it, whatever its cluster is called.
func TestTrustedFreeCreditIssuers_DropsLoopbackOnlyOffThisMachine(t *testing.T) {
	c, _ := zsescrow.ClusterPreset(zsescrow.ClusterLocalnet)
	if len(c.FreeCreditIssuers) == 0 || !c.FreeCreditIssuers[0].LoopbackOnly {
		t.Fatal("the localnet issuer is not marked LoopbackOnly")
	}
	open := zsescrow.FreeCreditIssuer{Key: "open"}
	issuers := append([]zsescrow.FreeCreditIssuer{open}, c.FreeCreditIssuers...)
	for _, ep := range []string{"http://127.0.0.1:8899", "http://localhost:8899", "http://[::1]:8899", "http://127.8.0.1"} {
		if got := zsescrow.TrustedFreeCreditIssuers(issuers, ep); len(got) != 2 {
			t.Errorf("%s: kept %v, want both", ep, got)
		}
	}
	for _, ep := range []string{"https://api.devnet.solana.com", "http://10.0.0.5:8899", "http://localhost.example.com", "http://0.0.0.0:8899", "", "::not a url"} {
		if got := zsescrow.TrustedFreeCreditIssuers(issuers, ep); !reflect.DeepEqual(got, []zsescrow.FreeCreditIssuer{open}) {
			t.Errorf("%q: kept %v, want only the open issuer", ep, got)
		}
	}
}

// A node's config and the payer SDK must accept the same spellings, and the
// node calls ClusterPreset directly, without ResolveNetwork's lowering.
func TestClusterPreset_MatchesAnyCase(t *testing.T) {
	want, ok := zsescrow.ClusterPreset(zsescrow.ClusterDevnet)
	if !ok {
		t.Fatal("devnet is not a preset")
	}
	for _, name := range []string{"Devnet", "DEVNET"} {
		if got, ok := zsescrow.ClusterPreset(name); !ok || !reflect.DeepEqual(got, want) {
			t.Errorf("ClusterPreset(%q) = %+v, %v; want devnet's", name, got, ok)
		}
	}
	if _, ok := zsescrow.ClusterPreset("mainnet"); ok {
		t.Error("mainnet is a preset; there is no mainnet deployment")
	}
}
