/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zsescrow_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
)

type idlEntry struct {
	Name          string  `json:"name"`
	Discriminator []uint8 `json:"discriminator"`
}

var idl struct {
	Address      solana.PublicKey `json:"address"`
	Instructions []idlEntry       `json:"instructions"`
	Accounts     []idlEntry       `json:"accounts"`
	Events       []idlEntry       `json:"events"`
}

func readIDL(t *testing.T) {
	t.Helper()
	if idl.Instructions != nil {
		return
	}
	b, err := os.ReadFile("../idl/zs_escrow.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &idl); err != nil {
		t.Fatal(err)
	}
}

// The builders and decoders compute Anchor's discriminators from names; the
// IDL lists the program's own. A renamed instruction, account or event fails
// here before it fails on chain.
func TestIDLDiscriminators(t *testing.T) {
	readIDL(t)
	if idl.Address != zsescrow.ProgramID {
		t.Errorf("IDL program %s, ProgramID %s", idl.Address, zsescrow.ProgramID)
	}
	for _, e := range idl.Instructions {
		if got := zsescrow.Discriminator("global", e.Name); string(got[:]) != string(e.Discriminator) {
			t.Errorf("instruction %s: %x, IDL %x", e.Name, got, e.Discriminator)
		}
	}
	for _, e := range idl.Accounts {
		if got := zsescrow.Discriminator("account", e.Name); string(got[:]) != string(e.Discriminator) {
			t.Errorf("account %s: %x, IDL %x", e.Name, got, e.Discriminator)
		}
	}
	if len(idl.Accounts) != 5 {
		t.Errorf("the IDL has %d account types; the decoders read 5", len(idl.Accounts))
	}
	for _, e := range idl.Events {
		if got := zsescrow.Discriminator("event", e.Name); string(got[:]) != string(e.Discriminator) {
			t.Errorf("event %s: %x, IDL %x", e.Name, got, e.Discriminator)
		}
	}
	if len(idl.Events) != 4 {
		t.Errorf("the IDL has %d events; ParseEvent reads 4", len(idl.Events))
	}
}
