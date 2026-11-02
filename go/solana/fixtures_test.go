/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package solana_test

// Replays the transactions and addresses the zs_escrow program's own tests
// wrote (`make sync-proto-fixtures` in zerosignal-contracts' solana/). Rust built these, so
// matching them byte for byte is what shows this codec is the runtime's.
// proto/ts replays the same files.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/TxnLab/zerosignal/go/solana"
)

type fixtureContext struct {
	Keys map[string]struct {
		Pubkey solana.PublicKey `json:"pubkey"`
		Seed   byte             `json:"seed"`
	} `json:"keys"`
}

type fixtureMeta struct {
	Pubkey     solana.PublicKey `json:"pubkey"`
	IsSigner   bool             `json:"is_signer"`
	IsWritable bool             `json:"is_writable"`
}

type txFixture struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	RecentBlockhash string `json:"recent_blockhash"`
	FeePayer        string `json:"fee_payer"`
	Header          struct {
		NumRequiredSignatures       uint8 `json:"num_required_signatures"`
		NumReadonlySignedAccounts   uint8 `json:"num_readonly_signed_accounts"`
		NumReadonlyUnsignedAccounts uint8 `json:"num_readonly_unsigned_accounts"`
	} `json:"header"`
	AccountKeys         []fixtureMeta `json:"account_keys"`
	AddressTableLookups []struct {
		AccountKey      solana.PublicKey `json:"account_key"`
		WritableIndexes []uint8          `json:"writable_indexes"`
		ReadonlyIndexes []uint8          `json:"readonly_indexes"`
	} `json:"address_table_lookups"`
	Signatures   []string `json:"signatures"`
	Instructions []struct {
		ProgramIDIndex uint8   `json:"program_id_index"`
		Accounts       []uint8 `json:"accounts"`
		Data           string  `json:"data_base64"`
	} `json:"instructions"`
	BuiltInstructions []struct {
		ProgramID solana.PublicKey `json:"program_id"`
		Accounts  []fixtureMeta    `json:"accounts"`
		Data      string           `json:"data_base64"`
	} `json:"built_instructions"`
	Message string `json:"message_base64"`
	Wire    string `json:"wire_base64"`
}

func readFixture(t *testing.T, name string, v any) {
	t.Helper()
	b, err := os.ReadFile("../../testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

func b64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestTxFixtures(t *testing.T) {
	var f struct {
		Context      fixtureContext `json:"context"`
		Transactions []txFixture    `json:"transactions"`
	}
	readFixture(t, "solana_tx_vectors.json", &f)
	if len(f.Transactions) == 0 {
		t.Fatal("no transactions")
	}
	seedOf := map[solana.PublicKey]byte{}
	for _, k := range f.Context.Keys {
		seedOf[k.Pubkey] = k.Seed
	}
	for _, c := range f.Transactions {
		t.Run(c.Name, func(t *testing.T) {
			wire := b64(t, c.Wire)
			msgBytes := b64(t, c.Message)
			tx, err := solana.ParseTransaction(wire)
			if err != nil {
				t.Fatal(err)
			}
			m := &tx.Message
			if got, _ := m.MarshalBinary(); !bytes.Equal(got, msgBytes) {
				t.Fatal("message does not re-encode to the signed bytes")
			}
			if got, _ := tx.MarshalBinary(); !bytes.Equal(got, wire) {
				t.Fatal("transaction does not re-encode to the wire bytes")
			}
			if m.Version.String() != c.Version {
				t.Errorf("version %s, want %s", m.Version, c.Version)
			}
			if m.RecentBlockhash.String() != c.RecentBlockhash || m.FeePayer().String() != c.FeePayer {
				t.Errorf("blockhash %s payer %s", m.RecentBlockhash, m.FeePayer())
			}
			h := c.Header
			if m.Header != (solana.MessageHeader{NumRequiredSignatures: h.NumRequiredSignatures, NumReadonlySignedAccounts: h.NumReadonlySignedAccounts, NumReadonlyUnsignedAccounts: h.NumReadonlyUnsignedAccounts}) {
				t.Errorf("header %+v", m.Header)
			}
			if len(m.AccountKeys) != len(c.AccountKeys) {
				t.Fatalf("%d keys, want %d", len(m.AccountKeys), len(c.AccountKeys))
			}
			for i, k := range c.AccountKeys {
				if m.AccountKeys[i] != k.Pubkey || m.IsSigner(i) != k.IsSigner || m.IsWritable(i) != k.IsWritable {
					t.Errorf("key %d: %s signer=%v writable=%v, want %+v", i, m.AccountKeys[i], m.IsSigner(i), m.IsWritable(i), k)
				}
			}
			if len(m.Instructions) != len(c.Instructions) {
				t.Fatalf("%d instructions, want %d", len(m.Instructions), len(c.Instructions))
			}
			for i, ix := range c.Instructions {
				got := m.Instructions[i]
				if got.ProgramIDIndex != ix.ProgramIDIndex || !bytes.Equal(got.Accounts, ix.Accounts) || !bytes.Equal(got.Data, b64(t, ix.Data)) {
					t.Errorf("instruction %d: %+v", i, got)
				}
			}
			if len(m.AddressTableLookups) != len(c.AddressTableLookups) {
				t.Fatalf("%d lookups, want %d", len(m.AddressTableLookups), len(c.AddressTableLookups))
			}
			for i, l := range c.AddressTableLookups {
				got := m.AddressTableLookups[i]
				if got.AccountKey != l.AccountKey || !bytes.Equal(got.WritableIndexes, l.WritableIndexes) || !bytes.Equal(got.ReadonlyIndexes, l.ReadonlyIndexes) {
					t.Errorf("lookup %d: %+v", i, got)
				}
			}
			// Looked-up addresses follow the static keys, writable ones first,
			// and none signs; an index past them all has no answer.
			n, total, w := len(m.AccountKeys), len(m.AccountKeys), 0
			for _, l := range c.AddressTableLookups {
				w += len(l.WritableIndexes)
				total += len(l.WritableIndexes) + len(l.ReadonlyIndexes)
			}
			for i := n; i < total; i++ {
				if m.IsWritable(i) != (i < n+w) || m.IsSigner(i) {
					t.Errorf("looked-up %d: writable=%v signer=%v", i, m.IsWritable(i), m.IsSigner(i))
				}
			}
			for _, i := range []int{-1, total} {
				func() {
					defer func() {
						if recover() == nil {
							t.Errorf("IsWritable(%d) of %d answers", i, total)
						}
					}()
					m.IsWritable(i)
				}()
			}
			if err := tx.VerifySignatures(); err != nil {
				t.Error(err)
			}

			// Signing again with the seeded keys gives the same signatures,
			// each in its signer's slot: ed25519 is deterministic.
			resigned := solana.NewTransaction(m)
			for i := range int(m.Header.NumRequiredSignatures) {
				seed, ok := seedOf[m.AccountKeys[i]]
				if !ok {
					t.Fatalf("signer %s has no seed", m.AccountKeys[i])
				}
				if err := resigned.Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))); err != nil {
					t.Fatal(err)
				}
			}
			for i, s := range c.Signatures {
				if resigned.Signatures[i].String() != s {
					t.Errorf("signature %d differs after re-signing", i)
				}
			}

			// The rest compile to the bytes Rust signed, except a message with
			// lookups or with a key no instruction names: no instruction list
			// compiles to either.
			if len(c.AddressTableLookups) > 0 {
				return
			}
			named := map[solana.PublicKey]bool{m.FeePayer(): true}
			var ixs []solana.Instruction
			for _, b := range c.BuiltInstructions {
				ix := solana.Instruction{ProgramID: b.ProgramID, Data: b64(t, b.Data)}
				named[b.ProgramID] = true
				for _, a := range b.Accounts {
					ix.Accounts = append(ix.Accounts, solana.AccountMeta{PublicKey: a.Pubkey, IsSigner: a.IsSigner, IsWritable: a.IsWritable})
					named[a.Pubkey] = true
				}
				ixs = append(ixs, ix)
			}
			if len(named) != len(m.AccountKeys) {
				return
			}
			v := solana.Legacy
			if c.Version == "v0" {
				v = solana.V0
			}
			compiled, err := solana.Compile(m.FeePayer(), m.RecentBlockhash, ixs, v)
			if err != nil {
				t.Fatal(err)
			}
			if got, _ := compiled.MarshalBinary(); !bytes.Equal(got, msgBytes) {
				t.Errorf("compiled message differs from the signed one")
			}
		})
	}
}

func TestFixtureKeysAreTheirSeeds(t *testing.T) {
	var f struct {
		Context fixtureContext `json:"context"`
	}
	readFixture(t, "solana_tx_vectors.json", &f)
	for name, k := range f.Context.Keys {
		priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{k.Seed}, 32))
		if !bytes.Equal(priv.Public().(ed25519.PublicKey), k.Pubkey[:]) {
			t.Errorf("%s: seed %d gives another key", name, k.Seed)
		}
	}
}

func TestPDAFixtures(t *testing.T) {
	var f struct {
		ProgramID solana.PublicKey `json:"program_id"`
		Accounts  []struct {
			Name     string           `json:"name"`
			Address  solana.PublicKey `json:"address"`
			SeedsHex []string         `json:"seeds_hex"`
			Bump     uint8            `json:"bump"`
		} `json:"accounts"`
	}
	readFixture(t, "solana_account_vectors.json", &f)
	if len(f.Accounts) == 0 {
		t.Fatal("no accounts")
	}
	for _, a := range f.Accounts {
		var seeds [][]byte
		for _, s := range a.SeedsHex {
			b, err := hex.DecodeString(s)
			if err != nil {
				t.Fatal(err)
			}
			seeds = append(seeds, b)
		}
		got, bump, err := solana.FindProgramAddress(seeds, f.ProgramID)
		if err != nil {
			t.Fatalf("%s: %v", a.Name, err)
		}
		if got != a.Address || bump != a.Bump {
			t.Errorf("%s: %s bump %d, want %s bump %d", a.Name, got, bump, a.Address, a.Bump)
		}
		if solana.IsOnCurve(got) {
			t.Errorf("%s: a PDA on the curve", a.Name)
		}
		withBump := append(seeds, []byte{a.Bump})
		if k, err := solana.CreateProgramAddress(withBump, f.ProgramID); err != nil || k != a.Address {
			t.Errorf("%s: create_program_address %s %v", a.Name, k, err)
		}
	}
}
