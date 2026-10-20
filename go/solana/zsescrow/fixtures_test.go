/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zsescrow_test

// Replays the instructions, accounts and events the zs_escrow program's own
// tests recorded (contracts-solana `make sync-proto-fixtures`): every builder
// must give the instruction the program was sent, byte for byte and meta for
// meta, and every decoder must read what the program wrote as the program's
// own deserialization does. proto/ts replays the same files.

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"testing"

	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
)

type fixtureContext struct {
	Keys map[string]struct {
		Pubkey solana.PublicKey `json:"pubkey"`
	} `json:"keys"`
	Treasury solana.PublicKey `json:"treasury"`
	USDCMint solana.PublicKey `json:"usdc_mint"`
}

func readFixture(t *testing.T, name string, v any) {
	t.Helper()
	b, err := os.ReadFile("../../../testdata/" + name)
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

// flatten writes v in the fixtures' shape: u64 and i64 as decimal strings,
// keys base58, other byte arrays hex, enums by variant name.
func flatten(v reflect.Value) any {
	if s, ok := v.Interface().(fmt.Stringer); ok && v.Kind() == reflect.Uint8 {
		return s.String()
	}
	switch x := v.Interface().(type) {
	case solana.PublicKey:
		return x.String()
	case solana.Hash:
		return hex.EncodeToString(x[:])
	}
	switch v.Kind() {
	case reflect.Uint64:
		return strconv.FormatUint(v.Uint(), 10)
	case reflect.Int64:
		return strconv.FormatInt(v.Int(), 10)
	case reflect.Uint8, reflect.Uint16, reflect.Uint32:
		return float64(v.Uint())
	case reflect.Bool:
		return v.Bool()
	case reflect.String:
		return v.String()
	case reflect.Pointer:
		if v.IsNil() {
			return nil
		}
		return flatten(v.Elem())
	case reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			b := make([]byte, v.Len())
			reflect.Copy(reflect.ValueOf(b), v)
			return hex.EncodeToString(b)
		}
		out := make([]any, v.Len())
		for i := range out {
			out[i] = flatten(v.Index(i))
		}
		return out
	case reflect.Struct:
		out := map[string]any{}
		for i := range v.NumField() {
			out[v.Type().Field(i).Tag.Get("json")] = flatten(v.Field(i))
		}
		return out
	}
	panic("flatten: " + v.Type().String())
}

func TestAccountFixtures(t *testing.T) {
	var f struct {
		ProgramID solana.PublicKey `json:"program_id"`
		Context   fixtureContext   `json:"context"`
		Accounts  []struct {
			Name     string           `json:"name"`
			Type     string           `json:"type"`
			Address  solana.PublicKey `json:"address"`
			Owner    solana.PublicKey `json:"owner"`
			SeedsHex []string         `json:"seeds_hex"`
			DataLen  int              `json:"data_len"`
			Data     string           `json:"data_base64"`
			Decoded  map[string]any   `json:"decoded"`
		} `json:"accounts"`
	}
	readFixture(t, "solana_account_vectors.json", &f)
	d := zsescrow.Deployment{Program: f.ProgramID, Mint: f.Context.USDCMint}
	sizes := map[string]int{
		"Config": zsescrow.ConfigSize, "Operator": zsescrow.OperatorSize, "Node": zsescrow.NodeSize,
		"Ticket": zsescrow.TicketSize, "SignerIndex": zsescrow.SignerIndexSize, "RefundOwed": zsescrow.RefundOwedSize,
		"TokenAccount": zsescrow.TokenAccountSize,
	}
	seen := map[string]bool{}
	for _, a := range f.Accounts {
		t.Run(a.Name, func(t *testing.T) {
			data := b64(t, a.Data)
			if len(data) != a.DataLen || sizes[a.Type] != a.DataLen {
				t.Fatalf("%s is %d bytes, fixture says %d, decoder %d", a.Type, len(data), a.DataLen, sizes[a.Type])
			}
			var got any
			var err error
			switch a.Type {
			case "Config":
				got, err = zsescrow.DecodeConfig(data)
			case "Operator":
				got, err = zsescrow.DecodeOperator(data)
			case "Node":
				got, err = zsescrow.DecodeNode(data)
			case "Ticket":
				got, err = zsescrow.DecodeTicket(data)
			case "SignerIndex":
				got, err = zsescrow.DecodeSignerIndex(data)
			case "RefundOwed":
				got, err = zsescrow.DecodeRefundOwed(data)
			case "TokenAccount":
				got, err = zsescrow.DecodeTokenAccount(data)
			default:
				t.Fatalf("no decoder for %s", a.Type)
			}
			if err != nil {
				t.Fatal(err)
			}
			seen[a.Type] = true

			// The address is the one Deployment derives from what the
			// account holds, and the account belongs to the program that
			// writes it.
			var want solana.PublicKey
			owner := d.Program
			switch v := got.(type) {
			case *zsescrow.Config:
				want = d.Config()
			case *zsescrow.Operator:
				want = d.Operator(v.ID)
			case *zsescrow.Node:
				want = d.Node(v.OperatorID, v.NodeID)
				if v.Vault != d.Vault(want) || v.Operator != d.Operator(v.OperatorID) {
					t.Errorf("node stores vault %s operator %s", v.Vault, v.Operator)
				}
			case *zsescrow.Ticket:
				id, _ := hex.DecodeString(a.SeedsHex[2])
				want = d.Ticket(v.Node, [16]byte(id))
			case *zsescrow.SignerIndex:
				signing, _ := hex.DecodeString(a.SeedsHex[1])
				want = d.SignerIndex(solana.PublicKey(signing))
			case *zsescrow.RefundOwed:
				want = d.RefundOwed(v.Payer)
			case *zsescrow.TokenAccount:
				owner = solana.TokenProgramID
				switch seed, _ := hex.DecodeString(a.SeedsHex[0]); string(seed) {
				case zsescrow.VaultSeed:
					want = d.Vault(v.Owner)
				case zsescrow.StakeVaultSeed:
					want = d.StakeVault()
				case zsescrow.OwedVaultSeed:
					want = d.OwedVault()
				}
				if v.Mint != d.Mint {
					t.Errorf("a vault of mint %s", v.Mint)
				}
			}
			if a.Address != want || a.Owner != owner {
				t.Errorf("at %s owned by %s; Deployment derives %s, owner %s", a.Address, a.Owner, want, owner)
			}
			flat := flatten(reflect.ValueOf(got)).(map[string]any)
			// The fixture gives a token account's mint, owner, amount and
			// state only; the program's own accounts in full.
			if a.Type != "TokenAccount" && len(flat) != len(a.Decoded) {
				t.Errorf("decoder has %d fields, fixture %d", len(flat), len(a.Decoded))
			}
			for k, want := range a.Decoded {
				if !reflect.DeepEqual(flat[k], want) {
					t.Errorf("%s = %v, want %v", k, flat[k], want)
				}
			}
			// Another type's discriminator is refused.
			if a.Type != "Config" && a.Type != "TokenAccount" {
				if _, err := zsescrow.DecodeConfig(data); err == nil {
					t.Error("decodes as a Config")
				}
			}
		})
	}
	if len(seen) != len(sizes) {
		t.Errorf("decoded %d types of %d", len(seen), len(sizes))
	}
}

type instructionCase struct {
	Case        string         `json:"case"`
	Instruction string         `json:"instruction"`
	Args        map[string]any `json:"args"`
	Data        string         `json:"data_base64"`
	Accounts    []struct {
		Name       string           `json:"name"`
		Pubkey     solana.PublicKey `json:"pubkey"`
		IsSigner   bool             `json:"is_signer"`
		IsWritable bool             `json:"is_writable"`
	} `json:"accounts"`
}

// argReader reads the fixture's decoded args: u64 and i64 as strings, keys
// base58, byte arrays hex, nulls for None.
type argReader struct {
	t *testing.T
	m map[string]any
}

func (a argReader) sub(k string) argReader { return argReader{a.t, a.m[k].(map[string]any)} }
func (a argReader) null(k string) bool     { return a.m[k] == nil }
func (a argReader) u64(k string) uint64 {
	v, err := strconv.ParseUint(a.m[k].(string), 10, 64)
	if err != nil {
		a.t.Fatal(err)
	}
	return v
}
func (a argReader) i64(k string) int64 {
	v, err := strconv.ParseInt(a.m[k].(string), 10, 64)
	if err != nil {
		a.t.Fatal(err)
	}
	return v
}
func (a argReader) num(k string) uint64 { return uint64(a.m[k].(float64)) }
func (a argReader) str(k string) string { return a.m[k].(string) }
func (a argReader) key(k string) solana.PublicKey {
	return solana.MustPublicKey(a.str(k))
}
func (a argReader) bytes(k string) []byte {
	b, err := hex.DecodeString(a.str(k))
	if err != nil {
		a.t.Fatal(err)
	}
	return b
}
func (a argReader) claim(k string) zsescrow.ClaimFields {
	f := a.sub(k)
	return zsescrow.ClaimFields{
		Amount: f.u64("amount"), ReceiptDigest: [32]byte(f.bytes("receipt_digest")),
		TTFTMs: uint32(f.num("ttft_ms")), DecodeMs: uint32(f.num("decode_ms")),
		InputUnits: f.u64("input_units"), OutputUnits: f.u64("output_units"),
		OutputUsageType: uint8(f.num("output_usage_type")), AuxUsageType: uint8(f.num("aux_usage_type")),
		AuxCount: uint32(f.num("aux_count")),
	}
}

func optional[T any](a argReader, k string, get func(string) T) *T {
	if a.null(k) {
		return nil
	}
	v := get(k)
	return &v
}

func TestInstructionFixtures(t *testing.T) {
	var f struct {
		ProgramID    solana.PublicKey  `json:"program_id"`
		Context      fixtureContext    `json:"context"`
		Instructions []instructionCase `json:"instructions"`
	}
	readFixture(t, "solana_instruction_vectors.json", &f)
	d := zsescrow.Deployment{Program: f.ProgramID, Mint: f.Context.USDCMint}
	known := []solana.PublicKey{f.Context.Treasury}
	for _, k := range f.Context.Keys {
		known = append(known, k.Pubkey)
	}
	covered := map[string]bool{}
	for _, c := range f.Instructions {
		t.Run(c.Case, func(t *testing.T) {
			acct := map[string]solana.PublicKey{}
			for _, a := range c.Accounts {
				acct[a.Name] = a.Pubkey
			}
			args := argReader{t, c.Args}
			// The fixtures name accounts, not the ids and keys a builder
			// derives them from; find those by deriving.
			find := func(what string, match func(k solana.PublicKey) bool) solana.PublicKey {
				for _, k := range known {
					if match(k) {
						return k
					}
				}
				t.Fatalf("no known key gives the %s", what)
				return solana.PublicKey{}
			}
			ownerOf := func(account string) solana.PublicKey {
				return find(account, func(k solana.PublicKey) bool { return d.TokenAccount(k) == acct[account] })
			}
			operatorID := func() uint64 {
				for id := uint64(1); id < 16; id++ {
					if d.Operator(id) == acct["operator"] {
						return id
					}
				}
				t.Fatal("no operator id gives the operator")
				return 0
			}
			nodeIDs := func() (uint64, uint64) {
				for op := uint64(1); op < 8; op++ {
					for n := uint64(1); n < 8; n++ {
						if d.Node(op, n) == acct["node"] {
							return op, n
						}
					}
				}
				t.Fatal("no ids give the node")
				return 0, 0
			}
			ticketID := func(node solana.PublicKey) [16]byte {
				for b := range 256 {
					id := [16]byte(bytes.Repeat([]byte{byte(b)}, 16))
					if d.Ticket(node, id) == acct["ticket"] {
						return id
					}
				}
				t.Fatal("no ticket id gives the ticket")
				return [16]byte{}
			}
			ending := func() zsescrow.Ending {
				op, n := nodeIDs()
				e := zsescrow.Ending{
					Submitter: acct["submitter"], OperatorID: op, NodeID: n, TicketID: ticketID(acct["node"]),
					RentPayer: acct["rent_payer"], Payer: ownerOf("payer_ata"),
				}
				for _, a := range c.Accounts {
					if a.Name == "refund_owed" && a.Pubkey != d.Program {
						e.Fallback = zsescrow.FallbackReadonly
						if a.IsWritable {
							e.Fallback = zsescrow.FallbackWritable
						}
					}
				}
				if want := args.sub("bumps"); d.RefundBumps(e.Payer) != (zsescrow.RefundBumps{PayerATA: uint8(want.num("payer_ata")), RefundOwed: uint8(want.num("refund_owed"))}) {
					t.Errorf("refund bumps %+v", d.RefundBumps(e.Payer))
				}
				return e
			}

			var ix solana.Instruction
			switch c.Instruction {
			case "initialize":
				ix = d.Initialize(acct["admin"], acct["treasury"], zsescrow.InitializeArgs{
					GenesisHash: solana.Hash(args.bytes("genesis_hash")), Arbiter: args.key("arbiter"),
					FeeBps: uint16(args.num("fee_bps")), MaxGrace: uint32(args.num("max_grace")),
					DefaultGrace: uint32(args.num("default_grace")), MinGrace: uint32(args.num("min_grace")),
					MaxTicketLifetime: args.i64("max_ticket_lifetime"),
					OperatorStake:     args.u64("operator_stake"), NodeStake: args.u64("node_stake"),
				})
			case "set_config":
				var err error
				ix, err = d.SetConfig(acct["admin"], zsescrow.SetConfigArgs{
					PauseOpen:         optional(args, "pause_open", func(k string) bool { return args.m[k].(bool) }),
					PauseRegistry:     optional(args, "pause_registry", func(k string) bool { return args.m[k].(bool) }),
					FeeBps:            optional(args, "fee_bps", func(k string) uint16 { return uint16(args.num(k)) }),
					MaxGrace:          optional(args, "max_grace", func(k string) uint32 { return uint32(args.num(k)) }),
					DefaultGrace:      optional(args, "default_grace", func(k string) uint32 { return uint32(args.num(k)) }),
					MinGrace:          optional(args, "min_grace", func(k string) uint32 { return uint32(args.num(k)) }),
					MaxTicketLifetime: optional(args, "max_ticket_lifetime", args.i64),
					OperatorStake:     optional(args, "operator_stake", args.u64),
					NodeStake:         optional(args, "node_stake", args.u64),
					Treasury:          optional(args, "treasury", args.key),
				})
				if err != nil {
					t.Fatal(err)
				}
			case "propose_admin":
				ix = d.ProposeAdmin(acct["admin"], args.key("new_admin"))
			case "accept_admin":
				ix = d.AcceptAdmin(acct["new_admin"])
			case "propose_arbiter":
				ix = d.ProposeArbiter(acct["arbiter"], args.key("new_arbiter"))
			case "accept_arbiter":
				ix = d.AcceptArbiter(acct["new_arbiter"])
			case "create_operator":
				ix = d.CreateOperator(acct["owner"], acct["owner_usdc"], operatorID())
			case "create_node":
				op, n := nodeIDs()
				ix = d.CreateNode(acct["owner"], acct["owner_usdc"], op, n, acct["signing"], args.str("base_url"))
			case "update_node":
				op, n := nodeIDs()
				old := find("old signer index", func(k solana.PublicKey) bool { return d.SignerIndex(k) == acct["old_signer_index"] })
				ix = d.UpdateNode(acct["owner"], op, n, old, acct["new_signing"], args.str("base_url"))
			case "update_node_url":
				op, n := nodeIDs()
				ix = d.UpdateNodeURL(acct["authority"], op, n, args.str("base_url"))
			case "set_node_staging":
				op, n := nodeIDs()
				ix = d.SetNodeStaging(acct["authority"], op, n, args.m["staging"].(bool))
			case "update_operator":
				ix = d.UpdateOperator(acct["owner"], operatorID(), args.key("new_owner"), args.key("name_ref"))
			case "unregister_node":
				op, n := nodeIDs()
				signing := find("signer index", func(k solana.PublicKey) bool { return d.SignerIndex(k) == acct["signer_index"] })
				ix = d.UnregisterNode(acct["owner"], acct["owner_usdc"], op, n, signing, acct["treasury_usdc"])
			case "unregister_operator":
				ix = d.UnregisterOperator(acct["owner"], acct["owner_usdc"], operatorID())
			case "admin_unregister_operator":
				ix = d.AdminUnregisterOperator(acct["admin"], operatorID(), acct["owner"], acct["owner_usdc"])
			case "evict":
				ix = d.Evict(acct["admin"], operatorID(), acct["treasury_usdc"], uint16(args.num("slash_bps")), args.str("reason"))
			case "reinstate":
				ix = d.Reinstate(acct["admin"], operatorID())
			case "open":
				op, n := nodeIDs()
				ix = d.Open(acct["node_signer"], op, n, zsescrow.OpenArgs{
					TicketID: [16]byte(args.bytes("ticket_id")), Payer: args.key("payer"),
					MaxPrice: args.u64("max_price"), ExpiresAt: args.i64("expires_at"), Grace: uint32(args.num("grace")),
				})
			case "claim":
				op, n := nodeIDs()
				ix = d.Claim(acct["node_signer"], op, n, ticketID(acct["node"]), args.claim("fields"))
			case "settle_cooperative":
				ix = d.SettleCooperative(ending(), args.claim("fields"))
			case "ack":
				ix = d.Ack(ending(), args.claim("fields"))
			case "settle_lapsed":
				ix = d.SettleLapsed(ending(), args.claim("fields"))
			case "refund_inactive":
				ix = d.RefundInactive(ending())
			case "resolve_frozen":
				ix = d.ResolveFrozen(ending(), args.u64("node_amount"))
			case "protest":
				op, n := nodeIDs()
				id := [16]byte(args.bytes("ticket_id"))
				if d.Ticket(acct["node"], id) != acct["ticket"] {
					t.Error("the protest's ticket id names another ticket")
				}
				ix = d.Protest(acct["payer"], op, n, id, args.bytes("receipt"), uint8(args.num("reason")))
			case "claim_refund_owed":
				ix = d.ClaimRefundOwed(acct["payer"], acct["rent_payer"])
			case "close_refund_owed":
				payer := find("refund owed", func(k solana.PublicKey) bool { return d.RefundOwed(k) == acct["refund_owed"] })
				ix = d.CloseRefundOwed(acct["rent_payer"], payer)
			case "withdraw_payout":
				op, n := nodeIDs()
				ix = d.WithdrawPayout(op, n, ownerOf("owner_usdc"))
			case "sweep_fees":
				op, n := nodeIDs()
				ix = d.SweepFees(op, n, ownerOf("treasury_usdc"))
			default:
				t.Fatalf("no builder for %s", c.Instruction)
			}
			covered[c.Instruction] = true
			if ix.ProgramID != d.Program {
				t.Errorf("program %s", ix.ProgramID)
			}
			if !bytes.Equal(ix.Data, b64(t, c.Data)) {
				t.Errorf("data %x\nwant %x", ix.Data, b64(t, c.Data))
			}
			if len(ix.Accounts) != len(c.Accounts) {
				t.Fatalf("%d accounts, want %d", len(ix.Accounts), len(c.Accounts))
			}
			for i, a := range c.Accounts {
				if ix.Accounts[i] != (solana.AccountMeta{PublicKey: a.Pubkey, IsSigner: a.IsSigner, IsWritable: a.IsWritable}) {
					t.Errorf("account %d (%s): %+v, want %s signer=%v writable=%v", i, a.Name, ix.Accounts[i], a.Pubkey, a.IsSigner, a.IsWritable)
				}
			}
		})
	}
	readIDL(t)
	for _, ix := range idl.Instructions {
		if !covered[ix.Name] {
			t.Errorf("no fixture pins the %s builder", ix.Name)
		}
	}
}

func TestEventFixtures(t *testing.T) {
	var f struct {
		ProgramID solana.PublicKey `json:"program_id"`
		Context   fixtureContext   `json:"context"`
		EmitCPI   struct {
			EventAuthority solana.PublicKey `json:"event_authority"`
			EventIxTagHex  string           `json:"event_ix_tag_hex"`
		} `json:"emit_cpi"`
		Events []struct {
			Case             string         `json:"case"`
			Event            string         `json:"event"`
			DiscriminatorHex string         `json:"discriminator_hex"`
			Event64          string         `json:"event_base64"`
			Decoded          map[string]any `json:"decoded"`
			Inner            struct {
				ProgramID solana.PublicKey   `json:"program_id"`
				Accounts  []solana.PublicKey `json:"accounts"`
				Data      string             `json:"data_base64"`
			} `json:"inner_instruction"`
		} `json:"events"`
	}
	readFixture(t, "solana_event_vectors.json", &f)
	d := zsescrow.Deployment{Program: f.ProgramID, Mint: f.Context.USDCMint}
	if d.EventAuthority() != f.EmitCPI.EventAuthority || hex.EncodeToString(zsescrow.EventIxTag[:]) != f.EmitCPI.EventIxTagHex {
		t.Fatalf("event authority %s, tag %x", d.EventAuthority(), zsescrow.EventIxTag)
	}
	if len(f.Events) == 0 {
		t.Fatal("no events")
	}
	for _, e := range f.Events {
		t.Run(e.Case, func(t *testing.T) {
			data := b64(t, e.Inner.Data)
			if !bytes.Equal(data[8:], b64(t, e.Event64)) || hex.EncodeToString(data[8:16]) != e.DiscriminatorHex {
				t.Fatal("the fixture's event bytes are not its instruction's")
			}
			if !d.IsEventInstruction(e.Inner.ProgramID, e.Inner.Accounts) {
				t.Error("not read as an event instruction")
			}
			if d.IsEventInstruction(e.Inner.ProgramID, append(e.Inner.Accounts, d.Program)) {
				t.Error("an event instruction with a second account")
			}
			ev, err := zsescrow.ParseEvent(data)
			if err != nil {
				t.Fatal(err)
			}
			if reflect.TypeOf(ev).Name() != e.Event {
				t.Fatalf("decoded as %T", ev)
			}
			flat := flatten(reflect.ValueOf(ev)).(map[string]any)
			if !reflect.DeepEqual(flat, e.Decoded) {
				t.Errorf("decoded %v\nwant %v", flat, e.Decoded)
			}
			if _, err := zsescrow.ParseEvent(append(bytes.Clone(data), 0)); err == nil {
				t.Error("a trailing byte parses")
			}
			if _, err := zsescrow.ParseEvent(data[:len(data)-1]); err == nil {
				t.Error("a short event parses")
			}
		})
	}
}
