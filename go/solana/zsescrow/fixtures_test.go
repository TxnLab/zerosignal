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
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"testing"

	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
	"github.com/TxnLab/zerosignal/go/ticket"
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
		"Ticket": zsescrow.TicketSize, "RentPool": zsescrow.RentPoolSize, "TokenAccount": zsescrow.TokenAccountSize,
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
			case "RentPool":
				got, err = zsescrow.DecodeRentPool(data)
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
				// From the stored id, so the field a walk ends a ticket by
				// must be the one its address derives from.
				want = d.Ticket(v.Node, v.TicketID)
				if id, _ := hex.DecodeString(a.SeedsHex[2]); [16]byte(id) != v.TicketID {
					t.Errorf("ticket stores id %x, its seed is %x", v.TicketID, id)
				}
				// The offset a payer's ticket listing filters on, against the
				// program's own bytes.
				if got := solana.PublicKey(data[zsescrow.TicketPayerOffset : zsescrow.TicketPayerOffset+32]); got != v.Payer {
					t.Errorf("TicketPayerOffset reads %s, the ticket's payer is %s", got, v.Payer)
				}
			case *zsescrow.RentPool:
				want = d.RentPool(v.Payer)
				if _, bump, _ := solana.FindProgramAddress([][]byte{[]byte(zsescrow.RentPoolSeed), v.Payer[:]}, d.Program); v.Bump != bump {
					t.Errorf("pool stores bump %d, derives %d", v.Bump, bump)
				}
			case *zsescrow.TokenAccount:
				owner = solana.TokenProgramID
				switch seed, _ := hex.DecodeString(a.SeedsHex[0]); string(seed) {
				case zsescrow.VaultSeed:
					want = d.Vault(v.Owner)
				case zsescrow.StakeVaultSeed:
					want = d.StakeVault()
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
	v, err := strconv.ParseUint(a.str(k), 10, 64)
	if err != nil {
		a.t.Fatal(err)
	}
	return v
}
func (a argReader) i64(k string) int64 {
	v, err := strconv.ParseInt(a.str(k), 10, 64)
	if err != nil {
		a.t.Fatal(err)
	}
	return v
}

// num and str fail the case, not the run, on an arg the fixture lacks: a
// fixture from another program version then reports every case it breaks.
func (a argReader) num(k string) uint64 {
	v, ok := a.m[k].(float64)
	if !ok {
		a.t.Fatalf("arg %s is %v, not a number", k, a.m[k])
	}
	return uint64(v)
}
func (a argReader) str(k string) string {
	v, ok := a.m[k].(string)
	if !ok {
		a.t.Fatalf("arg %s is %v, not a string", k, a.m[k])
	}
	return v
}
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
		TTFTMs: f.u64("ttft_ms"), DecodeMs: f.u64("decode_ms"),
		InputUnits: f.u64("input_units"), OutputUnits: f.u64("output_units"),
		OutputUsageType: uint8(f.num("output_usage_type")), AuxUsageType: uint8(f.num("aux_usage_type")),
		AuxCount: f.u64("aux_count"),
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
				// The program's fixtures fill ids with one byte, but for the
				// one ticket given distinct bytes to pin their order.
				ids := [][16]byte{[16]byte([]byte("sixteen-byte-id!"))}
				for b := range 256 {
					ids = append(ids, [16]byte(bytes.Repeat([]byte{byte(b)}, 16)))
				}
				for _, id := range ids {
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
					if a.Name == "treasury_usdc" && a.Pubkey != d.Program {
						e.Treasury = ownerOf("treasury_usdc")
						e.Fallback = zsescrow.FallbackReadonly
						if a.IsWritable {
							e.Fallback = zsescrow.FallbackWritable
						}
					}
				}
				if want := args.sub("bumps"); d.RefundBumps(e.Payer) != (zsescrow.RefundBumps{PayerATA: uint8(want.num("payer_ata"))}) || len(want.m) != 1 {
					t.Errorf("refund bumps %+v, fixture %v", d.RefundBumps(e.Payer), want.m)
				}
				return e
			}

			var ix solana.Instruction
			switch c.Instruction {
			case "initialize":
				ix = d.Initialize(acct["admin"], acct["treasury"], zsescrow.InitializeArgs{
					GenesisHash: solana.Hash(args.bytes("genesis_hash")),
					FeeBps:      uint16(args.num("fee_bps")), DefaultGrace: uint32(args.num("default_grace")),
					OperatorStake: args.u64("operator_stake"), NodeStake: args.u64("node_stake"),
				})
			case "set_config":
				var err error
				ix, err = d.SetConfig(acct["admin"], zsescrow.SetConfigArgs{
					Paused:        optional(args, "paused", func(k string) bool { return args.m[k].(bool) }),
					FeeBps:        optional(args, "fee_bps", func(k string) uint16 { return uint16(args.num(k)) }),
					DefaultGrace:  optional(args, "default_grace", func(k string) uint32 { return uint32(args.num(k)) }),
					OperatorStake: optional(args, "operator_stake", args.u64),
					NodeStake:     optional(args, "node_stake", args.u64),
					Treasury:      optional(args, "treasury", args.key),
				})
				if err != nil {
					t.Fatal(err)
				}
			case "propose_admin":
				ix = d.ProposeAdmin(acct["admin"], args.key("new_admin"))
			case "accept_admin":
				ix = d.AcceptAdmin(acct["new_admin"])
			case "create_operator":
				ix = d.CreateOperator(acct["owner"], acct["owner_usdc"], operatorID())
			case "create_node":
				op, n := nodeIDs()
				ix = d.CreateNode(acct["owner"], acct["owner_usdc"], op, n, args.key("signing"), args.str("base_url"))
			case "update_node":
				op, n := nodeIDs()
				ix = d.UpdateNode(acct["owner"], op, n, args.key("signing"), args.str("base_url"))
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
				ix = d.UnregisterNode(acct["owner"], acct["owner_usdc"], op, n, acct["treasury_usdc"])
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
				ix = d.Claim(ending(), args.claim("fields"))
			case "settle_cooperative":
				ix = d.SettleCooperative(ending(), args.claim("fields"))
			case "ack":
				ix = d.Ack(ending(), args.claim("fields"))
			case "settle_lapsed":
				ix = d.SettleLapsed(ending())
			case "refund_inactive":
				ix = d.RefundInactive(ending())
			case "resolve_frozen":
				ix = d.ResolveFrozen(ending(), uint16(args.num("operator_share_bps")), args.str("reason"))
			case "protest":
				op, n := nodeIDs()
				id := [16]byte(args.bytes("ticket_id"))
				if d.Ticket(acct["node"], id) != acct["ticket"] {
					t.Error("the protest's ticket id names another ticket")
				}
				ix = d.Protest(acct["payer"], op, n, id, args.bytes("receipt"), uint8(args.num("reason")))
			case "withdraw_payout":
				op, n := nodeIDs()
				ix = d.WithdrawPayout(op, n, ownerOf("owner_usdc"))
			case "sweep_fees":
				op, n := nodeIDs()
				ix = d.SweepFees(op, n, ownerOf("treasury_usdc"))
			case "deposit_rent":
				ix = d.DepositRent(acct["payer"], args.u64("amount"))
			case "withdraw_rent":
				ix = d.WithdrawRent(acct["payer"], args.u64("amount"))
			case "close_rent_pool":
				ix = d.CloseRentPool(acct["payer"])
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

// The payer's ack the program checked: the claim hash of the settle's own
// fields, the digest over it, and the Ed25519 precompile instruction signing
// exactly that digest with the payer's key. A payer that computes another
// digest signs an ack the program refuses.
func TestAckDigestFixture(t *testing.T) {
	type ackTx struct {
		txFixture
		OpenSeq   string `json:"open_seq"`
		ClaimHash string `json:"claim_hash_hex"`
		AckDigest string `json:"ack_digest_hex"`
	}
	var f struct {
		ProgramID solana.PublicKey `json:"program_id"`
		Context   struct {
			GenesisHash string `json:"genesis_hash"`
		} `json:"context"`
		Transactions []ackTx `json:"transactions"`
	}
	readFixture(t, "solana_tx_vectors.json", &f)
	d := zsescrow.Deployment{Program: f.ProgramID}
	genesis := solana.Hash(mustHex(t, f.Context.GenesisHash))
	settleDisc := zsescrow.Discriminator("global", "settle_cooperative")
	seen := 0
	for _, tx := range f.Transactions {
		if tx.AckDigest == "" {
			continue
		}
		seen++
		t.Run(tx.Name, func(t *testing.T) {
			var settle, precompile *solana.Instruction
			for _, ix := range tx.instructions(t) {
				switch {
				case ix.ProgramID == d.Program && bytes.HasPrefix(ix.Data, settleDisc[:]):
					settle = &ix
				case ix.ProgramID == solana.Ed25519ProgramID:
					precompile = &ix
				}
			}
			if settle == nil || precompile == nil {
				t.Fatal("no settle_cooperative beside an Ed25519 instruction")
			}
			claim := zsescrow.ClaimHash(claimFieldsOf(t, settle.Data[8:]))
			if hex.EncodeToString(claim[:]) != tx.ClaimHash {
				t.Errorf("claim hash %x, fixture %s", claim, tx.ClaimHash)
			}
			openSeq, err := strconv.ParseUint(tx.OpenSeq, 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			const ticketAt = 4
			digest := d.AckDigest(genesis, settle.Accounts[ticketAt].PublicKey, openSeq, claim)
			if hex.EncodeToString(digest[:]) != tx.AckDigest {
				t.Errorf("ack digest %x, fixture %s", digest, tx.AckDigest)
			}
			signed, by := ed25519Message(t, precompile.Data)
			if !bytes.Equal(signed, digest[:]) || by != solana.MustPublicKey(tx.Payer) {
				t.Errorf("the precompile signs %x by %s, want the digest by the payer %s", signed, by, tx.Payer)
			}
		})
	}
	if seen == 0 {
		t.Fatal("no transaction carries an ack digest")
	}
}

// The protest of a pending ticket the program accepted. The protest carries
// no claim fields, the node's Ed25519 instruction signs the receipt's digest,
// and the pending claim the ticket holds carries that same digest: sha256 of
// the receipt's canonical bytes, as ticket.ReceiptSigDigest computes it and
// ClaimFromReceipt puts it in a claim. A payer computing another digest
// would protest a receipt the program refuses as ReceiptNotPending.
func TestProtestPendingFixture(t *testing.T) {
	type protestTx struct {
		txFixture
		Program       string `json:"program"`
		ReceiptDigest string `json:"receipt_digest_hex"`
	}
	var f struct {
		ProgramID    solana.PublicKey `json:"program_id"`
		Transactions []protestTx      `json:"transactions"`
	}
	readFixture(t, "solana_tx_vectors.json", &f)
	protestDisc := zsescrow.Discriminator("global", "protest")
	for _, tx := range f.Transactions {
		if tx.Name != "protest_pending" {
			continue
		}
		if tx.Program != "ok" {
			t.Fatalf("the program refused it: %s", tx.Program)
		}
		var protest, precompile *solana.Instruction
		for _, ix := range tx.instructions(t) {
			switch {
			case ix.ProgramID == f.ProgramID && bytes.HasPrefix(ix.Data, protestDisc[:]):
				protest = &ix
			case ix.ProgramID == solana.Ed25519ProgramID:
				precompile = &ix
			}
		}
		if protest == nil || precompile == nil {
			t.Fatal("no protest beside an Ed25519 instruction")
		}
		// ticket_id, then the receipt as a u32-prefixed vector and the
		// reason, and nothing after.
		args := protest.Data[8+16:]
		n := int(binary.LittleEndian.Uint32(args))
		if len(args) != 4+n+1 {
			t.Fatalf("protest arguments of %d bytes, receipt of %d", len(args), n)
		}
		receipt := args[4 : 4+n]
		var fields map[string]any
		if err := json.Unmarshal(tx.ClaimFields, &fields); err != nil {
			t.Fatal(err)
		}
		pending := argReader{t, map[string]any{"pending": fields}}.claim("pending")
		var r ticket.UsageReceipt
		if err := json.Unmarshal(tx.Receipt, &r); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(r.CanonicalBytes(), receipt) {
			t.Fatal("the protest's receipt is not the receipt value's canonical bytes")
		}
		digest := ticket.ReceiptSigDigest(&r)
		if digest != pending.ReceiptDigest || hex.EncodeToString(digest[:]) != tx.ReceiptDigest {
			t.Errorf("receipt digest %x, pending names %x, fixture %s", digest, pending.ReceiptDigest, tx.ReceiptDigest)
		}
		if zsescrow.ClaimFromReceipt(&r) != pending {
			t.Errorf("the pending claim is not the receipt's: %+v", pending)
		}
		if signed, _ := ed25519Message(t, precompile.Data); !bytes.Equal(signed, digest[:]) {
			t.Errorf("the precompile signs %x, not the receipt's digest", signed)
		}
		return
	}
	t.Fatal("no protest_pending transaction")
}

// The Ed25519 instruction of each protest the program accepted is the one
// solana.Ed25519Verify builds from the receipt: its signature by the node's
// key over its digest. The program reads that layout and no other, so a
// builder off by an offset protests nothing.
func TestProtestPrecompileFixtures(t *testing.T) {
	type protestTx struct {
		txFixture
		Program string `json:"program"`
	}
	var f struct {
		Transactions []protestTx `json:"transactions"`
	}
	readFixture(t, "solana_tx_vectors.json", &f)
	seen := 0
	for _, tx := range f.Transactions {
		if tx.Name != "protest" && tx.Name != "protest_pending" {
			continue
		}
		seen++
		if tx.Program != "ok" {
			t.Fatalf("%s: the program refused it: %s", tx.Name, tx.Program)
		}
		var precompile *solana.Instruction
		for _, ix := range tx.instructions(t) {
			if ix.ProgramID == solana.Ed25519ProgramID {
				precompile = &ix
			}
		}
		if precompile == nil {
			t.Fatalf("%s: no Ed25519 instruction", tx.Name)
		}
		var r ticket.UsageReceipt
		if err := json.Unmarshal(tx.Receipt, &r); err != nil {
			t.Fatal(err)
		}
		sig, err := base64.StdEncoding.DecodeString(r.Sig)
		if err != nil || len(sig) != 64 {
			t.Fatalf("%s: the receipt's signature: %d bytes, %v", tx.Name, len(sig), err)
		}
		digest := ticket.ReceiptSigDigest(&r)
		_, node := ed25519Message(t, precompile.Data)
		if !solana.VerifyStrict(node, digest[:], solana.Signature(sig)) {
			t.Fatalf("%s: the receipt's signature is not the node's over its digest", tx.Name)
		}
		got := solana.Ed25519Verify(node, solana.Signature(sig), digest[:])
		if got.ProgramID != precompile.ProgramID || len(got.Accounts) != 0 || !bytes.Equal(got.Data, precompile.Data) {
			t.Errorf("%s: built %x, the program accepted %x", tx.Name, got.Data, precompile.Data)
		}
	}
	if seen != 2 {
		t.Fatalf("%d protest transactions, want 2", seen)
	}
}

// claimFieldsOf reads ClaimFields from the head of an instruction's
// arguments, in the program's Borsh order.
func claimFieldsOf(t *testing.T, b []byte) zsescrow.ClaimFields {
	if len(b) < 82 {
		t.Fatalf("claim fields of %d bytes", len(b))
	}
	le := func(at int) uint64 { return binary.LittleEndian.Uint64(b[at:]) }
	return zsescrow.ClaimFields{
		Amount: le(0), ReceiptDigest: [32]byte(b[8:40]), TTFTMs: le(40), DecodeMs: le(48),
		InputUnits: le(56), OutputUnits: le(64), OutputUsageType: b[72], AuxUsageType: b[73], AuxCount: le(74),
	}
}

// ed25519Message reads the one signature an Ed25519 precompile instruction
// verifies: the message it signs and the key, each at an offset in the
// instruction's own data.
func ed25519Message(t *testing.T, data []byte) ([]byte, solana.PublicKey) {
	if len(data) < 16 || data[0] != 1 {
		t.Fatalf("an Ed25519 instruction of %d bytes, not one signature", len(data))
	}
	u16 := func(at int) int { return int(binary.LittleEndian.Uint16(data[at:])) }
	const own = 0xffff
	if u16(4) != own || u16(8) != own || u16(14) != own {
		t.Fatal("the precompile reads another instruction's data")
	}
	pk, msg, size := u16(6), u16(10), u16(12)
	if pk+32 > len(data) || msg+size > len(data) {
		t.Fatal("the precompile's offsets run past its data")
	}
	return data[msg : msg+size], solana.PublicKey(data[pk : pk+32])
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
