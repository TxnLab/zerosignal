/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package escrow

// Cross-impl vectors for the payer's checks on a node-built group:
// proto/testdata/escrow_group_vectors.json. Each case is an open or settle
// group as it arrives on the wire (base64 msgpack of []SignedTxn) and the
// Field of the rejection VerifyOpenGroup / VerifySettleGroup returns, or null.
// The valid group is the composer's real output; every other case breaks one
// guard and then re-groups and re-signs, so that guard and no other is what
// refuses it. @txnlab/zerosignal's verifiers read the same file.
//
// Regenerate after an intentional change with:
//
//	cd proto/go && go test ./escrow -run TestGroupVectors -update

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

const groupVectorsPath = "../../testdata/escrow_group_vectors.json"

type openSpecVector struct {
	AppID                  uint64 `json:"app_id"`
	AppAddress             string `json:"app_address"`
	TicketIDB64            string `json:"ticket_id_b64"`
	OperatorID             uint64 `json:"operator_id"`
	NodeID                 uint64 `json:"node_id"`
	MaxPrice               uint64 `json:"max_price"`
	UsdcAssetID            uint64 `json:"usdc_asset_id"`
	NodeSigningAddr        string `json:"node_signing_addr"`
	PayerAddr              string `json:"payer_addr"`
	ExpiresAt              uint64 `json:"expires_at"`
	SettlementGraceSeconds uint64 `json:"settlement_grace_seconds"`
}

type groupCaseVector struct {
	Name     string `json:"name"`
	GroupB64 string `json:"group_b64"`
	// Expected is the rejecting check's Field, or null when the group passes.
	Expected *string `json:"expected"`
}

type groupVectorsFile struct {
	Version int    `json:"version"`
	Comment string `json:"comment"`
	// Selectors pin the method signatures the TS side hard-codes.
	Selectors map[string]string `json:"selectors"`
	Open      struct {
		Spec  openSpecVector    `json:"spec"`
		Cases []groupCaseVector `json:"cases"`
		// Completed is the valid group as a payer hands it to a node that
		// submits the open (wire.SubmitsOpen). ed25519 is deterministic, so a
		// port signing with the same payer key must produce these bytes.
		Completed completedGroupVector `json:"completed"`
	} `json:"open"`
	Settle struct {
		Spec  settleSpecVector  `json:"spec"`
		Cases []groupCaseVector `json:"cases"`
		// Completed is the valid group as a payer hands it to a node that
		// takes the settle ack (wire.TakesSettleAck).
		Completed completedGroupVector `json:"completed"`
	} `json:"settle"`
}

// payerSeed is the byte vectorKey repeats into the payer's ed25519 seed.
const payerSeed = 2

type completedGroupVector struct {
	PayerSeed byte `json:"payer_seed"`
	// Encoded is the completed group in EncodeOpenGroup / EncodeSettleGroup
	// form, as CompletePresignedOpenGroup / CompletePresignedSettleGroup
	// return it.
	Encoded string `json:"encoded"`
}

type settleSpecVector struct {
	AppID               uint64 `json:"app_id"`
	TicketIDB64         string `json:"ticket_id_b64"`
	AmountCharged       uint64 `json:"amount_charged"`
	ReceiptDigestB64    string `json:"receipt_digest_b64"`
	TtftMs              uint64 `json:"ttft_ms"`
	DecodeMs            uint64 `json:"decode_ms"`
	InputCount          uint64 `json:"input_count"`
	OutputCount         uint64 `json:"output_count"`
	OutputUsageType     uint64 `json:"output_usage_type"`
	AuxOutputUsageType  uint64 `json:"aux_output_usage_type"`
	AuxOutputCount      uint64 `json:"aux_output_count"`
	PayerAddr           string `json:"payer_addr"`
	OperatorSigningAddr string `json:"operator_signing_addr"`
}

func vectorKey(seed byte) (ed25519.PrivateKey, types.Address) {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed
	}
	sk := ed25519.NewKeyFromSeed(s)
	var a types.Address
	copy(a[:], sk.Public().(ed25519.PublicKey))
	return sk, a
}

// regroup recomputes the group id over the members as they now stand and
// re-signs the node's app call, the way a node would hand over a group it
// built that way on purpose.
func regroup(t *testing.T, g []types.SignedTxn, nodeSK ed25519.PrivateKey, appCall int) []types.SignedTxn {
	t.Helper()
	txns := make([]types.Transaction, len(g))
	for i := range g {
		txns[i] = g[i].Txn
		txns[i].Group = types.Digest{}
	}
	gid, err := crypto.ComputeGroupID(txns)
	if err != nil {
		t.Fatalf("group id: %v", err)
	}
	out := make([]types.SignedTxn, len(g))
	for i := range g {
		txns[i].Group = gid
		out[i] = types.SignedTxn{Txn: txns[i]}
		if i == appCall {
			_, raw, err := crypto.SignTransaction(nodeSK, txns[i])
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			if err := msgpack.Decode(raw, &out[i]); err != nil {
				t.Fatalf("decode signed: %v", err)
			}
		}
	}
	return out
}

// wireTxn returns a generically decoded member's txn map, normalized to
// string keys so a case can set one and the map re-encodes canonically. The
// generic decode reads msgpack strings as []byte, so the txn's two string
// fields are turned back into strings or they would re-encode as bin.
func wireTxn(member map[string]any) map[string]any {
	var out map[string]any
	switch txn := member["txn"].(type) {
	case map[string]any:
		return txn
	case map[any]any:
		out = make(map[string]any, len(txn))
		for k, v := range txn {
			key := k.(string)
			if b, ok := v.([]byte); ok && (key == "type" || key == "gen") {
				v = string(b)
			}
			out[key] = v
		}
	default:
		panic("wireTxn: member has no txn map")
	}
	member["txn"] = out
	return out
}

// regroupWire sets a group id hashed over the members' bytes exactly as they
// stand, which differs from algod's whenever they aren't canonical.
func regroupWire(m []map[string]any) {
	txlist := make([][]byte, len(m))
	for i := range m {
		bare := maps.Clone(wireTxn(m[i]))
		delete(bare, "grp")
		h := sha512.Sum512_256(append([]byte("TX"), msgpack.Encode(bare)...))
		txlist[i] = h[:]
	}
	gid := sha512.Sum512_256(append([]byte("TG"), msgpack.Encode(map[string]any{"txlist": txlist})...))
	for i := range m {
		wireTxn(m[i])["grp"] = gid[:]
	}
}

func cloneGroup(g []types.SignedTxn) []types.SignedTxn {
	out := make([]types.SignedTxn, len(g))
	for i := range g {
		out[i] = g[i]
		out[i].Txn.ApplicationArgs = append([][]byte(nil), g[i].Txn.ApplicationArgs...)
		for j, a := range out[i].Txn.ApplicationArgs {
			out[i].Txn.ApplicationArgs[j] = append([]byte(nil), a...)
		}
	}
	return out
}

func buildGroupVectors(t *testing.T) *groupVectorsFile {
	t.Helper()
	nodeSK, nodeAddr := vectorKey(1)
	payerSK, payerAddr := vectorKey(payerSeed)
	_, otherAddr := vectorKey(3)

	algod, _ := newFakeAlgodForCompose(t)
	c, err := NewClient(1001, algod)
	if err != nil {
		t.Fatal(err)
	}
	c.TicketMbr, c.UsdcAssetID = 34_100, 10458941

	ticketID := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	args := OpenArgs{
		TicketIDRaw: ticketID, OperatorID: 7, NodeID: 3, PayerAddr: payerAddr.String(),
		MaxPrice: 4040, ExpiresAt: 1_900_000_000,
	}
	signer := transaction.BasicAccountTransactionSigner{Account: crypto.Account{PrivateKey: nodeSK, Address: nodeAddr}}
	valid, err := c.ComposeOpenGroup(context.Background(), args, signer, nodeAddr.String())
	if err != nil {
		t.Fatalf("ComposeOpenGroup: %v", err)
	}
	spec := OpenGroupSpec{
		AppID: c.AppID, AppAddress: c.AppAddr, TicketIDRaw: ticketID,
		OperatorID: args.OperatorID, NodeID: args.NodeID, MaxPrice: args.MaxPrice,
		TicketMbr: c.TicketMbr, UsdcAssetID: c.UsdcAssetID,
		NodeSigningAddr: nodeAddr, PayerAddr: payerAddr, ExpiresAt: args.ExpiresAt,
	}

	pay, app := onMember(0), onMember(1)
	cases := []groupMutation{
		{name: "valid", mut: keep, raw: true},
		{name: "size_one", mut: func(g []types.SignedTxn) []types.SignedTxn { return g[:1] }, raw: true},
		{name: "size_three", mut: func(g []types.SignedTxn) []types.SignedTxn { return append(g, g[1]) }, raw: true},
		{name: "group_id_zero", raw: true, mut: func(g []types.SignedTxn) []types.SignedTxn {
			g[0].Txn.Group, g[1].Txn.Group = types.Digest{}, types.Digest{}
			return g
		}},
		{name: "group_id_differs_across_members", raw: true, mut: app(func(x *types.Transaction) { x.Group[0] ^= 1 })},
		// The gid still names the honest members; the app call shown is another.
		{name: "group_id_not_over_members", raw: true, mut: app(func(x *types.Transaction) { x.Note = []byte("x") })},

		{name: "payer_not_axfer", mut: pay(func(x *types.Transaction) {
			x.Type = types.PaymentTx
			x.Receiver, x.Amount = x.AssetReceiver, types.MicroAlgos(x.AssetAmount)
			x.AssetReceiver, x.AssetAmount, x.XferAsset = types.Address{}, 0, 0
		})},
		{name: "payer_rekey", mut: pay(func(x *types.Transaction) { x.RekeyTo = otherAddr })},
		{name: "payer_asset_close_to", mut: pay(func(x *types.Transaction) { x.AssetCloseTo = otherAddr })},
		{name: "payer_asset_sender", mut: pay(func(x *types.Transaction) { x.AssetSender = otherAddr })},
		{name: "payer_close_remainder_to", mut: pay(func(x *types.Transaction) { x.CloseRemainderTo = otherAddr })},
		{name: "payer_payment_fields", mut: pay(func(x *types.Transaction) { x.Receiver, x.Amount = otherAddr, 1 })},
		{name: "payer_app_fields", mut: pay(func(x *types.Transaction) { x.ApplicationID = 5 })},
		// An explicit zero is not in the canonical form the txid hashes, so the
		// honest gid still commits to the member.
		{name: "payer_explicit_zero_fee", raw: true, mut: keep, wire: func(m []map[string]any) { wireTxn(m[0])["fee"] = uint64(0) }},
		{name: "payer_explicit_zero_close", raw: true, mut: keep, wire: func(m []map[string]any) { wireTxn(m[0])["close"] = make([]byte, 32) }},
		{name: "open_explicit_empty_note", raw: true, mut: keep, wire: func(m []map[string]any) { wireTxn(m[1])["note"] = []byte{} }},
		// A gid taken over the non-canonical bytes commits to txids algod
		// never computes.
		{name: "group_id_over_explicit_zero", raw: true, mut: keep, wire: func(m []map[string]any) {
			wireTxn(m[0])["fee"] = uint64(0)
			regroupWire(m)
		}},
		{name: "payer_fee", mut: pay(func(x *types.Transaction) { x.Fee = 1000 })},
		{name: "payer_note", mut: pay(func(x *types.Transaction) { x.Note = []byte("hi") })},
		{name: "payer_lease", mut: pay(func(x *types.Transaction) { x.Lease[0] = 1 })},
		{name: "payer_sender", mut: pay(func(x *types.Transaction) { x.Sender = otherAddr })},
		{name: "payer_receiver", mut: pay(func(x *types.Transaction) { x.AssetReceiver = otherAddr })},
		{name: "payer_asset", mut: pay(func(x *types.Transaction) { x.XferAsset++ })},
		{name: "payer_amount", mut: pay(func(x *types.Transaction) { x.AssetAmount++ })},

		{name: "open_not_appl", mut: app(func(x *types.Transaction) {
			*x = types.Transaction{Type: types.PaymentTx, Header: x.Header, PaymentTxnFields: types.PaymentTxnFields{Receiver: otherAddr, Amount: 1}}
		})},
		{name: "open_app_id", mut: app(func(x *types.Transaction) { x.ApplicationID++ })},
		{name: "open_sender", mut: app(func(x *types.Transaction) { x.Sender = otherAddr })},
		{name: "open_no_args", mut: app(func(x *types.Transaction) { x.ApplicationArgs = nil })},
		{name: "open_selector", mut: app(func(x *types.Transaction) { x.ApplicationArgs[0][0] ^= 1 })},
		{name: "open_too_few_args", mut: app(func(x *types.Transaction) { x.ApplicationArgs = x.ApplicationArgs[:5] })},
		{name: "open_ticket_id", mut: app(func(x *types.Transaction) { x.ApplicationArgs[1][17] ^= 1 })},
		{name: "open_ticket_id_prefix", mut: app(func(x *types.Transaction) { x.ApplicationArgs[1][1]++ })},
		{name: "open_ticket_id_short", mut: app(func(x *types.Transaction) { x.ApplicationArgs[1] = []byte{0} })},
		// A self-consistent prefix over 15 bytes: only the length check names it.
		{name: "open_ticket_id_length", mut: app(func(x *types.Transaction) {
			x.ApplicationArgs[1] = append([]byte{0, 15}, x.ApplicationArgs[1][2:17]...)
		})},
		{name: "open_operator_id", mut: app(func(x *types.Transaction) { x.ApplicationArgs[2] = u64arg(8) })},
		{name: "open_operator_id_width", mut: app(func(x *types.Transaction) { x.ApplicationArgs[2] = x.ApplicationArgs[2][1:] })},
		{name: "open_node_id", mut: app(func(x *types.Transaction) { x.ApplicationArgs[3] = u64arg(4) })},
		{name: "open_node_id_width", mut: app(func(x *types.Transaction) { x.ApplicationArgs[3] = x.ApplicationArgs[3][1:] })},
		{name: "open_payer_addr", mut: app(func(x *types.Transaction) { x.ApplicationArgs[4] = otherAddr[:] })},
		{name: "open_payer_addr_width", mut: app(func(x *types.Transaction) { x.ApplicationArgs[4] = x.ApplicationArgs[4][1:] })},
		{name: "open_max_price", mut: app(func(x *types.Transaction) { x.ApplicationArgs[5] = u64arg(4041) })},
		{name: "open_max_price_width", mut: app(func(x *types.Transaction) { x.ApplicationArgs[5] = append(x.ApplicationArgs[5], 0) })},
		{name: "open_clear_state", mut: app(func(x *types.Transaction) { x.OnCompletion = types.ClearStateOC })},
		{name: "open_opt_in", mut: app(func(x *types.Transaction) { x.OnCompletion = types.OptInOC })},
		{name: "open_close_out", mut: app(func(x *types.Transaction) { x.OnCompletion = types.CloseOutOC })},
		{name: "open_update", mut: app(func(x *types.Transaction) { x.OnCompletion = types.UpdateApplicationOC })},
		{name: "open_delete", mut: app(func(x *types.Transaction) { x.OnCompletion = types.DeleteApplicationOC })},
		{name: "open_no_window_args", mut: app(func(x *types.Transaction) { x.ApplicationArgs = x.ApplicationArgs[:7] })},
		{name: "open_expires_at", mut: app(func(x *types.Transaction) { x.ApplicationArgs[6] = u64arg(1_900_000_001) })},
		{name: "open_expires_at_width", mut: app(func(x *types.Transaction) { x.ApplicationArgs[6] = x.ApplicationArgs[6][1:] })},
		{name: "open_grace", mut: app(func(x *types.Transaction) { x.ApplicationArgs[7] = u64arg(1) })},
		{name: "open_grace_width", mut: app(func(x *types.Transaction) { x.ApplicationArgs[7] = []byte{} })},
		// The node's fee is its own business: an over-fee passes.
		{name: "open_node_fee_unchecked", mut: app(func(x *types.Transaction) { x.Fee = 50_000 })},
	}

	f := &groupVectorsFile{
		Version: 2,
		Comment: "Payer-side checks on a node-built escrow group: the rejecting check's field, or null. " +
			"Regenerate via: cd proto/go && go test ./escrow -run TestGroupVectors -update. " +
			"Loaded by proto/go/escrow/group_vectors_test.go and proto/sdk/test/escrow-{open,settle}.test.ts.",
		Selectors: map[string]string{},
	}
	for _, m := range []string{"open", "settle"} {
		sel, err := MethodSelector(m)
		if err != nil {
			t.Fatal(err)
		}
		f.Selectors[m] = hex.EncodeToString(sel)
	}
	f.Open.Spec = openSpecVector{
		AppID: spec.AppID, AppAddress: spec.AppAddress.String(), TicketIDB64: base64.StdEncoding.EncodeToString(ticketID),
		OperatorID: spec.OperatorID, NodeID: spec.NodeID, MaxPrice: spec.MaxPrice, UsdcAssetID: spec.UsdcAssetID,
		NodeSigningAddr: nodeAddr.String(), PayerAddr: payerAddr.String(),
		ExpiresAt: spec.ExpiresAt, SettlementGraceSeconds: spec.SettlementGraceSeconds,
	}
	f.Open.Cases = emitCases(t, cases, valid, nodeSK, 1, func(g []types.SignedTxn) *string {
		err := VerifyOpenGroup(g, spec)
		if err == nil {
			return nil
		}
		var rej *OpenGroupRejectedError
		if !errors.As(err, &rej) {
			t.Fatalf("untyped open rejection %v", err)
		}
		return &rej.Field
	})
	payerSigner := transaction.BasicAccountTransactionSigner{Account: crypto.Account{PrivateKey: payerSK, Address: payerAddr}}
	done, err := c.CompletePresignedOpenGroup(cloneGroup(valid), payerSigner, spec)
	if err != nil {
		t.Fatalf("CompletePresignedOpenGroup: %v", err)
	}
	if _, err := DecodeOpenGroup(done.Encoded); err != nil {
		t.Fatalf("DecodeOpenGroup(Encoded): %v", err)
	}
	f.Open.Completed = completedGroupVector{PayerSeed: payerSeed, Encoded: done.Encoded}
	buildSettleVectors(t, f, c, nodeSK, nodeAddr, payerSK, payerAddr, otherAddr)
	return f
}

// groupMutation is one vector case: an edit to a copy of the valid group.
type groupMutation struct {
	name string
	// mut edits a copy of the valid group; the result is regrouped unless raw.
	mut func(g []types.SignedTxn) []types.SignedTxn
	raw bool
	// wire edits the encoded members as generic maps, for encodings Go's
	// struct can't produce (an explicit zero that canonical form omits).
	wire func(m []map[string]any)
}

func keep(g []types.SignedTxn) []types.SignedTxn { return g }

func onMember(i int) func(func(*types.Transaction)) func([]types.SignedTxn) []types.SignedTxn {
	return func(f func(*types.Transaction)) func([]types.SignedTxn) []types.SignedTxn {
		return func(g []types.SignedTxn) []types.SignedTxn { f(&g[i].Txn); return g }
	}
}

func u64arg(v uint64) []byte {
	b := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
	return b
}

// emitCases applies each mutation, re-signing member signed with nodeSK, and
// records the verdict on the group as it decodes from the wire, the way a
// payer receives it.
func emitCases(t *testing.T, cases []groupMutation, valid []types.SignedTxn, nodeSK ed25519.PrivateKey, signed int, verdict func([]types.SignedTxn) *string) []groupCaseVector {
	t.Helper()
	var out []groupCaseVector
	for _, m := range cases {
		g := m.mut(cloneGroup(valid))
		if !m.raw {
			g = regroup(t, g, nodeSK, signed)
		}
		wire := msgpack.Encode(g)
		if m.wire != nil {
			var w []map[string]any
			if err := msgpack.Decode(wire, &w); err != nil {
				t.Fatalf("%s: decode to maps: %v", m.name, err)
			}
			for i := range w {
				wireTxn(w[i])
			}
			m.wire(w)
			wire = msgpack.Encode(w)
		}
		g = nil
		if err := msgpack.Decode(wire, &g); err != nil {
			t.Fatalf("%s: decode: %v", m.name, err)
		}
		out = append(out, groupCaseVector{Name: m.name, GroupB64: base64.StdEncoding.EncodeToString(wire), Expected: verdict(g)})
	}
	return out
}

// buildSettleVectors adds the settle group: ComposeSettleGroup's real output
// (operator half signed, payer ack unsigned) and one variant per guard. Each
// per-member guard runs on both halves, since VerifySettleGroup checks them
// with the same code and a port could still wire one half wrong.
func buildSettleVectors(t *testing.T, f *groupVectorsFile, c *Client, nodeSK ed25519.PrivateKey, nodeAddr types.Address, payerSK ed25519.PrivateKey, payerAddr, otherAddr types.Address) {
	t.Helper()
	_, ownerAddr := vectorKey(4)
	_, treasuryAddr := vectorKey(5)
	c.Treasury = treasuryAddr.String()

	ticketID := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	var digest [32]byte
	for i := range digest {
		digest[i] = byte(0xa0 + i)
	}
	args := SettleArgs{
		TicketIDRaw: ticketID, AmountCharged: 3030, MaxPrice: 4040, ReceiptDigest: digest,
		TtftMs: 1200, DecodeMs: 300, InputCount: 250, OutputCount: 750,
		OutputUsageType: 1, AuxOutputUsageType: 2, AuxOutputCount: 1,
		PayerAddr: payerAddr.String(), OperatorOwnerAddr: ownerAddr.String(), OperatorID: 7, NodeID: 3,
	}
	signer := transaction.BasicAccountTransactionSigner{Account: crypto.Account{PrivateKey: nodeSK, Address: nodeAddr}}
	valid, err := c.ComposeSettleGroup(context.Background(), args, signer, nodeAddr.String())
	if err != nil {
		t.Fatalf("ComposeSettleGroup: %v", err)
	}
	spec := SettleGroupSpec{
		AppID: c.AppID, TicketIDRaw: ticketID, AmountCharged: args.AmountCharged, ReceiptDigest: digest,
		TtftMs: args.TtftMs, DecodeMs: args.DecodeMs, InputCount: args.InputCount, OutputCount: args.OutputCount,
		OutputUsageType: args.OutputUsageType, AuxOutputUsageType: args.AuxOutputUsageType, AuxOutputCount: args.AuxOutputCount,
		PayerAddr: payerAddr, OperatorSigningAddr: nodeAddr,
	}

	op, ack := onMember(0), onMember(1)
	cases := []groupMutation{
		{name: "valid", mut: keep, raw: true},
		{name: "size_one", mut: func(g []types.SignedTxn) []types.SignedTxn { return g[:1] }, raw: true},
		{name: "size_three", mut: func(g []types.SignedTxn) []types.SignedTxn { return append(g, g[1]) }, raw: true},
		{name: "group_id_zero", raw: true, mut: func(g []types.SignedTxn) []types.SignedTxn {
			g[0].Txn.Group, g[1].Txn.Group = types.Digest{}, types.Digest{}
			return g
		}},
		{name: "group_id_differs_across_members", raw: true, mut: ack(func(x *types.Transaction) { x.Group[0] ^= 1 })},
		{name: "group_id_not_over_members", raw: true, mut: ack(func(x *types.Transaction) { x.ApplicationArgs[2] = u64arg(1) })},
		{name: "payer_explicit_zero_fee", raw: true, mut: keep, wire: func(m []map[string]any) { wireTxn(m[1])["fee"] = uint64(0) }},
		{name: "group_id_over_explicit_zero", raw: true, mut: keep, wire: func(m []map[string]any) {
			wireTxn(m[1])["fee"] = uint64(0)
			regroupWire(m)
		}},
		{name: "payer_fee", mut: ack(func(x *types.Transaction) { x.Fee = 1000 })},
		{name: "payer_note", mut: ack(func(x *types.Transaction) { x.Note = []byte("hi") })},
		{name: "payer_lease", mut: ack(func(x *types.Transaction) { x.Lease[0] = 1 })},
		{name: "payer_payment_fields", mut: ack(func(x *types.Transaction) { x.Receiver, x.Amount = otherAddr, 1 })},
		{name: "payer_close_remainder_to", mut: ack(func(x *types.Transaction) { x.CloseRemainderTo = otherAddr })},
		{name: "payer_extra_arg", mut: ack(func(x *types.Transaction) { x.ApplicationArgs = append(x.ApplicationArgs, []byte("tag")) })},
		// The operator funds its half and its note and spare args are its own:
		// none is checked.
		{name: "operator_fee_unchecked", mut: op(func(x *types.Transaction) { x.Fee = 50_000 })},
		{name: "operator_note_unchecked", mut: op(func(x *types.Transaction) { x.Note = []byte("hi") })},
		{name: "operator_extra_arg_unchecked", mut: op(func(x *types.Transaction) { x.ApplicationArgs = append(x.ApplicationArgs, []byte("tag")) })},
	}
	for _, r := range []struct {
		role   string
		member func(func(*types.Transaction)) func([]types.SignedTxn) []types.SignedTxn
	}{{"operator", op}, {"payer", ack}} {
		m := r.member
		arg := func(i int, v []byte) func([]types.SignedTxn) []types.SignedTxn {
			return m(func(x *types.Transaction) { x.ApplicationArgs[i] = v })
		}
		cases = append(cases,
			groupMutation{name: r.role + "_not_appl", mut: m(func(x *types.Transaction) {
				*x = types.Transaction{Type: types.PaymentTx, Header: x.Header, PaymentTxnFields: types.PaymentTxnFields{Receiver: otherAddr, Amount: 1}}
			})},
			groupMutation{name: r.role + "_app_id", mut: m(func(x *types.Transaction) { x.ApplicationID++ })},
			groupMutation{name: r.role + "_rekey", mut: m(func(x *types.Transaction) { x.RekeyTo = otherAddr })},
			groupMutation{name: r.role + "_clear_state", mut: m(func(x *types.Transaction) { x.OnCompletion = types.ClearStateOC })},
			groupMutation{name: r.role + "_close_out", mut: m(func(x *types.Transaction) { x.OnCompletion = types.CloseOutOC })},
			groupMutation{name: r.role + "_sender", mut: m(func(x *types.Transaction) { x.Sender = otherAddr })},
			groupMutation{name: r.role + "_too_few_args", mut: m(func(x *types.Transaction) { x.ApplicationArgs = x.ApplicationArgs[:11] })},
			groupMutation{name: r.role + "_selector", mut: m(func(x *types.Transaction) { x.ApplicationArgs[0][0] ^= 1 })},
			groupMutation{name: r.role + "_ticket_id", mut: m(func(x *types.Transaction) { x.ApplicationArgs[1][17] ^= 1 })},
			groupMutation{name: r.role + "_ticket_id_prefix", mut: m(func(x *types.Transaction) { x.ApplicationArgs[1][1]++ })},
			groupMutation{name: r.role + "_ticket_id_short", mut: arg(1, []byte{0})},
			groupMutation{name: r.role + "_amount_charged", mut: arg(2, u64arg(3031))},
			groupMutation{name: r.role + "_amount_charged_width", mut: arg(2, u64arg(3030)[1:])},
			groupMutation{name: r.role + "_receipt_digest", mut: m(func(x *types.Transaction) { x.ApplicationArgs[3][2] ^= 1 })},
			groupMutation{name: r.role + "_ttft_ms", mut: arg(4, u64arg(1201))},
			groupMutation{name: r.role + "_decode_ms", mut: arg(5, u64arg(301))},
			groupMutation{name: r.role + "_input_count", mut: arg(6, u64arg(251))},
			groupMutation{name: r.role + "_output_count", mut: arg(7, u64arg(751))},
			groupMutation{name: r.role + "_output_usage_type", mut: arg(8, u64arg(2))},
			groupMutation{name: r.role + "_aux_output_usage_type", mut: arg(9, u64arg(0))},
			groupMutation{name: r.role + "_aux_output_count", mut: arg(10, u64arg(2))},
			groupMutation{name: r.role + "_as_operator_flipped", mut: m(func(x *types.Transaction) { x.ApplicationArgs[11][0] ^= 0x80 })},
			groupMutation{name: r.role + "_as_operator_width", mut: m(func(x *types.Transaction) { x.ApplicationArgs[11] = append(x.ApplicationArgs[11], 0) })},
		)
	}

	f.Settle.Spec = settleSpecVector{
		AppID: spec.AppID, TicketIDB64: base64.StdEncoding.EncodeToString(ticketID),
		AmountCharged: spec.AmountCharged, ReceiptDigestB64: base64.StdEncoding.EncodeToString(digest[:]),
		TtftMs: spec.TtftMs, DecodeMs: spec.DecodeMs, InputCount: spec.InputCount, OutputCount: spec.OutputCount,
		OutputUsageType: spec.OutputUsageType, AuxOutputUsageType: spec.AuxOutputUsageType, AuxOutputCount: spec.AuxOutputCount,
		PayerAddr: payerAddr.String(), OperatorSigningAddr: nodeAddr.String(),
	}
	f.Settle.Cases = emitCases(t, cases, valid, nodeSK, 0, func(g []types.SignedTxn) *string {
		err := VerifySettleGroup(g, spec)
		if err == nil {
			return nil
		}
		var rej *SettleGroupRejectedError
		if !errors.As(err, &rej) {
			t.Fatalf("untyped settle rejection %v", err)
		}
		return &rej.Field
	})
	payerSigner := transaction.BasicAccountTransactionSigner{Account: crypto.Account{PrivateKey: payerSK, Address: payerAddr}}
	_, encoded, err := c.CompletePresignedSettleGroup(cloneGroup(valid), payerSigner, spec)
	if err != nil {
		t.Fatalf("CompletePresignedSettleGroup: %v", err)
	}
	if _, err := DecodeSettleGroup(encoded); err != nil {
		t.Fatalf("DecodeSettleGroup(encoded): %v", err)
	}
	f.Settle.Completed = completedGroupVector{PayerSeed: payerSeed, Encoded: encoded}
}

func TestGroupVectors(t *testing.T) {
	got, err := json.MarshalIndent(buildGroupVectors(t), "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got = append(got, '\n')
	if *updateEscrowVectors {
		if err := os.WriteFile(groupVectorsPath, got, 0o644); err != nil {
			t.Fatalf("write %s: %v", groupVectorsPath, err)
		}
		t.Logf("wrote %s", groupVectorsPath)
		return
	}
	want, err := os.ReadFile(groupVectorsPath)
	if err != nil {
		t.Fatalf("read %s (regenerate with -update): %v", groupVectorsPath, err)
	}
	if !bytes.Equal(want, got) {
		t.Fatalf("%s is stale. If intentional, run "+
			"`cd proto/go && go test ./escrow -run TestGroupVectors -update` "+
			"and port the same change to proto/sdk/src/escrow.", groupVectorsPath)
	}
}
