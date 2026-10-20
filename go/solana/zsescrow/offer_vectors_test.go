/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zsescrow_test

// The open-offer verdicts both payers must reach. Every open offer the
// program's tests wrote (solana_tx_vectors.json) is replayed with the spec a
// payer would hold, beside offers built here for the checks the program's
// shapes don't reach. Generates / verifies
// proto/testdata/solana_open_offer_vectors.json, which proto/ts replays.
//
//	cd proto/go && go test ./solana/zsescrow -run TestOpenOfferVectors -update
//
// TestOpenOfferVectorsMeanWhatTheySay checks each fixture's verdict against
// why the program's tests wrote it, and the specs against the fixtures.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
	"github.com/TxnLab/zerosignal/go/ticket"
)

const offerVectorsPath = "../../../testdata/solana_open_offer_vectors.json"

type offerFold struct {
	OperatorID string          `json:"operator_id"`
	NodeID     string          `json:"node_id"`
	TicketID   string          `json:"ticket_id"`
	Receipt    json.RawMessage `json:"receipt"`
}

type offerSpec struct {
	NodeSigning string     `json:"node_signing"`
	OperatorID  string     `json:"operator_id"`
	NodeID      string     `json:"node_id"`
	Payer       string     `json:"payer"`
	PayerUSDC   string     `json:"payer_usdc"`
	Decimals    uint8      `json:"decimals"`
	TicketID    string     `json:"ticket_id"`
	MaxPrice    string     `json:"max_price"`
	ExpiresAt   string     `json:"expires_at"`
	Fold        *offerFold `json:"fold,omitempty"`
}

type offerCase struct {
	Name    string    `json:"name"`
	About   string    `json:"about"`
	Source  string    `json:"source"`
	Message string    `json:"message_base64"`
	Spec    offerSpec `json:"spec"`
	Verdict string    `json:"verdict"`
}

type offerVectors struct {
	Version   int         `json:"version"`
	Comment   string      `json:"comment"`
	ProgramID string      `json:"program_id"`
	Mint      string      `json:"usdc_mint"`
	Cases     []offerCase `json:"cases"`
}

type txMeta struct {
	Pubkey     solana.PublicKey `json:"pubkey"`
	IsSigner   bool             `json:"is_signer"`
	IsWritable bool             `json:"is_writable"`
}

type txFixture struct {
	Name      string `json:"name"`
	About     string `json:"about"`
	Message   string `json:"message_base64"`
	Blockhash string `json:"recent_blockhash"`
	Payer     string `json:"payer"`
	Built     []struct {
		ProgramID solana.PublicKey `json:"program_id"`
		Accounts  []txMeta         `json:"accounts"`
		Data      string           `json:"data_base64"`
	} `json:"built_instructions"`
	Receipt       json.RawMessage `json:"receipt_value"`
	ReceiptHex    string          `json:"receipt_hex"`
	SettledTicket string          `json:"settled_ticket"`
	ClaimFields   json.RawMessage `json:"claim_fields"`
}

// openOf is the fixture's open, which some shapes follow with another
// instruction.
func (f txFixture) openOf(t *testing.T) solana.Instruction {
	disc := zsescrow.Discriminator("global", "open")
	for _, ix := range f.instructions(t) {
		if bytes.HasPrefix(ix.Data, disc[:]) {
			return ix
		}
	}
	t.Fatalf("%s: no open", f.Name)
	return solana.Instruction{}
}

func (f txFixture) instructions(t *testing.T) []solana.Instruction {
	var out []solana.Instruction
	for _, b := range f.Built {
		ix := solana.Instruction{ProgramID: b.ProgramID, Data: b64(t, b.Data)}
		for _, a := range b.Accounts {
			ix.Accounts = append(ix.Accounts, solana.AccountMeta{PublicKey: a.Pubkey, IsSigner: a.IsSigner, IsWritable: a.IsWritable})
		}
		out = append(out, ix)
	}
	return out
}

type offerWorld struct {
	d         zsescrow.Deployment
	decimals  uint8
	blockhash solana.Hash
	attacker  solana.PublicKey
	byName    map[string]txFixture
	order     []string
}

func loadOfferWorld(t *testing.T) offerWorld {
	var f struct {
		ProgramID solana.PublicKey `json:"program_id"`
		Context   struct {
			fixtureContext
			Decimals uint8 `json:"usdc_decimals"`
		} `json:"context"`
		Transactions []txFixture `json:"transactions"`
	}
	readFixture(t, "solana_tx_vectors.json", &f)
	w := offerWorld{d: zsescrow.Deployment{Program: f.ProgramID, Mint: f.Context.USDCMint}, decimals: f.Context.Decimals,
		attacker: f.Context.Keys["attacker"].Pubkey, byName: map[string]txFixture{}}
	for _, x := range f.Transactions {
		if strings.HasPrefix(x.Name, "open") {
			w.byName[x.Name] = x
			w.order = append(w.order, x.Name)
		}
	}
	bh, err := solana.ParseHash(w.byName["open"].Blockhash)
	if err != nil {
		t.Fatal(err)
	}
	w.blockhash = bh
	return w
}

// specFor is the spec the payer of base holds: the ticket, price and expiry
// it reserved, read here off base's open, and its previous ticket's receipt.
// TestOpenOfferVectorsMeanWhatTheySay checks those against the fixtures'
// accounts, since reading them off the offer under test proves nothing alone.
func (w offerWorld) specFor(t *testing.T, base txFixture, receiptFrom *txFixture) zsescrow.OpenOfferSpec {
	open := base.openOf(t)
	data := open.Data[8:]
	s := zsescrow.OpenOfferSpec{
		NodeSigning: open.Accounts[0].PublicKey,
		Payer:       solana.MustPublicKey(base.Payer),
		Decimals:    w.decimals,
		TicketID:    [16]byte(data[:16]),
		MaxPrice:    binary.LittleEndian.Uint64(data[48:]),
		ExpiresAt:   int64(binary.LittleEndian.Uint64(data[56:])),
	}
	s.PayerUSDC = w.d.TokenAccount(s.Payer)
	for op := uint64(1); op < 8 && s.OperatorID == 0; op++ {
		for n := uint64(1); n < 8; n++ {
			if w.d.Node(op, n) == open.Accounts[3].PublicKey {
				s.OperatorID, s.NodeID = op, n
			}
		}
	}
	if receiptFrom != nil {
		var r ticket.UsageReceipt
		if err := json.Unmarshal(receiptFrom.Receipt, &r); err != nil {
			t.Fatal(err)
		}
		s.Fold = &zsescrow.FoldSpec{OperatorID: s.OperatorID, NodeID: s.NodeID, TicketID: [16]byte(mustB64(t, r.TicketID)), Receipt: &r}
	}
	return s
}

func specJSON(t *testing.T, s zsescrow.OpenOfferSpec) offerSpec {
	j := offerSpec{
		NodeSigning: s.NodeSigning.String(), OperatorID: strconv.FormatUint(s.OperatorID, 10), NodeID: strconv.FormatUint(s.NodeID, 10),
		Payer: s.Payer.String(), PayerUSDC: s.PayerUSDC.String(), Decimals: s.Decimals, TicketID: hex.EncodeToString(s.TicketID[:]),
		MaxPrice: strconv.FormatUint(s.MaxPrice, 10), ExpiresAt: strconv.FormatInt(s.ExpiresAt, 10),
	}
	if s.Fold != nil {
		r, err := json.Marshal(s.Fold.Receipt)
		if err != nil {
			t.Fatal(err)
		}
		j.Fold = &offerFold{OperatorID: strconv.FormatUint(s.Fold.OperatorID, 10), NodeID: strconv.FormatUint(s.Fold.NodeID, 10),
			TicketID: hex.EncodeToString(s.Fold.TicketID[:]), Receipt: r}
	}
	return j
}

func verdictOf(err error) string {
	if err == nil {
		return "ok"
	}
	var r *zsescrow.OfferRejectedError
	if !errors.As(err, &r) {
		return "error: " + err.Error()
	}
	return r.Field
}

// The fixtures' verdicts, from why the program's tests wrote each shape
// (contracts-solana README "Transactions").
var fixtureVerdicts = map[string]string{
	"open":                          "ok",
	"open_v0":                       "ok",
	"open_fold_settle":              "ok",
	"open_extra_instruction":        "instructions.shape",
	"open_wrong_vault":              "transfer.accounts",
	"open_wrong_amount":             "transfer.data",
	"open_extra_signer":             "header.signers",
	"open_approve":                  "token.instruction",
	"open_payer_writable":           "header.payerWritable",
	"open_foreign_program":          "instruction.program",
	"open_duplicate_compute_budget": "computeBudget.duplicate",
	"open_grace_nonzero":            "open.data",
	"open_close_account":            "token.instruction",
	"open_set_authority":            "token.instruction",
	"open_v0_lookup_table":          "message.lookups",
	"open_fold_settle_wrong_amount": "fold.data",
	"open_fold_settle_wrong_digest": "fold.data",
	"open_fold_settle_wrong_usage":  "fold.data",
	"open_fold_settle_wrong_ticket": "fold.accounts",
}

func buildOfferVectors(t *testing.T) offerVectors {
	w := loadOfferWorld(t)
	d := w.d
	v := offerVectors{
		Version: 1,
		Comment: "Generated by `cd proto/go && go test ./solana/zsescrow -run TestOpenOfferVectors -update`. " +
			"Each case is an open offer's message and the spec its payer holds; verdict is \"ok\" or the field slug of the check that refuses it. " +
			"source \"fixture\" is the program's own transaction of that name in solana_tx_vectors.json; \"built\" is one built here.",
		ProgramID: d.Program.String(),
		Mint:      d.Mint.String(),
	}
	add := func(name, about, source string, message []byte, s zsescrow.OpenOfferSpec) string {
		verdict := verdictOf(zsescrow.VerifyOpenOffer(d, message, s))
		v.Cases = append(v.Cases, offerCase{Name: name, About: about, Source: source, Message: base64.StdEncoding.EncodeToString(message),
			Spec: specJSON(t, s), Verdict: verdict})
		return verdict
	}
	open, fold := w.byName["open"], w.byName["open_fold_settle"]
	for _, name := range w.order {
		// Each fixture opens a ticket of its own, for the payer it names.
		f := w.byName[name]
		receipt := (*txFixture)(nil)
		if f.Receipt != nil {
			receipt = &f
		}
		add(name, f.About, "fixture", b64(t, f.Message), w.specFor(t, f, receipt))
	}

	spec := w.specFor(t, open, nil)
	ixs := open.instructions(t)
	cbLimit, cbPrice, transfer, openIx := ixs[0], ixs[1], ixs[2], ixs[3]
	compile := func(feePayer solana.PublicKey, ixs ...solana.Instruction) []byte {
		m, err := solana.Compile(feePayer, w.blockhash, ixs, solana.Legacy)
		if err != nil {
			t.Fatal(err)
		}
		b, err := m.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	built := func(name, about, want string, message []byte, s zsescrow.OpenOfferSpec) {
		if got := add(name, about, "built", message, s); got != want {
			t.Fatalf("%s: verdict %s, want %s", name, got, want)
		}
	}
	node := spec.NodeSigning
	openWith := func(f func(a *zsescrow.OpenArgs)) solana.Instruction {
		a := zsescrow.OpenArgs{TicketID: spec.TicketID, Payer: spec.Payer, MaxPrice: spec.MaxPrice, ExpiresAt: spec.ExpiresAt}
		f(&a)
		return d.Open(node, spec.OperatorID, spec.NodeID, a)
	}
	vault := d.Vault(d.Node(spec.OperatorID, spec.NodeID))
	ownTransfer := solana.TransferChecked(spec.PayerUSDC, d.Mint, vault, spec.Payer, spec.MaxPrice, spec.Decimals)

	built("from_the_builders", "the offer a node composes from the builders, as the payer rebuilds it", "ok",
		compile(node, cbLimit, cbPrice, ownTransfer, openWith(func(*zsescrow.OpenArgs) {})), spec)
	built("no_compute_budget", "the transfer and open alone", "ok", compile(node, transfer, openIx), spec)
	built("truncated", "the open offer's message with its last byte cut", "message.parse", b64(t, open.Message)[:len(b64(t, open.Message))-1], spec)
	built("fee_payer_not_the_node", "open signed and paid for by another key", "header.feePayer",
		compile(w.attacker, cbLimit, cbPrice, transfer, d.Open(w.attacker, spec.OperatorID, spec.NodeID, zsescrow.OpenArgs{
			TicketID: spec.TicketID, Payer: spec.Payer, MaxPrice: spec.MaxPrice, ExpiresAt: spec.ExpiresAt})), spec)
	unsigned := transfer
	unsigned.Accounts = append([]solana.AccountMeta(nil), transfer.Accounts...)
	unsigned.Accounts[3].IsSigner = false
	built("payer_not_a_signer", "the transfer's authority not marked a signer, so only the node signs", "header.signers",
		compile(node, cbLimit, cbPrice, unsigned, openIx), spec)
	other := spec
	other.Payer = w.attacker
	other.PayerUSDC = d.TokenAccount(w.attacker)
	built("another_payer", "the open offer judged by a payer it does not name", "header.payer", b64(t, open.Message), other)
	built("another_ticket", "open names a ticket id the payer did not reserve", "open.accounts",
		compile(node, cbLimit, cbPrice, transfer, openWith(func(a *zsescrow.OpenArgs) { a.TicketID[0] ^= 1 })), spec)
	built("another_expiry", "open names an expiry one second past the ticket's", "open.data",
		compile(node, cbLimit, cbPrice, transfer, openWith(func(a *zsescrow.OpenArgs) { a.ExpiresAt++ })), spec)
	built("both_amounts_raised", "the transfer and open agree on one unit more than the payer reserved", "transfer.data",
		compile(node, cbLimit, cbPrice, solana.TransferChecked(spec.PayerUSDC, d.Mint, vault, spec.Payer, spec.MaxPrice+1, spec.Decimals),
			openWith(func(a *zsescrow.OpenArgs) { a.MaxPrice++ })), spec)
	built("transfer_from_another_account", "the transfer draws from a token account other than the payer's", "transfer.accounts",
		compile(node, cbLimit, cbPrice, solana.TransferChecked(d.TokenAccount(w.attacker), d.Mint, vault, spec.Payer, spec.MaxPrice, spec.Decimals), openIx), spec)
	built("transfer_other_decimals", "the transfer names 9 decimals", "transfer.data",
		compile(node, cbLimit, cbPrice, solana.TransferChecked(spec.PayerUSDC, d.Mint, vault, spec.Payer, spec.MaxPrice, 9), openIx), spec)
	built("heap_frame", "a RequestHeapFrame among the compute budget", "computeBudget.instruction",
		compile(node, solana.Instruction{ProgramID: solana.ComputeBudgetProgramID, Data: []byte{1, 0, 0, 1, 0}}, cbLimit, transfer, openIx), spec)
	longLimit := cbLimit
	longLimit.Data = append(append([]byte(nil), cbLimit.Data...), 0)
	built("compute_budget_long", "a SetComputeUnitLimit with a byte past its u32", "computeBudget.instruction",
		compile(node, longLimit, cbPrice, transfer, openIx), spec)
	shortLimit := cbLimit
	shortLimit.Data = cbLimit.Data[:4]
	built("compute_budget_short", "a SetComputeUnitLimit a byte short of its u32", "computeBudget.instruction",
		compile(node, shortLimit, cbPrice, transfer, openIx), spec)
	bareprice := cbPrice
	bareprice.Data = cbPrice.Data[:1]
	built("compute_budget_tag_alone", "a SetComputeUnitPrice with its tag and no price", "computeBudget.instruction",
		compile(node, cbLimit, bareprice, transfer, openIx), spec)
	withAccount := cbLimit
	withAccount.Accounts = []solana.AccountMeta{{PublicKey: spec.PayerUSDC, IsWritable: true}}
	built("compute_budget_with_an_account", "a SetComputeUnitLimit naming the payer's token account", "computeBudget.instruction",
		compile(node, withAccount, cbPrice, transfer, openIx), spec)
	built("compute_budget_after_transfer", "a compute-budget instruction between the transfer and open", "computeBudget.order",
		compile(node, cbLimit, transfer, cbPrice, openIx), spec)
	built("no_transfer", "open with no transfer before it, so the payer signs nothing and is no signer", "header.signers", compile(node, cbLimit, cbPrice, openIx), spec)
	built("transfer_twice", "two copies of the transfer before open", "instructions.shape", compile(node, cbLimit, cbPrice, transfer, transfer, openIx), spec)
	built("transfer_after_open", "the transfer after open", "instructions.shape", compile(node, cbLimit, cbPrice, openIx, transfer), spec)
	built("open_twice", "open, then open again", "instructions.shape", compile(node, cbLimit, cbPrice, transfer, openIx, openIx), spec)
	built("claim_beside", "a claim of the payer's ticket after open", "escrow.instruction",
		compile(node, cbLimit, cbPrice, transfer, openIx, d.Claim(node, spec.OperatorID, spec.NodeID, spec.TicketID, zsescrow.ClaimFields{Amount: 1})), spec)

	foldSpec := w.specFor(t, fold, &fold)
	foldIxs := fold.instructions(t)
	settle := foldIxs[2]
	built("fold_without_a_ticket", "the folded offer judged by a payer with no ticket to settle", "fold.unexpected",
		b64(t, fold.Message), w.specFor(t, fold, nil))
	claim, err := zsescrow.ClaimFromReceipt(foldSpec.Fold.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	ending := zsescrow.Ending{Submitter: foldSpec.NodeSigning, OperatorID: foldSpec.OperatorID, NodeID: foldSpec.NodeID,
		TicketID: foldSpec.Fold.TicketID, RentPayer: settle.Accounts[5].PublicKey, Payer: foldSpec.Payer}
	for _, c := range []struct {
		name string
		fb   zsescrow.RefundFallback
	}{{"fold_readonly_fallback", zsescrow.FallbackReadonly}, {"fold_writable_fallback", zsescrow.FallbackWritable}} {
		e := ending
		e.Fallback = c.fb
		ix := append(append([]solana.Instruction{}, foldIxs[:2]...), d.SettleCooperative(e, claim), foldIxs[3], foldIxs[4])
		built(c.name, "the folded settle passing the RefundOwed fallback, which the program decides whether to use", "ok", compile(foldSpec.NodeSigning, ix...), foldSpec)
	}
	built("fold_after_transfer", "the folded settle between the transfer and open", "instructions.shape",
		compile(foldSpec.NodeSigning, foldIxs[0], foldIxs[1], foldIxs[3], settle, foldIxs[4]), foldSpec)
	withFold := func(f func(*zsescrow.FoldSpec)) zsescrow.OpenOfferSpec {
		s := foldSpec
		fs := *foldSpec.Fold
		f(&fs)
		s.Fold = &fs
		return s
	}
	built("fold_at_another_node", "the folded settle judged by a payer whose ticket is at another node", "fold.accounts", b64(t, fold.Message),
		withFold(func(f *zsescrow.FoldSpec) { f.NodeID++ }))
	built("fold_receipt_of_another_ticket", "the folded settle and its receipt both name a ticket other than the payer's previous one", "fold.receipt", b64(t, fold.Message),
		withFold(func(f *zsescrow.FoldSpec) { f.TicketID[0] ^= 1 }))
	unpadded := *foldSpec.Fold.Receipt
	unpadded.TicketID = strings.TrimRight(unpadded.TicketID, "=")
	built("fold_receipt_ticket_unpadded", "the receipt spells the payer's ticket id without base64 padding", "fold.receipt", b64(t, fold.Message),
		withFold(func(f *zsescrow.FoldSpec) { f.Receipt = &unpadded }))
	built("fold_no_receipt", "the payer's previous ticket with no receipt", "fold.receipt", b64(t, fold.Message),
		withFold(func(f *zsescrow.FoldSpec) { f.Receipt = nil }))
	short := settle
	short.Accounts = settle.Accounts[:5]
	built("fold_five_accounts", "the folded settle cut off before its rent payer", "fold.accounts",
		compile(foldSpec.NodeSigning, foldIxs[0], foldIxs[1], short, foldIxs[3], foldIxs[4]), foldSpec)
	full := *foldSpec.Fold.Receipt
	full.TtftMs, full.DecodeMs, full.AuxOutputCount = math.MaxUint32, math.MaxUint32, math.MaxUint32
	fullClaim, err := zsescrow.ClaimFromReceipt(&full)
	if err != nil {
		t.Fatal(err)
	}
	built("fold_receipt_at_u32_max", "the payer's receipt has ttft, decode and aux count each the largest a claim's u32 carries", "ok",
		compile(foldSpec.NodeSigning, foldIxs[0], foldIxs[1], d.SettleCooperative(ending, fullClaim), foldIxs[3], foldIxs[4]),
		withFold(func(f *zsescrow.FoldSpec) { f.Receipt = &full }))
	for _, c := range []struct {
		name, field string
		set         func(r *ticket.UsageReceipt)
	}{
		{"fold_receipt_ttft_overflows", "ttft", func(r *ticket.UsageReceipt) { r.TtftMs = 1 << 32 }},
		{"fold_receipt_decode_overflows", "decode time", func(r *ticket.UsageReceipt) { r.DecodeMs = 1 << 32 }},
		{"fold_receipt_aux_overflows", "aux count", func(r *ticket.UsageReceipt) { r.AuxOutputCount = 1 << 32 }},
	} {
		over := *foldSpec.Fold.Receipt
		c.set(&over)
		built(c.name, "the payer's receipt has a "+c.field+" no claim's u32 can carry", "fold.receipt", b64(t, fold.Message),
			withFold(func(f *zsescrow.FoldSpec) { f.Receipt = &over }))
	}
	return v
}

func mustB64(t *testing.T, s string) []byte {
	b := b64(t, s)
	if len(b) != 16 {
		t.Fatalf("ticket id %q", s)
	}
	return b
}

func TestOpenOfferVectors(t *testing.T) {
	got, err := json.MarshalIndent(buildOfferVectors(t), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if *updateVectors {
		if err := os.WriteFile(offerVectorsPath, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(offerVectorsPath)
	if err != nil {
		t.Fatalf("%v (run with -update)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("solana_open_offer_vectors.json is stale: go test ./solana/zsescrow -run TestOpenOfferVectors -update")
	}
}

func TestOpenOfferVectorsMeanWhatTheySay(t *testing.T) {
	v := buildOfferVectors(t)
	w := loadOfferWorld(t)
	for _, c := range v.Cases {
		if c.Source != "fixture" {
			continue
		}
		want, ok := fixtureVerdicts[c.Name]
		if !ok {
			t.Errorf("%s: a fixture with no expected verdict; add it to fixtureVerdicts", c.Name)
		} else if c.Verdict != want {
			t.Errorf("%s: verdict %s, want %s", c.Name, c.Verdict, want)
		}
	}
	if len(w.order) != len(fixtureVerdicts) {
		t.Errorf("%d open fixtures, %d expected verdicts", len(w.order), len(fixtureVerdicts))
	}

	// The specs are the payers': each names the ticket its open creates, at a
	// node the payer reserved with, a payer the fixture says is judged, and
	// the price its open escrows; each fold's receipt is the bytes the
	// program read.
	for _, name := range w.order {
		f := w.byName[name]
		ixs := f.instructions(t)
		open := f.openOf(t)
		s := w.specFor(t, f, nil)
		if s.OperatorID == 0 || open.Accounts[4].PublicKey != w.d.Ticket(w.d.Node(s.OperatorID, s.NodeID), s.TicketID) {
			t.Errorf("%s: the spec's ticket is not the one open creates", name)
		}
		if f.Payer == "" || !bytes.Equal(open.Data[8+16:8+48], s.Payer[:]) {
			t.Errorf("%s: the judged payer is not the one open names", name)
		}
		for _, ix := range ixs {
			if ix.ProgramID == solana.TokenProgramID && ix.Data[0] == solana.TokenTransferChecked && ix.Accounts[3].PublicKey != s.Payer {
				t.Errorf("%s: the transfer's authority is not the judged payer", name)
			}
		}
		if f.Receipt == nil {
			continue
		}
		var r ticket.UsageReceipt
		if err := json.Unmarshal(f.Receipt, &r); err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(r.CanonicalBytes()) != f.ReceiptHex {
			t.Errorf("%s: the receipt's canonical bytes are not the fixture's", name)
		}
		if name == "open_fold_settle" {
			claim, err := zsescrow.ClaimFromReceipt(&r)
			if err != nil {
				t.Fatal(err)
			}
			var c struct {
				Amount          uint64 `json:"amount,string"`
				ReceiptDigest   string `json:"receipt_digest"`
				TTFTMs          uint32 `json:"ttft_ms"`
				DecodeMs        uint32 `json:"decode_ms"`
				InputUnits      uint64 `json:"input_units,string"`
				OutputUnits     uint64 `json:"output_units,string"`
				OutputUsageType uint8  `json:"output_usage_type"`
				AuxUsageType    uint8  `json:"aux_usage_type"`
				AuxCount        uint32 `json:"aux_count"`
			}
			if err := json.Unmarshal(f.ClaimFields, &c); err != nil {
				t.Fatal(err)
			}
			want := zsescrow.ClaimFields{Amount: c.Amount, ReceiptDigest: [32]byte(mustHex(t, c.ReceiptDigest)), TTFTMs: c.TTFTMs, DecodeMs: c.DecodeMs,
				InputUnits: c.InputUnits, OutputUnits: c.OutputUnits, OutputUsageType: c.OutputUsageType, AuxUsageType: c.AuxUsageType, AuxCount: c.AuxCount}
			if claim != want || claim.ReceiptDigest != sha256.Sum256(mustHex(t, f.ReceiptHex)) {
				t.Errorf("the claim from the receipt %+v, the fixture's %+v", claim, want)
			}
			s := w.specFor(t, f, &f)
			if w.d.Ticket(w.d.Node(s.Fold.OperatorID, s.Fold.NodeID), s.Fold.TicketID).String() != f.SettledTicket {
				t.Error("the fold's spec does not name the ticket the fixture settled")
			}
		}
	}
}

func mustHex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
