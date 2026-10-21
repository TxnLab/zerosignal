/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zsescrow_test

// The relayed-ack verdicts and receipt ack digests both payers must reach.
// The program's own ack transactions (solana_tx_vectors.json) are replayed
// with the spec a payer would hold, beside acks built here for the checks
// those shapes don't reach. Generates / verifies
// proto/testdata/solana_ack_vectors.json, which proto/ts replays.
//
//	cd proto/go && go test ./solana/zsescrow -run TestAckVectors -update
//
// TestAckVectorsMeanWhatTheySay checks each fixture's verdict against why the
// program's tests wrote it, and ties the built acceptances to the program's
// own relayed ack.

import (
	"bytes"
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

const ackVectorsPath = "../../../testdata/solana_ack_vectors.json"

type ackSpecJSON struct {
	Payer      string          `json:"payer"`
	OperatorID string          `json:"operator_id"`
	NodeID     string          `json:"node_id"`
	TicketID   string          `json:"ticket_id"`
	Receipt    json.RawMessage `json:"receipt"`
	Treasury   string          `json:"treasury"`
}

type ackCase struct {
	Name    string      `json:"name"`
	About   string      `json:"about"`
	Source  string      `json:"source"`
	Message string      `json:"message_base64"`
	Spec    ackSpecJSON `json:"spec"`
	Verdict string      `json:"verdict"`
}

type ackDigestCase struct {
	Name       string          `json:"name"`
	About      string          `json:"about"`
	OperatorID string          `json:"operator_id"`
	NodeID     string          `json:"node_id"`
	TicketID   string          `json:"ticket_id"`
	OpenSeq    string          `json:"open_seq"`
	Receipt    json.RawMessage `json:"receipt"`
	Digest     string          `json:"digest_hex,omitempty"`
	Verdict    string          `json:"verdict"`
}

type ackVectors struct {
	Version     int             `json:"version"`
	Comment     string          `json:"comment"`
	ProgramID   string          `json:"program_id"`
	Mint        string          `json:"usdc_mint"`
	GenesisHash string          `json:"genesis_hash"`
	RelayedAcks []ackCase       `json:"relayed_acks"`
	Digests     []ackDigestCase `json:"digests"`
}

// The fixtures' verdicts, from why the program's tests wrote each ack. The
// program's relayed ack carries a placeholder receipt_digest, not a digest of
// any receipt, so it is refused as data; its receipt-claim twin below is the
// acceptance. The payer-paid acks have one signer: a payer builds those
// itself and has no relayer's transaction to check.
var ackFixtureVerdicts = map[string]string{
	"ack":              "header.signers",
	"ack_first_half":   "header.signers",
	"ack_mismatch":     "header.signers",
	"ack_relayed":      "ack.data",
	"ack_extra_settle": "escrow.instruction",
}

type ackWorld struct {
	d         zsescrow.Deployment
	genesis   solana.Hash
	blockhash solana.Hash
	payer     solana.PublicKey
	attacker  solana.PublicKey
	treasury  solana.PublicKey
	decimals  uint8
	// foldReceipt is the program's receipt for its folded settle, of the
	// same usage as every ack fixture's claim.
	foldReceipt ticket.UsageReceipt
	byName      map[string]txFixture
	order       []string
}

func loadAckWorld(t *testing.T) ackWorld {
	var f struct {
		ProgramID solana.PublicKey `json:"program_id"`
		Context   struct {
			fixtureContext
			GenesisHash string `json:"genesis_hash"`
			Decimals    uint8  `json:"usdc_decimals"`
		} `json:"context"`
		Transactions []txFixture `json:"transactions"`
	}
	readFixture(t, "solana_tx_vectors.json", &f)
	w := ackWorld{d: zsescrow.Deployment{Program: f.ProgramID, Mint: f.Context.USDCMint}, genesis: solana.Hash(mustHex(t, f.Context.GenesisHash)),
		payer: f.Context.Keys["payer"].Pubkey, attacker: f.Context.Keys["attacker"].Pubkey, treasury: f.Context.Treasury,
		decimals: f.Context.Decimals, byName: map[string]txFixture{}}
	for _, x := range f.Transactions {
		w.byName[x.Name] = x
		if strings.HasPrefix(x.Name, "ack") {
			w.order = append(w.order, x.Name)
		}
	}
	bh, err := solana.ParseHash(w.byName["ack_relayed"].Blockhash)
	if err != nil {
		t.Fatal(err)
	}
	w.blockhash = bh
	if err := json.Unmarshal(w.byName["open_fold_settle"].Receipt, &w.foldReceipt); err != nil {
		t.Fatal(err)
	}
	return w
}

// ackOf is the fixture's ack instruction.
func (f txFixture) ackOf(t *testing.T) solana.Instruction {
	disc := zsescrow.Discriminator("global", "ack")
	for _, ix := range f.instructions(t) {
		if bytes.HasPrefix(ix.Data, disc[:]) {
			return ix
		}
	}
	t.Fatalf("%s: no ack", f.Name)
	return solana.Instruction{}
}

// specFor is the spec the payer of fixture f holds: its ticket, found as the
// node and ticket id the fixtures' flows use, and a receipt for that ticket
// of the usage the fixtures claim, at amount.
func (w ackWorld) specFor(t *testing.T, f txFixture, amount uint64) zsescrow.AckSpec {
	ack := f.ackOf(t)
	s := zsescrow.AckSpec{Payer: solana.MustPublicKey(f.Payer), Treasury: w.treasury}
	for op := uint64(1); op < 8 && s.OperatorID == 0; op++ {
		for n := uint64(1); n < 8; n++ {
			if w.d.Node(op, n) == ack.Accounts[2].PublicKey {
				s.OperatorID, s.NodeID = op, n
			}
		}
	}
	node := w.d.Node(s.OperatorID, s.NodeID)
	for b := 0; b < 256; b++ {
		id := [16]byte(bytes.Repeat([]byte{byte(b)}, 16))
		if w.d.Ticket(node, id) == ack.Accounts[4].PublicKey {
			s.TicketID = id
		}
	}
	if s.OperatorID == 0 || w.d.Ticket(node, s.TicketID) != ack.Accounts[4].PublicKey {
		t.Fatalf("%s: no node and ticket id of the fixtures' flows", f.Name)
	}
	r := w.foldReceipt
	r.TicketID = base64.StdEncoding.EncodeToString(s.TicketID[:])
	r.AmountCharged = amount
	s.Receipt = &r
	return s
}

func ackSpecToJSON(t *testing.T, s zsescrow.AckSpec) ackSpecJSON {
	r, err := json.Marshal(s.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	return ackSpecJSON{Payer: s.Payer.String(), OperatorID: strconv.FormatUint(s.OperatorID, 10), NodeID: strconv.FormatUint(s.NodeID, 10),
		TicketID: hex.EncodeToString(s.TicketID[:]), Receipt: r, Treasury: s.Treasury.String()}
}

func ackVerdictOf(err error) string {
	if err == nil {
		return "ok"
	}
	var r *zsescrow.AckRejectedError
	if !errors.As(err, &r) {
		return "error: " + err.Error()
	}
	return r.Field
}

// claimAmount is the amount an escrow instruction's claim fields carry.
func claimAmount(ix solana.Instruction) uint64 { return binary.LittleEndian.Uint64(ix.Data[8:]) }

func buildAckVectors(t *testing.T) ackVectors {
	w := loadAckWorld(t)
	d := w.d
	v := ackVectors{
		Version: 1,
		Comment: "Generated by `cd proto/go && go test ./solana/zsescrow -run TestAckVectors -update`. " +
			"relayed_acks: an ack transaction someone else built, its message and the spec its payer holds; verdict is \"ok\" or the field slug of the check that refuses it. " +
			"source \"fixture\" is the program's own transaction of that name in solana_tx_vectors.json; \"built\" is one built here. " +
			"digests: the ack digest the payer signs off chain for a receipt, or the slug that refuses the receipt. genesis_hash is hex; ticket ids are hex; receipts are proto's receipt JSON.",
		ProgramID:   d.Program.String(),
		Mint:        d.Mint.String(),
		GenesisHash: hex.EncodeToString(w.genesis[:]),
	}
	add := func(name, about, source string, message []byte, s zsescrow.AckSpec) string {
		verdict := ackVerdictOf(zsescrow.VerifyRelayedAck(d, message, s))
		v.RelayedAcks = append(v.RelayedAcks, ackCase{Name: name, About: about, Source: source, Message: base64.StdEncoding.EncodeToString(message),
			Spec: ackSpecToJSON(t, s), Verdict: verdict})
		return verdict
	}
	for _, name := range w.order {
		f := w.byName[name]
		add(name, f.About, "fixture", b64(t, f.Message), w.specFor(t, f, claimAmount(f.ackOf(t))))
	}

	relayed, extra := w.byName["ack_relayed"], w.byName["ack_extra_settle"]
	spec := w.specFor(t, relayed, claimAmount(relayed.ackOf(t)))
	relayer := w.feePayerOf(t, relayed)
	claim := zsescrow.ClaimFromReceipt(spec.Receipt)
	ending := zsescrow.Ending{Submitter: spec.Payer, OperatorID: spec.OperatorID, NodeID: spec.NodeID, TicketID: spec.TicketID,
		RentPayer: relayed.ackOf(t).Accounts[5].PublicKey, Payer: spec.Payer, Treasury: spec.Treasury}
	ack := d.Ack(ending, claim)
	compile := func(feePayer solana.PublicKey, ixs ...solana.Instruction) []byte {
		return marshal(t, compileMessage(t, feePayer, w.blockhash, solana.Legacy, ixs...))
	}
	built := func(name, about, want string, message []byte, s zsescrow.AckSpec) {
		if got := add(name, about, "built", message, s); got != want {
			t.Fatalf("%s: verdict %s, want %s", name, got, want)
		}
	}
	withSpec := func(f func(*zsescrow.AckSpec)) zsescrow.AckSpec {
		s := spec
		f(&s)
		return s
	}
	ackWith := func(f func(e *zsescrow.Ending, c *zsescrow.ClaimFields)) solana.Instruction {
		e, c := ending, claim
		f(&e, &c)
		return d.Ack(e, c)
	}
	cbLimit, cbPrice := solana.SetComputeUnitLimit(40_000), solana.SetComputeUnitPrice(1_000)

	built("receipt_claim", "the program's relayed ack with the claim's receipt_digest the receipt's: only those 32 bytes differ", "ok", compile(relayer, ack), spec)
	built("from_the_builders", "a relayed ack under a compute-unit limit and price, from the builders", "ok", compile(relayer, cbLimit, cbPrice, ack), spec)
	built("another_relayer", "the ack paid for by a key that is neither the node nor the payer", "ok", compile(w.attacker, ack), spec)
	built("readonly_fallback", "the ack passing the treasury's USDC account read-only, which the program uses only for a refund the payer's account can't take", "ok",
		compile(relayer, ackWith(func(e *zsescrow.Ending, _ *zsescrow.ClaimFields) { e.Fallback = zsescrow.FallbackReadonly })), spec)
	built("writable_fallback", "the ack passing the treasury's USDC account writable, accepted: the program forfeits a refund the payer's account can't take on every ending", "ok",
		compile(relayer, ackWith(func(e *zsescrow.Ending, _ *zsescrow.ClaimFields) { e.Fallback = zsescrow.FallbackWritable })), spec)
	built("treasury_of_another", "the ack passing another key's USDC account where the treasury's goes", "ack.accounts",
		compile(relayer, ackWith(func(e *zsescrow.Ending, _ *zsescrow.ClaimFields) {
			e.Fallback, e.Treasury = zsescrow.FallbackReadonly, w.attacker
		})), spec)
	built("treasury_unknown", "the ack passing the treasury's USDC account, judged by a payer that names no treasury", "ack.accounts",
		compile(relayer, ackWith(func(e *zsescrow.Ending, _ *zsescrow.ClaimFields) { e.Fallback = zsescrow.FallbackReadonly })),
		withSpec(func(s *zsescrow.AckSpec) { s.Treasury = solana.PublicKey{} }))

	built("truncated", "the receipt-claim ack's message with its last byte cut", "message.parse", func() []byte { b := compile(relayer, ack); return b[:len(b)-1] }(), spec)
	lookup := compileMessage(t, relayer, w.blockhash, solana.V0, ack)
	lookup.AddressTableLookups = []solana.AddressTableLookup{{AccountKey: w.attacker, ReadonlyIndexes: []uint8{0}}}
	built("lookup_table", "the ack as a v0 message that loads one address from a lookup table no instruction reads", "message.lookups", marshal(t, lookup), spec)
	built("payer_pays", "the payer as its own fee payer: one signer, a transaction the payer builds itself", "header.signers", compile(spec.Payer, ack), spec)
	extraSigner := compileMessage(t, relayer, w.blockhash, solana.Legacy, ack)
	spliceSigner(extraSigner, w.attacker)
	built("extra_signer", "the header requires a third signature, by a key no instruction references", "header.signers", marshal(t, extraSigner), spec)
	built("another_payer", "the ack judged by a payer it does not name", "header.payer", compile(relayer, ack),
		withSpec(func(s *zsescrow.AckSpec) { s.Payer = w.attacker }))
	built("payer_writable", "the ack names the payer's wallet as its rent payer, so the header grants the payer a write lock", "header.payerWritable",
		compile(relayer, ackWith(func(e *zsescrow.Ending, _ *zsescrow.ClaimFields) { e.RentPayer = spec.Payer })), spec)

	built("heap_frame", "a RequestHeapFrame before the ack", "computeBudget.instruction",
		compile(relayer, solana.Instruction{ProgramID: solana.ComputeBudgetProgramID, Data: []byte{1, 0, 0, 1, 0}}, ack), spec)
	built("compute_budget_twice", "a second SetComputeUnitLimit", "computeBudget.duplicate", compile(relayer, cbLimit, solana.SetComputeUnitLimit(80_000), ack), spec)
	built("compute_budget_after_ack", "a compute-budget instruction after the ack", "computeBudget.order", compile(relayer, ack, cbPrice), spec)

	systemTransfer := solana.Instruction{ProgramID: solana.SystemProgramID,
		Accounts: []solana.AccountMeta{{PublicKey: relayer, IsSigner: true, IsWritable: true}, {PublicKey: w.attacker, IsWritable: true}},
		Data:     binary.LittleEndian.AppendUint64([]byte{2, 0, 0, 0}, 1_000_000)}
	built("system_transfer_beside", "a System Program transfer from the relayer's own key beside the ack", "instruction.program", compile(relayer, ack, systemTransfer), spec)
	built("token_transfer_beside", "a TransferChecked of the payer's USDC to another key's account beside the ack", "instruction.program",
		compile(relayer, solana.TransferChecked(d.TokenAccount(spec.Payer), d.Mint, d.TokenAccount(w.attacker), spec.Payer, 1, w.decimals), ack), spec)
	built("precompile_beside", "an Ed25519 precompile instruction before the ack", "instruction.program",
		compile(relayer, solana.Instruction{ProgramID: solana.Ed25519ProgramID, Data: []byte{0, 0}}, ack), spec)

	otherSettle := extra.instructions(t)[1]
	built("extra_settle_receipt_claim", "the receipt-claim ack with the program's settle_cooperative of another of the payer's claimed tickets beside it", "escrow.instruction",
		compile(relayer, ack, otherSettle), spec)
	built("settle_before_ack", "that settle_cooperative before the ack", "escrow.instruction", compile(relayer, otherSettle, ack), spec)
	other := w.specFor(t, extra, claimAmount(extra.ackOf(t)))
	otherAck := d.Ack(zsescrow.Ending{Submitter: spec.Payer, OperatorID: other.OperatorID, NodeID: other.NodeID, TicketID: other.TicketID,
		RentPayer: ending.RentPayer, Payer: spec.Payer}, claim)
	built("ack_twice", "a second ack, of another of the payer's tickets at this receipt's claim, beside the ack", "instructions.shape", compile(relayer, ack, otherAck), spec)
	built("claim_beside", "the node's claim of the payer's ticket beside the ack", "escrow.instruction",
		compile(relayer, ack, d.Claim(zsescrow.Ending{Submitter: relayer, OperatorID: spec.OperatorID, NodeID: spec.NodeID, TicketID: spec.TicketID,
			RentPayer: ending.RentPayer, Payer: spec.Payer}, claim)), spec)

	budgetOnly := compileMessage(t, relayer, w.blockhash, solana.Legacy, cbLimit)
	spliceSigner(budgetOnly, spec.Payer)
	built("compute_budget_only", "the payer as a read-only second signer of a message with only a compute budget", "instructions.shape", marshal(t, budgetOnly), spec)
	built("ack_of_another_ticket", "an ack at this receipt's claim, of another of the payer's tickets", "ack.accounts", compile(relayer, otherAck), spec)
	built("ack_at_another_node", "the ack judged by a payer whose ticket is at another node", "ack.accounts", compile(relayer, ack),
		withSpec(func(s *zsescrow.AckSpec) { s.NodeID++ }))
	built("amount_raised", "the ack charges one unit more than the receipt", "ack.data",
		compile(relayer, ackWith(func(_ *zsescrow.Ending, c *zsescrow.ClaimFields) { c.Amount++ })), spec)
	bare := ack
	bare.Data = ack.Data[:8]
	built("discriminator_only", "ack's discriminator with no claim", "ack.data", compile(relayer, bare), spec)
	short := ack
	short.Accounts = ack.Accounts[:5]
	built("five_accounts", "the ack cut off before its rent payer", "ack.accounts", compile(relayer, short), spec)
	short.Accounts = ack.Accounts[:len(ack.Accounts)-1]
	built("short", "the ack without its last account", "ack.accounts", compile(relayer, short), spec)

	built("receipt_of_another_ticket", "the payer's ticket is not the one the receipt and the ack name", "ack.receipt", compile(relayer, ack),
		withSpec(func(s *zsescrow.AckSpec) { s.TicketID[0] ^= 1 }))
	unpadded := *spec.Receipt
	unpadded.TicketID = strings.TrimRight(unpadded.TicketID, "=")
	built("receipt_ticket_unpadded", "the receipt spells the payer's ticket id without base64 padding", "ack.receipt", compile(relayer, ack),
		withSpec(func(s *zsescrow.AckSpec) { s.Receipt = &unpadded }))
	built("no_receipt", "the payer holds no receipt for the ticket", "ack.receipt", compile(relayer, ack),
		withSpec(func(s *zsescrow.AckSpec) { s.Receipt = nil }))

	digest := func(name, about string, ticketID [16]byte, openSeq uint64, r *ticket.UsageReceipt) {
		rj, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		c := ackDigestCase{Name: name, About: about, OperatorID: strconv.FormatUint(spec.OperatorID, 10), NodeID: strconv.FormatUint(spec.NodeID, 10),
			TicketID: hex.EncodeToString(ticketID[:]), OpenSeq: strconv.FormatUint(openSeq, 10), Receipt: rj}
		got, err := zsescrow.ReceiptAckDigest(d, w.genesis, spec.OperatorID, spec.NodeID, ticketID, openSeq, r)
		c.Verdict = ackVerdictOf(err)
		if err == nil {
			c.Digest = hex.EncodeToString(got[:])
		}
		v.Digests = append(v.Digests, c)
	}
	digest("receipt_claim", "the receipt's claim on the relayed ack's ticket", spec.TicketID, 7, spec.Receipt)
	digest("open_seq_max", "the same at the largest open_seq", spec.TicketID, math.MaxUint64, spec.Receipt)
	digest("receipt_of_another_ticket", "the payer's ticket is not the one the receipt names", [16]byte(append([]byte{spec.TicketID[0] ^ 1}, spec.TicketID[1:]...)), 7, spec.Receipt)
	digest("receipt_ticket_unpadded", "the receipt spells the payer's ticket id without base64 padding", spec.TicketID, 7, &unpadded)
	digest("no_receipt", "the payer holds no receipt for the ticket", spec.TicketID, 7, nil)
	return v
}

func (w ackWorld) feePayerOf(t *testing.T, f txFixture) solana.PublicKey {
	m, err := solana.ParseMessage(b64(t, f.Message))
	if err != nil {
		t.Fatal(err)
	}
	return m.FeePayer()
}

func compileMessage(t *testing.T, feePayer solana.PublicKey, blockhash solana.Hash, v solana.MessageVersion, ixs ...solana.Instruction) *solana.Message {
	m, err := solana.Compile(feePayer, blockhash, ixs, v)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func marshal(t *testing.T, m *solana.Message) []byte {
	b, err := m.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// spliceSigner adds k as a readonly signer no instruction references, as the
// program's open_extra_signer fixture does: a compiler includes only the keys
// instructions name.
func spliceSigner(m *solana.Message, k solana.PublicKey) {
	at := m.Header.NumRequiredSignatures
	m.AccountKeys = append(m.AccountKeys[:at], append([]solana.PublicKey{k}, m.AccountKeys[at:]...)...)
	m.Header.NumRequiredSignatures++
	m.Header.NumReadonlySignedAccounts++
	shift := func(i *uint8) {
		if *i >= at {
			*i++
		}
	}
	for n := range m.Instructions {
		shift(&m.Instructions[n].ProgramIDIndex)
		for a := range m.Instructions[n].Accounts {
			shift(&m.Instructions[n].Accounts[a])
		}
	}
}

func TestAckVectors(t *testing.T) {
	got, err := json.MarshalIndent(buildAckVectors(t), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if *updateVectors {
		if err := os.WriteFile(ackVectorsPath, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(ackVectorsPath)
	if err != nil {
		t.Fatalf("%v (run with -update)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("solana_ack_vectors.json is stale: go test ./solana/zsescrow -run TestAckVectors -update")
	}
}

func TestAckVectorsMeanWhatTheySay(t *testing.T) {
	v := buildAckVectors(t)
	w := loadAckWorld(t)
	for _, c := range v.RelayedAcks {
		if c.Source != "fixture" {
			continue
		}
		want, ok := ackFixtureVerdicts[c.Name]
		if !ok {
			t.Errorf("%s: a fixture with no expected verdict; add it to ackFixtureVerdicts", c.Name)
		} else if c.Verdict != want {
			t.Errorf("%s: verdict %s, want %s", c.Name, c.Verdict, want)
		}
	}
	if len(w.order) != len(ackFixtureVerdicts) {
		t.Errorf("%d ack fixtures, %d expected verdicts", len(w.order), len(ackFixtureVerdicts))
	}
	for _, name := range []string{"ack_relayed", "ack_extra_settle"} {
		if f := w.byName[name]; f.Payer == "" || w.feePayerOf(t, f).String() == f.Payer {
			t.Errorf("%s: not a relayer's transaction the payer co-signs", name)
		}
	}

	// The acceptance stands in for the program's own relayed ack, which the
	// program ran: the two messages differ in the claim's receipt_digest
	// alone, and the receipt's claim is the fixture's in every other field.
	relayed := w.byName["ack_relayed"]
	fixtureClaim := claimFieldsOf(t, relayed.ackOf(t).Data[8:])
	spec := w.specFor(t, relayed, fixtureClaim.Amount)
	receiptClaim := zsescrow.ClaimFromReceipt(spec.Receipt)
	if receiptClaim.ReceiptDigest == fixtureClaim.ReceiptDigest {
		t.Fatal("the fixture's claim names the receipt's digest: replay it as the acceptance")
	}
	withDigest := fixtureClaim
	withDigest.ReceiptDigest = receiptClaim.ReceiptDigest
	if withDigest != receiptClaim {
		t.Errorf("the receipt's claim %+v differs from the fixture's %+v beyond receipt_digest", receiptClaim, fixtureClaim)
	}
	var accepted []byte
	for _, c := range v.RelayedAcks {
		if c.Name == "receipt_claim" {
			accepted = b64(t, c.Message)
		}
	}
	fixture := b64(t, relayed.Message)
	at := bytes.Index(fixture, fixtureClaim.ReceiptDigest[:])
	if at < 0 {
		t.Fatal("the fixture's receipt_digest is not in its message")
	}
	if len(accepted) != len(fixture) {
		t.Fatalf("the accepted ack is %d bytes, the fixture's %d", len(accepted), len(fixture))
	}
	patched := append(append(append([]byte(nil), fixture[:at]...), receiptClaim.ReceiptDigest[:]...), fixture[at+32:]...)
	if !bytes.Equal(patched, accepted) {
		t.Error("the accepted ack is not the program's relayed ack with the receipt's digest")
	}

	// The digest is the program's: AckDigest over the receipt's claim hash.
	for _, c := range v.Digests {
		if c.Verdict != "ok" {
			continue
		}
		seq, err := strconv.ParseUint(c.OpenSeq, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		want := w.d.AckDigest(w.genesis, w.d.Ticket(w.d.Node(spec.OperatorID, spec.NodeID), spec.TicketID), seq, zsescrow.ClaimHash(receiptClaim))
		if c.Digest != hex.EncodeToString(want[:]) {
			t.Errorf("%s: digest %s, want %x", c.Name, c.Digest, want)
		}
	}
}
