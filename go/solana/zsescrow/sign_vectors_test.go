/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zsescrow_test

// The payer's signed transactions both languages must write byte for byte.
// The program's own open offers and acks are completed with its payer's key,
// and must come out as the transactions Rust signed; offers and acks built
// here for the account_vectors.json phrases are completed through
// keystore.SolanaKeys. Generates / verifies
// proto/testdata/solana_sign_vectors.json, which proto/sdk replays through
// its own key derivation and signer.
//
//	cd proto/go && go test ./solana/zsescrow -run TestSignVectors -update
//
// TestCompleteSignsOnlyWhatPasses runs every case of the open-offer and
// relayed-ack vectors through the Complete functions.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"testing"

	"github.com/TxnLab/zerosignal/go/keystore"
	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
	"github.com/TxnLab/zerosignal/go/ticket"
)

const signVectorsPath = "../../../testdata/solana_sign_vectors.json"

// signKey names the key a case signs with, never its secret: a key of
// solana_tx_vectors.json's context, whose secret is its seed, or a solana row
// of account_vectors.json, whose phrase the replay derives.
type signKey struct {
	Fixture string `json:"fixture,omitempty"`
	Account string `json:"account,omitempty"`
	Address string `json:"address"`
}

type signOfferCase struct {
	Name   string    `json:"name"`
	About  string    `json:"about"`
	Source string    `json:"source"`
	Signer signKey   `json:"signer"`
	Offer  string    `json:"offer_base64"`
	Spec   offerSpec `json:"spec"`
	Wire   string    `json:"wire_base64"`
}

type signAckCase struct {
	Name   string      `json:"name"`
	About  string      `json:"about"`
	Source string      `json:"source"`
	Signer signKey     `json:"signer"`
	Ack    string      `json:"ack_base64"`
	Spec   ackSpecJSON `json:"spec"`
	Wire   string      `json:"wire_base64"`
}

type signOwnCase struct {
	Name     string  `json:"name"`
	About    string  `json:"about"`
	Source   string  `json:"source"`
	Signer   signKey `json:"signer"`
	Unsigned string  `json:"unsigned_base64"`
	Wire     string  `json:"wire_base64"`
}

type signVectors struct {
	Version   int             `json:"version"`
	Comment   string          `json:"comment"`
	ProgramID string          `json:"program_id"`
	Mint      string          `json:"usdc_mint"`
	Offers    []signOfferCase `json:"offers"`
	Acks      []signAckCase   `json:"relayed_acks"`
	Own       []signOwnCase   `json:"own"`
}

// fixtureKeys are solana_tx_vectors.json's keys by name, each the 32 bytes of
// its seed.
func fixtureKeys(t *testing.T) map[string]ed25519.PrivateKey {
	var f struct {
		Context struct {
			Keys map[string]struct {
				Pubkey solana.PublicKey `json:"pubkey"`
				Seed   byte             `json:"seed"`
			} `json:"keys"`
		} `json:"context"`
	}
	readFixture(t, "solana_tx_vectors.json", &f)
	out := map[string]ed25519.PrivateKey{}
	for name, k := range f.Context.Keys {
		priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{k.Seed}, 32))
		if !bytes.Equal(priv.Public().(ed25519.PublicKey), k.Pubkey[:]) {
			t.Fatalf("%s: seed %d gives another key", name, k.Seed)
		}
		out[name] = priv
	}
	return out
}

// keySigner signs as the keys it holds, by base58 address, and records each
// address it is asked to sign as.
type keySigner struct {
	keys  map[string]ed25519.PrivateKey
	asked []string
}

func newKeySigner(keys map[string]ed25519.PrivateKey) *keySigner {
	s := &keySigner{keys: map[string]ed25519.PrivateKey{}}
	for _, k := range keys {
		s.keys[solana.PublicKey(k.Public().(ed25519.PublicKey)).String()] = k
	}
	return s
}

func (s *keySigner) SignTransactionMessage(_ context.Context, address string, message []byte) ([]byte, error) {
	s.asked = append(s.asked, address)
	k, ok := s.keys[address]
	if !ok {
		return nil, errors.New("no key for " + address)
	}
	return ed25519.Sign(k, message), nil
}

type phrases []keystore.MnemonicEntry

func (p phrases) Mnemonics(context.Context) ([]keystore.MnemonicEntry, error) { return p, nil }

// accountKeys loads the named solana rows of account_vectors.json into a
// keystore.SolanaKeys.
func accountKeys(t *testing.T, names ...string) (*keystore.SolanaKeys, map[string]solana.PublicKey) {
	var f struct {
		Solana []struct {
			Name    string `json:"name"`
			Phrase  string `json:"phrase"`
			Address string `json:"address"`
		} `json:"solana"`
	}
	readFixture(t, "account_vectors.json", &f)
	var p phrases
	addr := map[string]solana.PublicKey{}
	for _, n := range names {
		for _, c := range f.Solana {
			if c.Name == n {
				p = append(p, keystore.MnemonicEntry{Name: "V", Mnemonic: c.Phrase})
				addr[n] = solana.MustPublicKey(c.Address)
			}
		}
		if _, ok := addr[n]; !ok {
			t.Fatalf("no solana account vector %q", n)
		}
	}
	ks, err := keystore.NewSolanaKeys(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	for n, a := range addr {
		if !ks.HasAccount(a.String()) {
			t.Fatalf("%s: the keystore did not load %s", n, a)
		}
	}
	return ks, addr
}

// withEmptySlot is tx's wire form with the slot of key cleared, as its
// builder hands it over.
func withEmptySlot(t *testing.T, wire []byte, key solana.PublicKey) []byte {
	tx, err := solana.ParseTransaction(wire)
	if err != nil {
		t.Fatal(err)
	}
	cleared := false
	for i := range tx.Signatures {
		if tx.Message.AccountKeys[i] == key {
			tx.Signatures[i], cleared = solana.Signature{}, true
		}
	}
	if !cleared {
		t.Fatalf("%s signs nothing here", key)
	}
	b, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// signedBy is message's transaction with only signer's slot filled.
func signedBy(t *testing.T, message []byte, signer ed25519.PrivateKey) []byte {
	m, err := solana.ParseMessage(message)
	if err != nil {
		t.Fatal(err)
	}
	tx := solana.NewTransaction(m)
	if err := tx.Sign(signer); err != nil {
		t.Fatal(err)
	}
	b, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func buildSignVectors(t *testing.T) signVectors {
	ctx := context.Background()
	ow, aw := loadOfferWorld(t), loadAckWorld(t)
	d := ow.d
	keys := fixtureKeys(t)
	fixtures := newKeySigner(keys)
	ks, accounts := accountKeys(t, "client vector", "solana-keygen 24 words", "solana-keygen 12 words")
	v := signVectors{
		Version: 1,
		Comment: "Generated by `cd proto/go && go test ./solana/zsescrow -run TestSignVectors -update`. " +
			"offers and relayed_acks: a transaction someone else built, the payer's slot empty, and the spec its payer holds; wire_base64 is the transaction once the payer has checked and signed it. " +
			"own: a transaction the payer built itself, unsigned, and signed. signer names the key: fixture is a key of solana_tx_vectors.json's context, whose secret is its seed; account is a solana row of account_vectors.json, whose phrase derives it. " +
			"source \"fixture\" is the program's own transaction of that name, whose wire_base64 is the one Rust signed; \"built\" is one built here. Specs are as in solana_open_offer_vectors.json and solana_ack_vectors.json.",
		ProgramID: d.Program.String(),
		Mint:      d.Mint.String(),
	}
	fixtureKey := func(name string) signKey {
		return signKey{Fixture: name, Address: solana.PublicKey(keys[name].Public().(ed25519.PublicKey)).String()}
	}
	accountKey := func(name string) signKey { return signKey{Account: name, Address: accounts[name].String()} }
	signerOf := func(k signKey) solana.TransactionSigner {
		if k.Fixture != "" {
			return fixtures
		}
		return ks.Signer(k.Address)
	}
	encode := base64.StdEncoding.EncodeToString

	offer := func(name, about, source string, k signKey, wire []byte, s zsescrow.OpenOfferSpec) []byte {
		got, err := zsescrow.CompleteOpenOffer(ctx, d, wire, s, signerOf(k))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		v.Offers = append(v.Offers, signOfferCase{Name: name, About: about, Source: source, Signer: k, Offer: encode(wire), Spec: specJSON(t, s), Wire: encode(got)})
		return got
	}
	ack := func(name, about, source string, k signKey, wire []byte, s zsescrow.AckSpec) []byte {
		got, err := zsescrow.CompleteRelayedAck(ctx, d, wire, s, signerOf(k))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		v.Acks = append(v.Acks, signAckCase{Name: name, About: about, Source: source, Signer: k, Ack: encode(wire), Spec: ackSpecToJSON(t, s), Wire: encode(got)})
		return got
	}
	own := func(name, about, source string, k signKey, message []byte) []byte {
		m, err := solana.ParseMessage(message)
		if err != nil {
			t.Fatal(err)
		}
		tx := solana.NewTransaction(m)
		unsigned, err := tx.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.SignWith(ctx, solana.MustPublicKey(k.Address), signerOf(k)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got, err := tx.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		v.Own = append(v.Own, signOwnCase{Name: name, About: about, Source: source, Signer: k, Unsigned: encode(unsigned), Wire: encode(got)})
		return got
	}
	asRust := func(name string, got []byte, rust string) {
		if !bytes.Equal(got, b64(t, rust)) {
			t.Fatalf("%s: the payer's transaction is not the one the program's test signed", name)
		}
	}
	payer := fixtureKey("payer")

	for _, name := range []string{"open", "open_v0", "open_fold_settle"} {
		f := ow.byName[name]
		var fold *txFixture
		if f.Receipt != nil {
			fold = &f
		}
		wire := wireOf(t, "solana_tx_vectors.json", name)
		got := offer(name, "the program's "+name+", which its node signed", "fixture", payer, withEmptySlot(t, wire, solana.MustPublicKey(payer.Address)), ow.specFor(t, f, fold))
		asRust(name, got, encode(wire))
	}

	open, fixtureFold := ow.byName["open"], ow.byName["open_fold_settle"]
	node := keys["node1_signing"]
	ixs := open.instructions(t)
	cbLimit, cbPrice := ixs[0], ixs[1]
	accountOffer := func(name, about, account string, ver solana.MessageVersion, folded bool) {
		s := ow.specFor(t, open, nil)
		var foldIx []solana.Instruction
		if folded {
			s = ow.specFor(t, fixtureFold, &fixtureFold)
			settle := fixtureFold.instructions(t)[2]
			foldIx = []solana.Instruction{d.SettleCooperative(zsescrow.Ending{Submitter: s.NodeSigning, OperatorID: s.Fold.OperatorID, NodeID: s.Fold.NodeID,
				TicketID: s.Fold.TicketID, RentPayer: settle.Accounts[5].PublicKey, Payer: accounts[account]}, zsescrow.ClaimFromReceipt(s.Fold.Receipt))}
		}
		s.Payer, s.PayerUSDC = accounts[account], d.TokenAccount(accounts[account])
		transfer := solana.TransferChecked(s.PayerUSDC, d.Mint, d.Vault(d.Node(s.OperatorID, s.NodeID)), s.Payer, s.MaxPrice, s.Decimals)
		openIx := d.Open(s.NodeSigning, s.OperatorID, s.NodeID, zsescrow.OpenArgs{TicketID: s.TicketID, Payer: s.Payer, MaxPrice: s.MaxPrice, ExpiresAt: s.ExpiresAt})
		all := append(append([]solana.Instruction{cbLimit, cbPrice}, foldIx...), transfer, openIx)
		offer(name, about, "built", accountKey(account), signedBy(t, marshal(t, compileMessage(t, s.NodeSigning, ow.blockhash, ver, all...)), node), s)
	}
	accountOffer("client_vector_open", "an open offer to the chat app's exported phrase's Solana account, which node1 signed", "client vector", solana.Legacy, false)
	accountOffer("keygen24_open", "an open offer to solana-keygen's 24-word phrase's account", "solana-keygen 24 words", solana.Legacy, false)
	accountOffer("keygen12_open_v0", "an open offer as a v0 message, to solana-keygen's 12-word phrase's account", "solana-keygen 12 words", solana.V0, false)
	accountOffer("client_vector_open_fold", "an open offer folding the settle of the chat app account's previous ticket", "client vector", solana.Legacy, true)

	relayed := aw.byName["ack_relayed"]
	wire := wireOf(t, "solana_tx_vectors.json", "ack_relayed")
	asRust("ack_relayed", ack("ack_relayed", "the program's relayed ack, which its node signed and paid for", "fixture", payer,
		withEmptySlot(t, wire, solana.MustPublicKey(payer.Address)), aw.specFor(t, relayed)), encode(wire))

	spec := aw.specFor(t, relayed)
	relayer := aw.feePayerOf(t, relayed)
	rentPayer := relayed.ackOf(t).Accounts[5].PublicKey
	ackOf := func(account string) (solana.Instruction, zsescrow.AckSpec) {
		s := spec
		s.Payer = accounts[account]
		return d.Ack(zsescrow.Ending{Submitter: s.Payer, OperatorID: s.OperatorID, NodeID: s.NodeID, TicketID: s.TicketID, RentPayer: rentPayer,
			Payer: s.Payer, Treasury: s.Treasury}, zsescrow.ClaimFromReceipt(s.Receipt)), s
	}
	keygenAck, keygenSpec := ackOf("solana-keygen 24 words")
	ack("keygen24_relayed_ack", "a relayed ack for solana-keygen's 24-word phrase's account under a compute budget, which node1 signed and pays for", "built",
		accountKey("solana-keygen 24 words"), signedBy(t, marshal(t, compileMessage(t, relayer, aw.blockhash, solana.Legacy,
			solana.SetComputeUnitLimit(40_000), solana.SetComputeUnitPrice(1_000), keygenAck)), node), keygenSpec)

	for _, name := range []string{"ack", "protest"} {
		f := aw.byName[name]
		asRust(name, own(name, "the program's "+name+", which its payer built and pays for", "fixture", payer, b64(t, f.Message)), encode(wireOf(t, "solana_tx_vectors.json", name)))
	}
	clientAck, _ := ackOf("client vector")
	own("client_vector_ack", "the chat app account's ack of its ticket, as its own fee payer", "built", accountKey("client vector"),
		marshal(t, compileMessage(t, accounts["client vector"], aw.blockhash, solana.Legacy, clientAck)))
	return v
}

// wireOf is the wire form of fixture name in file.
func wireOf(t *testing.T, file, name string) []byte {
	var f struct {
		Transactions []struct {
			Name string `json:"name"`
			Wire string `json:"wire_base64"`
		} `json:"transactions"`
	}
	readFixture(t, file, &f)
	for _, x := range f.Transactions {
		if x.Name == name {
			return b64(t, x.Wire)
		}
	}
	t.Fatalf("%s: no transaction %q", file, name)
	return nil
}

func TestSignVectors(t *testing.T) {
	got, err := json.MarshalIndent(buildSignVectors(t), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if *updateVectors {
		if err := os.WriteFile(signVectorsPath, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(signVectorsPath)
	if err != nil {
		t.Fatalf("%v (run with -update)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("solana_sign_vectors.json is stale: go test ./solana/zsescrow -run TestSignVectors -update")
	}
}

// Every completed transaction carries a valid signature in each slot, the
// message it was handed unchanged, and the other signers' slots as given.
func TestSignVectorsMeanWhatTheySay(t *testing.T) {
	v := buildSignVectors(t)
	check := func(name, before, after string) {
		in, err := solana.ParseTransaction(b64(t, before))
		if err != nil {
			t.Fatal(err)
		}
		out, err := solana.ParseTransaction(b64(t, after))
		if err != nil {
			t.Fatal(err)
		}
		if err := out.VerifySignatures(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		inMsg, _ := in.Message.MarshalBinary()
		outMsg, _ := out.Message.MarshalBinary()
		if !bytes.Equal(inMsg, outMsg) {
			t.Errorf("%s: the message changed", name)
		}
		filled := 0
		for i := range in.Signatures {
			if in.Signatures[i] != out.Signatures[i] {
				if in.Signatures[i] != (solana.Signature{}) {
					t.Errorf("%s: slot %d was given and replaced", name, i)
				}
				filled++
			}
		}
		if filled != 1 {
			t.Errorf("%s: %d slots filled, want the payer's", name, filled)
		}
	}
	sources := map[string]int{}
	for _, c := range v.Offers {
		check(c.Name, c.Offer, c.Wire)
		sources[c.Source]++
	}
	for _, c := range v.Acks {
		check(c.Name, c.Ack, c.Wire)
		sources[c.Source]++
	}
	for _, c := range v.Own {
		check(c.Name, c.Unsigned, c.Wire)
		sources[c.Source]++
	}
	if sources["fixture"] < 6 || sources["built"] < 6 {
		t.Errorf("sources %v", sources)
	}
}

func offerSpecOf(t *testing.T, j offerSpec) zsescrow.OpenOfferSpec {
	s := zsescrow.OpenOfferSpec{NodeSigning: solana.MustPublicKey(j.NodeSigning), OperatorID: mustUint(t, j.OperatorID), NodeID: mustUint(t, j.NodeID),
		Payer: solana.MustPublicKey(j.Payer), PayerUSDC: solana.MustPublicKey(j.PayerUSDC), Decimals: j.Decimals,
		TicketID: [16]byte(mustHexLen(t, j.TicketID, 16)), MaxPrice: mustUint(t, j.MaxPrice), ExpiresAt: int64(mustUint(t, j.ExpiresAt))}
	if j.Fold != nil {
		s.Fold = &zsescrow.FoldSpec{OperatorID: mustUint(t, j.Fold.OperatorID), NodeID: mustUint(t, j.Fold.NodeID),
			TicketID: [16]byte(mustHexLen(t, j.Fold.TicketID, 16)), Receipt: receiptOf(t, j.Fold.Receipt), Treasury: solana.MustPublicKey(j.Fold.Treasury)}
	}
	return s
}

func ackSpecOf(t *testing.T, j ackSpecJSON) zsescrow.AckSpec {
	return zsescrow.AckSpec{Payer: solana.MustPublicKey(j.Payer), OperatorID: mustUint(t, j.OperatorID), NodeID: mustUint(t, j.NodeID),
		TicketID: [16]byte(mustHexLen(t, j.TicketID, 16)), Receipt: receiptOf(t, j.Receipt), Treasury: solana.MustPublicKey(j.Treasury)}
}

func receiptOf(t *testing.T, raw json.RawMessage) *ticket.UsageReceipt {
	var r *ticket.UsageReceipt
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func mustUint(t *testing.T, s string) uint64 {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func mustHexLen(t *testing.T, s string, n int) []byte {
	b := mustHex(t, s)
	if len(b) != n {
		t.Fatalf("%q is not %d bytes", s, n)
	}
	return b
}

// emptySlots is message's transaction with every slot empty. A message too
// short to name its signer count gets one slot, which the decode refuses
// either way.
func emptySlots(message []byte) []byte {
	n := 1
	switch {
	case len(message) > 1 && message[0]&0x80 != 0:
		n = int(message[1])
	case len(message) > 0:
		n = int(message[0])
	}
	return append(append([]byte{byte(n)}, make([]byte, 64*n)...), message...)
}

// The Complete functions sign exactly what their verifier accepts: a refused
// offer or ack never reaches the signer, and an accepted one is signed once,
// as its payer, over the message it was handed.
func TestCompleteSignsOnlyWhatPasses(t *testing.T) {
	ctx := context.Background()
	keys := fixtureKeys(t)
	var offers offerVectors
	readFixture(t, "solana_open_offer_vectors.json", &offers)
	var acks ackVectors
	readFixture(t, "solana_ack_vectors.json", &acks)
	d := zsescrow.Deployment{Program: solana.MustPublicKey(offers.ProgramID), Mint: solana.MustPublicKey(offers.Mint)}
	if acks.ProgramID != offers.ProgramID || acks.Mint != offers.Mint {
		t.Fatal("the offer and ack vectors name other deployments")
	}

	run := func(kind, name, verdict, message string, payer string, complete func(solana.TransactionSigner, []byte) ([]byte, error), field func(error) (string, bool)) {
		s := newKeySigner(keys)
		msg := b64(t, message)
		got, err := complete(s, emptySlots(msg))
		switch verdict {
		case "ok":
			if err != nil {
				t.Errorf("%s %s: %v", kind, name, err)
				return
			}
			if len(s.asked) != 1 || s.asked[0] != payer {
				t.Errorf("%s %s: asked to sign as %v, want the payer %s", kind, name, s.asked, payer)
			}
			tx, err := solana.ParseTransaction(got)
			if err != nil {
				t.Fatal(err)
			}
			signed, _ := tx.Message.MarshalBinary()
			if !bytes.Equal(signed, msg) {
				t.Errorf("%s %s: signed another message", kind, name)
			}
			for i, sig := range tx.Signatures {
				k := tx.Message.AccountKeys[i]
				if k.String() == payer {
					if !solana.VerifyStrict(k, msg, sig) {
						t.Errorf("%s %s: the payer's slot does not verify", kind, name)
					}
				} else if sig != (solana.Signature{}) {
					t.Errorf("%s %s: slot %d filled", kind, name, i)
				}
			}
		case "message.parse":
			if _, rejected := field(err); err == nil || rejected || len(s.asked) != 0 {
				t.Errorf("%s %s: %v, asked %v; want a decode error before any signature", kind, name, err, s.asked)
			}
		default:
			if f, rejected := field(err); !rejected || f != verdict || got != nil || len(s.asked) != 0 {
				t.Errorf("%s %s: %v, asked %v; want %s before any signature", kind, name, err, s.asked, verdict)
			}
		}
	}
	for _, c := range offers.Cases {
		spec := offerSpecOf(t, c.Spec)
		run("offer", c.Name, c.Verdict, c.Message, c.Spec.Payer, func(s solana.TransactionSigner, wire []byte) ([]byte, error) {
			return zsescrow.CompleteOpenOffer(ctx, d, wire, spec, s)
		}, func(err error) (string, bool) {
			var r *zsescrow.OfferRejectedError
			ok := errors.As(err, &r)
			if ok {
				return r.Field, true
			}
			return "", false
		})
	}
	for _, c := range acks.RelayedAcks {
		spec := ackSpecOf(t, c.Spec)
		run("ack", c.Name, c.Verdict, c.Message, c.Spec.Payer, func(s solana.TransactionSigner, wire []byte) ([]byte, error) {
			return zsescrow.CompleteRelayedAck(ctx, d, wire, spec, s)
		}, func(err error) (string, bool) {
			var r *zsescrow.AckRejectedError
			ok := errors.As(err, &r)
			if ok {
				return r.Field, true
			}
			return "", false
		})
	}
	if len(offers.Cases) < 40 || len(acks.RelayedAcks) < 30 {
		t.Fatalf("%d offers, %d acks", len(offers.Cases), len(acks.RelayedAcks))
	}
}

// A signer that fails, or signs as another key, leaves the payer with no
// transaction, and the error is not a refusal of the offer.
func TestCompleteSignerFailure(t *testing.T) {
	ctx := context.Background()
	w := loadOfferWorld(t)
	open := w.byName["open"]
	spec := w.specFor(t, open, nil)
	offer := withEmptySlot(t, wireOf(t, "solana_tx_vectors.json", "open"), spec.Payer)
	keys := fixtureKeys(t)
	for name, s := range map[string]solana.TransactionSigner{
		"no key":      newKeySigner(nil),
		"another key": impostor{keys["attacker"]},
	} {
		got, err := zsescrow.CompleteOpenOffer(ctx, w.d, offer, spec, s)
		var r *zsescrow.OfferRejectedError
		if err == nil || got != nil || errors.As(err, &r) {
			t.Errorf("%s: %v", name, err)
		}
	}
	s := newKeySigner(keys)
	if _, err := zsescrow.CompleteOpenOffer(ctx, w.d, offer[:len(offer)-1], spec, s); err == nil || len(s.asked) != 0 {
		t.Errorf("a truncated offer: %v, asked %v", err, s.asked)
	}
}

// impostor signs every address with one key.
type impostor struct{ k ed25519.PrivateKey }

func (i impostor) SignTransactionMessage(_ context.Context, _ string, message []byte) ([]byte, error) {
	return ed25519.Sign(i.k, message), nil
}
