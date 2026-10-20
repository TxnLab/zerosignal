/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zsescrow_test

// Cross-impl parity for what the program's fixtures can't show, because the
// program never writes it: accounts and events the decoders must refuse or
// read a particular way, instructions that only look like events, ticket
// deadlines at their edges, and a settle built with the read-only refund
// fallback. Generates / verifies proto/testdata/solana_zsescrow_vectors.json,
// which proto/ts replays, so the two payers refuse the same data.
//
// To regenerate after an intentional change:
//
//	cd proto/go && go test ./solana/zsescrow -run TestZsEscrowVectors -update
//
// Without -update, this asserts the on-disk file matches current Go output.
// TestZsEscrowVectorsMeanWhatTheySay checks the cases against the program's
// layouts independently of the decoders.

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"reflect"
	"strconv"
	"testing"

	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
)

var updateVectors = flag.Bool("update", false, "regenerate proto/testdata/solana_zsescrow_vectors.json")

const vectorsPath = "../../../testdata/solana_zsescrow_vectors.json"

// U+FEFF, built from its code point: a literal in source is a byte order
// mark the compiler refuses.
var bomMark = string(rune(0xfeff))

type dataCase struct {
	Name    string         `json:"name"`
	Type    string         `json:"type,omitempty"`
	About   string         `json:"about"`
	Data    string         `json:"data_base64"`
	Decoded map[string]any `json:"decoded,omitempty"`
}

type eventInstructionCase struct {
	Name      string   `json:"name"`
	ProgramID string   `json:"program_id"`
	Accounts  []string `json:"accounts"`
	IsEvent   bool     `json:"is_event"`
}

type deadlineCase struct {
	ExpiresAt string `json:"expires_at"`
	Grace     uint32 `json:"grace"`
	Deadline  string `json:"deadline"`
}

type buildMeta struct {
	Pubkey     string `json:"pubkey"`
	IsSigner   bool   `json:"is_signer"`
	IsWritable bool   `json:"is_writable"`
}

type buildCase struct {
	Name    string            `json:"name"`
	About   string            `json:"about"`
	Builder string            `json:"builder"`
	Ending  map[string]string `json:"ending"`
	Data    string            `json:"data_base64"`
	Metas   []buildMeta       `json:"accounts"`
}

type zsVectors struct {
	Version           int                    `json:"version"`
	Comment           string                 `json:"comment"`
	ProgramID         string                 `json:"program_id"`
	Mint              string                 `json:"usdc_mint"`
	AccountsRefused   []dataCase             `json:"accounts_refused"`
	AccountsAccepted  []dataCase             `json:"accounts_accepted"`
	EventsRefused     []dataCase             `json:"events_refused"`
	EventsAccepted    []dataCase             `json:"events_accepted"`
	EventInstructions []eventInstructionCase `json:"event_instructions"`
	Deadlines         []deadlineCase         `json:"deadlines"`
	Builds            []buildCase            `json:"builds"`
	SetConfigRefused  []map[string]string    `json:"set_config_refused"`
}

type fixtureFiles struct {
	program  solana.PublicKey
	mint     solana.PublicKey
	accounts map[string][]byte
	events   map[string][]byte
	known    []solana.PublicKey
	settle   instructionCase
}

func loadFixtureFiles(t *testing.T) fixtureFiles {
	var a struct {
		ProgramID solana.PublicKey `json:"program_id"`
		Context   fixtureContext   `json:"context"`
		Accounts  []struct {
			Name string `json:"name"`
			Data string `json:"data_base64"`
		} `json:"accounts"`
	}
	readFixture(t, "solana_account_vectors.json", &a)
	var e struct {
		Events []struct {
			Case  string `json:"case"`
			Inner struct {
				Data string `json:"data_base64"`
			} `json:"inner_instruction"`
		} `json:"events"`
	}
	readFixture(t, "solana_event_vectors.json", &e)
	var ix struct {
		Instructions []instructionCase `json:"instructions"`
	}
	readFixture(t, "solana_instruction_vectors.json", &ix)
	f := fixtureFiles{program: a.ProgramID, mint: a.Context.USDCMint, accounts: map[string][]byte{}, events: map[string][]byte{}, known: []solana.PublicKey{a.Context.Treasury}}
	for _, k := range a.Context.Keys {
		f.known = append(f.known, k.Pubkey)
	}
	for _, x := range a.Accounts {
		f.accounts[x.Name] = b64(t, x.Data)
	}
	for _, x := range e.Events {
		f.events[x.Case] = b64(t, x.Inner.Data)
	}
	for _, c := range ix.Instructions {
		if c.Case == "refund_inactive_refund_owed" {
			f.settle = c
		}
	}
	return f
}

func account(t *testing.T, f fixtureFiles, name string) []byte {
	b, ok := f.accounts[name]
	if !ok {
		t.Fatalf("no %s fixture", name)
	}
	return bytes.Clone(b)
}

func decodeAs(typ string, data []byte) (any, error) {
	switch typ {
	case "Config":
		return zsescrow.DecodeConfig(data)
	case "Operator":
		return zsescrow.DecodeOperator(data)
	case "Node":
		return zsescrow.DecodeNode(data)
	case "Ticket":
		return zsescrow.DecodeTicket(data)
	case "SignerIndex":
		return zsescrow.DecodeSignerIndex(data)
	case "RefundOwed":
		return zsescrow.DecodeRefundOwed(data)
	case "TokenAccount":
		return zsescrow.DecodeTokenAccount(data)
	}
	panic(typ)
}

// The offsets of the fields the cases change, read off the program's
// layouts: the 8-byte discriminator, then the fields in order.
const (
	configPauseOpenAt = 8 + 5
	nodeBaseURLLenAt  = 8 + 5
	nodeBaseURLAt     = 8 + 8 + 3*32
	ticketStatusAt    = 8 + 1
	tokenDelegateAt   = 32 + 32 + 8
	tokenStateAt      = tokenDelegateAt + 4 + 32
	tokenIsNativeAt   = tokenStateAt + 1
	tokenDelegatedAt  = tokenIsNativeAt + 4 + 8
	tokenCloseAuthAt  = tokenDelegatedAt + 8
)

func buildZsVectors(t *testing.T) zsVectors {
	f := loadFixtureFiles(t)
	v := zsVectors{
		Version: 1,
		Comment: "Generated by `cd proto/go && go test ./solana/zsescrow -run TestZsEscrowVectors -update`. " +
			"accounts_refused / events_refused: data the decoder of type (or the event parser) must refuse. " +
			"accounts_accepted / events_accepted: data it must read as decoded (the fixtures' shape). " +
			"event_instructions: whether an inner instruction is the program's event self-invocation. " +
			"deadlines: a ticket's expires_at and grace and the deadline they give. " +
			"builds: a settle builder's instruction for an ending. set_config_refused: treasuries set_config must refuse.",
		ProgramID: f.program.String(),
		Mint:      f.mint.String(),
	}
	refuse := func(name, typ, about string, data []byte) {
		if _, err := decodeAs(typ, data); err == nil {
			t.Fatalf("%s: decodes", name)
		}
		v.AccountsRefused = append(v.AccountsRefused, dataCase{Name: name, Type: typ, About: about, Data: base64.StdEncoding.EncodeToString(data)})
	}
	accept := func(name, typ, about string, data []byte) {
		got, err := decodeAs(typ, data)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		v.AccountsAccepted = append(v.AccountsAccepted, dataCase{Name: name, Type: typ, About: about, Data: base64.StdEncoding.EncodeToString(data),
			Decoded: flatten(reflect.ValueOf(got)).(map[string]any)})
	}

	config := account(t, f, "config_initialized")
	b := bytes.Clone(config)
	b[8] = 2
	refuse("config_version_2", "Config", "a later program's version", b)
	refuse("config_short", "Config", "one byte short", config[:len(config)-1])
	b = bytes.Clone(config)
	b[configPauseOpenAt] = 2
	refuse("config_pause_open_2", "Config", "a bool of 2", b)
	b = bytes.Clone(config)
	b[0] ^= 1
	refuse("config_wrong_discriminator", "Config", "the first discriminator byte flipped", b)
	refuse("ticket_as_config", "Config", "a Ticket's bytes", account(t, f, "ticket_open"))
	refuse("config_as_ticket", "Ticket", "a Config's bytes", config)
	refuse("empty", "Operator", "no data", []byte{})

	node := account(t, f, "node_with_metrics")
	b = bytes.Clone(node)
	b[nodeBaseURLLenAt] = zsescrow.BaseURLMax + 1
	refuse("node_base_url_len_249", "Node", "a URL length past the field", b)
	b = bytes.Clone(node)
	b[nodeBaseURLAt] = 0xff
	refuse("node_base_url_not_utf8", "Node", "a URL that is not UTF-8", b)
	b = bytes.Clone(node)
	url := bomMark + "https://x.example"
	clear(b[nodeBaseURLAt : nodeBaseURLAt+zsescrow.BaseURLMax])
	copy(b[nodeBaseURLAt:], url)
	b[nodeBaseURLLenAt] = byte(len(url))
	accept("node_base_url_bom", "Node", "a URL starting with U+FEFF, kept as written", b)

	ticket := account(t, f, "ticket_open")
	b = bytes.Clone(ticket)
	b[ticketStatusAt] = 7
	accept("ticket_status_unknown", "Ticket", "a status a later program might add, read as unknown", b)

	vault := account(t, f, "node_vault")
	refuse("token_account_short", "TokenAccount", "164 bytes", vault[:len(vault)-1])
	refuse("token_account_long", "TokenAccount", "166 bytes", append(bytes.Clone(vault), 0))
	b = bytes.Clone(vault)
	b[tokenDelegateAt] = 2
	refuse("token_account_coption_tag_2", "TokenAccount", "a delegate tag of 2", b)
	b = bytes.Clone(vault)
	delegate := solana.MustPublicKey("F25s3DdjXdCxYBhh2z8FBusVEMT4b9bGNFVKJi3wFoF4")
	closer := solana.MustPublicKey("3Atsbq9N5EaCc9YWmqD2rUVedX4pqDe7hyk6JSyWRTrG")
	binary.LittleEndian.PutUint32(b[tokenDelegateAt:], 1)
	copy(b[tokenDelegateAt+4:], delegate[:])
	b[tokenStateAt] = 2
	binary.LittleEndian.PutUint32(b[tokenIsNativeAt:], 1)
	binary.LittleEndian.PutUint64(b[tokenIsNativeAt+4:], 2039280)
	binary.LittleEndian.PutUint64(b[tokenDelegatedAt:], 5000)
	binary.LittleEndian.PutUint32(b[tokenCloseAuthAt:], 1)
	copy(b[tokenCloseAuthAt+4:], closer[:])
	accept("token_account_every_option", "TokenAccount", "frozen, with a delegate, a native reserve and a close authority", b)

	refuseEvent := func(name, about string, data []byte) {
		if _, err := zsescrow.ParseEvent(data); err == nil {
			t.Fatalf("%s: parses", name)
		}
		v.EventsRefused = append(v.EventsRefused, dataCase{Name: name, About: about, Data: base64.StdEncoding.EncodeToString(data)})
	}
	settled := f.events["settled_cooperative"]
	evicted := f.events["operator_evicted"]
	if settled == nil || evicted == nil {
		t.Fatalf("event fixtures: %v", keys(f.events))
	}
	b = bytes.Clone(settled)
	b[8] ^= 1
	refuseEvent("unknown_discriminator", "a TicketSettled with its discriminator's first byte flipped", b)
	b = bytes.Clone(settled)
	b[0] ^= 1
	refuseEvent("wrong_tag", "the event tag's first byte flipped", b)
	b = bytes.Clone(settled)
	b[len(b)-1] = 2
	refuseEvent("settled_refund_owed_2", "a bool of 2", b)
	refuseEvent("settled_trailing_byte", "one byte after the fields", append(bytes.Clone(settled), 0))
	refuseEvent("settled_short", "the last byte cut", settled[:len(settled)-1])
	refuseEvent("tag_only", "the tag and nothing else", append([]byte{}, zsescrow.EventIxTag[:]...))
	// The reason is the last field: u64 operator id, u64 slashed, then a u32
	// length and the bytes.
	reasonAt := 16 + 8 + 8
	b = bytes.Clone(evicted)
	b[reasonAt+4] = 0xff
	refuseEvent("evicted_reason_not_utf8", "a reason that is not UTF-8", b)
	b = bytes.Clone(evicted)
	binary.LittleEndian.PutUint32(b[reasonAt:], 1<<20)
	refuseEvent("evicted_reason_past_end", "a reason length past the data", b)
	bom := append(append(bytes.Clone(evicted[:reasonAt]), binary.LittleEndian.AppendUint32(nil, 4)...), bomMark+"x"...)
	ev, err := zsescrow.ParseEvent(bom)
	if err != nil {
		t.Fatal(err)
	}
	v.EventsAccepted = append(v.EventsAccepted, dataCase{Name: "evicted_reason_bom", About: "a reason starting with U+FEFF, kept as written",
		Data: base64.StdEncoding.EncodeToString(bom), Decoded: flatten(reflect.ValueOf(ev)).(map[string]any)})

	d := zsescrow.Deployment{Program: f.program, Mint: f.mint}
	other := zsescrow.Deployment{Program: solana.MustPublicKey("G2TVpB3WqPLtb3cy4LKhH9yk38fWXvxtEi4Y9BmtVBdj"), Mint: f.mint}
	for _, c := range []struct {
		name     string
		program  solana.PublicKey
		accounts []solana.PublicKey
	}{
		{"genuine", d.Program, []solana.PublicKey{d.EventAuthority()}},
		{"another_program", other.Program, []solana.PublicKey{d.EventAuthority()}},
		{"another_deployments_authority", d.Program, []solana.PublicKey{other.EventAuthority()}},
		{"another_program_with_its_authority", other.Program, []solana.PublicKey{other.EventAuthority()}},
		{"no_accounts", d.Program, nil},
		{"a_second_account", d.Program, []solana.PublicKey{d.EventAuthority(), d.Program}},
		{"the_authority_second", d.Program, []solana.PublicKey{d.Program, d.EventAuthority()}},
		{"the_config_as_authority", d.Program, []solana.PublicKey{d.Config()}},
	} {
		ec := eventInstructionCase{Name: c.name, ProgramID: c.program.String(), Accounts: []string{}, IsEvent: d.IsEventInstruction(c.program, c.accounts)}
		for _, k := range c.accounts {
			ec.Accounts = append(ec.Accounts, k.String())
		}
		v.EventInstructions = append(v.EventInstructions, ec)
	}

	for _, c := range []struct {
		expiresAt int64
		grace     uint32
	}{
		{1790000300, 120},
		{1790000300, 0},
		{-5, 10},
		{1<<63 - 1 - 600, 600},
		{1<<63 - 1 - 599, 600},
		{1<<63 - 1, 1<<32 - 1},
	} {
		tk := zsescrow.Ticket{ExpiresAt: c.expiresAt, Grace: c.grace}
		v.Deadlines = append(v.Deadlines, deadlineCase{strconv.FormatInt(c.expiresAt, 10), c.grace, strconv.FormatInt(tk.Deadline(), 10)})
	}

	e := settleEnding(t, d, f)
	for _, c := range []struct {
		name, builder, about string
		fallback             zsescrow.RefundFallback
	}{
		{"refund_inactive_readonly_fallback", "refund_inactive", "the RefundOwed and owed vault passed read-only, as a submitter may always", zsescrow.FallbackReadonly},
		{"refund_inactive_no_fallback", "refund_inactive", "neither passed: the program id in each slot", zsescrow.NoFallback},
	} {
		e.Fallback = c.fallback
		ix := d.RefundInactive(e)
		bc := buildCase{Name: c.name, About: c.about, Builder: c.builder, Data: base64.StdEncoding.EncodeToString(ix.Data), Ending: map[string]string{
			"submitter": e.Submitter.String(), "operator_id": strconv.FormatUint(e.OperatorID, 10), "node_id": strconv.FormatUint(e.NodeID, 10),
			"ticket_id": hex.EncodeToString(e.TicketID[:]), "rent_payer": e.RentPayer.String(), "payer": e.Payer.String(),
			"fallback": [...]string{"none", "readonly", "writable"}[c.fallback],
		}}
		for _, m := range ix.Accounts {
			bc.Metas = append(bc.Metas, buildMeta{m.PublicKey.String(), m.IsSigner, m.IsWritable})
		}
		v.Builds = append(v.Builds, bc)
	}
	zero := solana.PublicKey{}
	if _, err := d.SetConfig(e.Submitter, zsescrow.SetConfigArgs{Treasury: &zero}); err == nil {
		t.Fatal("a zero treasury builds")
	}
	v.SetConfigRefused = []map[string]string{{"treasury": zero.String(), "about": "the default key, whose token accounts nobody can sign for"}}
	return v
}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// settleEnding is the ending the refund_inactive_refund_owed fixture sent.
func settleEnding(t *testing.T, d zsescrow.Deployment, f fixtureFiles) zsescrow.Ending {
	acct := map[string]solana.PublicKey{}
	for _, a := range f.settle.Accounts {
		acct[a.Name] = a.Pubkey
	}
	e := zsescrow.Ending{Submitter: acct["submitter"], RentPayer: acct["rent_payer"]}
	for op := uint64(1); op < 8 && e.OperatorID == 0; op++ {
		for n := uint64(1); n < 8; n++ {
			if d.Node(op, n) == acct["node"] {
				e.OperatorID, e.NodeID = op, n
			}
		}
	}
	for b := range 256 {
		if id := [16]byte(bytes.Repeat([]byte{byte(b)}, 16)); d.Ticket(acct["node"], id) == acct["ticket"] {
			e.TicketID = id
		}
	}
	for _, k := range f.known {
		if d.TokenAccount(k) == acct["payer_ata"] {
			e.Payer = k
		}
	}
	if e.OperatorID == 0 || e.Payer.IsZero() {
		t.Fatal("the settle fixture's ending is not derivable")
	}
	return e
}

func TestZsEscrowVectors(t *testing.T) {
	got, err := json.MarshalIndent(buildZsVectors(t), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if *updateVectors {
		if err := os.WriteFile(vectorsPath, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("%v (run with -update)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("solana_zsescrow_vectors.json is stale: go test ./solana/zsescrow -run TestZsEscrowVectors -update")
	}
}

// The vectors pin what this package does; these check it against the
// program, independently of the decoders and builders.
func TestZsEscrowVectorsMeanWhatTheySay(t *testing.T) {
	v := buildZsVectors(t)
	for _, c := range v.EventInstructions {
		if c.IsEvent != (c.Name == "genuine") {
			t.Errorf("%s: is_event %v", c.Name, c.IsEvent)
		}
	}
	for _, c := range v.Deadlines {
		exp, _ := strconv.ParseInt(c.ExpiresAt, 10, 64)
		want := strconv.FormatInt(exp+int64(c.Grace), 10)
		if exp > 1<<63-1-int64(c.Grace) {
			want = strconv.FormatInt(1<<63-1, 10) // saturating_add, as the program's deadline()
		}
		if c.Deadline != want {
			t.Errorf("%s + %d: %s, want %s", c.ExpiresAt, c.Grace, c.Deadline, want)
		}
	}
	for _, c := range v.AccountsAccepted {
		switch c.Name {
		case "token_account_every_option":
			want := map[string]any{"delegate": "F25s3DdjXdCxYBhh2z8FBusVEMT4b9bGNFVKJi3wFoF4", "state": "Frozen", "is_native": "2039280",
				"delegated_amount": "5000", "close_authority": "3Atsbq9N5EaCc9YWmqD2rUVedX4pqDe7hyk6JSyWRTrG"}
			for k, w := range want {
				if c.Decoded[k] != w {
					t.Errorf("%s: %s = %v, want %v", c.Name, k, c.Decoded[k], w)
				}
			}
		case "node_base_url_bom":
			if c.Decoded["base_url"] != bomMark+"https://x.example" {
				t.Errorf("base_url %q", c.Decoded["base_url"])
			}
		case "ticket_status_unknown":
			if c.Decoded["status"] != "TicketStatus(7)" {
				t.Errorf("status %v", c.Decoded["status"])
			}
		}
	}
	if v.EventsAccepted[0].Decoded["reason"] != bomMark+"x" {
		t.Errorf("reason %q", v.EventsAccepted[0].Decoded["reason"])
	}

	// The read-only fallback is the writable fixture's instruction with the
	// two accounts demoted, and no fallback the program id in all three.
	f := loadFixtureFiles(t)
	for _, c := range v.Builds {
		if !bytes.Equal(b64(t, c.Data), b64(t, f.settle.Data)) {
			t.Errorf("%s: data differs from the fixture's", c.Name)
		}
		for i, a := range f.settle.Accounts {
			want := buildMeta{a.Pubkey.String(), a.IsSigner, a.IsWritable}
			switch {
			case c.Builder == "refund_inactive" && c.Ending["fallback"] == "readonly" && (a.Name == "refund_owed" || a.Name == "owed_vault"):
				want.IsWritable = false
			case c.Ending["fallback"] == "none" && (a.Name == "refund_owed" || a.Name == "owed_vault" || a.Name == "system_program"):
				want = buildMeta{f.program.String(), false, false}
			}
			if c.Metas[i] != want {
				t.Errorf("%s account %d (%s): %+v, want %+v", c.Name, i, a.Name, c.Metas[i], want)
			}
		}
	}
}
