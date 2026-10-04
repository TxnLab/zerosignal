/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"

	"github.com/TxnLab/zerosignal/go/algod"
	"github.com/TxnLab/zerosignal/go/escrow"
	"github.com/TxnLab/zerosignal/go/ticket"
)

// suppliedParts is a Config whose network parts are all supplied, so New
// reads no chain. The algod endpoint is unroutable to prove it.
func suppliedParts(t *testing.T) Config {
	t.Helper()
	registry, err := NewStaticRegistryProvider(nil)
	if err != nil {
		t.Fatal(err)
	}
	return Config{
		Signer:        fakeSigner{addr: "PAYER"},
		Network:       Network{Algod: algod.Config{Endpoint: "http://algod.invalid"}, EscrowAppID: 1},
		Registry:      registry,
		ReserveClient: &scriptedReserveClient{},
		Wallet:        fakeFeeWallet{},
	}
}

// New uses supplied network parts as given and builds the in-process ones it
// was not handed.
func TestNew_KeepsSuppliedParts(t *testing.T) {
	cfg := suppliedParts(t)
	c, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.registryProvider != cfg.Registry || c.reserveClient != cfg.ReserveClient || c.wallet != cfg.Wallet {
		t.Error("New replaced a supplied registry, reserve client or wallet")
	}
	if c.Registry() != cfg.Registry {
		t.Error("Registry() is not the routing registry")
	}
	if st := c.Config().Stores; st.RelayReputation != nil || st.NodeExclusions != nil {
		t.Error("New filled a routing store with no source of its own to back it")
	}
	if c.toolAffinity == nil || c.responseAffinity == nil {
		t.Error("New left an affinity cache nil")
	}
	if c.tokenizer == nil {
		t.Error("New left the tokenizer nil")
	}

	tool := NewIDAffinity(4, time.Minute, time.Now)
	cfg.Stores.ToolAffinity = tool
	c, err = New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.toolAffinity != tool {
		t.Error("New replaced the supplied tool affinity")
	}
}

// New checks the Config before it reads any chain, so a mistake is named
// rather than surfacing as a network error.
func TestNew_ValidatesConfig(t *testing.T) {
	cfg := suppliedParts(t)
	cfg.Signer = nil
	if _, err := New(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "Signer is required") {
		t.Errorf("err = %v, want Signer is required", err)
	}
}

// A wallet New must build reads the escrow config, and a failure there fails
// New: every open needs it.
func TestNew_FailsWhenTheEscrowConfigCannotBeRead(t *testing.T) {
	algodSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer algodSrv.Close()
	cfg := suppliedParts(t)
	cfg.Network.Algod = algod.Config{Endpoint: algodSrv.URL}
	cfg.Wallet = nil
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := New(ctx, cfg); err == nil || !strings.Contains(err.Error(), "escrow config") {
		t.Errorf("err = %v, want an escrow config read failure", err)
	}
}

// fakeEscrowAlgod answers the escrow config read: mbrForTicket returns mbr,
// the app predates the free-ticket quota, and the globals carry a USDC id and
// a treasury. senders lists each simulate's sender.
func fakeEscrowAlgod(t *testing.T, mbr uint64) (url string, senders func() []string) {
	t.Helper()
	mbrMethod, err := escrow.MethodByName("mbrForTicket")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var seen []string
	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(v); err != nil {
			t.Error(err)
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/v2/transactions/params"):
			writeJSON(w, models.TransactionParametersResponse{
				ConsensusVersion: "v30", Fee: 1000, MinFee: 1000, LastRound: 100,
				GenesisId: "dev-v1", GenesisHash: make([]byte, 32),
			})
		case strings.HasSuffix(r.URL.Path, "/v2/transactions/simulate"):
			body, _ := io.ReadAll(r.Body)
			var req models.SimulateRequest
			if err := msgpack.Decode(body, &req); err != nil || len(req.TxnGroups) != 1 || len(req.TxnGroups[0].Txns) != 1 {
				http.Error(w, "bad simulate request", http.StatusBadRequest)
				return
			}
			txn := req.TxnGroups[0].Txns[0].Txn
			mu.Lock()
			seen = append(seen, txn.Sender.String())
			mu.Unlock()
			group := models.SimulateTransactionGroupResult{TxnResults: []models.SimulateTransactionResult{{}}}
			if len(txn.ApplicationArgs) > 0 && bytes.Equal(txn.ApplicationArgs[0], mbrMethod.GetSelector()) {
				ret := binary.BigEndian.AppendUint64([]byte{0x15, 0x1f, 0x7c, 0x75}, mbr)
				group.TxnResults[0].TxnResult.Logs = [][]byte{ret}
			} else {
				group.FailureMessage = "logic eval error: err opcode executed"
			}
			writeJSON(w, models.SimulateResponse{Version: 2, LastRound: 100, TxnGroups: []models.SimulateTransactionGroupResult{group}})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v2/transactions"):
			writeJSON(w, map[string]string{"txId": "SUBMITTED"})
		case strings.Contains(r.URL.Path, "/v2/applications/"):
			writeJSON(w, models.Application{Id: 1, Params: models.ApplicationParams{GlobalState: []models.TealKeyValue{
				{Key: base64.StdEncoding.EncodeToString([]byte("usdc")), Value: models.TealValue{Type: 2, Uint: 31566704}},
				{Key: base64.StdEncoding.EncodeToString([]byte("trea")), Value: models.TealValue{Type: 1, Bytes: base64.StdEncoding.EncodeToString(make([]byte, 32))}},
			}}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(seen)
	}
}

// The wallet New builds opens against the configured escrow as the Signer,
// funds the configured working set, and reads the escrow config before the
// payer holds any ALGO: on a public network the read is simulated from the
// fee sink, since a simulate from an account not in the ledger fails.
func TestNew_BuildsTheWalletFromTheEscrowConfig(t *testing.T) {
	url, senders := fakeEscrowAlgod(t, 123_400)
	cfg := suppliedParts(t)
	cfg.Network.Algod = algod.Config{Network: "testnet", Endpoint: url}
	cfg.Wallet = nil
	cfg.ConcurrentSlots = 7
	cfg.Remedies.RecoverTicket = "recover it by hand"
	c, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Both give-up logs are the only trace of a ticket left on chain.
	if c.refunds.remedy != "recover it by hand" || c.reconcile == nil || c.reconcile.remedy != "recover it by hand" {
		t.Errorf("watchdog remedy %q, reconciler %+v: want both to carry Remedies.RecoverTicket", c.refunds.remedy, c.reconcile)
	}
	w, ok := c.Config().Wallet.(*Wallet)
	if !ok {
		t.Fatalf("wallet %T, want the built *Wallet", c.Config().Wallet)
	}
	if w.PayerAddr() != "PAYER" || w.keystore != cfg.Signer || w.depositSlots != 7 {
		t.Errorf("payer %q keystore %v slots %d, want PAYER, the Signer and 7", w.PayerAddr(), w.keystore, w.depositSlots)
	}
	if w.escrow.AppID != 1 || w.escrow.TicketMbr != 123_400 || w.escrow.UsdcAssetID != 31566704 {
		t.Errorf("escrow app %d mbr %d usdc %d, want the configured app's config", w.escrow.AppID, w.escrow.TicketMbr, w.escrow.UsdcAssetID)
	}
	got := senders()
	if len(got) == 0 {
		t.Fatal("no simulate made")
	}
	for _, s := range got {
		if s != algod.FeeSink("testnet") {
			t.Errorf("simulated from %s, want the testnet fee sink", s)
		}
	}

	// The built wallet gets a reconciler over the default journal, scoped to
	// this payer and app, that leaves the watchdog's live tickets alone.
	r := c.reconcile
	if r == nil || c.journal == nil || r.journal != c.journal || r.payer != "PAYER" || r.appID != 1 {
		t.Fatalf("reconciler %+v over journal %v, want one over the client's journal for PAYER on app 1", r, c.journal)
	}
	if wc, ok := r.chain.(walletChain); !ok || wc.w != w {
		t.Errorf("reconciler chain %#v, want the built wallet", r.chain)
	}
	never := func(context.Context) (string, error) { return "", errors.New("unused") }
	c.refunds.track("LIVE", time.Now().Add(time.Hour),
		func(context.Context) (ticketProbe, error) { return ticketProbe{}, nil }, never, never)
	defer c.refunds.Resolve("LIVE")
	if !r.watching("LIVE") || r.watching("OTHER") {
		t.Error("the reconciler does not defer to the client's refund watchdog")
	}
	c.Close()
	select {
	case <-r.done:
	default:
		t.Error("the reconciler is still running after Close")
	}
}

// Each receipt value lands in its own SettleArgs slot. Every value is distinct
// and non-zero, so a swap or a dropped field fails.
func TestSettleArgsOf_EveryValueInItsSlot(t *testing.T) {
	r := &ticket.UsageReceipt{AmountCharged: 1, TtftMs: 3, DecodeMs: 4, ActualInputCount: 5, ActualOutputCount: 6,
		OutputUsageType: 7, AuxOutputUsageType: 8, AuxOutputCount: 9}
	want := SettleArgs{AmountCharged: 1, ReceiptDigest: ticket.ReceiptSigDigest(r), TtftMs: 3, DecodeMs: 4,
		InputTokens: 5, OutputTokens: 6, OutputUsageType: 7, AuxOutputUsageType: 8, AuxOutputCount: 9}
	if got := settleArgsOf(r); got != want {
		t.Errorf("settleArgsOf =\n  %+v\nwant\n  %+v", got, want)
	}
}

// The payer's settle carries each receipt value in its own slot: the contract
// freezes the ticket on any difference from the operator's half. Every value
// is distinct, so a swap fails.
func TestPayerSettleArgs_EveryValueInItsSlot(t *testing.T) {
	h := &OpenHandle{Operator: Operator{ID: 11, NodeID: 12, OwnerAddr: "OWNER"}, MaxPrice: 13,
		wallet: &Wallet{payerAddr: "PAYER"}}
	a := SettleArgs{AmountCharged: 1, ReceiptDigest: [32]byte{2}, TtftMs: 3, DecodeMs: 4, InputTokens: 5,
		OutputTokens: 6, OutputUsageType: 7, AuxOutputUsageType: 8, AuxOutputCount: 9}
	want := escrow.SettleArgs{
		TicketIDRaw: []byte{10}, AmountCharged: 1, MaxPrice: 13, ReceiptDigest: [32]byte{2}, TtftMs: 3, DecodeMs: 4,
		InputCount: 5, OutputCount: 6, OutputUsageType: 7, AuxOutputUsageType: 8, AuxOutputCount: 9,
		AsOperator: false, PayerAddr: "PAYER", OperatorOwnerAddr: "OWNER", OperatorID: 11, NodeID: 12,
	}
	if got := h.payerSettleArgs([]byte{10}, a); !reflect.DeepEqual(got, want) {
		t.Errorf("payerSettleArgs =\n  %+v\nwant\n  %+v", got, want)
	}
}

// The reconciler's lapse and re-settle reach the chain with the box's owner:
// without it the call cannot name the account the contract pays, and fails.
func TestWalletChain_LapseAndResettleSubmit(t *testing.T) {
	url, _ := fakeEscrowAlgod(t, 123_400)
	payer := crypto.GenerateAccount().Address.String()
	cfg := suppliedParts(t)
	cfg.Signer = fakeSigner{addr: payer}
	cfg.Network.Algod = algod.Config{Network: "testnet", Endpoint: url}
	cfg.Wallet = nil
	c, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	chain := walletChain{c.Config().Wallet.(*Wallet)}
	rec := TicketRecord{TicketID: "NkImzFiSJz3WK6cx7PFU1Q==", Target: NodeRef{Op: 3, Node: 4}, MaxPrice: 99, Settle: &settled}
	box := &escrow.TicketRecord{OperatorOwnerAddr: crypto.GenerateAccount().Address.String()}
	if _, err := chain.lapse(context.Background(), rec, box); err != nil {
		t.Errorf("lapse: %v", err)
	}
	if _, err := chain.resettle(context.Background(), rec, box); err != nil {
		t.Errorf("re-settle: %v", err)
	}
}

// The wallet's chain acts on the journaled ticket, paying the box's operator
// owner, and refuses a re-settle with no recorded receipt.
func TestWalletChain_HandleForARecord(t *testing.T) {
	w := &Wallet{}
	rec := TicketRecord{TicketID: "T", Target: NodeRef{Op: 3, Node: 4}, MaxPrice: 99}
	h := walletChain{w}.handle(rec, &escrow.TicketRecord{OperatorOwnerAddr: "OWNER"})
	if h.TicketID != "T" || h.Operator.ID != 3 || h.Operator.NodeID != 4 || h.Operator.OwnerAddr != "OWNER" ||
		h.MaxPrice != 99 || h.wallet != w {
		t.Errorf("handle = %+v", h)
	}
	if h := (walletChain{w}).handle(rec, nil); h.Operator.OwnerAddr != "" {
		t.Errorf("owner %q without a box", h.Operator.OwnerAddr)
	}
	if _, err := (walletChain{w}).resettle(context.Background(), rec, nil); err == nil {
		t.Error("re-settle without a recorded receipt was submitted")
	}
}

// A caller's wallet gets no reconciler, and so no default journal that only
// grows; a journal the caller supplies is still written.
func TestNew_CallersWalletRunsNoReconciler(t *testing.T) {
	c, err := New(context.Background(), suppliedParts(t))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.reconcile != nil || c.journal != nil {
		t.Errorf("reconciler %v journal %v, want neither", c.reconcile, c.journal)
	}
	cfg := suppliedParts(t)
	j := newMemJournal()
	cfg.Stores.Journal = j
	c2, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if c2.reconcile != nil || c2.journal != j {
		t.Errorf("reconciler %v journal %v, want none and the supplied journal", c2.reconcile, c2.journal)
	}
}

// With RequireMaxOutput and no Tokenizer, the tokenizer New builds must refuse
// a request that names no output budget, not size it at MaxOutputCeiling.
func TestNew_RequireMaxOutputWithoutTokenizer(t *testing.T) {
	registry, err := NewStaticRegistryProvider([]Operator{retryOp(1, "OWNER_A")})
	if err != nil {
		t.Fatal(err)
	}
	rc := &scriptedReserveClient{script: []error{&ReserveHTTPError{Status: 400, Code: "invalid_request"}}}
	cfg := suppliedParts(t)
	cfg.Privacy, cfg.RequireMaxOutput = PrivacyDirect, true
	cfg.Registry, cfg.ReserveClient = registry, rc
	c, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	ze := turnErr(t, c, `{"model":"gpt-test","messages":[{"role":"user","content":"hi"}]}`)
	if ze.Code != "max_output_required" {
		t.Errorf("code %q, want max_output_required", ze.Code)
	}
	if rc.calls() != 0 {
		t.Errorf("%d reserves made for an unsized request", rc.calls())
	}
}

// A caller who never sets Privacy must not send direct: a direct send shows
// the target the payer's IP. Only PrivacyDirect opts out; anything else,
// including a typo, relays.
func TestConfig_RelaysUnlessDirect(t *testing.T) {
	for _, tc := range []struct {
		privacy Privacy
		want    bool
	}{
		{"", true},
		{PrivacyRelayRequired, true},
		{"relay-required", true},
		{PrivacyDirect, false},
	} {
		c := &Config{Privacy: tc.privacy}
		if got := c.relayByDefault(); got != tc.want {
			t.Errorf("Privacy %q: relayByDefault = %v, want %v", tc.privacy, got, tc.want)
		}
	}
}

func TestConfig_TEERequiredOnlyForListedModels(t *testing.T) {
	c := &Config{RequireTEEModels: []string{"listed"}}
	if !c.teeRequired("listed") {
		t.Error("a listed model is not TEE-required")
	}
	if c.teeRequired("other") {
		t.Error("an unlisted model is TEE-required; one entry must not gate every model")
	}
	if (&Config{}).teeRequired("listed") {
		t.Error("an empty list requires TEE")
	}
}

// The Config doc promises a zero Affinity behaves as prefer: the tool-call pin
// leads. AffinityNone is the control that shows the pin is what moved it.
func TestPickCandidates_ZeroAffinityPinsLikePrefer(t *testing.T) {
	const model = "gpt-4o-mini"
	// The pin takes the higher id so a tie-break can't put it first by itself.
	pinned, peer := signerOp(9, model, nil), signerOp(8, model, nil)
	body := []byte(`{"model":"gpt-4o-mini","messages":[{"role":"tool","tool_call_id":"call_1","content":"x"}]}`)

	first := func(policy AffinityPolicy) uint64 {
		srv := minimalTEEServer(t, []Operator{peer, pinned})
		srv.cfg.Affinity.Policy = policy
		srv.toolAffinity = NewIDAffinity(16, time.Minute, time.Now)
		srv.toolAffinity.Record(pinned.ID, pinned.NodeID, []string{"call_1"})
		got := pickChat(t, srv, model, body)
		if len(got.Operators) != 2 {
			t.Fatalf("policy %q: got %v, want both operators", policy, opIDSet(got.Operators))
		}
		return got.Operators[0].ID
	}
	if got := first(AffinityNone); got == pinned.ID {
		t.Fatal("control: the pinned node leads with affinity off, so this test can't tell")
	}
	if got := first(""); got != pinned.ID {
		t.Errorf("zero Affinity: %d leads, want the pinned %d", got, pinned.ID)
	}
}

// Under prefer, an underfunded pin with no funded peer is a model-wide outage.
// Naming the pin and "strict affinity" would send the payer to a knob
// they already have set the way the message recommends.
func TestPickCandidates_ToolAffinityPrefer_UnderfundedPinNotReportedAsStrict(t *testing.T) {
	const model = "gpt-4o-mini"
	pinned := signerOp(7, model, micro(0))
	srv := minimalTEEServer(t, []Operator{pinned})
	srv.cfg.Affinity.Policy = AffinityPrefer
	srv.toolAffinity = NewIDAffinity(16, time.Minute, time.Now)
	srv.toolAffinity.Record(pinned.ID, pinned.NodeID, []string{"call_1"})

	body := []byte(`{"model":"gpt-4o-mini","messages":[{"role":"tool","tool_call_id":"call_1","content":"x"}]}`)
	pick := pickChat(t, srv, model, body)
	if !pick.SignerUnderfundedBlocked {
		t.Fatalf("got %+v, want SignerUnderfundedBlocked", pick)
	}
	if r := pick.SignerUnderfundedReason; r != "" {
		t.Errorf("reason = %q, want empty so the model-wide message is used", r)
	}
}
