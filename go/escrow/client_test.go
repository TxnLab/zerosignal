/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package escrow

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sdkalgod "github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"

	protoalgod "github.com/TxnLab/zerosignal/go/algod"
)

// stubAlgod implements protoalgod.Client for validation-only tests that never
// reach the network. All methods panic — if a test unexpectedly calls one,
// the panic is a clear signal that the guard under test failed to short-circuit.
type stubAlgod struct{}

func (stubAlgod) SuggestedParams(_ context.Context) (types.SuggestedParams, error) {
	panic("stubAlgod: SuggestedParams called unexpectedly")
}
func (stubAlgod) SendRawTransactionGroup(_ context.Context, _ []byte) (string, error) {
	panic("stubAlgod: SendRawTransactionGroup called unexpectedly")
}
func (stubAlgod) PendingTransactionInformation(_ context.Context, _ string) (models.PendingTransactionInfoResponse, error) {
	panic("stubAlgod: PendingTransactionInformation called unexpectedly")
}
func (stubAlgod) PendingTransactions(_ context.Context, _ uint64) (uint64, []types.SignedTxn, error) {
	panic("stubAlgod: PendingTransactions called unexpectedly")
}
func (stubAlgod) SDKClient() *sdkalgod.Client { return &sdkalgod.Client{} }

// TestComposeOpen_BuildsExpectedGroup drives ComposeOpen end-to-end
// against a fake algod that serves suggested-params and echoes back
// a txid for the submit call. That forces the full
// AddMethodCall → BuildGroup → GatherSignatures → VerifyOpenGroup →
// Submit pipeline to run, which catches any ABI-arg type drift on
// the open() method. Also asserts the expected pair of BoxReferences
// made it onto the wire — the contract's open() reads
// operators[operatorID] and writes tickets[ticketId], so both must
// be on the foreign-boxes array or algod rejects the group at
// admission time.
func TestComposeOpen_BuildsExpectedGroup(t *testing.T) {
	const appID = uint64(1234)
	const operatorID = uint64(7)
	const nodeID = uint64(11)

	payer := crypto.GenerateAccount()
	operator := crypto.GenerateAccount()

	algod, gotSubmit := newFakeAlgodForCompose(t)

	client, err := NewClient(appID, algod)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client.TicketMbr = 86_500     // box MBR only
	client.UsdcAssetID = 31566704 // arbitrary non-zero asa id for the test

	ticketIDRaw := make([]byte, 16)
	copy(ticketIDRaw, "ticket-id-16byte")

	res, err := client.ComposeOpen(context.Background(), OpenArgs{
		TicketIDRaw:            ticketIDRaw,
		OperatorID:             operatorID,
		NodeID:                 nodeID,
		PayerAddr:              payer.Address.String(),
		MaxPrice:               1_000_000,
		ExpiresAt:              2_000_000_000,
		SettlementGraceSeconds: 60,
	},
		transaction.BasicAccountTransactionSigner{Account: operator},
		operator.Address.String(),
		transaction.BasicAccountTransactionSigner{Account: payer},
	)
	if err != nil {
		t.Fatalf("ComposeOpen: %v", err)
	}

	if len(res.TxIDs) != 2 {
		t.Fatalf("TxIDs = %d, want 2", len(res.TxIDs))
	}
	if res.GroupID == "" {
		t.Error("GroupID empty")
	}
	if len(res.SignedGroup) != 2 {
		t.Fatalf("SignedGroup members = %d, want 2", len(res.SignedGroup))
	}
	if !*gotSubmit {
		t.Error("fake algod never received a submit call")
	}

	// Group order: usdcPayment, app call. Decode the app call
	// (position 1) and check the expected box references.
	var appCall types.SignedTxn
	if err := msgpack.Decode(res.SignedGroup[1], &appCall); err != nil {
		t.Fatalf("decode app call: %v", err)
	}
	// This is a PAID open (MaxPrice > 0), so the free-quota box is NOT
	// referenced — the contract touches freeQuotas[payer] only when
	// MaxPrice == 0. See TestComposeOpen_FreeOpenReferencesQuotaBox for the
	// free-open case where it IS present.
	wantBoxes := []types.BoxReference{
		{ForeignAppIdx: 0, Name: OperatorBoxKey(operatorID)},
		{ForeignAppIdx: 0, Name: NodeBoxKey(operatorID, nodeID)},
		{ForeignAppIdx: 0, Name: TicketBoxKey(ticketIDRaw)},
	}
	gotBoxes := appCall.Txn.BoxReferences
	if len(gotBoxes) != len(wantBoxes) {
		t.Fatalf("BoxReferences = %d entries, want %d (%+v)", len(gotBoxes), len(wantBoxes), gotBoxes)
	}
	for i, want := range wantBoxes {
		if gotBoxes[i].ForeignAppIdx != want.ForeignAppIdx {
			t.Errorf("BoxReferences[%d].ForeignAppIdx = %d, want %d", i, gotBoxes[i].ForeignAppIdx, want.ForeignAppIdx)
		}
		if !bytes.Equal(gotBoxes[i].Name, want.Name) {
			t.Errorf("BoxReferences[%d].Name = %x, want %x", i, gotBoxes[i].Name, want.Name)
		}
	}

	// Sanity-check the gtxn[1] sender is the operator and fee = 2000
	// (covers both outer txns via Algorand fee pooling).
	if appCall.Txn.Sender != operator.Address {
		t.Errorf("gtxn[1].Sender = %s, want operator %s", appCall.Txn.Sender, operator.Address)
	}
	if appCall.Txn.Fee != types.MicroAlgos(2000) {
		t.Errorf("gtxn[1].Fee = %d, want 2000", appCall.Txn.Fee)
	}

	// Sanity-check gtxn[0] is the payer-signed usdcPayment with fee=0.
	var axfer types.SignedTxn
	if err := msgpack.Decode(res.SignedGroup[0], &axfer); err != nil {
		t.Fatalf("decode axfer: %v", err)
	}
	if axfer.Txn.Sender != payer.Address {
		t.Errorf("gtxn[0].Sender = %s, want payer %s", axfer.Txn.Sender, payer.Address)
	}
	if axfer.Txn.Fee != 0 {
		t.Errorf("gtxn[0].Fee = %d, want 0", axfer.Txn.Fee)
	}

	// Fee bookkeeping: TotalFeeMicroalgos covers the whole group's
	// outer fees (just the operator's gtxn[1] in the new design),
	// PayerFeeMicroalgos isolates the payer's slice (= 0 because
	// gtxn[0] has Fee=0).
	if res.TotalFeeMicroalgos != 2000 {
		t.Errorf("res.TotalFeeMicroalgos = %d, want 2000", res.TotalFeeMicroalgos)
	}
	if res.PayerFeeMicroalgos != 0 {
		t.Errorf("res.PayerFeeMicroalgos = %d, want 0 (payer-signed gtxn[0]/gtxn[1] both have Fee=0)", res.PayerFeeMicroalgos)
	}
}

// TestComposeOpen_FreeOpenReferencesQuotaBox is the MaxPrice == 0 counterpart to
// TestComposeOpen_BuildsExpectedGroup: a free open MUST carry the payer's
// free-quota box, because open() reads and may create freeQuotas[payer] inside
// its MaxPrice == 0 guard and a missing reference is a hard admission failure.
func TestComposeOpen_FreeOpenReferencesQuotaBox(t *testing.T) {
	const appID = uint64(1234)
	const operatorID = uint64(7)
	const nodeID = uint64(11)

	payer := crypto.GenerateAccount()
	operator := crypto.GenerateAccount()
	algod, _ := newFakeAlgodForCompose(t)

	client, err := NewClient(appID, algod)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client.TicketMbr = 86_500
	client.UsdcAssetID = 31566704

	ticketIDRaw := make([]byte, 16)
	copy(ticketIDRaw, "ticket-id-16byte")

	res, err := client.ComposeOpen(context.Background(), OpenArgs{
		TicketIDRaw:            ticketIDRaw,
		OperatorID:             operatorID,
		NodeID:                 nodeID,
		PayerAddr:              payer.Address.String(),
		MaxPrice:               0, // free open — the quota box must be referenced
		ExpiresAt:              2_000_000_000,
		SettlementGraceSeconds: 60,
	},
		transaction.BasicAccountTransactionSigner{Account: operator},
		operator.Address.String(),
		transaction.BasicAccountTransactionSigner{Account: payer},
	)
	if err != nil {
		t.Fatalf("ComposeOpen: %v", err)
	}

	var appCall types.SignedTxn
	if err := msgpack.Decode(res.SignedGroup[1], &appCall); err != nil {
		t.Fatalf("decode app call: %v", err)
	}
	wantBoxes := [][]byte{
		OperatorBoxKey(operatorID),
		NodeBoxKey(operatorID, nodeID),
		TicketBoxKey(ticketIDRaw),
		FreeQuotaBoxKey(payer.Address),
	}
	got := appCall.Txn.BoxReferences
	if len(got) != len(wantBoxes) {
		t.Fatalf("BoxReferences = %d, want %d (operator + node + ticket + free-quota) (%+v)", len(got), len(wantBoxes), got)
	}
	for i, want := range wantBoxes {
		if !bytes.Equal(got[i].Name, want) {
			t.Errorf("BoxReferences[%d].Name = %x, want %x", i, got[i].Name, want)
		}
	}
}

// TestComposeOpen_NoDiscountRefs pins that the HAY fee discount is retired: even
// with HAY/oracle/staking fully configured on the client, the open AppCall
// carries NO HAY/oracle/staking foreign references and no discount inner-txn
// fee. open() snapshots discountBps as 0 and makes no staking/oracle inner-call,
// so gtxn[1] over-fees exactly the 2 outer txns (2 * minFee), only the three
// escrow boxes (operator + node + ticket) are referenced, and only the payer is
// on the account array (for its prepaid-pool local state).
func TestComposeOpen_NoDiscountRefs(t *testing.T) {
	const (
		appID      = uint64(1234)
		operatorID = uint64(7)
		hayAsset   = uint64(99)
		oracleApp  = uint64(555)
		stakingApp = uint64(777)
	)

	payer := crypto.GenerateAccount()
	operator := crypto.GenerateAccount()
	algod, _ := newFakeAlgodForCompose(t)

	client, err := NewClient(appID, algod)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client.TicketMbr = 86_500
	client.UsdcAssetID = 31566704
	// Configure HAY fully — the whole point is that it now makes NO difference
	// to the open group.
	client.HayAssetID = hayAsset
	client.HayOracleAppID = oracleApp
	client.StakingAppID = stakingApp

	ticketIDRaw := make([]byte, 16)
	copy(ticketIDRaw, "ticket-id-16byte")

	res, err := client.ComposeOpen(context.Background(), OpenArgs{
		TicketIDRaw:            ticketIDRaw,
		OperatorID:             operatorID,
		NodeID:                 1,
		PayerAddr:              payer.Address.String(),
		MaxPrice:               1_000_000,
		ExpiresAt:              2_000_000_000,
		SettlementGraceSeconds: 60,
	},
		transaction.BasicAccountTransactionSigner{Account: operator},
		operator.Address.String(),
		transaction.BasicAccountTransactionSigner{Account: payer},
	)
	if err != nil {
		t.Fatalf("ComposeOpen: %v", err)
	}

	var appCall types.SignedTxn
	if err := msgpack.Decode(res.SignedGroup[1], &appCall); err != nil {
		t.Fatalf("decode app call: %v", err)
	}

	// gtxn[1] over-fees exactly 2 outer txns — no discount inner txn.
	if uint64(appCall.Txn.Fee) != 2000 {
		t.Errorf("gtxn[1].Fee = %d, want 2000 (2 outer txns, no discount inner)", appCall.Txn.Fee)
	}
	if res.TotalFeeMicroalgos != 2000 {
		t.Errorf("res.TotalFeeMicroalgos = %d, want 2000", res.TotalFeeMicroalgos)
	}

	// No HAY/oracle/staking foreign refs, despite HAY being configured.
	gotApps := make([]uint64, len(appCall.Txn.ForeignApps))
	for i, a := range appCall.Txn.ForeignApps {
		gotApps[i] = uint64(a)
	}
	if !equalUint64Slice(gotApps, nil) {
		t.Errorf("ForeignApps = %v, want none (HAY discount retired)", gotApps)
	}
	gotAssets := make([]uint64, len(appCall.Txn.ForeignAssets))
	for i, a := range appCall.Txn.ForeignAssets {
		gotAssets[i] = uint64(a)
	}
	if !equalUint64Slice(gotAssets, nil) {
		t.Errorf("ForeignAssets = %v, want none (HAY discount retired)", gotAssets)
	}

	// Only the payer on the account array (for its prepaid-pool local state).
	if len(appCall.Txn.Accounts) != 1 {
		t.Fatalf("Accounts = %v, want exactly [payer]", appCall.Txn.Accounts)
	}
	if appCall.Txn.Accounts[0] != payer.Address {
		t.Errorf("Accounts[0] = %s, want payer %s", appCall.Txn.Accounts[0], payer.Address)
	}

	// Exactly the three escrow boxes a PAID open() touches — no staking box, and
	// no free-quota box (that one rides along only when MaxPrice == 0). Asserted
	// by KEY, not count: a missing/wrong box name is rejected by algod at admit
	// time with an opaque "invalid Box reference", so the names are the part
	// worth pinning.
	wantBoxes := [][]byte{
		OperatorBoxKey(operatorID),
		NodeBoxKey(operatorID, 1),
		TicketBoxKey(ticketIDRaw),
	}
	if len(appCall.Txn.BoxReferences) != len(wantBoxes) {
		t.Fatalf("BoxReferences = %d, want %d (operator + node + ticket, no staking or free-quota box)",
			len(appCall.Txn.BoxReferences), len(wantBoxes))
	}
	for i, want := range wantBoxes {
		if got := appCall.Txn.BoxReferences[i].Name; !bytes.Equal(got, want) {
			t.Errorf("BoxReferences[%d].Name = %q, want %q", i, got, want)
		}
	}
}

func equalUint64Slice(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestComposeDepositMbr_BuildsOptInGroup drives the 2-tx deposit group
// (payment + depositMbr AppCall) end-to-end: the first call opts in
// (OnComplete=OptIn) and fee-pools both outers on the AppCall; a top-up
// is NoOp.
func TestComposeDepositMbr_BuildsOptInGroup(t *testing.T) {
	const appID = uint64(1234)
	payer := crypto.GenerateAccount()
	algod, gotSubmit := newFakeAlgodForCompose(t)
	client, err := NewClient(appID, algod)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	signer := transaction.BasicAccountTransactionSigner{Account: payer}

	res, err := client.ComposeDepositMbr(context.Background(), 922_400, true, signer, payer.Address.String())
	if err != nil {
		t.Fatalf("ComposeDepositMbr: %v", err)
	}
	if !*gotSubmit {
		t.Error("fake algod never received a submit call")
	}
	if res.TxID == "" {
		t.Error("TxID empty")
	}
	// 2 outer (payment + AppCall) pooled on the AppCall.
	if res.FeeMicroalgos != 2000 {
		t.Errorf("FeeMicroalgos = %d, want 2000", res.FeeMicroalgos)
	}
	var appCall types.SignedTxn
	if err := msgpack.Decode(res.SignedTxn, &appCall); err != nil {
		t.Fatalf("decode app call: %v", err)
	}
	if appCall.Txn.Type != types.ApplicationCallTx {
		t.Errorf("SignedTxn type = %q, want appl", appCall.Txn.Type)
	}
	if appCall.Txn.OnCompletion != types.OptInOC {
		t.Errorf("OnCompletion = %d, want OptIn (%d)", appCall.Txn.OnCompletion, types.OptInOC)
	}
	if appCall.Txn.Sender != payer.Address {
		t.Errorf("AppCall sender = %s, want payer %s", appCall.Txn.Sender, payer.Address)
	}

	// Top-up variant is NoOp.
	res2, err := client.ComposeDepositMbr(context.Background(), 115_300, false, signer, payer.Address.String())
	if err != nil {
		t.Fatalf("ComposeDepositMbr top-up: %v", err)
	}
	var appCall2 types.SignedTxn
	if err := msgpack.Decode(res2.SignedTxn, &appCall2); err != nil {
		t.Fatalf("decode top-up app call: %v", err)
	}
	if appCall2.Txn.OnCompletion != types.NoOpOC {
		t.Errorf("top-up OnCompletion = %d, want NoOp (%d)", appCall2.Txn.OnCompletion, types.NoOpOC)
	}

	// Zero amount is rejected.
	if _, err := client.ComposeDepositMbr(context.Background(), 0, false, signer, payer.Address.String()); err == nil {
		t.Error("ComposeDepositMbr(0) should error")
	}
}

// TestComposeWithdrawAndClose_Fees covers the single-txn pool-management
// methods: each fee-pools 1 outer + 1 inner refund (2 × minTxnFee), and
// closeDeposit carries OnComplete=CloseOut.
func TestComposeWithdrawAndClose_Fees(t *testing.T) {
	const appID = uint64(1234)
	payer := crypto.GenerateAccount()
	algod, _ := newFakeAlgodForCompose(t)
	client, err := NewClient(appID, algod)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	signer := transaction.BasicAccountTransactionSigner{Account: payer}

	wres, err := client.ComposeWithdrawMbr(context.Background(), 230_600, signer, payer.Address.String())
	if err != nil {
		t.Fatalf("ComposeWithdrawMbr: %v", err)
	}
	if wres.FeeMicroalgos != 2000 { // 1 outer + 1 inner refund
		t.Errorf("withdraw fee = %d, want 2000", wres.FeeMicroalgos)
	}
	if _, err := client.ComposeWithdrawMbr(context.Background(), 0, signer, payer.Address.String()); err == nil {
		t.Error("ComposeWithdrawMbr(0) should error")
	}

	cres, err := client.ComposeCloseDeposit(context.Background(), signer, payer.Address.String())
	if err != nil {
		t.Fatalf("ComposeCloseDeposit: %v", err)
	}
	if cres.FeeMicroalgos != 2000 { // 1 outer + 1 inner refund
		t.Errorf("close fee = %d, want 2000", cres.FeeMicroalgos)
	}
	var closeCall types.SignedTxn
	if err := msgpack.Decode(cres.SignedTxn, &closeCall); err != nil {
		t.Fatalf("decode close call: %v", err)
	}
	if closeCall.Txn.OnCompletion != types.CloseOutOC {
		t.Errorf("close OnCompletion = %d, want CloseOut (%d)", closeCall.Txn.OnCompletion, types.CloseOutOC)
	}
}

// newFakeAlgodForAccount stands up an httptest.Server that serves a
// single GET /v2/accounts/{addr} account-info body verbatim — enough for
// IsPayerOptedIn, which only reads AppsLocalState. `appsLocalStateJSON`
// is spliced into the response's apps-local-state array (pass "" for a
// not-opted-in account).
func newFakeAlgodForAccount(t *testing.T, addr, appsLocalStateJSON string) protoalgod.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/v2/accounts/") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{
				"address": "`+addr+`",
				"amount": 1000000,
				"amount-without-pending-rewards": 1000000,
				"min-balance": 100000,
				"pending-rewards": 0,
				"rewards": 0,
				"round": 100,
				"status": "Offline",
				"apps-local-state": [`+appsLocalStateJSON+`]
			}`)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	c, err := protoalgod.NewClient(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// TestIsPayerOptedIn covers the opt-in probe IsPayerOptedIn uses to pick
// the depositMbr OnComplete (OptIn on first deposit, NoOp on top-up). It
// reports true only when the account's apps-local-state names this app id
// — the distinction ReadPayerDeposit / payerDeposit cannot make (both
// report a zero tuple for a drained-but-opted-in pool).
func TestIsPayerOptedIn(t *testing.T) {
	const appID = uint64(1234)
	payer := crypto.GenerateAccount()
	addr := payer.Address.String()
	ctx := context.Background()

	// Opted into the escrow app (has a pool record) → true.
	{
		algod := newFakeAlgodForAccount(t, addr, `{"id":1234,"schema":{"num-uint":2,"num-byte-slice":0},"key-value":[]}`)
		client, err := NewClient(appID, algod)
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		opted, err := client.IsPayerOptedIn(ctx, addr)
		if err != nil {
			t.Fatalf("IsPayerOptedIn: %v", err)
		}
		if !opted {
			t.Error("opted = false, want true (account has a local-state record for this app)")
		}
	}

	// No local state at all → false.
	{
		algod := newFakeAlgodForAccount(t, addr, "")
		client, err := NewClient(appID, algod)
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		opted, err := client.IsPayerOptedIn(ctx, addr)
		if err != nil {
			t.Fatalf("IsPayerOptedIn: %v", err)
		}
		if opted {
			t.Error("opted = true, want false (empty apps-local-state)")
		}
	}

	// Opted into some *other* app only → false (must match THIS app id).
	{
		algod := newFakeAlgodForAccount(t, addr, `{"id":9999,"schema":{"num-uint":1,"num-byte-slice":0},"key-value":[]}`)
		client, err := NewClient(appID, algod)
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		opted, err := client.IsPayerOptedIn(ctx, addr)
		if err != nil {
			t.Fatalf("IsPayerOptedIn: %v", err)
		}
		if opted {
			t.Error("opted = true, want false (only opted into a different app)")
		}
	}
}

// newFakeAlgodForCompose stands up an httptest.Server that serves the
// two endpoints ComposeOpen touches: GET /v2/transactions/params for
// SuggestedParams, and POST /v2/transactions for ATC.Submit. Returns
// a protoalgod.Client pointed at it plus a bool pointer that flips
// true when the submit endpoint is hit.
// newFakeAlgod serves suggested-params and hands the submit POST to onSubmit,
// so a test can choose between a committed group and a contract revert.
func newFakeAlgod(t *testing.T, onSubmit http.HandlerFunc) protoalgod.Client {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v2/transactions/params"):
			w.Header().Set("Content-Type", "application/json")
			// GenesisHash is arbitrary but must base64-decode to 32 bytes
			// for the SDK to accept the response.
			gh := base64.StdEncoding.EncodeToString(make([]byte, 32))
			_, _ = io.WriteString(w, `{
				"consensus-version": "v30",
				"fee": 1000,
				"genesis-id": "dev-v1",
				"genesis-hash": "`+gh+`",
				"last-round": 100,
				"min-fee": 1000
			}`)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v2/transactions"):
			_, _ = io.Copy(io.Discard, r.Body)
			onSubmit(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	c, err := protoalgod.NewClient(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func newFakeAlgodForCompose(t *testing.T) (protoalgod.Client, *bool) {
	t.Helper()
	gotSubmit := false
	c := newFakeAlgod(t, func(w http.ResponseWriter, _ *http.Request) {
		gotSubmit = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"txId":"FAKETXID"}`)
	})
	return c, &gotSubmit
}

// newFakeAlgodRejectingSubmit answers the submit with algod's real
// logic-eval-error shape for the given PC. algod knows nothing about the
// contract's assert strings — a PC is the entire signal on the wire — which is
// what makes the source-map lookup in enrichSubmitError load-bearing rather
// than cosmetic.
func newFakeAlgodRejectingSubmit(t *testing.T, pc uint64) protoalgod.Client {
	t.Helper()
	return newFakeAlgod(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(w, `{"message":"TransactionPool.Remember: transaction ABC: logic eval error: assert failed pc=%d. Details: pc=%d, opcodes=..."}`, pc, pc)
	})
}

// TestComposeOpen_ValidatesInputs covers the early-return guards in
// ComposeOpen (ticket id length, empty MBR/USDC, zero operator id,
// missing or bad payer address). Hits pre-network validation only, so
// no fake algod is needed — any attempt to reach the network would
// panic the test.
func TestComposeOpen_ValidatesInputs(t *testing.T) {
	payer := crypto.GenerateAccount()
	operator := crypto.GenerateAccount()
	opSigner := transaction.BasicAccountTransactionSigner{Account: operator}
	paySigner := transaction.BasicAccountTransactionSigner{Account: payer}
	ctx := context.Background()

	// Uninitialized TicketMbr: dedicated error.
	{
		client := &Client{AppID: 1, AppAddr: crypto.GetApplicationAddress(1), Algod: stubAlgod{}, UsdcAssetID: 31566704}
		_, err := client.ComposeOpen(ctx, OpenArgs{
			TicketIDRaw: make([]byte, 16),
			OperatorID:  1,
			PayerAddr:   payer.Address.String(),
		}, opSigner, operator.Address.String(), paySigner)
		if err == nil || !strings.Contains(err.Error(), "ticket MBR not loaded") {
			t.Errorf("expected MBR-not-loaded error, got %v", err)
		}
	}

	// Uninitialized UsdcAssetID: dedicated error.
	{
		client := &Client{AppID: 1, AppAddr: crypto.GetApplicationAddress(1), Algod: stubAlgod{}, TicketMbr: 86_500}
		_, err := client.ComposeOpen(ctx, OpenArgs{
			TicketIDRaw: make([]byte, 16),
			OperatorID:  1,
			PayerAddr:   payer.Address.String(),
		}, opSigner, operator.Address.String(), paySigner)
		if err == nil || !strings.Contains(err.Error(), "USDC asset id not loaded") {
			t.Errorf("expected USDC-not-loaded error, got %v", err)
		}
	}

	// Wrong ticket id length.
	{
		client := &Client{AppID: 1, AppAddr: crypto.GetApplicationAddress(1), Algod: stubAlgod{}, TicketMbr: 86_500, UsdcAssetID: 31566704}
		_, err := client.ComposeOpen(ctx, OpenArgs{
			TicketIDRaw: make([]byte, 15),
			OperatorID:  1,
			PayerAddr:   payer.Address.String(),
		}, opSigner, operator.Address.String(), paySigner)
		if err == nil || !strings.Contains(err.Error(), "ticket id must be 16 bytes") {
			t.Errorf("expected ticket-id-length error, got %v", err)
		}
	}

	// Zero operator id.
	{
		client := &Client{AppID: 1, AppAddr: crypto.GetApplicationAddress(1), Algod: stubAlgod{}, TicketMbr: 86_500, UsdcAssetID: 31566704}
		_, err := client.ComposeOpen(ctx, OpenArgs{
			TicketIDRaw: make([]byte, 16),
			OperatorID:  0,
			PayerAddr:   payer.Address.String(),
		}, opSigner, operator.Address.String(), paySigner)
		if err == nil || !strings.Contains(err.Error(), "operator id must be > 0") {
			t.Errorf("expected operator-id-zero error, got %v", err)
		}
	}

	// Zero node id.
	{
		client := &Client{AppID: 1, AppAddr: crypto.GetApplicationAddress(1), Algod: stubAlgod{}, TicketMbr: 86_500, UsdcAssetID: 31566704}
		_, err := client.ComposeOpen(ctx, OpenArgs{
			TicketIDRaw: make([]byte, 16),
			OperatorID:  1,
			NodeID:      0,
			PayerAddr:   payer.Address.String(),
		}, opSigner, operator.Address.String(), paySigner)
		if err == nil || !strings.Contains(err.Error(), "node id must be > 0") {
			t.Errorf("expected node-id-zero error, got %v", err)
		}
	}

	// Missing payer address.
	{
		client := &Client{AppID: 1, AppAddr: crypto.GetApplicationAddress(1), Algod: stubAlgod{}, TicketMbr: 86_500, UsdcAssetID: 31566704}
		_, err := client.ComposeOpen(ctx, OpenArgs{
			TicketIDRaw: make([]byte, 16),
			OperatorID:  1,
			NodeID:      1,
		}, opSigner, operator.Address.String(), paySigner)
		if err == nil || !strings.Contains(err.Error(), "payer addr is required") {
			t.Errorf("expected payer-addr-required error, got %v", err)
		}
	}

	// Bad payer address.
	{
		client := &Client{AppID: 1, AppAddr: crypto.GetApplicationAddress(1), Algod: stubAlgod{}, TicketMbr: 86_500, UsdcAssetID: 31566704}
		_, err := client.ComposeOpen(ctx, OpenArgs{
			TicketIDRaw: make([]byte, 16),
			OperatorID:  1,
			NodeID:      1,
			PayerAddr:   "not-an-address",
		}, opSigner, operator.Address.String(), paySigner)
		if err == nil || !strings.Contains(err.Error(), "decode payer addr") {
			t.Errorf("expected decode-payer error, got %v", err)
		}
	}
}

// TestComposeOpenGroup_SplitSigners covers the consensus-verified-operator
// reserve/open split: ComposeOpenGroup is the node-side composer that
// signs gtxn[1] only; SubmitPresignedOpenGroup is the proxy-side
// completer that signs gtxn[0] and submits. EncodeOpenGroup /
// DecodeOpenGroup are the wire helpers in between. This test runs the
// whole round-trip end-to-end (operator-signed gtxn[1] survives the
// base64-msgpack round-trip; group hash is preserved; final group
// passes VerifyOpenGroup).
func TestComposeOpenGroup_SplitSigners(t *testing.T) {
	const appID = uint64(1234)
	const operatorID = uint64(7)

	payer := crypto.GenerateAccount()
	operator := crypto.GenerateAccount()

	algod, gotSubmit := newFakeAlgodForCompose(t)

	client, err := NewClient(appID, algod)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client.TicketMbr = 86_500
	client.UsdcAssetID = 31566704

	ticketIDRaw := make([]byte, 16)
	copy(ticketIDRaw, "ticket-id-16byte")

	args := OpenArgs{
		TicketIDRaw:            ticketIDRaw,
		OperatorID:             operatorID,
		NodeID:                 11,
		PayerAddr:              payer.Address.String(),
		MaxPrice:               1_000_000,
		ExpiresAt:              2_000_000_000,
		SettlementGraceSeconds: 60,
	}

	// Node side: build the partially-signed group.
	group, err := client.ComposeOpenGroup(
		context.Background(),
		args,
		transaction.BasicAccountTransactionSigner{Account: operator},
		operator.Address.String(),
	)
	if err != nil {
		t.Fatalf("ComposeOpenGroup: %v", err)
	}
	if len(group) != 2 {
		t.Fatalf("ComposeOpenGroup returned %d txns, want 2", len(group))
	}

	// gtxn[1] (open AppCall) is operator-signed; gtxn[0] (usdcPayment) has empty Sig.
	if group[1].Sig == (types.Signature{}) {
		t.Error("gtxn[1] Sig is empty; operator should have signed it")
	}
	if group[0].Sig != (types.Signature{}) {
		t.Error("gtxn[0] Sig is non-empty; should be unsigned at this stage")
	}

	// gtxn[1].sender == operator; gtxn[0].sender == payer.
	if group[1].Txn.Sender != operator.Address {
		t.Errorf("gtxn[1].Sender = %s, want operator %s", group[1].Txn.Sender, operator.Address)
	}
	if group[0].Txn.Sender != payer.Address {
		t.Errorf("gtxn[0].Sender = %s, want payer %s", group[0].Txn.Sender, payer.Address)
	}

	// Wire round-trip: encode, decode, ensure identity.
	encoded, err := EncodeOpenGroup(group)
	if err != nil {
		t.Fatalf("EncodeOpenGroup: %v", err)
	}
	if encoded == "" {
		t.Fatal("EncodeOpenGroup returned empty string")
	}
	decoded, err := DecodeOpenGroup(encoded)
	if err != nil {
		t.Fatalf("DecodeOpenGroup: %v", err)
	}
	if len(decoded) != 2 {
		t.Fatalf("DecodeOpenGroup returned %d txns, want 2", len(decoded))
	}
	if decoded[1].Sig != group[1].Sig {
		t.Error("operator sig did not survive round-trip")
	}

	// Proxy side: verify + complete signing + submit. The spec mirrors what
	// a payer-side caller pins from its signature-verified ticket.
	spec := OpenGroupSpec{
		AppID:                  appID,
		AppAddress:             client.AppAddr,
		TicketIDRaw:            ticketIDRaw,
		OperatorID:             operatorID,
		NodeID:                 11,
		MaxPrice:               1_000_000,
		TicketMbr:              client.TicketMbr,
		UsdcAssetID:            client.UsdcAssetID,
		NodeSigningAddr:        operator.Address,
		PayerAddr:              payer.Address,
		ExpiresAt:              2_000_000_000,
		SettlementGraceSeconds: 60,
	}
	res, err := client.SubmitPresignedOpenGroup(
		context.Background(),
		decoded,
		transaction.BasicAccountTransactionSigner{Account: payer},
		spec,
	)
	if err != nil {
		t.Fatalf("SubmitPresignedOpenGroup: %v", err)
	}

	// A spec that disagrees with the node-authored window args must refuse
	// BEFORE signing/submitting — this is the payer-side pin on
	// settlementGraceSeconds (a hostile node stretching the refundInactive
	// deadline) and, below, on a tampered usdcPayment amount (a hostile node
	// steering the payer's blind-signed transfer).
	badGrace := spec
	badGrace.SettlementGraceSeconds = 0
	if _, err := client.SubmitPresignedOpenGroup(
		context.Background(), decoded,
		transaction.BasicAccountTransactionSigner{Account: payer}, badGrace,
	); err == nil || !strings.Contains(err.Error(), "settlementGraceSeconds") {
		t.Errorf("grace-mismatched spec: err = %v, want settlementGraceSeconds refusal", err)
	}
	tampered := make([]types.SignedTxn, 2)
	copy(tampered, decoded)
	tampered[0].Txn.AssetAmount = 50_000_000 // node-composed transfer inflated past max_price
	if _, err := client.SubmitPresignedOpenGroup(
		context.Background(), regrouped(t, tampered),
		transaction.BasicAccountTransactionSigner{Account: payer}, spec,
	); err == nil || !strings.Contains(err.Error(), "asset_amount") {
		t.Errorf("tampered usdcPayment: err = %v, want asset_amount refusal", err)
	}
	if !*gotSubmit {
		t.Error("fake algod never received a submit call")
	}
	if len(res.TxIDs) != 2 {
		t.Errorf("res.TxIDs = %d, want 2", len(res.TxIDs))
	}
	if res.GroupID == "" {
		t.Error("res.GroupID empty")
	}
	if res.TotalFeeMicroalgos != 2000 {
		t.Errorf("res.TotalFeeMicroalgos = %d, want 2000 (operator's fee pool)", res.TotalFeeMicroalgos)
	}
	if res.PayerFeeMicroalgos != 0 {
		t.Errorf("res.PayerFeeMicroalgos = %d, want 0 (payer-signed gtxn[0] has Fee=0; operator pools)", res.PayerFeeMicroalgos)
	}
}

// TestSubmitPresignedOpenGroup_RevertIsTyped crosses the seam nothing else
// does: a real open() revert, from the real submit path, arriving at the
// caller as an *ApprovalError carrying the source-mapped assert message.
//
// It matters because the proxy's MBR-pool classifier reads exactly that type,
// and the classifier can be tested green all day against a hand-built value
// while this function returns something else entirely — which is the state it
// was in before, matching a shape production never produced. algod puts only
// "assert failed pc=NNN" on the wire, so if this path skips enrichSubmitError
// there is no message to classify on at all.
func TestSubmitPresignedOpenGroup_RevertIsTyped(t *testing.T) {
	const appID = uint64(1234)
	const operatorID = uint64(7)
	const nodeID = uint64(11)

	spec, err := GetSpec()
	if err != nil {
		t.Fatal(err)
	}
	// Drive off the assert the proxy actually classifies on, at whatever PC
	// this build of the contract compiled it to.
	pc := pcsForApprovalMessage(t, spec, AssertInsufficientMbrDeposit)[0]

	payer := crypto.GenerateAccount()
	operator := crypto.GenerateAccount()

	client, err := NewClient(appID, newFakeAlgodRejectingSubmit(t, pc))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client.TicketMbr = 86_500
	client.UsdcAssetID = 31566704

	ticketIDRaw := make([]byte, 16)
	copy(ticketIDRaw, "ticket-id-16byte")

	group, err := client.ComposeOpenGroup(
		context.Background(),
		OpenArgs{
			TicketIDRaw:            ticketIDRaw,
			OperatorID:             operatorID,
			NodeID:                 nodeID,
			PayerAddr:              payer.Address.String(),
			MaxPrice:               1_000_000,
			ExpiresAt:              2_000_000_000,
			SettlementGraceSeconds: 60,
		},
		transaction.BasicAccountTransactionSigner{Account: operator},
		operator.Address.String(),
	)
	if err != nil {
		t.Fatalf("ComposeOpenGroup: %v", err)
	}

	_, err = client.SubmitPresignedOpenGroup(
		context.Background(),
		group,
		transaction.BasicAccountTransactionSigner{Account: payer},
		OpenGroupSpec{
			AppID:                  appID,
			AppAddress:             client.AppAddr,
			TicketIDRaw:            ticketIDRaw,
			OperatorID:             operatorID,
			NodeID:                 nodeID,
			MaxPrice:               1_000_000,
			TicketMbr:              client.TicketMbr,
			UsdcAssetID:            client.UsdcAssetID,
			NodeSigningAddr:        operator.Address,
			PayerAddr:              payer.Address,
			ExpiresAt:              2_000_000_000,
			SettlementGraceSeconds: 60,
		},
	)
	if err == nil {
		t.Fatal("submit against a rejecting algod returned nil error")
	}

	revert, ok := errors.AsType[*ApprovalError](err)
	if !ok {
		t.Fatalf("err = %v, want an *ApprovalError so callers can classify the revert", err)
	}
	if revert.Method != "open" {
		t.Errorf("Method = %q, want %q — callers and logs name the failing call by it", revert.Method, "open")
	}
	if revert.PC != pc {
		t.Errorf("PC = %d, want %d", revert.PC, pc)
	}
	if revert.Message != AssertInsufficientMbrDeposit {
		t.Errorf("Message = %q, want %q", revert.Message, AssertInsufficientMbrDeposit)
	}
}

// TestComposeOpen_RevertIsTyped is the twin of the above for the non-presigned
// open path. ComposeOpen has no production caller today, which is exactly why
// it needs the pin: the two submit paths must not diverge silently, and the
// day something routes an open through this one, an unenriched error would
// downgrade the proxy's actionable "raise zs.concurrent_slots" 429 to an
// opaque 502 with nothing failing.
func TestComposeOpen_RevertIsTyped(t *testing.T) {
	const appID = uint64(1234)

	spec, err := GetSpec()
	if err != nil {
		t.Fatal(err)
	}
	pc := pcsForApprovalMessage(t, spec, AssertInsufficientMbrDeposit)[0]

	payer := crypto.GenerateAccount()
	operator := crypto.GenerateAccount()

	client, err := NewClient(appID, newFakeAlgodRejectingSubmit(t, pc))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client.TicketMbr = 86_500
	client.UsdcAssetID = 31566704

	ticketIDRaw := make([]byte, 16)
	copy(ticketIDRaw, "ticket-id-16byte")

	_, err = client.ComposeOpen(context.Background(), OpenArgs{
		TicketIDRaw:            ticketIDRaw,
		OperatorID:             7,
		NodeID:                 11,
		PayerAddr:              payer.Address.String(),
		MaxPrice:               1_000_000,
		ExpiresAt:              2_000_000_000,
		SettlementGraceSeconds: 60,
	},
		transaction.BasicAccountTransactionSigner{Account: operator},
		operator.Address.String(),
		transaction.BasicAccountTransactionSigner{Account: payer},
	)
	if err == nil {
		t.Fatal("ComposeOpen against a rejecting algod returned nil error")
	}
	revert, ok := errors.AsType[*ApprovalError](err)
	if !ok {
		t.Fatalf("err = %v, want an *ApprovalError", err)
	}
	if revert.Method != "open" || revert.PC != pc || revert.Message != AssertInsufficientMbrDeposit {
		t.Errorf("revert = %+v, want method=open pc=%d message=%q", revert, pc, AssertInsufficientMbrDeposit)
	}
}

// TestSubmitSingle_SettleLapsedRevertIsTyped covers the submit path the NODE
// actually consumes, and it is the one that matters most: ComposeSettleLapsed
// → submitSingle is the only production route into the settlement driver's
// lapse switch. The node's own tests build the *ApprovalError by hand, so they
// prove the switch is right and prove nothing about whether production ever
// hands it that type — drop the enrichment here and all four errors.Is cases
// miss at once, every permanent revert rejoins the transient retry tail, and
// the driver eventually writes a terminal failed row for a ticket that only
// needed to wait.
func TestSubmitSingle_SettleLapsedRevertIsTyped(t *testing.T) {
	const appID = uint64(1234)

	spec, err := GetSpec()
	if err != nil {
		t.Fatal(err)
	}
	pc := pcsForApprovalMessage(t, spec, AssertTooEarlyToLapseSettle)[0]

	payer := crypto.GenerateAccount()
	operator := crypto.GenerateAccount()
	opOwner := crypto.GenerateAccount()
	treasury := crypto.GenerateAccount()

	client, err := NewClient(appID, newFakeAlgodRejectingSubmit(t, pc))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client.UsdcAssetID = 31566704
	client.Treasury = treasury.Address.String()

	ticketIDRaw := make([]byte, 16)
	copy(ticketIDRaw, "ticket-id-16byte")

	_, err = client.ComposeSettleLapsed(context.Background(), SettleLapsedArgs{
		TicketIDRaw:       ticketIDRaw,
		OperatorID:        7,
		NodeID:            11,
		OperatorOwnerAddr: opOwner.Address.String(),
		PayerAddr:         payer.Address.String(),
	}, transaction.BasicAccountTransactionSigner{Account: operator}, operator.Address.String())
	if err == nil {
		t.Fatal("ComposeSettleLapsed against a rejecting algod returned nil error")
	}

	if !errors.Is(err, ErrTooEarlyToLapseSettle) {
		t.Errorf("err = %v, want it to resolve to ErrTooEarlyToLapseSettle", err)
	}
	revert, ok := errors.AsType[*ApprovalError](err)
	if !ok {
		t.Fatalf("err = %v, want an *ApprovalError", err)
	}
	if revert.Method != "settleLapsed" || revert.PC != pc || revert.Message != AssertTooEarlyToLapseSettle {
		t.Errorf("revert = %+v, want method=settleLapsed pc=%d message=%q", revert, pc, AssertTooEarlyToLapseSettle)
	}
}

// TestSubmitPresignedSettleGroup_RevertIsTyped is the third of the three
// submit paths. A settle group reverts on the same guards the settlement
// driver fails fast on, so losing the typed form here means those reverts
// silently rejoin the retry budget instead of terminating.
func TestSubmitPresignedSettleGroup_RevertIsTyped(t *testing.T) {
	const appID = uint64(1234)

	spec, err := GetSpec()
	if err != nil {
		t.Fatal(err)
	}
	pc := pcsForApprovalMessage(t, spec, AssertTicketNotFound)[0]

	payer := crypto.GenerateAccount()
	operator := crypto.GenerateAccount()
	opOwner := crypto.GenerateAccount()
	treasury := crypto.GenerateAccount()

	client, err := NewClient(appID, newFakeAlgodRejectingSubmit(t, pc))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client.UsdcAssetID = 31566704
	client.Treasury = treasury.Address.String()

	ticketIDRaw := make([]byte, 16)
	copy(ticketIDRaw, "ticket-id-16byte")
	var digest [32]byte
	copy(digest[:], "digest-32-bytes-receipt-xxxxxxxxxxx")

	args := SettleArgs{
		TicketIDRaw:       ticketIDRaw,
		AmountCharged:     50_000,
		MaxPrice:          60_000,
		ReceiptDigest:     digest,
		TtftMs:            1200,
		DecodeMs:          300,
		InputCount:        250,
		OutputCount:       750,
		OutputUsageType:   1,
		PayerAddr:         payer.Address.String(),
		OperatorOwnerAddr: opOwner.Address.String(),
		OperatorID:        7,
	}
	group, err := client.ComposeSettleGroup(
		context.Background(),
		args,
		transaction.BasicAccountTransactionSigner{Account: operator},
		operator.Address.String(),
	)
	if err != nil {
		t.Fatalf("ComposeSettleGroup: %v", err)
	}

	_, err = client.SubmitPresignedSettleGroup(
		context.Background(),
		group,
		transaction.BasicAccountTransactionSigner{Account: payer},
		SettleGroupSpec{
			AppID:               appID,
			TicketIDRaw:         ticketIDRaw,
			AmountCharged:       args.AmountCharged,
			ReceiptDigest:       digest,
			TtftMs:              args.TtftMs,
			DecodeMs:            args.DecodeMs,
			InputCount:          args.InputCount,
			OutputCount:         args.OutputCount,
			OutputUsageType:     args.OutputUsageType,
			PayerAddr:           payer.Address,
			OperatorSigningAddr: operator.Address,
		},
	)
	if err == nil {
		t.Fatal("submit against a rejecting algod returned nil error")
	}
	if !errors.Is(err, ErrTicketNotFound) {
		t.Errorf("err = %v, want it to resolve to ErrTicketNotFound", err)
	}
	revert, ok := errors.AsType[*ApprovalError](err)
	if !ok {
		t.Fatalf("err = %v, want an *ApprovalError", err)
	}
	if revert.Method != "settle" || revert.Message != AssertTicketNotFound {
		t.Errorf("revert = %+v, want method=settle message=%q", revert, AssertTicketNotFound)
	}
}

// TestComposeSettleGroup_SplitSigners covers the atomic-settle split:
// node signs gtxn[0] (operator first-half, asOperator=true, and the whole
// group's pooled fee), proxy signs gtxn[1] (payer ack, asOperator=false,
// fee=0) and submits. Fee sizing per case is pinned in
// TestComposeSettleGroup_FeeSizing.
func TestComposeSettleGroup_SplitSigners(t *testing.T) {
	const appID = uint64(1234)
	payer := crypto.GenerateAccount()
	operator := crypto.GenerateAccount()
	opOwner := crypto.GenerateAccount()
	treasury := crypto.GenerateAccount()

	algod, gotSubmit := newFakeAlgodForCompose(t)

	client, err := NewClient(appID, algod)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client.UsdcAssetID = 31566704
	client.Treasury = treasury.Address.String()

	ticketIDRaw := make([]byte, 16)
	copy(ticketIDRaw, "ticket-id-16byte")

	var digest [32]byte
	copy(digest[:], "digest-32-bytes-receipt-xxxxxxxxxxx")

	args := SettleArgs{
		TicketIDRaw:       ticketIDRaw,
		AmountCharged:     50_000,
		MaxPrice:          60_000, // headroom → all 3 disbursement inners fire
		ReceiptDigest:     digest,
		TtftMs:            1200,
		DecodeMs:          300,
		InputCount:        250,
		OutputCount:       750,
		OutputUsageType:   1, // ticket.UsageTypeTokens
		PayerAddr:         payer.Address.String(),
		OperatorOwnerAddr: opOwner.Address.String(),
		OperatorID:        7,
		GapOpUps:          1, // cold last-settle-day tracker
	}

	// Node side: build the partially-signed group.
	group, err := client.ComposeSettleGroup(
		context.Background(),
		args,
		transaction.BasicAccountTransactionSigner{Account: operator},
		operator.Address.String(),
	)
	if err != nil {
		t.Fatalf("ComposeSettleGroup: %v", err)
	}
	if len(group) != 2 {
		t.Fatalf("group len = %d, want 2", len(group))
	}
	if group[0].Sig == (types.Signature{}) {
		t.Error("gtxn[0] should be operator-signed")
	}
	if group[1].Sig != (types.Signature{}) {
		t.Error("gtxn[1] should be unsigned at this stage")
	}
	if group[0].Txn.Sender != operator.Address {
		t.Errorf("gtxn[0].Sender = %s, want operator %s", group[0].Txn.Sender, operator.Address)
	}
	if group[1].Txn.Sender != payer.Address {
		t.Errorf("gtxn[1].Sender = %s, want payer %s", group[1].Txn.Sender, payer.Address)
	}
	if group[0].Txn.Fee != types.MicroAlgos(6000) {
		t.Errorf("gtxn[0].Fee = %d, want 6000", group[0].Txn.Fee)
	}
	if group[1].Txn.Fee != 0 {
		t.Errorf("gtxn[1].Fee = %d, want 0", group[1].Txn.Fee)
	}

	// Treasury must appear in both txns' AppAccounts so the AVM
	// authorizes the inner USDC fee transfer finalizeSettlement fires.
	for i, tx := range []types.SignedTxn{group[0], group[1]} {
		if !containsAddr(tx.Txn.Accounts, treasury.Address) {
			t.Errorf("gtxn[%d].AppAccounts missing treasury %s (got %v)", i, treasury.Address, tx.Txn.Accounts)
		}
	}

	// Wire round-trip.
	encoded, err := EncodeSettleGroup(group)
	if err != nil {
		t.Fatalf("EncodeSettleGroup: %v", err)
	}
	decoded, err := DecodeSettleGroup(encoded)
	if err != nil {
		t.Fatalf("DecodeSettleGroup: %v", err)
	}
	if decoded[0].Sig != group[0].Sig {
		t.Error("operator sig didn't survive round-trip")
	}

	// Proxy side: complete signing + submit. The spec pins every value the
	// verifier compares against — sourced (as in production) from the same
	// receipt/args the node composed the group from, so a well-formed group
	// passes.
	spec := SettleGroupSpec{
		AppID:               appID,
		TicketIDRaw:         ticketIDRaw,
		AmountCharged:       args.AmountCharged,
		ReceiptDigest:       digest,
		TtftMs:              args.TtftMs,
		DecodeMs:            args.DecodeMs,
		InputCount:          args.InputCount,
		OutputCount:         args.OutputCount,
		OutputUsageType:     args.OutputUsageType,
		AuxOutputUsageType:  args.AuxOutputUsageType,
		AuxOutputCount:      args.AuxOutputCount,
		PayerAddr:           payer.Address,
		OperatorSigningAddr: operator.Address,
	}
	res, err := client.SubmitPresignedSettleGroup(
		context.Background(),
		decoded,
		transaction.BasicAccountTransactionSigner{Account: payer},
		spec,
	)
	if err != nil {
		t.Fatalf("SubmitPresignedSettleGroup: %v", err)
	}
	if !*gotSubmit {
		t.Error("fake algod never received a submit call")
	}
	if res.TxID == "" {
		t.Error("res.TxID empty")
	}
	if res.FeeMicroalgos != 6000 {
		t.Errorf("res.FeeMicroalgos = %d, want 6000 (operator's fee pool)", res.FeeMicroalgos)
	}
	if res.PayerFeeMicroalgos != 0 {
		t.Errorf("res.PayerFeeMicroalgos = %d, want 0 (payer ack gtxn[1].Fee=0; operator's gtxn[0] pools)", res.PayerFeeMicroalgos)
	}
}

// TestSubmitPresignedSettleGroup_RejectsTamperedGroup guards the
// verify→submit→AckSettle plumbing that the shape-fraud defense depends on:
// SubmitPresignedSettleGroup must (1) reject a node-tampered group BEFORE
// signing/broadcasting, (2) return the *SettleGroupRejectedError
// UN-WRAPPED so the proxy's errors.As(err, &rejected) in AckSettle catches
// it and falls back to the standalone ack (rather than hard-erroring), and
// (3) never touch algod. The VerifySettleGroup matrix in verify_test.go
// tests the verifier in isolation; this test is the one that would catch a
// future regression where the error is wrapped non-transparently or the
// verify call is dropped from the submit path.
func TestSubmitPresignedSettleGroup_RejectsTamperedGroup(t *testing.T) {
	const appID = uint64(1234)
	payer := crypto.GenerateAccount()
	operator := crypto.GenerateAccount()
	opOwner := crypto.GenerateAccount()
	treasury := crypto.GenerateAccount()

	algod, gotSubmit := newFakeAlgodForCompose(t)
	client, err := NewClient(appID, algod)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client.UsdcAssetID = 31566704
	client.Treasury = treasury.Address.String()

	ticketIDRaw := make([]byte, 16)
	copy(ticketIDRaw, "ticket-id-16byte")
	var digest [32]byte
	copy(digest[:], "digest-32-bytes-receipt-xxxxxxxxxxx")

	args := SettleArgs{
		TicketIDRaw:       ticketIDRaw,
		AmountCharged:     50_000,
		MaxPrice:          60_000,
		ReceiptDigest:     digest,
		TtftMs:            1200,
		DecodeMs:          300,
		InputCount:        250,
		OutputCount:       750,
		OutputUsageType:   1,
		PayerAddr:         payer.Address.String(),
		OperatorOwnerAddr: opOwner.Address.String(),
		OperatorID:        7,
	}
	group, err := client.ComposeSettleGroup(
		context.Background(),
		args,
		transaction.BasicAccountTransactionSigner{Account: operator},
		operator.Address.String(),
	)
	if err != nil {
		t.Fatalf("ComposeSettleGroup: %v", err)
	}

	// The node hands a group whose payer-ack half carries a RekeyTo — an
	// account-takeover attempt. The group id is recomputed over the tampered
	// members, as a node building the fraud deliberately would, so the rekey
	// check — not the group-id commitment — is what fires.
	var attacker types.Address
	attacker[0] = 0x09
	group[1].Txn.RekeyTo = attacker
	group = regrouped(t, group)

	spec := SettleGroupSpec{
		AppID:               appID,
		TicketIDRaw:         ticketIDRaw,
		AmountCharged:       args.AmountCharged,
		ReceiptDigest:       digest,
		TtftMs:              args.TtftMs,
		DecodeMs:            args.DecodeMs,
		InputCount:          args.InputCount,
		OutputCount:         args.OutputCount,
		OutputUsageType:     args.OutputUsageType,
		AuxOutputUsageType:  args.AuxOutputUsageType,
		AuxOutputCount:      args.AuxOutputCount,
		PayerAddr:           payer.Address,
		OperatorSigningAddr: operator.Address,
	}

	_, err = client.SubmitPresignedSettleGroup(
		context.Background(),
		group,
		transaction.BasicAccountTransactionSigner{Account: payer},
		spec,
	)
	if err == nil {
		t.Fatal("SubmitPresignedSettleGroup accepted a rekey'd group; want rejection")
	}
	// The proxy branches on this exact type via errors.As — a wrapped or
	// re-typed error here would silently convert refuse+fallback into a hard
	// settlement failure.
	var rejected *SettleGroupRejectedError
	if !errors.As(err, &rejected) {
		t.Fatalf("err = %v (%T), want *SettleGroupRejectedError via errors.As", err, err)
	}
	if rejected.Field != "payer.rekeyTo" {
		t.Errorf("rejected.Field = %q, want payer.rekeyTo", rejected.Field)
	}
	if *gotSubmit {
		t.Error("algod received a submit for a rejected group; verification must precede broadcast")
	}
}

// containsAddr reports whether addr is present in addrs. Used by the
// settle-path tests that assert the treasury (and other inner-txn
// receivers) made it onto the txn's AppAccounts reference array.
func containsAddr(addrs []types.Address, addr types.Address) bool {
	for _, a := range addrs {
		if a == addr {
			return true
		}
	}
	return false
}

// TestComposeSettleStandalone_IncludesTreasuryRef asserts the
// standalone settle txn carries treasury in its AppAccounts. Without
// it the contract's inner USDC fee transfer to treasury would fail AVM
// authorization the moment netFee > 0.
func TestComposeSettleStandalone_IncludesTreasuryRef(t *testing.T) {
	const appID = uint64(1234)
	payer := crypto.GenerateAccount()
	operator := crypto.GenerateAccount()
	opOwner := crypto.GenerateAccount()
	treasury := crypto.GenerateAccount()

	algod, _ := newFakeAlgodForCompose(t)
	client, err := NewClient(appID, algod)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client.UsdcAssetID = 31566704
	client.Treasury = treasury.Address.String()

	ticketIDRaw := make([]byte, 16)
	copy(ticketIDRaw, "ticket-id-16byte")
	var digest [32]byte
	copy(digest[:], "digest-32-bytes-receipt-xxxxxxxxxxx")

	res, err := client.ComposeSettleStandalone(context.Background(), SettleArgs{
		TicketIDRaw:       ticketIDRaw,
		AmountCharged:     50_000,
		ReceiptDigest:     digest,
		TtftMs:            1200,
		DecodeMs:          300,
		InputCount:        250,
		OutputCount:       750,
		OutputUsageType:   1, // ticket.UsageTypeTokens
		AsOperator:        true,
		PayerAddr:         payer.Address.String(),
		OperatorOwnerAddr: opOwner.Address.String(),
		OperatorID:        7,
	}, transaction.BasicAccountTransactionSigner{Account: operator}, operator.Address.String())
	if err != nil {
		t.Fatalf("ComposeSettleStandalone: %v", err)
	}

	var stx types.SignedTxn
	if err := msgpack.Decode(res.SignedTxn, &stx); err != nil {
		t.Fatalf("decode signed txn: %v", err)
	}
	if !containsAddr(stx.Txn.Accounts, treasury.Address) {
		t.Errorf("AppAccounts missing treasury %s (got %v)", treasury.Address, stx.Txn.Accounts)
	}
	if !containsAddr(stx.Txn.Accounts, payer.Address) {
		t.Errorf("AppAccounts missing payer %s (got %v)", payer.Address, stx.Txn.Accounts)
	}
	if !containsAddr(stx.Txn.Accounts, opOwner.Address) {
		t.Errorf("AppAccounts missing operator-owner %s (got %v)", opOwner.Address, stx.Txn.Accounts)
	}
}

// TestComposeSettleLapsed_IncludesTreasuryRef asserts settleLapsed's
// txn carries treasury in its AppAccounts (same finalizeSettlement
// path as settle).
func TestComposeSettleLapsed_IncludesTreasuryRef(t *testing.T) {
	const appID = uint64(1234)
	payer := crypto.GenerateAccount()
	caller := crypto.GenerateAccount()
	opOwner := crypto.GenerateAccount()
	treasury := crypto.GenerateAccount()

	algod, _ := newFakeAlgodForCompose(t)
	client, err := NewClient(appID, algod)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client.UsdcAssetID = 31566704
	client.Treasury = treasury.Address.String()

	ticketIDRaw := make([]byte, 16)
	copy(ticketIDRaw, "ticket-id-16byte")

	res, err := client.ComposeSettleLapsed(
		context.Background(),
		SettleLapsedArgs{
			TicketIDRaw:       ticketIDRaw,
			OperatorID:        7,
			OperatorOwnerAddr: opOwner.Address.String(),
			PayerAddr:         payer.Address.String(),
		},
		transaction.BasicAccountTransactionSigner{Account: caller},
		caller.Address.String(),
	)
	if err != nil {
		t.Fatalf("ComposeSettleLapsed: %v", err)
	}

	var stx types.SignedTxn
	if err := msgpack.Decode(res.SignedTxn, &stx); err != nil {
		t.Fatalf("decode signed txn: %v", err)
	}
	if !containsAddr(stx.Txn.Accounts, treasury.Address) {
		t.Errorf("AppAccounts missing treasury %s (got %v)", treasury.Address, stx.Txn.Accounts)
	}
	if !containsAddr(stx.Txn.Accounts, payer.Address) {
		t.Errorf("AppAccounts missing payer %s (got %v)", payer.Address, stx.Txn.Accounts)
	}
	if !containsAddr(stx.Txn.Accounts, opOwner.Address) {
		t.Errorf("AppAccounts missing operator-owner %s (got %v)", opOwner.Address, stx.Txn.Accounts)
	}
}

// TestComposeSettle_GuardsMissingTreasury asserts each settle composer
// errors clearly when c.Treasury is unset, before any algod round-trip.
// stubAlgod panics on every method call, so an unintended algod hit
// surfaces as a panic rather than a silent network read.
func TestComposeSettle_GuardsMissingTreasury(t *testing.T) {
	payer := crypto.GenerateAccount()
	operator := crypto.GenerateAccount()
	opOwner := crypto.GenerateAccount()
	caller := crypto.GenerateAccount()

	ticketIDRaw := make([]byte, 16)
	copy(ticketIDRaw, "ticket-id-16byte")
	var digest [32]byte
	copy(digest[:], "digest-32-bytes-receipt-xxxxxxxxxxx")

	args := SettleArgs{
		TicketIDRaw:       ticketIDRaw,
		AmountCharged:     50_000,
		ReceiptDigest:     digest,
		AsOperator:        true,
		PayerAddr:         payer.Address.String(),
		OperatorOwnerAddr: opOwner.Address.String(),
		OperatorID:        7,
	}

	client := &Client{AppID: 1, AppAddr: crypto.GetApplicationAddress(1), Algod: stubAlgod{}, UsdcAssetID: 31566704}

	if _, err := client.ComposeSettleGroup(
		context.Background(), args,
		transaction.BasicAccountTransactionSigner{Account: operator}, operator.Address.String(),
	); err == nil || !strings.Contains(err.Error(), "treasury addr not loaded") {
		t.Errorf("ComposeSettleGroup: expected treasury-not-loaded error, got %v", err)
	}

	if _, err := client.ComposeSettleStandalone(
		context.Background(), args,
		transaction.BasicAccountTransactionSigner{Account: operator}, operator.Address.String(),
	); err == nil || !strings.Contains(err.Error(), "treasury addr not loaded") {
		t.Errorf("ComposeSettleStandalone: expected treasury-not-loaded error, got %v", err)
	}

	if _, err := client.ComposeSettleLapsed(
		context.Background(),
		SettleLapsedArgs{
			TicketIDRaw:       ticketIDRaw,
			OperatorID:        7,
			OperatorOwnerAddr: opOwner.Address.String(),
			PayerAddr:         payer.Address.String(),
		},
		transaction.BasicAccountTransactionSigner{Account: caller}, caller.Address.String(),
	); err == nil || !strings.Contains(err.Error(), "treasury addr not loaded") {
		t.Errorf("ComposeSettleLapsed: expected treasury-not-loaded error, got %v", err)
	}
}

// TestRefreshTreasury_DecodesGlobalState asserts readTreasury parses
// the contract's `trea` (Account, Type==1 bytes) global into the
// 58-char encoded address. Mirrors the algod GET-application response
// shape so any drift in TealValue.Bytes encoding shows up here.
func TestRefreshTreasury_DecodesGlobalState(t *testing.T) {
	const appID = uint64(4242)
	treasury := crypto.GenerateAccount()
	wantAddr := treasury.Address.String()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v2/applications/4242") {
			w.Header().Set("Content-Type", "application/json")
			// `trea` global with Type==1 (bytes), .Bytes is base64 of
			// the raw 32-byte address.
			treasuryB64 := base64.StdEncoding.EncodeToString(treasury.Address[:])
			_, _ = io.WriteString(w, `{
				"id": 4242,
				"params": {
					"approval-program": "",
					"clear-state-program": "",
					"creator": "`+treasury.Address.String()+`",
					"global-state": [
						{"key":"dHJlYQ==","value":{"type":1,"bytes":"`+treasuryB64+`","uint":0}}
					]
				}
			}`)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	algod, err := protoalgod.NewClient(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client, err := NewClient(appID, algod)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := client.RefreshTreasury(context.Background()); err != nil {
		t.Fatalf("RefreshTreasury: %v", err)
	}
	if client.Treasury != wantAddr {
		t.Errorf("Treasury = %q, want %q", client.Treasury, wantAddr)
	}
}

// TestRefreshTreasury_MissingGlobal asserts a clear error when the
// `trea` slot is absent (e.g. wrong app id).
func TestRefreshTreasury_MissingGlobal(t *testing.T) {
	const appID = uint64(4242)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v2/applications/4242") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{
				"id": 4242,
				"params": {
					"approval-program": "",
					"clear-state-program": "",
					"creator": "`+crypto.GenerateAccount().Address.String()+`",
					"global-state": []
				}
			}`)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	algod, err := protoalgod.NewClient(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client, err := NewClient(appID, algod)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	err = client.RefreshTreasury(context.Background())
	if err == nil || !strings.Contains(err.Error(), "treasury global not found") {
		t.Errorf("expected treasury-not-found error, got %v", err)
	}
}

// TestComposeUpdateOperatorURL_BuildsExpectedTxn asserts the
// single-txn updateOperatorUrl call carries the right ABI args, the
// operator-box reference, no foreign accounts/assets, no inner txns
// (outer fee = 1 × minFee), and is signed by the supplied signer.
func TestComposeUpdateOperatorURL_BuildsExpectedTxn(t *testing.T) {
	const appID = uint64(2025)
	signer := crypto.GenerateAccount()
	algod, gotSubmit := newFakeAlgodForCompose(t)
	client, err := NewClient(appID, algod)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	// updateOperatorUrl does not fire inner USDC / HAY transfers, so the
	// treasury / asset id load that settle paths require is irrelevant
	// here. Leave them zero to confirm the helper doesn't accidentally
	// gate on them.

	res, err := client.ComposeUpdateNodeURL(
		context.Background(),
		UpdateNodeURLArgs{
			OperatorID: 7,
			NodeID:     3,
			BaseURL:    "https://node.example.com:9090",
		},
		transaction.BasicAccountTransactionSigner{Account: signer},
		signer.Address.String(),
	)
	if err != nil {
		t.Fatalf("ComposeUpdateNodeURL: %v", err)
	}
	if !*gotSubmit {
		t.Fatalf("expected ATC.Submit to hit /v2/transactions")
	}
	if res.TxID == "" {
		t.Errorf("TxID should be non-empty (ATC computes it from the signed bytes)")
	}

	var stx types.SignedTxn
	if err := msgpack.Decode(res.SignedTxn, &stx); err != nil {
		t.Fatalf("decode signed txn: %v", err)
	}
	// Single-txn group with no inner txns → outer fee == 1 × min fee.
	if stx.Txn.Fee != 1000 {
		t.Errorf("Fee = %d, want 1000 (one min-fee for one outer txn)", stx.Txn.Fee)
	}
	// updateNodeUrl references the operator box (owner/status check) and the
	// node box (the field it rewrites) — two entries, no others.
	if len(stx.Txn.BoxReferences) != 2 {
		t.Fatalf("BoxReferences len = %d, want 2 (operator + node box): %+v", len(stx.Txn.BoxReferences), stx.Txn.BoxReferences)
	}
	if !bytes.Equal(stx.Txn.BoxReferences[0].Name, OperatorBoxKey(7)) {
		t.Errorf("BoxReferences[0].Name = %x, want %x (OperatorBoxKey(7))", stx.Txn.BoxReferences[0].Name, OperatorBoxKey(7))
	}
	if !bytes.Equal(stx.Txn.BoxReferences[1].Name, NodeBoxKey(7, 3)) {
		t.Errorf("BoxReferences[1].Name = %x, want %x (NodeBoxKey(7,3))", stx.Txn.BoxReferences[1].Name, NodeBoxKey(7, 3))
	}
	if len(stx.Txn.Accounts) != 0 {
		t.Errorf("Accounts should be empty for updateNodeUrl (no inner payments), got %v", stx.Txn.Accounts)
	}
	if len(stx.Txn.ForeignAssets) != 0 {
		t.Errorf("ForeignAssets should be empty (no inner asset transfers), got %v", stx.Txn.ForeignAssets)
	}
}

// TestComposeUpdateNodeURL_ValidatesInputs covers the early-return guards
// in ComposeUpdateNodeURL. None of these should hit algod — stubAlgod
// panics on any method call, so an unintended round-trip would surface as
// a panic rather than a silent network read.
func TestComposeUpdateNodeURL_ValidatesInputs(t *testing.T) {
	signer := crypto.GenerateAccount()
	client := &Client{AppID: 1, AppAddr: crypto.GetApplicationAddress(1), Algod: stubAlgod{}}
	tsigner := transaction.BasicAccountTransactionSigner{Account: signer}
	ctx := context.Background()

	cases := []struct {
		name    string
		args    UpdateNodeURLArgs
		wantSub string
	}{
		{"zero operator id", UpdateNodeURLArgs{OperatorID: 0, NodeID: 1, BaseURL: "https://x"}, "operator id"},
		{"zero node id", UpdateNodeURLArgs{OperatorID: 1, NodeID: 0, BaseURL: "https://x"}, "node id"},
		{"empty url", UpdateNodeURLArgs{OperatorID: 1, NodeID: 1, BaseURL: ""}, "empty"},
		{"too long", UpdateNodeURLArgs{OperatorID: 1, NodeID: 1, BaseURL: strings.Repeat("a", BaseURLMax+1)}, "max "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := client.ComposeUpdateNodeURL(ctx, tc.args, tsigner, signer.Address.String())
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("expected error containing %q, got %v", tc.wantSub, err)
			}
		})
	}
}

// Compile-time guards: assert that the SDK types ComposeOpen relies
// on still exist under the import paths this test uses. If the SDK
// restructures these, the test file breaks and so does the
// production code — fail at compile time.
var (
	_ = types.ZeroAddress
	_ = transaction.BasicAccountTransactionSigner{}
	_ = crypto.GenerateAccount
)

// TestComposeSettleGroup_FeeSizing pins the operator's pooled gtxn[0] fee to the
// work the group actually performs: 2 outers + the disbursement inners
// finalizeSettlement will submit + the funded op-ups. A free model settles for
// 2 minTxnFee, not the 6 a flat worst-case fee used to charge.
func TestComposeSettleGroup_FeeSizing(t *testing.T) {
	const appID = uint64(1234)
	payer := crypto.GenerateAccount()
	operator := crypto.GenerateAccount()
	opOwner := crypto.GenerateAccount()
	treasury := crypto.GenerateAccount()

	ticketIDRaw := make([]byte, 16)
	copy(ticketIDRaw, "ticket-id-16byte")

	cases := []struct {
		name                    string
		amountCharged, maxPrice uint64
		gapOpUps                uint64
		wantFee                 uint64
	}{
		{"free model: no inners, no op-up", 0, 0, 0, 2_000},
		{"zero charge (failed request): refund only", 0, 25_000, 0, 3_000},
		{"paid, steady state: 3 inners, no op-up", 50_000, 60_000, 0, 5_000},
		{"paid, cold tracker: 3 inners + 1 op-up", 50_000, 60_000, 1, 6_000},
		{"paid, spent exactly: payout + fee only", 60_000, 60_000, 0, 4_000},
		{"free model after a long idle: op-ups only", 0, 0, 3, 5_000},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			algod, _ := newFakeAlgodForCompose(t)
			client, err := NewClient(appID, algod)
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			client.UsdcAssetID = 31566704
			client.Treasury = treasury.Address.String()

			group, err := client.ComposeSettleGroup(
				context.Background(),
				SettleArgs{
					TicketIDRaw:       ticketIDRaw,
					AmountCharged:     tc.amountCharged,
					MaxPrice:          tc.maxPrice,
					OutputUsageType:   1,
					PayerAddr:         payer.Address.String(),
					OperatorOwnerAddr: opOwner.Address.String(),
					OperatorID:        7,
					GapOpUps:          tc.gapOpUps,
				},
				transaction.BasicAccountTransactionSigner{Account: operator},
				operator.Address.String(),
			)
			if err != nil {
				t.Fatalf("ComposeSettleGroup: %v", err)
			}
			if got := uint64(group[0].Txn.Fee); got != tc.wantFee {
				t.Errorf("gtxn[0].Fee = %d, want %d", got, tc.wantFee)
			}
			// The payer never funds the settle; the operator pools for both.
			if got := uint64(group[1].Txn.Fee); got != 0 {
				t.Errorf("gtxn[1].Fee = %d, want 0 (operator pools)", got)
			}
		})
	}
}

// TestComposeSettleLapsed_FeeFailSafe pins the lapse composer's behavior when it
// cannot read the ticket box to size the fee: it must assume every disbursement
// inner fires. settleLapsed takes only a ticket id, so the box is the ONLY
// source for amountCharged/maxPrice; guessing low would under-pool the fee and
// revert the call on every retry, stranding the operator's USDC. Guessing high
// costs one minTxnFee.
//
// The fake algod here serves suggested-params and submits, but no boxes — so
// both the ticket read and the op-up gap reads fail, which is the fail-safe
// path. Fee = 1 outer + 3 disbursements + 1 base op-up = 5 x minTxnFee.
func TestComposeSettleLapsed_FeeFailSafe(t *testing.T) {
	const appID = uint64(1234)
	payer := crypto.GenerateAccount()
	caller := crypto.GenerateAccount()
	opOwner := crypto.GenerateAccount()
	treasury := crypto.GenerateAccount()

	algod, _ := newFakeAlgodForCompose(t)
	client, err := NewClient(appID, algod)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client.UsdcAssetID = 31566704
	client.Treasury = treasury.Address.String()

	ticketIDRaw := make([]byte, 16)
	copy(ticketIDRaw, "ticket-id-16byte")

	res, err := client.ComposeSettleLapsed(
		context.Background(),
		SettleLapsedArgs{
			TicketIDRaw:       ticketIDRaw,
			OperatorID:        7,
			NodeID:            1,
			OperatorOwnerAddr: opOwner.Address.String(),
			PayerAddr:         payer.Address.String(),
		},
		transaction.BasicAccountTransactionSigner{Account: caller},
		caller.Address.String(),
	)
	if err != nil {
		t.Fatalf("ComposeSettleLapsed: %v", err)
	}

	var stx types.SignedTxn
	if err := msgpack.Decode(res.SignedTxn, &stx); err != nil {
		t.Fatalf("decode signed txn: %v", err)
	}
	if got := uint64(stx.Txn.Fee); got != 5_000 {
		t.Errorf("unreadable-box fee = %d, want 5000 (worst-case 3 inners + base op-up)", got)
	}
}

// newFakeAlgodForSimulate stands up an httptest.Server serving the two
// endpoints a readonly simulate touches — GET /v2/transactions/params and
// POST /v2/transactions/simulate — with the group's eval failure message under
// the test's control.
func newFakeAlgodForSimulate(t *testing.T, failureMessage string) protoalgod.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v2/transactions/params"):
			w.Header().Set("Content-Type", "application/json")
			gh := base64.StdEncoding.EncodeToString(make([]byte, 32))
			_, _ = io.WriteString(w, `{
				"consensus-version": "v30",
				"fee": 1000,
				"genesis-id": "dev-v1",
				"genesis-hash": "`+gh+`",
				"last-round": 100,
				"min-fee": 1000
			}`)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v2/transactions/simulate"):
			_, _ = io.Copy(io.Discard, r.Body)
			w.Header().Set("Content-Type", "application/json")
			body, err := json.Marshal(models.SimulateResponse{
				Version:   2,
				LastRound: 100,
				TxnGroups: []models.SimulateTransactionGroupResult{{
					FailureMessage: failureMessage,
					TxnResults:     []models.SimulateTransactionResult{{}},
				}},
			})
			if err != nil {
				t.Errorf("marshal simulate response: %v", err)
				return
			}
			_, _ = w.Write(body)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	c, err := protoalgod.NewClient(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// ReadFreeQuotaMbr must classify ONLY an ABI-router reject (a logic eval
// failure) as "this app predates the free-ticket quota". Callers latch that
// answer for the process lifetime — RefreshConfig maps it to a 0 sizing term —
// so folding an unrelated simulate failure into it would silently drop the
// quota MBR from deposit sizing forever, and every payer's first free open
// would then revert on the contract's pool guard with nothing left to retry it.
func TestReadFreeQuotaMbr_ClassifiesOnlyEvalRejectAsUnsupported(t *testing.T) {
	sender := crypto.GenerateAccount()

	cases := []struct {
		name            string
		failureMessage  string
		wantUnsupported bool
	}{
		{
			name:            "abi router reject on an app predating the quota",
			failureMessage:  "logic eval error: err opcode executed. Details: app=1234, pc=512",
			wantUnsupported: true,
		},
		{
			name:            "unfunded simulate sender",
			failureMessage:  "overspend (account ABC, data {_struct:{} Status:Offline MicroAlgos:{Raw:0}})",
			wantUnsupported: false,
		},
		{
			name:            "fee too small",
			failureMessage:  "txn dead: round 100 outside of 90--100",
			wantUnsupported: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewClient(1234, newFakeAlgodForSimulate(t, tc.failureMessage))
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			_, err = c.ReadFreeQuotaMbr(context.Background(), sender.Address.String())
			if err == nil {
				t.Fatalf("ReadFreeQuotaMbr: want an error for failure-message %q", tc.failureMessage)
			}
			if got := errors.Is(err, ErrFreeQuotaUnsupported); got != tc.wantUnsupported {
				t.Fatalf("errors.Is(err, ErrFreeQuotaUnsupported) = %v, want %v (err = %v)",
					got, tc.wantUnsupported, err)
			}
			// Either way the underlying failure message has to survive: it is
			// the only thing that tells an operator a "quota unsupported" log
			// line apart from a misconfigured app id.
			if !strings.Contains(err.Error(), tc.failureMessage) {
				t.Errorf("err = %v, want it to carry the failure message %q", err, tc.failureMessage)
			}
		})
	}
}
