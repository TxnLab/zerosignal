/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package algod

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// Fake algod HTTP server. Supports only the endpoints this package
// exercises — keeps the tests hermetic and fast. Response bodies are
// the same msgpack / JSON shapes the real algod emits.
func newFakeAlgod(t *testing.T, handler http.HandlerFunc) (Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c, err := NewClient(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c, srv
}

func TestSuggestedParams_PassesTokenHeader(t *testing.T) {
	var gotToken string
	handler := func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("X-Algo-API-Token")
		// Real algod returns JSON for this one.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"consensus-version": "v30",
			"fee": 1000,
			"genesis-id": "dev-v1",
			"genesis-hash": "SGVsbG9Xb3JsZEhlbGxvV29ybGRIZWxsb1dvcmxkSGVsbG89",
			"last-round": 100,
			"min-fee": 1000
		}`))
	}
	c, _ := newFakeAlgod(t, handler)

	sp, err := c.SuggestedParams(context.Background())
	if err != nil {
		t.Fatalf("SuggestedParams: %v", err)
	}
	if gotToken != "test-token" {
		t.Errorf("token header = %q, want %q", gotToken, "test-token")
	}
	if sp.FirstRoundValid != 100 {
		t.Errorf("FirstRoundValid = %d, want 100", sp.FirstRoundValid)
	}
	if sp.MinFee != 1000 {
		t.Errorf("MinFee = %d, want 1000", sp.MinFee)
	}
}

func TestSendRawTransactionGroup_Roundtrip(t *testing.T) {
	var gotBody []byte
	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/v2/transactions") {
			gotBody, _ = io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"txId":"FAKETXID123"}`))
			return
		}
		http.NotFound(w, r)
	}
	c, _ := newFakeAlgod(t, handler)

	txid, err := c.SendRawTransactionGroup(context.Background(), []byte("raw group bytes"))
	if err != nil {
		t.Fatalf("SendRawTransactionGroup: %v", err)
	}
	if txid != "FAKETXID123" {
		t.Errorf("txid = %q, want FAKETXID123", txid)
	}
	if string(gotBody) != "raw group bytes" {
		t.Errorf("body = %q, want raw group bytes", gotBody)
	}
}

func TestPendingTransactions_DecodesPool(t *testing.T) {
	sp := types.SuggestedParams{
		FirstRoundValid: 1,
		LastRoundValid:  100,
		MinFee:          1000,
		FlatFee:         true,
		GenesisID:       "dev-v1",
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var addr types.Address
	copy(addr[:], pub)
	txn, err := makePaymentTxn(addr.String(), sp)
	if err != nil {
		t.Fatal(err)
	}
	poolBytes := mustMsgpackPool(t, []types.SignedTxn{{Txn: txn}})

	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/transactions/pending" {
			w.Header().Set("Content-Type", "application/msgpack")
			_, _ = w.Write(poolBytes)
			return
		}
		http.NotFound(w, r)
	}
	c, _ := newFakeAlgod(t, handler)

	total, txns, err := c.PendingTransactions(context.Background(), 10)
	if err != nil {
		t.Fatalf("PendingTransactions: %v", err)
	}
	if total != 1 {
		t.Errorf("total = %d, want 1", total)
	}
	if len(txns) != 1 {
		t.Fatalf("txns len = %d, want 1", len(txns))
	}
}

func TestNewClient_WithTransport_AndHeader(t *testing.T) {
	var gotExtra string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotExtra = r.Header.Get("X-Extra")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"last-round":1,"min-fee":1000,"fee":1000,"genesis-id":"g","genesis-hash":"SGVsbG9Xb3JsZEhlbGxvV29ybGRIZWxsb1dvcmxkSGVsbG89"}`))
	}))
	t.Cleanup(srv.Close)

	// RoundTripper that records how many times it was dispatched,
	// proving the injected transport is actually used.
	tr := &countingRoundTripper{RoundTripper: http.DefaultTransport}
	c, err := NewClient(srv.URL, "tok", WithTransport(tr), WithHeader("X-Extra", "yes"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.SuggestedParams(context.Background()); err != nil {
		t.Fatalf("SuggestedParams: %v", err)
	}
	if tr.calls == 0 {
		t.Fatal("custom transport was not invoked")
	}
	if gotExtra != "yes" {
		t.Errorf("X-Extra header = %q, want yes", gotExtra)
	}
}

func TestPendingTransactions_RejectsZeroMax(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("handler should not be hit when max == 0; got %s %s", r.Method, r.URL.Path)
	}
	c, _ := newFakeAlgod(t, handler)
	if _, _, err := c.PendingTransactions(context.Background(), 0); err == nil {
		t.Fatal("expected error for max == 0")
	}
}

// --- helpers ---

type countingRoundTripper struct {
	http.RoundTripper
	calls int
}

func (c *countingRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	c.calls++
	return c.RoundTripper.RoundTrip(r)
}

func makePaymentTxn(addr string, sp types.SuggestedParams) (types.Transaction, error) {
	a, err := types.DecodeAddress(addr)
	if err != nil {
		return types.Transaction{}, err
	}
	var gh types.Digest
	copy(gh[:], sp.GenesisHash)
	return types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:      a,
			Fee:         1000,
			FirstValid:  sp.FirstRoundValid,
			LastValid:   sp.LastRoundValid,
			GenesisID:   sp.GenesisID,
			GenesisHash: gh,
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: a,
			Amount:   1000,
		},
	}, nil
}

func mustMsgpackPool(t *testing.T, txns []types.SignedTxn) []byte {
	t.Helper()
	// Mirror the SDK's shape: {"top-transactions": [...]}.
	wrapper := struct {
		TopTransactions   []types.SignedTxn `codec:"top-transactions"`
		TotalTransactions uint64            `codec:"total-transactions"`
	}{
		TopTransactions:   txns,
		TotalTransactions: uint64(len(txns)),
	}
	b := msgpack.Encode(&wrapper)
	return b
}
