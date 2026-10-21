/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package rpc

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/solana"
)

type seenCall struct {
	Method string
	Params json.RawMessage
	Body   []byte
	Header http.Header
	Proto  int
}

// reply answers one call: an HTTP status, headers, and a body.
type reply func(w http.ResponseWriter, c seenCall)

// fakeRPC is a JSON-RPC server answering each call with the next reply, the
// last one repeating.
type fakeRPC struct {
	srv     *httptest.Server
	mu      sync.Mutex
	seen    []seenCall
	replies []reply
}

func newFakeRPC(t *testing.T, replies ...reply) *fakeRPC {
	t.Helper()
	f := &fakeRPC{replies: replies}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeRPC) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var req struct {
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	_ = json.Unmarshal(body, &req)
	c := seenCall{Method: req.Method, Params: req.Params, Body: body, Header: r.Header.Clone(), Proto: r.ProtoMajor}
	f.mu.Lock()
	f.seen = append(f.seen, c)
	rep := f.replies[min(len(f.seen)-1, len(f.replies)-1)]
	f.mu.Unlock()
	rep(w, c)
}

func (f *fakeRPC) calls() []seenCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]seenCall(nil), f.seen...)
}

func result(v string) reply {
	return func(w http.ResponseWriter, _ seenCall) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":%s}`, v)
	}
}

func rpcError(code int, data string) reply {
	return func(w http.ResponseWriter, _ seenCall) {
		if data == "" {
			data = "null"
		}
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"error":{"code":%d,"message":"refused","data":%s}}`, code, data)
	}
}

func status(code int, header ...string) reply {
	return func(w http.ResponseWriter, _ seenCall) {
		for i := 0; i+1 < len(header); i += 2 {
			w.Header().Set(header[i], header[i+1])
		}
		w.WriteHeader(code)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":429,"message":"Too many requests"}}`))
	}
}

// hangUp drops the connection without an answer.
func hangUp(w http.ResponseWriter, _ seenCall) {
	conn, _, err := w.(http.Hijacker).Hijack()
	if err == nil {
		_ = conn.Close()
	}
}

// truncated promises a longer body than it sends.
func truncated(w http.ResponseWriter, _ seenCall) {
	w.Header().Set("Content-Length", "100")
	_, _ = w.Write([]byte(`{"jsonrpc":"2.0",`))
}

// quick is a short budget, so retry tests run in milliseconds.
var quick = WithRetry(RetryPolicy{MaxRetries: 2, WaitMin: 5 * time.Millisecond, WaitMax: 20 * time.Millisecond})

func newTestClient(t *testing.T, f *fakeRPC, opts ...Option) *HTTPClient {
	t.Helper()
	c, err := NewClient(f.srv.URL+"/rpc?api-key=secret", append([]Option{quick}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var (
	testKey     = solana.PublicKey(bytes.Repeat([]byte{0x5a}, 32))
	testProgram = solana.MustPublicKey("2sXCgAPUVAFvmDhXG1pLGA6mjnWpqR521MZTfMnyc9h1")
	testSig     = solana.Signature(bytes.Repeat([]byte{0x11}, 64))
)

func accountJSON(data []byte, owner solana.PublicKey, lamports uint64) string {
	return fmt.Sprintf(`{"data":[%q,"base64"],"executable":false,"lamports":%d,"owner":%q,"rentEpoch":18446744073709551615,"space":%d}`,
		base64.StdEncoding.EncodeToString(data), lamports, owner, len(data))
}

func TestGetAccountInfo(t *testing.T) {
	data := []byte{1, 2, 3, 4}
	f := newFakeRPC(t, result(`{"context":{"apiVersion":"4.3.0","slot":9},"value":`+accountJSON(data, testProgram, 1_752_600)+`}`))
	a, err := newTestClient(t, f).GetAccountInfo(t.Context(), testKey, Confirmed)
	if err != nil {
		t.Fatal(err)
	}
	want := Account{Lamports: 1_752_600, Owner: testProgram, Data: data}
	if a.Lamports != want.Lamports || a.Owner != want.Owner || !bytes.Equal(a.Data, want.Data) || a.Executable {
		t.Fatalf("account = %+v, want %+v", a, want)
	}
	c := f.calls()[0]
	if got := c.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q", got)
	}
	var env map[string]any
	_ = json.Unmarshal(c.Body, &env)
	if env["jsonrpc"] != "2.0" || env["method"] != "getAccountInfo" {
		t.Errorf("envelope = %v", env)
	}
}

func TestGetAccountInfoNull(t *testing.T) {
	f := newFakeRPC(t, result(`{"context":{"slot":9},"value":null}`))
	_, err := newTestClient(t, f).GetAccountInfo(t.Context(), testKey, "")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestAccountDataMustBeBase64(t *testing.T) {
	for _, data := range []string{`["AQID","base58"]`, `["AQID"]`, `["!!","base64"]`, `"AQID"`} {
		f := newFakeRPC(t, result(`{"context":{"slot":9},"value":{"data":`+data+`,"executable":false,"lamports":1,"owner":"`+testProgram.String()+`"}}`))
		if _, err := newTestClient(t, f).GetAccountInfo(t.Context(), testKey, ""); err == nil {
			t.Errorf("data %s: no error", data)
		}
	}
}

func TestGetProgramAccounts(t *testing.T) {
	other := solana.PublicKey(bytes.Repeat([]byte{0x22}, 32))
	f := newFakeRPC(t, result(`[{"pubkey":"`+testKey.String()+`","account":`+accountJSON([]byte{9}, testProgram, 5)+`},`+
		`{"pubkey":"`+other.String()+`","account":`+accountJSON(nil, testProgram, 6)+`}]`))
	got, err := newTestClient(t, f).GetProgramAccounts(t.Context(), testProgram, Confirmed, DataSize(1))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Key != testKey || !bytes.Equal(got[0].Account.Data, []byte{9}) || got[1].Key != other || got[1].Account.Lamports != 6 || len(got[1].Account.Data) != 0 {
		t.Fatalf("accounts = %+v", got)
	}
}

func TestGetBalanceAndHeights(t *testing.T) {
	ctx := t.Context()
	// Past 2^53: Go reads a u64 exactly.
	f := newFakeRPC(t, result(`{"context":{"slot":9},"value":18446744073709551615}`))
	if bal, err := newTestClient(t, f).GetBalance(ctx, testKey, ""); err != nil || bal != 18446744073709551615 {
		t.Fatalf("balance = %d, %v", bal, err)
	}
	hash := solana.Hash(bytes.Repeat([]byte{0x33}, 32))
	f = newFakeRPC(t, result(`{"context":{"slot":9},"value":{"blockhash":"`+hash.String()+`","lastValidBlockHeight":300}}`))
	if bh, err := newTestClient(t, f).GetLatestBlockhash(ctx, Finalized); err != nil || bh != (Blockhash{Hash: hash, LastValidBlockHeight: 300}) {
		t.Fatalf("blockhash = %+v, %v", bh, err)
	}
	f = newFakeRPC(t, result(`{"context":{"slot":9},"value":{"blockhash":"not-base58","lastValidBlockHeight":300}}`))
	if _, err := newTestClient(t, f).GetLatestBlockhash(ctx, ""); err == nil {
		t.Fatal("a malformed blockhash decoded")
	}
	f = newFakeRPC(t, result(`287`))
	if h, err := newTestClient(t, f).GetBlockHeight(ctx, ""); err != nil || h != 287 {
		t.Fatalf("height = %d, %v", h, err)
	}
	f = newFakeRPC(t, result(`"`+hash.String()+`"`))
	if g, err := newTestClient(t, f).GetGenesisHash(ctx); err != nil || g != hash {
		t.Fatalf("genesis = %v, %v", g, err)
	}
}

func TestSendTransaction(t *testing.T) {
	f := newFakeRPC(t, result(`"`+testSig.String()+`"`))
	tx := []byte{1, 2, 3}
	sig, err := newTestClient(t, f).SendTransaction(t.Context(), tx, SendOptions{PreflightCommitment: Processed})
	if err != nil || sig != testSig {
		t.Fatalf("sig = %v, %v", sig, err)
	}
	var params []json.RawMessage
	_ = json.Unmarshal(f.calls()[0].Params, &params)
	var b64 string
	_ = json.Unmarshal(params[0], &b64)
	if b64 != base64.StdEncoding.EncodeToString(tx) {
		t.Fatalf("tx param = %s", params[0])
	}
}

func TestGetSignatureStatuses(t *testing.T) {
	f := newFakeRPC(t, result(`{"context":{"slot":9},"value":[null,`+
		`{"slot":7,"confirmations":null,"err":null,"status":{"Ok":null},"confirmationStatus":"finalized"},`+
		`{"slot":8,"confirmations":3,"err":{"InstructionError":[1,{"Custom":6001}]},"status":{"Err":{}},"confirmationStatus":"confirmed"}]}`))
	got, err := newTestClient(t, f).GetSignatureStatuses(t.Context(), []solana.Signature{testSig, testSig, testSig}, true)
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != nil {
		t.Errorf("unknown signature = %+v, want nil", got[0])
	}
	if s := got[1]; s.Slot != 7 || s.Confirmations != nil || s.Err != nil || s.ConfirmationStatus != Finalized {
		t.Errorf("finalized status = %+v", s)
	}
	if s := got[2]; s.Slot != 8 || s.Confirmations == nil || *s.Confirmations != 3 || TxErrName(s.Err) != "InstructionError" || s.ConfirmationStatus != Confirmed {
		t.Errorf("failed status = %+v", s)
	}

	f = newFakeRPC(t, result(`{"context":{"slot":9},"value":[null]}`))
	if _, err := newTestClient(t, f).GetSignatureStatuses(t.Context(), []solana.Signature{testSig, testSig}, false); err == nil {
		t.Fatal("one status for two signatures was accepted")
	}
	f = newFakeRPC(t, result(`{"context":{"slot":9},"value":[{"slot":7,"confirmations":null,"err":null,"confirmationStatus":"rooted"}]}`))
	if _, err := newTestClient(t, f).GetSignatureStatuses(t.Context(), []solana.Signature{testSig}, false); err == nil {
		t.Fatal("an unknown confirmationStatus was accepted")
	}
}

func TestRetriesWeather(t *testing.T) {
	ok := result(`287`)
	for name, first := range map[string]reply{
		"503":          status(503),
		"429":          status(429),
		"502":          status(502),
		"node behind":  rpcError(CodeNodeUnhealthy, `{"numSlotsBehind":12}`),
		"no answer":    hangUp,
		"cut-off body": truncated,
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeRPC(t, first, ok)
			if h, err := newTestClient(t, f).GetBlockHeight(t.Context(), ""); err != nil || h != 287 {
				t.Fatalf("height = %d, %v", h, err)
			}
			if n := len(f.calls()); n != 2 {
				t.Fatalf("%d calls, want 2", n)
			}
		})
	}
}

func TestAnswersAreNotRetried(t *testing.T) {
	for name, first := range map[string]reply{
		"400":            status(400),
		"401":            status(401),
		"403":            status(403),
		"404":            status(404),
		"invalid params": rpcError(-32602, ``),
		"internal":       rpcError(-32603, ``),
		"scan":           rpcError(-32012, ``),
		"not json":       result(`}`),
		"null result":    result(`null`),
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeRPC(t, first, result(`287`))
			if _, err := newTestClient(t, f).GetBlockHeight(t.Context(), ""); err == nil {
				t.Fatal("no error")
			}
			if n := len(f.calls()); n != 1 {
				t.Fatalf("%d calls, want 1", n)
			}
		})
	}
}

func TestSubmitRetriesAMissingBlockhash(t *testing.T) {
	f := newFakeRPC(t, rpcError(CodePreflightFailure, `{"err":"BlockhashNotFound","logs":[]}`), result(`"`+testSig.String()+`"`))
	if _, err := newTestClient(t, f).SendTransaction(t.Context(), []byte{1, 2, 3}, SendOptions{}); err != nil {
		t.Fatal(err)
	}
	calls := f.calls()
	if len(calls) != 2 || !bytes.Equal(calls[0].Body, calls[1].Body) {
		t.Fatalf("calls = %d, bodies equal %v", len(calls), len(calls) == 2 && bytes.Equal(calls[0].Body, calls[1].Body))
	}
}

func TestSubmitFailureIsAnAnswer(t *testing.T) {
	for _, name := range []string{"AlreadyProcessed", "InsufficientFundsForFee"} {
		f := newFakeRPC(t, rpcError(CodePreflightFailure, `{"err":"`+name+`","logs":["Program log: x"]}`), result(`"`+testSig.String()+`"`))
		_, err := newTestClient(t, f).SendTransaction(t.Context(), []byte{1}, SendOptions{})
		e, ok := errors.AsType[*Error](err)
		if !ok || e.Code != CodePreflightFailure || e.TxErrName() != name || e.Method != "sendTransaction" {
			t.Fatalf("%s: err = %v", name, err)
		}
		if n := len(f.calls()); n != 1 {
			t.Fatalf("%s: %d calls, want 1", name, n)
		}
	}
}

func TestGivesUpWithTheLastFailure(t *testing.T) {
	f := newFakeRPC(t, status(503))
	_, err := newTestClient(t, f).GetBlockHeight(t.Context(), "")
	if e, ok := errors.AsType[*HTTPError](err); !ok || e.Status != 503 || !strings.Contains(string(e.Body), "Too many requests") {
		t.Fatalf("err = %v", err)
	}
	if n := len(f.calls()); n != 3 {
		t.Fatalf("%d calls, want 3", n)
	}
}

func TestHonorsRetryAfterUpToTheCap(t *testing.T) {
	f := newFakeRPC(t, status(429, "Retry-After", "5"), result(`1`))
	c := newTestClient(t, f, WithRetry(RetryPolicy{MaxRetries: 1, WaitMin: 5 * time.Millisecond, WaitMax: 150 * time.Millisecond}))
	start := time.Now()
	if _, err := c.GetBlockHeight(t.Context(), ""); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d < 140*time.Millisecond || d > 2*time.Second {
		t.Fatalf("waited %v, want the 150ms cap", d)
	}
}

func TestStopsOnCancelMidWait(t *testing.T) {
	f := newFakeRPC(t, status(503))
	c := newTestClient(t, f, WithRetry(RetryPolicy{MaxRetries: 5, WaitMin: 10 * time.Second, WaitMax: 10 * time.Second}))
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	_, err := c.GetBlockHeight(ctx, "")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	if n := len(f.calls()); n != 1 {
		t.Fatalf("%d calls, want 1", n)
	}
}

func TestSendsHeadersAndKeepsTheKeyOutOfErrors(t *testing.T) {
	f := newFakeRPC(t, result(`1`))
	if _, err := newTestClient(t, f, WithHeader("X-Api-Key", "k1")).GetBlockHeight(t.Context(), ""); err != nil {
		t.Fatal(err)
	}
	if got := f.calls()[0].Header.Get("X-Api-Key"); got != "k1" {
		t.Fatalf("header = %q", got)
	}

	f.srv.Close()
	_, err := newTestClient(t, f).GetBlockHeight(t.Context(), "")
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("err = %v", err)
	}
}

func TestNewClientRefusesEndpoints(t *testing.T) {
	for _, e := range []string{
		"ws://rpc.example/?api-key=secret", "rpc.example/?api-key=secret", "://secret",
		"https://user:secret@rpc.example/", "https://rpc.example/%zz?api-key=secret",
	} {
		_, err := NewClient(e)
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Errorf("%q: err = %v", e, err)
		}
	}
}

// The public endpoints cap new connections per IP, so DefaultTransport must
// speak HTTP/2 over TLS.
func TestDefaultTransportSpeaksHTTP2(t *testing.T) {
	f := &fakeRPC{replies: []reply{result(`1`)}}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.srv.EnableHTTP2 = true
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)

	tr := DefaultTransport()
	tr.TLSClientConfig = &tls.Config{RootCAs: f.srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs}
	c, err := NewClient(f.srv.URL, WithTransport(tr))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetBlockHeight(t.Context(), ""); err != nil {
		t.Fatal(err)
	}
	if p := f.calls()[0].Proto; p != 2 {
		t.Fatalf("HTTP/%d, want HTTP/2", p)
	}
}
