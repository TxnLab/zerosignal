/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/wire"
)

// reserveTestHarness bundles everything a reserve test needs: a fake
// node HTTP server, the operator that points at it, and the identity
// (for sealed-request tests).
type reserveTestHarness struct {
	server   *httptest.Server
	operator Operator
	identity *age.X25519Identity
	signKey  ed25519.PrivateKey
	signAddr string
}

// decodeReserve opens the sealed reserve body the proxy now sends
// (SealedReserveContentType) with the harness node identity and returns the
// inner ticket.ReserveRequest. Fake node handlers use this in place of a
// plaintext json.Decode now that the request rides the wire age-sealed.
func (h *reserveTestHarness) decodeReserve(t *testing.T, r *http.Request) ticket.ReserveRequest {
	t.Helper()
	if ct := r.Header.Get("Content-Type"); ct != wire.SealedReserveContentType {
		t.Fatalf("reserve Content-Type = %q, want %q", ct, wire.SealedReserveContentType)
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read reserve body: %v", err)
	}
	plaintext, err := wire.OpenReserveRequest(raw, h.identity)
	if err != nil {
		t.Fatalf("open sealed reserve: %v", err)
	}
	var rr ticket.ReserveRequest
	if err := json.Unmarshal(plaintext, &rr); err != nil {
		t.Fatalf("unmarshal inner reserve request: %v", err)
	}
	return rr
}

// rawKeyBytesSigner satisfies ticket.BytesSigner with a single raw
// ed25519.PrivateKey — used in tests that need a signer interface but
// already hold the key directly.
type rawKeyBytesSigner struct {
	addr string
	priv ed25519.PrivateKey
}

func (r rawKeyBytesSigner) SignBytes(_ context.Context, addr string, msg []byte) ([]byte, error) {
	if addr != r.addr {
		return nil, errors.New("rawKeyBytesSigner: address mismatch")
	}
	return ed25519.Sign(r.priv, msg), nil
}

// newReserveHarness builds a fake node with a bound handler h. The
// operator published by the harness has h's URL as its BaseURL.
func newReserveHarness(t *testing.T, h http.HandlerFunc) *reserveTestHarness {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	signingAddr, pub, priv, err := ticket.GenerateAlgorandKeypair()
	if err != nil {
		t.Fatal(err)
	}
	ownerAddr, _, _, err := ticket.GenerateAlgorandKeypair()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	return &reserveTestHarness{
		server: srv,
		operator: Operator{
			ID:          1,
			OwnerAddr:   ownerAddr,
			SigningAddr: signingAddr,
			// Mandatory forward secrecy: the harness node opens reserves with
			// h.identity (== id), so advertise that identity as the operator's
			// (valid, unexpired) ephemeral recipient — there is no anchor.
			EphemeralRecipient:       id.Recipient(),
			EphemeralRecipientPubkey: id.Recipient().String(),
			EphemeralExpiry:          time.Now().Add(10 * time.Minute).Unix(),
			EphemeralIssuedAt:        time.Now().Unix(),
			TicketSigningKey:         pub,
			BaseURL:                  srv.URL,
			Models:                   []string{"gpt-test"},
		},
		identity: id,
		signKey:  priv,
		signAddr: signingAddr,
	}
}

// issueValidTicket builds, signs, and returns a ticket.ReserveResponse
// for the given reserve request. h.signKey signs the ticket. Callers
// usually inject this as the fake node's handler output.
func (h *reserveTestHarness) issueValidTicket(t *testing.T, req ticket.ReserveRequest) ticket.ReserveResponse {
	t.Helper()
	var k [wire.ResponseKeySize]byte
	_, _ = rand.Read(k[:])
	commit := ticket.CommitResponseKey(k)

	var idRaw [16]byte
	_, _ = rand.Read(idRaw[:])
	tkt := ticket.Ticket{
		TicketID:       base64.StdEncoding.EncodeToString(idRaw[:]),
		OperatorID:     h.operator.ID,
		InputCount:     req.InputCount,
		MaxOutputCount: req.MaxOutputCount,
		InputRate:      2,
		OutputRate:     5,
		MaxPrice:       req.InputCount*2 + req.MaxOutputCount*5,
		ExpiresAt:      time.Now().Add(30 * time.Second).Unix(),
		Model:          req.Model,
		Stream:         req.Stream,
		CommitK:        base64.StdEncoding.EncodeToString(commit[:]),
	}
	if err := tkt.Sign(context.Background(), rawKeyBytesSigner{addr: h.signAddr, priv: h.signKey}, h.signAddr); err != nil {
		t.Fatal(err)
	}

	// Wrap K_response to the proxy's declared age recipient so the real
	// HTTPReserveClient can unwrap it and succeed. The harness isn't
	// testing the admission-tag path directly but the client always
	// expects a non-empty wrapped key now.
	recipient, err := age.ParseX25519Recipient(req.ProxyRecipient)
	if err != nil {
		t.Fatalf("parse proxy recipient: %v", err)
	}
	var buf bytes.Buffer
	aw, err := age.Encrypt(&buf, recipient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := aw.Write(k[:]); err != nil {
		t.Fatal(err)
	}
	if err := aw.Close(); err != nil {
		t.Fatal(err)
	}
	return ticket.ReserveResponse{
		Ticket:             tkt,
		WrappedResponseKey: base64.StdEncoding.EncodeToString(buf.Bytes()),
	}
}

// writeSealedReserve writes a 200 reserve response the way an 8.0 node does:
// the whole body age-sealed to the caller's proxy_recipient, because
// presigned_open_txn would otherwise show a forwarding relay the payer address.
func writeSealedReserve(t *testing.T, w http.ResponseWriter, resp ticket.ReserveResponse, proxyRecipient string) {
	t.Helper()
	recipient, err := age.ParseX25519Recipient(proxyRecipient)
	if err != nil {
		t.Fatalf("parse proxy recipient: %v", err)
	}
	plaintext, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal reserve response: %v", err)
	}
	sealed, err := wire.SealReserveResponse(plaintext, recipient)
	if err != nil {
		t.Fatalf("seal reserve response: %v", err)
	}
	w.Header().Set("Content-Type", wire.SealedReserveResponseContentType)
	_, _ = w.Write(sealed)
}

func sampleReserveReq() ticket.ReserveRequest {
	return ticket.ReserveRequest{
		Model:          "gpt-test",
		InputCount:     100,
		MaxOutputCount: 50,
		Stream:         false,
	}
}

func TestHTTPReserveClient_HappyPath(t *testing.T) {
	req := sampleReserveReq()
	var seen ticket.ReserveRequest
	h := newReserveHarness(t, func(w http.ResponseWriter, r *http.Request) {})
	// Fill in the response: re-derive via h after seen.
	h.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/zs/reserve" {
			http.NotFound(w, r)
			return
		}
		rr := h.decodeReserve(t, r)
		seen = rr
		resp := h.issueValidTicket(t, rr)
		writeSealedReserve(t, w, resp, rr.ProxyRecipient)
	})

	c := &HTTPReserveClient{HTTPClient: http.DefaultClient}
	got, err := c.Reserve(context.Background(), h.operator, req, nil)
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if got.Ticket.Model != req.Model {
		t.Errorf("ticket.Model = %q", got.Ticket.Model)
	}
	if seen.Model != req.Model {
		t.Errorf("node saw Model = %q", seen.Model)
	}
	if seen.ProxyRecipient == "" {
		t.Error("node did not see ProxyRecipient in ReserveRequest")
	}
	if got.AgeIdentity == nil {
		t.Error("ReservedTicket.AgeIdentity is nil")
	}
	var zero [wire.ResponseKeySize]byte
	if got.ResponseKey == zero {
		t.Error("ReservedTicket.ResponseKey is the zero value (unwrap did not fire)")
	}
}

// A caller that leaves HTTPClient nil gets New's guard, not http.DefaultClient:
// the reserve to a loopback node is refused at dial, and the per-reserve
// deadline still applies.
func TestHTTPReserveClient_NilClientIsGuarded(t *testing.T) {
	var reached atomic.Bool
	h := newReserveHarness(t, func(w http.ResponseWriter, r *http.Request) { reached.Store(true) })

	_, err := (&HTTPReserveClient{}).Reserve(context.Background(), h.operator, sampleReserveReq(), nil)
	if err == nil || reached.Load() {
		t.Fatalf("a nil-client reserve reached a loopback node (err %v, reached %v)", err, reached.Load())
	}
	if defaultReserveHTTPClient.Timeout != DefaultReserveTimeout {
		t.Errorf("nil-client timeout = %v, want %v", defaultReserveHTTPClient.Timeout, DefaultReserveTimeout)
	}
}

func TestHTTPReserveClient_BusyReturnsBusyError(t *testing.T) {
	h := newReserveHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"message":"busy"}}`))
	})
	c := &HTTPReserveClient{HTTPClient: http.DefaultClient}
	_, err := c.Reserve(context.Background(), h.operator, sampleReserveReq(), nil)
	if !IsBusy(err) {
		t.Fatalf("err = %v, want BusyError", err)
	}
	var be *BusyError
	_ = errors.As(err, &be)
	if be.RetryAfter != 7*time.Second {
		t.Errorf("RetryAfter = %v, want 7s", be.RetryAfter)
	}
}

func TestHTTPReserveClient_BadSigRejected(t *testing.T) {
	h := newReserveHarness(t, func(w http.ResponseWriter, r *http.Request) {})
	// Rewire handler after construction so it can reference h.
	h.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rr := h.decodeReserve(t, r)
		resp := h.issueValidTicket(t, rr)
		// Flip a byte in the sig to invalidate it.
		sigBytes, _ := base64.StdEncoding.DecodeString(resp.Ticket.Sig)
		sigBytes[0] ^= 0xFF
		resp.Ticket.Sig = base64.StdEncoding.EncodeToString(sigBytes)
		writeSealedReserve(t, w, resp, rr.ProxyRecipient)
	})
	c := &HTTPReserveClient{HTTPClient: http.DefaultClient}
	_, err := c.Reserve(context.Background(), h.operator, sampleReserveReq(), nil)
	if err == nil {
		t.Fatal("want sig verify error")
	}
	if !strings.Contains(err.Error(), "verify") {
		t.Errorf("err = %v", err)
	}
}

// TestHTTPReserveClient_CommitKMismatchRejected covers the reserve-time
// commit_k check: a node signs a valid ticket committing sha256(K_real) but
// wraps a DIFFERENT key in wrapped_response_key. The ticket signature still
// verifies, so only the commit_k↔wrapped-key binding catches the fraud —
// before the caller composes/submits open() and burns tx fees. Mirrors the
// TS SDK's reserve-time check (sdk/src/reserve.ts).
func TestHTTPReserveClient_CommitKMismatchRejected(t *testing.T) {
	h := newReserveHarness(t, func(w http.ResponseWriter, r *http.Request) {})
	h.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rr := h.decodeReserve(t, r)
		resp := h.issueValidTicket(t, rr)
		// Re-wrap an unrelated key to the proxy's recipient, leaving the
		// signed ticket (and its committed commit_k) untouched.
		recipient, err := age.ParseX25519Recipient(rr.ProxyRecipient)
		if err != nil {
			t.Fatalf("parse proxy recipient: %v", err)
		}
		var kBad [wire.ResponseKeySize]byte
		_, _ = rand.Read(kBad[:])
		var buf bytes.Buffer
		aw, err := age.Encrypt(&buf, recipient)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := aw.Write(kBad[:]); err != nil {
			t.Fatal(err)
		}
		if err := aw.Close(); err != nil {
			t.Fatal(err)
		}
		resp.WrappedResponseKey = base64.StdEncoding.EncodeToString(buf.Bytes())
		writeSealedReserve(t, w, resp, rr.ProxyRecipient)
	})
	c := &HTTPReserveClient{HTTPClient: http.DefaultClient}
	_, err := c.Reserve(context.Background(), h.operator, sampleReserveReq(), nil)
	if err == nil {
		t.Fatal("want commit_k mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "commit_k mismatch") {
		t.Errorf("err = %v, want commit_k mismatch", err)
	}
}

func TestHTTPReserveClient_TicketModelMismatch(t *testing.T) {
	h := newReserveHarness(t, func(w http.ResponseWriter, r *http.Request) {})
	h.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rr := h.decodeReserve(t, r)
		rr.Model = "gpt-cheater" // build a ticket for a different model
		resp := h.issueValidTicket(t, rr)
		writeSealedReserve(t, w, resp, rr.ProxyRecipient)
	})
	c := &HTTPReserveClient{HTTPClient: http.DefaultClient}
	_, err := c.Reserve(context.Background(), h.operator, sampleReserveReq(), nil)
	if err == nil || !strings.Contains(err.Error(), "model") {
		t.Errorf("err = %v, want model mismatch", err)
	}
}

func TestHTTPReserveClient_Non200NonBusy(t *testing.T) {
	h := newReserveHarness(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusBadRequest)
	})
	c := &HTTPReserveClient{HTTPClient: http.DefaultClient}
	_, err := c.Reserve(context.Background(), h.operator, sampleReserveReq(), nil)
	if err == nil || strings.Contains(err.Error(), "busy") {
		t.Errorf("err = %v; want non-busy error", err)
	}
	if IsBusy(err) {
		t.Error("IsBusy should be false for 400s")
	}
	if IsSize(err) {
		t.Error("IsSize should be false for an unstructured 400 (text/plain body)")
	}
}

// A body our own deadline cuts off is not a ReserveHTTPError: a response did
// arrive, so there is no transport failure to charge, and no code to read. The
// TS SDK's reserve mirrors this (reserve-call.test.ts).
func TestHTTPReserveClient_BodyCutOffByDeadline_Unclassified(t *testing.T) {
	h := newReserveHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":`))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	c := &HTTPReserveClient{HTTPClient: http.DefaultClient}
	_, err := c.Reserve(ctx, h.operator, sampleReserveReq(), nil)
	if err == nil || !strings.HasPrefix(err.Error(), "read reserve response: ") {
		t.Fatalf("err = %v; want the body read failure", err)
	}
	if _, ok := AsReserveHTTP(err); ok {
		t.Error("a cut-off body must not read as a ReserveHTTPError")
	}
}

// A 400 carrying the node's OpenAI-shaped "context_length_exceeded"
// error must come back as *SizeError so dispatch can prefer
// 400 context_length_exceeded over 503 operators_busy when every
// reserve attempt refuses for size.
func TestHTTPReserveClient_ContextLengthExceeded_ReturnsSizeError(t *testing.T) {
	h := newReserveHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"message":"max_output_tokens exceeds this operator's cap for the model","type":"invalid_request_error","code":"context_length_exceeded"}}`))
	})
	c := &HTTPReserveClient{HTTPClient: http.DefaultClient}
	_, err := c.Reserve(context.Background(), h.operator, sampleReserveReq(), nil)
	if !IsSize(err) {
		t.Fatalf("err = %v, want SizeError", err)
	}
	if IsBusy(err) {
		t.Error("IsBusy should be false for a sizing rejection")
	}
	var se *SizeError
	if !errors.As(err, &se) {
		t.Fatalf("errors.As did not produce *SizeError; err = %v", err)
	}
	if se.Code != "context_length_exceeded" {
		t.Errorf("Code = %q, want context_length_exceeded", se.Code)
	}
	if !strings.Contains(se.Message, "max_output_tokens") {
		t.Errorf("Message = %q, want it to mention max_output_tokens", se.Message)
	}
}

// A 400 with a recognised OpenAI envelope but a *non-sizing* code
// (e.g. invalid_payer_addr) is operator-environment fallout, not
// something the dispatcher should reclassify as 400
// context_length_exceeded — must remain a generic non-Busy non-Size
// error so the loop logs it at warn and falls through to 503.
func TestHTTPReserveClient_OtherEnvelopedBadRequest_NotSizeError(t *testing.T) {
	h := newReserveHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"message":"bad payer addr","type":"invalid_request_error","code":"invalid_payer_addr"}}`))
	})
	c := &HTTPReserveClient{HTTPClient: http.DefaultClient}
	_, err := c.Reserve(context.Background(), h.operator, sampleReserveReq(), nil)
	if err == nil {
		t.Fatal("want error")
	}
	if IsSize(err) {
		t.Errorf("IsSize true for a non-sizing 400; err = %v", err)
	}
	if IsBusy(err) {
		t.Errorf("IsBusy true for a 400; err = %v", err)
	}
}

// TestValidateTicketShape_MinPriceInvariant confirms the proxy rejects
// a ticket whose min_price exceeds max_price — a malformed quote that
// would either underfund escrow or signal a misbehaving operator. The
// node always bumps max_price to cover min_price at reserve time, so
// this invariant must hold for every ticket the proxy accepts.
func TestValidateTicketShape_MinPriceInvariant(t *testing.T) {
	op := Operator{ID: 7}
	req := ticket.ReserveRequest{
		Model:          "gpt-test",
		InputCount:     100,
		MaxOutputCount: 50,
		Stream:         false,
	}
	base := ticket.Ticket{
		OperatorID:     op.ID,
		InputCount:     req.InputCount,
		MaxOutputCount: req.MaxOutputCount,
		Stream:         req.Stream,
		ExpiresAt:      time.Now().Add(time.Minute).Unix(),
		TicketID:       "id",
		CommitK:        "commit",
		Model:          req.Model,
	}

	// min_price <= max_price always accepted (including 0 / equality).
	for _, c := range []struct {
		name       string
		minP, maxP uint64
	}{
		{"floor disabled (min=0)", 0, 1_000},
		{"min < max", 100, 1_000},
		{"min == max", 1_000, 1_000},
	} {
		tk := base
		tk.MinPrice, tk.MaxPrice = c.minP, c.maxP
		if err := validateTicketShape(&tk, op, req); err != nil {
			t.Errorf("%s: validateTicketShape err = %v, want nil", c.name, err)
		}
	}

	// min_price > max_price must be rejected — invariant violated.
	tk := base
	tk.MinPrice, tk.MaxPrice = 1_001, 1_000
	err := validateTicketShape(&tk, op, req)
	if err == nil {
		t.Fatal("validateTicketShape accepted min_price > max_price; want error")
	}
	if !strings.Contains(err.Error(), "min_price") {
		t.Errorf("error %q does not mention min_price", err.Error())
	}
}

// A ticket bound to a different node than the one we selected must be rejected
// — the routing primary key is (operator id, node id), so a node-id-only
// mismatch (e.g. a node misconfigured to sign under a node id that differs from
// its on-chain NodeRecord) can't be trusted to settle or attribute correctly.
func TestValidateTicketShape_NodeIDMismatch(t *testing.T) {
	op := Operator{ID: 7, NodeID: 2}
	req := ticket.ReserveRequest{
		Model:          "gpt-test",
		InputCount:     100,
		MaxOutputCount: 50,
		Stream:         false,
	}
	base := ticket.Ticket{
		OperatorID:     op.ID,
		NodeID:         op.NodeID,
		InputCount:     req.InputCount,
		MaxOutputCount: req.MaxOutputCount,
		Stream:         req.Stream,
		ExpiresAt:      time.Now().Add(time.Minute).Unix(),
		TicketID:       "id",
		CommitK:        "commit",
		Model:          req.Model,
		MaxPrice:       1_000,
	}

	// Matching (operator id, node id) is accepted.
	if err := validateTicketShape(&base, op, req); err != nil {
		t.Fatalf("matching node id rejected: %v", err)
	}

	// node_id mismatch is rejected, and the error names the node id.
	tk := base
	tk.NodeID = 3
	err := validateTicketShape(&tk, op, req)
	if err == nil {
		t.Fatal("validateTicketShape accepted a node_id mismatch; want error")
	}
	if !strings.Contains(err.Error(), "node id") {
		t.Errorf("error %q does not mention node id", err.Error())
	}
}

// The node caps input_count at the context window (SPEC §3a), and an older node
// also floored it at its own min_input_count, so an honest ticket can carry a
// different count than was asked for.
func TestValidateTicketShape_AcceptsAClampedInputCount(t *testing.T) {
	op := Operator{ID: 7, NodeID: 2}
	req := ticket.ReserveRequest{Model: "gpt-test", InputCount: 300, MaxOutputCount: 50}
	for _, signed := range []uint64{512, 200} {
		tk := ticket.Ticket{
			OperatorID: op.ID, NodeID: op.NodeID, Model: req.Model,
			InputCount: signed, MaxOutputCount: req.MaxOutputCount,
			ExpiresAt: time.Now().Add(time.Minute).Unix(), TicketID: "id", CommitK: "commit", MaxPrice: 1_000,
		}
		if err := validateTicketShape(&tk, op, req); err != nil {
			t.Errorf("input_count %d against a request of %d: %v", signed, req.InputCount, err)
		}
	}
}

// A free-ticket allowance resets up to a day out, and the caller is told when;
// the TypeScript SDK's parseRetryAfter holds the same cases.
func TestParseRetryAfter(t *testing.T) {
	for _, c := range []struct {
		in   string
		want time.Duration
	}{
		{"", 0},
		{"0", 0},
		{"-5", 0},
		{"1.5", 0},
		{"Wed, 21 Oct 2026 07:28:00 GMT", 0},
		{" 30 ", 30 * time.Second},
		{"+30", 30 * time.Second},
		{"86400", 24 * time.Hour},
		{"86401", 24 * time.Hour},
		{"76172", 76172 * time.Second},
		// Past where seconds × 1e9 overflows an int64, and past an int.
		{"9223372037", 24 * time.Hour},
		{"18446744074", 24 * time.Hour},
		// The last value an int64 holds still reads as a day; one past it is no hint.
		{"9223372036854775807", 24 * time.Hour},
		{"9223372036854775808", 0},
		{"99999999999999999999", 0},
	} {
		if got := parseRetryAfter(c.in); got != c.want {
			t.Errorf("parseRetryAfter(%q) = %s, want %s", c.in, got, c.want)
		}
	}
}

func TestHTTPReserveClient_NetworkFailure(t *testing.T) {
	// Operator with an unreachable URL but a valid, unexpired ephemeral
	// recipient, so the seal step succeeds and the failure is genuinely the
	// network hop.
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	op := Operator{
		OwnerAddr:                "OP",
		EphemeralRecipient:       id.Recipient(),
		EphemeralRecipientPubkey: id.Recipient().String(),
		EphemeralExpiry:          time.Now().Add(10 * time.Minute).Unix(),
		TicketSigningKey:         make(ed25519.PublicKey, ed25519.PublicKeySize),
		BaseURL:                  "http://127.0.0.1:1", // unlikely to be listening
	}
	c := &HTTPReserveClient{HTTPClient: &http.Client{Timeout: 200 * time.Millisecond}}
	_, err = c.Reserve(context.Background(), op, sampleReserveReq(), nil)
	if err == nil {
		t.Fatal("want network error")
	}
	if IsBusy(err) {
		t.Error("network failure should not be BusyError")
	}
}

// TestHTTPReserveClient_SealsRequest confirms the proxy seals the reserve
// body to the operator's age recipient and sends it under
// SealedReserveContentType — the bytes on the wire must not carry the
// plaintext payer_addr, and they must open to the original request.
func TestHTTPReserveClient_SealsRequest(t *testing.T) {
	var rawBody []byte
	var gotCT string
	h := newReserveHarness(t, func(w http.ResponseWriter, r *http.Request) {})
	h.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		rawBody, _ = io.ReadAll(r.Body)
		// Re-open from the captured bytes so the client still gets a ticket.
		plaintext, err := wire.OpenReserveRequest(rawBody, h.identity)
		if err != nil {
			t.Fatalf("open sealed reserve: %v", err)
		}
		var rr ticket.ReserveRequest
		if err := json.Unmarshal(plaintext, &rr); err != nil {
			t.Fatalf("unmarshal inner: %v", err)
		}
		resp := h.issueValidTicket(t, rr)
		writeSealedReserve(t, w, resp, rr.ProxyRecipient)
	})

	req := sampleReserveReq()
	req.PayerAddr = "PAYERADDR1234567890"
	c := &HTTPReserveClient{HTTPClient: http.DefaultClient}
	if _, err := c.Reserve(context.Background(), h.operator, req, nil); err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if gotCT != wire.SealedReserveContentType {
		t.Errorf("Content-Type = %q, want %q", gotCT, wire.SealedReserveContentType)
	}
	if bytes.Contains(rawBody, []byte("PAYERADDR1234567890")) || bytes.Contains(rawBody, []byte("payer_addr")) {
		t.Errorf("sealed reserve body leaks plaintext payer_addr: %s", rawBody)
	}
	// The wire body must be a SealedReserveEnvelope (single ciphertext field).
	var env wire.SealedReserveEnvelope
	if err := json.Unmarshal(rawBody, &env); err != nil || env.Ciphertext == "" {
		t.Errorf("body is not a SealedReserveEnvelope: err=%v body=%s", err, rawBody)
	}
}

// TestHTTPReserveClient_SignsPayer verifies the P3a signer: with a Signer
// wired, the reserve body the node receives carries a payer_sig +
// payer_issued_at, the signature verifies under the payer key for the target
// (op.ID, op.NodeID) the proxy routed to, and it is target-bound (a sibling
// node / other operator rejects it).
func TestHTTPReserveClient_SignsPayer(t *testing.T) {
	payerAddr, payerPub, payerPriv, err := ticket.GenerateAlgorandKeypair()
	if err != nil {
		t.Fatal(err)
	}

	var seen ticket.ReserveRequest
	h := newReserveHarness(t, func(w http.ResponseWriter, r *http.Request) {})
	h.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != reservePath {
			http.NotFound(w, r)
			return
		}
		seen = h.decodeReserve(t, r)
		resp := h.issueValidTicket(t, seen)
		writeSealedReserve(t, w, resp, seen.ProxyRecipient)
	})

	req := sampleReserveReq()
	req.PayerAddr = payerAddr
	c := &HTTPReserveClient{HTTPClient: http.DefaultClient, Signer: rawKeyBytesSigner{addr: payerAddr, priv: payerPriv}}
	if _, err := c.Reserve(context.Background(), h.operator, req, nil); err != nil {
		t.Fatalf("Reserve: %v", err)
	}

	if seen.PayerSig == "" {
		t.Fatal("reserve body carried no payer_sig")
	}
	if seen.PayerIssuedAt == 0 {
		t.Fatal("reserve body carried no payer_issued_at")
	}
	// Verifies for the target the proxy routed to (the node's own identity).
	if err := seen.Verify(payerPub, h.operator.ID, h.operator.NodeID, time.Now(), ticket.DefaultReserveSkew); err != nil {
		t.Fatalf("node-side verify of the proxy signature failed: %v", err)
	}
	// Target-bound: a sibling node or a different operator rejects it.
	if err := seen.Verify(payerPub, h.operator.ID, h.operator.NodeID+1, time.Now(), ticket.DefaultReserveSkew); err == nil {
		t.Error("signature verified for the wrong node_id (target binding broken)")
	}
	if err := seen.Verify(payerPub, h.operator.ID+1, h.operator.NodeID, time.Now(), ticket.DefaultReserveSkew); err == nil {
		t.Error("signature verified for the wrong operator_id (target binding broken)")
	}
}

// On a 401 invalid_payer_sig carrying node_time (clock skew), Reserve re-stamps
// payer_issued_at to the node's clock, re-signs, and retries once against the
// same operator — instead of surfacing the 401 (which the dispatcher would
// launder into operators_busy).
func TestHTTPReserveClient_ResyncsOnClockSkew(t *testing.T) {
	payerAddr, payerPub, payerPriv, err := ticket.GenerateAlgorandKeypair()
	if err != nil {
		t.Fatal(err)
	}
	const nodeTime = int64(1_700_000_123)
	var seen []ticket.ReserveRequest
	calls := 0
	h := newReserveHarness(t, func(w http.ResponseWriter, r *http.Request) {})
	h.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != reservePath {
			http.NotFound(w, r)
			return
		}
		rr := h.decodeReserve(t, r)
		seen = append(seen, rr)
		calls++
		if calls == 1 {
			// Reject for skew and hand back the node's clock (plaintext error).
			w.Header().Set("Content-Type", ticket.ReserveContentType)
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, `{"error":{"code":"invalid_payer_sig","message":"payer signature verification failed (node_time=%d)"}}`, nodeTime)
			return
		}
		resp := h.issueValidTicket(t, rr)
		writeSealedReserve(t, w, resp, rr.ProxyRecipient)
	})

	req := sampleReserveReq()
	req.PayerAddr = payerAddr
	c := &HTTPReserveClient{HTTPClient: http.DefaultClient, Signer: rawKeyBytesSigner{addr: payerAddr, priv: payerPriv}}
	if _, err := c.Reserve(context.Background(), h.operator, req, nil); err != nil {
		t.Fatalf("Reserve should succeed after the node_time resync: %v", err)
	}
	if calls != 2 {
		t.Fatalf("want 2 attempts (401 skew + resync retry), got %d", calls)
	}
	// The retry re-stamped payer_issued_at to the node's clock and re-signed.
	if seen[1].PayerIssuedAt != nodeTime {
		t.Fatalf("resync payer_issued_at = %d, want node_time %d", seen[1].PayerIssuedAt, nodeTime)
	}
	if seen[0].PayerIssuedAt == nodeTime {
		t.Fatal("first attempt should have used the local clock, not node_time")
	}
	// The resynced signature verifies for the target at the node's clock.
	if err := seen[1].Verify(payerPub, h.operator.ID, h.operator.NodeID, time.Unix(nodeTime+5, 0), ticket.DefaultReserveSkew); err != nil {
		t.Fatalf("resynced signature should verify: %v", err)
	}
}

// A persistent 401 invalid_payer_sig is retried at most once, then surfaced —
// Reserve does not loop.
func TestHTTPReserveClient_ResyncsAtMostOnce(t *testing.T) {
	payerAddr, _, payerPriv, err := ticket.GenerateAlgorandKeypair()
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	h := newReserveHarness(t, func(w http.ResponseWriter, r *http.Request) {})
	h.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != reservePath {
			http.NotFound(w, r)
			return
		}
		_ = h.decodeReserve(t, r)
		calls++
		w.Header().Set("Content-Type", ticket.ReserveContentType)
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":{"code":"invalid_payer_sig","message":"still bad (node_time=1700000123)"}}`)
	})

	req := sampleReserveReq()
	req.PayerAddr = payerAddr
	c := &HTTPReserveClient{HTTPClient: http.DefaultClient, Signer: rawKeyBytesSigner{addr: payerAddr, priv: payerPriv}}
	_, err = c.Reserve(context.Background(), h.operator, req, nil)
	if err == nil {
		t.Fatal("Reserve should fail when the node persistently rejects the signature")
	}
	if calls != 2 {
		t.Fatalf("want exactly 2 attempts (initial + one resync), got %d", calls)
	}
	// As any other refusal, so the dispatcher classifies it rather than
	// reading an unknown error as busy.
	if re, ok := AsReserveHTTP(err); !ok || re.Status != http.StatusUnauthorized || re.Code != "invalid_payer_sig" {
		t.Fatalf("err = %#v, want a *ReserveHTTPError 401 invalid_payer_sig", err)
	}
}

// An unsigned reserve can't resync, so a skew 401 surfaces as a refusal.
func TestHTTPReserveClient_UnsignedSkewIsARefusal(t *testing.T) {
	h := newReserveHarness(t, func(w http.ResponseWriter, r *http.Request) {})
	h.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = h.decodeReserve(t, r)
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":{"code":"invalid_payer_sig","message":"required (node_time=1700000123)"}}`)
	})
	c := &HTTPReserveClient{HTTPClient: http.DefaultClient}
	_, err := c.Reserve(context.Background(), h.operator, sampleReserveReq(), nil)
	if re, ok := AsReserveHTTP(err); !ok || re.Status != http.StatusUnauthorized {
		t.Fatalf("err = %#v, want a *ReserveHTTPError 401", err)
	}
}

// One node's hint is capped where it becomes the caller's wait.
func TestNodeRetryHint(t *testing.T) {
	if got := nodeRetryHint(24 * time.Hour); got != maxNodeRetryHint {
		t.Errorf("nodeRetryHint(24h) = %s, want %s", got, maxNodeRetryHint)
	}
	if got := nodeRetryHint(30 * time.Second); got != 30*time.Second {
		t.Errorf("nodeRetryHint(30s) = %s, want 30s", got)
	}
}

// A reserve client with no Signer wired must still work (verify-if-present on
// the node) and emit no payer_sig — the rollout-safe default.
func TestHTTPReserveClient_NoSignerOmitsSig(t *testing.T) {
	var seen ticket.ReserveRequest
	h := newReserveHarness(t, func(w http.ResponseWriter, r *http.Request) {})
	h.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = h.decodeReserve(t, r)
		resp := h.issueValidTicket(t, seen)
		writeSealedReserve(t, w, resp, seen.ProxyRecipient)
	})

	req := sampleReserveReq()
	req.PayerAddr = "PAYERADDR1234567890"
	c := &HTTPReserveClient{HTTPClient: http.DefaultClient} // no Signer
	if _, err := c.Reserve(context.Background(), h.operator, req, nil); err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if seen.PayerSig != "" || seen.PayerIssuedAt != 0 {
		t.Errorf("unsigned client emitted a signature: sig=%q issued=%d", seen.PayerSig, seen.PayerIssuedAt)
	}
}

// TestHTTPReserveClient_NoEphemeral_Error: an operator with no valid ephemeral
// recipient must fail fast with errNoEphemeral before any HTTP hop — mandatory
// forward secrecy has no anchor to fall back to, so the proxy cannot seal.
func TestHTTPReserveClient_NoEphemeral_Error(t *testing.T) {
	op := Operator{
		ID:               9,
		OwnerAddr:        "OP",
		TicketSigningKey: make(ed25519.PublicKey, ed25519.PublicKeySize),
		BaseURL:          "http://127.0.0.1:1",
	}
	c := &HTTPReserveClient{HTTPClient: http.DefaultClient}
	_, err := c.Reserve(context.Background(), op, sampleReserveReq(), nil)
	if !IsNoEphemeral(err) {
		t.Fatalf("err = %v, want errNoEphemeral for an operator with no ephemeral recipient", err)
	}
}
