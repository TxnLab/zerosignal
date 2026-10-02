/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"

	"github.com/algorand/go-algorand-sdk/v2/types"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/TxnLab/zerosignal/go/escrow"
	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/wire"
	hayai "github.com/TxnLab/zerosignal/go/zs"
	"github.com/TxnLab/zerosignal/go/zs/tokenize"
)

// --- fake-node harness ----------------------------------------------------
//
// Every slice-3 proxy test drives a fake node that handles both
// /v1/zs/reserve and the sealed inference endpoints. The node:
//
//   - Issues a signed ticket with a pre-committed K on reserve (unless
//     the test's nodeMode says "busy" or a specific reserve failure).
//   - Remembers the last issued (ticket_id → K) so the inference handler
//     can seal responses with the exact K the ticket committed to —
//     this is what lets the proxy's commit_k verification succeed.

type nodeMode int

const (
	modeNonStreamEncrypted           nodeMode = iota
	modeNonStreamPlaintext200                 // operator returns 200 unsealed (protocol violation)
	modeNonStreamDefensiveCTMismatch          // operator sets key but writes plaintext body (protocol violation)
	modeNonStreamTamperedCiphertext
	modeNonStreamBadKeyHeader
	modeNonStreamCommitKMismatch // node seals with a fresh K, breaking commit_k
	// modeNonStreamPreEnvelopeError: node writes a plaintext OpenAI-shaped
	// 4xx with no response key — the pre-envelope error passthrough path.
	modeNonStreamPreEnvelopeError
	modeStreamEncrypted
	modeStreamPlaintext // operator returns 200 SSE without sealing (protocol violation)
	modeStreamMixedEvents
	modeStreamTamperedFrame
	modeStreamCommitKMismatch // node seals the stream with a fresh K, breaking commit_k
	// modeStreamReceiptDropTail emits all content frames sealed at their true
	// indices but DROPS the tail content frame on the wire, then emits the
	// frame-index-bound zs-receipt — simulating a relay that drops a tail
	// content frame. The proxy's frameIndex desyncs, so the receipt fails to
	// decrypt and is swallowed (no protest). Requires buildReceipt + ≥2 frames.
	modeStreamReceiptDropTail
	// modeStreamReceiptTruncated emits the content frames then [DONE] but NO
	// zs-receipt frame — simulating a relay truncating before the receipt.
	// runReceiptChecks never runs (no protest). Requires buildReceipt.
	modeStreamReceiptTruncated
	// modeStreamReceiptIntact emits content frames + an intact frame-index-bound
	// zs-receipt — the positive control: the proxy decrypts the receipt and
	// runReceiptChecks runs (and protests on a body_hash mismatch). Proves the
	// drop/truncate negative tests aren't vacuous. Requires buildReceipt.
	modeStreamReceiptIntact
	// modeInferenceGatewayHTMLError models an operator's CDN answering the
	// INFERENCE forward instead of its node: a code-less HTML 504 with no
	// response key. This is the shape a bunny.net origin failure produced in
	// production, and forwarding it verbatim is what handed a strict SSE client
	// an unparseable body.
	modeInferenceGatewayHTMLError
	modeReserveBusy         // reserve always returns 429
	modeReserveSizeRejected // reserve always returns 400 context_length_exceeded
	// modeReserveGatewayError models an operator whose CDN / ingress / LB is
	// answering for it while the node behind it restarts: an HTML 504 with no
	// OpenAI-shaped error code at all. That missing code is the whole signal —
	// it is what distinguishes gateway weather from a node's considered refusal.
	modeReserveGatewayError
)

type nodeConfig struct {
	mode                  nodeMode
	replyPlaintext        []byte
	streamFrames          [][]byte
	onRequest             func(r *http.Request, clientBody []byte)
	onReserve             func(req ticket.ReserveRequest) // observes the decoded reserve request
	skipClientBodyDecrypt bool
	retryAfterSeconds     int // 0 = don't emit the header on 429
	// busyCode overrides the OpenAI error.code on a 429. Empty = "no_capacity"
	// (the one re-askable condition). Set it to payer_slot_cap /
	// reserve_temporarily_banned / rate_limited to drive the must-not-re-ask paths.
	busyCode string
	// busyNoCode sends the 429 body with no error.code at all, as an older node
	// does; busyCode is then ignored.
	busyNoCode bool
	// gatewayRetryAfter / gatewayCTSuffix shape the modeInferenceGatewayHTMLError
	// response: a Retry-After the proxy must preserve across body replacement, and
	// a padded Content-Type that must be truncated before it reaches a log or the
	// client.
	gatewayRetryAfter string
	gatewayCTSuffix   string
	// gatewayThenRefuseAfter, when > 0, makes the reserve handler return a
	// code-less HTML 504 (gateway weather) for the first N calls and a coded
	// `provider_unavailable` 503 (a considered refusal) thereafter — used to
	// drive the proxy's multi-sweep terminal-selection: sweep 0 is pure weather,
	// a later sweep sees a refusal. Overrides `mode` for the reserve route.
	gatewayThenRefuseAfter int
	// busyThenServeAfter, when > 0, makes the reserve handler return 429 for the
	// first N calls and serve normally thereafter — a node whose queue drains
	// while the caller waits. Drives the proxy's bounded busy re-sweep. Overrides
	// `mode` for the reserve route, like gatewayThenRefuseAfter.
	busyThenServeAfter int
	// extraRespHeaders are literal response headers the node sets on the
	// inference response before the mode writer runs — models node-set
	// X-Zs-* metadata (e.g. X-Zs-Settle-Group) the proxy must strip.
	extraRespHeaders map[string]string
	// reserveBadEnvelopeOnOpenFail makes a reserve the node can't age-open
	// (sealed to a recipient that isn't node.identity) return the real node's
	// OpenAI-shaped bad_reserve_envelope 400 instead of failing the test — used
	// to drive the proxy's stale-ephemeral self-heal re-probe path. With it
	// unset, an unexpected mis-seal still fails the test as before.
	reserveBadEnvelopeOnOpenFail bool
	// Receipt. When non-nil, the node attaches a signed
	// UsageReceipt to non-stream responses and as a final sealed
	// zs-receipt frame on stream responses. The builder is called
	// with the plaintext body (or concatenated stream frames); it
	// returns the unsigned receipt for the harness to sign. Return
	// nil from the builder to skip attaching.
	buildReceipt func(plaintext []byte) *ticket.UsageReceipt
}

type fakeNode struct {
	*httptest.Server
	operator    hayai.Operator
	identity    *age.X25519Identity
	signingKey  ed25519.PrivateKey
	signingAddr string

	mu        sync.Mutex
	tickets   map[string][wire.ResponseKeySize]byte // ticket_id → K
	callCount int                                   // how many requests of any kind reached this node
	// lastSealedAlgorandTxID records the envelope's AlgorandTxID on
	// every sealed request so tests can assert which payment-path
	// produced it (stub random vs wallet group id).
	lastSealedAlgorandTxID string
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

func newFakeNode(t *testing.T, cfg *nodeConfig) *fakeNode {
	t.Helper()
	ageID, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate age identity: %v", err)
	}
	signingAddr, pub, priv, err := ticket.GenerateAlgorandKeypair()
	if err != nil {
		t.Fatalf("generate signing keypair: %v", err)
	}
	ownerAddr, _, _, err := ticket.GenerateAlgorandKeypair()
	if err != nil {
		t.Fatalf("generate payment keypair: %v", err)
	}

	node := &fakeNode{
		identity:    ageID,
		signingKey:  priv,
		signingAddr: signingAddr,
		tickets:     make(map[string][wire.ResponseKeySize]byte),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/zs/reserve", func(w http.ResponseWriter, r *http.Request) {
		node.incCallCount()
		if cfg.mode == modeReserveBusy {
			if cfg.retryAfterSeconds > 0 {
				w.Header().Set("Retry-After", itoa(cfg.retryAfterSeconds))
			}
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write(busyBody(cfg))
			return
		}
		if cfg.busyThenServeAfter > 0 && node.callCountValue() <= cfg.busyThenServeAfter {
			// Queue full for now. incCallCount already ran, so callCountValue
			// reflects THIS call.
			if cfg.retryAfterSeconds > 0 {
				w.Header().Set("Retry-After", itoa(cfg.retryAfterSeconds))
			}
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write(busyBody(cfg))
			return
		}
		if cfg.gatewayThenRefuseAfter > 0 {
			// First N calls: code-less gateway weather (504). After: a coded
			// considered refusal (provider_unavailable). node.incCallCount already
			// ran above, so callCountValue reflects THIS call.
			if node.callCountValue() > cfg.gatewayThenRefuseAfter {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"error":{"message":"backend down","type":"server_error","code":"provider_unavailable"}}`))
				return
			}
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusGatewayTimeout)
			_, _ = w.Write([]byte("<html><body>504</body></html>"))
			return
		}
		if cfg.mode == modeReserveGatewayError {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusGatewayTimeout)
			_, _ = w.Write([]byte("<html><head><title>504 Gateway Time-out</title></head><body></body></html>"))
			return
		}
		if cfg.mode == modeReserveSizeRejected {
			// Mirrors node/internal/server/reserve.go's
			// "max_output_tokens exceeds this operator's cap for the
			// model" branch (HTTP 400, OpenAI-shaped envelope, code
			// "context_length_exceeded"). Used by tests that exercise
			// the proxy's reserve-time sizing-rejection path.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":{"message":"max_output_tokens exceeds this operator's cap for the model","type":"invalid_request_error","code":"context_length_exceeded"}}`))
			return
		}
		// Reserve now rides the wire age-sealed (SealedReserveContentType);
		// open it with the node identity before parsing, mirroring the
		// production node's handleReserve.
		if ct := r.Header.Get("Content-Type"); ct != wire.SealedReserveContentType {
			t.Errorf("node: reserve Content-Type = %q, want %q", ct, wire.SealedReserveContentType)
			http.Error(w, "bad content type", http.StatusUnsupportedMediaType)
			return
		}
		rawReserve, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("node: read reserve: %v", err)
			http.Error(w, "bad reserve", http.StatusBadRequest)
			return
		}
		plaintext, err := wire.OpenReserveRequest(rawReserve, node.identity)
		if err != nil {
			// Sealed to a recipient this node can't open. When the test expects it
			// (a stale-but-unexpired ephemeral), mirror the production node's
			// OpenAI-shaped bad_reserve_envelope 400 so the proxy maps it to
			// errBadReserveEnvelope and runs its self-heal re-probe. Otherwise it's
			// an unexpected mis-seal — fail the test as before.
			if cfg.reserveBadEnvelopeOnOpenFail {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":{"message":"failed to open sealed reserve request","type":"invalid_request_error","code":"bad_reserve_envelope"}}`))
				return
			}
			t.Errorf("node: open sealed reserve: %v", err)
			http.Error(w, "bad reserve", http.StatusBadRequest)
			return
		}
		var req ticket.ReserveRequest
		if err := json.Unmarshal(plaintext, &req); err != nil {
			t.Errorf("node: parse reserve: %v", err)
			http.Error(w, "bad reserve", http.StatusBadRequest)
			return
		}
		if cfg.onReserve != nil {
			cfg.onReserve(req)
		}
		node.issueTicket(t, w, pub, req)
	})
	mux.HandleFunc("POST /v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		node.incCallCount()
		node.handleSealed(t, cfg, w, r)
	})
	mux.HandleFunc("POST /v1/responses", func(w http.ResponseWriter, r *http.Request) {
		node.incCallCount()
		node.handleSealed(t, cfg, w, r)
	})
	mux.HandleFunc("POST /v1/images/generations", func(w http.ResponseWriter, r *http.Request) {
		node.incCallCount()
		node.handleSealed(t, cfg, w, r)
	})
	mux.HandleFunc("POST /v1/images/edits", func(w http.ResponseWriter, r *http.Request) {
		node.incCallCount()
		node.handleSealed(t, cfg, w, r)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	node.Server = srv
	node.operator = hayai.Operator{
		ID:          nextFakeOperatorID(),
		OwnerAddr:   ownerAddr,
		SigningAddr: signingAddr,
		// Mandatory forward secrecy: the proxy seals only to the operator's
		// ephemeral recipient (there is no anchor). The fake node opens both
		// reserve and inference with node.identity (== ageID), so advertise that
		// identity as the (valid, unexpired) ephemeral so round-trips work.
		EphemeralRecipient:       ageID.Recipient(),
		EphemeralRecipientPubkey: ageID.Recipient().String(),
		EphemeralExpiry:          time.Now().Add(10 * time.Minute).Unix(),
		EphemeralIssuedAt:        time.Now().Unix(),
		TicketSigningKey:         pub,
		BaseURL:                  srv.URL,
		Models:                   []string{"gpt-test"},
		ProtoVersion:             wire.ProtoVersion,
	}
	return node
}

// fakeOperatorIDs hands each newFakeNode a distinct operator id so the
// proxy registry can disambiguate them. The contract uses sequential
// uint64 ids; tests just need uniqueness.
var fakeOperatorIDCounter uint64 // protected by atomic via nextFakeOperatorID

func nextFakeOperatorID() uint64 {
	return atomic.AddUint64(&fakeOperatorIDCounter, 1)
}

func (n *fakeNode) incCallCount() {
	n.mu.Lock()
	n.callCount++
	n.mu.Unlock()
}

func (n *fakeNode) callCountValue() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.callCount
}

func (n *fakeNode) issueTicket(t *testing.T, w http.ResponseWriter, pub ed25519.PublicKey, req ticket.ReserveRequest) {
	t.Helper()
	var k [wire.ResponseKeySize]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	var idRaw [16]byte
	if _, err := rand.Read(idRaw[:]); err != nil {
		t.Fatal(err)
	}
	tid := base64.StdEncoding.EncodeToString(idRaw[:])
	n.mu.Lock()
	n.tickets[tid] = k
	n.mu.Unlock()

	commit := ticket.CommitResponseKey(k)
	tkt := ticket.Ticket{
		TicketID:       tid,
		OperatorID:     n.operator.ID,
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
	if err := tkt.Sign(context.Background(), rawKeyBytesSigner{addr: n.signingAddr, priv: n.signingKey}, n.signingAddr); err != nil {
		t.Fatalf("sign ticket: %v", err)
	}
	// The operator field on the Operator struct is already set (uses the
	// server URL), so the returned ticket will point at itself — nothing
	// to patch up here.
	_ = pub

	// Wrap K_response to the proxy's declared age recipient so the real
	// HTTPReserveClient (under test) can unwrap it. Mirrors what the
	// production node does in node/internal/server/reserve.go.
	recipient, err := age.ParseX25519Recipient(req.ProxyRecipient)
	if err != nil {
		http.Error(w, "bad proxy_recipient: "+err.Error(), http.StatusBadRequest)
		return
	}
	var buf bytes.Buffer
	aw, err := age.Encrypt(&buf, recipient)
	if err != nil {
		t.Fatalf("wrap response key: %v", err)
	}
	if _, err := aw.Write(k[:]); err != nil {
		t.Fatalf("wrap response key: %v", err)
	}
	if err := aw.Close(); err != nil {
		t.Fatalf("wrap response key: %v", err)
	}

	// Seal the whole response to proxy_recipient, as a real 8.0 node does —
	// presigned_open_txn would otherwise show a relay the payer address.
	plaintext, err := json.Marshal(ticket.ReserveResponse{
		Ticket:             tkt,
		WrappedResponseKey: base64.StdEncoding.EncodeToString(buf.Bytes()),
	})
	if err != nil {
		t.Fatalf("marshal reserve response: %v", err)
	}
	sealed, err := wire.SealReserveResponse(plaintext, recipient)
	if err != nil {
		t.Fatalf("seal reserve response: %v", err)
	}
	w.Header().Set("Content-Type", wire.SealedReserveResponseContentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(sealed)
}

// envelopeFields decodes an envelope's top-level JSON keys so a test can assert
// what a byte-transparent relay would be able to read off the wire.
func envelopeFields(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("parse envelope: %v", err)
	}
	return fields
}

func (n *fakeNode) keyFor(ticketID string) ([wire.ResponseKeySize]byte, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	k, ok := n.tickets[ticketID]
	return k, ok
}

func (n *fakeNode) handleSealed(t *testing.T, cfg *nodeConfig, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		t.Errorf("node: read body: %v", err)
		return
	}
	// Since 8.0 the envelope carries only ciphertext — tx id, ticket id, reply-to
	// recipient, and admission tag all ride inside the seal. Decrypting is the
	// node's forced first step, so there is nothing to read before it.
	if fields := envelopeFields(t, raw); len(fields) != 1 || fields["ciphertext"] == nil {
		t.Errorf("node: request envelope fields = %v, want exactly ciphertext", fields)
	}
	dec, err := wire.DecryptRequest(raw, n.identity)
	if err != nil {
		t.Errorf("node: decrypt request: %v", err)
		http.Error(w, "bad env", http.StatusBadRequest)
		return
	}
	txID, ticketID := dec.AlgorandTxID, dec.TicketID

	n.mu.Lock()
	n.lastSealedAlgorandTxID = txID
	n.mu.Unlock()

	k, ok := n.keyFor(ticketID)
	if !ok {
		t.Errorf("node: unknown ticket_id %q", ticketID)
		http.Error(w, "no ticket", http.StatusBadRequest)
		return
	}

	var clientBody []byte
	if !cfg.skipClientBodyDecrypt {
		clientBody = dec.Body
	}

	if cfg.onRequest != nil {
		cfg.onRequest(r, clientBody)
	}

	ephemeral := dec.ReplyToRecipient

	// Extra literal response headers (set before the mode writers finalize
	// headers) — used to prove node-set X-Zs-* metadata never reaches the
	// client (SPEC §5.2 step 4).
	for hk, hv := range cfg.extraRespHeaders {
		w.Header().Set(hk, hv)
	}

	// Build + attach the receipt header BEFORE writeEncryptedBody
	// writes response headers (which finalize them). Only attached on
	// non-stream paths; the stream path appends a sealed receipt frame
	// after the content frames — see writeEncryptedStreamWithReceipt.
	if cfg.buildReceipt != nil && isNonStreamMode(cfg.mode) {
		if r := cfg.buildReceipt(cfg.replyPlaintext); r != nil {
			if r.TicketID == "" {
				r.TicketID = ticketID
			}
			n.attachReceiptHeader(t, w, r, k, ephemeral, txID, ticketID)
		}
	}

	switch cfg.mode {
	case modeInferenceGatewayHTMLError:
		// No response key, non-JSON body, code-less 5xx: a front door, not a node.
		if cfg.gatewayRetryAfter != "" {
			w.Header().Set("Retry-After", cfg.gatewayRetryAfter)
		}
		w.Header().Set("Content-Type", "text/html"+cfg.gatewayCTSuffix)
		w.WriteHeader(http.StatusGatewayTimeout)
		_, _ = w.Write([]byte("<!DOCTYPE html><html><head><title>504 Gateway Timeout</title></head><body>origin unreachable</body></html>"))
	case modeNonStreamEncrypted:
		writeEncryptedBody(t, w, k, cfg.replyPlaintext, ephemeral, txID, ticketID, false, false)
	case modeNonStreamPlaintext200:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(cfg.replyPlaintext)
	case modeNonStreamDefensiveCTMismatch:
		writeEncryptedBody(t, w, k, cfg.replyPlaintext, ephemeral, txID, ticketID, true, false)
	case modeNonStreamTamperedCiphertext:
		writeEncryptedBody(t, w, k, cfg.replyPlaintext, ephemeral, txID, ticketID, false, true)
	case modeNonStreamBadKeyHeader:
		w.Header().Set("Content-Type", wire.EncryptedContentType)
		w.Header().Set(wire.ResponseKeyHeader, "!!!not-b64!!!")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	case modeNonStreamCommitKMismatch:
		// Seal with a freshly generated K instead of the committed one —
		// breaks the proxy's commit_k check.
		var bogus [wire.ResponseKeySize]byte
		_, _ = rand.Read(bogus[:])
		writeEncryptedBody(t, w, bogus, cfg.replyPlaintext, ephemeral, txID, ticketID, false, false)
	case modeNonStreamPreEnvelopeError:
		// Plaintext OpenAI-shaped error, no response key — the proxy's
		// pre-envelope passthrough forwards status + body to the client.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusPaymentRequired)
		_, _ = w.Write([]byte(`{"error":{"message":"ticket expired","type":"invalid_request_error","code":"ticket_invalid"}}`))
	case modeStreamEncrypted:
		writeEncryptedStream(t, w, k, cfg.streamFrames, ephemeral, txID, ticketID, false)
	case modeStreamPlaintext:
		writePlainStream(t, w, cfg.streamFrames)
	case modeStreamMixedEvents:
		writeMixedStream(t, w, k, cfg.streamFrames, ephemeral, txID, ticketID)
	case modeStreamTamperedFrame:
		writeEncryptedStream(t, w, k, cfg.streamFrames, ephemeral, txID, ticketID, true)
	case modeStreamCommitKMismatch:
		// Seal the stream (and wrap the response-key header) with a freshly
		// generated K instead of the committed one — the proxy's stream-setup
		// commit_k check must refuse before pumping any frame.
		var bogus [wire.ResponseKeySize]byte
		_, _ = rand.Read(bogus[:])
		writeEncryptedStream(t, w, bogus, cfg.streamFrames, ephemeral, txID, ticketID, false)
	case modeStreamReceiptDropTail:
		rcpt := n.buildSignedStreamReceipt(t, cfg, ticketID)
		writeEncryptedStreamWithReceipt(t, w, k, cfg.streamFrames, rcpt, ephemeral, txID, ticketID, true, false)
	case modeStreamReceiptTruncated:
		rcpt := n.buildSignedStreamReceipt(t, cfg, ticketID)
		writeEncryptedStreamWithReceipt(t, w, k, cfg.streamFrames, rcpt, ephemeral, txID, ticketID, false, true)
	case modeStreamReceiptIntact:
		rcpt := n.buildSignedStreamReceipt(t, cfg, ticketID)
		writeEncryptedStreamWithReceipt(t, w, k, cfg.streamFrames, rcpt, ephemeral, txID, ticketID, false, false)
	}
}

// writeEncryptedStreamWithReceipt emits the content frames sealed at their true
// indices, then a frame-index-bound zs-receipt frame sealed at index
// len(frames) — mirroring the production node. The two failure toggles model a
// byte-transparent relay corrupting the stream's tail:
//
//   - dropTailContent: the LAST content frame is omitted from the wire (but the
//     receipt is still sealed at index len(frames), as the node generated it).
//     The proxy therefore reaches the receipt with frameIndex == len-1, the AAD
//     frame index disagrees, DecryptSSEDataValue fails, and the receipt is
//     swallowed — runReceiptChecks never runs, so no protest.
//   - omitReceipt: the receipt frame is dropped entirely (truncation before the
//     receipt). runReceiptChecks never runs, so no protest.
//
// Either way [DONE] is always emitted last (it's plaintext, §5.3).
func writeEncryptedStreamWithReceipt(
	t *testing.T,
	w http.ResponseWriter,
	key [wire.ResponseKeySize]byte,
	frames [][]byte,
	receipt *ticket.UsageReceipt,
	ephemeral age.Recipient,
	txID, ticketID string,
	dropTailContent, omitReceipt bool,
) {
	t.Helper()
	var wrapped bytes.Buffer
	wr, err := age.Encrypt(&wrapped, ephemeral)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wr.Write(key[:]); err != nil {
		t.Fatal(err)
	}
	if err := wr.Close(); err != nil {
		t.Fatal(err)
	}
	w.Header().Set(wire.ResponseKeyHeader, base64.StdEncoding.EncodeToString(wrapped.Bytes()))
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)

	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		t.Fatal(err)
	}
	writeFrame := func(event string, index int, plaintext []byte) {
		nonce := make([]byte, wire.NonceSize)
		_, _ = rand.Read(nonce)
		ct := aead.Seal(nil, nonce, plaintext, wire.BuildFrameAAD(txID, ticketID, uint64(index)))
		raw := append(append([]byte(nil), nonce...), ct...)
		_, _ = w.Write([]byte("event: " + event + "\ndata: " + base64.StdEncoding.EncodeToString(raw) + "\n\n"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}

	for i, plaintext := range frames {
		// Drop the tail content frame on the wire — but it still counted toward
		// the node's frame indexing, so the receipt is sealed at index len(frames).
		if dropTailContent && i == len(frames)-1 {
			continue
		}
		writeFrame(wire.StreamEventMarker, i, plaintext)
	}

	if !omitReceipt && receipt != nil {
		rb, err := json.Marshal(receipt)
		if err != nil {
			t.Fatal(err)
		}
		writeFrame(wire.StreamEventReceipt, len(frames), rb)
	}

	_, _ = w.Write([]byte("data: [DONE]\n\n"))
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

func writeEncryptedBody(
	t *testing.T,
	w http.ResponseWriter,
	key [wire.ResponseKeySize]byte,
	plaintext []byte,
	ephemeral age.Recipient,
	txID, ticketID string,
	ctMismatch, tamper bool,
) {
	t.Helper()
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, wire.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	ct := aead.Seal(nil, nonce, plaintext, wire.BuildBodyAAD(txID, ticketID))
	if tamper && len(ct) > 0 {
		ct[0] ^= 0xFF
	}

	env := wire.ResponseEnvelope{
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}
	body, _ := json.Marshal(env)

	var wrapped bytes.Buffer
	wr, err := age.Encrypt(&wrapped, ephemeral)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wr.Write(key[:]); err != nil {
		t.Fatal(err)
	}
	if err := wr.Close(); err != nil {
		t.Fatal(err)
	}

	w.Header().Set(wire.ResponseKeyHeader, base64.StdEncoding.EncodeToString(wrapped.Bytes()))
	if ctMismatch {
		w.Header().Set("Content-Type", "application/json")
	} else {
		w.Header().Set("Content-Type", wire.EncryptedContentType)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func writeEncryptedStream(
	t *testing.T,
	w http.ResponseWriter,
	key [wire.ResponseKeySize]byte,
	frames [][]byte,
	ephemeral age.Recipient,
	txID, ticketID string,
	tamperLast bool,
) {
	t.Helper()
	var wrapped bytes.Buffer
	wr, err := age.Encrypt(&wrapped, ephemeral)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wr.Write(key[:]); err != nil {
		t.Fatal(err)
	}
	if err := wr.Close(); err != nil {
		t.Fatal(err)
	}

	w.Header().Set(wire.ResponseKeyHeader, base64.StdEncoding.EncodeToString(wrapped.Bytes()))
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)

	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		t.Fatal(err)
	}

	for i, plaintext := range frames {
		nonce := make([]byte, wire.NonceSize)
		_, _ = rand.Read(nonce)
		ct := aead.Seal(nil, nonce, plaintext, wire.BuildFrameAAD(txID, ticketID, uint64(i)))
		if tamperLast && i == len(frames)-1 {
			ct[0] ^= 0xFF
		}
		raw := append(append([]byte(nil), nonce...), ct...)
		b64 := base64.StdEncoding.EncodeToString(raw)
		_, _ = w.Write([]byte("event: zs\ndata: " + b64 + "\n\n"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}
	_, _ = w.Write([]byte("data: [DONE]\n\n"))
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

func writePlainStream(t *testing.T, w http.ResponseWriter, frames [][]byte) {
	t.Helper()
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	for _, fr := range frames {
		_, _ = w.Write([]byte("data: "))
		_, _ = w.Write(fr)
		_, _ = w.Write([]byte("\n\n"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}
}

func writeMixedStream(
	t *testing.T,
	w http.ResponseWriter,
	key [wire.ResponseKeySize]byte,
	frames [][]byte,
	ephemeral age.Recipient,
	txID, ticketID string,
) {
	t.Helper()
	var wrapped bytes.Buffer
	wr, _ := age.Encrypt(&wrapped, ephemeral)
	_, _ = wr.Write(key[:])
	_ = wr.Close()
	w.Header().Set(wire.ResponseKeyHeader, base64.StdEncoding.EncodeToString(wrapped.Bytes()))
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)

	aead, _ := chacha20poly1305.New(key[:])
	var frameIndex uint64
	for i, pt := range frames {
		if i%2 == 0 {
			nonce := make([]byte, wire.NonceSize)
			_, _ = rand.Read(nonce)
			ct := aead.Seal(nil, nonce, pt, wire.BuildFrameAAD(txID, ticketID, frameIndex))
			frameIndex++
			b64 := base64.StdEncoding.EncodeToString(append(nonce, ct...))
			_, _ = w.Write([]byte("event: zs\ndata: " + b64 + "\n\n"))
		} else {
			_, _ = w.Write([]byte("event: ping\ndata: "))
			_, _ = w.Write(pt)
			_, _ = w.Write([]byte("\n\n"))
		}
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}
	_, _ = w.Write([]byte("data: [DONE]\n\n"))
}

// setupHayai wires a cfg + Options pair for a test against one or more
// fake nodes. The first node's age identity is also used by proxy-side
// decrypt. All nodes are placed into the static registry.
func setupHayai(t *testing.T, cfg *testCfg, nodes ...*fakeNode) Options {
	t.Helper()
	ops := make([]hayai.Operator, len(nodes))
	for i, n := range nodes {
		ops[i] = n.operator
	}
	registry, err := hayai.NewStaticRegistryProvider(ops)
	if err != nil {
		t.Fatalf("build registry: %v", err)
	}
	cfg.ResolvedOperators = ops
	cfg.Affinity = hayai.AffinityPrefer
	return Options{
		RegistryProvider: registry,
		ReserveClient:    &hayai.HTTPReserveClient{HTTPClient: http.DefaultClient},
		ToolAffinity:     hayai.NewIDAffinity(64, time.Minute, nil),
		ResponseAffinity: hayai.NewIDAffinity(64, time.Minute, nil),
		Wallet: &fakeWallet{
			appCallTxID: "TESTTX",
			groupID:     "TESTGROUP000000000000000000000000000000000000000000000",
		},
		Tokenizer: testTokenizer(),
	}
}

// testTokenizer returns a tokenize.Registry that returns a deterministic
// 8-input / 128-max-output Estimate for "gpt-test" so the sizing tests
// have stable numbers. The default tokenizer (SafeEstimator) handles
// every other model, but tests deliberately don't rely on its exact
// output.
func testTokenizer() *tokenize.Registry {
	reg := tokenize.NewRegistry()
	reg.Register("gpt-test", fakeEstimate{input: 8, maxOut: 128})
	reg.SetDefaultMaxOutput("gpt-test", 128)
	return reg
}

type fakeEstimate struct {
	input  uint64
	maxOut uint64
}

func (f fakeEstimate) Estimate(_ tokenize.Request) (tokenize.Estimate, error) {
	return tokenize.Estimate{InputTokens: f.input, MaxOutputTokens: f.maxOut}, nil
}

func itoa(i int) string {
	// avoid strconv import churn; used only for small Retry-After hints
	if i == 0 {
		return "0"
	}
	var b [11]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}

// clientReq builds an httptest request with a body containing `model:"gpt-test"`.
func clientReq(method, path, body string) *http.Request {
	return httptest.NewRequest(method, path, strings.NewReader(body))
}

// isNonStreamMode reports whether m is one of the non-stream response
// modes — i.e. the harness attaches the receipt on a response header
// rather than as a final SSE frame.
func isNonStreamMode(m nodeMode) bool {
	switch m {
	case modeNonStreamEncrypted,
		modeNonStreamPlaintext200,
		modeNonStreamDefensiveCTMismatch,
		modeNonStreamTamperedCiphertext,
		modeNonStreamBadKeyHeader,
		modeNonStreamCommitKMismatch:
		return true
	}
	return false
}

// attachReceiptHeader signs the given receipt with the fake node's
// signing key and sets the X-Zs-Receipt header. Must be called
// before any other code touches w.Header() (httptest.Recorder
// snapshots headers on first WriteHeader).
// buildSignedStreamReceipt builds the per-stream receipt from cfg.buildReceipt
// (over the flattened content frames), stamps the ticket id, and signs it with
// the node's key — so the proxy's VerifyReceipt reaches the body_hash compare
// (a sig failure would short-circuit before it). Returns nil when no builder is
// configured. Used by the streaming receipt-frame modes.
func (n *fakeNode) buildSignedStreamReceipt(t *testing.T, cfg *nodeConfig, ticketID string) *ticket.UsageReceipt {
	t.Helper()
	if cfg.buildReceipt == nil {
		return nil
	}
	r := cfg.buildReceipt(flattenFrames(cfg.streamFrames))
	if r == nil {
		return nil
	}
	if r.TicketID == "" {
		r.TicketID = ticketID
	}
	signer := rawKeyBytesSigner{addr: n.signingAddr, priv: n.signingKey}
	if err := r.Sign(context.Background(), signer, n.signingAddr); err != nil {
		t.Fatalf("sign stream receipt: %v", err)
	}
	return r
}

// attachReceiptHeader signs the receipt and seals it into X-Zs-Receipt under
// K_response, as a real 8.0 node does — the receipt's ticket_id would otherwise
// let a forwarding relay resolve the payer on chain.
func (n *fakeNode) attachReceiptHeader(t *testing.T, w http.ResponseWriter, r *ticket.UsageReceipt, k [wire.ResponseKeySize]byte, replyTo age.Recipient, txID, ticketID string) {
	t.Helper()
	signer := rawKeyBytesSigner{addr: n.signingAddr, priv: n.signingKey}
	if err := r.Sign(context.Background(), signer, n.signingAddr); err != nil {
		t.Fatalf("sign receipt: %v", err)
	}
	enc, err := r.EncodeReceiptHeader()
	if err != nil {
		t.Fatalf("encode receipt header: %v", err)
	}
	sealer, err := wire.NewResponseSealerWithKey(replyTo, txID, ticketID, k)
	if err != nil {
		t.Fatalf("new sealer: %v", err)
	}
	sealed, err := sealer.SealHeader(wire.SealedHeaderReceipt, []byte(enc))
	if err != nil {
		t.Fatalf("seal receipt header: %v", err)
	}
	w.Header().Set(wire.ReceiptHeader, sealed)
}

// --- tests -----------------------------------------------------------------

func TestDispatchHayai_NonStream_RoundTrip(t *testing.T) {
	expectedReply := []byte(`{"choices":[{"message":{"content":"hello"}}]}`)
	var seenBody []byte
	var seenAuth string
	node := newFakeNode(t, &nodeConfig{
		mode:           modeNonStreamEncrypted,
		replyPlaintext: expectedReply,
		onRequest: func(r *http.Request, b []byte) {
			seenBody = b
			seenAuth = r.Header.Get("Authorization")
		},
	})

	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, node))

	clientBody := `{"model":"gpt-test","stream":false}`
	// The proxy defaults `store: false` when the client omits the field
	// before sealing, so the body the node sees has the field added
	// (sorted into key order by encoding/json's map marshaler). See
	// SPEC.md "Upstream retention: caller-controlled, default off".
	wantNodeBody := `{"model":"gpt-test","store":false,"stream":false}`
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", clientBody))

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Result().StatusCode, w.Body.String())
	}
	if !bytes.Equal(w.Body.Bytes(), expectedReply) {
		t.Errorf("client body = %q, want %q", w.Body.Bytes(), expectedReply)
	}
	if string(seenBody) != wantNodeBody {
		t.Errorf("node saw %q, want %q", seenBody, wantNodeBody)
	}
	// The proxy injects no bearer auth — admission is via the on-chain
	// seal. Assert nothing leaks (neither config-side nor client-side).
	if seenAuth != "" {
		t.Errorf("node auth should be empty, got %q", seenAuth)
	}
	// Reserve + sealed request = 2 calls.
	if node.callCount != 2 {
		t.Errorf("node.callCount = %d, want 2", node.callCount)
	}
}

// TestDispatchHayai_NonStream_StripsProviderPreSeal asserts the caller's
// OpenRouter-style `provider` routing object is removed BEFORE sealing, so it
// never traverses the envelope to the node/upstream — a stray `provider` would
// 422 a strict upstream (vLLM/SGLang pydantic) and leak routing intent. This is
// the end-to-end guard for the inject.DropRoutingPreferences wiring in
// dispatchHayai (the inject function itself is unit-tested in proto). The
// `provider.only` here names the fake node's own operator so the request still
// routes to it; the body the node decrypts must have `provider` gone and
// `store:false` injected — identical to the no-provider round-trip body.
func TestDispatchHayai_NonStream_StripsProviderPreSeal(t *testing.T) {
	expectedReply := []byte(`{"choices":[{"message":{"content":"hi"}}]}`)
	var seenBody []byte
	node := newFakeNode(t, &nodeConfig{
		mode:           modeNonStreamEncrypted,
		replyPlaintext: expectedReply,
		onRequest:      func(_ *http.Request, b []byte) { seenBody = b },
	})

	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, node))

	// provider.only names this node's operator (so routing succeeds) plus an
	// app-side sort — both must vanish from the sealed body.
	clientBody := fmt.Sprintf(
		`{"model":"gpt-test","provider":{"only":["%d"],"sort":"throughput"},"stream":false}`,
		node.operator.ID)
	// After DropRoutingPreferences strips `provider`, DefaultStoreFalse adds
	// store:false; encoding/json re-sorts the map into key order. Byte-identical
	// to the plain round-trip body — proving `provider` left no trace.
	wantNodeBody := `{"model":"gpt-test","store":false,"stream":false}`

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", clientBody))

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Result().StatusCode, w.Body.String())
	}
	if string(seenBody) != wantNodeBody {
		t.Errorf("node saw %q, want %q (provider must be stripped pre-seal)", seenBody, wantNodeBody)
	}
	if bytes.Contains(seenBody, []byte("provider")) {
		t.Errorf("sealed body still contains a `provider` key: %q", seenBody)
	}
}

// TestDispatchHayai_NonStream_StripsPromptCacheKeyPreSeal asserts the caller's
// `prompt_cache_key` is removed BEFORE sealing, so it never reaches a node or
// the upstream. Unlike the `provider` strip above this is not about upstream
// validation — the field is valid OpenAI. It is a privacy control: clients
// derive the value from what does not change across a conversation (Hermes
// Agent: session id + system prompt + tool schemas), so it is stable for a
// whole session and identical whichever operator serves a turn. Operator
// rotation is how a payer's session is kept from any single operator; a
// correlator that survives rotation lets two of them join their views back
// into one session. End-to-end guard for the inject.DropPromptCacheKey wiring
// in dispatchHayai; the inject function itself is unit-tested in proto.
func TestDispatchHayai_NonStream_StripsPromptCacheKeyPreSeal(t *testing.T) {
	expectedReply := []byte(`{"choices":[{"message":{"content":"hi"}}]}`)
	var seenBody []byte
	node := newFakeNode(t, &nodeConfig{
		mode:           modeNonStreamEncrypted,
		replyPlaintext: expectedReply,
		onRequest:      func(_ *http.Request, b []byte) { seenBody = b },
	})

	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, node))

	const cacheKey = "pck_5f3a9c1e7b2d4086"
	clientBody := fmt.Sprintf(`{"model":"gpt-test","prompt_cache_key":%q,"stream":false}`, cacheKey)
	// Byte-identical to the plain round-trip body — proving the key left no trace.
	wantNodeBody := `{"model":"gpt-test","store":false,"stream":false}`

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", clientBody))

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Result().StatusCode, w.Body.String())
	}
	if string(seenBody) != wantNodeBody {
		t.Errorf("node saw %q, want %q (prompt_cache_key must be stripped pre-seal)", seenBody, wantNodeBody)
	}
	// The value itself is the join key, so assert on it directly and not only on
	// the field name: a strip that renamed the field would still leak it.
	if bytes.Contains(seenBody, []byte(cacheKey)) {
		t.Errorf("sealed body still carries the cache key value: %q", seenBody)
	}
}

// TestDispatchHayai_NonStream_PlaintextRefused — when the operator returns
// a 2xx response without sealing it, the proxy treats it as a protocol
// violation and surfaces a 502 rather than passing the plaintext body
// through to the client.
func TestDispatchHayai_NonStream_PlaintextRefused(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{
		mode:           modeNonStreamPlaintext200,
		replyPlaintext: []byte(`{"plain":true}`),
	})
	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, node))

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))
	if w.Result().StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", w.Result().StatusCode)
	}
	if bytes.Contains(w.Body.Bytes(), []byte(`"plain":true`)) {
		t.Errorf("plaintext body leaked through: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "operator_unsealed_response") {
		t.Errorf("expected operator_unsealed_response code: %s", w.Body.String())
	}
}

// TestDispatchHayai_NonStream_DefensiveCTMismatchRefused — when the
// operator sets the response key but writes the body in plaintext, the
// proxy refuses (operator_inconsistent_response).
func TestDispatchHayai_NonStream_DefensiveCTMismatchRefused(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{
		mode:           modeNonStreamDefensiveCTMismatch,
		replyPlaintext: []byte(`{"x":1}`),
	})
	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, node))

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))
	if w.Result().StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", w.Result().StatusCode)
	}
	if !strings.Contains(w.Body.String(), "operator_inconsistent_response") {
		t.Errorf("expected operator_inconsistent_response code: %s", w.Body.String())
	}
}

func TestDispatchHayai_NonStream_TamperedCiphertextFails(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{
		mode:           modeNonStreamTamperedCiphertext,
		replyPlaintext: []byte(`{"x":1}`),
	})
	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, node))

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))
	if w.Result().StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", w.Result().StatusCode)
	}
}

// TestDispatchHayai_NonStream_StripsHayaiHeaders — SPEC §5.2 step 4: the
// client must see NO node-set X-Zs-* header on a sealed success response —
// not the response key, not the receipt, and not the settle group (the
// operator's pre-signed first half). The proxy's own X-Zs usage headers
// are re-added after the strip and are allowed.
func TestDispatchHayai_NonStream_StripsHayaiHeaders(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{
		mode:           modeNonStreamEncrypted,
		replyPlaintext: []byte(`{"x":1}`),
		extraRespHeaders: map[string]string{
			"X-Zs-Settle-Group": "AAAA", // malformed on purpose; must be stripped either way
			"X-Zs-Future-Field": "leak-me",
		},
	})
	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, node))

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))
	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	for _, h := range []string{wire.ResponseKeyHeader, wire.ReceiptHeader, wire.SettleGroupHeader, "X-Zs-Future-Field"} {
		if got := res.Header.Get(h); got != "" {
			t.Errorf("node-set header %s leaked to client: %q", h, got)
		}
	}
}

// TestDispatchHayai_PreEnvelopeError_StripsHayaiHeaders — the plaintext
// error passthrough (status ≥ 400, no response key) forwards the node's
// status + body so the client sees the cause, but node-set X-Zs-*
// headers are stripped there too: a hostile node must not be able to
// stuff metadata past the proxy by riding an error response.
func TestDispatchHayai_PreEnvelopeError_StripsHayaiHeaders(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{
		mode: modeNonStreamPreEnvelopeError,
		extraRespHeaders: map[string]string{
			"X-Zs-Settle-Group": "AAAA",
			"X-Zs-Future-Field": "leak-me",
		},
	})
	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, node))

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))
	res := w.Result()
	if res.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want 402 (error passed through)", res.StatusCode)
	}
	if body := w.Body.String(); !strings.Contains(body, "ticket_invalid") {
		t.Errorf("error body not passed through: %s", body)
	}
	for _, h := range []string{wire.SettleGroupHeader, "X-Zs-Future-Field"} {
		if got := res.Header.Get(h); got != "" {
			t.Errorf("node-set header %s leaked through the error passthrough: %q", h, got)
		}
	}
}

func TestDispatchHayai_NonStream_CommitKMismatchFails(t *testing.T) {
	// Node seals with a fresh K rather than the committed one — proxy
	// must fail closed with a commit_k error.
	node := newFakeNode(t, &nodeConfig{
		mode:           modeNonStreamCommitKMismatch,
		replyPlaintext: []byte(`{"x":1}`),
	})
	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, node))

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))
	if w.Result().StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", w.Result().StatusCode)
	}
}

func TestDispatchHayai_NonStream_BadKeyHeader(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{mode: modeNonStreamBadKeyHeader})
	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, node))

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))
	if w.Result().StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", w.Result().StatusCode)
	}
}

func TestDispatchHayai_Stream_RoundTrip(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{
		mode:         modeStreamEncrypted,
		streamFrames: [][]byte{[]byte(`{"delta":"A"}`), []byte(`{"delta":"B"}`)},
	})
	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, node))

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test","stream":true}`))
	body := w.Body.String()
	if !strings.Contains(body, `{"delta":"A"}`) || !strings.Contains(body, `{"delta":"B"}`) {
		t.Errorf("stream body missing frames: %s", body)
	}
	if !strings.Contains(body, "[DONE]") {
		t.Errorf("stream missing [DONE]: %s", body)
	}
}

// TestDispatchHayai_Stream_CommitKMismatchFails — a node that wraps a
// key other than the reserve-committed one into X-Zs-Response-Key
// must be refused at stream setup (SPEC §3b case (a): key-substitution
// fraud), before a single frame reaches the client. Mirror of the
// non-stream commit_k test.
func TestDispatchHayai_Stream_CommitKMismatchFails(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{
		mode:         modeStreamCommitKMismatch,
		streamFrames: [][]byte{[]byte(`{"delta":"A"}`)},
	})
	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, node))

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test","stream":true}`))
	if w.Result().StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502 (stream_setup refusal)", w.Result().StatusCode)
	}
	if body := w.Body.String(); strings.Contains(body, `{"delta":"A"}`) {
		t.Errorf("plaintext frame leaked through a commit_k-mismatched stream: %s", body)
	}
}

func TestDispatchHayai_Stream_Mixed(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{
		mode:         modeStreamMixedEvents,
		streamFrames: [][]byte{[]byte(`{"delta":"A"}`), []byte(`keep`), []byte(`{"delta":"B"}`)},
	})
	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, node))

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test","stream":true}`))
	body := w.Body.String()
	if !strings.Contains(body, `{"delta":"A"}`) {
		t.Errorf("missing hayai frame A: %s", body)
	}
	if !strings.Contains(body, "event: ping") {
		t.Errorf("missing passthrough ping: %s", body)
	}
}

// TestDispatchHayai_Stream_PlaintextRefused — an operator that opens an
// SSE stream without sealing it is a protocol violation. The proxy
// refuses the stream rather than passing plaintext frames through.
func TestDispatchHayai_Stream_PlaintextRefused(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{
		mode:         modeStreamPlaintext,
		streamFrames: [][]byte{[]byte(`{"delta":"A"}`)},
	})
	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, node))

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test","stream":true}`))
	if w.Result().StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", w.Result().StatusCode)
	}
	if bytes.Contains(w.Body.Bytes(), []byte(`{"delta":"A"}`)) {
		t.Errorf("plaintext frame leaked through: %s", w.Body.String())
	}
}

func TestDispatchHayai_Stream_TamperedFrame(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{
		mode:         modeStreamTamperedFrame,
		streamFrames: [][]byte{[]byte(`{"delta":"A"}`)},
	})
	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, node))

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test","stream":true}`))
	body := w.Body.String()
	// The stream fails mid-flight; the proxy emits an error frame.
	if !strings.Contains(body, "error") {
		t.Errorf("expected error frame, got %s", body)
	}
}

func TestDispatchHayai_MissingModel(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{}`)})
	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, node))

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"messages":[]}`))
	if w.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Result().StatusCode)
	}
}

// An operator that stays busy for the whole budget still terminates in
// 503 operators_busy + Retry-After. The busy re-sweep bounds the waiting; it
// must not turn a persistently-full pool into a hang or a different code.
// fastSweeps zeroes the waits — without it the clamped Retry-After makes this
// sleep for the whole busyRetryBudget.
func TestDispatchHayai_AllBusy_503(t *testing.T) {
	busy := newFakeNode(t, &nodeConfig{mode: modeReserveBusy, retryAfterSeconds: 5})
	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, busy))
	s.fastSweeps = true

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))
	if w.Result().StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Result().StatusCode)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("missing Retry-After on 503")
	}
	if body := w.Body.String(); !strings.Contains(body, "operators_busy") {
		t.Errorf("body = %s; want operators_busy", body)
	}
	// The re-sweep must actually have been attempted. Literal 3 rather than
	// 1+busyRetries on purpose: derived from the constant, this assertion would
	// stay green if busyRetries were set to 0, which is exactly the regression it
	// exists to catch. Update it deliberately if the budget changes.
	if got := busy.callCountValue(); got != 3 {
		t.Errorf("reserve calls = %d, want 3 (one pass plus two busy re-sweeps)", got)
	}
}

// The point of the busy re-sweep: a node whose queue drains while the caller
// waits serves the request instead of handing back a 503. This is the GoLand
// burst case — a client fans out more concurrent requests than the pool has
// ticket slots, and everything past the first few used to fail instantly.
func TestDispatchHayai_BusyThenServes_Succeeds(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{
		mode:               modeNonStreamEncrypted,
		replyPlaintext:     []byte(`{"choices":[{"message":{"content":"ok"}}]}`),
		busyThenServeAfter: 1,
		retryAfterSeconds:  1,
	})
	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, node))
	s.fastSweeps = true

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200 — a drained queue must be retried, not refused",
			w.Result().StatusCode, w.Body.String())
	}
}

// A refusal that waiting cannot fix must still end the sweeps immediately, even
// when another candidate was merely busy. Otherwise the busy carve-out would
// re-ask questions whose answers are fixed, and the terminal error would arrive
// a budget later than it should.
func TestDispatchHayai_BusyPlusSizeRejection_NoBusyResweep(t *testing.T) {
	busy := newFakeNode(t, &nodeConfig{mode: modeReserveBusy, retryAfterSeconds: 1})
	sized := newFakeNode(t, &nodeConfig{mode: modeReserveSizeRejected})
	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, busy, sized))
	s.fastSweeps = true

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))
	// A sizing rejection is the actionable terminal — it outranks the busy 503.
	if w.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s; want 400", w.Result().StatusCode, w.Body.String())
	}
	// One pass only: each node saw exactly one reserve.
	if got := busy.callCountValue(); got != 1 {
		t.Errorf("busy node reserve calls = %d, want 1 — a hard refusal must not earn a busy re-sweep", got)
	}
}

// Every operator behind a broken gateway must surface as
// `operators_unreachable`, NOT `operators_busy`. The distinction is the point:
// the pool is not at capacity, it is unreachable, and telling a client "all
// eligible operators are at capacity; retry after the hint" during a fleet-wide
// node update invites an immediate retry storm against a condition that clears
// on its own.
func TestDispatchHayai_AllGatewayErrors_OperatorsUnreachable(t *testing.T) {
	gwA := newFakeNode(t, &nodeConfig{mode: modeReserveGatewayError})
	gwB := newFakeNode(t, &nodeConfig{mode: modeReserveGatewayError})
	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, gwA, gwB))
	// Shrink the budget: the production schedule deliberately sleeps for up to a
	// minute before giving up, which is correct in production and useless here.
	// The budget is shared across the WHOLE request, so this also bounds how far
	// down the candidate list the retries get — 1.5s buys each of the two nodes
	// its first retry (inner delays 0 / 500ms) and stops before the 1500ms third.
	s.retryBudget = 1500 * time.Millisecond

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))

	if w.Result().StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d body=%s; want 503", w.Result().StatusCode, w.Body.String())
	}
	if got := w.Body.String(); !strings.Contains(got, "operators_unreachable") {
		t.Errorf("body = %s; want the operators_unreachable code", got)
	}
	if strings.Contains(w.Body.String(), "operators_busy") {
		t.Error("gateway failures were laundered into operators_busy")
	}
	if got := w.Header().Get("Retry-After"); got != "30" {
		t.Errorf("Retry-After = %q on operators_unreachable, want 30", got)
	}
	// Both candidates were tried, and the pool as a whole saw more attempts than
	// candidates — i.e. at least one 504 was actually retried rather than the
	// operator being abandoned on first sight. Asserted in aggregate because the
	// budget is shared: whichever candidate is visited first consumes more of it,
	// so a per-node floor would encode the schedule's arithmetic into the test.
	a, b := gwA.callCountValue(), gwB.callCountValue()
	if a < 1 || b < 1 {
		t.Errorf("call counts A=%d B=%d; both candidates should have been tried", a, b)
	}
	if a+b < 3 {
		t.Errorf("total reserve attempts = %d across 2 candidates; want >2, proving a 504 was retried", a+b)
	}
}

// Regression for the review's proxy-F1: a considered refusal in a LATER sweep
// must NOT be reported as `operators_unreachable`. transientExhausted is set on
// sweep 0 (pure weather) and used to be sticky, so a sweep-1 refusal wrongly
// surfaced "none refused the request". Here the node 504s on sweep 0 then
// returns provider_unavailable, and the terminal must be operators_busy, not
// operators_unreachable. Needs ≥2 sweeps, so fastSweeps zeros the backoff (the
// original test used a 1.5s budget that never reached sweep 1, which is why the
// bug shipped green).
func TestDispatchHayai_LateSweepRefusal_NotOperatorsUnreachable(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{gatewayThenRefuseAfter: 1})
	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, node))
	s.fastSweeps = true
	s.retryBudget = 300 * time.Millisecond // small enough that sweep 0 makes one attempt

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))

	if w.Result().StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d body=%s; want 503", w.Result().StatusCode, w.Body.String())
	}
	body := w.Body.String()
	if strings.Contains(body, "operators_unreachable") || strings.Contains(body, "none refused") {
		t.Errorf("a later-sweep refusal was reported as operators_unreachable: %s", body)
	}
	if !strings.Contains(body, "operators_busy") {
		t.Errorf("body = %s; want operators_busy once an operator refused", body)
	}
	// It must actually have taken ≥2 sweeps to be a valid regression (sweep 0
	// weather + sweep 1 refusal), i.e. more than one reserve call.
	if node.callCountValue() < 2 {
		t.Errorf("reserve calls = %d; the multi-sweep path wasn't exercised", node.callCountValue())
	}
}

// A considered refusal must stop the retrying immediately: re-asking produces
// the same answer, and the caller deserves the real reason rather than a minute
// of pointless waiting followed by a vaguer one.
func TestDispatchHayai_SizeRejection_NotRetriedAsTransient(t *testing.T) {
	sized := newFakeNode(t, &nodeConfig{mode: modeReserveSizeRejected})
	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, sized))

	start := time.Now()
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))

	if w.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s; want 400", w.Result().StatusCode, w.Body.String())
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("took %v; a terminal refusal must not spend the transient retry budget", elapsed)
	}
	if n := sized.callCountValue(); n != 1 {
		t.Errorf("reserve calls = %d, want 1 (no retry against a considered refusal)", n)
	}
}

// TestDispatchHayai_NoEphemeral_503 confirms mandatory forward secrecy fails
// closed: when no candidate has a valid ephemeral recipient (there is no anchor
// fallback), every candidate is skipped and the proxy returns 503
// no_ephemeral_capacity — the FS analog of no_tee_capacity — without contacting
// a node.
func TestDispatchHayai_NoEphemeral_503(t *testing.T) {
	opA := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{}`)})
	opB := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{}`)})
	// Strip the ephemeral newFakeNode advertises so neither has a seal target.
	for _, op := range []*fakeNode{opA, opB} {
		op.operator.EphemeralRecipient = nil
		op.operator.EphemeralRecipientPubkey = ""
		op.operator.EphemeralExpiry = 0
		op.operator.EphemeralIssuedAt = 0
	}
	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, opA, opB))

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))
	if w.Result().StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d body=%s; want 503", w.Result().StatusCode, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"no_ephemeral_capacity"`) {
		t.Errorf("body missing no_ephemeral_capacity code: %s", w.Body.String())
	}
	// Fail closed: the proxy must NOT have contacted either node at all
	// (errNoEphemeral is raised before the reserve POST).
	if opA.callCount != 0 || opB.callCount != 0 {
		t.Errorf("reserved against a node despite no ephemeral: opA=%d opB=%d", opA.callCount, opB.callCount)
	}
	if w.Header().Get("Retry-After") != "" {
		t.Errorf("Retry-After should not be set on no_ephemeral_capacity; got %q", w.Header().Get("Retry-After"))
	}
}

// healingRegistry wraps a StaticRegistryProvider but models a successful live
// re-probe: ReprobeEphemeral returns heal(op) instead of the static no-op, so a
// test can simulate a node that has come back up (with a fresh ephemeral) since
// the cached snapshot was taken. calls counts the re-probes so the test can
// assert the self-heal fired exactly as expected.
type healingRegistry struct {
	*hayai.StaticRegistryProvider
	heal  func(hayai.Operator) (hayai.Operator, bool)
	calls int
}

func (h *healingRegistry) ReprobeEphemeral(_ context.Context, op hayai.Operator) (hayai.Operator, bool) {
	h.calls++
	return h.heal(op)
}

// TestDispatchHayai_NoEphemeral_ReprobeSelfHeals confirms the dispatch self-heal:
// a candidate skipped at reserve for a stale/missing ephemeral (the proxy's
// cached snapshot lost it while the node was briefly down) is re-probed live and
// the reserve is retried against the refreshed operator — turning a request that
// would otherwise 503 no_ephemeral_capacity (until the next scheduled refresh)
// into a clean 200.
func TestDispatchHayai_NoEphemeral_ReprobeSelfHeals(t *testing.T) {
	op := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{"ok":true}`)})
	// Capture the healthy operator (its ephemeral is the node's own identity, so
	// the retried reserve + inference open cleanly) BEFORE stripping the cache.
	healed := op.operator
	// Stale snapshot: strip the cached ephemeral so the first reserve attempt
	// fails closed (errNoEphemeral) without contacting the node.
	op.operator.EphemeralRecipient = nil
	op.operator.EphemeralRecipientPubkey = ""
	op.operator.EphemeralExpiry = 0
	op.operator.EphemeralIssuedAt = 0

	cfg := testConfig()
	opts := setupHayai(t, cfg, op)
	static, err := hayai.NewStaticRegistryProvider(cfg.ResolvedOperators)
	if err != nil {
		t.Fatal(err)
	}
	reg := &healingRegistry{
		StaticRegistryProvider: static,
		heal:                   func(hayai.Operator) (hayai.Operator, bool) { return healed, true },
	}
	opts.RegistryProvider = reg
	s := testServer(cfg, opts)

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200 after self-heal re-probe", w.Result().StatusCode, w.Body.String())
	}
	if reg.calls != 1 {
		t.Errorf("ReprobeEphemeral calls = %d, want 1 (re-probe the one stale candidate once)", reg.calls)
	}
	if op.callCount == 0 {
		t.Error("self-heal did not reach the node on the retried reserve")
	}
}

// TestDispatchHayai_BadReserveEnvelope_ReprobeSelfHeals confirms the dispatch
// self-heal for the *stale-but-unexpired* ephemeral case: unlike the
// errNoEphemeral path (cached key already expired → Reserve never contacts the
// node), here the proxy holds an unexpired-but-defunct recipient, seals the
// reserve to it, and the node 400s with bad_reserve_envelope (it can't age-open
// the body — its in-memory ephemeral rotated/regenerated on a restart inside the
// advertised validity window). Before the fix the proxy surfaced this as a
// misleading 503 operators_busy; now it re-probes the candidate live and retries
// the reserve against the refreshed ephemeral, turning it into a clean 200.
func TestDispatchHayai_BadReserveEnvelope_ReprobeSelfHeals(t *testing.T) {
	op := newFakeNode(t, &nodeConfig{
		mode:                         modeNonStreamEncrypted,
		replyPlaintext:               []byte(`{"ok":true}`),
		reserveBadEnvelopeOnOpenFail: true,
	})
	// Capture the healthy operator (its ephemeral is the node's own identity, so
	// the retried reserve + inference open cleanly) BEFORE swapping the cache to a
	// defunct recipient.
	healed := op.operator
	// Stale-but-unexpired snapshot: a valid, unexpired recipient the node cannot
	// age-open (a different identity than node.identity). The first reserve seals
	// to it and the node returns bad_reserve_envelope — distinct from the
	// errNoEphemeral case, where the cached key would be nil/expired and Reserve
	// would never reach the node.
	wrong, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate wrong ephemeral identity: %v", err)
	}
	op.operator.EphemeralRecipient = wrong.Recipient()
	op.operator.EphemeralRecipientPubkey = wrong.Recipient().String()
	op.operator.EphemeralExpiry = time.Now().Add(10 * time.Minute).Unix()
	op.operator.EphemeralIssuedAt = time.Now().Unix()

	cfg := testConfig()
	opts := setupHayai(t, cfg, op)
	static, err := hayai.NewStaticRegistryProvider(cfg.ResolvedOperators)
	if err != nil {
		t.Fatal(err)
	}
	reg := &healingRegistry{
		StaticRegistryProvider: static,
		heal:                   func(hayai.Operator) (hayai.Operator, bool) { return healed, true },
	}
	opts.RegistryProvider = reg
	s := testServer(cfg, opts)

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200 after bad_reserve_envelope self-heal re-probe", w.Result().StatusCode, w.Body.String())
	}
	if reg.calls != 1 {
		t.Errorf("ReprobeEphemeral calls = %d, want 1 (re-probe the one stale candidate once)", reg.calls)
	}
}

// TestDispatchHayai_ValidEphemeral_RoundTrip confirms that with an operator
// advertising a valid, unexpired ephemeral recipient, the request seals to the
// ephemeral and completes end-to-end under mandatory forward secrecy. The
// ephemeral here is the node's own age identity (so the fake node can open it
// with node.identity); the round-trip success proves SealRecipient sealed to
// it.
func TestDispatchHayai_ValidEphemeral_RoundTrip(t *testing.T) {
	op := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{"ok":true}`)})
	// newFakeNode already advertises the node's identity as the ephemeral
	// recipient; restate it here to make the intent explicit.
	op.operator.EphemeralRecipient = op.identity.Recipient()
	op.operator.EphemeralRecipientPubkey = op.identity.Recipient().String()
	op.operator.EphemeralExpiry = time.Now().Add(10 * time.Minute).Unix()

	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, op))

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200 (require_fs + valid ephemeral)", w.Result().StatusCode, w.Body.String())
	}
	if op.callCount == 0 {
		t.Error("require_fs with a valid ephemeral did not reach the node")
	}
}

// When every surviving candidate refuses at reserve with
// context_length_exceeded, the proxy must surface a 400 with an
// actionable per-operator breakdown — not the generic 503
// operators_busy that masks the real cause. This is the regression
// test for the "max-tokens 20000 against a 65k-context model returns
// operators_busy" symptom: operators advertised no per-model
// max_output cap (so the proxy pre-filter passed them) but the node-
// side reserve handler enforced a stricter limit and returned
// context_length_exceeded.
func TestDispatchHayai_AllReserveSizeRejected_400(t *testing.T) {
	opA := newFakeNode(t, &nodeConfig{mode: modeReserveSizeRejected})
	opB := newFakeNode(t, &nodeConfig{mode: modeReserveSizeRejected})
	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, opA, opB))

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))
	if w.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s; want 400", w.Result().StatusCode, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, `"context_length_exceeded"`) {
		t.Errorf("body missing context_length_exceeded code: %s", body)
	}
	wantA := fmt.Sprintf("op %d:", opA.operator.ID)
	wantB := fmt.Sprintf("op %d:", opB.operator.ID)
	if !strings.Contains(body, wantA) || !strings.Contains(body, wantB) {
		t.Errorf("body missing per-operator breakdown for both operators: %s", body)
	}
	if !strings.Contains(body, "max_output_tokens exceeds this operator") {
		t.Errorf("body did not surface node's underlying error message: %s", body)
	}
	if w.Header().Get("Retry-After") != "" {
		t.Errorf("Retry-After should not be set on 400 sizing path; got %q", w.Header().Get("Retry-After"))
	}
}

// Regression guard: an empty-Models node is excluded from candidates
// (ServesModel no longer wildcards on Reachable), so a reachable-but-empty node
// can't mask another operator's sizing rejection. opWild has empty Models +
// Reachable=true (previously a "serves everything" wildcard that would capture
// every routing decision); opReal advertises the requested model with a
// per-model max_output_tokens cap the request blows past. opWild is now dropped
// before dispatch, so the loop sees only opReal's SizingMiss and the client gets
// 400 context_length_exceeded with opReal's per-model cap surfaced — never
// opWild's operators_busy.
func TestDispatchHayai_EmptyModelsNodeExcluded_SizingMissSurfaces(t *testing.T) {
	opWild := newFakeNode(t, &nodeConfig{mode: modeReserveBusy, retryAfterSeconds: 5})
	opReal := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{}`)})
	cfg := testConfig()
	opts := setupHayai(t, cfg, opWild, opReal)

	ops := cfg.ResolvedOperators
	// opWild: empty Models + Reachable=true. Previously a "serves everything"
	// wildcard; now excluded from candidates entirely, so its modeReserveBusy
	// state can't mask opReal's sizing miss.
	ops[0].Models = nil
	ops[0].Reachable = true
	ops[0].ModelCapacities = nil
	// opReal: advertises gpt-test with a max-output cap below the
	// test tokenizer's 128-token request, so it fails Fits() and
	// lands in SizingMisses.
	ops[1].ModelCapacities = map[string]hayai.ModelCapacity{"gpt-test": {MaxOutputTokens: 64}}
	cfg.ResolvedOperators = ops
	registry, err := hayai.NewStaticRegistryProvider(ops)
	if err != nil {
		t.Fatal(err)
	}
	opts.RegistryProvider = registry

	s := testServer(cfg, opts)
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))

	if w.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s; want 400 (sizing miss surfaced)", w.Result().StatusCode, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, `"context_length_exceeded"`) {
		t.Errorf("body missing context_length_exceeded: %s", body)
	}
	wantReal := fmt.Sprintf("op %d: max_output_tokens=64 (over by 64)", opReal.operator.ID)
	if !strings.Contains(body, wantReal) {
		t.Errorf("body missing real operator's sizing miss %q: %s", wantReal, body)
	}
}

// Mixed busy + sizing rejections must still prefer the actionable
// 400 — a sizing failure is a hard request-shape problem (no amount
// of waiting will fix it), so the proxy reports
// context_length_exceeded rather than masking it as operators_busy.
func TestDispatchHayai_MixedBusyAndSizeRejected_PrefersSizing400(t *testing.T) {
	opBusy := newFakeNode(t, &nodeConfig{mode: modeReserveBusy, retryAfterSeconds: 5})
	opSize := newFakeNode(t, &nodeConfig{mode: modeReserveSizeRejected})
	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, opBusy, opSize))

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))
	if w.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s; want 400 (sizing wins)", w.Result().StatusCode, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, `"context_length_exceeded"`) {
		t.Errorf("body missing context_length_exceeded: %s", body)
	}
	// The sizing-refusing operator must appear in the breakdown; the
	// busy one is not relevant to the 400 (it didn't reject for size).
	wantSize := fmt.Sprintf("op %d:", opSize.operator.ID)
	if !strings.Contains(body, wantSize) {
		t.Errorf("body missing sizing-rejecting operator %q: %s", wantSize, body)
	}
}

func TestDispatchHayai_BusyThenHealthy_Fallthrough(t *testing.T) {
	busy := newFakeNode(t, &nodeConfig{mode: modeReserveBusy})
	healthy := newFakeNode(t, &nodeConfig{
		mode:           modeNonStreamEncrypted,
		replyPlaintext: []byte(`{"ok":true}`),
	})
	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, busy, healthy))

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Result().StatusCode, w.Body.String())
	}
	if !bytes.Equal(w.Body.Bytes(), []byte(`{"ok":true}`)) {
		t.Errorf("body = %s", w.Body.String())
	}
	if busy.callCount != 1 {
		t.Errorf("busy.callCount = %d, want 1 (reserve only)", busy.callCount)
	}
	if healthy.callCount != 2 {
		t.Errorf("healthy.callCount = %d, want 2 (reserve + seal)", healthy.callCount)
	}
}

func TestDispatchHayai_Affinity_PrefersRecordedOperator(t *testing.T) {
	// Two healthy operators. First request we'll route to operator A by
	// virtue of registry order; A's reply carries a tool_call id "call-1".
	// Second request's messages reference call-1 → proxy must route to A
	// again even though B is listed first in the (reshuffled) registry.
	opAReply := []byte(`{"choices":[{"message":{"tool_calls":[{"id":"call-1","function":{"name":"f"}}]}}]}`)
	opBReply := []byte(`{"choices":[{"message":{"content":"B saw this"}}]}`)

	opA := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: opAReply})
	opB := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: opBReply})

	cfg := testConfig()
	opts := setupHayai(t, cfg, opA, opB)
	s := testServer(cfg, opts)

	// Turn 1: goes to opA (first in registry).
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("turn 1 status = %d body=%s", w.Result().StatusCode, w.Body.String())
	}
	if !bytes.Equal(w.Body.Bytes(), opAReply) {
		t.Fatalf("turn 1 body = %s", w.Body.String())
	}
	aCalls := opA.callCount
	bCalls := opB.callCount

	// Turn 2: continuation carrying tool_call_id → affinity must pin to A.
	// We simulate the registry preferring B this time by hand-building a
	// reordered registry. In practice the affinity cache overrides order.
	cfg.ResolvedOperators = []hayai.Operator{opB.operator, opA.operator}
	registry, err := hayai.NewStaticRegistryProvider(cfg.ResolvedOperators)
	if err != nil {
		t.Fatal(err)
	}
	s.registryProvider = registry

	turn2Body := `{"model":"gpt-test","messages":[{"role":"tool","tool_call_id":"call-1","content":"result"}]}`
	w2 := httptest.NewRecorder()
	s.mux.ServeHTTP(w2, clientReq(http.MethodPost, "/v1/chat/completions", turn2Body))
	if w2.Result().StatusCode != http.StatusOK {
		t.Fatalf("turn 2 status = %d body=%s", w2.Result().StatusCode, w2.Body.String())
	}
	if !bytes.Equal(w2.Body.Bytes(), opAReply) {
		t.Fatalf("affinity didn't route to A; got %s", w2.Body.String())
	}
	if opA.callCount <= aCalls {
		t.Errorf("opA.callCount did not increase (%d → %d)", aCalls, opA.callCount)
	}
	if opB.callCount != bCalls {
		t.Errorf("opB.callCount changed (%d → %d); affinity should have skipped B", bCalls, opB.callCount)
	}
}

func TestDispatchHayai_ResponseID_NonStream_PinsToOriginalOperator(t *testing.T) {
	// Two operators serve /v1/responses. Turn 1 lands on opA (first in
	// registry) and its reply carries response_id "resp_X". Turn 2 sends
	// previous_response_id="resp_X" — even after we reorder the registry
	// to put opB first, the pin must still route to opA.
	opAReply := []byte(`{"id":"resp_X","object":"response","output":[{"type":"message","content":"A"}]}`)
	opBReply := []byte(`{"id":"resp_Y","object":"response","output":[{"type":"message","content":"B"}]}`)

	opA := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: opAReply})
	opB := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: opBReply})

	cfg := testConfig()
	opts := setupHayai(t, cfg, opA, opB)
	s := testServer(cfg, opts)

	// Turn 1 → opA records resp_X.
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/responses", `{"model":"gpt-test","input":[]}`))
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("turn 1 status = %d body=%s", w.Result().StatusCode, w.Body.String())
	}
	if !bytes.Equal(w.Body.Bytes(), opAReply) {
		t.Fatalf("turn 1 body = %s", w.Body.String())
	}
	aCalls := opA.callCount
	bCalls := opB.callCount

	// Reorder registry so opB is preferred by default; the response-id
	// pin must override that preference.
	cfg.ResolvedOperators = []hayai.Operator{opB.operator, opA.operator}
	registry, err := hayai.NewStaticRegistryProvider(cfg.ResolvedOperators)
	if err != nil {
		t.Fatal(err)
	}
	s.registryProvider = registry

	w2 := httptest.NewRecorder()
	s.mux.ServeHTTP(w2, clientReq(http.MethodPost, "/v1/responses",
		`{"model":"gpt-test","previous_response_id":"resp_X","input":[]}`))
	if w2.Result().StatusCode != http.StatusOK {
		t.Fatalf("turn 2 status = %d body=%s", w2.Result().StatusCode, w2.Body.String())
	}
	if !bytes.Equal(w2.Body.Bytes(), opAReply) {
		t.Fatalf("response_id pin didn't route to opA; got %s", w2.Body.String())
	}
	if opA.callCount <= aCalls {
		t.Errorf("opA.callCount did not increase (%d → %d)", aCalls, opA.callCount)
	}
	if opB.callCount != bCalls {
		t.Errorf("opB.callCount changed (%d → %d); response_id pin should have skipped B", bCalls, opB.callCount)
	}
}

func TestDispatchHayai_ResponseID_StrictRegardlessOfPolicy(t *testing.T) {
	// Even with affinity_policy: none, a previous_response_id pin must
	// be honored — falling through to a different operator would 404 at
	// upstream OpenAI (the session lives in opA's account).
	opAReply := []byte(`{"id":"resp_X","object":"response"}`)
	opBReply := []byte(`{"id":"resp_Y","object":"response"}`)

	opA := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: opAReply})
	opB := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: opBReply})

	cfg := testConfig()
	opts := setupHayai(t, cfg, opA, opB)
	s := testServer(cfg, opts)

	// Turn 1: warm the cache.
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/responses", `{"model":"gpt-test","input":[]}`))
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("turn 1 status = %d body=%s", w.Result().StatusCode, w.Body.String())
	}
	bBeforeTurn2 := opB.callCount

	// Now disable affinity and reorder so opB is preferred.
	s.cfg.Affinity = hayai.AffinityNone
	cfg.ResolvedOperators = []hayai.Operator{opB.operator, opA.operator}
	registry, err := hayai.NewStaticRegistryProvider(cfg.ResolvedOperators)
	if err != nil {
		t.Fatal(err)
	}
	s.registryProvider = registry

	w2 := httptest.NewRecorder()
	s.mux.ServeHTTP(w2, clientReq(http.MethodPost, "/v1/responses",
		`{"model":"gpt-test","previous_response_id":"resp_X","input":[]}`))
	if w2.Result().StatusCode != http.StatusOK {
		t.Fatalf("turn 2 status = %d body=%s", w2.Result().StatusCode, w2.Body.String())
	}
	if !bytes.Equal(w2.Body.Bytes(), opAReply) {
		t.Fatalf("strict response_id pin should have routed to A even with policy=none; got %s", w2.Body.String())
	}
	if opB.callCount != bBeforeTurn2 {
		t.Errorf("opB was called despite response_id pin (%d → %d)", bBeforeTurn2, opB.callCount)
	}
}

func TestDispatchHayai_ResponseID_UnknownPin_400(t *testing.T) {
	// Cache miss on previous_response_id: block with a 400 explaining
	// the conversation can't be routed, rather than silently picking a
	// random operator that would 404 at upstream.
	op := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{"id":"resp_X","object":"response"}`)})
	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, op))

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/responses",
		`{"model":"gpt-test","previous_response_id":"resp_unknown","input":[]}`))
	if w.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Result().StatusCode, w.Body.String())
	}
	if op.callCount != 0 {
		t.Errorf("operator should not have been called (cache miss must block before reserve); calls=%d", op.callCount)
	}
	if !strings.Contains(w.Body.String(), "previous_response_id") {
		t.Errorf("error body should mention previous_response_id; got %s", w.Body.String())
	}
}

func TestDispatchHayai_ResponseID_OperatorUnregistered_400(t *testing.T) {
	// Realistic operational scenario: turn 1 lands on opA and records
	// resp_X. Between turns, opA deregisters (registry now contains only
	// opB). The responseAffinity cache still holds resp_X → opA.ID, so
	// resolveResponseIDPin's Resolve() call fails — the pin must surface
	// as a 400 with the "no longer registered" message rather than
	// silently relocating the session to opB (which would 404 upstream).
	opAReply := []byte(`{"id":"resp_X","object":"response"}`)
	opBReply := []byte(`{"id":"resp_Y","object":"response"}`)

	opA := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: opAReply})
	opB := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: opBReply})

	cfg := testConfig()
	opts := setupHayai(t, cfg, opA, opB)
	s := testServer(cfg, opts)

	// Turn 1 → opA records resp_X.
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/responses", `{"model":"gpt-test","input":[]}`))
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("turn 1 status = %d body=%s", w.Result().StatusCode, w.Body.String())
	}
	aCalls := opA.callCount
	bCalls := opB.callCount

	// Drop opA from the registry — opB is the only remaining operator.
	cfg.ResolvedOperators = []hayai.Operator{opB.operator}
	registry, err := hayai.NewStaticRegistryProvider(cfg.ResolvedOperators)
	if err != nil {
		t.Fatal(err)
	}
	s.registryProvider = registry

	w2 := httptest.NewRecorder()
	s.mux.ServeHTTP(w2, clientReq(http.MethodPost, "/v1/responses",
		`{"model":"gpt-test","previous_response_id":"resp_X","input":[]}`))
	if w2.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("turn 2 status = %d, want 400; body=%s", w2.Result().StatusCode, w2.Body.String())
	}
	body := w2.Body.String()
	if !strings.Contains(body, "no longer registered") {
		t.Errorf("error body missing 'no longer registered'; got %s", body)
	}
	if !strings.Contains(body, fmt.Sprintf("operator %d", opA.operator.ID)) {
		t.Errorf("error body should name the unregistered operator id %d; got %s", opA.operator.ID, body)
	}
	if opA.callCount != aCalls {
		t.Errorf("opA called after deregistration (%d → %d); pin must block before reserve", aCalls, opA.callCount)
	}
	if opB.callCount != bCalls {
		t.Errorf("opB called despite pin failure (%d → %d); strict pin must not fall through", bCalls, opB.callCount)
	}
}

func TestDispatchHayai_ResponseID_Stream_RecordsFromCreatedEvent(t *testing.T) {
	// Streaming path: response.created arrives as the first hayai-sealed
	// frame and must record the response_id for the next turn's pin.
	opA := newFakeNode(t, &nodeConfig{
		mode: modeStreamEncrypted,
		streamFrames: [][]byte{
			[]byte(`{"type":"response.created","response":{"id":"resp_S","object":"response"}}`),
			[]byte(`{"type":"response.output_text.delta","delta":"hi"}`),
			[]byte(`{"type":"response.completed","response":{"id":"resp_S"}}`),
		},
	})
	opB := newFakeNode(t, &nodeConfig{
		mode:         modeStreamEncrypted,
		streamFrames: [][]byte{[]byte(`{"type":"response.created","response":{"id":"resp_OTHER"}}`)},
	})

	cfg := testConfig()
	opts := setupHayai(t, cfg, opA, opB)
	s := testServer(cfg, opts)

	// Turn 1: stream from opA, proxy must record resp_S.
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/responses",
		`{"model":"gpt-test","stream":true,"input":[]}`))
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("turn 1 status = %d body=%s", w.Result().StatusCode, w.Body.String())
	}
	bCalls := opB.callCount

	// Reorder so opB is preferred; the resp_S pin must still send turn 2 to opA.
	cfg.ResolvedOperators = []hayai.Operator{opB.operator, opA.operator}
	registry, err := hayai.NewStaticRegistryProvider(cfg.ResolvedOperators)
	if err != nil {
		t.Fatal(err)
	}
	s.registryProvider = registry

	w2 := httptest.NewRecorder()
	s.mux.ServeHTTP(w2, clientReq(http.MethodPost, "/v1/responses",
		`{"model":"gpt-test","stream":true,"previous_response_id":"resp_S","input":[]}`))
	if w2.Result().StatusCode != http.StatusOK {
		t.Fatalf("turn 2 status = %d body=%s", w2.Result().StatusCode, w2.Body.String())
	}
	if !strings.Contains(w2.Body.String(), `resp_S`) {
		t.Errorf("turn 2 should have streamed opA's frames containing resp_S; got %s", w2.Body.String())
	}
	if opB.callCount != bCalls {
		t.Errorf("opB called despite response_id pin (%d → %d)", bCalls, opB.callCount)
	}
}

func TestDispatchHayai_WalletOpenError(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{}`)})
	cfg := testConfig()
	opts := setupHayai(t, cfg, node)
	s := testServer(cfg, opts)
	s.wallet = &fakeWallet{err: errors.New("algod down")}

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))
	if w.Result().StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", w.Result().StatusCode)
	}
}

func TestDispatchHayai_Sizing_SkipsOversizeOperator(t *testing.T) {
	// Two operators; A has a tiny declared capacity, B has a huge one.
	// Tokenizer produces more than A's window, so A must be skipped
	// without a reserve call and B must serve the request.
	opA := newFakeNode(t, &nodeConfig{mode: modeReserveBusy}) // would 429 if called
	opB := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{"ok":true}`)})

	cfg := testConfig()
	opts := setupHayai(t, cfg, opA, opB)

	// Point A at a tiny context window for gpt-test so the filter drops it.
	ops := cfg.ResolvedOperators
	ops[0].ModelCapacities = map[string]hayai.ModelCapacity{"gpt-test": {ContextWindow: 4}}
	cfg.ResolvedOperators = ops
	registry, err := hayai.NewStaticRegistryProvider(ops)
	if err != nil {
		t.Fatal(err)
	}
	opts.RegistryProvider = registry

	s := testServer(cfg, opts)
	// Default test tokenizer returns input=8 max_out=128 → 136 > 4. A fails Fits.
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Result().StatusCode, w.Body.String())
	}
	if opA.callCount != 0 {
		t.Errorf("opA should have been skipped by sizing filter, got %d calls", opA.callCount)
	}
	if opB.callCount == 0 {
		t.Error("opB was never called")
	}
}

func TestDispatchHayai_Sizing_NoFit_400ContextLengthExceeded(t *testing.T) {
	// Only operator has a capacity too small for the request → 400.
	op := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{}`)})
	cfg := testConfig()
	opts := setupHayai(t, cfg, op)

	ops := cfg.ResolvedOperators
	ops[0].ModelCapacities = map[string]hayai.ModelCapacity{"gpt-test": {ContextWindow: 4}}
	cfg.ResolvedOperators = ops
	registry, err := hayai.NewStaticRegistryProvider(ops)
	if err != nil {
		t.Fatal(err)
	}
	opts.RegistryProvider = registry

	s := testServer(cfg, opts)
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))
	if w.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s; want 400", w.Result().StatusCode, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, `"context_length_exceeded"`) {
		t.Errorf("body missing context_length_exceeded: %s", body)
	}
	// The diagnostic should call out THIS operator and report the
	// context-window gap. Default test tokenizer returns input=8
	// max_out=128, so the request needs 136 against a window of 4.
	wantOpLine := fmt.Sprintf("op %d: context_window=4 (request needs 136)", op.operator.ID)
	if !strings.Contains(body, wantOpLine) {
		t.Errorf("body missing per-operator diagnostic %q: %s", wantOpLine, body)
	}
	if op.callCount != 0 {
		t.Errorf("no reserve should have fired, got %d calls", op.callCount)
	}
}

// TestDispatchHayai_Sizing_NoFit_PerOperatorReasons verifies the
// no-fit diagnostic identifies each rejected operator individually and
// reports the *correct* limit being violated. opA fails on context
// window, opB fails on the standalone max_output_tokens cap — distinct
// branches in describeMiss. Both reasons must appear.
func TestDispatchHayai_Sizing_NoFit_PerOperatorReasons(t *testing.T) {
	opA := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{}`)})
	opB := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{}`)})
	cfg := testConfig()
	opts := setupHayai(t, cfg, opA, opB)

	ops := cfg.ResolvedOperators
	// A: input+max_output=136 > ContextWindow=4 → context-window miss.
	ops[0].ModelCapacities = map[string]hayai.ModelCapacity{"gpt-test": {ContextWindow: 4}}
	// B: ContextWindow=0 (unbounded) but MaxOutputTokens=64 < 128 →
	// max_output_tokens miss. Distinct branch in describeMiss.
	ops[1].ModelCapacities = map[string]hayai.ModelCapacity{"gpt-test": {MaxOutputTokens: 64}}
	cfg.ResolvedOperators = ops
	registry, err := hayai.NewStaticRegistryProvider(ops)
	if err != nil {
		t.Fatal(err)
	}
	opts.RegistryProvider = registry

	s := testServer(cfg, opts)
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))
	if w.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s; want 400", w.Result().StatusCode, w.Body.String())
	}
	body := w.Body.String()
	wantA := fmt.Sprintf("op %d: context_window=4 (request needs 136)", opA.operator.ID)
	wantB := fmt.Sprintf("op %d: max_output_tokens=64 (over by 64)", opB.operator.ID)
	if !strings.Contains(body, wantA) {
		t.Errorf("body missing opA diagnostic %q: %s", wantA, body)
	}
	if !strings.Contains(body, wantB) {
		t.Errorf("body missing opB diagnostic %q: %s", wantB, body)
	}
	if opA.callCount != 0 || opB.callCount != 0 {
		t.Errorf("no reserve should have fired, got A=%d B=%d", opA.callCount, opB.callCount)
	}
}

// TestDescribeMiss covers the pure formatter that picks which limit
// each operator was rejected against. The branches mirror Fits's check
// order — context-window first, max_output cap second — and a 0 limit
// must not be blamed as the cause (Fits treats 0 as unbounded).
//
// The gap math reads the miss's own EffectiveMaxOutput, never
// req.MaxOutputTokens — so req carries a deliberately large flat display
// ceiling (a flat display ceiling the caller never sent) that must NOT
// leak into any message; a regression to req.MaxOutputTokens would blow every
// expected number up by ~32k.
func TestDescribeMiss(t *testing.T) {
	req := hayai.SizingRequest{Model: "m", InputTokens: 8, MaxOutputTokens: 32000, DeriveMaxOutput: true}
	cases := []struct {
		name string
		miss sizingMiss
		want string
	}{
		{
			name: "context_window violation",
			miss: sizingMiss{OperatorID: 7, ContextWindow: 4, EffectiveMaxOutput: 128},
			want: "op 7: context_window=4 (request needs 136)",
		},
		{
			name: "max_output_tokens violation",
			miss: sizingMiss{OperatorID: 11, MaxOutputTokens: 64, EffectiveMaxOutput: 128},
			want: "op 11: max_output_tokens=64 (over by 64)",
		},
		{
			name: "context_window prioritised over max_output",
			miss: sizingMiss{OperatorID: 13, ContextWindow: 4, MaxOutputTokens: 64, EffectiveMaxOutput: 128},
			want: "op 13: context_window=4 (request needs 136)",
		},
		{
			// Derive mode: the operator was fit-checked against its own derived
			// ctx/4=1024 slice, not the flat 32000. The reported gap must be the
			// derived one (8+1024=1032), proving the flat display ceiling is ignored.
			name: "derive mode uses per-operator effective, not flat ceiling",
			miss: sizingMiss{OperatorID: 15, ContextWindow: 512, EffectiveMaxOutput: 1024},
			want: "op 15: context_window=512 (request needs 1032)",
		},
		{
			name: "all-zero (defensive fallback)",
			miss: sizingMiss{OperatorID: 17},
			want: "op 17: declared capacity does not fit (context_window=0, max_output_tokens=0)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := describeMiss(tc.miss, req); got != tc.want {
				t.Errorf("describeMiss = %q\nwant %q", got, tc.want)
			}
		})
	}
}

// TestNoFitMaxOutputLabel pins the no-fit header's max_output rendering: the
// concrete flat value when the caller specified one, and a non-numeric
// "derived-per-operator" marker in derive mode (where there is no single
// request-level ceiling — each operator got its own, shown in the breakdown).
func TestNoFitMaxOutputLabel(t *testing.T) {
	if got := noFitMaxOutputLabel(hayai.SizingRequest{MaxOutputTokens: 4096}); got != "4096" {
		t.Errorf("flat label = %q, want 4096", got)
	}
	derive := hayai.SizingRequest{MaxOutputTokens: 32000, DeriveMaxOutput: true}
	if got := noFitMaxOutputLabel(derive); got != "derived-per-operator" {
		t.Errorf("derive label = %q, want derived-per-operator", got)
	}
	// The flat display ceiling must not leak into the header.
	head := formatNoFitMessage("m", hayai.SizingRequest{Model: "m", InputTokens: 8, MaxOutputTokens: 32000, DeriveMaxOutput: true}, nil)
	if strings.Contains(head, "32000") {
		t.Errorf("derive-mode header leaked the flat ceiling: %q", head)
	}
}

// TestFormatNoFitMessage_NoMissesPreservesOriginalLine pins the
// backwards-compatible behaviour: when no per-operator misses were
// captured (e.g. the registry is empty for some other reason and we
// somehow reach this branch), the message body is exactly the original
// "no operator serves" line. Clients that string-match on that prefix
// keep working.
func TestFormatNoFitMessage_NoMissesPreservesOriginalLine(t *testing.T) {
	req := hayai.SizingRequest{Model: "m", InputTokens: 5, MaxOutputTokens: 7}
	got := formatNoFitMessage("m", req, nil)
	want := "no operator serves m with input_tokens=5 max_output_tokens=7"
	if got != want {
		t.Errorf("formatNoFitMessage = %q\nwant %q", got, want)
	}
}

func TestDispatchHayai_Sizing_StrictAffinity_TargetMisfit_400(t *testing.T) {
	// Two operators: opA (strict-affinity target) has a tiny context
	// window; opB has unbounded capacity and WOULD fit. Under strict
	// affinity we must fail with a distinct message that names the
	// affinity constraint rather than misrepresent the failure as a
	// pool-wide context_length_exceeded — the client needs to know
	// switching affinity_policy is an option.
	opA := newFakeNode(t, &nodeConfig{mode: modeReserveBusy}) // would 429 if called
	opB := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{}`)})

	cfg := testConfig()
	opts := setupHayai(t, cfg, opA, opB)
	cfg.Affinity = hayai.AffinityStrict

	// opA is tiny, opB is unbounded (nil ModelCapacities).
	ops := cfg.ResolvedOperators
	ops[0].ModelCapacities = map[string]hayai.ModelCapacity{"gpt-test": {ContextWindow: 4}}
	cfg.ResolvedOperators = ops
	registry, err := hayai.NewStaticRegistryProvider(ops)
	if err != nil {
		t.Fatal(err)
	}
	opts.RegistryProvider = registry

	// Pin the tool_call_id to opA so affinity picks it.
	opts.ToolAffinity.Record(opA.operator.ID, opA.operator.NodeID, []string{"call-strict-1"})

	s := testServer(cfg, opts)
	reqBody := `{"model":"gpt-test","messages":[{"role":"tool","tool_call_id":"call-strict-1","content":"x"}]}`
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", reqBody))

	if w.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s; want 400", w.Result().StatusCode, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "strict affinity target") {
		t.Errorf("body missing strict-affinity-specific message: %s", w.Body.String())
	}
	if opA.callCount != 0 {
		t.Errorf("opA should not have been reserved, got %d", opA.callCount)
	}
	if opB.callCount != 0 {
		t.Errorf("opB should not have been reserved under strict affinity, got %d", opB.callCount)
	}
}

func TestDispatchHayai_UnknownModelGetsSafeEstimate(t *testing.T) {
	// Escrow + signed receipt make per-model tokenizer accuracy
	// optional: any model gets the safe upper-bound estimator and goes
	// through. The only remaining hard failure is "no max output anywhere"
	// (covered by TestDispatchHayai_MissingMaxOutput_400).
	node := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{"ok":true}`)})
	cfg := testConfig()
	opts := setupHayai(t, cfg, node)
	s := testServer(cfg, opts)

	w := httptest.NewRecorder()
	// Empty registry: no per-model override AND no max-output default.
	// Body supplies max_tokens so dispatch can produce a complete estimate.
	s.tokenizer = tokenize.NewRegistry()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions",
		`{"model":"gpt-test","max_tokens":64}`))
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Result().StatusCode, w.Body.String())
	}
}

func TestDispatchHayai_MissingMaxOutput_400(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{}`)})
	cfg := testConfig()
	opts := setupHayai(t, cfg, node)
	s := testServer(cfg, opts)

	// Register a tokenizer whose Estimate returns 0 for max out, and no default.
	reg := tokenize.NewRegistry()
	reg.Register("gpt-test", fakeEstimate{input: 10, maxOut: 0})
	s.tokenizer = reg

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))
	if w.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s; want 400", w.Result().StatusCode, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"max_output_required"`) {
		t.Errorf("body missing max_output_required: %s", w.Body.String())
	}
}

func TestDispatchHayai_RegistryError(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{}`)})
	cfg := testConfig()
	opts := setupHayai(t, cfg, node)
	opts.RegistryProvider = errRegistry{err: errors.New("registry down")}
	s := testServer(cfg, opts)

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))
	if w.Result().StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", w.Result().StatusCode)
	}
}

// Sanity: the proxy sent a *correctly shaped* ticket_id AAD — we can
// decrypt the body the node sealed with BuildBodyAAD(tx, ticket_id).
func TestDispatchHayai_AADIncludesTicketID(t *testing.T) {
	reply := []byte(`{"ok":true}`)
	node := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: reply})
	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, node))

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Result().StatusCode, w.Body.String())
	}
	if !bytes.Equal(w.Body.Bytes(), reply) {
		t.Errorf("body = %s", w.Body.String())
	}
}

// --- cross-check: commit_k derivation uses sha256 of the raw key -------

func TestCommitKDerivation_MatchesSha256(t *testing.T) {
	var k [wire.ResponseKeySize]byte
	_, _ = rand.Read(k[:])
	want := sha256.Sum256(k[:])
	got := ticket.CommitResponseKey(k)
	if got != want {
		t.Fatal("CommitResponseKey != sha256(k)")
	}
}

// suppress unused-import warnings when the file is edited mid-slice
var _ = context.Background

// --- wallet payment path ----------------------------------------------------

// fakeWallet implements WalletOpener on
// client so dispatch tests can assert the payment path without
// wiring a real algod + escrow client. Records each Open invocation
// and returns a deterministic handle so the test can assert which
// value ends up in the envelope's AlgorandTxID: the app-call txid
// (the real one), not the group id.
type fakeWallet struct {
	appCallTxID string
	groupID     string
	openCalls   int
	lastOp      hayai.Operator
	lastTID     string
	err         error
}

func (f *fakeWallet) PayerAddr() string {
	return "TESTPAYERADDRESSXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXAAAAAA"
}

func (f *fakeWallet) Open(_ context.Context, ticket *ticket.Ticket, op hayai.Operator, _ []types.SignedTxn) (*hayai.OpenHandle, error) {
	f.openCalls++
	f.lastOp = op
	f.lastTID = ticket.TicketID
	if f.err != nil {
		return nil, f.err
	}
	return &hayai.OpenHandle{
		AppCallTxID: f.appCallTxID,
		GroupID:     f.groupID,
		TicketID:    ticket.TicketID,
		Operator:    op,
		MaxPrice:    ticket.MaxPrice,
	}, nil
}

func TestDispatchHayai_WalletPath_ThreadsAppCallTxIDIntoEnvelope(t *testing.T) {
	reply := []byte(`{"ok":true}`)
	node := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: reply})
	cfg := testConfig()
	opts := setupHayai(t, cfg, node)
	s := testServer(cfg, opts)

	// Swap in the fake wallet — dispatch should prefer it over the
	// stub txid provider for the envelope's AlgorandTxID, and it must
	// send the app-call txid (NOT the group id — that's retained for
	// audit only).
	fw := &fakeWallet{
		appCallTxID: "APPCALLTXID00000000000000000000000000000000000000000",
		groupID:     "WALLETGROUPID0000000000000000000000000000000000000000",
	}
	s.wallet = fw

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Result().StatusCode, w.Body.String())
	}
	if fw.openCalls != 1 {
		t.Errorf("wallet.Open calls = %d, want 1", fw.openCalls)
	}
	if node.lastSealedAlgorandTxID != fw.appCallTxID {
		t.Errorf("envelope AlgorandTxID = %q, want app-call txid %q", node.lastSealedAlgorandTxID, fw.appCallTxID)
	}
	if node.lastSealedAlgorandTxID == fw.groupID {
		t.Errorf("envelope AlgorandTxID should be the app-call txid, not the group id %q", fw.groupID)
	}
	if fw.lastOp.OwnerAddr == "" {
		t.Error("wallet did not receive operator in Open call")
	}
}

func TestDispatchHayai_WalletPath_OpenFailure_502(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{}`)})
	cfg := testConfig()
	opts := setupHayai(t, cfg, node)
	s := testServer(cfg, opts)

	s.wallet = &fakeWallet{err: errors.New("algod unreachable")}

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))

	if w.Result().StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d body=%s; want 502", w.Result().StatusCode, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"wallet_open"`) {
		t.Errorf("body missing wallet_open code: %s", w.Body.String())
	}
	// Reserve did fire; sealed request did NOT — node should only see
	// the reserve call. callCount = 1.
	if node.callCount != 1 {
		t.Errorf("node.callCount = %d, want 1 (reserve only)", node.callCount)
	}
}

// --- receipt verification ---------------------------------------------------

// TestDispatchHayai_Receipt_NonStream_HappyPath: node attaches a
// valid receipt; proxy verifies it and logs "receipt verified" at
// debug. The response still flows normally and the receipt header is
// stripped from the client-visible response (it's internal audit
// metadata).
func TestDispatchHayai_Receipt_NonStream_HappyPath(t *testing.T) {
	reply := []byte(`{"choices":[{"message":{"content":"hi"}}]}`)
	node := newFakeNode(t, &nodeConfig{
		mode:           modeNonStreamEncrypted,
		replyPlaintext: reply,
		buildReceipt: func(plaintext []byte) *ticket.UsageReceipt {
			r := &ticket.UsageReceipt{
				TicketID:          "", // filled in by the harness from the envelope
				ActualInputCount:  8,
				ActualOutputCount: 3,
				AmountCharged:     8*2 + 3*5,
			}
			r.SetBodyHashBytes(wire.BodyHashOfBody(plaintext))
			return r
		},
	})
	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, node))

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Result().StatusCode, w.Body.String())
	}
	if !bytes.Equal(w.Body.Bytes(), reply) {
		t.Errorf("body = %s", w.Body.String())
	}
	// X-Zs-Receipt must be stripped from the client-visible response.
	if got := w.Header().Get(wire.ReceiptHeader); got != "" {
		t.Errorf("receipt header leaked to client: %q", got)
	}
	// The payer's report of the verified charge, from the receipt above.
	for h, want := range map[string]string{
		"X-Zs-Inference-Amount":    "31",
		"X-Zs-Actual-Input-Count":  "8",
		"X-Zs-Actual-Output-Count": "3",
		"X-Zs-Operator-Id":         fmt.Sprint(node.operator.ID),
	} {
		if got := w.Header().Get(h); got != want {
			t.Errorf("%s = %q, want %q", h, got, want)
		}
	}
	// The node's Content-Length measured the sealed envelope, not the
	// plaintext written here.
	if got := w.Header().Get("Content-Length"); got != "" {
		t.Errorf("Content-Length %q passed through from the sealed reply", got)
	}
}

// The streaming twin of TestDispatchHayai_NonStream_TamperedCiphertextFails: a
// stream request the node answers with a sealed non-SSE body still fails
// closed when that body won't open.
func TestDispatchHayai_Stream_NonSSETamperedCiphertextFails(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{
		mode:           modeNonStreamTamperedCiphertext,
		replyPlaintext: []byte(`{"x":1}`),
	})
	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, node))

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test","stream":true}`))
	if w.Result().StatusCode != http.StatusBadGateway || !strings.Contains(w.Body.String(), `"response_handler"`) {
		t.Errorf("status = %d body=%s, want 502 response_handler", w.Result().StatusCode, w.Body.String())
	}
}

// TestDispatchHayai_Receipt_BodyHashMismatch_DrivesProtest: with a
// wallet wired up (escrow mode), a body_hash mismatch fires the
// Protest path. The fake wallet returns a detached OpenHandle whose
// Protest method is guarded and returns an error — so the dispatch
// logs "protest failed", proving the hook is reached. The important
// assertion: the protest log line is present (regardless of whether
// the submission would succeed in a real-algod setup).
func TestDispatchHayai_Receipt_BodyHashMismatch_DrivesProtest(t *testing.T) {
	reply := []byte(`{"choices":[{"message":{"content":"actual"}}]}`)
	node := newFakeNode(t, &nodeConfig{
		mode:           modeNonStreamEncrypted,
		replyPlaintext: reply,
		buildReceipt: func(plaintext []byte) *ticket.UsageReceipt {
			r := &ticket.UsageReceipt{
				ActualInputCount:  8,
				ActualOutputCount: 3,
				AmountCharged:     100,
				Sig:               base64.StdEncoding.EncodeToString(make([]byte, 64)), // placeholder; verify fails at body_hash first
			}
			r.SetBodyHashBytes(wire.BodyHashOfBody([]byte("fake content")))
			return r
		},
	})
	cfg := testConfig()
	opts := setupHayai(t, cfg, node)

	var logBuf bytes.Buffer
	s := New(&cfg.Config, capturingLogger(&logBuf), nil, nil, opts)
	// Inject the fake wallet so the receipt path runs through the
	// "wallet is present, drive Protest" branch.
	s.wallet = &fakeWallet{
		appCallTxID: "APPCALLTXID00000000000000000000000000000000000000000",
		groupID:     "WALLETGROUPID0000000000000000000000000000000000000000",
	}

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Result().StatusCode, w.Body.String())
	}
	// The protest submit runs after the response; wait for its log line.
	if err := s.WaitSettles(context.Background()); err != nil {
		t.Fatalf("WaitSettles: %v", err)
	}

	logs := logBuf.String()
	if !strings.Contains(logs, "receipt verification failed") {
		t.Errorf("expected receipt verification log; got: %s", logs)
	}
	// Proof the Protest hook fired — either failed (detached handle)
	// or submitted. Either way, the log line proves we reached the
	// ReceiptViolationBodyHash branch.
	if !strings.Contains(logs, "protest failed") && !strings.Contains(logs, "protest submitted") {
		t.Errorf("expected protest hook to fire; got: %s", logs)
	}
}

// TestDispatchHayai_Receipt_BodyHashMismatch_LoggedAsViolation: the
// node attaches a receipt whose body_hash doesn't match what the
// proxy decrypts. Until step 8 wires escrow.protest, the violation
// is recorded via a log line — assert that line fires.
func TestDispatchHayai_Receipt_BodyHashMismatch_LoggedAsViolation(t *testing.T) {
	reply := []byte(`{"choices":[{"message":{"content":"actual"}}]}`)
	node := newFakeNode(t, &nodeConfig{
		mode:           modeNonStreamEncrypted,
		replyPlaintext: reply,
		buildReceipt: func(plaintext []byte) *ticket.UsageReceipt {
			r := &ticket.UsageReceipt{
				ActualInputCount:  8,
				ActualOutputCount: 3,
				AmountCharged:     100,
			}
			// Hash over DIFFERENT plaintext — this is the dispute
			// trigger that drives escrow.protest in step 8.
			r.SetBodyHashBytes(wire.BodyHashOfBody([]byte("fake content")))
			return r
		},
	})
	cfg := testConfig()
	opts := setupHayai(t, cfg, node)

	var logBuf bytes.Buffer
	s := New(&cfg.Config, capturingLogger(&logBuf), nil, nil, opts)

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))

	// Response still flows — the receipt mismatch is recorded evidence,
	// not a reason to withhold content from the client.
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Result().StatusCode, w.Body.String())
	}
	// The protest submit runs after the response and writes to the same log.
	if err := s.WaitSettles(context.Background()); err != nil {
		t.Fatalf("WaitSettles: %v", err)
	}

	logs := logBuf.String()
	if !strings.Contains(logs, "receipt verification failed") {
		t.Errorf("expected 'receipt verification failed' in logs, got: %s", logs)
	}
	if !strings.Contains(logs, "violation=body_hash") {
		t.Errorf("expected violation=body_hash in logs, got: %s", logs)
	}
}

// TestDispatchHayai_Receipt_AmountExceedsMaxPrice: node signs a
// receipt with amount_charged > ticket.max_price. Proxy logs
// violation=amount (ReceiptViolationAmount); the response still goes
// through because payout clamping happens in the contract.
func TestDispatchHayai_Receipt_AmountExceedsMaxPrice(t *testing.T) {
	reply := []byte(`{"ok":true}`)
	node := newFakeNode(t, &nodeConfig{
		mode:           modeNonStreamEncrypted,
		replyPlaintext: reply,
		buildReceipt: func(plaintext []byte) *ticket.UsageReceipt {
			r := &ticket.UsageReceipt{
				ActualInputCount:  8,
				ActualOutputCount: 128,
				AmountCharged:     1_000_000_000, // astronomically above any plausible ticket.max_price
			}
			r.SetBodyHashBytes(wire.BodyHashOfBody(plaintext))
			return r
		},
	})
	cfg := testConfig()
	opts := setupHayai(t, cfg, node)

	var logBuf bytes.Buffer
	s := New(&cfg.Config, capturingLogger(&logBuf), nil, nil, opts)

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Result().StatusCode, w.Body.String())
	}
	logs := logBuf.String()
	if !strings.Contains(logs, "receipt verification failed") {
		t.Errorf("expected failure log, got: %s", logs)
	}
	if !strings.Contains(logs, "violation=amount") {
		t.Errorf("expected violation=amount in logs, got: %s", logs)
	}
}

// TestDispatchHayai_Receipt_MissingHeader_Tolerated: the node omits
// X-Zs-Receipt entirely (e.g. older build). Proxy accepts the
// response and does not log a failure — missing receipts are
// tolerated.
func TestDispatchHayai_Receipt_MissingHeader_Tolerated(t *testing.T) {
	reply := []byte(`{"ok":true}`)
	node := newFakeNode(t, &nodeConfig{
		mode:           modeNonStreamEncrypted,
		replyPlaintext: reply,
		// no buildReceipt
	})
	cfg := testConfig()
	opts := setupHayai(t, cfg, node)

	var logBuf bytes.Buffer
	s := New(&cfg.Config, capturingLogger(&logBuf), nil, nil, opts)

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Result().StatusCode, w.Body.String())
	}
	if strings.Contains(logBuf.String(), "receipt verification failed") {
		t.Errorf("missing receipt should not log verification failure: %s", logBuf.String())
	}
}

// TestProtestReasonForViolation pins the wire mapping between the
// proxy's local violation enum and the on-chain reason code carried on
// protest(). Today only BodyHash actually reaches Protest at the call
// site, but the mapper has cases for the others so future protest
// triggers slot in without a wire-format break.
func TestProtestReasonForViolation(t *testing.T) {
	cases := []struct {
		violation hayai.ReceiptViolation
		want      escrow.ProtestReasonCode
	}{
		{hayai.ReceiptViolationBodyHash, escrow.ProtestReasonBodyHash},
		{hayai.ReceiptViolationSig, escrow.ProtestReasonReceiptSig},
		{hayai.ReceiptViolationAmount, escrow.ProtestReasonAmount},
		{hayai.ReceiptOK, escrow.ProtestReasonUnspecified},
	}
	for _, tc := range cases {
		if got := protestReasonForViolation(tc.violation); got != tc.want {
			t.Errorf("protestReasonForViolation(%s) = %d, want %d",
				tc.violation, got, tc.want)
		}
	}
}

// The exhaustive frame-shape table now lives in proto/testdata/stream_vectors.json
// (wire.ClassifyStreamFrame), shared with the reference client so the two can't
// drift on which frames end a stream. What stays proxy-local — and is what this
// asserts — is the route-to-vocabulary mapping feeding it: get that wrong and
// every frame classifies against the other endpoint's needles, so the drain
// never arms and every ticket loses its in-band settle.
func TestStreamAPIForEndpoint(t *testing.T) {
	cases := []struct {
		endpoint string
		want     wire.StreamAPI
	}{
		{endpointResponses, wire.StreamAPIResponses},
		{endpointChatCompletions, wire.StreamAPIChat},
		// /v1/completions is emulated by re-dispatching as chat
		// (completions.go), so it never reaches here as its own endpoint —
		// anything unrecognized must still fall back to chat, not silently
		// classify against the Responses needles.
		{endpointImages, wire.StreamAPIChat},
		{"", wire.StreamAPIChat},
	}
	for _, tc := range cases {
		if got := streamAPIFor(tc.endpoint); got != tc.want {
			t.Errorf("streamAPIFor(%q) = %q, want %q", tc.endpoint, got, tc.want)
		}
	}
	// The two properties the drain depends on, asserted through the proxy's own
	// mapping rather than proto's: a terminal chat chunk and an error frame both
	// arm it, a mid-stream delta does not.
	armed := func(frame, endpoint string) bool {
		return wire.ClassifyStreamFrame([]byte(frame), streamAPIFor(endpoint)).Terminal
	}
	if !armed(`{"choices":[{"finish_reason":"stop"}]}`, endpointChatCompletions) {
		t.Error("chat stop chunk did not arm the tail drain")
	}
	if !armed(`{"error":{"message":"invalid temperature: only 1 is allowed for this model"}}`, endpointChatCompletions) {
		t.Error("chat error frame did not arm the tail drain — the ticket would lapse unverified")
	}
	if !armed(`{"type":"error","message":"boom"}`, endpointResponses) {
		t.Error("responses error event did not arm the tail drain — the ticket would lapse unverified")
	}
	if armed(`{"choices":[{"delta":{"content":"hi"}}]}`, endpointChatCompletions) {
		t.Error("mid-stream delta armed the tail drain; disconnects would stop cancelling promptly")
	}
}

// responseErrorMessage surfaces operator/upstream error envelopes (logged at
// WARN, default-on) while NOT mistaking normal chunks — including the empty-
// choices usage chunk or a delta that merely mentions "error" — for errors.
func TestResponseErrorMessage(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantOK  bool
		wantMsg string
	}{
		{"error envelope", `{"error":{"message":"tools must not be empty","type":"server_error"}}`, true, "tools must not be empty"},
		{"error without message", `{"error":{"code":"x"}}`, true, `{"code":"x"}`},
		{"content chunk", `{"id":"c","object":"chat.completion.chunk","choices":[{"delta":{"content":"hi"}}]}`, false, ""},
		{"usage chunk empty choices", `{"choices":[],"usage":{"prompt_tokens":3}}`, false, ""},
		{"delta mentioning error", `{"choices":[{"delta":{"content":"the error was X"}}]}`, false, ""},
		{"error null", `{"error":null,"choices":[]}`, false, ""},
		{"no error key", `{"id":"c","choices":[{"delta":{}}]}`, false, ""},
		{"not json", `nope`, false, ""},
		// Responses-API error event: no top-level "error" object at all, so the
		// chat-shape branch alone reported false and the frame went both
		// unlogged and (via the shared predicate) undrained.
		{"responses error event", `{"type":"error","code":"context_length_exceeded","message":"too long"}`, true, "too long"},
		{"responses error event without message", `{"type":"error","code":"x"}`, true, "error"},
		// response.failed nests its error under "response" — already terminal
		// via the lifecycle needles, and must not match the type discriminator.
		{"responses failed event", `{"type":"response.failed","response":{"error":{"message":"nope"}}}`, false, ""},
		{"responses delta mentioning error", `{"type":"response.output_text.delta","delta":"error"}`, false, ""},
	}
	for _, tc := range cases {
		msg, ok := responseErrorMessage([]byte(tc.in))
		if ok != tc.wantOK {
			t.Errorf("%s: ok = %v, want %v", tc.name, ok, tc.wantOK)
		}
		if ok && msg != tc.wantMsg {
			t.Errorf("%s: msg = %q, want %q", tc.name, msg, tc.wantMsg)
		}
	}
}

// busyCodeOr returns the 429 error.code a fake node should emit, defaulting to
// the one re-askable condition. A literal rather than transient.BusyCodeNoCapacity
// so the fake speaks the wire string and a renamed constant fails the re-sweep tests.
func busyCodeOr(cfg *nodeConfig) string {
	if cfg.busyCode != "" {
		return cfg.busyCode
	}
	return "no_capacity"
}

func busyBody(cfg *nodeConfig) []byte {
	if cfg.busyNoCode {
		return []byte(`{"error":{"message":"busy"}}`)
	}
	return []byte(`{"error":{"message":"busy","code":"` + busyCodeOr(cfg) + `"}}`)
}

// Only a "no_capacity" 429 may be re-asked. The other three the node emits are
// not time-varying, and one of them charges the payer for asking:
// payer_slot_cap calls RecordSlotCapTrip, weight 2 against a 20-point strike
// budget with a 1-minute doubling ban. Re-sweeping it turned one logical request
// into three strikes and earned a real ban on the node we were trying to reach —
// the exact opposite of what the re-sweep is for.
func TestDispatchHayai_BusyNonRetryableCodes_NoResweep(t *testing.T) {
	cases := []struct {
		name   string
		code   string
		noCode bool
	}{
		{name: "payer_slot_cap", code: "payer_slot_cap"},
		{name: "reserve_temporarily_banned", code: "reserve_temporarily_banned"},
		{name: "rate_limited", code: "rate_limited"},
		{name: "unknown_code_fails_closed", code: "some_unknown_future_code"},
		{name: "absent_code_fails_closed", noCode: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfgNode := &nodeConfig{mode: modeReserveBusy, retryAfterSeconds: 1, busyCode: tc.code, busyNoCode: tc.noCode}
			busy := newFakeNode(t, cfgNode)
			cfg := testConfig()
			s := testServer(cfg, setupHayai(t, cfg, busy))
			s.fastSweeps = true

			w := httptest.NewRecorder()
			s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))

			if w.Result().StatusCode != http.StatusServiceUnavailable {
				t.Fatalf("status = %d body=%s; want 503", w.Result().StatusCode, w.Body.String())
			}
			// Exactly ONE reserve: no re-sweep for a non-retryable 429.
			if got := busy.callCountValue(); got != 1 {
				t.Errorf("reserve calls = %d, want 1 — %q must not be re-asked", got, cfgNode.busyCode)
			}
		})
	}
}

// A 429 that carried no Retry-After leaves busyHint at zero while still being a
// capacity answer, so "was anyone busy?" has to be its own signal (anyBusy) —
// every terminal branch that reads it as busyHint == 0 mis-reports. Here one
// candidate has no forward-secrecy ephemeral and the other is at capacity without
// a hint: the truthful answer is operators_busy (the pool is full and a slot frees
// on its own), NOT the hard posture gap no_ephemeral_capacity, which tells a
// client that no operator CAN serve the request. Both outcomes are 503, so the
// code is the whole assertion.
//
// It also settles an internal contradiction: the busy re-sweep's narrow
// disqualifier set is justified by ephemeralMissing being subordinate to busy in
// the ladder, so with busyHint == 0 the proxy would spend the re-sweep budget and
// then return the very error that veto would have short-circuited.
func TestDispatchHayai_HintlessBusyOutranksEphemeralGap(t *testing.T) {
	// retryAfterSeconds: 0 ⇒ the 429 carries no Retry-After, so busyHint stays 0.
	busy := newFakeNode(t, &nodeConfig{mode: modeReserveBusy})
	noEph := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{}`)})
	noEph.operator.EphemeralRecipient = nil
	noEph.operator.EphemeralRecipientPubkey = ""
	noEph.operator.EphemeralExpiry = 0
	noEph.operator.EphemeralIssuedAt = 0

	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, busy, noEph))
	s.fastSweeps = true

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))

	if w.Result().StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d body=%s; want 503", w.Result().StatusCode, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"operators_busy"`) {
		t.Errorf("body = %s; want operators_busy — a hint-less 429 is still a capacity answer", w.Body.String())
	}
	if strings.Contains(w.Body.String(), `"no_ephemeral_capacity"`) {
		t.Errorf("reported a forward-secrecy posture gap while an operator was at capacity: %s", w.Body.String())
	}
	// The re-sweep engaged (busy is re-askable and nothing outranking it refused),
	// which is what makes the ladder's agreement load-bearing rather than academic.
	if got := busy.callCountValue(); got < 2 {
		t.Errorf("reserve calls = %d, want >= 2 — a no_capacity 429 earns a re-sweep", got)
	}
	// Nothing to hint with: the node sent no Retry-After and the proxy must not
	// invent one.
	if got := w.Header().Get("Retry-After"); got != "" {
		t.Errorf("Retry-After = %q, want empty — no operator supplied a hint", got)
	}
}
