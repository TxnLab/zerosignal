/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/wire"
	"github.com/TxnLab/zerosignal/go/zs"
)

// Deliverable 6a: the streaming receipt frame is frame-index-bound (AAD carries
// the running frameIndex), so a byte-transparent relay that drops a tail
// content frame or truncates before the receipt cannot make the proxy run
// runReceiptChecks against a desynced / absent receipt — the body_hash compare
// that drives a protest simply never runs, so an honest target is never
// protested for a relay's transport fault. These tests document that property
// and lock it against a future buildFrameFactory refactor (no behavior
// change). The positive control proves the streaming receipt path actually
// verifies (and protests) when the stream is intact, so the negatives aren't
// vacuous.

// mismatchingReceipt returns a receipt whose body_hash is over unrelated bytes,
// so it WOULD drive a protest if runReceiptChecks ever ran on it.
func mismatchingReceipt(_ []byte) *ticket.UsageReceipt {
	r := &ticket.UsageReceipt{
		ActualInputCount:  8,
		ActualOutputCount: 3,
		AmountCharged:     100,
		// 64-byte placeholder sig: passes the length guard so runReceiptChecks
		// reaches the body_hash compare first (the body_hash violation is what
		// drives Protest; a sig-length failure would short-circuit before it).
		Sig: base64.StdEncoding.EncodeToString(make([]byte, 64)),
	}
	r.SetBodyHashBytes(wire.BodyHashOfBody([]byte("fake content")))
	return r
}

// verifyingReceipt returns a receipt over the content the node sent, which
// the fake node signs, so it passes every check.
func verifyingReceipt(plaintext []byte) *ticket.UsageReceipt {
	r := &ticket.UsageReceipt{ActualInputCount: 8, ActualOutputCount: 3, AmountCharged: 321}
	r.SetBodyHashBytes(wire.BodyHashOfBody(plaintext))
	return r
}

func streamReceiptServer(t *testing.T, mode nodeMode) (*Server, *bytes.Buffer) {
	t.Helper()
	return streamReceiptServerWith(t, mode, mismatchingReceipt)
}

func streamReceiptServerWith(t *testing.T, mode nodeMode, build func([]byte) *ticket.UsageReceipt) (*Server, *bytes.Buffer) {
	t.Helper()
	node := newFakeNode(t, &nodeConfig{
		mode:         mode,
		streamFrames: [][]byte{[]byte(`{"delta":"A"}`), []byte(`{"delta":"B"}`)},
		buildReceipt: build,
	})
	cfg := testConfig()
	opts := setup(t, cfg, node)
	var logBuf bytes.Buffer
	// A wired wallet makes the protest path reachable, so a fired protest is
	// observable in the logs (the negatives assert it does NOT fire).
	opts.Wallet = &fakeWallet{
		appCallTxID: "APPCALLTXID00000000000000000000000000000000000000000",
		groupID:     "WALLETGROUPID0000000000000000000000000000000000000000",
	}
	s := newServer(&cfg.policy, capturingLogger(&logBuf), nil, nil, opts)
	return s, &logBuf
}

func driveStream(t *testing.T, s *Server) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test","stream":true}`))
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Result().StatusCode, w.Body.String())
	}
	return w
}

// Positive control: with an intact stream the proxy decrypts the receipt,
// runReceiptChecks runs, and the body_hash mismatch drives a protest.
func TestDispatch_Stream_ReceiptIntact_Protests(t *testing.T) {
	s, logBuf := streamReceiptServer(t, modeStreamReceiptIntact)
	driveStream(t, s)
	logs := logBuf.String()
	if !strings.Contains(logs, "receipt verification failed") {
		t.Errorf("intact receipt: expected runReceiptChecks to flag the body_hash mismatch; got: %s", logs)
	}
	if !strings.Contains(logs, "protest failed") && !strings.Contains(logs, "protest submitted") {
		t.Errorf("intact receipt: expected the protest hook to fire; got: %s", logs)
	}
}

// 6a (i): a relay drops the tail content frame → the proxy's frameIndex
// desyncs → the receipt frame fails to decrypt and is swallowed →
// runReceiptChecks never runs → NO protest (the honest target is spared).
func TestDispatch_Stream_RelayDropsTailContent_NoProtest(t *testing.T) {
	s, logBuf := streamReceiptServer(t, modeStreamReceiptDropTail)
	driveStream(t, s)
	logs := logBuf.String()
	// The receipt frame arrived but failed to decrypt at the desynced index.
	if !strings.Contains(logs, "decrypt receipt frame failed") {
		t.Errorf("expected the swallowed-receipt log (index desync); got: %s", logs)
	}
	// The safety property: no verification, no protest.
	if strings.Contains(logs, "receipt verification failed") {
		t.Errorf("receipt was verified despite a dropped content frame: %s", logs)
	}
	if strings.Contains(logs, "protest failed") || strings.Contains(logs, "protest submitted") {
		t.Errorf("protest fired on a swallowed receipt — an honest target would be punished for a relay fault: %s", logs)
	}
}

// 6a (ii): a relay truncates before the receipt frame → no receipt arrives →
// runReceiptChecks never runs → NO protest.
func TestDispatch_Stream_RelayTruncatesBeforeReceipt_NoProtest(t *testing.T) {
	s, logBuf := streamReceiptServer(t, modeStreamReceiptTruncated)
	w := driveStream(t, s)
	logs := logBuf.String()
	if strings.Contains(logs, "decrypt receipt frame failed") {
		t.Errorf("no receipt frame was sent, yet a decrypt was attempted: %s", logs)
	}
	if strings.Contains(logs, "receipt verification failed") {
		t.Errorf("receipt verified despite truncation before the receipt: %s", logs)
	}
	if strings.Contains(logs, "protest failed") || strings.Contains(logs, "protest submitted") {
		t.Errorf("protest fired without a receipt: %s", logs)
	}
	// Content delivered before the truncation still reached the client.
	if !strings.Contains(w.Body.String(), `{"delta":"A"}`) {
		t.Errorf("pre-truncation content frame missing from client stream: %s", w.Body.String())
	}
}

// SPEC § 5.3: content after the receipt is outside its body_hash. The receipt
// settles what it priced and the unpriced frame never reaches the client, but
// the stream does not fail: an honest node writes upstream frames that follow
// [DONE] after its receipt.
func TestDispatch_Stream_ContentAfterReceipt_Dropped(t *testing.T) {
	s, logBuf := streamReceiptServerWith(t, modeStreamContentAfterReceipt, verifyingReceipt)
	w := driveStream(t, s)
	body, logs := w.Body.String(), logBuf.String()
	if !strings.Contains(body, `{"delta":"A"}`) {
		t.Errorf("content before the receipt missing from the client stream: %s", body)
	}
	if strings.Contains(body, `{"delta":"B"}`) {
		t.Errorf("content after the receipt reached the client: %s", body)
	}
	if strings.Contains(body, `"error"`) {
		t.Errorf("a settled stream ended in an error: %s", body)
	}
	if strings.Contains(logs, "receipt verification failed") {
		t.Errorf("the receipt over the earlier content should verify: %s", logs)
	}
}

// A settle group that won't open could be a relay's, so it opens no tail:
// the content after it still reaches the client and the receipt settles it.
func TestDispatch_Stream_UnopenableSettleGroupKeepsContent(t *testing.T) {
	s, logBuf := streamReceiptServerWith(t, modeStreamUnopenableSettleGroup, verifyingReceipt)
	w := driveStream(t, s)
	body, logs := w.Body.String(), logBuf.String()
	if !strings.Contains(body, `{"delta":"A"}`) {
		t.Errorf("content after an unopenable settle group was dropped: %s", body)
	}
	if strings.Contains(logs, "receipt verification failed") {
		t.Errorf("the receipt over the content should verify: %s", logs)
	}
}

// keepingReserveClient remembers every ticket it hands out, and the identity
// each held when it did.
type keepingReserveClient struct {
	zs.ReserveClient
	got        []*zs.ReservedTicket
	identities []string
}

func (k *keepingReserveClient) Reserve(ctx context.Context, op zs.Operator, req ticket.ReserveRequest, hop *zs.RelayHop) (*zs.ReservedTicket, error) {
	rt, err := k.ReserveClient.Reserve(ctx, op, req, hop)
	if rt != nil {
		k.got = append(k.got, rt)
		k.identities = append(k.identities, rt.AgeIdentity.String())
	}
	return rt, err
}

// SPEC § 3: no per-request ephemeral material outlives the response handler.
func TestDispatch_Stream_WipesReservedKeys(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{
		mode:         modeStreamReceiptIntact,
		streamFrames: [][]byte{[]byte(`{"delta":"A"}`)},
		buildReceipt: verifyingReceipt,
	})
	cfg := testConfig()
	opts := setup(t, cfg, node)
	keep := &keepingReserveClient{ReserveClient: opts.ReserveClient}
	opts.ReserveClient = keep
	var logBuf bytes.Buffer
	s := newServer(&cfg.policy, capturingLogger(&logBuf), nil, nil, opts)
	driveStream(t, s)
	if len(keep.got) != 1 {
		t.Fatalf("%d tickets reserved, want 1", len(keep.got))
	}
	rt := keep.got[0]
	if rt.ResponseKey != ([wire.ResponseKeySize]byte{}) {
		t.Error("K_response still held after the stream ended")
	}
	if rt.AgeIdentity.String() == keep.identities[0] {
		t.Error("the reply-to identity was not wiped")
	}
}

// The zs.usage SSE frame is opt-in (usageFrameHeader): its data payload
// is not a valid OpenAI chat chunk, so strict OpenAI clients (JetBrains/Koog)
// that parse every data: line throw on it. Default off keeps the stream
// OpenAI-compatible; settlement runs either way (driven by reading the receipt,
// before the frame is built).
func TestDispatch_Stream_UsageFrameOptIn(t *testing.T) {
	t.Run("default suppressed but settlement runs", func(t *testing.T) {
		s, logBuf := streamReceiptServer(t, modeStreamReceiptIntact)
		w := httptest.NewRecorder()
		s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test","stream":true}`))
		if w.Result().StatusCode != http.StatusOK {
			t.Fatalf("status = %d body=%s", w.Result().StatusCode, w.Body.String())
		}
		body := w.Body.String()
		if strings.Contains(body, "zs.usage") {
			t.Errorf("default stream leaked the zs.usage frame to a vanilla client: %s", body)
		}
		// Standard content + [DONE] still reach the client.
		if !strings.Contains(body, `{"delta":"A"}`) || !strings.Contains(body, "[DONE]") {
			t.Errorf("standard content/[DONE] missing from suppressed stream: %s", body)
		}
		// Settlement still ran: the (mismatching) receipt drove verification.
		if !strings.Contains(logBuf.String(), "receipt verification failed") {
			t.Errorf("settlement/verify did not run when the usage frame was suppressed: %s", logBuf.String())
		}
	})

	optIn := func(t *testing.T, build func([]byte) *ticket.UsageReceipt) string {
		t.Helper()
		s, _ := streamReceiptServerWith(t, modeStreamReceiptIntact, build)
		w := httptest.NewRecorder()
		req := clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test","stream":true}`)
		req.Header.Set(usageFrameHeader, "1")
		s.mux.ServeHTTP(w, req)
		if w.Result().StatusCode != http.StatusOK {
			t.Fatalf("status = %d body=%s", w.Result().StatusCode, w.Body.String())
		}
		return w.Body.String()
	}
	t.Run("emitted on opt-in", func(t *testing.T) {
		if body := optIn(t, verifyingReceipt); !strings.Contains(body, "zs.usage") {
			t.Errorf("opt-in client did not receive the zs.usage frame: %s", body)
		}
	})
	// A receipt that failed its checks is not what the turn cost.
	t.Run("not for a violated receipt", func(t *testing.T) {
		if body := optIn(t, mismatchingReceipt); strings.Contains(body, "zs.usage") {
			t.Errorf("a violated receipt was reported as the turn's usage: %s", body)
		}
	})
}
