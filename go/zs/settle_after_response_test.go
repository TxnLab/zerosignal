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
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/TxnLab/zerosignal/go/escrow"
	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/wire"
)

// blockingSettlementHandle holds AckSettle open until release is closed, so a
// test can observe what the client has received while the submit is in flight.
type blockingSettlementHandle struct {
	started chan struct{}
	release chan struct{}
}

func (b *blockingSettlementHandle) AckSettle(context.Context, *ticket.UsageReceipt, string) (string, uint64, bool, error) {
	close(b.started)
	<-b.release
	return "ACK_TXID", 0, false, nil
}

func (b *blockingSettlementHandle) Protest(context.Context, *ticket.UsageReceipt, []byte, escrow.ProtestReasonCode) (string, uint64, error) {
	return "", 0, nil
}

// TestNonStreamResponder_WritesBeforeSettleSubmit pins the ordering: the
// non-streaming responder must hand the client its complete response without
// waiting on the escrow submit, which is an algod round-trip bounded only by
// settleSubmitTimeout. The handle blocks the submit, so a responder that ran
// it inline would not return until release, and the test would time out.
func TestNonStreamResponder_WritesBeforeSettleSubmit(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	var signAddr types.Address
	copy(signAddr[:], pub)
	op := Operator{ID: 7, NodeID: 3, SigningAddr: signAddr.String(), TicketSigningKey: pub}

	var k [wire.ResponseKeySize]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	commit := ticket.CommitResponseKey(k)
	tkt := &ticket.Ticket{
		TicketID:   "dGlja2V0LXhvcnZvenp6MDA=",
		OperatorID: op.ID,
		NodeID:     op.NodeID,
		MaxPrice:   100_000,
		CommitK:    base64.StdEncoding.EncodeToString(commit[:]),
	}
	const txID = "APPCALLTXID00000000000000000000000000000000000000000"

	ephemeral, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity: %v", err)
	}
	sealer, err := wire.NewResponseSealerWithKey(ephemeral.Recipient(), txID, tkt.TicketID, k)
	if err != nil {
		t.Fatalf("NewResponseSealerWithKey: %v", err)
	}
	plaintext := []byte(`{"choices":[{"message":{"content":"hi"}}]}`)
	body, err := sealer.SealBody(plaintext)
	if err != nil {
		t.Fatalf("SealBody: %v", err)
	}

	receipt := &ticket.UsageReceipt{
		TicketID:          tkt.TicketID,
		ActualInputCount:  10,
		ActualOutputCount: 5,
		AmountCharged:     50_000,
	}
	receipt.SetBodyHashBytes(wire.BodyHashOfBody(plaintext))
	if err := receipt.Sign(context.Background(), rawKeyBytesSigner{addr: op.SigningAddr, priv: priv}, op.SigningAddr); err != nil {
		t.Fatalf("sign receipt: %v", err)
	}
	enc, err := receipt.EncodeReceiptHeader()
	if err != nil {
		t.Fatalf("EncodeReceiptHeader: %v", err)
	}
	sealedReceipt, err := sealer.SealHeader(wire.SealedHeaderReceipt, []byte(enc))
	if err != nil {
		t.Fatalf("SealHeader: %v", err)
	}

	upstream := &http.Response{StatusCode: http.StatusOK, Header: http.Header{}}
	upstream.Header.Set("Content-Type", wire.EncryptedContentType)
	upstream.Header.Set(wire.ResponseKeyHeader, sealer.WrappedKeyHeader())
	upstream.Header.Set(wire.ReceiptHeader, sealedReceipt)

	discard := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &Client{cfg: Config{Privacy: PrivacyDirect}, log: discard, refunds: NewRefundWatchdog(discard)}
	handle := &blockingSettlementHandle{started: make(chan struct{}), release: make(chan struct{})}
	responder := s.buildNonStreamResponder(context.Background(), ephemeral, txID, tkt, op, handle,
		nil, endpointChatCompletions, "test-model", 0.20, 0, nil)

	returned := make(chan error, 1)
	em := &recEmitter{}
	go func() { returned <- responder(em, upstream, body) }()

	select {
	case err := <-returned:
		if err != nil {
			t.Fatalf("responder: %v", err)
		}
	case <-time.After(5 * time.Second):
		close(handle.release)
		t.Fatal("responder did not return while the settle submit was blocked: the client's response waits on algod")
	}
	if em.replied == nil || !bytes.Equal(em.replied.Body, plaintext) {
		t.Errorf("client reply = %+v, want body %s", em.replied, plaintext)
	}

	// The submit still runs, and WaitSettles must not report done until it has
	// returned: shutdown relies on that to keep a settle from dying with the
	// process.
	select {
	case <-handle.started:
	case <-time.After(5 * time.Second):
		t.Fatal("AckSettle was never called after the response was written")
	}
	shortCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := s.WaitSettles(shortCtx); err == nil {
		t.Error("WaitSettles returned nil while AckSettle was still blocked")
	} else if msg := err.Error(); !strings.Contains(msg, "tickets still settling: "+tkt.TicketID) || strings.Contains(msg, "not yet seen to land") {
		t.Errorf("WaitSettles = %q, want the blocked ticket named as a submit", msg)
	}
	close(handle.release)
	if err := s.WaitSettles(context.Background()); err != nil {
		t.Errorf("WaitSettles after release: %v", err)
	}
}
