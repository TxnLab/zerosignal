/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"context"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/wire"
	"github.com/TxnLab/zerosignal/go/zs"
)

// Wait reports the submit of a turn run through Client.Stream, on both
// responders. The test wallet's handle is detached, so every submit fails;
// what is pinned is that Wait sees it, with the right kind and ticket.
func TestStreamWait_ReportsTheTurnsSubmit(t *testing.T) {
	verifying := func(plaintext []byte) *ticket.UsageReceipt {
		r := &ticket.UsageReceipt{ActualInputCount: 8, ActualOutputCount: 3, AmountCharged: 321}
		r.SetBodyHashBytes(wire.BodyHashOfBody(plaintext))
		return r
	}
	frames := [][]byte{[]byte(`{"delta":"A"}`), []byte(`{"delta":"B"}`)}
	cases := []struct {
		name     string
		node     nodeConfig
		body     string
		wantKind zs.SettleKind
		wantErr  bool
	}{
		{"whole reply, payer ack",
			nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{"choices":[{"message":{"content":"hi"}}]}`), buildReceipt: verifying},
			`{"model":"gpt-test"}`, zs.SettlePayerAck, true},
		{"stream, payer ack",
			nodeConfig{mode: modeStreamReceiptIntact, streamFrames: frames, buildReceipt: verifying},
			`{"model":"gpt-test","stream":true}`, zs.SettlePayerAck, true},
		{"stream, protest",
			nodeConfig{mode: modeStreamReceiptIntact, streamFrames: frames, buildReceipt: mismatchingReceipt},
			`{"model":"gpt-test","stream":true}`, zs.SettleProtest, true},
		{"stream cut before the receipt",
			nodeConfig{mode: modeStreamReceiptTruncated, streamFrames: frames, buildReceipt: mismatchingReceipt},
			`{"model":"gpt-test","stream":true}`, zs.SettleNone, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			node := newFakeNode(t, &tc.node)
			cfg := testConfig()
			opts := setup(t, cfg, node)
			wallet := &fakeWallet{appCallTxID: "APPCALLTX"}
			opts.Wallet = wallet
			s := testServer(cfg, opts)

			// FramesOnly, as the handler runs it: the fake node's frames are not
			// OpenAI chunks a decoder would accept as finished.
			st := s.Client.Stream(context.Background(), zs.Request{Endpoint: zs.EndpointChatCompletions, Body: []byte(tc.body), FramesOnly: true})
			for _, err := range st.Events() {
				if err != nil {
					t.Fatalf("turn failed: %v", err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			r, err := st.Wait(ctx)
			if r.Kind != tc.wantKind || (err != nil) != tc.wantErr {
				t.Fatalf("Wait = %+v, %v; want kind %q, error %v", r, err, tc.wantKind, tc.wantErr)
			}
			if tc.wantKind != zs.SettleNone && (r.TicketID == "" || r.TicketID != wallet.lastTID) {
				t.Errorf("Wait ticket %q, opened %q", r.TicketID, wallet.lastTID)
			}
		})
	}
}
