/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package escrow

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	protoalgod "github.com/TxnLab/zerosignal/go/algod"
)

// recordingAlgod records each group submitted to it.
type recordingAlgod struct {
	stubAlgod
	sent [][]byte
}

func (a *recordingAlgod) SendRawTransactionGroup(_ context.Context, raw []byte) (string, error) {
	a.sent = append(a.sent, raw)
	return "", nil
}

func signedPair() []types.SignedTxn {
	return []types.SignedTxn{
		{Txn: types.Transaction{Type: types.ApplicationCallTx, Header: types.Header{FirstValid: 1}}},
		{Txn: types.Transaction{Type: types.ApplicationCallTx, Header: types.Header{FirstValid: 2}}},
	}
}

// The node submits a payer-completed group with these. Each must send the
// two members concatenated in order (algod's raw group form), refuse any
// other count rather than silently drop or pad a member, and return a
// contract revert typed so the node can name its category.
func TestSubmitNodeHandedGroups(t *testing.T) {
	for _, tc := range []struct {
		method string
		submit func(context.Context, protoalgod.Client, []types.SignedTxn) error
	}{
		{"open", SubmitOpenGroup},
		{"settle", SubmitSettleGroup},
	} {
		t.Run(tc.method, func(t *testing.T) {
			group := signedPair()
			algod := &recordingAlgod{}
			if err := tc.submit(context.Background(), algod, group); err != nil {
				t.Fatal(err)
			}
			want := append(msgpack.Encode(group[0]), msgpack.Encode(group[1])...)
			if len(algod.sent) != 1 || !bytes.Equal(algod.sent[0], want) {
				t.Errorf("sent %d groups, want the two members concatenated once", len(algod.sent))
			}

			for _, n := range []int{1, 3} {
				bad := make([]types.SignedTxn, n)
				if err := tc.submit(context.Background(), &recordingAlgod{}, bad); err == nil {
					t.Errorf("a %d-txn group was accepted", n)
				}
			}

			spec, err := GetSpec()
			if err != nil {
				t.Fatal(err)
			}
			pc := pcsForApprovalMessage(t, spec, AssertSettleAfterRefundDeadline)[0]
			err = tc.submit(context.Background(), newFakeAlgodRejectingSubmit(t, pc), group)
			revert, ok := errors.AsType[*ApprovalError](err)
			if !ok {
				t.Fatalf("err = %v, want an *ApprovalError", err)
			}
			if revert.Method != tc.method || revert.Message != AssertSettleAfterRefundDeadline {
				t.Errorf("revert = %+v, want method %q message %q", revert, tc.method, AssertSettleAfterRefundDeadline)
			}
		})
	}
}
