/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package wire_test

import (
	"testing"

	"filippo.io/age"

	"github.com/TxnLab/zerosignal/go/wire"
)

// The node looks the ticket up and matches the group against it, so an ack
// missing either field has nothing to check and must not open.
func TestOpenSettleAck_RefusesAnIncompleteAck(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		ack  wire.SettleAck
		ok   bool
	}{
		{"complete", wire.SettleAck{TicketID: "T", SettleGroup: "G"}, true},
		{"no ticket_id", wire.SettleAck{SettleGroup: "G"}, false},
		{"no settle_group", wire.SettleAck{TicketID: "T"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sealed, err := wire.SealSettleAck(tc.ack, id.Recipient())
			if err != nil {
				t.Fatal(err)
			}
			got, err := wire.OpenSettleAck(sealed, id)
			if (err == nil) != tc.ok {
				t.Fatalf("OpenSettleAck err = %v, want ok=%v", err, tc.ok)
			}
			if tc.ok && got != tc.ack {
				t.Errorf("opened %+v, want %+v", got, tc.ack)
			}
		})
	}
}
