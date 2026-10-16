/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package wire_test

import (
	"strings"
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

// A 9.13 payer names the group payment_settle and an older one settle_group;
// the node must open both. Naming it twice is accepted only when the two agree,
// since the node would otherwise submit a group the payer may not have meant.
func TestOpenSettleAck_ReadsEitherName(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	for _, neutral := range []bool{false, true} {
		ack := wire.SettleAck{TicketID: "T", SettleGroup: "G", NeutralNames: neutral}
		sealed, err := wire.SealSettleAck(ack, id.Recipient())
		if err != nil {
			t.Fatal(err)
		}
		got, err := wire.OpenSettleAck(sealed, id)
		if err != nil || got != ack {
			t.Fatalf("neutral=%v: opened %+v, %v; want %+v", neutral, got, err, ack)
		}
	}
	for _, tc := range []struct {
		name, plaintext string
		ok              bool
	}{
		{"both, agreeing", `{"ticket_id":"T","settle_group":"G","payment_settle":"G"}`, true},
		{"both, disagreeing", `{"ticket_id":"T","settle_group":"G","payment_settle":"H"}`, false},
		{"neutral only", `{"ticket_id":"T","payment_settle":"G"}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sealed, err := wire.SealReserveRequest([]byte(tc.plaintext), id.Recipient())
			if err != nil {
				t.Fatal(err)
			}
			got, err := wire.OpenSettleAck(sealed, id)
			if (err == nil) != tc.ok {
				t.Fatalf("OpenSettleAck err = %v, want ok=%v", err, tc.ok)
			}
			if tc.ok && (got.SettleGroup != "G" || !got.NeutralNames) {
				t.Fatalf("opened %+v, want group G under the neutral name", got)
			}
		})
	}
}

// What a payer writes is what the gate says: an older node reads only the
// legacy names.
func TestSealSettleAck_WritesTheChosenName(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		neutral   bool
		want, not string
	}{
		{false, `"settle_group":"G"`, "payment_settle"},
		{true, `"payment_settle":"G"`, "settle_group"},
	} {
		sealed, err := wire.SealSettleAck(wire.SettleAck{TicketID: "T", SettleGroup: "G", NeutralNames: tc.neutral}, id.Recipient())
		if err != nil {
			t.Fatal(err)
		}
		plain, err := wire.OpenReserveRequest(sealed, id)
		if err != nil {
			t.Fatal(err)
		}
		if s := string(plain); !strings.Contains(s, tc.want) || strings.Contains(s, tc.not) {
			t.Fatalf("neutral=%v: plaintext %s, want %s and no %s", tc.neutral, s, tc.want, tc.not)
		}
	}
}
