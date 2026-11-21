/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/TxnLab/zerosignal/go/ticket"
)

// railReserve runs one reserve on rail against a harness node, for a request
// whose caller already set a ticket id the client must not send; edit, when
// set, changes the response before it is sent. It returns what the node saw.
func railReserve(t *testing.T, rail ticket.Rail, edit func(h *reserveTestHarness, resp *ticket.ReserveResponse)) (ticket.ReserveRequest, *ReservedTicket, error) {
	t.Helper()
	var seen ticket.ReserveRequest
	h := newReserveHarness(t, func(http.ResponseWriter, *http.Request) {})
	h.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = h.decodeReserve(t, r)
		resp := h.issueValidTicket(t, seen)
		if edit != nil {
			edit(h, &resp)
		}
		writeSealedReserve(t, w, resp, seen.ProxyRecipient)
	})
	c := &HTTPReserveClient{Deployment: harnessDeployment, HTTPClient: http.DefaultClient, Rail: rail}
	req := sampleReserveReq()
	req.TicketID = staleTicketID
	rt, err := c.Reserve(context.Background(), h.operator, req, nil)
	return seen, rt, err
}

// Only a free Solana turn opens nothing; an Algorand free ticket opens at
// zero under the contract's quota. The TS SDK's 'opensOnChain'.
func TestOpensOnChain(t *testing.T) {
	for _, c := range []struct {
		rail     ticket.Rail
		maxPrice uint64
		want     bool
	}{
		{0, 0, true},
		{ticket.RailAlgorand, 0, true},
		{ticket.RailAlgorand, 5, true},
		{ticket.RailSolana, 1, true},
		{ticket.RailSolana, 0, false},
	} {
		if got := opensOnChain(c.rail, &ticket.Ticket{MaxPrice: c.maxPrice}); got != c.want {
			t.Errorf("opensOnChain(%v, %d) = %v, want %v", c.rail, c.maxPrice, got, c.want)
		}
	}
}

// staleTicketID is an id a caller left on the request, perhaps one already
// opened at the node.
const staleTicketID = "c3RhbGUtdGlja2V0LWlkLg=="

// A Solana payer names a fresh 16-byte ticket id on every reserve, in the
// ticket's canonical spelling, in place of any the caller set, and opens the
// ticket that carries it.
func TestReserve_SolanaPayerChoosesTheTicketID(t *testing.T) {
	ids := map[string]bool{}
	for range 3 {
		seen, rt, err := railReserve(t, ticket.RailSolana, nil)
		if err != nil {
			t.Fatalf("Reserve: %v", err)
		}
		raw, err := base64.StdEncoding.DecodeString(seen.TicketID)
		if err != nil || len(raw) != 16 || base64.StdEncoding.EncodeToString(raw) != seen.TicketID {
			t.Fatalf("ticket_id %q is not 16 bytes in canonical base64", seen.TicketID)
		}
		if rt.Ticket.TicketID != seen.TicketID {
			t.Fatalf("opened ticket %q, asked for %q", rt.Ticket.TicketID, seen.TicketID)
		}
		ids[seen.TicketID] = true
	}
	if ids[staleTicketID] {
		t.Fatal("sent the caller's ticket id instead of a fresh one")
	}
	if len(ids) != 3 {
		t.Fatalf("three reserves named %d ticket ids, want three fresh ones", len(ids))
	}
}

// A ticket naming another id than the one asked for is refused, even when
// the node signed it: opening it would let the node pick an id the payer has
// opened before.
func TestReserve_SolanaPayerRefusesAnotherTicketID(t *testing.T) {
	_, _, err := railReserve(t, ticket.RailSolana, func(h *reserveTestHarness, resp *ticket.ReserveResponse) {
		resp.Ticket.TicketID = "AAAAAAAAAAAAAAAAAAAAAA=="
		if err := resp.Ticket.Sign(context.Background(), rawKeyBytesSigner{addr: h.signAddr, priv: h.signKey}, h.signAddr); err != nil {
			t.Fatal(err)
		}
	})
	if err == nil || !strings.Contains(err.Error(), "is not the requested") {
		t.Fatalf("err = %v, want the ticket id refused", err)
	}
}

// An Algorand payer leaves the id to the node, named rail or not, and drops
// one the caller set.
func TestReserve_AlgorandPayerNamesNoTicketID(t *testing.T) {
	for _, rail := range []ticket.Rail{0, ticket.RailAlgorand} {
		seen, _, err := railReserve(t, rail, nil)
		if err != nil {
			t.Fatalf("rail %d: Reserve: %v", rail, err)
		}
		if seen.TicketID != "" {
			t.Fatalf("rail %d: named ticket id %q", rail, seen.TicketID)
		}
	}
}

// solanaOffer is a node's open offer from the shared wire vectors.
func solanaOffer(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../testdata/solana_wire_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Opens []struct {
			PresignedOpenTxn string `json:"presigned_open_txn"`
		} `json:"opens"`
	}
	if err := json.Unmarshal(b, &v); err != nil || len(v.Opens) == 0 {
		t.Fatalf("solana_wire_vectors.json: %v", err)
	}
	return v.Opens[0].PresignedOpenTxn
}

// On Solana the open is checked as the offer transaction, so an Algorand group
// fails the reserve there as an offer fails it on Algorand.
func TestReserve_OpenIsCheckedForTheRail(t *testing.T) {
	offer := solanaOffer(t)
	for _, tc := range []struct {
		name        string
		rail        ticket.Rail
		open        string
		wantErr     string
		wantPayload bool
	}{
		{"Solana offer", ticket.RailSolana, offer, "", true},
		{"Algorand group on Solana", ticket.RailSolana, testOpenGroup, "decode presigned open offer", false},
		{"not base64 on Solana", ticket.RailSolana, "not-an-offer", "decode presigned open offer", false},
		{"offer respelled on Solana", ticket.RailSolana, strings.TrimRight(offer, "="), "decode presigned open offer", false},
		{"base64 but not a transaction on Solana", ticket.RailSolana, "AAAA", "decode presigned open offer", false},
		{"Solana offer on Algorand", ticket.RailAlgorand, offer, "decode presigned open group", false},
		{"Algorand group", ticket.RailAlgorand, testOpenGroup, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, rt, err := railReserve(t, tc.rail, func(_ *reserveTestHarness, resp *ticket.ReserveResponse) {
				resp.PreSignedOpenTxn = tc.open
			})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if rt.PresignedOpen != tc.open {
				t.Errorf("PresignedOpen = %q, want the node's %q", rt.PresignedOpen, tc.open)
			}
		})
	}
}
