/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package solanastub

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/TxnLab/zerosignal/go/solana"
)

// The /stub/ routes let a test in another process, the TS SDK's, drive a
// scenario as the Go tests drive it in-process: fund a payer and pick its
// Behavior, read back what happened on chain, and lapse a claim. They are
// served beside the node's own routes with no auth, so anyone who reaches the
// stub can mint its test USDC; StartLocalnet's loopback check keeps that to a
// local validator's.

type behaviorJSON struct {
	NoReceipt        bool   `json:"no_receipt"`
	ClaimNoReceipt   bool   `json:"claim_no_receipt"`
	BadBodyHash      bool   `json:"bad_body_hash"`
	OverClaim        uint64 `json:"over_claim"`
	TicketLifetimeMs int64  `json:"ticket_lifetime_ms"`
	IssuerDown       bool   `json:"issuer_down"`
}

type ticketJSON struct {
	TicketID      string `json:"ticket_id"`
	Closed        bool   `json:"closed"`
	Status        string `json:"status,omitempty"`
	FreezeOrigin  uint8  `json:"freeze_origin,omitempty"`
	Deadline      int64  `json:"deadline,omitempty"`
	PendingAmount uint64 `json:"pending_amount,omitempty"`
}

type payerJSON struct {
	USDC     uint64       `json:"usdc"`
	Tickets  []ticketJSON `json:"tickets"`
	Receipts []uint64     `json:"receipt_amounts"`
	Errors   []string     `json:"errors"`
	// Credits is how many verified credits the payer's free reserves
	// carried, and IssuerCalls how many issue-wire requests it made.
	Credits     int `json:"credits"`
	IssuerCalls int `json:"issuer_calls"`
}

func (l *Localnet) handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", l.Node.Handler())
	mux.HandleFunc("POST /stub/payers", l.addPayer)
	mux.HandleFunc("GET /stub/payers/{address}", l.payerState)
	mux.HandleFunc("POST /stub/lapse", l.lapse)
	return mux
}

// decodeStrict refuses an unknown field: a misspelled Behavior knob would
// otherwise run the honest node, and some endings still pass on it, slower.
func decodeStrict(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func (l *Localnet) addPayer(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Address  string       `json:"address"`
		Behavior behaviorJSON `json:"behavior"`
	}
	if err := decodeStrict(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	payer, err := solana.ParsePublicKey(req.Address)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := l.FundPayer(r.Context(), payer); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	b := req.Behavior
	l.Node.SetBehavior(payer, Behavior{
		NoReceipt: b.NoReceipt, ClaimNoReceipt: b.ClaimNoReceipt, BadBodyHash: b.BadBodyHash,
		OverClaim: b.OverClaim, TicketLifetime: time.Duration(b.TicketLifetimeMs) * time.Millisecond,
		IssuerDown: b.IssuerDown,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (l *Localnet) payerState(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	payer, err := solana.ParsePublicKey(r.PathValue("address"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	out := payerJSON{Tickets: []ticketJSON{}, Receipts: []uint64{}, Errors: []string{}}
	if out.USDC, err = l.Chain.USDC(ctx, payer); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	for _, id := range l.Node.Opened(payer) {
		tk, err := l.Chain.Ticket(ctx, l.OperatorID, l.NodeID, id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		tj := ticketJSON{TicketID: base64.StdEncoding.EncodeToString(id[:]), Closed: tk == nil}
		if tk != nil {
			tj.Status, tj.FreezeOrigin, tj.Deadline, tj.PendingAmount = tk.Status.String(), tk.FreezeOrigin, tk.Deadline(), tk.Pending.Amount
		}
		out.Tickets = append(out.Tickets, tj)
	}
	for _, rc := range l.Node.Receipts(payer) {
		out.Receipts = append(out.Receipts, rc.AmountCharged)
	}
	for _, e := range l.Node.Errors(payer) {
		out.Errors = append(out.Errors, e.Error())
	}
	out.Credits, out.IssuerCalls = l.Node.Credits(payer), l.Node.Issuer().Calls(payer)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (l *Localnet) lapse(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Address  string `json:"address"`
		TicketID string `json:"ticket_id"`
	}
	if err := decodeStrict(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	payer, err := solana.ParsePublicKey(req.Address)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	raw, err := base64.StdEncoding.DecodeString(req.TicketID)
	if err != nil || len(raw) != 16 {
		http.Error(w, "ticket_id is not 16 bytes of base64", http.StatusBadRequest)
		return
	}
	var id [16]byte
	copy(id[:], raw)
	if err := l.Node.SettleLapsed(r.Context(), id, payer); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
