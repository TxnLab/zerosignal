/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package solanastub

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/TxnLab/zerosignal/go/solana"
)

// The /stub/ routes let a test in another process, the TS SDK's, drive a
// scenario as the Go tests drive it in-process: fund a payer and pick its
// Behavior, read back what happened on chain, lapse a claim and resolve a
// freeze. They are served beside the node's own routes with no auth, so
// anyone who reaches the stub can spend the run's SOL and test USDC; Start
// serves only on loopback.

type behaviorJSON struct {
	NoReceipt        bool   `json:"no_receipt"`
	ClaimNoReceipt   bool   `json:"claim_no_receipt"`
	BadBodyHash      bool   `json:"bad_body_hash"`
	OverClaim        uint64 `json:"over_claim"`
	TicketLifetimeMs int64  `json:"ticket_lifetime_ms"`
	IssuerDown       bool   `json:"issuer_down"`
	HoldOpen         bool   `json:"hold_open"`
}

type ticketJSON struct {
	TicketID      string `json:"ticket_id"`
	MaxPrice      uint64 `json:"max_price"`
	Closed        bool   `json:"closed"`
	Status        string `json:"status,omitempty"`
	FreezeOrigin  uint8  `json:"freeze_origin,omitempty"`
	Deadline      int64  `json:"deadline,omitempty"`
	PendingAmount uint64 `json:"pending_amount,omitempty"`
}

type payerJSON struct {
	USDC    uint64       `json:"usdc"`
	Tickets []ticketJSON `json:"tickets"`
	// Unopened is every priced ticket the stub issued the payer whose open
	// never landed; closed says no account exists at its address.
	Unopened []ticketJSON `json:"unopened"`
	Receipts []uint64     `json:"receipt_amounts"`
	Errors   []string     `json:"errors"`
	// Credits is how many verified credits the payer's free reserves
	// carried, and IssuerCalls how many issue-wire requests it made.
	Credits     int `json:"credits"`
	IssuerCalls int `json:"issuer_calls"`
}

func (s *Stub) handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", s.Node.Handler())
	mux.HandleFunc("POST /stub/payers", s.addPayer)
	mux.HandleFunc("GET /stub/payers/{address}", s.payerState)
	mux.HandleFunc("POST /stub/fund", s.fund)
	mux.HandleFunc("POST /stub/lapse", s.lapse)
	mux.HandleFunc("POST /stub/resolve", s.resolve)
	return mux
}

// decodeStrict refuses an unknown field: a misspelled Behavior knob would
// otherwise run the honest node, and some endings still pass on it, slower.
func decodeStrict(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func (s *Stub) addPayer(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Address  string       `json:"address"`
		Behavior behaviorJSON `json:"behavior"`
		// USDC is the test USDC to give, in base units; zero is PayerUSDC.
		USDC uint64 `json:"usdc"`
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
	usdc := req.USDC
	if usdc == 0 {
		usdc = PayerUSDC
	}
	if err := s.FundPayer(r.Context(), payer, usdc); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	b := req.Behavior
	s.Node.SetBehavior(payer, Behavior{
		NoReceipt: b.NoReceipt, ClaimNoReceipt: b.ClaimNoReceipt, BadBodyHash: b.BadBodyHash,
		OverClaim: b.OverClaim, TicketLifetime: time.Duration(b.TicketLifetimeMs) * time.Millisecond,
		IssuerDown: b.IssuerDown, HoldOpen: b.HoldOpen,
	})
	w.WriteHeader(http.StatusNoContent)
}

// fund gives an address SOL alone, for a wallet a test drives apart from any
// payer the stub serves.
func (s *Stub) fund(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Address  string `json:"address"`
		Lamports uint64 `json:"lamports"`
	}
	if err := decodeStrict(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	to, err := solana.ParsePublicKey(req.Address)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.Chain.FundSOL(r.Context(), s.Funding, to, req.Lamports); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Stub) payerState(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	payer, err := solana.ParsePublicKey(r.PathValue("address"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	out := payerJSON{Tickets: []ticketJSON{}, Unopened: []ticketJSON{}, Receipts: []uint64{}, Errors: []string{}}
	if out.USDC, err = s.Chain.USDC(ctx, payer); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	for _, is := range s.Node.Issued(payer) {
		if !is.Opened && is.MaxPrice == 0 {
			continue
		}
		tk, err := s.Chain.Ticket(ctx, s.OperatorID, s.NodeID, is.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		tj := ticketJSON{TicketID: base64.StdEncoding.EncodeToString(is.ID[:]), MaxPrice: is.MaxPrice, Closed: tk == nil}
		if tk != nil {
			tj.Status, tj.FreezeOrigin, tj.Deadline, tj.PendingAmount = tk.Status.String(), tk.FreezeOrigin, tk.Deadline(), tk.Pending.Amount
		}
		if is.Opened {
			out.Tickets = append(out.Tickets, tj)
		} else {
			out.Unopened = append(out.Unopened, tj)
		}
	}
	for _, rc := range s.Node.Receipts(payer) {
		out.Receipts = append(out.Receipts, rc.AmountCharged)
	}
	for _, e := range s.Node.Errors(payer) {
		out.Errors = append(out.Errors, e.Error())
	}
	out.Credits, out.IssuerCalls = s.Node.Credits(payer), s.Node.Issuer().Calls(payer)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// ticketRef is a payer's ticket, as /stub/lapse and /stub/resolve name it.
type ticketRef struct {
	Address  string `json:"address"`
	TicketID string `json:"ticket_id"`
}

func (req ticketRef) parse() (solana.PublicKey, [16]byte, error) {
	var id [16]byte
	payer, err := solana.ParsePublicKey(req.Address)
	if err != nil {
		return payer, id, err
	}
	raw, err := base64.StdEncoding.DecodeString(req.TicketID)
	if err != nil || len(raw) != 16 {
		return payer, id, errors.New("ticket_id is not 16 bytes of base64")
	}
	copy(id[:], raw)
	return payer, id, nil
}

func (s *Stub) lapse(w http.ResponseWriter, r *http.Request) {
	var req ticketRef
	if err := decodeStrict(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	payer, id, err := req.parse()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.Node.SettleLapsed(r.Context(), id, payer); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Stub) resolve(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ticketRef
		ShareBps uint16 `json:"operator_share_bps"`
	}
	if err := decodeStrict(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	payer, id, err := req.parse()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	err = s.Resolve(r.Context(), id, payer, req.ShareBps)
	switch {
	case errors.Is(err, ErrNoAdmin):
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	case err != nil:
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
