/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package solanastub

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"filippo.io/age"

	"github.com/TxnLab/zerosignal/go/inject"
	"github.com/TxnLab/zerosignal/go/pricing"
	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/rpc"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/wire"
)

// Model is the stub's priced model, at InputUSDPer1M and OutputUSDPer1M, and
// FreeModel its free one, whose turns open nothing.
const (
	Model          = "stub-model"
	FreeModel      = "stub-free-model"
	InputUSDPer1M  = 1.0
	OutputUSDPer1M = 2.0
	// OutputTokens is what every reply reports generating.
	OutputTokens = 7
	// Reply is the assistant's text in every reply.
	Reply = "hello from the stub node"
)

// Behavior selects how the stub departs from an honest node, for the endings
// a payer drives. The zero value is honest.
type Behavior struct {
	// NoReceipt lands the open, then answers 502 with no receipt: a ticket
	// the node never served, which the payer refunds at its deadline.
	NoReceipt bool
	// ClaimNoReceipt lands the open, posts a claim for the full max_price,
	// then answers 502 with no receipt: a claim the payer can't contest,
	// which lapses to the node at the deadline.
	ClaimNoReceipt bool
	// BadBodyHash signs a receipt whose body_hash is not the reply's, which
	// the payer protests.
	BadBodyHash bool
	// OverClaim posts a claim this much above the receipt before answering,
	// and refuses the payer's ack: the payer freezes the ticket.
	OverClaim uint64
	// TicketLifetime is how far ahead a ticket expires; zero is a minute.
	TicketLifetime time.Duration
}

// Node is the stub. Its identity is fixed when it is built; each payer's
// Behavior can change between requests, so scenarios run side by side.
type Node struct {
	chain      *Chain
	signing    ed25519.PrivateKey
	operatorID uint64
	nodeID     uint64
	deployment ticket.DeploymentID
	identity   *age.X25519Identity

	mu        sync.Mutex
	behaviors map[solana.PublicKey]Behavior
	tickets   map[string]*entry
	errs      map[solana.PublicKey][]error
}

// entry is one ticket the stub issued.
type entry struct {
	ticket    ticket.Ticket
	id        [16]byte
	k         [wire.ResponseKeySize]byte
	payer     solana.PublicKey
	offer     []byte // the offer's message bytes
	lastValid uint64
	opened    bool
	openSeq   uint64
	receipt   *ticket.UsageReceipt
}

// NewNode builds the stub for node (operatorID, nodeID), whose signing key on
// chain is signing's.
func NewNode(chain *Chain, signing ed25519.PrivateKey, operatorID, nodeID uint64) (*Node, error) {
	dep, err := ticket.SolanaDeploymentID(chain.Genesis[:], chain.Deployment.Program[:])
	if err != nil {
		return nil, err
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}
	return &Node{
		chain: chain, signing: signing, operatorID: operatorID, nodeID: nodeID,
		deployment: dep, identity: id,
		behaviors: map[solana.PublicKey]Behavior{}, tickets: map[string]*entry{},
		errs: map[solana.PublicKey][]error{},
	}, nil
}

// SetBehavior sets how the stub treats payer's requests from now on.
func (n *Node) SetBehavior(payer solana.PublicKey, b Behavior) {
	n.mu.Lock()
	n.behaviors[payer] = b
	n.mu.Unlock()
}

func (n *Node) behaviorFor(payer solana.PublicKey) Behavior {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.behaviors[payer]
}

// Receipts is every receipt the stub signed for payer.
func (n *Node) Receipts(payer solana.PublicKey) []ticket.UsageReceipt {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []ticket.UsageReceipt
	for _, e := range n.tickets {
		if e.payer == payer && e.receipt != nil {
			out = append(out, *e.receipt)
		}
	}
	return out
}

// Errors is what went wrong on the stub's side serving payer, such as a
// settle it sent in the background that failed. A test asserts it is empty;
// keyed by payer so scenarios running side by side each see their own.
func (n *Node) Errors(payer solana.PublicKey) []error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]error(nil), n.errs[payer]...)
}

func (n *Node) fail(payer solana.PublicKey, err error) {
	n.mu.Lock()
	n.errs[payer] = append(n.errs[payer], err)
	n.mu.Unlock()
}

// Opened is every ticket payer opened at the stub, in no order.
func (n *Node) Opened(payer solana.PublicKey) [][16]byte {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out [][16]byte
	for _, e := range n.tickets {
		if e.opened && e.payer == payer {
			out = append(out, e.id)
		}
	}
	return out
}

// Handler serves the routes a payer reaches on the Solana rail.
func (n *Node) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/zs/details", n.details)
	mux.HandleFunc("POST /v1/zs/reserve", n.reserve)
	mux.HandleFunc("POST /v1/chat/completions", n.chat)
	mux.HandleFunc("POST "+wire.SettleAckPath, n.settleAck)
	return mux
}

type keySigner ed25519.PrivateKey

func (k keySigner) SignBytes(_ context.Context, _ string, msg []byte) ([]byte, error) {
	return ed25519.Sign(ed25519.PrivateKey(k), msg), nil
}

func (n *Node) signingAddr() string { return PublicKey(n.signing).String() }

func writeError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"message": msg, "type": "invalid_request_error", "code": code}})
}

func (n *Node) details(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	adv := ticket.EphemeralAdvertisement{
		AgePubkey:  n.identity.Recipient().String(),
		IssuedAt:   now.Unix(),
		Expiry:     now.Add(25 * time.Minute).Unix(),
		Deployment: n.deployment,
	}
	if err := adv.Sign(r.Context(), keySigner(n.signing), n.signingAddr(), n.operatorID, n.nodeID); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	d := inject.OperatorDetails{
		OperatorID:          n.operatorID,
		NodeID:              n.nodeID,
		SigningAddr:         n.signingAddr(),
		Deployment:          n.deployment.String(),
		EphemeralAgePubkey:  adv.AgePubkey,
		EphemeralExpiry:     adv.Expiry,
		EphemeralIssuedAt:   adv.IssuedAt,
		EphemeralSig:        adv.Sig,
		EphemeralDeployment: n.deployment.String(),
		EphemeralSigV2:      adv.SigV2,
		Models: []inject.OperatorDetailsModel{
			{ID: Model, InputRateUSDPer1M: InputUSDPer1M, OutputRateUSDPer1M: OutputUSDPer1M, ContextWindow: 32_768, MaxOutputTokens: 1024},
			{ID: FreeModel, ContextWindow: 32_768, MaxOutputTokens: 1024},
		},
		ProtoVersion: wire.ProtoVersion,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(d)
}

func rates() (in, out uint64) {
	in, _ = pricing.USDRateToMicroUSDCPer1M(InputUSDPer1M)
	out, _ = pricing.USDRateToMicroUSDCPer1M(OutputUSDPer1M)
	return in, out
}

// ratesFor is model's rates, and false for a model the stub doesn't serve.
func ratesFor(model string) (in, out uint64, ok bool) {
	switch model {
	case Model:
		in, out = rates()
		return in, out, true
	case FreeModel:
		return 0, 0, true
	}
	return 0, 0, false
}

func (n *Node) reserve(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "read_body", err.Error())
		return
	}
	plain, err := wire.OpenReserveRequest(raw, n.identity)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_reserve_envelope", err.Error())
		return
	}
	var req ticket.ReserveRequest
	if err := json.Unmarshal(plain, &req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_reserve", err.Error())
		return
	}
	inRate, outRate, ok := ratesFor(req.Model)
	if !ok {
		writeError(w, http.StatusNotFound, "model_not_found", "the stub serves "+Model+" and "+FreeModel)
		return
	}
	if !req.Deployment.IsZero() && req.Deployment != n.deployment {
		writeError(w, http.StatusBadRequest, "deployment_mismatch", "another deployment")
		return
	}
	payer, err := solana.ParsePublicKey(req.PayerAddr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_payer", err.Error())
		return
	}
	pub := ed25519.PublicKey(payer[:])
	if err := req.VerifyFor(pub, n.operatorID, n.nodeID, time.Now(), time.Minute, n.deployment, false); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_payer_sig", err.Error())
		return
	}
	idRaw, err := base64.StdEncoding.DecodeString(req.TicketID)
	if err != nil || len(idRaw) != 16 {
		writeError(w, http.StatusBadRequest, "bad_ticket_id", "ticket_id is not 16 bytes of base64")
		return
	}
	recipient, err := age.ParseX25519Recipient(req.ProxyRecipient)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_proxy_recipient", err.Error())
		return
	}

	e := &entry{payer: payer}
	copy(e.id[:], idRaw)
	if _, err := rand.Read(e.k[:]); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	n.mu.Lock()
	if _, taken := n.tickets[req.TicketID]; taken {
		n.mu.Unlock()
		writeError(w, http.StatusConflict, "ticket_id_taken", "ticket id already issued")
		return
	}
	n.tickets[req.TicketID] = e
	n.mu.Unlock()

	maxPrice, err := pricing.ExpectedMaxPrice(req.InputCount, req.MaxOutputCount, inRate, outRate, 0, 0, uint64(n.chain.Config.FeeBps))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_size", err.Error())
		return
	}
	lifetime := n.behaviorFor(payer).TicketLifetime
	if lifetime <= 0 {
		lifetime = time.Minute
	}
	commit := ticket.CommitResponseKey(e.k)
	e.ticket = ticket.Ticket{
		TicketID: req.TicketID, OperatorID: n.operatorID, NodeID: n.nodeID,
		InputCount: req.InputCount, MaxOutputCount: req.MaxOutputCount,
		InputRate: inRate, OutputRate: outRate, CacheReadRate: inRate,
		MaxPrice: maxPrice, ExpiresAt: time.Now().Add(lifetime).Unix(),
		Model: req.Model, Stream: req.Stream, CommitK: base64.StdEncoding.EncodeToString(commit[:]),
		InputUsageType: ticket.UsageTypeTokens, OutputUsageType: ticket.UsageTypeTokens,
		Deployment: req.Deployment,
	}
	if err := e.ticket.Sign(ctx, keySigner(n.signing), n.signingAddr()); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}

	// A free ticket opens nothing, so it has no offer.
	var offer string
	if maxPrice > 0 {
		if offer, err = n.openOffer(ctx, e); err != nil {
			// Code-less, as a gateway's would be, so the payer's transient retry
			// re-asks rather than taking it as the node's answer.
			http.Error(w, "the stub could not read a blockhash", http.StatusServiceUnavailable)
			return
		}
	}
	var wrapped bytes.Buffer
	aw, err := age.Encrypt(&wrapped, recipient)
	if err == nil {
		_, err = aw.Write(e.k[:])
	}
	if err == nil {
		err = aw.Close()
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	body, err := json.Marshal(ticket.ReserveResponse{
		Ticket:             e.ticket,
		WrappedResponseKey: base64.StdEncoding.EncodeToString(wrapped.Bytes()),
		PreSignedOpenTxn:   offer,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	sealed, err := wire.SealReserveResponse(body, recipient)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	w.Header().Set("Content-Type", wire.SealedReserveResponseContentType)
	_, _ = w.Write(sealed)
}

// openOffer builds and node-signs the open for e: the payer's transfer of
// max_price into the node's vault and the node's open, with the payer's
// signature slot left empty.
func (n *Node) openOffer(ctx context.Context, e *entry) (string, error) {
	d, cfg, node := n.chain.Deployment, n.chain.Config, PublicKey(n.signing)
	vault := d.Vault(d.Node(n.operatorID, n.nodeID))
	ixs := []solana.Instruction{
		solana.TransferChecked(d.TokenAccount(e.payer), d.Mint, vault, e.payer, e.ticket.MaxPrice, cfg.USDCDecimals),
		d.Open(node, n.operatorID, n.nodeID, zsescrow.OpenArgs{TicketID: e.id, Payer: e.payer, MaxPrice: e.ticket.MaxPrice, ExpiresAt: e.ticket.ExpiresAt}),
	}
	bh, err := n.chain.RPC.GetLatestBlockhash(ctx, rpc.Confirmed)
	if err != nil {
		return "", err
	}
	m, err := solana.Compile(node, bh.Hash, ixs, solana.Legacy)
	if err != nil {
		return "", err
	}
	if e.offer, err = m.MarshalBinary(); err != nil {
		return "", err
	}
	e.lastValid = bh.LastValidBlockHeight
	tx := solana.NewTransaction(m)
	if err := tx.Sign(n.signing); err != nil {
		return "", err
	}
	raw, err := tx.MarshalBinary()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

func (n *Node) lookup(ticketID string) *entry {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.tickets[ticketID]
}

func (n *Node) chat(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "read_body", err.Error())
		return
	}
	dec, err := wire.DecryptRequest(raw, n.identity)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_envelope", err.Error())
		return
	}
	e := n.lookup(dec.TicketID)
	if e == nil {
		writeError(w, http.StatusPaymentRequired, "ticket_invalid", "unknown ticket")
		return
	}
	paymentRef, paymentOpen := dec.AlgorandTxID, dec.OpenGroup
	if !hmac.Equal(dec.AdmissionTag, wire.ComputeAdmissionTag(e.k, dec.TicketID, paymentRef, dec.Body)) {
		writeError(w, http.StatusPaymentRequired, "admission_tag_mismatch", "admission tag does not bind this request")
		return
	}
	free := e.ticket.MaxPrice == 0
	switch {
	case free && (paymentOpen != "" || paymentRef != ""):
		writeError(w, http.StatusPaymentRequired, "payment_verification_failed", "a free ticket opens nothing")
		return
	case !free:
		if err := n.landOpen(ctx, e, paymentOpen, paymentRef); err != nil {
			writeError(w, http.StatusPaymentRequired, "payment_verification_failed", err.Error())
			return
		}
	}

	b := n.behaviorFor(e.payer)
	if b.ClaimNoReceipt {
		inRate, outRate := rates()
		ceiling, err := pricing.ExpectedBaseMax(e.ticket.InputCount, e.ticket.MaxOutputCount, inRate, outRate, 0, 0)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
		// The most the ticket allows: max_price less the fee it was grossed up for.
		fields := zsescrow.ClaimFields{Amount: ceiling, OutputUsageType: uint8(ticket.UsageTypeTokens)}
		if err := n.claim(ctx, e, fields); err != nil {
			n.fail(e.payer, err)
		}
	}
	if b.NoReceipt || b.ClaimNoReceipt {
		writeError(w, http.StatusBadGateway, "upstream_error", "the stub's upstream failed")
		return
	}

	var req struct {
		Stream bool `json:"stream"`
	}
	_ = json.Unmarshal(dec.Body, &req)
	sealer, err := wire.NewResponseSealerWithKey(dec.ReplyToRecipient, paymentRef, dec.TicketID, e.k)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	// A free ticket has no open_seq to ack, so no settle slot.
	var slot string
	if !free {
		if slot, err = sealer.SealHeader(wire.SealedHeaderSettleGroup, []byte(zsescrow.FormatOpenSeq(e.openSeq))); err != nil {
			writeError(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
	}
	if req.Stream {
		n.stream(ctx, w, e, sealer, slot, b)
		return
	}
	body, _ := json.Marshal(map[string]any{
		"id": "stub-" + dec.TicketID, "object": "chat.completion", "model": Model,
		"choices": []any{map[string]any{"index": 0, "finish_reason": "stop", "message": map[string]string{"role": "assistant", "content": Reply}}},
		"usage":   map[string]uint64{"prompt_tokens": e.ticket.InputCount, "completion_tokens": OutputTokens},
	})
	rcpt, err := n.receipt(ctx, e, wire.BodyHashOfBody(body), b)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	rh, err := rcpt.EncodeReceiptHeader()
	if err == nil {
		rh, err = sealer.SealHeader(wire.SealedHeaderReceipt, []byte(rh))
	}
	sealedBody, err2 := sealer.SealBody(body)
	if err != nil || err2 != nil {
		writeError(w, http.StatusInternalServerError, "internal", fmt.Sprint(err, err2))
		return
	}
	w.Header().Set(wire.ResponseKeyHeader, sealer.WrappedKeyHeader())
	w.Header().Set(wire.ReceiptHeader, rh)
	if slot != "" {
		w.Header().Set(wire.SettleGroupHeader, slot)
	}
	w.Header().Set("Content-Type", wire.EncryptedContentType)
	_, _ = w.Write(sealedBody)
}

func (n *Node) stream(ctx context.Context, w http.ResponseWriter, e *entry, sealer *wire.ResponseSealer, slot string, b Behavior) {
	var frames [][]byte
	for i, word := range []string{"hello ", "from ", "the ", "stub ", "node"} {
		delta := map[string]any{"content": word}
		if i == 0 {
			delta["role"] = "assistant"
		}
		f, _ := json.Marshal(map[string]any{
			"id": "stub-" + e.ticket.TicketID, "object": "chat.completion.chunk", "model": Model,
			"choices": []any{map[string]any{"index": 0, "delta": delta, "finish_reason": nil}},
		})
		frames = append(frames, f)
	}
	last, _ := json.Marshal(map[string]any{
		"id": "stub-" + e.ticket.TicketID, "object": "chat.completion.chunk", "model": Model,
		"choices": []any{map[string]any{"index": 0, "delta": map[string]any{}, "finish_reason": "stop"}},
		"usage":   map[string]uint64{"prompt_tokens": e.ticket.InputCount, "completion_tokens": OutputTokens},
	})
	frames = append(frames, last)
	rcpt, err := n.receipt(ctx, e, wire.BodyHashFromFrames(frames), b)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	w.Header().Set(wire.ResponseKeyHeader, sealer.WrappedKeyHeader())
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	flush := func() {
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}
	for _, f := range frames {
		data, err := sealer.SealStreamFrame(f)
		if err != nil {
			n.fail(e.payer, err)
			return
		}
		_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", wire.StreamEventMarker, data)
		flush()
	}
	if slot != "" {
		_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", wire.StreamEventSettleGroup, slot)
	}
	rb, _ := json.Marshal(rcpt)
	data, err := sealer.SealStreamFrame(rb)
	if err != nil {
		n.fail(e.payer, err)
		return
	}
	_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", wire.StreamEventReceipt, data)
	_, _ = io.WriteString(w, "data: [DONE]\n\n")
	flush()
}

// receipt signs e's receipt for a reply whose body hashes to sum, and posts
// the over-claim Behavior asks for before the reply goes out.
func (n *Node) receipt(ctx context.Context, e *entry, sum [32]byte, b Behavior) (*ticket.UsageReceipt, error) {
	// The charge is net of the protocol fee, which the program adds on top.
	amount, err := pricing.ExpectedBaseMax(e.ticket.InputCount, OutputTokens, e.ticket.InputRate, e.ticket.OutputRate, 0, 0)
	if err != nil {
		return nil, err
	}
	r := &ticket.UsageReceipt{
		TicketID: e.ticket.TicketID, ActualInputCount: e.ticket.InputCount, ActualOutputCount: OutputTokens,
		AmountCharged: amount, TtftMs: 40, DecodeMs: 60,
		InputUsageType: ticket.UsageTypeTokens, OutputUsageType: ticket.UsageTypeTokens,
		Deployment: e.ticket.Deployment,
	}
	if b.BadBodyHash {
		sum[0] ^= 0xff
	}
	r.BodyHash = hex.EncodeToString(sum[:])
	if err := r.Sign(ctx, keySigner(n.signing), n.signingAddr()); err != nil {
		return nil, err
	}
	n.mu.Lock()
	e.receipt = r
	n.mu.Unlock()
	if b.OverClaim > 0 {
		fields := zsescrow.ClaimFromReceipt(r)
		fields.Amount += b.OverClaim
		if err := n.claim(ctx, e, fields); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// landOpen checks that the payer's completed open is the offer the stub
// signed, sends it and reads the ticket's open_seq once it is confirmed.
func (n *Node) landOpen(ctx context.Context, e *entry, paymentOpen, paymentRef string) error {
	tx, err := zsescrow.DecodeOpenPayment(paymentOpen, paymentRef)
	if err != nil {
		return err
	}
	msg, err := tx.Message.MarshalBinary()
	if err != nil {
		return err
	}
	if !bytes.Equal(msg, e.offer) {
		return fmt.Errorf("the open is not the offer this node signed")
	}
	if _, err := n.chain.SendSigned(ctx, tx, e.lastValid); err != nil {
		return err
	}
	t, err := n.chain.Ticket(ctx, n.operatorID, n.nodeID, e.id)
	if err != nil {
		return err
	}
	if t == nil {
		return fmt.Errorf("the open landed but the ticket account is missing")
	}
	n.mu.Lock()
	e.opened, e.openSeq = true, t.OpenSeq
	n.mu.Unlock()
	return nil
}

func (n *Node) ending(ctx context.Context, e *entry) (zsescrow.Ending, error) {
	t, err := n.chain.Ticket(ctx, n.operatorID, n.nodeID, e.id)
	if err != nil {
		return zsescrow.Ending{}, err
	}
	if t == nil {
		return zsescrow.Ending{}, fmt.Errorf("ticket %x is closed", e.id)
	}
	return zsescrow.Ending{
		Submitter: PublicKey(n.signing), OperatorID: n.operatorID, NodeID: n.nodeID,
		TicketID: e.id, RentPayer: t.RentPayer, Payer: e.payer,
	}, nil
}

// claim posts the node's half of a settle with fields.
func (n *Node) claim(ctx context.Context, e *entry, fields zsescrow.ClaimFields) error {
	end, err := n.ending(ctx, e)
	if err != nil {
		return err
	}
	_, err = n.chain.Send(ctx, []solana.Instruction{n.chain.Deployment.Claim(end, fields)}, n.signing)
	if err != nil {
		return fmt.Errorf("solanastub: claim: %w", err)
	}
	return nil
}

// SettleLapsed lapses a claim the payer left unanswered past the deadline, as
// any account may; the stub's signing key pays.
func (n *Node) SettleLapsed(ctx context.Context, ticketID [16]byte, payer solana.PublicKey) error {
	end, err := n.ending(ctx, &entry{id: ticketID, payer: payer})
	if err != nil {
		return err
	}
	_, err = n.chain.Send(ctx, []solana.Instruction{n.chain.Deployment.SettleLapsed(end)}, n.signing)
	return err
}

func (n *Node) settleAck(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "read_body", err.Error())
		return
	}
	ack, err := wire.OpenSettleAck(raw, n.identity)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_settle_ack", err.Error())
		return
	}
	e := n.lookup(ack.TicketID)
	var receipt *ticket.UsageReceipt
	var openSeq uint64
	if e != nil {
		n.mu.Lock()
		receipt, openSeq = e.receipt, e.openSeq
		n.mu.Unlock()
	}
	if receipt == nil {
		writeError(w, http.StatusNotFound, "settle_ack_unknown_ticket", "no receipt for this ticket")
		return
	}
	if n.behaviorFor(e.payer).OverClaim > 0 {
		writeError(w, http.StatusConflict, "settle_ack_rejected", "the stub refuses acks while over-claiming")
		return
	}
	sig, err := zsescrow.DecodeAckSignature(ack.SettleGroup)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_settle_ack", err.Error())
		return
	}
	d := n.chain.Deployment
	fields := zsescrow.ClaimFromReceipt(receipt)
	ticketKey := d.Ticket(d.Node(n.operatorID, n.nodeID), e.id)
	digest := d.AckDigest(n.chain.Genesis, ticketKey, openSeq, zsescrow.ClaimHash(fields))
	if !solana.VerifyStrict(e.payer, digest[:], sig) {
		writeError(w, http.StatusBadRequest, "settle_ack_mismatch", "the ack does not sign this ticket's receipt")
		return
	}
	// The route answers once the settle is sent; the confirmation is the
	// stub's to watch, as a node's driver watches it. Bounded, so a stalled
	// RPC fails the ack rather than holding it past the payer's budget.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 30*time.Second)
	defer cancel()
	end, err := n.ending(ctx, e)
	if err != nil {
		writeError(w, http.StatusConflict, "settle_ack_too_late", err.Error())
		return
	}
	ixs := []solana.Instruction{solana.Ed25519Verify(e.payer, sig, digest[:]), d.SettleCooperative(end, fields)}
	bh, err := n.chain.RPC.GetLatestBlockhash(ctx, rpc.Confirmed)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "rpc_unavailable", err.Error())
		return
	}
	m, err := solana.Compile(PublicKey(n.signing), bh.Hash, ixs, solana.Legacy)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	tx := solana.NewTransaction(m)
	if err := tx.Sign(n.signing); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	txRaw, _ := tx.MarshalBinary()
	txSig, err := n.chain.RPC.SendTransaction(ctx, txRaw, rpc.SendOptions{PreflightCommitment: rpc.Processed})
	if err != nil {
		writeError(w, http.StatusConflict, "settle_ack_rejected", err.Error())
		return
	}
	w.WriteHeader(http.StatusAccepted)
	go func() {
		cctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		res, err := rpc.Confirm(cctx, n.chain.RPC, txSig, bh.LastValidBlockHeight, rpc.Confirmed, rpc.ConfirmOptions{Poll: 200 * time.Millisecond})
		switch {
		case err != nil:
			n.fail(e.payer, fmt.Errorf("solanastub: settle %s: %w", txSig, err))
		case res.Err != nil:
			n.fail(e.payer, fmt.Errorf("solanastub: settle %s landed and failed: %s", txSig, res.Err))
		}
	}()
}
