/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/TxnLab/zerosignal/go/ticket"
)

// emitter receives what a dispatch produces. Dispatch decides what happened;
// the emitter turns it into the caller's view, which for a Stream is its
// event sequence.
//
// A request ends in exactly one of: fail, reply, or open followed by frames
// (and interrupt if the stream breaks). clamped, reserved, committed and note
// may precede any of them.
type emitter interface {
	// note reports a routing milestone. It never ends the request.
	note(ev Event)
	// clamped reports that the request's max_output was lowered to ceiling.
	clamped(ceiling uint64)
	// reserved reports the ticket a node signed.
	reserved(rt *ReservedTicket, op Operator)
	// committed reports the escrow open; nothing is resent after it. A free
	// Solana turn reports it with no open (openTxID empty) once it is sealed,
	// and that does not make the turn paid: nothing was locked.
	committed(ticketID, openTxID string, networkFees uint64)
	// fail ends the request with e before any response has started.
	fail(e *Error)
	// reply delivers a complete response. header is the node's response
	// header set; usage is nil when the node sent no readable receipt.
	reply(status int, header http.Header, body []byte, usage *usageReport)
	// open starts a stream. A non-nil error means it could not start and the
	// caller has already been told.
	open(status int, header http.Header) error
	// frame delivers one stream frame and returns its size on the wire, for
	// the stream tally; a usage report is not a frame and counts 0.
	frame(f outFrame) (int, error)
	// interrupt ends an open stream that broke before its end; cause, when
	// known, is the stream_interrupted error's Err.
	interrupt(cause error)
}

type noteKey struct{}

// withNote carries a turn's emitter note to the reserve retry, which runs
// below dispatch and has no emitter of its own.
func withNote(ctx context.Context, note func(Event)) context.Context {
	return context.WithValue(ctx, noteKey{}, note)
}

// noteFrom is ctx's note, or one that drops the event.
func noteFrom(ctx context.Context) func(Event) {
	if note, ok := ctx.Value(noteKey{}).(func(Event)); ok && note != nil {
		return note
	}
	return func(Event) {}
}

// withoutNote is ctx for work that can outlive the turn's events, such as a
// settle submitted after the reply: the emitter can no longer take an event
// then, and is not safe to call from another goroutine.
func withoutNote(ctx context.Context) context.Context { return withNote(ctx, nil) }

func routeCandidates(model string, ops []Operator) RouteCandidates {
	refs := make([]NodeRef, len(ops))
	for i, op := range ops {
		refs[i] = RefOf(op)
	}
	return RouteCandidates{Model: model, Candidates: refs}
}

// relayOf is the relay a hop rides, nil for a direct connection.
func relayOf(hop *RelayHop) *NodeRef {
	if hop == nil {
		return nil
	}
	r := hop.RelayRef()
	return &r
}

// usageReport is what the payer is told about a turn's receipt, and, on a
// stream, the settle submitted before done.
type usageReport struct {
	receipt      *ticket.UsageReceipt
	ticket       *ticket.Ticket
	op           Operator
	openFees     uint64
	settleFees   uint64
	algoUSDPrice float64
	unit         FeeUnit
	feeBps       uint64
	haveFee      bool
	// check is how the receipt fared and what its submit did.
	check receiptCheck
}

// events are the report in the order the payer hears it.
func (u *usageReport) events() []Event {
	c := u.check
	if c.violation != "" {
		v := ReceiptViolated{Violation: c.violation}
		if c.settled.Kind == SettleProtest {
			v.ProtestTxID = c.settled.TxID
		}
		evs := []Event{v}
		if c.excluded {
			evs = append(evs, NodeExcluded{Node: RefOf(u.op), Reason: c.exclusion})
		}
		return evs
	}
	evs := []Event{u.verified()}
	if c.excluded {
		evs = append(evs, NodeExcluded{Node: RefOf(u.op), Reason: c.exclusion})
	}
	if c.settled.TxID != "" {
		evs = append(evs, SettleSubmitted{
			TicketID:       u.ticket.TicketID,
			TxID:           c.settled.TxID,
			FeesMicroAlgos: c.settled.FeesMicroAlgos,
			Atomic:         c.settled.Kind == SettleAtomic,
			NetworkFees:    c.settled.NetworkFees,
			Frozen:         c.settled.Frozen,
		})
	}
	return evs
}

func (u *usageReport) verified() ReceiptVerified {
	return ReceiptVerified{
		Receipt:              *u.receipt,
		Ticket:               *u.ticket,
		Target:               RefOf(u.op),
		OwnerAddr:            u.op.OwnerAddr,
		OpenFeesMicroAlgos:   algoOnly(u.unit, u.openFees),
		SettleFeesMicroAlgos: algoOnly(u.unit, u.settleFees),
		AlgoUSD:              algoOnly(u.unit, u.algoUSDPrice),
		FeeBps:               u.feeBps,
		FeeBpsKnown:          u.haveFee,
		OpenNetworkFees:      u.openFees,
		SettleNetworkFees:    u.settleFees,
		// The reserve's rate is ALGO/USD (ticket.ReserveResponse.AlgoUSDPrice),
		// so it prices no other coin.
		NativeUSD: algoOnly(u.unit, u.algoUSDPrice),
		FeeUnit:   u.unit,
	}
}

// NodeReply is a node's own error response, kept as the cause of an Error so
// an adapter can answer its caller with the node's status and body rather than
// one of its own. Header excludes the node's X-Zs-* fields.
type NodeReply struct {
	Status int
	Header http.Header
	Body   []byte
	// ContentType replaces the node's when Body is one the SDK wrote in place
	// of a body it could not parse.
	ContentType string
}

func (r *NodeReply) Error() string {
	return fmt.Sprintf("operator returned HTTP %d", r.Status)
}

// streamEmitter is the emitter behind Stream.Events: each call becomes events
// handed to the range loop's yield. A loop that stops ranging is a caller who
// left, so it cancels the dispatch context, which the forwarder already reads
// as a disconnect (drain the receipt tail if generation completed, cancel the
// upstream if not); from then on events are dropped.
type streamEmitter struct {
	yield  func(Event, error) bool
	cancel context.CancelFunc
	// callerCtx is the context the caller passed: a turn it ended is not one
	// to retry.
	callerCtx context.Context
	// dec decodes sealed frames into content events; nil for FramesOnly.
	dec *decoder
	// unit is the coin the deployment's network fees are paid in.
	unit FeeUnit

	stopped bool
	// ended is set once the turn's one ending, Done or an error, is decided;
	// nothing later can change it.
	ended  bool
	ticket *Ticket
	paid   bool
	err    *Error
}

// emit hands ev to the caller unless it has already stopped ranging.
func (e *streamEmitter) emit(ev Event) bool {
	if e.stopped {
		return false
	}
	if !e.yield(ev, nil) {
		e.stopped = true
		e.cancel()
		return false
	}
	return true
}

// end delivers the terminal error, and decides whether it is Retryable here,
// once, for every way a turn can fail. Once the request is paid, the error
// says so and names the ticket, because nothing is resent after the open.
func (e *streamEmitter) end(err *Error) {
	if e.ended {
		return
	}
	e.ended = true
	err.Retryable = retryable(err) && (e.callerCtx == nil || e.callerCtx.Err() == nil)
	if e.paid {
		err.Paid = true
		if err.Ticket == nil {
			err.Ticket = e.ticket
		}
	}
	e.err = err
	if !e.stopped {
		e.stopped = true
		e.yield(nil, err)
	}
}

func (e *streamEmitter) note(ev Event) { e.emit(ev) }

func (e *streamEmitter) clamped(ceiling uint64) { e.emit(MaxOutputClamped{Ceiling: ceiling}) }

func (e *streamEmitter) reserved(rt *ReservedTicket, op Operator) {
	t := rt.Ticket
	e.ticket = &Ticket{ID: t.TicketID, Signed: *t, Target: RefOf(op)}
	e.emit(ReserveSucceeded{
		TicketID:  t.TicketID,
		Target:    RefOf(op),
		MaxPrice:  t.MaxPrice,
		ExpiresAt: time.Unix(t.ExpiresAt, 0),
	})
}

func (e *streamEmitter) committed(ticketID, openTxID string, networkFees uint64) {
	// Paid says money is locked and a Ticket can still move it; a free
	// Solana turn locked none, and a resend of it costs nothing.
	e.paid = openTxID != ""
	e.emit(PaymentCommitted{TicketID: ticketID, OpenTxID: openTxID, FeesMicroAlgos: algoOnly(e.unit, networkFees), NetworkFees: networkFees})
}

func (e *streamEmitter) fail(err *Error) { e.end(err) }

func (e *streamEmitter) reply(status int, header http.Header, body []byte, usage *usageReport) {
	if !e.emit(ResponseStarted{Status: status, Header: nodeHeader(header)}) {
		return
	}
	if !e.emit(Frame{Data: body, Sealed: true}) {
		return
	}
	if e.dec != nil && !e.emitAll(e.dec.body(body)) {
		return
	}
	if usage != nil && !e.emitAll(usage.events()) {
		return
	}
	if e.dec != nil && status >= http.StatusBadRequest && e.dec.failure == nil {
		// A sealed reply the node marked failed, in a body that does not say
		// why, is not a finished answer.
		e.dec.failure = &Error{
			Kind:    KindUpstream,
			Code:    "upstream_error",
			Message: fmt.Sprintf("the node answered HTTP %d", status),
			Err:     &NodeReply{Status: status, Header: nodeHeader(header), Body: body},
		}
	}
	if e.dec != nil && e.dec.failure != nil && status >= http.StatusBadRequest {
		e.dec.failure.RetryAfter = NodeRetryAfter(header)
		if pe, ok := e.dec.failure.Err.(*ProviderError); ok {
			pe.Status = status
		}
	}
	e.finish()
}

// emitAll hands evs to the caller in order, stopping if it stops ranging.
func (e *streamEmitter) emitAll(evs []Event) bool {
	for _, ev := range evs {
		if !e.emit(ev) {
			return false
		}
	}
	return true
}

// finish ends a response that is over: a whole reply, or a stream once the
// forwarder returns. The receipt has been handled by then, so a failed turn is
// still settled at what the node charged. The decoder decides between Done
// and an error from the node's sealed frames alone.
func (e *streamEmitter) finish() {
	if e.ended {
		return
	}
	if e.dec == nil {
		e.ended = true
		e.emit(Done{})
		return
	}
	done, err := e.dec.outcome()
	if err != nil {
		e.end(err)
		return
	}
	e.ended = true
	e.emit(done)
}

func (e *streamEmitter) open(status int, header http.Header) error {
	e.emit(ResponseStarted{Status: status, Header: nodeHeader(header), Streaming: true})
	return nil
}

func (e *streamEmitter) frame(out outFrame) (int, error) {
	if out.usage != nil {
		e.emitAll(out.usage.events())
		return 0, nil
	}
	f := out.frame
	n := len(f.SSE())
	if e.emit(f) && f.Sealed && e.dec != nil {
		e.emitAll(e.dec.frame(f.Data))
	}
	return n, nil
}

// interrupt ends a stream that broke. A failure the node already reported is
// the better account of why, so it wins.
func (e *streamEmitter) interrupt(cause error) {
	if e.dec != nil && e.dec.failure != nil {
		e.end(e.dec.failure)
		return
	}
	err := newError("stream_interrupted", "the stream broke before its end")
	err.Err = cause
	e.end(err)
}
