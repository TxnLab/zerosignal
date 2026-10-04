/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/transient"
)

// Event is one element of a Stream's ordered sequence. Content deltas and
// payment milestones share the sequence so their relative order survives:
// a consumer can tell which text arrived before payment.committed and which
// after. Switch on the concrete type; EventType is the dotted name the
// TypeScript SDK uses as its discriminant.
//
// The set is closed: only this package implements Event.
//
// Some types are declared ahead of the code that emits them: RouteCandidates,
// RelayHopChanged, ReserveStarted, ReserveRetrying, ReceiptViolated,
// SettleSubmitted, SettleConfirmed and NodeExcluded are not yet emitted.
type Event interface {
	EventType() string
	event()
}

// RouteCandidates fires once per sweep with the ordered targets the sweep
// will try.
type RouteCandidates struct {
	Model      string
	Candidates []NodeRef
	// SizeMisses are nodes serving Model that the request does not fit
	// (context window or output reservation).
	SizeMisses []NodeRef
}

// RelayHopReason says why a RelayHopChanged event fired.
type RelayHopReason string

const (
	RelayHopChosen  RelayHopReason = "chosen"
	RelayHopRotated RelayHopReason = "rotated"
)

// RelayHopChanged fires when the SDK picks a relay, and again on each
// pre-payment rotation. Relay is nil for a direct connection, which only
// happens under PrivacyDirect.
type RelayHopChanged struct {
	Relay  *NodeRef
	Target NodeRef
	Reason RelayHopReason
}

// ReserveStarted fires on each reserve attempt.
type ReserveStarted struct {
	Target  NodeRef
	Relay   *NodeRef
	Attempt int
}

// ReserveRetrying fires before a busy or transient retry, which only ever
// happens before payment.
type ReserveRetrying struct {
	Target      NodeRef
	Code        string
	Attribution transient.Attribution
	Wait        time.Duration
	Attempt     int
}

// ReserveSucceeded fires once, when a node issues a signed ticket.
type ReserveSucceeded struct {
	TicketID  string
	Target    NodeRef
	MaxPrice  uint64 // microUSDC
	ExpiresAt time.Time
}

// PaymentCommitted fires once, when the escrow open confirms. Nothing is
// resent after it: a later failure ends in settle, protest or refund.
type PaymentCommitted struct {
	TicketID       string
	OpenTxID       string
	FeesMicroAlgos uint64
}

// MaxOutputClamped fires before any reserve when the request asked for more
// output than the routable nodes allow, and was lowered to Ceiling rather than
// refused.
type MaxOutputClamped struct {
	Ceiling uint64
}

// ResponseStarted fires once, when the node answers. Header is the node's
// response header set without its X-Zs-* fields, which are protocol plumbing
// rather than part of the response. Streaming is false for a single-body
// reply, which then arrives as one Frame.
type ResponseStarted struct {
	Status    int
	Header    http.Header
	Streaming bool
}

// Frame is one Server-Sent Event of the node's response, as an
// OpenAI-compatible endpoint would have written it, so an adapter can re-emit
// the original bytes (Frame.SSE). Sealed frames were decrypted from the node's
// sealed stream; the rest (the `[DONE]` sentinel, keepalive comments) pass
// through as the node sent them. A non-streaming response is one sealed Frame
// holding the whole body. The content events decoded from a sealed Frame
// follow it, unless the Request set FramesOnly.
type Frame struct {
	Event   string
	ID      string
	Data    []byte
	Comment string
	Retry   int
	Sealed  bool
}

func (f Frame) isEmpty() bool {
	return len(f.Data) == 0 && f.Event == "" && f.ID == "" && f.Retry == 0 && f.Comment == ""
}

// Item is one output item of a /v1/responses reply (a message, reasoning
// block, function call, image or built-in tool call), as the node's sealed
// frames describe it. Raw is the item's JSON for fields the SDK does not
// model. Chat Completions has no items, so a chat turn yields none, and its
// deltas carry no ItemID.
type Item struct {
	ID   string
	Type string
	Raw  json.RawMessage
}

type ItemOpened struct{ Item Item }
type ItemClosed struct{ Item Item }

// TextDelta is a piece of the answer text. A non-streaming reply yields each
// text part whole, as one delta.
type TextDelta struct {
	ItemID string
	Delta  string
}

// ReasoningDelta is a piece of the model's reasoning, or of its summary.
type ReasoningDelta struct {
	ItemID string
	Delta  string
}

// ToolCallDelta is a piece of a function call's arguments. CallID and Name
// are repeated on every delta of the call.
type ToolCallDelta struct {
	ItemID         string
	CallID         string
	Name           string
	ArgumentsDelta string
}

// AnnotationAdded carries a citation or similar annotation on a text item.
type AnnotationAdded struct {
	ItemID     string
	Annotation json.RawMessage
}

// ToolState is a built-in (zs_*) tool call's progress.
type ToolState string

const (
	ToolInProgress ToolState = "in_progress"
	ToolCompleted  ToolState = "completed"
)

// ToolStatus reports a built-in tool the node runs on the caller's behalf.
// Action is the node's description of what the tool did, without its icons;
// Icons are the sources' favicons by host, as data URLs, limited in number,
// size and type (no SVG) because the node chooses their bytes.
type ToolStatus struct {
	CallID string
	Name   string
	State  ToolState
	Action json.RawMessage
	Icons  map[string]string
}

type ImageProgress struct {
	ItemID string
	Value  int
	Max    int
}

type ImagePartial struct {
	ItemID string
	B64    string
	MIME   string
}

// Usage reports token counts as the response carries them; Source is
// "response". Counts are running totals, so a later Usage replaces an earlier
// one rather than adding to it. The billed figures are the receipt's, in
// ReceiptVerified.
type Usage struct {
	InputTokens     uint64
	OutputTokens    uint64
	ReasoningTokens uint64
	Source          string
}

// ReceiptVerified fires once, before done, when the node's signed receipt
// checks out against the ticket and the content delivered. The fee fields are
// the payer's own: what it paid in ALGO network fees for the open and, on a
// stream, the settle, which a non-streaming reply reports as 0 because the
// settle is submitted after the reply.
//
// Until ReceiptViolated is emitted, a stream whose receipt failed its checks
// ends with this event too, and SettleFeesMicroAlgos is then the protest's
// fee.
type ReceiptVerified struct {
	Receipt ticket.UsageReceipt
	// Ticket is the signed ticket the receipt settles; its MaxPrice and
	// MinPrice bound the charge.
	Ticket ticket.Ticket
	Target NodeRef
	// OwnerAddr is the operator's owner account.
	OwnerAddr            string
	OpenFeesMicroAlgos   uint64
	SettleFeesMicroAlgos uint64
	// AlgoUSD is the ALGO/USD rate the reserve priced at; 0 when unknown.
	AlgoUSD float64
	// FeeBps is the protocol fee rate on top of the operator's charge, valid
	// only when FeeBpsKnown: the rate is read from chain in the background and
	// is unknown until that read first succeeds.
	FeeBps      uint64
	FeeBpsKnown bool
}

// ReceiptViolated replaces ReceiptVerified when a check fails. ProtestTxID is
// set only for a body_hash violation: the contract rejects sig and amount
// protests, so those are recorded and logged only.
type ReceiptViolated struct {
	Violation   string
	ProtestTxID string
}

// SettleSubmitted and SettleConfirmed are not emitted yet. Until they are,
// Stream.Wait reports the submit, including one that ends after the Events
// loop, where no event could carry it. Atomic is false when the SDK fell back
// to a standalone payer ack.
type SettleSubmitted struct {
	TicketID       string
	TxID           string
	FeesMicroAlgos uint64
	Atomic         bool
}

type SettleConfirmed struct {
	TicketID       string
	TxID           string
	FeesMicroAlgos uint64
	Atomic         bool
	Round          uint64
}

// NodeExcluded fires when the node's pre-signed settle group fails
// verification. The node is barred for the rest of the process.
type NodeExcluded struct {
	Node   NodeRef
	Reason string
}

// Done is the last event of a turn whose response the node sealed as finished:
// a chat finish_reason, a Responses completed or incomplete event, or a whole
// reply. The stream's plaintext [DONE] decides nothing, since a relay can add
// or drop it; a response that ends without the node's word is a
// stream_interrupted *Error. One the node reports failed ends in a
// KindUpstream *Error. Either error replaces Done.
//
// FinishReason is the dialect's own: a chat finish_reason ("stop", "length",
// "tool_calls") or a response status ("completed", "incomplete").
// IncompleteReason is set for an incomplete response. Empty means the turn
// produced no answer: no text that is not blank, no refusal, no tool call and
// no image. Reasoning alone is not an answer, so a model that stopped
// mid-thought ends Empty.
//
// With Request.FramesOnly nothing is decoded, so Done carries no fields and
// fires whenever the response ends.
type Done struct {
	FinishReason     string
	IncompleteReason string
	Empty            bool
}

func (RouteCandidates) EventType() string  { return "route.candidates" }
func (RelayHopChanged) EventType() string  { return "relay.hop" }
func (ReserveStarted) EventType() string   { return "reserve.started" }
func (ReserveRetrying) EventType() string  { return "reserve.retrying" }
func (ReserveSucceeded) EventType() string { return "reserve.succeeded" }
func (PaymentCommitted) EventType() string { return "payment.committed" }
func (MaxOutputClamped) EventType() string { return "max_output.clamped" }
func (ResponseStarted) EventType() string  { return "response.started" }
func (Frame) EventType() string            { return "frame" }
func (ItemOpened) EventType() string       { return "item.opened" }
func (ItemClosed) EventType() string       { return "item.closed" }
func (TextDelta) EventType() string        { return "delta.text" }
func (ReasoningDelta) EventType() string   { return "delta.reasoning" }
func (ToolCallDelta) EventType() string    { return "delta.tool_call" }
func (AnnotationAdded) EventType() string  { return "annotation.added" }
func (ToolStatus) EventType() string       { return "tool.status" }
func (ImageProgress) EventType() string    { return "image.progress" }
func (ImagePartial) EventType() string     { return "image.partial" }
func (Usage) EventType() string            { return "usage" }
func (ReceiptVerified) EventType() string  { return "receipt.verified" }
func (ReceiptViolated) EventType() string  { return "receipt.violated" }
func (SettleSubmitted) EventType() string  { return "settle.submitted" }
func (SettleConfirmed) EventType() string  { return "settle.confirmed" }
func (NodeExcluded) EventType() string     { return "node.excluded" }
func (Done) EventType() string             { return "done" }

func (RouteCandidates) event()  {}
func (RelayHopChanged) event()  {}
func (ReserveStarted) event()   {}
func (ReserveRetrying) event()  {}
func (ReserveSucceeded) event() {}
func (PaymentCommitted) event() {}
func (MaxOutputClamped) event() {}
func (ResponseStarted) event()  {}
func (Frame) event()            {}
func (ItemOpened) event()       {}
func (ItemClosed) event()       {}
func (TextDelta) event()        {}
func (ReasoningDelta) event()   {}
func (ToolCallDelta) event()    {}
func (AnnotationAdded) event()  {}
func (ToolStatus) event()       {}
func (ImageProgress) event()    {}
func (ImagePartial) event()     {}
func (Usage) event()            {}
func (ReceiptVerified) event()  {}
func (ReceiptViolated) event()  {}
func (SettleSubmitted) event()  {}
func (SettleConfirmed) event()  {}
func (NodeExcluded) event()     {}
func (Done) event()             {}
