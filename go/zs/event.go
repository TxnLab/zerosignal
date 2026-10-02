/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"encoding/json"
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

// HopReason says why a RelayHop event fired.
type HopReason string

const (
	HopChosen  HopReason = "chosen"
	HopRotated HopReason = "rotated"
)

// RelayHop fires when the SDK picks a relay, and again on each pre-payment
// rotation. Relay is nil for a direct connection, which only happens under
// PrivacyDirect.
type RelayHop struct {
	Relay  *NodeRef
	Target NodeRef
	Reason HopReason
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

// Item is one output item of the response (a message, reasoning block,
// function call, image or built-in tool call), as the node's sealed frames
// describe it. Raw is the item's JSON for fields the SDK does not model.
type Item struct {
	ID   string
	Type string
	Raw  json.RawMessage
}

type ItemOpened struct{ Item Item }
type ItemClosed struct{ Item Item }

type TextDelta struct {
	ItemID string
	Delta  string
}

type ReasoningDelta struct {
	ItemID string
	Delta  string
}

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
type ToolStatus struct {
	CallID string
	Name   string
	State  ToolState
	Action json.RawMessage
	Icons  []string
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

// Usage reports token counts as the stream carries them. The billed figures
// are the receipt's, in ReceiptVerified.
type Usage struct {
	InputTokens     uint64
	OutputTokens    uint64
	ReasoningTokens uint64
	Source          string
}

// ReceiptVerified fires once, before done, when the node's signed receipt
// checks out against the ticket and the content delivered.
type ReceiptVerified struct {
	Receipt ticket.UsageReceipt
}

// ReceiptViolated replaces ReceiptVerified when a check fails. ProtestTxID is
// set only for a body_hash violation: the contract rejects sig and amount
// protests, so those are recorded and logged only.
type ReceiptViolated struct {
	Violation   string
	ProtestTxID string
}

// SettleSubmitted and SettleConfirmed run on a context the caller's cancel
// cannot reach, so they can arrive after Done. Atomic is false when the SDK
// fell back to a standalone payer ack.
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

// Done fires at the node's [DONE]. Empty is set when no content arrived.
type Done struct {
	FinishReason     string
	IncompleteReason string
	Empty            bool
}

func (RouteCandidates) EventType() string  { return "route.candidates" }
func (RelayHop) EventType() string         { return "relay.hop" }
func (ReserveStarted) EventType() string   { return "reserve.started" }
func (ReserveRetrying) EventType() string  { return "reserve.retrying" }
func (ReserveSucceeded) EventType() string { return "reserve.succeeded" }
func (PaymentCommitted) EventType() string { return "payment.committed" }
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
func (RelayHop) event()         {}
func (ReserveStarted) event()   {}
func (ReserveRetrying) event()  {}
func (ReserveSucceeded) event() {}
func (PaymentCommitted) event() {}
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
