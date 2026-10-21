/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/TxnLab/zerosignal/go/ticket"
)

// ReceiptCheck is the three-part verification the proxy runs on every
// UsageReceipt. One helper so the non-stream responder and the
// stream-end responder run the exact same checks in the same order
// and produce consistent error surfaces (and the same dispute
// trigger).
//
//   - Sig verifies under the operator's SigningAddr ed25519 pubkey, and
//     the receipt names the payer's ticket.
//   - AmountCharged ≤ ticket.MaxPrice (the contract enforces this too,
//     but we fail fast and with a clean error).
//   - BodyHash equals sha256 of the plaintext the proxy just
//     reconstructed. Mismatch is cryptographic evidence the operator
//     signed for content it didn't deliver (SPEC.md § 3b case (e))
//     and drives escrow.protest in step 8.
type ReceiptCheck struct {
	Ticket       *ticket.Ticket
	Operator     Operator
	Receipt      *ticket.UsageReceipt
	ComputedHash [32]byte // sha256 of the plaintext body / concatenated stream frames
}

// ReceiptViolation enumerates the three failure modes VerifyReceipt
// can surface. Used by callers to decide logging level and (step 8)
// whether to drive escrow.protest.
type ReceiptViolation int

const (
	ReceiptOK                ReceiptViolation = iota // no violation
	ReceiptViolationSig                              // signature invalid, or the receipt names another ticket
	ReceiptViolationAmount                           // amount_charged > max_price, or a self-inconsistent billing count (cached_input_count > actual_input_count)
	ReceiptViolationBodyHash                         // body_hash != computed
)

// String renders the violation as a stable lowercase tag suitable for
// structured-log fields and metric labels. Keeps the wire/log surface
// readable without leaking the underlying iota value.
func (v ReceiptViolation) String() string {
	switch v {
	case ReceiptOK:
		return "ok"
	case ReceiptViolationSig:
		return "sig"
	case ReceiptViolationAmount:
		return "amount"
	case ReceiptViolationBodyHash:
		return "body_hash"
	default:
		return "unknown"
	}
}

// ReceiptError wraps the underlying error plus a classification so
// callers can distinguish "operator misbehaved" (protest material)
// from "receipt corrupted in transit" (retry / reject).
type ReceiptError struct {
	Violation ReceiptViolation
	Err       error
}

func (e *ReceiptError) Error() string {
	return e.Err.Error()
}

func (e *ReceiptError) Unwrap() error { return e.Err }

// VerifyReceipt runs the three checks. Returns nil on happy path, a
// *ReceiptError on any violation.
func VerifyReceipt(c ReceiptCheck) error {
	if c.Receipt == nil {
		return &ReceiptError{
			Violation: ReceiptViolationSig,
			Err:       errors.New("receipt is nil"),
		}
	}
	if len(c.Operator.TicketSigningKey) != ed25519.PublicKeySize {
		return &ReceiptError{
			Violation: ReceiptViolationSig,
			Err:       fmt.Errorf("operator signing key length %d, want %d", len(c.Operator.TicketSigningKey), ed25519.PublicKeySize),
		}
	}
	if c.Ticket == nil {
		return &ReceiptError{
			Violation: ReceiptViolationSig,
			Err:       errors.New("no ticket to bind the receipt to"),
		}
	}
	// A receipt is bound exactly when its ticket is, and to the same
	// deployment; the ticket's binding was checked against ours at reserve.
	want := c.Ticket.Deployment
	if err := c.Receipt.VerifyFor(c.Operator.TicketSigningKey, want, want.IsZero()); err != nil {
		return &ReceiptError{
			Violation: ReceiptViolationSig,
			Err:       fmt.Errorf("receipt signature verify: %w", err),
		}
	}
	// The signature holds for whichever ticket the receipt names, so a node can
	// hand over one it signed for another ticket. Classed with the signature,
	// as the node signed nothing for this ticket: none of the receipt's figures
	// is pinned or journaled, and no protest goes out. Solana's program refuses
	// a protest over another ticket's receipt; Algorand's refuses it against a
	// pending claim with another digest, and otherwise freezes this ticket on
	// evidence about another. Ahead of the amount and body_hash checks, which
	// would otherwise pin the figure or protest.
	if err := receiptNamesTicket(c.Receipt.TicketID, c.Ticket.TicketID); err != nil {
		return &ReceiptError{Violation: ReceiptViolationSig, Err: err}
	}
	if c.Receipt.AmountCharged > c.Ticket.MaxPrice {
		return &ReceiptError{
			Violation: ReceiptViolationAmount,
			Err:       fmt.Errorf("receipt amount_charged %d exceeds ticket max_price %d", c.Receipt.AmountCharged, c.Ticket.MaxPrice),
		}
	}
	// Cached-read count is a subset of the input (SPEC §3a). A signed but
	// self-inconsistent receipt (cached > actual input) is operator
	// misbehaviour — mirror the node-side buildReceipt invariant so a buggy /
	// malicious operator can't slip a malformed billing tuple past the proxy.
	// Log-only (no protest): there's no body_hash dispute here, and the
	// contract settles on the digest regardless.
	if c.Receipt.CachedInputCount > c.Receipt.ActualInputCount {
		return &ReceiptError{
			Violation: ReceiptViolationAmount,
			Err:       fmt.Errorf("receipt cached_input_count %d exceeds actual_input_count %d", c.Receipt.CachedInputCount, c.Receipt.ActualInputCount),
		}
	}
	gotHash, err := c.Receipt.BodyHashBytes()
	if err != nil {
		return &ReceiptError{
			Violation: ReceiptViolationBodyHash,
			Err:       fmt.Errorf("receipt body_hash malformed: %w", err),
		}
	}
	if gotHash != c.ComputedHash {
		return &ReceiptError{
			Violation: ReceiptViolationBodyHash,
			Err:       fmt.Errorf("receipt body_hash mismatch (got %x want %x)", gotHash, c.ComputedHash),
		}
	}
	return nil
}

// receiptNamesTicket refuses a receipt that doesn't name the payer's ticket.
// The receipt's id is compared as the string the node signed against the
// canonical spelling of the bytes the payer opened, as the open offer's fold
// compares, so no decoder's leniency makes two spellings of one id agree. The
// ticket's own id must be that spelling too: Go's decoder takes non-zero
// padding bits and TS's doesn't, so without it the two SDKs would accept
// different receipts for one ticket.
func receiptNamesTicket(receiptID, ticketID string) error {
	raw, err := decodeTicketID(ticketID)
	if err != nil {
		return fmt.Errorf("the payer's ticket id: %w", err)
	}
	want := base64.StdEncoding.EncodeToString(raw)
	if ticketID != want {
		return fmt.Errorf("the payer's ticket id %q is not the canonical spelling %q", ticketID, want)
	}
	if receiptID != want {
		return fmt.Errorf("the receipt names ticket %q, not the payer's %q", receiptID, want)
	}
	return nil
}

// AsReceiptError unwraps err into its *ReceiptError, if any. Thin
// convenience for log-path callers that want the classification.
func AsReceiptError(err error) (*ReceiptError, bool) {
	if err == nil {
		return nil, false
	}
	if re, ok := errors.AsType[*ReceiptError](err); ok {
		return re, true
	}
	return nil, false
}
