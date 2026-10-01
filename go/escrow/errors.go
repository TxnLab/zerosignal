/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package escrow

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
)

// The assert/err strings ZeroSignalEscrow.algo.ts compiles into its approval
// program, exported so a caller classifies a revert against a named constant
// instead of a string literal copied out of the contract. Every one of them is
// pinned to the embedded ARC-56 by TestApprovalAssertConstants_ExistInARC56, so
// a contract reword turns into a red test here rather than a classifier that
// silently stops matching in production.
//
// Not every assert needs a constant — only the ones an off-chain caller acts
// on. Add one when a caller starts caring, and add the sentinel below too if
// the caller wants errors.Is rather than a Message comparison.
const (
	AssertTicketNotFound            = "ticket not found"
	AssertSettleAfterRefundDeadline = "settle after refund deadline"
	AssertTicketNotSettleable       = "ticket not settleable"

	// The three settleLapsed guards. The operator's settlement driver routes
	// on all three, and each means something different about a lapsed ticket.
	AssertTicketNotPendingSettle     = "ticket not pending settle"
	AssertTooEarlyToLapseSettle      = "too early to lapse settle"
	AssertOnlyOperatorClaimsCanLapse = "only operator claims can lapse into settle"

	// The three open() guards on the payer's prepaid ticket-MBR pool. All
	// three mean the same thing to the proxy — the pool can't back another
	// ticket box — but they name different terms of the shortfall, so they
	// stay distinct constants and the proxy lists all three at its call site.
	AssertInsufficientMbrDeposit          = "insufficient MBR deposit"
	AssertInsufficientMbrDepositFreeQuota = "insufficient MBR deposit for free-quota box"
	AssertPayerHasNoMbrDeposit            = "payer has no MBR deposit"
)

// ErrTicketNotFound is returned (wrapped) when the contract reverts
// because the ticket box doesn't exist on-chain. The most common
// trigger is the payer's `open()` call having been observed in the
// mempool but never confirmed (e.g. balance shifted between
// admission and block-production), so the operator's settle finds
// no box to settle against. Match with errors.Is — the algod error
// string is wrapped via %w so callers don't need to substring-match
// on the underlying message.
var ErrTicketNotFound = errors.New("escrow: " + AssertTicketNotFound)

// ErrSettleAfterRefundDeadline is returned (wrapped) when settle()
// reverts because the refund deadline (ticket.expiresAt +
// settlementGraceSeconds) has already passed. No amount of retrying
// changes that — the box has aged out of settle()'s window and only
// settleLapsed (operator-pending claim) or refundInactive (no claim,
// or payer-pending) can finalize it now. Callers should fail fast and
// surface the deadline-miss in their logs.
var ErrSettleAfterRefundDeadline = errors.New("escrow: " + AssertSettleAfterRefundDeadline)

// ErrTicketNotSettleable is returned (wrapped) when settle() reverts
// because the ticket is not in STATUS_OPEN or STATUS_PENDING_SETTLE —
// in practice this means the payer has called protest() and the box is
// now STATUS_FROZEN. The contract has no path back out of FROZEN, so
// retrying settle() can never succeed; off-chain arbitration is the
// only forward path. Callers should fail fast, escalate the FROZEN
// signal in logs/ops tooling, and stop consuming retry budget.
var ErrTicketNotSettleable = errors.New("escrow: " + AssertTicketNotSettleable)

// ErrTicketNotPendingSettle is returned (wrapped) when settleLapsed()
// reverts because the box exists but its status has moved out of
// STATUS_PENDING_SETTLE — almost always STATUS_FROZEN, i.e. the payer
// answered with a disagreeing settle() or a protest(). The lapse can
// never land now; the ticket belongs to off-chain arbitration.
var ErrTicketNotPendingSettle = errors.New("escrow: " + AssertTicketNotPendingSettle)

// ErrTooEarlyToLapseSettle is returned (wrapped) when settleLapsed()
// reverts because the block timestamp has not yet passed the box's
// D = expires_at + settlement_grace_seconds. The only retry class in
// this family that is worth waiting on — and the box itself carries
// the authoritative deadline to wait until.
var ErrTooEarlyToLapseSettle = errors.New("escrow: " + AssertTooEarlyToLapseSettle)

// ErrOnlyOperatorClaimsCanLapse is returned (wrapped) when
// settleLapsed() reverts because the box's pending claim is the
// payer's, not the operator's. settleLapsed disburses an operator
// claim; a payer-pending box is refundInactive's job instead.
var ErrOnlyOperatorClaimsCanLapse = errors.New("escrow: " + AssertOnlyOperatorClaimsCanLapse)

// sentinelByApprovalMessage maps the source-mapped errorMessage
// string from the ARC-56 approval-program sourceInfo to the typed
// sentinel callers should match on. Add an entry here when promoting
// a contract revert message to a sentinel. Strings without an entry
// flow through enrichSubmitError unmatched: callers still see the
// friendly message in ApprovalError.Message and in the wrapped error
// text, just not a sentinel they can errors.Is against.
//
// Every sentinel's own text is "escrow: " + its key, enforced by
// TestSentinelText_MirrorsApprovalMessage. That is what makes the two
// rendering shapes in ApprovalError.Error() interchangeable for a log
// reader, and it is why promoting a message to a sentinel does not
// change what an operator sees in the error text.
var sentinelByApprovalMessage = map[string]error{
	AssertTicketNotFound:             ErrTicketNotFound,
	AssertSettleAfterRefundDeadline:  ErrSettleAfterRefundDeadline,
	AssertTicketNotSettleable:        ErrTicketNotSettleable,
	AssertTicketNotPendingSettle:     ErrTicketNotPendingSettle,
	AssertTooEarlyToLapseSettle:      ErrTooEarlyToLapseSettle,
	AssertOnlyOperatorClaimsCanLapse: ErrOnlyOperatorClaimsCanLapse,
}

// ApprovalError is a contract revert: algod rejected the submit with a TEAL
// assert failure, and we know the program counter it failed at. It exists so a
// caller can ask the three questions the old flat error string collapsed into
// two — "which assert fired" (Message against an Assert* constant, or errors.Is
// against a sentinel), "was this a revert we could not name" (Message == ""),
// and "was this a revert at all" (errors.As succeeding).
//
// That last distinction is the load-bearing one. A PC the embedded ARC-56 does
// not know is NOT exotic: the compiled-in spec is always the newest contract
// while the deployed app may be older, which is exactly when PCs shift. In that
// state every message comparison misses at once, and a caller matching on
// strings cannot tell "this revert is not one I handle" from "I could not
// determine the reason" — so a permanent failure reads as a transient one.
// Message == "" names that state.
type ApprovalError struct {
	// Method is the ABI method that was submitted ("settleLapsed", "open", …).
	Method string
	// PC is the program counter algod reported the assert failing at.
	PC uint64
	// Message is the assert string recovered from the ARC-56 approval
	// sourceInfo, or "" when the PC could not be resolved to one.
	Message string
	// Err is the wrapped cause: the sentinel when Message maps to one,
	// otherwise algod's original error. Unwrap returns it, which is what
	// keeps every existing errors.Is site working.
	Err error
}

// Sentinel returns the typed sentinel this revert maps to, or nil when the
// message has none (including the unresolvable Message == "" case).
func (e *ApprovalError) Sentinel() error { return sentinelByApprovalMessage[e.Message] }

// Error renders the two historical shapes byte-for-byte, because both are
// still read: operator logs, and any caller that has not yet moved off
// substring matching. They differ because the sentinel branch deliberately
// drops algod's raw string — the source-mapped message is more informative and
// the PC is enough for debugging — while the unmapped branch has nothing but
// that raw string to carry, so it interpolates the message ahead of it.
//
// The mapped branch prints the SENTINEL, not Err, even though enrichSubmitError
// makes them the same value. Printing Err would let the branch condition and
// the printed value be two different facts that merely agree today: a
// hand-built ApprovalError whose Message maps to a sentinel but whose Err is
// the raw algod error would take this branch and render as if the revert were
// unnameable, silently dropping the one thing the type exists to carry.
func (e *ApprovalError) Error() string {
	if sentinel := e.Sentinel(); sentinel != nil {
		return fmt.Sprintf("escrow: submit %s pc=%d: %v", e.Method, e.PC, sentinel)
	}
	if e.Message == "" {
		return fmt.Sprintf("escrow: submit %s pc=%d: %v", e.Method, e.PC, e.Err)
	}
	return fmt.Sprintf("escrow: submit %s pc=%d: %s: %v", e.Method, e.PC, e.Message, e.Err)
}

// Unwrap returns the wrapped cause so errors.Is reaches either the sentinel or
// the original algod error, whichever this revert carries.
func (e *ApprovalError) Unwrap() error { return e.Err }

// pcPattern extracts the program-counter value from algod's logic
// eval error string. The format algod emits is "...assert failed
// pc=NNN. Details: pc=NNN, opcodes=..." — multiple occurrences are
// fine; FindStringSubmatch returns the first.
var pcPattern = regexp.MustCompile(`pc=(\d+)`)

// extractPC pulls the first pc=NNN match out of an algod error
// string. Returns (pc, true) on a match; (0, false) when the string
// carries no PC (network errors, transient failures, malformed
// errors — anything that didn't come from a TEAL eval failure).
func extractPC(msg string) (uint64, bool) {
	m := pcPattern.FindStringSubmatch(msg)
	if len(m) != 2 {
		return 0, false
	}
	pc, err := strconv.ParseUint(m[1], 10, 64)
	if err != nil {
		return 0, false
	}
	return pc, true
}

// enrichSubmitError converts algod's stringly-typed submit failure into a
// typed-error chain whenever it can. The pipeline:
//
//  1. Pull pc=NNN out of the error string. No PC means this was not a TEAL
//     eval failure at all (network, signing, a ledger-eval balance failure) —
//     there is nothing to classify, so it comes back as a plain wrap and NOT
//     as an ApprovalError.
//  2. Look up that PC in the embedded ARC-56 approval sourceInfo to recover
//     the assert message the contract was compiled from. A miss leaves
//     Message == "": a revert we could not name, which is not the same fact
//     as a revert whose name we do not handle.
//  3. If the message has a matching sentinel, that becomes the wrapped cause
//     so callers can errors.Is.
//
// Never returns nil for a non-nil err.
func enrichSubmitError(methodName string, err error) error {
	if err == nil {
		return nil
	}
	pc, ok := extractPC(err.Error())
	if !ok {
		return fmt.Errorf("escrow: submit %s: %w", methodName, err)
	}
	revert := &ApprovalError{Method: methodName, PC: pc, Err: err}
	// A spec-parse failure needs no branch of its own: GetSpec returns a nil
	// *Spec, ApprovalErrorMessage is nil-safe, and the resulting Message == ""
	// is already the right answer — "a revert we could not name". Special-casing
	// it would add a branch no test can reach (the spec is an embedded build
	// artifact behind a sync.Once, so it parses always or never) whose only
	// possible drift is to stop returning the typed error.
	spec, _ := GetSpec()
	msg, found := spec.ApprovalErrorMessage(pc)
	if !found {
		return revert
	}
	revert.Message = msg
	if sentinel, hit := sentinelByApprovalMessage[msg]; hit {
		revert.Err = sentinel
	}
	return revert
}
