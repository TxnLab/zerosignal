/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"errors"
	"fmt"
	"testing"

	"github.com/TxnLab/zerosignal/go/escrow"
)

func TestIsUnderfundedOpenError(t *testing.T) {
	// Realistic algod ledger-eval messages for the funding failure modes,
	// wrapped the way Wallet.Open wraps them.
	underfunded := []string{
		"TransactionPool.Remember: transaction ABC: overspend (account XYZ, data {...})",
		"account XYZ balance 99000 below min 100000",
		"underflow on subtracting 5000000 from sender for asset 10458941",
		"asset 10458941 missing from XYZ",
	}
	for _, m := range underfunded {
		if !isUnderfundedOpenError(fmt.Errorf("wallet: submit presigned open group: %s", m)) {
			t.Errorf("expected underfunded=true for %q", m)
		}
	}

	notUnderfunded := []error{
		nil,
		errors.New("algod unreachable"),
		errors.New("context deadline exceeded"),
		errors.New("dial tcp: connection refused"),
		errors.New("escrow submit returned 2 txids, want 3"),
	}
	for _, e := range notUnderfunded {
		if isUnderfundedOpenError(e) {
			t.Errorf("expected underfunded=false for %v", e)
		}
	}
}

// openRevert builds the error shape Wallet.Open actually returns for a
// contract revert: the escrow client resolves algod's PC through the ARC-56
// source map into an *escrow.ApprovalError, and the wallet %w-wraps it.
// Building the string by hand instead is how this classifier came to be tested
// against a shape production has never produced.
func openRevert(msg string) error { return revertFrom("open", msg) }

// revertFrom takes the method explicitly so the classifier's method dimension
// is testable at all. Hardcoding "open" in the only fixture made the
// classifier's method-agnosticism and the fixtures' method-uniformity agree by
// accident, with neither the check nor its absence observable.
func revertFrom(method, msg string) error {
	revert := &escrow.ApprovalError{
		Method:  method,
		PC:      1234,
		Message: msg,
		Err:     errors.New("HTTP 400: TransactionPool.Remember: logic eval error: assert failed pc=1234"),
	}
	return fmt.Errorf("wallet: submit presigned open group: %w", revert)
}

// TestPoolExhaustedMethodNameIsARealABIMethod checks only that the constant
// names SOME method the contract actually has — it cannot tell "open" from any
// other real method, and it should not be read as pinning that identity. What
// pins the identity is the fixtures: openRevert stamps "open" on every positive
// case, and the method sweep below rejects every other ABI method. This one
// exists for the narrower failure of the contract renaming open() out from
// under a constant whose message half would still match.
func TestPoolExhaustedMethodNameIsARealABIMethod(t *testing.T) {
	if _, err := escrow.MethodByName(escrowOpenMethod); err != nil {
		t.Errorf("escrow contract has no method %q: %v", escrowOpenMethod, err)
	}
}

func TestIsPoolExhaustedOpenError(t *testing.T) {
	// All three prepaid-MBR-pool guards on open(), sourced from the exported
	// constants so a contract reword fails in proto rather than silently here.
	exhausted := []string{
		escrow.AssertInsufficientMbrDeposit,
		escrow.AssertInsufficientMbrDepositFreeQuota,
		escrow.AssertPayerHasNoMbrDeposit,
	}
	for _, m := range exhausted {
		err := openRevert(m)
		if !isPoolExhaustedOpenError(err) {
			t.Errorf("expected pool-exhausted=true for %q", m)
		}
		// Pool exhaustion must NOT also classify as a balance shortfall — the
		// dispatch checks exhaustion first and the two conditions are disjoint.
		if isUnderfundedOpenError(err) {
			t.Errorf("pool-exhaustion %q must not match underfunded signatures", m)
		}
	}

	notExhausted := []error{
		nil,
		errors.New("algod unreachable"),
		fmt.Errorf("wallet: submit presigned open group: %s", "account XYZ balance 99000 below min 100000"),
		// A different contract revert. The old substring form matched this one
		// too ('no mbr deposit' is a substring of closeDeposit's assert), which
		// would have reported a 429 "raise your slots" for a call that never
		// touched the pool.
		openRevert("no MBR deposit"),
		// Method dimension's twin of the prefix case below. The contract's
		// naming convention is prefix families (unregisterNode/-Operator,
		// updateNode/-Url), so an openFree() or openWithDeposit() is a plausible
		// next method — and the whole-contract method sweep can't see a prefix
		// rewrite, since it only knows the methods that exist today.
		revertFrom(escrowOpenMethod+"Free", escrow.AssertInsufficientMbrDeposit),
		// Same message, different entry point. Wallet.Open runs the prepaid-pool
		// top-up before the open, so a depositMbr revert reaches this classifier
		// through the same return value — and "raise zs.concurrent_slots, retry
		// in 2s" is the wrong answer for one.
		revertFrom("depositMbr", escrow.AssertInsufficientMbrDeposit),
		// Exact match, not a prefix. AssertInsufficientMbrDeposit is a strict
		// prefix of AssertInsufficientMbrDepositFreeQuota, so a "clarifying"
		// rewrite to strings.HasPrefix would pass against today's contract and
		// silently over-match the day it grows another assert in that family.
		// This synthetic message is that assert, arriving early.
		openRevert(escrow.AssertInsufficientMbrDeposit + " for the operator stake box"),
		// A revert the embedded ARC-56 couldn't resolve to a message at all:
		// unclassifiable is not the same fact as pool-exhausted.
		fmt.Errorf("wallet: submit presigned open group: %w", &escrow.ApprovalError{
			Method: "open", PC: 999999, Err: errors.New("assert failed pc=999999"),
		}),
	}
	for _, e := range notExhausted {
		if isPoolExhaustedOpenError(e) {
			t.Errorf("expected pool-exhausted=false for %v", e)
		}
	}
}

// TestIsPoolExhaustedOpenError_ComplementOverWholeContract asserts the
// classifier against EVERY assert the contract can emit, not a hand-picked
// sample. A negative list can only catch over-matching on the strings someone
// thought to list — the contract carries ~9 deposit/MBR-flavoured asserts, and
// admitting any one of them answers an unrelated revert with
// "429, raise zs.concurrent_slots", which is the exact misclassification the
// substring version was replaced to stop. Walking the ARC-56 also picks up
// asserts added to the contract later, for free.
func TestIsPoolExhaustedOpenError_ComplementOverWholeContract(t *testing.T) {
	spec, err := escrow.GetSpec()
	if err != nil {
		t.Fatal(err)
	}
	// A set, not a counter: several contract asserts compile to more than one
	// PC, so an increment would double-count the day one of these three gains
	// a second call site and fail for a reason unrelated to the classifier.
	// The near-misses this sweep exists to catch — same vocabulary as the pool
	// guards, different call sites. Asserting they were actually swept keeps
	// the test's coverage claim honest: a shrinking message list would
	// otherwise quietly turn this back into the hand-picked sample.
	nearMisses := map[string]bool{
		"no MBR deposit":           false,
		"deposit must be positive": false,
	}
	matched := map[string]bool{}
	for _, msg := range spec.ApprovalErrorMessages() {
		if _, isNearMiss := nearMisses[msg]; isNearMiss {
			nearMisses[msg] = true
		}
		want := msg == escrow.AssertInsufficientMbrDeposit ||
			msg == escrow.AssertInsufficientMbrDepositFreeQuota ||
			msg == escrow.AssertPayerHasNoMbrDeposit
		if got := isPoolExhaustedOpenError(openRevert(msg)); got != want {
			t.Errorf("isPoolExhaustedOpenError(%q) = %v, want %v", msg, got, want)
		}
		if want {
			matched[msg] = true
		}
	}
	if len(matched) != 3 {
		t.Errorf("matched %d of the contract's asserts, want exactly the 3 open() pool guards", len(matched))
	}
	for msg, swept := range nearMisses {
		if !swept {
			t.Errorf("%q was never swept — this test is no longer covering the whole contract", msg)
		}
	}

	// Sweep the METHOD dimension the same way. The decision has two axes and a
	// single negative case pins only one alternative: any weakening that still
	// excludes that one method reads as gated while admitting every other. This
	// makes the gate a whitelist by test rather than by coincidence, and it
	// covers a prefix rewrite too, since no other ABI method starts with "open".
	// The full cross product, not one cell of it. Two axis-independent sweeps
	// — all messages at method "open", all methods at one message — leave the
	// gate droppable for the other two messages with everything green. That
	// cell is live: Wallet.Open runs the pool top-up first, so a depositMbr
	// revert carrying 'payer has no MBR deposit' reaches this classifier.
	for name := range spec.Methods {
		if name == escrowOpenMethod {
			continue
		}
		for msg := range poolExhaustedAsserts {
			if isPoolExhaustedOpenError(revertFrom(name, msg)) {
				t.Errorf("method %q with message %q admitted by the open-only gate", name, msg)
			}
		}
	}
}
