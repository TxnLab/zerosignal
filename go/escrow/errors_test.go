/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package escrow

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
)

// pcsForApprovalMessage walks the embedded ARC-56 approval-program
// sourceInfo map and returns every PC whose source-mapped errorMessage
// equals msg. Same-package _test.go gives us access to the
// unexported approvalErrorMessages field, which keeps this helper
// from needing a public API.
//
// We drive tests off the assert/err *string* rather than off PCs
// because the strings are the contract's source of truth — PCs
// shift on every puya-ts rebuild, so any test that hardcodes them
// would have to be updated each time the contract is recompiled.
// Asserting the message-to-PC mapping exists in *some* direction
// (≥1 PC for the expected message) is the real invariant we care
// about.
//
// Fatals if the embedded spec has no entry for the message — that's
// the signal a contract change has renamed or dropped the assert
// and the sentinel registry in errors.go needs an audit.
func pcsForApprovalMessage(t *testing.T, spec *Spec, msg string) []uint64 {
	t.Helper()
	var pcs []uint64
	for pc, m := range spec.approvalErrorMessages {
		if m == msg {
			pcs = append(pcs, pc)
		}
	}
	if len(pcs) == 0 {
		t.Fatalf("no source-info entry with errorMessage %q in embedded ARC-56", msg)
	}
	sort.Slice(pcs, func(i, j int) bool { return pcs[i] < pcs[j] })
	return pcs
}

// TestExtractPC: regex must pull the PC out of the algod surface.
// Algod's logic-eval-error string carries pc=NNN multiple times; we
// only need the first one. Non-TEAL errors (network, transport) lack
// the marker and must return ok=false.
func TestExtractPC(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		wantPC uint64
		wantOK bool
	}{
		{
			name:   "algod logic eval error",
			input:  "TransactionPool.Remember: logic eval error: assert failed pc=1988. Details: pc=1988, opcodes=...",
			wantPC: 1988,
			wantOK: true,
		},
		{
			name:   "single occurrence",
			input:  "logic eval error pc=42",
			wantPC: 42,
			wantOK: true,
		},
		{
			name:   "no pc marker",
			input:  "read tcp 1.2.3.4:80: connection reset by peer",
			wantOK: false,
		},
		{
			name:   "empty",
			input:  "",
			wantOK: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pc, ok := extractPC(tc.input)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && pc != tc.wantPC {
				t.Errorf("pc = %d, want %d", pc, tc.wantPC)
			}
		})
	}
}

// TestApprovalErrorMessage_TicketNotFound: the embedded ARC-56 must
// carry at least one approval-program sourceInfo entry whose
// errorMessage is "ticket not found", and every PC under that entry
// must round-trip back through spec.ApprovalErrorMessage to the same
// string. If a contract change drops or renames the assert, the
// helper fatals; if the PC→message half of the map disagrees with
// the message→PC half, the round-trip flags it. Driving off the
// message keeps the test stable across PC drift from puya-ts
// rebuilds.
func TestApprovalErrorMessage_TicketNotFound(t *testing.T) {
	spec, err := GetSpec()
	if err != nil {
		t.Fatal(err)
	}
	const want = "ticket not found"
	for _, pc := range pcsForApprovalMessage(t, spec, want) {
		msg, ok := spec.ApprovalErrorMessage(pc)
		if !ok {
			t.Errorf("pc=%d: no source-info entry on round-trip", pc)
			continue
		}
		if msg != want {
			t.Errorf("pc=%d: message = %q, want %q", pc, msg, want)
		}
	}
}

// TestEnrichSubmitError_TicketNotFound: a synthesized algod error
// containing a pc=NNN that resolves to "ticket not found" must come
// out wrapped against ErrTicketNotFound so callers can errors.Is.
// The PC is sourced from the embedded ARC-56 spec rather than
// hardcoded — keeps the test green across puya-ts rebuilds that
// shift PCs by a few bytes.
func TestEnrichSubmitError_TicketNotFound(t *testing.T) {
	spec, err := GetSpec()
	if err != nil {
		t.Fatal(err)
	}
	pc := pcsForApprovalMessage(t, spec, "ticket not found")[0]
	algodErr := fmt.Errorf("HTTP 400: TransactionPool.Remember: logic eval error: assert failed pc=%d. Details: pc=%d, opcodes=...", pc, pc)
	got := enrichSubmitError("settle", algodErr)
	if got == nil {
		t.Fatal("enrichSubmitError returned nil for non-nil input")
	}
	if !errors.Is(got, ErrTicketNotFound) {
		t.Errorf("errors.Is(got, ErrTicketNotFound) = false; got = %v", got)
	}
	// Friendly message + PC must appear in the error text for ops/log
	// consumers that don't switch on the sentinel.
	msg := got.Error()
	if !strings.Contains(msg, fmt.Sprintf("pc=%d", pc)) {
		t.Errorf("error text missing pc: %q", msg)
	}
	if !strings.Contains(msg, "ticket not found") {
		t.Errorf("error text missing friendly message: %q", msg)
	}
}

// TestApprovalErrorMessage_SettleAfterRefundDeadline: same shape as
// the ticket-not-found mapping check — message-driven so PC drift
// from puya-ts rebuilds doesn't break the test, while a contract
// change that drops the assert still trips pcsForApprovalMessage's
// fatal.
func TestApprovalErrorMessage_SettleAfterRefundDeadline(t *testing.T) {
	spec, err := GetSpec()
	if err != nil {
		t.Fatal(err)
	}
	const want = "settle after refund deadline"
	for _, pc := range pcsForApprovalMessage(t, spec, want) {
		msg, ok := spec.ApprovalErrorMessage(pc)
		if !ok {
			t.Errorf("pc=%d: no source-info entry on round-trip", pc)
			continue
		}
		if msg != want {
			t.Errorf("pc=%d: message = %q, want %q", pc, msg, want)
		}
	}
}

// TestEnrichSubmitError_SettleAfterRefundDeadline: synthesized algod
// error with a pc=NNN that resolves to "settle after refund deadline"
// must come out wrapped against ErrSettleAfterRefundDeadline. PC
// sourced from the embedded spec.
func TestEnrichSubmitError_SettleAfterRefundDeadline(t *testing.T) {
	spec, err := GetSpec()
	if err != nil {
		t.Fatal(err)
	}
	pc := pcsForApprovalMessage(t, spec, "settle after refund deadline")[0]
	algodErr := fmt.Errorf("HTTP 400: TransactionPool.Remember: logic eval error: assert failed pc=%d. Details: pc=%d, opcodes=...", pc, pc)
	got := enrichSubmitError("settle", algodErr)
	if got == nil {
		t.Fatal("enrichSubmitError returned nil for non-nil input")
	}
	if !errors.Is(got, ErrSettleAfterRefundDeadline) {
		t.Errorf("errors.Is(got, ErrSettleAfterRefundDeadline) = false; got = %v", got)
	}
	msg := got.Error()
	if !strings.Contains(msg, fmt.Sprintf("pc=%d", pc)) {
		t.Errorf("error text missing pc: %q", msg)
	}
	if !strings.Contains(msg, "settle after refund deadline") {
		t.Errorf("error text missing friendly message: %q", msg)
	}
}

// TestApprovalErrorMessage_TicketNotSettleable: same shape as the
// other message-driven mapping checks — guards against a contract
// change that drops or renames the "not OPEN / not PENDING_SETTLE"
// assert in settle() (the assert that fires when a payer-protested
// ticket is FROZEN and the operator's settle still tries to land).
func TestApprovalErrorMessage_TicketNotSettleable(t *testing.T) {
	spec, err := GetSpec()
	if err != nil {
		t.Fatal(err)
	}
	const want = "ticket not settleable"
	for _, pc := range pcsForApprovalMessage(t, spec, want) {
		msg, ok := spec.ApprovalErrorMessage(pc)
		if !ok {
			t.Errorf("pc=%d: no source-info entry on round-trip", pc)
			continue
		}
		if msg != want {
			t.Errorf("pc=%d: message = %q, want %q", pc, msg, want)
		}
	}
}

// TestEnrichSubmitError_TicketNotSettleable: synthesized algod error
// with a pc=NNN that resolves to "ticket not settleable" must come out
// wrapped against ErrTicketNotSettleable so the settlement driver can
// errors.Is against it and route to the FROZEN-arbitration path. PC
// sourced from the embedded spec.
func TestEnrichSubmitError_TicketNotSettleable(t *testing.T) {
	spec, err := GetSpec()
	if err != nil {
		t.Fatal(err)
	}
	pc := pcsForApprovalMessage(t, spec, "ticket not settleable")[0]
	algodErr := fmt.Errorf("HTTP 400: TransactionPool.Remember: logic eval error: assert failed pc=%d. Details: pc=%d, opcodes=...", pc, pc)
	got := enrichSubmitError("settle", algodErr)
	if got == nil {
		t.Fatal("enrichSubmitError returned nil for non-nil input")
	}
	if !errors.Is(got, ErrTicketNotSettleable) {
		t.Errorf("errors.Is(got, ErrTicketNotSettleable) = false; got = %v", got)
	}
	msg := got.Error()
	if !strings.Contains(msg, fmt.Sprintf("pc=%d", pc)) {
		t.Errorf("error text missing pc: %q", msg)
	}
	if !strings.Contains(msg, "ticket not settleable") {
		t.Errorf("error text missing friendly message: %q", msg)
	}
}

// TestEnrichSubmitError_UnknownPC: a pc value the source map doesn't
// know about (e.g. a contract update) must still return a wrapped
// error that surfaces both the PC and the underlying algod text,
// just without a sentinel.
func TestEnrichSubmitError_UnknownPC(t *testing.T) {
	algodErr := errors.New("logic eval error: assert failed pc=999999")
	got := enrichSubmitError("settle", algodErr)
	if got == nil {
		t.Fatal("nil result for non-nil input")
	}
	if errors.Is(got, ErrTicketNotFound) {
		t.Error("unknown PC unexpectedly matched ErrTicketNotFound")
	}
	if !errors.Is(got, algodErr) {
		t.Error("underlying algod err must remain unwrappable when PC is unknown")
	}
	if !strings.Contains(got.Error(), "pc=999999") {
		t.Errorf("error text missing pc: %q", got.Error())
	}
}

// TestEnrichSubmitError_NoPC: a non-TEAL transport error (network,
// timeout) has no pc=NNN marker — the wrapper falls back to the
// plain "escrow: submit ..." form and keeps the original error
// chained for inspection.
func TestEnrichSubmitError_NoPC(t *testing.T) {
	transport := errors.New("read tcp: connection reset by peer")
	got := enrichSubmitError("settle", transport)
	if got == nil {
		t.Fatal("nil result for non-nil input")
	}
	if errors.Is(got, ErrTicketNotFound) {
		t.Error("transport error unexpectedly matched ErrTicketNotFound")
	}
	if !errors.Is(got, transport) {
		t.Error("transport error must remain unwrappable")
	}
}

// TestEnrichSubmitError_Nil: a nil input must produce nil output —
// the helper is on the err != nil hot path of submitSingle, but
// keeping it nil-safe avoids landmine if a future caller forgets
// the guard.
func TestEnrichSubmitError_Nil(t *testing.T) {
	if got := enrichSubmitError("settle", nil); got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

// exportedApprovalAsserts maps every Assert* constant errors.go publishes to
// the literal it is supposed to hold. Listed by hand because Go gives no way
// to enumerate a const block, and spelled out as literals **on purpose**: a
// table that read `AssertTooEarlyToLapseSettle: AssertTooEarlyToLapseSettle`
// would assert nothing. Every other test in this package sources its input
// from these constants, so this table is the only thing standing between a
// constant and a value that is some *other* real contract assert — which the
// ARC-56 existence check below would happily wave through while the driver
// silently routed FROZEN tickets into the "already resolved" branch.
var exportedApprovalAsserts = map[string]string{
	"AssertTicketNotFound":                  "ticket not found",
	"AssertSettleAfterRefundDeadline":       "settle after refund deadline",
	"AssertTicketNotSettleable":             "ticket not settleable",
	"AssertTicketNotPendingSettle":          "ticket not pending settle",
	"AssertTooEarlyToLapseSettle":           "too early to lapse settle",
	"AssertOnlyOperatorClaimsCanLapse":      "only operator claims can lapse into settle",
	"AssertInsufficientMbrDeposit":          "insufficient MBR deposit",
	"AssertInsufficientMbrDepositFreeQuota": "insufficient MBR deposit for free-quota box",
	"AssertPayerHasNoMbrDeposit":            "payer has no MBR deposit",
}

// TestApprovalAssertConstants_HoldTheirDocumentedValue is the half that stops
// a constant from silently naming a different assert than its name says. Both
// halves are needed: this one pins name→value, and ExistInARC56 below pins
// value→contract.
func TestApprovalAssertConstants_HoldTheirDocumentedValue(t *testing.T) {
	got := map[string]string{
		"AssertTicketNotFound":                  AssertTicketNotFound,
		"AssertSettleAfterRefundDeadline":       AssertSettleAfterRefundDeadline,
		"AssertTicketNotSettleable":             AssertTicketNotSettleable,
		"AssertTicketNotPendingSettle":          AssertTicketNotPendingSettle,
		"AssertTooEarlyToLapseSettle":           AssertTooEarlyToLapseSettle,
		"AssertOnlyOperatorClaimsCanLapse":      AssertOnlyOperatorClaimsCanLapse,
		"AssertInsufficientMbrDeposit":          AssertInsufficientMbrDeposit,
		"AssertInsufficientMbrDepositFreeQuota": AssertInsufficientMbrDepositFreeQuota,
		"AssertPayerHasNoMbrDeposit":            AssertPayerHasNoMbrDeposit,
	}
	if len(got) != len(exportedApprovalAsserts) {
		t.Fatalf("checked %d constants, table lists %d — add the new one to both", len(got), len(exportedApprovalAsserts))
	}
	for name, want := range exportedApprovalAsserts {
		if got[name] != want {
			t.Errorf("%s = %q, want %q", name, got[name], want)
		}
	}
}

// TestApprovalAssertConstants_ExistInARC56 is the drift gate the substring
// era never had: every message an off-chain caller classifies on must still
// be a message the compiled contract actually emits. Reword an assert in
// ZeroSignalEscrow.algo.ts, rebuild, and this goes red — instead of a
// classifier that quietly stops matching in production and reclassifies a
// permanent revert as a transient one.
func TestApprovalAssertConstants_ExistInARC56(t *testing.T) {
	spec, err := GetSpec()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range exportedApprovalAsserts {
		// pcsForApprovalMessage fatals when the message is absent.
		for _, pc := range pcsForApprovalMessage(t, spec, want) {
			got, ok := spec.ApprovalErrorMessage(pc)
			if !ok {
				t.Errorf("%q: pc=%d has no source-info entry on round-trip", want, pc)
				continue
			}
			if got != want {
				t.Errorf("pc=%d: message = %q, want %q", pc, got, want)
			}
		}
	}
	// The sentinel map is gated in its own right, not merely because every key
	// happens to also be a listed constant today. errors.go invites the
	// ungated edit ("Add an entry here when promoting a contract revert
	// message to a sentinel"), and a key the contract never emits is a
	// sentinel no revert can ever match — inert, and invisible without this.
	for msg := range sentinelByApprovalMessage {
		pcsForApprovalMessage(t, spec, msg)
	}
}

// TestSentinelText_MirrorsApprovalMessage pins the rule that makes promoting
// a message to a sentinel invisible to a log reader: the sentinel's own text
// is "escrow: " + the contract's assert string. Break it and the sentinel
// branch of ApprovalError.Error() starts rendering something the unmapped
// branch would not have — which is exactly the drift that made the old
// substring callers fragile.
func TestSentinelText_MirrorsApprovalMessage(t *testing.T) {
	for msg, sentinel := range sentinelByApprovalMessage {
		if want := "escrow: " + msg; sentinel.Error() != want {
			t.Errorf("sentinel for %q reads %q, want %q", msg, sentinel.Error(), want)
		}
	}
}

// TestEnrichSubmitError_LapseSentinels: each settleLapsed guard must come
// back as its own sentinel so the settlement driver can errors.Is instead of
// substring-matching the four outcomes apart. Byte-identity of the rendered
// text is asserted alongside, because operator logs and any caller still on
// the old matching style both read it.
func TestEnrichSubmitError_LapseSentinels(t *testing.T) {
	spec, err := GetSpec()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		msg      string
		sentinel error
	}{
		{AssertTicketNotPendingSettle, ErrTicketNotPendingSettle},
		{AssertTooEarlyToLapseSettle, ErrTooEarlyToLapseSettle},
		{AssertOnlyOperatorClaimsCanLapse, ErrOnlyOperatorClaimsCanLapse},
	}
	for _, tc := range cases {
		t.Run(tc.msg, func(t *testing.T) {
			pc := pcsForApprovalMessage(t, spec, tc.msg)[0]
			algodErr := fmt.Errorf("HTTP 400: TransactionPool.Remember: logic eval error: assert failed pc=%d. Details: pc=%d, opcodes=...", pc, pc)
			got := enrichSubmitError("settleLapsed", algodErr)
			if !errors.Is(got, tc.sentinel) {
				t.Fatalf("errors.Is(got, %v) = false; got = %v", tc.sentinel, got)
			}
			// The three must stay mutually exclusive — a driver that routes
			// "too early" (retry) into the "not pending settle" branch
			// (terminal arbitration log) is the failure this whole change
			// exists to prevent.
			for _, other := range cases {
				if other.msg == tc.msg {
					continue
				}
				if errors.Is(got, other.sentinel) {
					t.Errorf("%q also matched %v", tc.msg, other.sentinel)
				}
			}
			revert, ok := errors.AsType[*ApprovalError](got)
			if !ok {
				t.Fatalf("got = %v, want an *ApprovalError", got)
			}
			if revert.Method != "settleLapsed" || revert.PC != pc || revert.Message != tc.msg {
				t.Errorf("revert = %+v, want method=settleLapsed pc=%d message=%q", revert, pc, tc.msg)
			}
			// errors.Is reaches the sentinel through Unwrap/Err and never
			// consults Sentinel(), so the exported accessor needs its own
			// positive assertion — otherwise it could return the wrong
			// sentinel for every mapped message with this test still green.
			if revert.Sentinel() != tc.sentinel {
				t.Errorf("Sentinel() = %v, want %v", revert.Sentinel(), tc.sentinel)
			}
			// And the two must be the SAME value, not merely both non-nil:
			// Error()'s branch and errors.Is read different fields, so a
			// constructor that let them diverge would render a named revert as
			// unnameable while errors.Is missed it entirely.
			if revert.Err != tc.sentinel {
				t.Errorf("Err = %v, want it to be the sentinel itself", revert.Err)
			}
			want := fmt.Sprintf("escrow: submit settleLapsed pc=%d: escrow: %s", pc, tc.msg)
			if got.Error() != want {
				t.Errorf("error text = %q, want %q", got.Error(), want)
			}
		})
	}
}

// TestApprovalError_RenderingDoesNotDependOnErrAndSentinelAgreeing feeds
// Error() an inconsistent value on purpose: Message maps to a sentinel, but
// Err is the raw algod string. enrichSubmitError never builds that — it sets
// Err = sentinel whenever one exists — so the branch condition (Sentinel())
// and the printed value agree today by construction rather than by design.
// Every hand-built fixture in this workspace is one edit away from the split,
// and when it happens the revert renders as though it were unnameable: the
// message vanishes and an operator reads a version-skew symptom instead of the
// assert that actually fired.
func TestApprovalError_RenderingDoesNotDependOnErrAndSentinelAgreeing(t *testing.T) {
	revert := &ApprovalError{
		Method:  "settleLapsed",
		PC:      4502,
		Message: AssertTicketNotPendingSettle,
		Err:     errors.New("HTTP 400: logic eval error: assert failed pc=4502"),
	}
	if got := revert.Error(); !strings.Contains(got, AssertTicketNotPendingSettle) {
		t.Errorf("Error() = %q, want it to name %q even when Err is not the sentinel",
			got, AssertTicketNotPendingSettle)
	}
	// Routing must NOT follow rendering here. Error() answers "which assert
	// fired" and may read Message; Unwrap answers "what caused this" and must
	// report the wrapped cause. Making Unwrap fall back to the mapped sentinel
	// would look like a tidy symmetry and would silently invent an errors.Is
	// match for a value whose author attached a different cause.
	if errors.Is(revert, ErrTicketNotPendingSettle) {
		t.Error("Unwrap reported the mapped sentinel; it must report the wrapped cause")
	}
	if !errors.Is(revert, revert.Err) {
		t.Error("Unwrap must reach the cause the value actually carries")
	}
}

// TestEnrichSubmitError_ResolvedButUnmapped: a revert whose message the
// ARC-56 resolves but which has no sentinel must still arrive typed, with
// Message populated and algod's original string still unwrappable. This is
// the state the proxy's MBR-pool classifier reads, and the state that used
// to be indistinguishable from an unresolvable PC.
func TestEnrichSubmitError_ResolvedButUnmapped(t *testing.T) {
	spec, err := GetSpec()
	if err != nil {
		t.Fatal(err)
	}
	const msg = AssertInsufficientMbrDeposit
	if _, mapped := sentinelByApprovalMessage[msg]; mapped {
		t.Fatalf("%q gained a sentinel — pick another unmapped message for this test", msg)
	}
	pc := pcsForApprovalMessage(t, spec, msg)[0]
	algodErr := fmt.Errorf("HTTP 400: TransactionPool.Remember: logic eval error: assert failed pc=%d. Details: pc=%d, opcodes=...", pc, pc)
	got := enrichSubmitError("open", algodErr)

	revert, ok := errors.AsType[*ApprovalError](got)
	if !ok {
		t.Fatalf("got = %v, want an *ApprovalError", got)
	}
	if revert.Message != msg {
		t.Errorf("Message = %q, want %q", revert.Message, msg)
	}
	if revert.Sentinel() != nil {
		t.Errorf("Sentinel() = %v, want nil", revert.Sentinel())
	}
	if !errors.Is(got, algodErr) {
		t.Error("algod error must stay unwrappable when the message has no sentinel")
	}
	want := fmt.Sprintf("escrow: submit open pc=%d: %s: %v", pc, msg, algodErr)
	if got.Error() != want {
		t.Errorf("error text = %q, want %q", got.Error(), want)
	}
}

// TestEnrichSubmitError_UnclassifiableRevert: a PC the embedded ARC-56 can't
// resolve is still a contract revert, and must say so — an *ApprovalError
// with an empty Message. Not exotic: the compiled-in spec is always the
// newest contract while the deployed app may be older, which is precisely
// when PCs shift. Collapsing this into "some transient failure" is what makes
// a permanent revert burn a retry budget and land in a terminal failed row.
func TestEnrichSubmitError_UnclassifiableRevert(t *testing.T) {
	algodErr := errors.New("logic eval error: assert failed pc=999999")
	got := enrichSubmitError("settleLapsed", algodErr)

	revert, ok := errors.AsType[*ApprovalError](got)
	if !ok {
		t.Fatalf("got = %v, want an *ApprovalError", got)
	}
	if revert.Message != "" {
		t.Errorf("Message = %q, want \"\" for an unresolvable PC", revert.Message)
	}
	if revert.PC != 999999 {
		t.Errorf("PC = %d, want 999999", revert.PC)
	}
	if !errors.Is(got, algodErr) {
		t.Error("algod error must stay unwrappable")
	}
	want := fmt.Sprintf("escrow: submit settleLapsed pc=999999: %v", algodErr)
	if got.Error() != want {
		t.Errorf("error text = %q, want %q", got.Error(), want)
	}
}

// TestEnrichSubmitError_NoPC_IsNotApprovalError: the other half of the same
// distinction. A transport or signing failure never reached the TEAL
// program, so it is not a revert at all and must NOT type-assert as one —
// otherwise a caller that treats every ApprovalError as "the contract said
// no" would stop retrying a network blip.
func TestEnrichSubmitError_NoPC_IsNotApprovalError(t *testing.T) {
	transport := errors.New("read tcp: connection reset by peer")
	got := enrichSubmitError("open", transport)

	if revert, ok := errors.AsType[*ApprovalError](got); ok {
		t.Errorf("transport error typed as a contract revert: %+v", revert)
	}
	if want := fmt.Sprintf("escrow: submit open: %v", transport); got.Error() != want {
		t.Errorf("error text = %q, want %q", got.Error(), want)
	}
}
