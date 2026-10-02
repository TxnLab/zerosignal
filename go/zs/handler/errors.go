/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/TxnLab/zerosignal/go/escrow"
)

type openAIErrorEnvelope struct {
	Error openAIError `json:"error"`
}

type openAIError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Code    string `json:"code,omitempty"`
}

// writeOpenAIError writes an OpenAI-shaped error JSON body with the given
// HTTP status. Safe to call before any other response headers are written.
func writeOpenAIError(w http.ResponseWriter, status int, errType, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(openAIErrorEnvelope{
		Error: openAIError{
			Message: message,
			Type:    errType,
			Code:    code,
		},
	})
}

// underfundedOpenSignatures are the algod ledger-eval substrings that mean the
// escrow open failed because the payer can't cover it: too little ALGO for fees
// / min-balance ("overspend", "below min"), too little USDC to lock ("underflow"
// on the asset subtract), or no USDC opt-in ("missing from"). Kept tight so an
// unrelated submit failure stays a 502 rather than a misleading "fund me" 402.
var underfundedOpenSignatures = []string{"overspend", "below min", "underflow", "missing from"}

// isUnderfundedOpenError reports whether a Wallet.Open failure was caused by the
// payer being unable to pay (vs a protocol/transport fault), so dispatch can
// surface an actionable 402 wallet_unfunded instead of a generic 502.
func isUnderfundedOpenError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, sig := range underfundedOpenSignatures {
		if strings.Contains(msg, sig) {
			return true
		}
	}
	return false
}

// poolExhaustedAsserts are the three open() guards on the payer's prepaid
// ticket-MBR pool: not enough headroom for another ticket slot, not enough for
// the one-time free-quota box, or no deposit at all (the pool was closed or
// drained out from under an in-flight open). All three mean the same thing to
// the payer — fund the pool — and none of them is a balance shortfall, so
// without this branch the operator gets a misleading generic 502 instead of
// "raise zs.concurrent_slots".
var poolExhaustedAsserts = map[string]bool{
	escrow.AssertInsufficientMbrDeposit:          true,
	escrow.AssertInsufficientMbrDepositFreeQuota: true,
	escrow.AssertPayerHasNoMbrDeposit:            true,
}

// escrowOpenMethod is the ABI method name enrichSubmitError stamps onto an
// open() revert. The message alone is NOT enough to classify: Wallet.Open also
// runs the prepaid-pool top-up, so a depositMbr revert reaches this classifier
// through the same return value, and the contract can grow a guard sharing one
// of these messages on a different entry point at any time. Advising
// "raise zs.concurrent_slots, retry in 2s" about a call that is not an open
// is confident, actionable, and wrong. Checked against the real ABI by
// TestPoolExhaustedMethodNameIsARealABIMethod; the identity is pinned by the
// classifier's own fixtures and its method sweep.
const escrowOpenMethod = "open"

// isPoolExhaustedOpenError reports whether a Wallet.Open failure was an
// MBR-pool-headroom revert (vs a balance shortfall or a protocol fault), so
// dispatch can point the operator at zs.concurrent_slots with a 429 rather
// than a bare 502. Distinct from isUnderfundedOpenError: the wallet HOLDS the
// ALGO, it's just all reserved by in-flight tickets.
//
// Matches the typed revert, never the error text. algod reports only
// "assert failed pc=NNN" — the assert message exists solely because the escrow
// client resolves that PC through the embedded ARC-56 source map — so a
// text-matching version of this check is testable but inert against a real
// node, which is exactly what it was.
func isPoolExhaustedOpenError(err error) bool {
	revert, ok := errors.AsType[*escrow.ApprovalError](err)
	return ok && revert.Method == escrowOpenMethod && poolExhaustedAsserts[revert.Message]
}
