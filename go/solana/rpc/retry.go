/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package rpc

import (
	"encoding/json"
	"net/http"
	"time"
)

// RetryPolicy is the client's retry budget: the first attempt, then up to
// MaxRetries more, waiting httpx.LinearBackoff between them. A canceled or
// expired ctx ends the call at once, mid-wait included.
type RetryPolicy struct {
	MaxRetries int
	// WaitMin is the wait before the first retry and the step each later one
	// adds; WaitMax caps every wait, a server's Retry-After included.
	WaitMin time.Duration
	WaitMax time.Duration
}

// DefaultRetry is the budget NewClient uses. The public endpoints meter each
// IP over 10-second windows and answer 429 with a Retry-After
// (https://solana.com/docs/references/clusters, "Rate limits"), so the cap is
// one window, and the linear schedule (18 s in all) waits out at least one.
// It is far shorter than algod's minutes: a submit that runs it out still has
// most of a blockhash's ~60 s life to be rebuilt and sent again, and a
// payer's read gives up while a caller is still waiting on it.
func DefaultRetry() RetryPolicy {
	return RetryPolicy{MaxRetries: 8, WaitMin: 500 * time.Millisecond, WaitMax: 10 * time.Second}
}

// JSON-RPC error codes the client retries, from Agave's
// rpc-client-api/src/custom_error.rs
// (https://github.com/anza-xyz/agave/blob/983722f7d083592fead8bb52276af8c7be959f97/rpc-client-api/src/custom_error.rs).
const (
	// CodePreflightFailure is sendTransaction's failed simulation. Its data
	// is the simulation result, whose err names the TransactionError.
	CodePreflightFailure = -32002
	// CodeNodeUnhealthy is a node behind the cluster (or not yet knowing
	// whether it is), which sendTransaction's preflight and getHealth answer
	// until it catches up.
	CodeNodeUnhealthy = -32005
)

// shouldRetry is whether an outcome is retried. status is the HTTP status,
// 0 for a request that got no response; rpcErr is the JSON-RPC error of a 2xx
// answer, nil for a result.
//
// A transport failure, a 429 and any 5xx are retried as algod's are. Any
// other non-2xx status is an answer. Within a 2xx, a node behind the cluster
// is weather, and so is a simulation that found no blockhash: the blockhash
// came from a node ahead of the one simulating (providers balance across
// nodes at different slots), and the same bytes pass once it catches up.
// Resending is safe on every method, sendTransaction included, because the
// cluster processes a signature once. Every other JSON-RPC error is an answer
// that asking again repeats, a failed simulation's InsufficientFundsForFee or
// program error included.
func shouldRetry(method string, status int, rpcErr *Error) bool {
	if status == 0 {
		return true
	}
	if status == http.StatusTooManyRequests || (status >= 500 && status <= 599) {
		return true
	}
	if status < 200 || status > 299 || rpcErr == nil {
		return false
	}
	switch rpcErr.Code {
	case CodeNodeUnhealthy:
		return true
	case CodePreflightFailure:
		return method == "sendTransaction" && rpcErr.TxErrName() == "BlockhashNotFound"
	}
	return false
}

// TxErrName is the variant of a TransactionError as the RPC spells it: serde's
// external tagging writes a unit variant as its name ("BlockhashNotFound") and
// any other as an object of one key ({"InstructionError":[0,{"Custom":1}]}).
// It is "" for null, for no error, and for anything else.
func TxErrName(raw json.RawMessage) string {
	var name string
	if json.Unmarshal(raw, &name) == nil {
		return name
	}
	var tagged map[string]json.RawMessage
	if json.Unmarshal(raw, &tagged) == nil && len(tagged) == 1 {
		for k := range tagged {
			return k
		}
	}
	return ""
}
