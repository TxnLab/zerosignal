/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import "net/http"

// retryable decides Error.Retryable from the error alone; the caller's
// context is the emitter's to weigh. It answers for a new turn, after the
// SDK's own retries are spent, which is why it is not the transient
// package's verdict: that one asks whether one hop may be resent now, and
// answers no for a coded refusal like no_capacity that a later turn routes
// around.
//
// proto/testdata/error_retry_vectors.json pins it for a port.
func retryable(e *Error) bool {
	switch e.Kind {
	case KindBusy, KindUnreachable:
		return true
	case KindInterrupted:
		// A node that refused admission said why: a timeout, a rate limit or
		// a server error passes, as does a refusal a new ticket gets past.
		// Anything else broke in transit.
		if nr, ok := e.Err.(*NodeReply); ok {
			switch {
			case nr.Status == http.StatusRequestTimeout, nr.Status == http.StatusTooManyRequests,
				nr.Status >= http.StatusInternalServerError:
				return true
			}
			return retryableRefusalCodes[e.Code]
		}
		return true
	case KindOperatorFault:
		// Every candidate mispriced its ticket; the next turn asks the same
		// operators.
		return e.Code != "ticket_price_rejected"
	case KindNoRoute:
		// Relays in backoff and nodes rotating their ephemeral key clear in
		// seconds. A network with no eligible relay at all never clears, but
		// the two can't be told apart here and an unpaid retry costs a round
		// trip. The other gaps take an operator minutes to hours, or never
		// close, which a retry loop would only spend its attempts on.
		return e.Code == "no_relay_available" || e.Code == "no_ephemeral_capacity"
	case KindUpstream:
		return upstreamRetryable(e.Err)
	}
	return false
}

// retryableProviderCodes are the provider failures a new turn can outlast.
// The code is the node's claim; trusting it costs at worst a wasted retry.
var retryableProviderCodes = map[string]bool{
	// The node retried a 429 or 5xx in place and gave up.
	"provider_overloaded": true,
	// A transport or untyped failure, which the node bills at zero.
	"provider_error": true,
	// The provider's stream ended before it finished.
	"upstream_truncated": true,
	// OpenAI's own, from a node that passes the provider's code through.
	"rate_limit_exceeded": true,
}

// retryableRefusalCodes are the node's admission refusals a new turn, with a
// new ticket, gets past: the ticket expired before its payment arrived, or
// the payment's verification failed and burned it (SPEC §10). The other
// refusals (ticket_required, bad_envelope, admission_tag_invalid,
// reply_to_mismatch, a 413) say the SDK built the request wrong, and it
// would build it the same way again.
var retryableRefusalCodes = map[string]bool{
	"ticket_invalid":              true,
	"payment_verification_failed": true,
}

// upstreamRetryable reads the cause of a KindUpstream Error: the node's code
// when it gave one, else the status of the reply that carried the failure.
func upstreamRetryable(cause error) bool {
	switch c := cause.(type) {
	case *ProviderError:
		if c.Code != "" {
			return retryableProviderCodes[c.Code]
		}
		return retryableReplyStatus(c.Status)
	case *NodeReply:
		return retryableReplyStatus(c.Status)
	}
	return false
}

// retryableReplyStatus is the statuses the node itself retries.
func retryableReplyStatus(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}
