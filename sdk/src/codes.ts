/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The code table a turn's ZsError is built from and the rule that decides its
// retryable, mirroring proto/go/zs's codes.go and retry.go. Internal: a caller
// branches on kind and reads the error, never builds one.
// proto/testdata/error_retry_vectors.json pins both against Go.

import { type Kind, NodeReply, ProviderError, ZsError, type ZsErrorInit } from './errors.js'

/**
 * errorKinds is the Kind of every code a turn reports. The code decides it, so
 * two sites reporting one condition can't disagree on its Kind. A Map, not an
 * object, because codes reach it from the node: "constructor" must not find
 * Object.prototype.
 */
export const errorKinds: ReadonlyMap<string, Kind> = new Map<string, Kind>([
    ['missing_model', 'invalid_request'],
    ['bad_image_request', 'invalid_request'],
    ['bad_image_edit_request', 'invalid_request'],
    ['max_output_required', 'invalid_request'],
    ['pin_conflicts_with_continuation', 'invalid_request'],
    ['unsupported_tool', 'invalid_request'],
    ['context_length_exceeded', 'context_exceeded'],
    ['price_ceiling_exceeded', 'price_rejected'],

    ['no_operator', 'no_route'],
    ['no_compatible_operator', 'no_route'],
    ['no_production_operator', 'no_route'],
    ['no_pinned_operator', 'no_route'],
    ['no_funded_operator', 'no_route'],
    ['no_tee_capacity', 'no_route'],
    ['no_tool_capacity', 'no_route'],
    ['no_ephemeral_capacity', 'no_route'],
    ['no_relay_available', 'no_route'],
    ['operators_busy', 'busy'],
    ['operators_unreachable', 'unreachable'],
    ['mbr_pool_exhausted', 'busy'],
    // The caller's signal ended during the reserve sweep, before any open.
    ['canceled', 'interrupted'],

    ['free_quota_exhausted', 'funds'],
    ['wallet_unfunded', 'funds'],
    ['mbr_pool_underfunded', 'funds'],
    ['spend_cap_exceeded', 'spend_cap'],
    ['ticket_price_rejected', 'operator_fault'],
    ['operator_ticket_reuse', 'operator_fault'],

    ['registry', 'internal'],
    ['tokenize', 'internal'],
    ['wrap_request', 'internal'],
    // Not unreachable: the code also covers an operator's bad presigned group
    // and a submit that timed out after algod may have accepted it, and a
    // caller reads unreachable as nothing paid, safe to retry.
    ['wallet_open', 'internal'],

    // After the open: escrow holds the payer's money from here on.
    // build_request fails on the operator- or relay-published base URL.
    ['build_request', 'operator_fault'],
    ['upstream_unreachable', 'interrupted'],
    ['read_upstream', 'interrupted'],
    ['response_handler', 'operator_fault'],
    ['stream_setup', 'operator_fault'],
    ['operator_unsealed_response', 'operator_fault'],
    ['operator_inconsistent_response', 'operator_fault'],
    // The stream broke after its first frame: the caller has part of a turn.
    ['stream_interrupted', 'interrupted'],
    // The provider failed inside the node's response. The node's own code, if
    // any, rides on the cause as a ProviderError, never here: it is the node's
    // choice and could name one of these.
    ['upstream_error', 'upstream'],
])

/**
 * newError builds the ZsError for a code in errorKinds; an unlisted code is
 * internal. A refusal that carries the node's own code (ticket_invalid, say)
 * names its kind and is built as a ZsError directly. Either way retryable is
 * left for markRetryable at delivery, because a cause can still learn its
 * reply's status after the error is built.
 */
export function newError(
    code: string,
    message: string,
    opts: Omit<ZsErrorInit, 'kind' | 'code' | 'message' | 'retryable'> = {},
): ZsError {
    return new ZsError({ ...opts, kind: errorKinds.get(code) ?? 'internal', code, message })
}

/**
 * markRetryable decides err.retryable once, at delivery, for every way a turn
 * can fail. A turn the caller's own signal ended is never retryable: nothing is
 * waiting for a resend.
 */
export function markRetryable(err: ZsError, callerAborted: boolean): void {
    ;(err as { retryable: boolean }).retryable = !callerAborted && retryable(err)
}

/**
 * retryable decides retryable from the error alone. It answers for a new turn,
 * after the SDK's own retries are spent, which is why it differs from the
 * transient verdict: that one asks whether one hop may be resent now, and
 * answers no for a coded refusal like no_capacity that a later turn routes
 * around.
 */
export function retryable(err: Pick<ZsError, 'kind' | 'code' | 'cause'>): boolean {
    const { kind, code, cause } = err
    switch (kind) {
        case 'busy':
        case 'unreachable':
            return true
        case 'interrupted':
            // The caller stopped the turn; nothing is waiting for a resend.
            if (code === 'canceled') return false
            // A node that refused admission said why: a timeout, a rate limit
            // or a server error passes, as does a refusal a new ticket gets
            // past. Anything else broke in transit.
            if (cause instanceof NodeReply) {
                const s = cause.status
                if (s === 408 || s === 429 || s >= 500) return true
                return retryableRefusalCodes.has(code)
            }
            return true
        case 'operator_fault':
            // Every candidate mispriced its ticket; the next turn asks the same
            // operators.
            return code !== 'ticket_price_rejected'
        case 'no_route':
            // Relays in backoff and nodes rotating their ephemeral key clear in
            // seconds. A network with no eligible relay at all never clears,
            // but the two can't be told apart here and an unpaid retry costs a
            // round trip. The other gaps take an operator minutes to hours, or
            // never close, which a retry loop would only spend its attempts on.
            return code === 'no_relay_available' || code === 'no_ephemeral_capacity'
        case 'upstream':
            if (cause instanceof ProviderError) {
                return cause.code ? retryableProviderCodes.has(cause.code) : retryableReplyStatus(cause.status)
            }
            if (cause instanceof NodeReply) return retryableReplyStatus(cause.status)
            return false
    }
    return false
}

// The provider failures a new turn can outlast. The code is the node's claim;
// trusting it costs at worst a wasted retry.
const retryableProviderCodes: ReadonlySet<string> = new Set([
    // The node retried a 429 or 5xx in place and gave up.
    'provider_overloaded',
    // A transport or untyped failure, which the node bills at zero.
    'provider_error',
    // The provider's stream ended before it finished.
    'upstream_truncated',
    // OpenAI's own, from a node that passes the provider's code through.
    'rate_limit_exceeded',
])

// The node's admission refusals a new ticket gets past: it expired before its
// payment arrived, or the payment's verification failed and burned it (SPEC
// §10). The others (ticket_required, bad_envelope, admission_tag_invalid,
// reply_to_mismatch, a 413) say the SDK built the request wrong, and it would
// build it the same way again.
const retryableRefusalCodes: ReadonlySet<string> = new Set(['ticket_invalid', 'payment_verification_failed'])

// The statuses the node itself retries.
function retryableReplyStatus(status: number): boolean {
    return status === 429 || status === 502 || status === 503 || status === 504
}
