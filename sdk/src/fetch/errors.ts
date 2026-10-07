/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// How the OpenAI-compatible surface renders an error, mirroring proto/go/zs
// handler/errors.go.

import type { Kind, ZsError } from '../errors.js'
import { openAIErrorBody } from '../responder.js'

/** How the OpenAI-compatible surface renders an error: its HTTP status and OpenAI error type. */
export interface ErrorShape {
    status: number
    type: string
}

const shape = (status: number, type: string): ErrorShape => ({ status, type })

/**
 * errorShapes renders each code a turn reports. The code decides the shape,
 * as it decides the Kind. A Map, because codes reach it from the node.
 */
export const errorShapes: ReadonlyMap<string, ErrorShape> = new Map([
    ['missing_model', shape(400, 'invalid_request_error')],
    ['bad_image_request', shape(400, 'invalid_request_error')],
    ['bad_image_edit_request', shape(400, 'invalid_request_error')],
    ['max_output_required', shape(400, 'invalid_request_error')],
    ['pin_conflicts_with_continuation', shape(400, 'invalid_request_error')],
    ['unsupported_tool', shape(400, 'invalid_request_error')],
    ['context_length_exceeded', shape(400, 'invalid_request_error')],
    ['price_ceiling_exceeded', shape(400, 'invalid_request_error')],

    // A model nobody serves is OpenAI's 404. The next three can't be served as
    // sent, or as the Client is configured, until someone changes something;
    // a 5xx would invite a client that ignores X-Should-Retry to resend.
    ['no_operator', shape(404, 'invalid_request_error')],
    ['no_compatible_operator', shape(400, 'invalid_request_error')],
    ['no_production_operator', shape(400, 'invalid_request_error')],
    ['no_pinned_operator', shape(400, 'invalid_request_error')],
    ['no_funded_operator', shape(503, 'service_unavailable')],
    ['no_tee_capacity', shape(503, 'service_unavailable')],
    ['no_tool_capacity', shape(503, 'service_unavailable')],
    ['no_ephemeral_capacity', shape(503, 'service_unavailable')],
    ['no_relay_available', shape(503, 'service_unavailable')],
    ['operators_busy', shape(503, 'service_unavailable')],
    ['operators_unreachable', shape(503, 'service_unavailable')],
    ['mbr_pool_exhausted', shape(429, 'rate_limit_exceeded')],
    // The caller ended the request; nobody reads this. 499 is the de facto
    // "client closed request" status, and keeps it out of the server-error
    // counts a 5xx would land in.
    ['canceled', shape(499, 'proxy_error')],

    ['free_quota_exhausted', shape(403, 'invalid_request_error')],
    ['wallet_unfunded', shape(402, 'insufficient_quota')],
    ['mbr_pool_underfunded', shape(402, 'insufficient_quota')],
    ['spend_cap_exceeded', shape(402, 'insufficient_quota')],
    ['ticket_price_rejected', shape(502, 'bad_gateway')],
    ['operator_ticket_reuse', shape(502, 'bad_gateway')],

    ['registry', shape(502, 'proxy_error')],
    ['tokenize', shape(502, 'proxy_error')],
    ['wrap_request', shape(502, 'proxy_error')],
    ['wallet_open', shape(502, 'proxy_error')],

    ['build_request', shape(502, 'proxy_error')],
    ['upstream_unreachable', shape(502, 'proxy_error')],
    ['read_upstream', shape(502, 'proxy_error')],
    ['response_handler', shape(502, 'proxy_error')],
    ['stream_setup', shape(502, 'proxy_error')],
    ['operator_unsealed_response', shape(502, 'proxy_error')],
    ['operator_inconsistent_response', shape(502, 'proxy_error')],
    // Only ever rendered as the SSE error frame: the stream's status is
    // already sent by the time it can happen.
    ['stream_interrupted', shape(502, 'proxy_error')],
    // Go's HTTP writer that can't flush; a fetch Response always streams, but
    // the row stays so a node naming the code renders as it does in Go.
    ['no_flusher', shape(500, 'proxy_error')],
    // Unreachable through zs.fetch, which reads frames only: the node's own
    // error frame is what its caller sees.
    ['upstream_error', shape(502, 'bad_gateway')],
])

/**
 * kindShapes renders a code errorShapes doesn't list. The one site that can
 * reach it is the payer refusal, whose code comes from the node, so funds
 * renders as that site's 403 rather than the table's 402.
 */
export const kindShapes: ReadonlyMap<Kind, ErrorShape> = new Map<Kind, ErrorShape>([
    ['invalid_request', shape(400, 'invalid_request_error')],
    ['context_exceeded', shape(400, 'invalid_request_error')],
    ['price_rejected', shape(400, 'invalid_request_error')],
    ['no_route', shape(503, 'service_unavailable')],
    ['busy', shape(503, 'service_unavailable')],
    ['unreachable', shape(503, 'service_unavailable')],
    ['funds', shape(403, 'invalid_request_error')],
    ['spend_cap', shape(402, 'insufficient_quota')],
    ['operator_fault', shape(502, 'bad_gateway')],
    ['upstream', shape(502, 'bad_gateway')],
    ['interrupted', shape(502, 'bad_gateway')],
    ['internal', shape(500, 'proxy_error')],
])

/**
 * SHOULD_RETRY_HEADER overrides the status for OpenAI's SDKs (Python, Node,
 * Go), which otherwise resend any 408, 409, 429 or 5xx on their own.
 */
export const SHOULD_RETRY_HEADER = 'X-Should-Retry'

/**
 * shouldRetry is whether a client may resend on its own. Never after paid: an
 * automatic resend is a second payment the payer did not choose, so that
 * choice is left to code that reads ZsError.paid.
 */
export function shouldRetry(e: ZsError): boolean {
    return e.retryable && !e.paid
}

export function setShouldRetry(h: Headers, retry: boolean): void {
    h.set(SHOULD_RETRY_HEADER, String(retry))
}

/** setRetryAfter writes ms in whole seconds, and removes any Retry-After when there is no wait to advise. */
export function setRetryAfter(h: Headers, ms: number | undefined): void {
    // Go's wait is a Duration, which is never infinite.
    if (ms === undefined || !(ms > 0) || !Number.isFinite(ms)) {
        h.delete('Retry-After')
        return
    }
    h.set('Retry-After', String(Math.trunc(ms / 1000)))
}

/**
 * openAIErrorResponse is an OpenAI-shaped error response over h. An error no
 * caller judged retryable says so, since an OpenAI SDK would otherwise resend
 * a 5xx on its own.
 */
export function openAIErrorResponse(h: Headers, status: number, type: string, code: string, message: string): Response {
    // Go tests for an empty value, not an absent one.
    if (!h.get(SHOULD_RETRY_HEADER)) setShouldRetry(h, false)
    h.set('Content-Type', 'application/json')
    return new Response(openAIErrorBody(type, code, message), { status, headers: h })
}

/** errorResponse renders e as an OpenAI-shaped error response over h. */
export function errorResponse(h: Headers, e: ZsError): Response {
    const sh = errorShapes.get(e.code) ?? kindShapes.get(e.kind)!
    setShouldRetry(h, shouldRetry(e))
    setRetryAfter(h, e.retryAfter)
    return openAIErrorResponse(h, sh.status, sh.type, e.code, e.message)
}
